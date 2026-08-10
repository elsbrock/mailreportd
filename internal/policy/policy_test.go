package policy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeResolver answers from maps so tests never touch the network. A name that
// is absent from every map returns NXDOMAIN, which is the case the checks must
// treat as a verdict rather than a failure.
type fakeResolver struct {
	mu   sync.Mutex
	txt  map[string][]string
	mx   map[string][]*net.MX
	errs map[string]error

	txtCalls int
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.txtCalls++
	name = strings.TrimSuffix(name, ".")
	if err, ok := f.errs[name]; ok {
		return nil, err
	}
	if v, ok := f.txt[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name = strings.TrimSuffix(name, ".")
	if v, ok := f.mx[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// fakeTransport serves canned policy bodies, keyed by URL.
type fakeTransport struct {
	bodies map[string]string
	status map[string]int
	err    error
}

func (t *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.err != nil {
		return nil, t.err
	}
	url := req.URL.String()
	body, ok := t.bodies[url]
	if !ok {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	code := http.StatusOK
	if c, ok := t.status[url]; ok {
		code = c
	}
	return &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func client(t *fakeTransport) *http.Client { return &http.Client{Transport: t} }

// dkimRecord builds a published DKIM record around a freshly generated key.
func dkimRecord(t *testing.T, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return "v=DKIM1; k=rsa; h=sha256; p=" + base64.StdEncoding.EncodeToString(der)
}

// weakDKIMRecord builds a record around an undersized modulus. The key is
// constructed rather than generated because Go refuses to generate RSA keys
// below 1024 bits, which is precisely the case under test.
func weakDKIMRecord(t *testing.T) string {
	t.Helper()
	n := new(big.Int).Lsh(big.NewInt(1), 511)
	n.Add(n, big.NewInt(1))
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
}

func TestDKIMValidKey(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"sel._domainkey.example.com": {dkimRecord(t, 2048)},
	}}
	c := New(r, client(&fakeTransport{}), time.Minute, map[string][]string{
		"example.com": {"sel"},
	})

	res := c.Check(context.Background(), "example.com")
	if len(res.DKIM) != 1 {
		t.Fatalf("want 1 selector result, got %d", len(res.DKIM))
	}
	got := res.DKIM[0]
	if !got.Found || !got.Valid || got.Revoked {
		t.Fatalf("want found+valid, got %+v", got)
	}
	if got.KeyBits != 2048 {
		t.Errorf("KeyBits = %d, want 2048", got.KeyBits)
	}
}

// An empty p= is a revocation, not a malformed record. Conflating the two
// sends the operator looking for a publishing mistake that is not there.
func TestDKIMRevoked(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"sel._domainkey.example.com": {"v=DKIM1; k=rsa; p="},
	}}
	c := New(r, client(&fakeTransport{}), time.Minute, map[string][]string{
		"example.com": {"sel"},
	})

	got := c.Check(context.Background(), "example.com").DKIM[0]
	if !got.Found {
		t.Error("Found = false, want true: the record exists")
	}
	if !got.Revoked {
		t.Error("Revoked = false, want true")
	}
	if got.Valid {
		t.Error("Valid = true, want false")
	}
}

func TestDKIMWeakKeyIsInvalid(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"sel._domainkey.example.com": {weakDKIMRecord(t)},
	}}
	c := New(r, client(&fakeTransport{}), time.Minute, map[string][]string{
		"example.com": {"sel"},
	})

	got := c.Check(context.Background(), "example.com").DKIM[0]
	if got.KeyBits != 512 {
		t.Fatalf("KeyBits = %d, want 512", got.KeyBits)
	}
	if got.Valid {
		t.Error("Valid = true for a 512-bit key, want false")
	}
}

// A missing record is a verdict about the domain. A failed lookup is a verdict
// about the network, and only the second may count as an incomplete check.
func TestMissingRecordIsNotAnError(t *testing.T) {
	r := &fakeResolver{}
	c := New(r, client(&fakeTransport{}), time.Minute, map[string][]string{
		"example.com": {"sel"},
	})

	res := c.Check(context.Background(), "example.com")
	if res.DKIM[0].Found || res.DKIM[0].Err != nil {
		t.Errorf("DKIM = %+v, want absent with no error", res.DKIM[0])
	}
	if res.DMARC.Found || res.DMARC.Err != nil {
		t.Errorf("DMARC = %+v, want absent with no error", res.DMARC)
	}
	if counts := c.ErrorCounts(); len(counts) != 0 {
		t.Errorf("ErrorCounts = %v, want none", counts)
	}
}

func TestLookupFailureCountsAsIncomplete(t *testing.T) {
	boom := &net.DNSError{Err: "server misbehaving", Name: "_dmarc.example.com"}
	r := &fakeResolver{errs: map[string]error{"_dmarc.example.com": boom}}
	c := New(r, client(&fakeTransport{}), time.Minute, nil)

	res := c.Check(context.Background(), "example.com")
	if res.DMARC.Err == nil {
		t.Fatal("DMARC.Err = nil, want an error")
	}
	if res.DMARC.Found {
		t.Error("Found = true, want false when the lookup failed")
	}

	counts := c.ErrorCounts()
	if len(counts) != 1 || counts[0].Check != CheckDMARC || counts[0].Count != 1 {
		t.Fatalf("ErrorCounts = %+v, want one dmarc error", counts)
	}
}

func TestDMARCPctAndInheritedSubdomainPolicy(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=reject; pct=50; rua=mailto:d@example.com"},
	}}
	c := New(r, client(&fakeTransport{}), time.Minute, nil)

	got := c.Check(context.Background(), "example.com").DMARC
	if !got.Valid || got.Policy != "reject" {
		t.Fatalf("DMARC = %+v, want valid reject", got)
	}
	if got.Pct != 50 {
		t.Errorf("Pct = %d, want 50", got.Pct)
	}
	// sp= is absent, so subdomains inherit p=.
	if got.SubdomainPolicy != "reject" {
		t.Errorf("SubdomainPolicy = %q, want inherited \"reject\"", got.SubdomainPolicy)
	}
	// A same-domain rua needs no authorization record.
	if len(got.RUAAuthorized) != 0 {
		t.Errorf("RUAAuthorized = %v, want empty for a same-domain rua", got.RUAAuthorized)
	}
}

func TestDMARCPctDefaultsTo100(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=none"},
	}}
	c := New(r, client(&fakeTransport{}), time.Minute, nil)

	if got := c.Check(context.Background(), "example.com").DMARC.Pct; got != 100 {
		t.Errorf("Pct = %d, want 100", got)
	}
}

// RFC 7489 §7.1: without the authorization record most large receivers send
// nothing, which looks exactly like a quiet mailbox.
func TestDMARCExternalDestinationUnauthorized(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=reject; rua=mailto:x@reports.vendor.net!10m"},
	}}
	c := New(r, client(&fakeTransport{}), time.Minute, nil)

	got := c.Check(context.Background(), "example.com").DMARC
	authorized, ok := got.RUAAuthorized["reports.vendor.net"]
	if !ok {
		t.Fatalf("RUAAuthorized = %v, want an entry for the external domain", got.RUAAuthorized)
	}
	if authorized {
		t.Error("authorized = true, want false with no _report._dmarc record")
	}
}

func TestDMARCExternalDestinationAuthorized(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"_dmarc.example.com":                            {"v=DMARC1; p=reject; rua=mailto:x@reports.vendor.net"},
		"example.com._report._dmarc.reports.vendor.net": {"v=DMARC1"},
	}}
	c := New(r, client(&fakeTransport{}), time.Minute, nil)

	got := c.Check(context.Background(), "example.com").DMARC
	if !got.RUAAuthorized["reports.vendor.net"] {
		t.Errorf("RUAAuthorized = %v, want authorized", got.RUAAuthorized)
	}
}

func TestDMARCExternalDestinationWildcard(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"_dmarc.example.com":                  {"v=DMARC1; p=reject; rua=mailto:x@reports.vendor.net"},
		"*._report._dmarc.reports.vendor.net": {"v=DMARC1"},
	}}
	c := New(r, client(&fakeTransport{}), time.Minute, nil)

	got := c.Check(context.Background(), "example.com").DMARC
	if !got.RUAAuthorized["reports.vendor.net"] {
		t.Errorf("RUAAuthorized = %v, want authorized by wildcard", got.RUAAuthorized)
	}
}

const stsURL = "https://mta-sts.example.com/.well-known/mta-sts.txt"

func stsResolver(mxHosts ...string) *fakeResolver {
	mxs := make([]*net.MX, 0, len(mxHosts))
	for _, h := range mxHosts {
		mxs = append(mxs, &net.MX{Host: h, Pref: 10})
	}
	return &fakeResolver{
		txt: map[string][]string{
			"_mta-sts.example.com": {"v=STSv1; id=20260101000000"},
		},
		mx: map[string][]*net.MX{"example.com": mxs},
	}
}

func TestMTASTSCovered(t *testing.T) {
	r := stsResolver("mail.example.com.")
	tr := &fakeTransport{bodies: map[string]string{
		stsURL: "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n",
	}}
	c := New(r, client(tr), time.Minute, nil)

	got := c.Check(context.Background(), "example.com").MTASTS
	if !got.TXTFound || !got.PolicyFetched || !got.Valid {
		t.Fatalf("MTASTS = %+v, want a valid fetched policy", got)
	}
	if got.Mode != "enforce" || got.MaxAge != 604800 {
		t.Errorf("Mode/MaxAge = %q/%d, want enforce/604800", got.Mode, got.MaxAge)
	}
	if !got.MXCovered {
		t.Error("MXCovered = false, want true")
	}
}

// An mx: list that no longer matches the live MX makes enforcing senders
// refuse delivery outright.
func TestMTASTSMXDrift(t *testing.T) {
	r := stsResolver("mail.example.com.", "mail2.elsewhere.net.")
	tr := &fakeTransport{bodies: map[string]string{
		stsURL: "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n",
	}}
	c := New(r, client(tr), time.Minute, nil)

	if got := c.Check(context.Background(), "example.com").MTASTS; got.MXCovered {
		t.Error("MXCovered = true, want false when an MX is outside the policy")
	}
}

func TestMTASTSWildcardMX(t *testing.T) {
	r := stsResolver("mail.example.com.")
	tr := &fakeTransport{bodies: map[string]string{
		stsURL: "version: STSv1\nmode: testing\nmx: *.example.com\nmax_age: 86400\n",
	}}
	c := New(r, client(tr), time.Minute, nil)

	got := c.Check(context.Background(), "example.com").MTASTS
	if !got.MXCovered {
		t.Error("MXCovered = false, want true: the wildcard matches one label")
	}
	if got.Mode != "testing" {
		t.Errorf("Mode = %q, want testing", got.Mode)
	}
}

// A body edited without bumping the id reaches nobody until every cache
// expires, which is commonly a week.
func TestMTASTSStaleID(t *testing.T) {
	r := stsResolver("mail.example.com.")
	tr := &fakeTransport{bodies: map[string]string{
		stsURL: "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n",
	}}
	// A zero-length cache so the second Check actually re-resolves.
	c := New(r, client(tr), time.Nanosecond, nil)

	if got := c.Check(context.Background(), "example.com").MTASTS; got.StaleID {
		t.Fatal("StaleID = true on first sighting, want false")
	}

	// Same id in DNS, different body.
	tr.bodies[stsURL] = "version: STSv1\nmode: enforce\nmx: other.example.com\nmax_age: 604800\n"
	if got := c.Check(context.Background(), "example.com").MTASTS; !got.StaleID {
		t.Error("StaleID = false, want true when the body changed under the same id")
	}
}

func TestMTASTSIDBumpIsNotStale(t *testing.T) {
	r := stsResolver("mail.example.com.")
	tr := &fakeTransport{bodies: map[string]string{
		stsURL: "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n",
	}}
	c := New(r, client(tr), time.Nanosecond, nil)
	c.Check(context.Background(), "example.com")

	r.mu.Lock()
	r.txt["_mta-sts.example.com"] = []string{"v=STSv1; id=20260202000000"}
	r.mu.Unlock()
	tr.bodies[stsURL] = "version: STSv1\nmode: enforce\nmx: other.example.com\nmax_age: 604800\n"

	if got := c.Check(context.Background(), "example.com").MTASTS; got.StaleID {
		t.Error("StaleID = true, want false when the id was bumped alongside the body")
	}
}

// Unreachable is not absent: senders keep serving the cached policy until
// max_age expires, so this is an incomplete check rather than a verdict.
func TestMTASTSUnreachablePolicy(t *testing.T) {
	r := stsResolver("mail.example.com.")
	tr := &fakeTransport{err: errors.New("connection refused")}
	c := New(r, client(tr), time.Minute, nil)

	got := c.Check(context.Background(), "example.com").MTASTS
	if !got.TXTFound {
		t.Error("TXTFound = false, want true")
	}
	if got.PolicyFetched || got.Valid {
		t.Error("want PolicyFetched and Valid false")
	}
	if got.Err == nil {
		t.Fatal("Err = nil, want an error")
	}
	counts := c.ErrorCounts()
	if len(counts) != 1 || counts[0].Check != CheckMTASTS {
		t.Fatalf("ErrorCounts = %+v, want one mtasts error", counts)
	}
}

// The cache exists so a slow or broken zone cannot be re-resolved on every
// refresh. Without it a DNS problem becomes a refresh that never finishes.
func TestResultsAreCached(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=none"},
	}}
	c := New(r, client(&fakeTransport{}), time.Hour, nil)

	c.Check(context.Background(), "example.com")
	first := r.txtCalls
	c.Check(context.Background(), "example.com")

	if r.txtCalls != first {
		t.Errorf("txtCalls = %d after second Check, want %d: result was not cached", r.txtCalls, first)
	}
}

// A name commonly holds several TXT records and only one is the policy.
func TestPicksPolicyAmongOtherTXTRecords(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"_dmarc.example.com": {"some-verification=abc123", "v=DMARC1; p=quarantine"},
	}}
	c := New(r, client(&fakeTransport{}), time.Minute, nil)

	got := c.Check(context.Background(), "example.com").DMARC
	if !got.Valid || got.Policy != "quarantine" {
		t.Errorf("DMARC = %+v, want the policy record to be found among others", got)
	}
}
