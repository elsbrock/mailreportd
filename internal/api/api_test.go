package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/elsbrock/mailreportd/internal/imaptest"
	"github.com/elsbrock/mailreportd/internal/store"
)

func aggregateXML() string {
	end := time.Now().Add(-12 * time.Hour)
	begin := end.Add(-24 * time.Hour)
	return fmt.Sprintf(`<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>google.com</org_name><report_id>r1</report_id>
    <date_range><begin>%d</begin><end>%d</end></date_range></report_metadata>
  <policy_published><domain>example.org</domain><p>reject</p><pct>100</pct></policy_published>
  <record><row><source_ip>203.0.113.10</source_ip><count>100</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>example.org</header_from></identifiers>
    <auth_results>
      <dkim><domain>relay-smtp.net</domain><selector>rly1</selector><result>pass</result></dkim>
      <dkim><domain>example.org</domain><selector>selector1</selector><result>pass</result></dkim>
    </auth_results></record>
  <record><row><source_ip>192.0.2.66</source_ip><count>40</count>
    <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.org</header_from></identifiers>
    <auth_results>
      <dkim><domain>spoofer.example</domain><selector>x</selector><result>fail</result></dkim>
    </auth_results></record>
</feedback>`, begin.Unix(), end.Unix())
}

func reportMail(t *testing.T, payload string) []byte {
	t.Helper()
	var gzbuf bytes.Buffer
	zw := gzip.NewWriter(&gzbuf)
	zw.Write([]byte(payload))
	zw.Close()

	var b strings.Builder
	b.WriteString("From: r@google.com\r\nSubject: report\r\nMIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"SEP\"\r\n\r\n--SEP\r\n")
	b.WriteString("Content-Type: application/gzip; name=\"r.xml.gz\"\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	b.WriteString(base64.StdEncoding.EncodeToString(gzbuf.Bytes()))
	b.WriteString("\r\n\r\n--SEP--\r\n")
	return []byte(b.String())
}

func testAPI(t *testing.T, tenants ...string) http.Handler {
	t.Helper()
	if len(tenants) == 0 {
		tenants = []string{"default"}
	}

	db, err := store.Open(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	stores := map[string]*store.Store{}
	for _, id := range tenants {
		s := db.Tenant(id)
		stores[id] = s
		if _, err := s.Ingest(context.Background(), store.RawMessage{
			Feeder: "test", Received: time.Now(), Body: reportMail(t, aggregateXML()),
		}); err != nil {
			t.Fatalf("ingest: %v", err)
		}
	}

	mux := http.NewServeMux()
	New(stores, slog.New(slog.NewTextHandler(io.Discard, nil))).Register(mux)
	return mux
}

func get(t *testing.T, h http.Handler, path string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode %s: %v (body: %s)", path, err, rec.Body.String())
	}
	return rec.Code, payload
}

func TestDomains(t *testing.T) {
	code, payload := get(t, testAPI(t), "/api/v1/domains")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}

	domains, ok := payload["domains"].([]any)
	if !ok || len(domains) != 1 {
		t.Fatalf("domains = %#v", payload["domains"])
	}
	d := domains[0].(map[string]any)
	if d["domain"] != "example.org" {
		t.Errorf("domain = %v", d["domain"])
	}
	if d["messages"].(float64) != 140 {
		t.Errorf("messages = %v, want 140", d["messages"])
	}
	if d["policy"] != "reject" {
		t.Errorf("policy = %v", d["policy"])
	}
}

func TestSourcesReturnsWorstFirst(t *testing.T) {
	code, payload := get(t, testAPI(t), "/api/v1/sources")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}

	sources := payload["sources"].([]any)
	if len(sources) != 2 {
		t.Fatalf("sources = %d, want 2", len(sources))
	}

	// The failing source is the actionable one and must come first.
	first := sources[0].(map[string]any)
	if first["source_ip"] != "192.0.2.66" {
		t.Errorf("first source = %v, want the failing one", first["source_ip"])
	}
	if first["failing"].(float64) != 40 {
		t.Errorf("failing = %v", first["failing"])
	}
	if first["rejected"].(float64) != 40 {
		t.Errorf("rejected = %v", first["rejected"])
	}
}

func TestSourcesFilterByDomain(t *testing.T) {
	h := testAPI(t)

	_, payload := get(t, h, "/api/v1/sources?domain=example.org")
	if len(payload["sources"].([]any)) != 2 {
		t.Errorf("expected both sources for the matching domain")
	}

	_, payload = get(t, h, "/api/v1/sources?domain=other.example")
	sources := payload["sources"].([]any)
	if len(sources) != 0 {
		t.Errorf("sources = %d, want 0 for an unknown domain", len(sources))
	}
}

func TestEmptyResultsAreArraysNotNull(t *testing.T) {
	// Clients should not have to special-case "no results".
	_, payload := get(t, testAPI(t), "/api/v1/quarantine")
	if _, ok := payload["entries"].([]any); !ok {
		t.Errorf("entries = %#v, want an array", payload["entries"])
	}
}

func TestSignersDistinguishesForeignFromExact(t *testing.T) {
	code, payload := get(t, testAPI(t), "/api/v1/signers")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}

	signers, ok := payload["signers"].([]any)
	if !ok || len(signers) != 3 {
		t.Fatalf("signers = %#v", payload["signers"])
	}

	byDomain := map[string]map[string]any{}
	for _, s := range signers {
		m := s.(map[string]any)
		byDomain[m["signing_domain"].(string)] = m
	}

	// The relay signs 100 messages and verifies on all of them, yet it is
	// foreign: none of that validity is what earned the receiver's dkim=pass.
	relay := byDomain["relay-smtp.net"]
	if relay == nil {
		t.Fatalf("no relay-smtp.net in %#v", byDomain)
	}
	if relay["relationship"] != "foreign" {
		t.Errorf("relay relationship = %v, want foreign", relay["relationship"])
	}
	if relay["signature_pass"].(float64) != 100 {
		t.Errorf("relay signature_pass = %v, want 100", relay["signature_pass"])
	}

	if byDomain["example.org"]["relationship"] != "exact" {
		t.Errorf("own relationship = %v, want exact", byDomain["example.org"]["relationship"])
	}
	if byDomain["spoofer.example"]["relationship"] != "foreign" {
		t.Errorf("spoofer relationship = %v, want foreign", byDomain["spoofer.example"]["relationship"])
	}

	// The remainder is always reported, even when nothing was cut off.
	omitted, ok := payload["omitted"].(map[string]any)
	if !ok {
		t.Fatalf("omitted = %#v, want an object", payload["omitted"])
	}
	if omitted["signers"].(float64) != 0 {
		t.Errorf("omitted signers = %v, want 0", omitted["signers"])
	}
}

func TestSignersReportsWhatTheLimitCutOff(t *testing.T) {
	_, payload := get(t, testAPI(t), "/api/v1/signers?limit=1")

	if len(payload["signers"].([]any)) != 1 {
		t.Fatalf("signers = %#v, want one", payload["signers"])
	}
	omitted := payload["omitted"].(map[string]any)
	if omitted["signers"].(float64) != 2 {
		t.Errorf("omitted signers = %v, want 2", omitted["signers"])
	}
	if omitted["messages"].(float64) == 0 {
		t.Error("omitted messages = 0, want the cut-off volume")
	}
}

func TestSourcesCarryDKIMAndSPFPass(t *testing.T) {
	_, payload := get(t, testAPI(t), "/api/v1/sources")

	for _, raw := range payload["sources"].([]any) {
		src := raw.(map[string]any)
		if src["source_ip"] != "203.0.113.10" {
			continue
		}
		if src["dkim_pass"].(float64) != 100 || src["spf_pass"].(float64) != 100 {
			t.Errorf("source = %#v, want dkim_pass and spf_pass of 100", src)
		}
		return
	}
	t.Fatalf("no 203.0.113.10 in %#v", payload["sources"])
}

func TestSourcesFilterByReporter(t *testing.T) {
	h := testAPI(t)

	_, payload := get(t, h, "/api/v1/sources?reporter=Google.com")
	if n := len(payload["sources"].([]any)); n != 2 {
		t.Errorf("google.com sources = %d, want 2", n)
	}
	_, payload = get(t, h, "/api/v1/sources?reporter=outlook.com")
	if n := len(payload["sources"].([]any)); n != 0 {
		t.Errorf("outlook.com sources = %d, want 0", n)
	}
}

func TestReporters(t *testing.T) {
	code, payload := get(t, testAPI(t), "/api/v1/reporters")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}

	reporters, ok := payload["reporters"].([]any)
	if !ok || len(reporters) != 1 {
		t.Fatalf("reporters = %#v", payload["reporters"])
	}
	google := reporters[0].(map[string]any)
	if google["reporter"] != "google.com" || google["total"].(float64) != 140 || google["dkim_pass"].(float64) != 100 {
		t.Errorf("google = %#v", google)
	}
	if _, ok := payload["omitted"].(map[string]any); !ok {
		t.Errorf("omitted = %#v, want an object", payload["omitted"])
	}
}

func TestSignersCarryDays(t *testing.T) {
	_, payload := get(t, testAPI(t), "/api/v1/signers")

	for _, raw := range payload["signers"].([]any) {
		signer := raw.(map[string]any)
		days, ok := signer["days"].([]any)
		if !ok || len(days) != 1 {
			t.Errorf("%v days = %#v, want one day", signer["signing_domain"], signer["days"])
		}
	}
}

func TestWindowIsHonoured(t *testing.T) {
	h := testAPI(t)

	// The fixture's window ended twelve hours ago, so a one-hour lookback must
	// exclude it.
	_, payload := get(t, h, "/api/v1/domains?window=1h")
	if len(payload["domains"].([]any)) != 0 {
		t.Errorf("a one hour window should exclude a report from twelve hours ago")
	}

	_, payload = get(t, h, "/api/v1/domains?window=72h")
	if len(payload["domains"].([]any)) != 1 {
		t.Errorf("a seventy-two hour window should include it")
	}
}

func TestBadParameters(t *testing.T) {
	h := testAPI(t)

	for _, path := range []string{
		"/api/v1/domains?window=banana",
		"/api/v1/domains?window=-1h",
		"/api/v1/sources?limit=0",
		"/api/v1/sources?limit=abc",
		"/api/v1/reporters?limit=0",
	} {
		code, payload := get(t, h, path)
		if code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", path, code)
		}
		if payload["error"] == nil {
			t.Errorf("%s: expected an error message", path)
		}
	}
}

func TestTenantScoping(t *testing.T) {
	h := testAPI(t, "alpha", "beta")

	// With more than one tenant configured, the caller must name one.
	code, _ := get(t, h, "/api/v1/domains")
	if code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 when the tenant is ambiguous", code)
	}

	code, payload := get(t, h, "/api/v1/domains?tenant=alpha")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if payload["tenant"] != "alpha" {
		t.Errorf("tenant = %v", payload["tenant"])
	}

	code, _ = get(t, h, "/api/v1/domains?tenant=nope")
	if code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an unknown tenant", code)
	}
}

func TestSingleTenantNeedsNoTenantParameter(t *testing.T) {
	// The common self-hosted case should never have to name its tenant.
	code, payload := get(t, testAPI(t), "/api/v1/domains")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if payload["tenant"] != "default" {
		t.Errorf("tenant = %v", payload["tenant"])
	}
}

func TestFailures(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "failures.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	key := make([]byte, 32)
	rand.Read(key)
	sealer, err := store.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	db.SetSealer(sealer)

	s := db.Tenant("default")
	if _, err := s.Ingest(context.Background(), store.RawMessage{
		Feeder: "test", Received: time.Now(),
		Body: imaptest.FailureMail(t, "arf-1", "example.org", "victim@dest.example", time.Now().Add(-12*time.Hour)),
	}); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	mux := http.NewServeMux()
	New(map[string]*store.Store{"default": s}, slog.New(slog.NewTextHandler(io.Discard, nil))).Register(mux)

	// The metadata view: envelope facts, no content, nothing logged.
	code, payload := get(t, mux, "/api/v1/failures")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	failures, ok := payload["failures"].([]any)
	if !ok || len(failures) != 1 {
		t.Fatalf("failures = %v", payload["failures"])
	}
	f := failures[0].(map[string]any)
	if f["domain"] != "example.org" || f["auth_failure"] != "dmarc" || f["has_content"] != true {
		t.Fatalf("failure = %v", f)
	}
	if _, present := payload["content"]; present {
		t.Fatal("content served without being asked for")
	}
	var logged int
	db.SQL().QueryRow(`SELECT COUNT(*) FROM failure_access_log`).Scan(&logged)
	if logged != 0 {
		t.Fatalf("metadata view was access-logged: %d rows", logged)
	}

	// The content view decrypts and leaves a log row.
	code, payload = get(t, mux, "/api/v1/failures?include=content")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	content, ok := payload["content"].(map[string]any)
	if !ok || len(content) != 1 {
		t.Fatalf("content = %v", payload["content"])
	}
	for _, c := range content {
		entry := c.(map[string]any)
		rcpt, _ := entry["original_rcpt_to"].([]any)
		if len(rcpt) != 1 || rcpt[0] != "victim@dest.example" {
			t.Fatalf("rcpt = %v", entry["original_rcpt_to"])
		}
	}
	db.SQL().QueryRow(`SELECT COUNT(*) FROM failure_access_log`).Scan(&logged)
	if logged != 1 {
		t.Fatalf("content read left %d access log rows, want 1", logged)
	}

	// Anything else asked for by include is a caller error.
	if code, _ := get(t, mux, "/api/v1/failures?include=everything"); code != http.StatusBadRequest {
		t.Fatalf("unknown include answered %d, want 400", code)
	}
}
