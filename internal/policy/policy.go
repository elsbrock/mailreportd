// Package policy checks what a domain publishes, as opposed to what receivers
// report about it.
//
// Reports are retrospective: they arrive a day late, out of order, and only
// when a receiver chooses to send one. A broken published policy is knowable
// now, from a DNS lookup, and has been since the moment it broke. The two
// views answer different questions and neither substitutes for the other.
//
// Everything here reads public DNS and public HTTPS and nothing else. No MTA
// API, no provider API, no privileged access. See docs/specs/policy-health.md.
package policy

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Resolver is the subset of *net.Resolver these checks need. It is an
// interface so tests do not touch the network, and it is deliberately narrower
// than classify.Resolver: nothing here resolves an address.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// maxPolicyBytes caps the MTA-STS policy body. The file is a handful of lines
// by specification; anything larger is a misconfigured server or a hostile one,
// and either way it must not be read into memory unbounded.
const maxPolicyBytes = 64 << 10

// Check names, used as a metric label and in error accounting.
const (
	CheckDKIM   = "dkim"
	CheckDMARC  = "dmarc"
	CheckMTASTS = "mtasts"
)

// DKIMResult is the state of one selector's published key.
type DKIMResult struct {
	Selector string
	// Found reports that a TXT record exists at the selector.
	Found bool
	// Valid reports a well-formed record carrying a usable key.
	Valid bool
	// Revoked reports an explicit empty p=, which is a revocation rather than
	// a malformed record: every signature made with this selector now fails,
	// and the fix is different from that for a missing record.
	Revoked bool
	// Testing reports t=y, which asks receivers to treat a failure as if the
	// message were unsigned.
	Testing bool
	// KeyBits is the RSA modulus size. Receivers reject keys below 1024.
	KeyBits int
	// Err is set when the selector could not be resolved at all, which is not
	// the same as the record being absent.
	Err error
}

// DMARCResult is the state of the published _dmarc record.
type DMARCResult struct {
	Found bool
	Valid bool
	// Policy and SubdomainPolicy are p= and sp=. An absent sp= inherits p=,
	// and that inheritance is resolved here so the label never lies.
	Policy          string
	SubdomainPolicy string
	// Pct is pct=, defaulting to 100. Below 100 enforces on a sample while
	// reading as full enforcement.
	Pct int
	// RUAAuthorized maps each external rua domain to whether that domain
	// publishes the RFC 7489 §7.1 authorization record. Same-domain rua needs
	// no authorization and never appears here.
	RUAAuthorized map[string]bool
	Err           error
}

// MTASTSResult is the state of the published MTA-STS policy.
type MTASTSResult struct {
	// TXTFound and ID come from _mta-sts.<domain>.
	TXTFound bool
	ID       string
	// PolicyFetched reports that the well-known URL returned a body.
	PolicyFetched bool
	Valid         bool
	// Mode is none, testing or enforce. testing generates TLS-RPT data and
	// enforces nothing, which is why it is exported rather than folded into a
	// boolean.
	Mode   string
	MaxAge int
	// MXCovered reports that every live MX host matches an mx: pattern. A
	// drifted list makes enforcing senders refuse delivery outright.
	MXCovered bool
	// StaleID reports a policy body that changed while its id did not.
	// Senders cache by id, so the edit reaches nobody until max_age expires.
	StaleID bool
	Err     error
}

// Result is one domain's full policy state.
type Result struct {
	Domain    string
	DKIM      []DKIMResult
	DMARC     DMARCResult
	MTASTS    MTASTSResult
	CheckedAt time.Time
}

// ErrorCount is a cumulative count of checks that could not be completed.
//
// This is separate from a failed verdict on purpose. A DNS timeout is not a
// missing record and an unreachable policy file is not a 404; collapsing the
// two would put "we could not tell" and "it is broken" on the same series.
type ErrorCount struct {
	Domain string
	Check  string
	Count  uint64
}

// Checker resolves and caches per-domain policy state.
type Checker struct {
	resolver  Resolver
	client    *http.Client
	ttl       time.Duration
	selectors map[string][]string

	mu     sync.Mutex
	cache  map[string]*cached
	seenID map[string]policyFingerprint
	errs   map[errKey]uint64
}

type cached struct {
	res     *Result
	expires time.Time
}

type errKey struct {
	domain string
	check  string
}

// policyFingerprint remembers the id a body was last seen under, which is the
// only way to catch an edit that forgot to bump the id.
type policyFingerprint struct {
	id   string
	hash string
}

// New returns a checker. A zero ttl defaults to fifteen minutes: short enough
// to notice a policy change within an export cycle or two, long enough that
// scrapes do not become a DNS storm. selectors maps a domain to the DKIM
// selectors to check, which cannot be discovered because DNS offers no way to
// enumerate names under _domainkey.
func New(resolver Resolver, client *http.Client, ttl time.Duration, selectors map[string][]string) *Checker {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	norm := make(map[string][]string, len(selectors))
	for domain, sels := range selectors {
		norm[normalizeDomain(domain)] = sels
	}
	return &Checker{
		resolver:  resolver,
		client:    client,
		ttl:       ttl,
		selectors: norm,
		cache:     make(map[string]*cached),
		seenID:    make(map[string]policyFingerprint),
		errs:      make(map[errKey]uint64),
	}
}

// Check returns the cached state for a domain, resolving it if needed.
//
// A resolution failure is cached like any other result. Retrying a broken or
// slow zone on every refresh turns a DNS problem into a refresh that never
// finishes.
func (c *Checker) Check(ctx context.Context, domain string) *Result {
	domain = normalizeDomain(domain)

	c.mu.Lock()
	if entry, ok := c.cache[domain]; ok && time.Now().Before(entry.expires) {
		c.mu.Unlock()
		return entry.res
	}
	c.mu.Unlock()

	res := c.resolve(ctx, domain)

	c.mu.Lock()
	c.cache[domain] = &cached{res: res, expires: time.Now().Add(c.ttl)}
	c.mu.Unlock()
	return res
}

// ErrorCounts returns cumulative incomplete-check counts.
//
// The checker owns these rather than the caller because results are cached:
// a caller counting errors off a returned Result would re-count the same
// failure on every refresh for as long as the cache holds it.
func (c *Checker) ErrorCounts() []ErrorCount {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([]ErrorCount, 0, len(c.errs))
	for k, v := range c.errs {
		out = append(out, ErrorCount{Domain: k.domain, Check: k.check, Count: v})
	}
	return out
}

func (c *Checker) countErr(domain, check string) {
	c.mu.Lock()
	c.errs[errKey{domain: domain, check: check}]++
	c.mu.Unlock()
}

func (c *Checker) resolve(ctx context.Context, domain string) *Result {
	res := &Result{Domain: domain, CheckedAt: time.Now()}

	res.DMARC = c.checkDMARC(ctx, domain)
	if res.DMARC.Err != nil {
		c.countErr(domain, CheckDMARC)
	}

	for _, selector := range c.selectors[domain] {
		r := c.checkDKIM(ctx, domain, selector)
		if r.Err != nil {
			c.countErr(domain, CheckDKIM)
		}
		res.DKIM = append(res.DKIM, r)
	}

	res.MTASTS = c.checkMTASTS(ctx, domain)
	if res.MTASTS.Err != nil {
		c.countErr(domain, CheckMTASTS)
	}

	return res
}

// ---------------------------------------------------------------- DKIM

func (c *Checker) checkDKIM(ctx context.Context, domain, selector string) DKIMResult {
	out := DKIMResult{Selector: selector}

	name := selector + "._domainkey." + domain
	records, err := c.resolver.LookupTXT(ctx, name)
	if err != nil {
		if isNotFound(err) {
			// An absent record is a verdict, not a failure to check.
			return out
		}
		out.Err = fmt.Errorf("lookup %s: %w", name, err)
		return out
	}

	record := pickRecord(records, "v=dkim1")
	if record == "" {
		return out
	}
	out.Found = true

	tags := parseTags(record)
	if !strings.EqualFold(tags["v"], "DKIM1") {
		return out
	}
	out.Testing = strings.Contains(strings.ToLower(tags["t"]), "y")

	key, ok := tags["p"]
	if !ok || strings.TrimSpace(key) == "" {
		// An empty p= is an explicit revocation. The record is well-formed and
		// the key is deliberately gone.
		out.Revoked = true
		return out
	}

	bits, err := rsaKeyBits(key)
	if err != nil {
		return out
	}
	out.KeyBits = bits
	out.Valid = bits >= 1024
	return out
}

// rsaKeyBits decodes a DKIM p= value and returns the RSA modulus size.
//
// Whitespace inside the base64 is tolerated because reporters and DNS UIs
// wrap long keys, and a record split across TXT character-strings arrives
// concatenated with no separator.
func rsaKeyBits(p string) (int, error) {
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, p)

	der, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return 0, fmt.Errorf("decode key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return 0, fmt.Errorf("parse key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		// Ed25519 keys are valid DKIM but carry no modulus. Reporting zero
		// bits for one would read as a broken RSA key.
		return 0, errors.New("not an RSA key")
	}
	return rsaPub.N.BitLen(), nil
}

// ---------------------------------------------------------------- DMARC

func (c *Checker) checkDMARC(ctx context.Context, domain string) DMARCResult {
	out := DMARCResult{Pct: 100}

	name := "_dmarc." + domain
	records, err := c.resolver.LookupTXT(ctx, name)
	if err != nil {
		if isNotFound(err) {
			return out
		}
		out.Err = fmt.Errorf("lookup %s: %w", name, err)
		return out
	}

	record := pickRecord(records, "v=dmarc1")
	if record == "" {
		return out
	}
	out.Found = true

	tags := parseTags(record)
	// v=DMARC1 must be the first tag, not merely present somewhere.
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(record)), "v=dmarc1") {
		return out
	}
	policy := strings.ToLower(strings.TrimSpace(tags["p"]))
	switch policy {
	case "none", "quarantine", "reject":
		out.Policy = policy
		out.Valid = true
	default:
		return out
	}

	// An absent sp= inherits p=. Resolving it here means the exported label is
	// the policy that actually applies to subdomains.
	sub := strings.ToLower(strings.TrimSpace(tags["sp"]))
	switch sub {
	case "none", "quarantine", "reject":
		out.SubdomainPolicy = sub
	default:
		out.SubdomainPolicy = policy
	}

	if raw, ok := tags["pct"]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && n >= 0 && n <= 100 {
			out.Pct = n
		}
	}

	out.RUAAuthorized = c.checkExternalDestinations(ctx, domain, tags["rua"])
	return out
}

// checkExternalDestinations implements RFC 7489 §7.1.
//
// When rua points at another domain, receivers first require that domain to
// publish an authorization record. Without it most large receivers send
// nothing at all, which presents as an empty mailbox and is indistinguishable
// from a quiet week.
func (c *Checker) checkExternalDestinations(ctx context.Context, domain, rua string) map[string]bool {
	if strings.TrimSpace(rua) == "" {
		return nil
	}

	var out map[string]bool
	for _, uri := range strings.Split(rua, ",") {
		uri = strings.TrimSpace(uri)
		if !strings.HasPrefix(strings.ToLower(uri), "mailto:") {
			continue
		}
		addr := uri[len("mailto:"):]
		// A destination may carry a size limit suffix, as in "…@x.example!10m".
		if i := strings.IndexByte(addr, '!'); i >= 0 {
			addr = addr[:i]
		}
		at := strings.LastIndexByte(addr, '@')
		if at < 0 {
			continue
		}
		target := normalizeDomain(addr[at+1:])
		if target == "" || target == domain || strings.HasSuffix(target, "."+domain) {
			// Same-domain and subdomain destinations need no authorization.
			continue
		}
		if out == nil {
			out = make(map[string]bool)
		}
		if _, done := out[target]; done {
			continue
		}
		out[target] = c.authorized(ctx, domain, target)
	}
	return out
}

func (c *Checker) authorized(ctx context.Context, domain, target string) bool {
	name := domain + "._report._dmarc." + target
	records, err := c.resolver.LookupTXT(ctx, name)
	if err == nil && pickRecord(records, "v=dmarc1") != "" {
		return true
	}
	// A wildcard record authorizes every reporting domain at once.
	wildcard := "*._report._dmarc." + target
	records, err = c.resolver.LookupTXT(ctx, wildcard)
	return err == nil && pickRecord(records, "v=dmarc1") != ""
}

// ---------------------------------------------------------------- MTA-STS

func (c *Checker) checkMTASTS(ctx context.Context, domain string) MTASTSResult {
	var out MTASTSResult

	name := "_mta-sts." + domain
	records, err := c.resolver.LookupTXT(ctx, name)
	if err != nil {
		if isNotFound(err) {
			return out
		}
		out.Err = fmt.Errorf("lookup %s: %w", name, err)
		return out
	}
	record := pickRecord(records, "v=stsv1")
	if record == "" {
		return out
	}
	out.TXTFound = true
	out.ID = strings.TrimSpace(parseTags(record)["id"])

	body, err := c.fetchPolicy(ctx, domain)
	if err != nil {
		// Unreachable is not absent. Senders keep serving the cached policy
		// until max_age expires, so this is a warning about the future.
		out.Err = err
		return out
	}
	out.PolicyFetched = true

	mode, maxAge, patterns, ok := parsePolicy(body)
	if !ok {
		return out
	}
	out.Mode = mode
	out.MaxAge = maxAge
	out.Valid = true

	out.StaleID = c.noteFingerprint(domain, out.ID, body)
	out.MXCovered = c.mxCovered(ctx, domain, patterns)
	return out
}

func (c *Checker) fetchPolicy(ctx context.Context, domain string) (string, error) {
	url := "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicyBytes))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", url, err)
	}
	return string(body), nil
}

// noteFingerprint reports whether the body changed while the id did not.
//
// The first sighting of a domain can never be stale: there is nothing to
// compare against, and reporting staleness on startup would be a false alarm
// on every restart.
func (c *Checker) noteFingerprint(domain, id, body string) bool {
	sum := sha256.Sum256([]byte(strings.TrimSpace(body)))
	hash := hex.EncodeToString(sum[:])

	c.mu.Lock()
	defer c.mu.Unlock()

	prev, seen := c.seenID[domain]
	c.seenID[domain] = policyFingerprint{id: id, hash: hash}
	if !seen {
		return false
	}
	return prev.id == id && prev.hash != hash
}

// mxCovered reports whether every live MX host matches an mx: pattern.
//
// A domain with no MX at all is not covered: there is nothing to deliver to,
// and reporting coverage would be vacuously true.
func (c *Checker) mxCovered(ctx context.Context, domain string, patterns []string) bool {
	mxs, err := c.resolver.LookupMX(ctx, domain)
	if err != nil || len(mxs) == 0 {
		return false
	}
	for _, mx := range mxs {
		host := normalizeDomain(mx.Host)
		if host == "" {
			continue
		}
		if !matchesAny(host, patterns) {
			return false
		}
	}
	return true
}

func matchesAny(host string, patterns []string) bool {
	for _, p := range patterns {
		p = normalizeDomain(p)
		if p == "" {
			continue
		}
		if p == host {
			return true
		}
		// RFC 8461 §3.2 allows a wildcard in the leftmost label only, and it
		// matches exactly one label.
		if rest, ok := strings.CutPrefix(p, "*."); ok {
			if idx := strings.IndexByte(host, '.'); idx >= 0 && host[idx+1:] == rest {
				return true
			}
		}
	}
	return false
}

// parsePolicy reads the well-known policy file. Fields are "key: value" lines
// and mx repeats.
func parsePolicy(body string) (mode string, maxAge int, mx []string, ok bool) {
	var version string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "version":
			version = value
		case "mode":
			mode = strings.ToLower(value)
		case "max_age":
			if n, err := strconv.Atoi(value); err == nil {
				maxAge = n
			}
		case "mx":
			mx = append(mx, value)
		}
	}
	if !strings.EqualFold(version, "STSv1") {
		return "", 0, nil, false
	}
	switch mode {
	case "none", "testing", "enforce":
	default:
		return "", 0, nil, false
	}
	return mode, maxAge, mx, true
}

// ---------------------------------------------------------------- helpers

// pickRecord returns the first TXT record carrying the given prefix.
//
// A name commonly holds several TXT records, only one of which is the policy;
// taking records[0] blindly is a real source of false negatives.
func pickRecord(records []string, prefix string) string {
	for _, r := range records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), prefix) {
			return r
		}
	}
	return ""
}

// parseTags splits a "k=v; k=v" record. Keys are lowercased; values keep their
// case because base64 key material is case-sensitive.
func parseTags(record string) map[string]string {
	out := make(map[string]string)
	for _, part := range strings.Split(record, ";") {
		key, value, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(value)
	}
	return out
}

func normalizeDomain(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// isNotFound distinguishes "the name does not exist" from "the lookup failed".
// The first is a verdict about the domain; the second is a verdict about the
// network, and treating them alike is how a resolver outage comes to look like
// every policy vanishing at once.
func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}
