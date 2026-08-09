package api

import (
	"bytes"
	"compress/gzip"
	"context"
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
    <identifiers><header_from>example.org</header_from></identifiers></record>
  <record><row><source_ip>192.0.2.66</source_ip><count>40</count>
    <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.org</header_from></identifiers></record>
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
