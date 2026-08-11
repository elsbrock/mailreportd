package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/elsbrock/mailreportd/internal/config"
	"github.com/elsbrock/mailreportd/internal/imaptest"
)

// fakeResolver serves the SPF zone the fixtures assume, so classification is
// exercised without touching real DNS.
type fakeResolver struct{ txt map[string][]string }

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if r, ok := f.txt[name]; ok {
		return r, nil
	}
	return nil, fmt.Errorf("no such host: %s", name)
}
func (f *fakeResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return nil, fmt.Errorf("no such host")
}
func (f *fakeResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	return nil, fmt.Errorf("no such host")
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// harness is a fully assembled daemon pointed at a live test mailbox.
type harness struct {
	daemon  *Daemon
	mailbox *imaptest.Mailbox
	private *httptest.Server
	public  *httptest.Server
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	mailbox := imaptest.NewMailbox(t)
	host, port := mailbox.HostPort(t)
	username, password := mailbox.Credentials()

	t.Setenv("MAILREPORTD_TEST_PASSWORD", password)

	cfg, err := config.Parse([]byte(fmt.Sprintf(`
log:
  level: error
storage:
  path: %q
metrics:
  window: 720h
tenants:
  - id: default
    domains: [example.org]
feeders:
  - name: mailbox
    type: imap
    host: %q
    port: %d
    username: %q
    password_env: MAILREPORTD_TEST_PASSWORD
    insecure: true
    interval: 1h
`, filepath.Join(t.TempDir(), "e2e.db"), host, port, username)))
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	// 203.0.113.0/24 is our own sending range; nothing else is.
	resolver := &fakeResolver{txt: map[string][]string{
		"example.org": {"v=spf1 ip4:203.0.113.0/24 -all"},
	}}

	d, err := New(cfg, quiet(), Options{Resolver: resolver, Version: "test"})
	if err != nil {
		t.Fatalf("assemble daemon: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	private := httptest.NewServer(d.PrivateMux())
	public := httptest.NewServer(d.PublicMux())
	t.Cleanup(private.Close)
	t.Cleanup(public.Close)

	return &harness{daemon: d, mailbox: mailbox, private: private, public: public}
}

// poll runs every feeder once and refreshes the metric snapshot, which is what
// the running daemon's loops do on their timers.
func (h *harness) poll(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	for _, f := range h.daemon.Feeders() {
		if _, err := f.Run(ctx); err != nil {
			t.Fatalf("feeder %s: %v", f.Name(), err)
		}
	}
	h.daemon.Refresh(ctx)
}

func (h *harness) get(t *testing.T, server *httptest.Server, path string) (int, string) {
	t.Helper()
	resp, err := http.Get(server.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return resp.StatusCode, string(body)
}

// TestEndToEnd walks the whole path a report actually takes: delivered to a
// real mailbox over IMAP, polled, decoded, parsed, stored, classified against
// SPF, and served as both metrics and JSON.
func TestEndToEnd(t *testing.T) {
	h := newHarness(t)

	h.mailbox.Deliver(t, imaptest.ReportMail(t, "Report Domain: example.org", "google.xml.gz",
		imaptest.AggregateXML("google-1", "example.org", 240, 12)))
	h.mailbox.Deliver(t, imaptest.ReportMail(t, "Report Domain: example.org", "tls.json.gz",
		imaptest.TLSJSON("tls-1", "example.org", 500, 7)))
	h.mailbox.Deliver(t, imaptest.PlainMail("Out of office", "Back Monday."))

	h.poll(t)

	t.Run("liveness on the public listener", func(t *testing.T) {
		code, body := h.get(t, h.public, "/healthz")
		if code != http.StatusOK || strings.TrimSpace(body) != "ok" {
			t.Errorf("healthz = %d %q", code, body)
		}
	})

	t.Run("read api is not on the public listener", func(t *testing.T) {
		// Source addresses describe the whole sending topology; they must not
		// be reachable from outside.
		if code, _ := h.get(t, h.public, "/api/v1/sources"); code != http.StatusNotFound {
			t.Errorf("public /api/v1/sources = %d, want 404", code)
		}
		if code, _ := h.get(t, h.public, "/metrics"); code != http.StatusNotFound {
			t.Errorf("public /metrics = %d, want 404", code)
		}
	})

	t.Run("metrics carry classified aggregates", func(t *testing.T) {
		code, body := h.get(t, h.private, "/metrics")
		if code != http.StatusOK {
			t.Fatalf("metrics = %d", code)
		}

		want := []string{
			// 240 messages from 203.0.113.10, which SPF authorizes.
			`mailreport_dmarc_messages{disposition="none",dkim="pass",domain="example.org",source_class="self",spf="pass",tenant="default"} 240`,
			// 12 from 192.0.2.66, which it does not.
			`mailreport_dmarc_messages{disposition="reject",dkim="fail",domain="example.org",source_class="unknown",spf="fail",tenant="default"} 12`,
			`mailreport_tlsrpt_sessions{domain="example.org",policy_type="sts",result="successful",tenant="default"} 500`,
			`mailreport_tlsrpt_sessions{domain="example.org",policy_type="sts",result="failed",tenant="default"} 7`,
			`mailreport_tlsrpt_failures{domain="example.org",result_type="certificate-expired",tenant="default"} 7`,
			`mailreport_raw_messages{state="quarantined",tenant="default"} 0`,
			`mailreport_raw_messages{state="ignored",tenant="default"} 1`,
			`mailreport_spf_resolvable{domain="example.org",tenant="default"} 1`,
			`mailreport_dmarc_policy{domain="example.org",p="reject",tenant="default"} 1`,
			`mailreport_build_info{version="test"} 1`,
		}
		for _, line := range want {
			if !strings.Contains(body, line) {
				t.Errorf("metrics missing:\n  %s", line)
			}
		}
	})

	t.Run("metrics never carry a source address", func(t *testing.T) {
		_, body := h.get(t, h.private, "/metrics")
		for _, addr := range []string{"203.0.113.10", "192.0.2.66"} {
			if strings.Contains(body, addr) {
				t.Errorf("metrics leak source address %s", addr)
			}
		}
	})

	t.Run("staleness is expressible", func(t *testing.T) {
		_, body := h.get(t, h.private, "/metrics")
		for _, format := range []string{"dmarc_aggregate", "tlsrpt"} {
			needle := fmt.Sprintf(
				`mailreport_report_last_received_timestamp_seconds{domain="example.org",format=%q,tenant="default"}`, format)
			if !strings.Contains(body, needle) {
				t.Errorf("missing last-received series for %s", format)
			}
		}
	})

	t.Run("read api serves per-source detail", func(t *testing.T) {
		code, body := h.get(t, h.private, "/api/v1/sources")
		if code != http.StatusOK {
			t.Fatalf("sources = %d: %s", code, body)
		}

		var payload struct {
			Sources []struct {
				SourceIP string `json:"source_ip"`
				Total    int64  `json:"total"`
				Failing  int64  `json:"failing"`
			} `json:"sources"`
		}
		if err := json.Unmarshal([]byte(body), &payload); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(payload.Sources) != 2 {
			t.Fatalf("sources = %d, want 2", len(payload.Sources))
		}
		// The detail Prometheus refuses to carry is available here, worst first.
		if payload.Sources[0].SourceIP != "192.0.2.66" || payload.Sources[0].Failing != 12 {
			t.Errorf("first source = %+v", payload.Sources[0])
		}
	})

	t.Run("domain summary", func(t *testing.T) {
		code, body := h.get(t, h.private, "/api/v1/domains")
		if code != http.StatusOK {
			t.Fatalf("domains = %d", code)
		}
		var payload struct {
			Domains []struct {
				Domain    string  `json:"domain"`
				Messages  int64   `json:"messages"`
				PassRate  float64 `json:"pass_rate"`
				Policy    string  `json:"policy"`
				TLSFailed int64   `json:"tls_failed"`
			} `json:"domains"`
		}
		if err := json.Unmarshal([]byte(body), &payload); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(payload.Domains) != 1 {
			t.Fatalf("domains = %d", len(payload.Domains))
		}
		d := payload.Domains[0]
		if d.Domain != "example.org" || d.Messages != 252 || d.Policy != "reject" || d.TLSFailed != 7 {
			t.Errorf("summary = %+v", d)
		}
		if d.PassRate < 0.95 {
			t.Errorf("pass rate = %v, want ~0.952", d.PassRate)
		}
	})
}

func TestEndToEndSecondPollIsStable(t *testing.T) {
	h := newHarness(t)
	h.mailbox.Deliver(t, imaptest.ReportMail(t, "r", "a.xml.gz",
		imaptest.AggregateXML("google-1", "example.org", 100, 5)))

	h.poll(t)
	_, first := h.get(t, h.private, "/api/v1/domains")

	// Polling again must change nothing: the mailbox has no new messages, and
	// even if it were rescanned the report is already stored.
	h.poll(t)
	_, second := h.get(t, h.private, "/api/v1/domains")

	firstCount := extractMessages(t, first)
	secondCount := extractMessages(t, second)
	if firstCount != secondCount {
		t.Errorf("message count changed across polls: %d then %d", firstCount, secondCount)
	}
	if firstCount != 105 {
		t.Errorf("messages = %d, want 105", firstCount)
	}
}

func extractMessages(t *testing.T, body string) int64 {
	t.Helper()
	var payload struct {
		Domains []struct {
			Messages int64 `json:"messages"`
		} `json:"domains"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload.Domains) == 0 {
		return 0
	}
	return payload.Domains[0].Messages
}

func TestRunStartsAndStopsCleanly(t *testing.T) {
	h := newHarness(t)
	h.mailbox.Deliver(t, imaptest.ReportMail(t, "r", "a.xml.gz",
		imaptest.AggregateXML("google-1", "example.org", 10, 1)))

	// Bind the real listeners on ephemeral ports.
	h.daemon.cfg.HTTP.Listen = "127.0.0.1:0"
	h.daemon.cfg.HTTP.MetricsListen = "127.0.0.1:0"

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.daemon.Run(ctx) }()

	// The first feeder pass happens immediately on start, so the report should
	// land without waiting for the poll interval.
	deadline := time.After(10 * time.Second)
	for {
		if extractMessages(t, mustGet(t, h)) == 11 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("report was not ingested within the deadline")
		case <-time.After(20 * time.Millisecond):
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("daemon did not shut down")
	}
}

// TestTLSRPTSubmissionGate: /tlsrpt exists on the public listener only when
// the operator enabled it, and an enabled endpoint stores what it accepts.
func TestTLSRPTSubmissionGate(t *testing.T) {
	// Default harness: submission off, the path must not exist.
	h := newHarness(t)
	resp, err := http.Post(h.public.URL+"/tlsrpt", "application/tlsrpt+json",
		strings.NewReader(imaptest.TLSJSON("t-off", "example.org", 5, 0)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled endpoint answered %d, want 404", resp.StatusCode)
	}

	// Enabled: the same POST lands in the store.
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
log:
  level: error
http:
  tlsrpt_submission: true
storage:
  path: %q
tenants:
  - id: default
    domains: [example.org]
`, filepath.Join(t.TempDir(), "submit.db"))))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	d, err := New(cfg, quiet(), Options{Version: "test"})
	if err != nil {
		t.Fatalf("assemble daemon: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	public := httptest.NewServer(d.PublicMux())
	t.Cleanup(public.Close)

	resp, err = http.Post(public.URL+"/tlsrpt", "application/tlsrpt+json",
		strings.NewReader(imaptest.TLSJSON("t-on", "example.org", 7, 1)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("enabled endpoint answered %d, want 201", resp.StatusCode)
	}
	tls, err := d.Stores()["default"].TLSSummaries(context.Background(), time.Now().Add(-30*24*time.Hour))
	if err != nil || len(tls) != 1 || tls[0].Successful != 7 || tls[0].Failed != 1 {
		t.Fatalf("tls summaries = %+v err = %v", tls, err)
	}
}

func mustGet(t *testing.T, h *harness) string {
	t.Helper()
	_, body := h.get(t, h.private, "/api/v1/domains")
	return body
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
