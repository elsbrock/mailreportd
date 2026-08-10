package metrics

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/elsbrock/mailreportd/internal/classify"
	"github.com/elsbrock/mailreportd/internal/policy"
	"github.com/elsbrock/mailreportd/internal/store"
)

type fakeResolver struct{ txt map[string][]string }

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if r, ok := f.txt[name]; ok {
		return r, nil
	}
	return nil, fmt.Errorf("no such host")
}
func (f *fakeResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return nil, fmt.Errorf("no such host")
}
func (f *fakeResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	return nil, fmt.Errorf("no such host")
}

// aggregateXML reports yesterday's window, so the fixture stays inside the
// collector's aggregation window no matter when the suite runs. Hardcoded
// timestamps would silently stop matching as the calendar moved.
func aggregateXML() string {
	end := time.Now().Add(-12 * time.Hour)
	begin := end.Add(-24 * time.Hour)

	return fmt.Sprintf(`<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>google.com</org_name><report_id>1</report_id>
    <date_range><begin>%d</begin><end>%d</end></date_range></report_metadata>
  <policy_published><domain>example.org</domain><p>reject</p><pct>100</pct></policy_published>
  <record><row><source_ip>203.0.113.10</source_ip><count>100</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>example.org</header_from></identifiers></record>
  <record><row><source_ip>198.51.100.9</source_ip><count>7</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.org</header_from></identifiers></record>
  <record><row><source_ip>192.0.2.66</source_ip><count>4</count>
    <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.org</header_from></identifiers></record>
</feedback>`, begin.Unix(), end.Unix())
}

func message(t *testing.T, filename, payload string) []byte {
	t.Helper()
	var gzbuf bytes.Buffer
	zw := gzip.NewWriter(&gzbuf)
	zw.Write([]byte(payload))
	zw.Close()

	var b strings.Builder
	b.WriteString("From: r@google.com\r\nTo: dmarc@example.org\r\nSubject: report\r\n")
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"SEP\"\r\n\r\n")
	b.WriteString("--SEP\r\n")
	fmt.Fprintf(&b, "Content-Type: application/gzip; name=%q\r\n", filename)
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	b.WriteString(base64.StdEncoding.EncodeToString(gzbuf.Bytes()))
	b.WriteString("\r\n\r\n--SEP--\r\n")
	return []byte(b.String())
}

func setup(t *testing.T) (*Collector, *prometheus.Registry) {
	t.Helper()

	db, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	s := db.Tenant("default")
	if _, err := s.Ingest(context.Background(), store.RawMessage{
		Feeder: "test", Received: time.Now(), Body: message(t, "r.xml.gz", aggregateXML()),
	}); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	// 203.0.113.0/24 is ours; the other two sources are not.
	resolver := &fakeResolver{txt: map[string][]string{
		"example.org": {"v=spf1 ip4:203.0.113.0/24 -all"},
	}}
	c := NewCollector(
		[]Tenant{{ID: "default", Store: s, Domains: []string{"example.org"}}},
		classify.New(resolver, time.Minute, nil),
		nil, // these tests cover report aggregation, not published policy
		30*24*time.Hour,
		nil,
	)
	c.Refresh(context.Background())

	reg := prometheus.NewRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("register: %v", err)
	}
	return c, reg
}

func TestCollectorClassifiesSources(t *testing.T) {
	_, reg := setup(t)

	expected := `
# HELP mailreport_dmarc_messages Messages reported in the aggregation window, by evaluation outcome and source class.
# TYPE mailreport_dmarc_messages gauge
mailreport_dmarc_messages{disposition="none",dkim="pass",domain="example.org",source_class="forwarder",spf="fail",tenant="default"} 7
mailreport_dmarc_messages{disposition="none",dkim="pass",domain="example.org",source_class="self",spf="pass",tenant="default"} 100
mailreport_dmarc_messages{disposition="reject",dkim="fail",domain="example.org",source_class="unknown",spf="fail",tenant="default"} 4
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "mailreport_dmarc_messages"); err != nil {
		t.Error(err)
	}
}

func TestCollectorNeverLabelsSourceAddresses(t *testing.T) {
	_, reg := setup(t)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	// The single rule this package exists to enforce. A regression here would
	// not fail loudly; it would quietly melt the time series database weeks
	// later, so it is asserted directly.
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				value := label.GetValue()
				if strings.Contains(value, "203.0.113.10") ||
					strings.Contains(value, "198.51.100.9") ||
					strings.Contains(value, "192.0.2.66") {
					t.Errorf("metric %q leaks a source address in label %q=%q",
						family.GetName(), label.GetName(), value)
				}
			}
		}
	}
}

func TestCollectorEmitsZeroStates(t *testing.T) {
	_, reg := setup(t)

	// An absent series cannot be alerted on. Quarantine must report zero rather
	// than not reporting.
	expected := `
# HELP mailreport_raw_messages Messages seen by the ingest pipeline, by outcome state.
# TYPE mailreport_raw_messages gauge
mailreport_raw_messages{state="ignored",tenant="default"} 0
mailreport_raw_messages{state="parsed",tenant="default"} 1
mailreport_raw_messages{state="quarantined",tenant="default"} 0
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "mailreport_raw_messages"); err != nil {
		t.Error(err)
	}
}

func TestCollectorReportsSPFHealth(t *testing.T) {
	_, reg := setup(t)

	expected := `
# HELP mailreport_spf_lookups DNS-querying mechanisms consumed by the domain's SPF record.
# TYPE mailreport_spf_lookups gauge
mailreport_spf_lookups{domain="example.org",tenant="default"} 0
# HELP mailreport_spf_lookup_limit_exceeded 1 when the domain's SPF record needs more than the RFC 7208 limit of ten DNS lookups.
# TYPE mailreport_spf_lookup_limit_exceeded gauge
mailreport_spf_lookup_limit_exceeded{domain="example.org",tenant="default"} 0
# HELP mailreport_spf_resolvable 1 when the domain's SPF record could be resolved.
# TYPE mailreport_spf_resolvable gauge
mailreport_spf_resolvable{domain="example.org",tenant="default"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected),
		"mailreport_spf_lookups", "mailreport_spf_lookup_limit_exceeded", "mailreport_spf_resolvable"); err != nil {
		t.Error(err)
	}
}

func TestCollectorReportsStaleness(t *testing.T) {
	_, reg := setup(t)

	value := testutil.ToFloat64(mustCollect(t, reg, "mailreport_report_last_received_timestamp_seconds"))
	if value <= 0 {
		t.Errorf("last received timestamp = %v, want a real unix time", value)
	}
}

// mustCollect adapts a gathered family back into something ToFloat64 accepts.
func mustCollect(t *testing.T, reg *prometheus.Registry, name string) prometheus.Collector {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		if len(family.GetMetric()) != 1 {
			t.Fatalf("%s has %d series, want 1", name, len(family.GetMetric()))
		}
		gauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe"})
		gauge.Set(family.GetMetric()[0].GetGauge().GetValue())
		return gauge
	}
	t.Fatalf("metric %q not found", name)
	return nil
}

func TestCollectorSurvivesUnresolvableSPF(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	s := db.Tenant("default")
	if _, err := s.Ingest(context.Background(), store.RawMessage{
		Feeder: "test", Received: time.Now(), Body: message(t, "r.xml.gz", aggregateXML()),
	}); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	// No SPF record at all. Everything must still export, with sources falling
	// back to unknown rather than the refresh aborting.
	c := NewCollector(
		[]Tenant{{ID: "default", Store: s, Domains: []string{"example.org"}}},
		classify.New(&fakeResolver{txt: map[string][]string{}}, time.Minute, nil),
		nil, // as above: no policy checker in this fixture
		30*24*time.Hour, nil,
	)
	c.Refresh(context.Background())

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	count, err := testutil.GatherAndCount(reg, "mailreport_dmarc_messages")
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if count == 0 {
		t.Error("dmarc series disappeared when SPF was unresolvable")
	}

	expected := `
# HELP mailreport_spf_resolvable 1 when the domain's SPF record could be resolved.
# TYPE mailreport_spf_resolvable gauge
mailreport_spf_resolvable{domain="example.org",tenant="default"} 0
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "mailreport_spf_resolvable"); err != nil {
		t.Error(err)
	}
}

// policyResolver answers absent names with a real NXDOMAIN. The published-policy
// checks depend on that distinction: "no such record" is a verdict about the
// domain, while any other resolver error means the check could not be made.
type policyResolver struct {
	txt map[string][]string
	err map[string]error
}

func (p *policyResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	name = strings.TrimSuffix(name, ".")
	if err, ok := p.err[name]; ok {
		return nil, err
	}
	if r, ok := p.txt[name]; ok {
		return r, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (p *policyResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}

func (p *policyResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func policyCollector(t *testing.T, resolver *policyResolver, selectors map[string][]string) *prometheus.Registry {
	t.Helper()

	db, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	c := NewCollector(
		[]Tenant{{ID: "default", Store: db.Tenant("default"), Domains: []string{"example.org"}}},
		classify.New(resolver, time.Minute, nil),
		policy.New(resolver, nil, time.Minute, selectors),
		30*24*time.Hour, nil,
	)
	c.Refresh(context.Background())

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	return reg
}

func TestPolicyMetricsExported(t *testing.T) {
	reg := policyCollector(t, &policyResolver{txt: map[string][]string{
		"_dmarc.example.org":         {"v=DMARC1; p=reject; pct=100; rua=mailto:d@example.org"},
		"sel._domainkey.example.org": {"v=DKIM1; k=rsa; p="},
	}}, map[string][]string{"example.org": {"sel"}})

	for _, name := range []string{
		"mailreport_dmarc_record_valid",
		"mailreport_dmarc_record_policy",
		"mailreport_dmarc_record_pct",
		"mailreport_dkim_record_state",
		"mailreport_policy_check_timestamp_seconds",
	} {
		count, err := testutil.GatherAndCount(reg, name)
		if err != nil {
			t.Fatalf("gather %s: %v", name, err)
		}
		if count == 0 {
			t.Errorf("%s: no series exported", name)
		}
	}

	// The selector is published but revoked, which must not read as missing.
	expected := `
# HELP mailreport_dkim_record_state Published DKIM selector state as a label set with value 1: missing, revoked, malformed, weak or ok.
# TYPE mailreport_dkim_record_state gauge
mailreport_dkim_record_state{domain="example.org",selector="sel",state="revoked",tenant="default"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "mailreport_dkim_record_state"); err != nil {
		t.Error(err)
	}
}

// A check that could not complete must leave the verdict series absent rather
// than exporting a zero. A zero here would page someone about a policy that is
// most likely fine, on the strength of a resolver hiccup.
func TestIncompletePolicyCheckEmitsNoVerdict(t *testing.T) {
	reg := policyCollector(t, &policyResolver{
		err: map[string]error{
			"_dmarc.example.org": &net.DNSError{Err: "server misbehaving", IsTemporary: true},
		},
	}, nil)

	count, err := testutil.GatherAndCount(reg, "mailreport_dmarc_record_valid")
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if count != 0 {
		t.Errorf("mailreport_dmarc_record_valid: %d series, want none for an incomplete check", count)
	}

	count, err = testutil.GatherAndCount(reg, "mailreport_policy_check_errors_total")
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if count != 1 {
		t.Errorf("mailreport_policy_check_errors_total: %d series, want 1", count)
	}
}
