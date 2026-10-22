package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db.Tenant("default")
}

func ingest(t *testing.T, s *Store, body []byte) IngestResult {
	t.Helper()
	res, err := s.Ingest(context.Background(), RawMessage{
		Feeder:    "test",
		SourceRef: "1",
		Received:  time.Now(),
		Body:      body,
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	return res
}

func TestIngestStoresReport(t *testing.T) {
	s := testStore(t)
	res := ingest(t, s, aggregateMessage(t))

	if res.State != StateParsed {
		t.Errorf("state = %q, want %q", res.State, StateParsed)
	}
	if res.Stored != 1 {
		t.Errorf("stored = %d, want 1", res.Stored)
	}

	sources, err := s.DMARCSources(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("sources: %v", err)
	}
	var total int64
	for _, src := range sources {
		total += src.Count
	}
	if total != 15 {
		t.Errorf("total messages = %d, want 15", total)
	}
}

func TestIngestIsIdempotentOnBytes(t *testing.T) {
	s := testStore(t)
	body := aggregateMessage(t)

	first := ingest(t, s, body)
	second := ingest(t, s, body)

	if first.Duplicate {
		t.Error("first ingest should not be a duplicate")
	}
	if !second.Duplicate {
		t.Error("second ingest of identical bytes should be a duplicate")
	}
	if second.Stored != 0 {
		t.Errorf("second ingest stored %d reports, want 0", second.Stored)
	}

	// Reprocessing a whole mailbox must not double the counts. This is the
	// documented recovery path, so it has to be safe.
	sources, err := s.DMARCSources(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("sources: %v", err)
	}
	var total int64
	for _, src := range sources {
		total += src.Count
	}
	if total != 15 {
		t.Errorf("total after reprocess = %d, want 15", total)
	}
}

func TestIngestIsIdempotentOnReportIdentity(t *testing.T) {
	s := testStore(t)

	// The same report delivered under two different envelopes: different bytes,
	// so the checksum differs, but it is the same report and must not be
	// counted twice.
	first := ingest(t, s, aggregateMessageWithSubject(t, "Report Domain: example.org"))
	second := ingest(t, s, aggregateMessageWithSubject(t, "FW: Report Domain: example.org"))

	if first.Stored != 1 {
		t.Fatalf("first stored = %d, want 1", first.Stored)
	}
	if second.Duplicate {
		t.Error("different bytes should not be a byte-level duplicate")
	}
	if second.Stored != 0 || second.Skipped != 1 {
		t.Errorf("second: stored = %d skipped = %d, want 0 and 1", second.Stored, second.Skipped)
	}
	if first.Redundant() {
		t.Error("first ingest should not be redundant")
	}
	if !second.Redundant() {
		t.Error("a resent report under a new envelope should be redundant")
	}

	sources, _ := s.DMARCSources(context.Background(), time.Time{})
	var total int64
	for _, src := range sources {
		total += src.Count
	}
	if total != 15 {
		t.Errorf("total = %d, want 15 (report counted once)", total)
	}
}

func TestIngestQuarantinesUnparseable(t *testing.T) {
	s := testStore(t)

	// Looks like a report (gzip attachment named .xml.gz) but is not one.
	body := brokenReportMessage(t)
	res := ingest(t, s, body)

	if res.State != StateQuarantined {
		t.Errorf("state = %q, want %q", res.State, StateQuarantined)
	}

	entries, err := s.Quarantine(context.Background(), 10)
	if err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("quarantine entries = %d, want 1", len(entries))
	}
	if entries[0].Error == "" {
		t.Error("quarantine entry should record why it failed")
	}
	// The body must be retained, or the failure cannot be diagnosed and the
	// message cannot be reprocessed once the parser is fixed.
	if entries[0].Size == 0 {
		t.Error("quarantined message body should be retained")
	}
}

func TestIngestIgnoresNonReports(t *testing.T) {
	s := testStore(t)

	res := ingest(t, s, []byte("From: a@b.example\r\nSubject: Out of office\r\n\r\nAway.\r\n"))
	if res.State != StateIgnored {
		t.Errorf("state = %q, want %q", res.State, StateIgnored)
	}

	// Autoreplies must not land in quarantine, or quarantine fills with noise
	// and stops being a signal worth alerting on.
	entries, _ := s.Quarantine(context.Background(), 10)
	if len(entries) != 0 {
		t.Errorf("quarantine entries = %d, want 0", len(entries))
	}
}

func TestTenantIsolation(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	a := db.Tenant("a")
	b := db.Tenant("b")

	ingest(t, a, aggregateMessage(t))

	aSources, _ := a.DMARCSources(context.Background(), time.Time{})
	if len(aSources) == 0 {
		t.Fatal("tenant a should see its own report")
	}
	bSources, _ := b.DMARCSources(context.Background(), time.Time{})
	if len(bSources) != 0 {
		t.Errorf("tenant b sees %d sources from tenant a", len(bSources))
	}

	// The same report must be storable under a second tenant: two customers can
	// legitimately receive reports about domains they both monitor.
	res := ingest(t, b, aggregateMessage(t))
	if res.Stored != 1 {
		t.Errorf("tenant b stored = %d, want 1", res.Stored)
	}
}

func TestTLSReportIngest(t *testing.T) {
	s := testStore(t)

	res := ingest(t, s, tlsMessage(t))
	if res.Stored != 1 {
		t.Fatalf("stored = %d, want 1", res.Stored)
	}

	summaries, err := s.TLSSummaries(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("tls summaries: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("summaries = %d, want 1", len(summaries))
	}
	if summaries[0].Successful != 412 || summaries[0].Failed != 3 {
		t.Errorf("summary = %+v", summaries[0])
	}

	failures, err := s.TLSFailures(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("tls failures: %v", err)
	}
	if len(failures) != 1 || failures[0].ResultType != "certificate-expired" || failures[0].Count != 3 {
		t.Errorf("failures = %+v", failures)
	}
}

func TestSweepKeepsQuarantine(t *testing.T) {
	s := testStore(t)
	ingest(t, s, aggregateMessage(t))
	ingest(t, s, brokenReportMessage(t))

	// Sweep everything older than an instant ago.
	res, err := s.Sweep(context.Background(), Retention{
		Raw:       time.Nanosecond,
		Aggregate: 365 * 24 * time.Hour,
	}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	_ = res

	// Quarantined evidence must survive a retention sweep: it exists precisely
	// because something needs fixing.
	entries, _ := s.Quarantine(context.Background(), 10)
	if len(entries) != 1 {
		t.Fatalf("quarantine entries = %d, want 1", len(entries))
	}
	if entries[0].Size == 0 {
		t.Error("sweep discarded a quarantined body")
	}
}

func TestSweepDeletesExpiredReports(t *testing.T) {
	s := testStore(t)
	ingest(t, s, aggregateMessage(t))

	// The fixture's window ends in August 2026; sweep with a now far beyond it.
	if _, err := s.Sweep(context.Background(), Retention{
		Raw:       time.Hour,
		Aggregate: time.Hour,
	}, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	sources, _ := s.DMARCSources(context.Background(), time.Time{})
	if len(sources) != 0 {
		t.Errorf("sources after expiry sweep = %d, want 0", len(sources))
	}
}

func TestDomainSummaries(t *testing.T) {
	s := testStore(t)
	ingest(t, s, aggregateMessage(t))
	ingest(t, s, tlsMessage(t))

	summaries, err := s.DomainSummaries(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("summaries: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("summaries = %d, want 1", len(summaries))
	}

	d := summaries[0]
	if d.Domain != "example.org" {
		t.Errorf("domain = %q", d.Domain)
	}
	if d.Messages != 15 || d.Passing != 12 || d.Failing != 3 {
		t.Errorf("counts = %+v", d)
	}
	if d.Policy != "reject" {
		t.Errorf("policy = %q, want reject", d.Policy)
	}
	if d.TLSSuccessful != 412 || d.TLSFailed != 3 {
		t.Errorf("tls = %d/%d", d.TLSSuccessful, d.TLSFailed)
	}
	if d.PassRate < 0.79 || d.PassRate > 0.81 {
		t.Errorf("pass rate = %v, want ~0.8", d.PassRate)
	}
}

func TestLastReports(t *testing.T) {
	s := testStore(t)
	ingest(t, s, aggregateMessage(t))

	last, err := s.LastReports(context.Background())
	if err != nil {
		t.Fatalf("last reports: %v", err)
	}
	if len(last) != 1 {
		t.Fatalf("last reports = %d, want 1", len(last))
	}
	if last[0].Received.IsZero() {
		t.Error("received timestamp should be set")
	}
}

func TestMigrationsAreIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	db, err := Open(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	ingest(t, db.Tenant("default"), aggregateMessage(t))
	db.Close()

	// Reopening must not re-run migrations or lose data.
	db, err = Open(path)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer db.Close()

	sources, err := db.Tenant("default").DMARCSources(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("sources: %v", err)
	}
	if len(sources) == 0 {
		t.Error("data lost across reopen")
	}
}
