package store

import (
	"context"
	"testing"
	"time"
)

// The two fixtures together: Google reports 15 messages (12 clean, 3 failing),
// Outlook.com reports 14 that all pass DMARC, 4 of them on SPF alone.
func reporterStore(t *testing.T) *Store {
	t.Helper()
	s := testStore(t)
	ingest(t, s, aggregateMessage(t))
	ingest(t, s, dkimOnlyAggregateMessage(t))
	return s
}

func TestSourcesSplitDKIMFromSPF(t *testing.T) {
	s := reporterStore(t)

	sources, err := s.Sources(context.Background(), time.Time{}, "", "", 100)
	if err != nil {
		t.Fatalf("sources: %v", err)
	}
	ours := findSource(t, sources, "2001:db8:98c0::103")

	// Every message passed DMARC, which is exactly why Passing alone hid the
	// four lost signatures.
	if ours.Total != 26 || ours.Passing != 26 || ours.Failing != 0 {
		t.Errorf("ours = %+v, want 26 total, all passing", ours)
	}
	if ours.DKIMPass != 22 || ours.SPFPass != 26 {
		t.Errorf("dkim_pass = %d spf_pass = %d, want 22 and 26", ours.DKIMPass, ours.SPFPass)
	}
}

func TestSourcesFilterByReporter(t *testing.T) {
	s := reporterStore(t)

	// Matching is on the normalized name, whatever case the caller uses.
	sources, err := s.Sources(context.Background(), time.Time{}, "", "OUTLOOK.com", 100)
	if err != nil {
		t.Fatalf("sources: %v", err)
	}
	if len(sources) != 1 {
		t.Fatalf("got %d sources, want only the one Outlook.com reported: %+v", len(sources), sources)
	}
	if sources[0].Total != 14 || sources[0].DKIMPass != 10 {
		t.Errorf("outlook view = %+v, want 14 total and 10 dkim_pass", sources[0])
	}
}

func TestDomainSummariesSplitDKIMFromSPF(t *testing.T) {
	s := reporterStore(t)

	summaries, err := s.DomainSummaries(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("summaries: %v", err)
	}
	d := summaries[0]
	if d.DKIMPass != 22 || d.SPFPass != 26 {
		t.Errorf("dkim_pass = %d spf_pass = %d, want 22 and 26", d.DKIMPass, d.SPFPass)
	}
}

func TestReporters(t *testing.T) {
	s := reporterStore(t)

	reporters, omitted, err := s.Reporters(context.Background(), time.Time{}, "", 100)
	if err != nil {
		t.Fatalf("reporters: %v", err)
	}
	if len(reporters) != 2 {
		t.Fatalf("got %d reporters, want 2: %+v", len(reporters), reporters)
	}
	if omitted.Reporters != 0 || omitted.Messages != 0 {
		t.Errorf("omitted = %+v, want zero", omitted)
	}

	google, outlook := reporters[0], reporters[1]
	if google.Reporter != "google.com" || google.Total != 15 || google.Failing != 3 || google.Reports != 1 {
		t.Errorf("google = %+v", google)
	}
	// Normalized: " Outlook.com " groups as outlook.com.
	if outlook.Reporter != "outlook.com" {
		t.Errorf("reporter = %q, want outlook.com", outlook.Reporter)
	}
	if outlook.Total != 14 || outlook.Passing != 14 || outlook.DKIMPass != 10 || outlook.SPFPass != 14 {
		t.Errorf("outlook = %+v, want 14 passing with 10 dkim_pass", outlook)
	}
}

func TestReportersReportTheRemainderItCutOff(t *testing.T) {
	s := reporterStore(t)

	reporters, omitted, err := s.Reporters(context.Background(), time.Time{}, "", 1)
	if err != nil {
		t.Fatalf("reporters: %v", err)
	}
	if len(reporters) != 1 || reporters[0].Reporter != "google.com" {
		t.Fatalf("reporters = %+v, want google.com only", reporters)
	}
	if omitted.Reporters != 1 || omitted.Messages != 14 {
		t.Errorf("omitted = %+v, want 1 reporter and 14 messages", omitted)
	}
}

func TestSignersBreakDownByDay(t *testing.T) {
	s := reporterStore(t)

	signers, _, err := s.Signers(context.Background(), time.Time{}, "", "", 100)
	if err != nil {
		t.Fatalf("signers: %v", err)
	}
	ours := find(t, signers, "example.org", "selector1")
	if ours.Messages != 26 {
		t.Errorf("messages = %d, want 26", ours.Messages)
	}

	// Google's window ends 23:59:59 on the 1st; Outlook's ends at midnight
	// after the 2nd and belongs to the 2nd, not the 3rd.
	want := []SignerDay{
		{Day: "2025-08-01", Messages: 12, SignaturePass: 12, EvaluatedPass: 12},
		{Day: "2025-08-02", Messages: 14, SignaturePass: 10, EvaluatedPass: 10},
	}
	if len(ours.Days) != len(want) {
		t.Fatalf("days = %+v, want %+v", ours.Days, want)
	}
	for i := range want {
		if ours.Days[i] != want[i] {
			t.Errorf("day %d = %+v, want %+v", i, ours.Days[i], want[i])
		}
	}
}

func TestSignerDaysCoverOnlyTheLimit(t *testing.T) {
	s := testStore(t)
	ingest(t, s, relayedAggregateMessage(t))

	signers, _, err := s.Signers(context.Background(), time.Time{}, "", "", 1)
	if err != nil {
		t.Fatalf("signers: %v", err)
	}
	if len(signers) != 1 || len(signers[0].Days) != 1 || signers[0].Days[0].Messages != 9 {
		t.Errorf("signers = %+v, want the relay alone with one 9-message day", signers)
	}
}

func TestSignersFilterByReporter(t *testing.T) {
	s := reporterStore(t)

	signers, _, err := s.Signers(context.Background(), time.Time{}, "", "outlook.com", 100)
	if err != nil {
		t.Fatalf("signers: %v", err)
	}
	ours := find(t, signers, "example.org", "selector1")
	if ours.Messages != 14 || len(ours.Days) != 1 {
		t.Errorf("outlook view = %+v, want 14 messages on one day", ours)
	}
}

func findSource(t *testing.T, in []SourceDetail, ip string) SourceDetail {
	t.Helper()
	for _, s := range in {
		if s.SourceIP == ip {
			return s
		}
	}
	t.Fatalf("no source %s in %+v", ip, in)
	return SourceDetail{}
}
