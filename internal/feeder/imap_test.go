package feeder

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/elsbrock/mailreportd/internal/imaptest"
	"github.com/elsbrock/mailreportd/internal/store"
)

// feederConfig points a feeder at a test mailbox.
func feederConfig(t *testing.T, m *imaptest.Mailbox, name, tenant string) IMAPConfig {
	t.Helper()
	host, port := m.HostPort(t)
	username, password := m.Credentials()
	return IMAPConfig{
		Name:     name,
		Tenant:   tenant,
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
		Mailbox:  "INBOX",
		Interval: time.Minute,
		Insecure: true,
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "feeder.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db.Tenant("default")
}

func TestIMAPFeederIngestsReports(t *testing.T) {
	mailbox := imaptest.NewMailbox(t)
	s := testStore(t)

	mailbox.Deliver(t, imaptest.ReportMail(t, "Report Domain: example.org", "a.xml.gz",
		imaptest.AggregateXML("report-a", "example.org", 100, 4)))
	mailbox.Deliver(t, imaptest.ReportMail(t, "Report Domain: example.org TLS", "b.json.gz",
		imaptest.TLSJSON("tls-a", "example.org", 412, 3)))

	f := NewIMAP(feederConfig(t, mailbox, "mailbox", "default"), s, quietLogger())

	stats, err := f.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if stats.Messages != 2 || stats.Reports != 2 {
		t.Fatalf("stats = %+v, want 2 messages and 2 reports", stats)
	}

	summaries, err := s.DomainSummaries(context.Background(), time.Now().Add(-30*24*time.Hour))
	if err != nil {
		t.Fatalf("summaries: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("domains = %d, want 1", len(summaries))
	}
	d := summaries[0]
	if d.Messages != 104 || d.Passing != 100 || d.Failing != 4 {
		t.Errorf("dmarc counts = %+v", d)
	}
	if d.TLSSuccessful != 412 || d.TLSFailed != 3 {
		t.Errorf("tls counts = %d/%d", d.TLSSuccessful, d.TLSFailed)
	}
}

func TestIMAPFeederIsIncremental(t *testing.T) {
	mailbox := imaptest.NewMailbox(t)
	s := testStore(t)
	f := NewIMAP(feederConfig(t, mailbox, "mailbox", "default"), s, quietLogger())
	ctx := context.Background()

	mailbox.Deliver(t, imaptest.ReportMail(t, "r1", "a.xml.gz", imaptest.AggregateXML("report-a", "example.org", 10, 1)))
	if stats, err := f.Run(ctx); err != nil || stats.Messages != 1 {
		t.Fatalf("first run: stats = %+v err = %v", stats, err)
	}

	// A second pass with nothing new must not refetch anything.
	stats, err := f.Run(ctx)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if stats.Messages != 0 {
		t.Errorf("second run fetched %d messages, want 0", stats.Messages)
	}

	// A new arrival is picked up, and only that one.
	mailbox.Deliver(t, imaptest.ReportMail(t, "r2", "b.xml.gz", imaptest.AggregateXML("report-b", "example.org", 20, 2)))
	stats, err = f.Run(ctx)
	if err != nil {
		t.Fatalf("third run: %v", err)
	}
	if stats.Messages != 1 || stats.Reports != 1 {
		t.Errorf("third run stats = %+v, want exactly the new message", stats)
	}

	summaries, _ := s.DomainSummaries(ctx, time.Now().Add(-30*24*time.Hour))
	if summaries[0].Messages != 33 {
		t.Errorf("total messages = %d, want 33", summaries[0].Messages)
	}
}

func TestIMAPFeederDoesNotMarkMessagesRead(t *testing.T) {
	mailbox := imaptest.NewMailbox(t)
	s := testStore(t)

	mailbox.Deliver(t, imaptest.ReportMail(t, "r1", "a.xml.gz", imaptest.AggregateXML("report-a", "example.org", 10, 1)))

	f := NewIMAP(feederConfig(t, mailbox, "mailbox", "default"), s, quietLogger())
	if _, err := f.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	// The mailbox may well be one a human also reads. Ingesting a report must
	// not silently mark it seen.
	username, password := mailbox.Credentials()
	client, err := imapclient.DialInsecure(mailbox.Addr(), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	if err := client.Login(username, password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := client.Select("INBOX", &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
		t.Fatalf("select: %v", err)
	}

	messages, err := client.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	if err != nil {
		t.Fatalf("fetch flags: %v", err)
	}
	for _, flag := range messages[0].Flags {
		if flag == imap.FlagSeen {
			t.Error("feeder marked the message as seen; it must peek")
		}
	}
}

func TestIMAPFeederIsIdempotentAcrossCursorReset(t *testing.T) {
	mailbox := imaptest.NewMailbox(t)
	s := testStore(t)
	cfg := feederConfig(t, mailbox, "mailbox", "default")
	ctx := context.Background()

	mailbox.Deliver(t, imaptest.ReportMail(t, "r1", "a.xml.gz", imaptest.AggregateXML("report-a", "example.org", 10, 1)))
	mailbox.Deliver(t, imaptest.ReportMail(t, "r2", "b.xml.gz", imaptest.AggregateXML("report-b", "example.org", 20, 2)))

	if _, err := NewIMAP(cfg, s, quietLogger()).Run(ctx); err != nil {
		t.Fatalf("first run: %v", err)
	}

	// Simulate a UIDVALIDITY change, or an operator wiping the cursor to force
	// a rescan. The whole mailbox is reprocessed and nothing is double counted.
	if err := s.SetCursor(ctx, "mailbox", store.Cursor{}); err != nil {
		t.Fatalf("reset cursor: %v", err)
	}

	stats, err := NewIMAP(cfg, s, quietLogger()).Run(ctx)
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if stats.Messages != 2 {
		t.Errorf("rescan fetched %d messages, want 2", stats.Messages)
	}
	if stats.Duplicate != 2 {
		t.Errorf("rescan recorded %d duplicates, want 2", stats.Duplicate)
	}
	if stats.Reports != 0 {
		t.Errorf("rescan stored %d reports, want 0", stats.Reports)
	}

	summaries, _ := s.DomainSummaries(ctx, time.Now().Add(-30*24*time.Hour))
	if summaries[0].Messages != 33 {
		t.Errorf("total after rescan = %d, want 33: reprocessing must be safe", summaries[0].Messages)
	}
}

func TestIMAPFeederHandlesNonReports(t *testing.T) {
	mailbox := imaptest.NewMailbox(t)
	s := testStore(t)
	ctx := context.Background()

	// A realistic mailbox: one real report among autoreplies and spam.
	mailbox.Deliver(t, imaptest.PlainMail("Out of office", "Back on Monday."))
	mailbox.Deliver(t, imaptest.ReportMail(t, "r1", "a.xml.gz", imaptest.AggregateXML("report-a", "example.org", 10, 1)))
	mailbox.Deliver(t, imaptest.PlainMail("Undelivered Mail Returned to Sender", "550 no such user"))

	stats, err := NewIMAP(feederConfig(t, mailbox, "mailbox", "default"), s, quietLogger()).Run(ctx)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if stats.Messages != 3 {
		t.Errorf("messages = %d, want 3", stats.Messages)
	}
	if stats.Reports != 1 {
		t.Errorf("reports = %d, want 1", stats.Reports)
	}
	if stats.Ignored != 2 {
		t.Errorf("ignored = %d, want 2", stats.Ignored)
	}
	if stats.Quarantine != 0 {
		t.Errorf("quarantined = %d, want 0: noise is not a parse failure", stats.Quarantine)
	}
}

func TestIMAPFeederQuarantinesBrokenReports(t *testing.T) {
	mailbox := imaptest.NewMailbox(t)
	s := testStore(t)
	ctx := context.Background()

	broken := `<feedback><report_metadata><org_name>broken.example</org_name>
		<report_id>9</report_id><date_range><begin>1</begin><end>2</end></date_range>
		</report_metadata><policy_published><domain>example.org</domain></policy_published></feedback>`
	mailbox.Deliver(t, imaptest.ReportMail(t, "broken", "broken.xml.gz", broken))

	stats, err := NewIMAP(feederConfig(t, mailbox, "mailbox", "default"), s, quietLogger()).Run(ctx)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if stats.Quarantine != 1 {
		t.Errorf("quarantined = %d, want 1", stats.Quarantine)
	}

	entries, err := s.Quarantine(ctx, 10)
	if err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].SourceRef == "" {
		t.Error("quarantine entry should record which message failed")
	}
	if entries[0].Size == 0 {
		t.Error("quarantine entry should retain the body for diagnosis")
	}
}

func TestIMAPFeederAdvancesPastUnparseableMessages(t *testing.T) {
	mailbox := imaptest.NewMailbox(t)
	s := testStore(t)
	ctx := context.Background()
	cfg := feederConfig(t, mailbox, "mailbox", "default")

	mailbox.Deliver(t, imaptest.ReportMail(t, "broken", "broken.xml.gz", "not xml at all"))
	if _, err := NewIMAP(cfg, s, quietLogger()).Run(ctx); err != nil {
		t.Fatalf("first run: %v", err)
	}

	// A message that cannot be parsed must not wedge the cursor and cause the
	// same message to be refetched on every pass forever.
	stats, err := NewIMAP(cfg, s, quietLogger()).Run(ctx)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if stats.Messages != 0 {
		t.Errorf("second run refetched %d messages; the cursor did not advance", stats.Messages)
	}
}

func TestIMAPFeederReportsUnreachableMailbox(t *testing.T) {
	s := testStore(t)
	f := NewIMAP(IMAPConfig{
		Name: "mailbox", Tenant: "default",
		Host: "127.0.0.1", Port: 1, Username: "u", Password: "p",
		Interval: time.Minute, Insecure: true,
	}, s, quietLogger())

	if _, err := f.Run(context.Background()); err == nil {
		t.Fatal("expected an error for an unreachable mailbox")
	}
}

func TestIMAPFeederRejectsBadCredentials(t *testing.T) {
	mailbox := imaptest.NewMailbox(t)
	s := testStore(t)

	cfg := feederConfig(t, mailbox, "mailbox", "default")
	cfg.Password = "wrong"

	if _, err := NewIMAP(cfg, s, quietLogger()).Run(context.Background()); err == nil {
		t.Fatal("expected an authentication error")
	}
}
