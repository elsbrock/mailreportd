package feeder

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/elsbrock/mailreportd/internal/imaptest"
	"github.com/elsbrock/mailreportd/internal/store"
)

// newMaildir lays out an empty maildir and returns its root.
func newMaildir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, sub := range []string{"new", "cur", "tmp"} {
		if err := os.Mkdir(filepath.Join(root, sub), 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
	}
	return root
}

func deliverFile(t *testing.T, root, sub, name string, body []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, sub, name), body, 0o640); err != nil {
		t.Fatalf("write %s/%s: %v", sub, name, err)
	}
}

func maildirFeeder(t *testing.T, root string) (*Maildir, *store.Store) {
	t.Helper()
	s := testStore(t)
	f := NewMaildir(MaildirConfig{
		Name:     "local",
		Tenant:   "default",
		Path:     root,
		Interval: time.Minute,
	}, s, quietLogger())
	return f, s
}

func TestMaildirFeederIngestsFromNewAndCur(t *testing.T) {
	root := newMaildir(t)
	deliverFile(t, root, "new", "1.eml",
		imaptest.ReportMail(t, "r1", "a.xml.gz", imaptest.AggregateXML("report-a", "example.org", 100, 4)))
	deliverFile(t, root, "cur", "2.eml:2,S",
		imaptest.ReportMail(t, "r2", "b.json.gz", imaptest.TLSJSON("tls-a", "example.org", 412, 3)))

	f, s := maildirFeeder(t, root)
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

func TestMaildirFeederRescanSkipsKnownFiles(t *testing.T) {
	root := newMaildir(t)
	ctx := context.Background()
	deliverFile(t, root, "new", "1.eml",
		imaptest.ReportMail(t, "r1", "a.xml.gz", imaptest.AggregateXML("report-a", "example.org", 10, 1)))

	f, _ := maildirFeeder(t, root)
	if stats, err := f.Run(ctx); err != nil || stats.Messages != 1 {
		t.Fatalf("first run: stats = %+v err = %v", stats, err)
	}

	// A second pass with nothing new must not re-ingest anything.
	stats, err := f.Run(ctx)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if stats.Messages != 0 {
		t.Errorf("second run processed %d messages, want 0", stats.Messages)
	}

	// A new arrival is picked up, and only that one.
	deliverFile(t, root, "new", "2.eml",
		imaptest.ReportMail(t, "r2", "b.xml.gz", imaptest.AggregateXML("report-b", "example.org", 20, 2)))
	stats, err = f.Run(ctx)
	if err != nil {
		t.Fatalf("third run: %v", err)
	}
	if stats.Messages != 1 || stats.Reports != 1 {
		t.Errorf("third run stats = %+v, want exactly the new message", stats)
	}
}

func TestMaildirFeederNeverTouchesTheMaildir(t *testing.T) {
	root := newMaildir(t)
	body := imaptest.ReportMail(t, "r1", "a.xml.gz", imaptest.AggregateXML("report-a", "example.org", 10, 1))
	deliverFile(t, root, "new", "1.eml", body)

	f, _ := maildirFeeder(t, root)
	if _, err := f.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	// The file must still be in new/ with identical bytes: no new/→cur/ move,
	// no flag rename, no deletion.
	got, err := os.ReadFile(filepath.Join(root, "new", "1.eml"))
	if err != nil {
		t.Fatalf("message no longer readable in new/: %v", err)
	}
	if string(got) != string(body) {
		t.Error("message bytes changed")
	}
	entries, _ := os.ReadDir(filepath.Join(root, "cur"))
	if len(entries) != 0 {
		t.Errorf("cur/ has %d entries, want 0", len(entries))
	}
}

func TestMaildirFeederSkipsTmpAndDotfiles(t *testing.T) {
	root := newMaildir(t)
	deliverFile(t, root, "tmp", "partial.eml",
		imaptest.ReportMail(t, "r1", "a.xml.gz", imaptest.AggregateXML("report-a", "example.org", 10, 1)))
	deliverFile(t, root, "new", ".dovecot-metadata", []byte("not a message"))

	f, _ := maildirFeeder(t, root)
	stats, err := f.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if stats.Messages != 0 {
		t.Errorf("stats = %+v, want nothing ingested", stats)
	}
}

func TestMaildirFeederRecordsNonReports(t *testing.T) {
	root := newMaildir(t)
	deliverFile(t, root, "new", "1.eml", imaptest.PlainMail("hello", "no report here"))

	f, _ := maildirFeeder(t, root)
	stats, err := f.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if stats.Messages != 1 || stats.Ignored != 1 {
		t.Errorf("stats = %+v, want 1 message recorded as ignored", stats)
	}
}

func TestMaildirFeederFailsLoudlyOnNonMaildir(t *testing.T) {
	f, _ := maildirFeeder(t, t.TempDir()) // no new/ or cur/
	if _, err := f.Run(context.Background()); err == nil {
		t.Fatal("expected an error for a path that is not a maildir")
	}
}
