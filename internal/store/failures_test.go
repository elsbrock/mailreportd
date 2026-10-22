package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/elsbrock/mailreportd/internal/imaptest"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func testSealer(t *testing.T) *Sealer {
	t.Helper()
	key := make([]byte, 32)
	rand.Read(key)
	s, err := NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	return s
}

func failureDB(t *testing.T, sealer *Sealer) (*DB, *Store) {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "failures.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if sealer != nil {
		db.SetSealer(sealer)
	}
	return db, db.Tenant("default")
}

func ingestFailure(t *testing.T, s *Store, msgID string, arrival time.Time) IngestResult {
	t.Helper()
	res, err := s.Ingest(context.Background(), RawMessage{
		Feeder:   "test",
		Received: arrival,
		Body:     imaptest.FailureMail(t, msgID, "example.org", "victim@dest.example", arrival),
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	return res
}

func TestFailureReportRoundTrip(t *testing.T) {
	_, s := failureDB(t, testSealer(t))
	ctx := context.Background()
	arrival := time.Now().Add(-12 * time.Hour)

	if res := ingestFailure(t, s, "arf-1", arrival); res.Stored != 1 {
		t.Fatalf("res = %+v, want one stored report", res)
	}

	list, err := s.Failures(ctx, time.Now().Add(-30*24*time.Hour), 50)
	if err != nil {
		t.Fatalf("failures: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("failures = %d, want 1", len(list))
	}
	f := list[0]
	if f.Domain != "example.org" || f.AuthFailure != "dmarc" || !f.HasContent {
		t.Fatalf("summary = %+v", f)
	}
	if f.Reporter != "mx.receiver.example" {
		t.Errorf("reporter = %q", f.Reporter)
	}

	contents, err := s.FailureContents(ctx, []int64{f.ID}, "127.0.0.1:9")
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	c, ok := contents[f.ID]
	if !ok {
		t.Fatal("no content returned")
	}
	if c.OriginalMailFrom != "bounce@example.org" {
		t.Errorf("mail from = %q", c.OriginalMailFrom)
	}
	if len(c.OriginalRcptTo) != 1 || c.OriginalRcptTo[0] != "victim@dest.example" {
		t.Errorf("rcpt = %v", c.OriginalRcptTo)
	}
	if !strings.Contains(c.OriginalMessage, "the original message") {
		t.Error("original message missing from content")
	}
}

func TestFailureContentIsEncryptedOnDisk(t *testing.T) {
	db, s := failureDB(t, testSealer(t))
	ingestFailure(t, s, "arf-1", time.Now().Add(-12*time.Hour))

	var (
		encrypted int
		blob      []byte
	)
	err := db.SQL().QueryRow(`SELECT encrypted, content FROM failure_report`).Scan(&encrypted, &blob)
	if err != nil {
		t.Fatalf("read row: %v", err)
	}
	if encrypted != 1 || len(blob) == 0 {
		t.Fatalf("encrypted = %d, blob = %d bytes", encrypted, len(blob))
	}
	// The address must not be findable in the stored bytes.
	if bytes.Contains(blob, []byte("victim@dest.example")) {
		t.Fatal("recipient address stored in the clear")
	}
}

func TestFailureWithoutKeyDropsContent(t *testing.T) {
	db, s := failureDB(t, nil)
	ctx := context.Background()
	ingestFailure(t, s, "arf-1", time.Now().Add(-12*time.Hour))

	list, err := s.Failures(ctx, time.Now().Add(-30*24*time.Hour), 50)
	if err != nil || len(list) != 1 {
		t.Fatalf("failures = %v err = %v", list, err)
	}
	if list[0].HasContent {
		t.Error("content claimed to exist without a key")
	}
	if _, err := s.FailureContents(ctx, []int64{list[0].ID}, "peer"); err == nil {
		t.Error("content read without a key did not fail")
	}

	// Nothing PII-shaped may exist anywhere in the row.
	var blob []byte
	db.SQL().QueryRow(`SELECT COALESCE(content, X'') FROM failure_report`).Scan(&blob)
	if len(blob) != 0 {
		t.Fatalf("content stored despite missing key: %d bytes", len(blob))
	}
}

func TestFailureContentReadIsLogged(t *testing.T) {
	db, s := failureDB(t, testSealer(t))
	ctx := context.Background()
	ingestFailure(t, s, "arf-1", time.Now().Add(-12*time.Hour))

	list, _ := s.Failures(ctx, time.Now().Add(-30*24*time.Hour), 50)
	if _, err := s.FailureContents(ctx, []int64{list[0].ID}, "192.0.2.9:4711"); err != nil {
		t.Fatalf("contents: %v", err)
	}

	var (
		count int
		peer  string
		ids   string
	)
	if err := db.SQL().QueryRow(
		`SELECT COUNT(*), MAX(peer), MAX(report_ids) FROM failure_access_log`).
		Scan(&count, &peer, &ids); err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if count != 1 || peer != "192.0.2.9:4711" || !strings.Contains(ids, "1") {
		t.Fatalf("access log = %d rows, peer %q, ids %q", count, peer, ids)
	}

	// The metadata view is not logged.
	s.Failures(ctx, time.Now().Add(-30*24*time.Hour), 50)
	db.SQL().QueryRow(`SELECT COUNT(*) FROM failure_access_log`).Scan(&count)
	if count != 1 {
		t.Fatalf("metadata read was logged: %d rows", count)
	}
}

func TestSweepAppliesForensicWindow(t *testing.T) {
	db, s := failureDB(t, testSealer(t))
	ctx := context.Background()

	// One failure report 10 days old, one 2 days old.
	old := time.Now().Add(-10 * 24 * time.Hour)
	fresh := time.Now().Add(-2 * 24 * time.Hour)
	ingestFailure(t, s, "arf-old", old)
	ingestFailure(t, s, "arf-fresh", fresh)

	res, err := s.Sweep(ctx, Retention{
		Raw:       30 * 24 * time.Hour,
		Aggregate: 365 * 24 * time.Hour,
		Forensic:  7 * 24 * time.Hour,
	}, time.Now())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.Failures != 1 {
		t.Fatalf("failures swept = %d, want 1", res.Failures)
	}

	list, _ := s.Failures(ctx, time.Now().Add(-30*24*time.Hour), 50)
	if len(list) != 1 {
		t.Fatalf("failures remaining = %d, want 1", len(list))
	}

	// The sealed content followed the report row out by cascade.
	var rows int
	db.SQL().QueryRow(`SELECT COUNT(*) FROM failure_report`).Scan(&rows)
	if rows != 1 {
		t.Fatalf("failure_report rows = %d, want 1", rows)
	}
}

func TestSealerRoundTripAndKeyFile(t *testing.T) {
	sealer := testSealer(t)
	blob, err := sealer.Seal([]byte("secret"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	plain, err := sealer.Open(blob)
	if err != nil || string(plain) != "secret" {
		t.Fatalf("open = %q err = %v", plain, err)
	}
	if _, err := sealer.Open(blob[:8]); err == nil {
		t.Error("truncated blob opened")
	}

	keyfile := filepath.Join(t.TempDir(), "key")
	writeFile(t, keyfile, "9f2c37e4a1b8d05c6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5\n")
	if _, err := NewSealerFromFile(keyfile); err != nil {
		t.Fatalf("key file: %v", err)
	}
	writeFile(t, keyfile, "too short")
	if _, err := NewSealerFromFile(keyfile); err == nil {
		t.Error("bad key file accepted")
	}
}

// A failure report that does not parse is quarantined, but its bytes are still
// recipient PII: sealed with a key, dropped without one, and gone after the
// failure-report window either way.
func TestQuarantinedFailureReportIsNotKeptInClear(t *testing.T) {
	body := imaptest.FailureMail(t, "arf-broken", "", "victim@dest.example", time.Now())
	ctx := context.Background()

	rawBody := func(t *testing.T, db *DB) []byte {
		t.Helper()
		var b []byte
		if err := db.sql.QueryRowContext(ctx,
			`SELECT body FROM raw_report WHERE state = ?`, StateQuarantined).Scan(&b); err != nil {
			t.Fatalf("read quarantined body: %v", err)
		}
		return b
	}

	t.Run("sealed with a key", func(t *testing.T) {
		sealer := testSealer(t)
		db, s := failureDB(t, sealer)
		res, err := s.Ingest(ctx, RawMessage{Feeder: "test", Body: body})
		if err != nil {
			t.Fatalf("ingest: %v", err)
		}
		if res.State != StateQuarantined {
			t.Fatalf("state = %q, want quarantined", res.State)
		}
		stored := rawBody(t, db)
		if bytes.Contains(stored, []byte("victim@dest.example")) {
			t.Fatal("quarantined failure report stored in clear")
		}
		plain, err := sealer.Open(stored)
		if err != nil || !bytes.Equal(plain, body) {
			t.Fatalf("sealed body does not open to the original: %v", err)
		}

		if _, err := s.Sweep(ctx, Retention{
			Raw: 365 * 24 * time.Hour, Aggregate: 365 * 24 * time.Hour, Forensic: time.Hour,
		}, time.Now().Add(2*time.Hour)); err != nil {
			t.Fatalf("sweep: %v", err)
		}
		if b := rawBody(t, db); b != nil {
			t.Error("quarantined failure body survived the failure-report window")
		}
	})

	t.Run("dropped without a key", func(t *testing.T) {
		db, s := failureDB(t, nil)
		if _, err := s.Ingest(ctx, RawMessage{Feeder: "test", Body: body}); err != nil {
			t.Fatalf("ingest: %v", err)
		}
		if b := rawBody(t, db); b != nil {
			t.Error("quarantined failure report kept without a key")
		}
	})
}
