package submit

import (
	"bytes"
	"compress/gzip"
	"context"
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

func testHandler(t *testing.T) (*TLSRPT, *store.Store) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "submit.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	s := db.Tenant("default")
	h := NewTLSRPT(
		map[string]*store.Store{"default": s},
		map[string]string{"example.org": "default"},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	return h, s
}

func post(h *TLSRPT, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/tlsrpt", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/tlsrpt+json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func rawCount(t *testing.T, s *store.Store) int64 {
	t.Helper()
	counts, err := s.StateCounts(context.Background())
	if err != nil {
		t.Fatalf("state counts: %v", err)
	}
	var total int64
	for _, n := range counts {
		total += n
	}
	return total
}

func TestSubmissionStoresReport(t *testing.T) {
	h, s := testHandler(t)

	rec := post(h, []byte(imaptest.TLSJSON("tls-1", "example.org", 400, 2)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", rec.Code, rec.Body)
	}

	tls, err := s.TLSSummaries(context.Background(), time.Now().Add(-30*24*time.Hour))
	if err != nil {
		t.Fatalf("tls summaries: %v", err)
	}
	if len(tls) != 1 || tls[0].Successful != 400 || tls[0].Failed != 2 {
		t.Fatalf("tls summaries = %+v, want one domain with 400/2 sessions", tls)
	}
}

func TestSubmissionAcceptsGzip(t *testing.T) {
	h, s := testHandler(t)

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(imaptest.TLSJSON("tls-gz", "example.org", 10, 0)))
	zw.Close()

	rec := post(h, buf.Bytes())
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	tls, err := s.TLSSummaries(context.Background(), time.Now().Add(-30*24*time.Hour))
	if err != nil || len(tls) != 1 || tls[0].Successful != 10 {
		t.Fatalf("tls summaries = %+v err = %v", tls, err)
	}
}

func TestSubmissionIsIdempotent(t *testing.T) {
	h, s := testHandler(t)
	body := []byte(imaptest.TLSJSON("tls-1", "example.org", 400, 2))

	// Identical bytes resent: recognized by checksum.
	if rec := post(h, body); rec.Code != http.StatusCreated {
		t.Fatalf("first: %d", rec.Code)
	}
	if rec := post(h, body); rec.Code != http.StatusCreated {
		t.Fatalf("resend: %d", rec.Code)
	}

	// The same report under different bytes: recognized by identity.
	if rec := post(h, append([]byte("  "), body...)); rec.Code != http.StatusCreated {
		t.Fatalf("reformatted resend: %d", rec.Code)
	}

	tls, err := s.TLSSummaries(context.Background(), time.Now().Add(-30*24*time.Hour))
	if err != nil || len(tls) != 1 || tls[0].Successful != 400 || tls[0].Failed != 2 {
		t.Fatalf("counts doubled: %+v err = %v", tls, err)
	}
}

func TestSubmissionRejectsGarbageWithoutStoring(t *testing.T) {
	h, s := testHandler(t)

	for _, body := range [][]byte{
		[]byte("not json at all"),
		[]byte(`{"looks":"like json","is":"not a report"}`),
		{},
	} {
		rec := post(h, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d for %q, want 400", rec.Code, body)
		}
	}
	if n := rawCount(t, s); n != 0 {
		t.Errorf("garbage was stored: %d raw rows", n)
	}
}

func TestSubmissionRejectsForeignDomains(t *testing.T) {
	h, s := testHandler(t)

	rec := post(h, []byte(imaptest.TLSJSON("tls-x", "someone-else.example", 5, 0)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if n := rawCount(t, s); n != 0 {
		t.Fatalf("foreign report was stored: %d raw rows", n)
	}
}

func TestSubmissionBoundsBodySize(t *testing.T) {
	h, _ := testHandler(t)

	// A syntactically plausible prefix followed by bulk, over the limit.
	big := strings.Repeat("x", 33<<20)
	rec := post(h, []byte(big))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}
