// Package store persists reports in an embedded SQLite database.
//
// A working install must not require a database server, so the default is
// embedded and pure Go: no cgo, no external process, one file on disk. SQL is
// kept portable so that a hosted deployment can move to Postgres later, but no
// abstraction is built for it until a second implementation actually exists.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/elsbrock/mailreportd/internal/report"
)

// State describes what happened to a raw message.
const (
	// StateParsed means at least one report was extracted and stored.
	StateParsed = "parsed"
	// StateQuarantined means the message looked like a report and could not be
	// parsed. It is kept, never deleted, so the failure can be diagnosed and
	// the message reprocessed once the parser is fixed.
	StateQuarantined = "quarantined"
	// StateIgnored means the message carried nothing report-shaped. Mailboxes
	// collect autoreplies and spam; those are not failures.
	StateIgnored = "ignored"
)

// DB is the process-wide database handle. Callers do not query it directly;
// they obtain a tenant-scoped Store.
type DB struct {
	sql    *sql.DB
	sealer *Sealer
}

// Open opens or creates the database at path and applies migrations.
func Open(path string) (*DB, error) {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}

	// WAL keeps the retention sweep from blocking ingest. busy_timeout covers
	// the brief writer contention between a sweep and a feeder.
	dsn := "file:" + path + "?" + url.Values{
		"_pragma": {
			"journal_mode(WAL)",
			"busy_timeout(10000)",
			"foreign_keys(1)",
			"synchronous(NORMAL)",
		},
	}.Encode()

	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// SQLite tolerates exactly one writer. Serializing here is simpler and
	// more predictable than discovering it as intermittent SQLITE_BUSY.
	sqldb.SetMaxOpenConns(1)

	db := &DB{sql: sqldb}
	if err := db.migrate(context.Background()); err != nil {
		sqldb.Close()
		return nil, err
	}
	return db, nil
}

// Close releases the database handle.
func (db *DB) Close() error { return db.sql.Close() }

// SQL exposes the underlying handle for tests.
func (db *DB) SQL() *sql.DB { return db.sql }

// SetSealer installs the cipher for failure-report content. Without one,
// failure reports are stored as envelope metadata only and their PII content
// is dropped rather than written in the clear.
func (db *DB) SetSealer(s *Sealer) { db.sealer = s }

func (db *DB) migrate(ctx context.Context) error {
	if _, err := db.sql.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}

	var current int
	err := db.sql.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current)
	if err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}

	for i := current; i < len(migrations); i++ {
		version := i + 1
		tx, err := db.sql.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", version, err)
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %d: %w", version, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			version, time.Now().Unix()); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %d: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", version, err)
		}
	}
	return nil
}

// Tenant returns a store scoped to one tenant. Every query in the daemon goes
// through one of these, so no query can forget the tenant predicate.
func (db *DB) Tenant(id string) *Store {
	return &Store{db: db.sql, tenant: id, sealer: db.sealer}
}

// Store is a tenant-scoped view of the database.
type Store struct {
	db     *sql.DB
	tenant string
	sealer *Sealer
}

// Tenant returns the tenant this store is bound to.
func (s *Store) Tenant() string { return s.tenant }

// RawMessage is a message as it arrived from a feeder.
type RawMessage struct {
	Feeder    string
	SourceRef string // feeder-specific locator, e.g. an IMAP UID
	MessageID string
	Filename  string
	Received  time.Time
	Body      []byte
}

// Checksum identifies the message bytes. Reports arrive more than once and
// mailboxes get reprocessed; this is what makes both harmless.
func (m RawMessage) Checksum() string {
	sum := sha256.Sum256(m.Body)
	return hex.EncodeToString(sum[:])
}

// IngestResult describes what a single message produced.
type IngestResult struct {
	Duplicate bool // the exact message bytes were already ingested
	Stored    int  // reports newly stored
	Skipped   int  // reports already present under the same identity
	State     string
}

// Ingest decodes, parses and stores one raw message in a single transaction.
//
// It is idempotent at two levels: identical message bytes are recognized by
// checksum, and reports that arrive twice under different envelopes are
// recognized by report identity. Reprocessing an entire mailbox is therefore
// safe and is the supported recovery path.
func (s *Store) Ingest(ctx context.Context, msg RawMessage) (IngestResult, error) {
	var res IngestResult

	if msg.Received.IsZero() {
		msg.Received = time.Now()
	}

	decoded, decodeErr := report.DecodeMessage(msg.Body)
	if decoded != nil && msg.MessageID == "" {
		msg.MessageID = decoded.MessageID
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("begin ingest: %w", err)
	}
	defer tx.Rollback()

	// The unique constraint on (tenant_id, checksum) is the duplicate check.
	// Doing it as an insert rather than a select avoids a race between two
	// feeders polling the same mailbox.
	state := StateParsed
	switch {
	case errors.Is(decodeErr, report.ErrNoPayload):
		state = StateIgnored
	case decodeErr != nil:
		state = StateQuarantined
	}

	errText := ""
	if decodeErr != nil {
		errText = decodeErr.Error()
	}

	// Only quarantined messages keep their body: that is the one case where the
	// bytes are still needed. Parsed reports are already normalized, and
	// ignored messages are noise.
	var body []byte
	if state == StateQuarantined {
		body = msg.Body
	}

	rawID, inserted, err := insertRaw(ctx, tx, s.tenant, msg, state, errText, body)
	if err != nil {
		return res, err
	}
	if !inserted {
		res.Duplicate = true
		res.State = StateParsed
		return res, tx.Commit()
	}

	if state != StateParsed {
		res.State = state
		return res, tx.Commit()
	}

	// A message may carry several reports. A failure in one must not discard
	// the others, but a message where nothing parsed is a quarantine case.
	var lastErr error
	for _, payload := range decoded.Payloads {
		rep, err := report.Parse(payload)
		if err != nil {
			lastErr = err
			continue
		}
		stored, err := s.storeReport(ctx, tx, rawID, rep)
		if err != nil {
			return res, err
		}
		if stored {
			res.Stored++
		} else {
			res.Skipped++
		}
	}

	if res.Stored == 0 && res.Skipped == 0 {
		state = StateQuarantined
		text := "no payload parsed"
		if lastErr != nil {
			text = lastErr.Error()
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE raw_report SET state = ?, error = ?, body = ? WHERE id = ?`,
			state, text, msg.Body, rawID); err != nil {
			return res, fmt.Errorf("quarantine message: %w", err)
		}
	}

	res.State = state
	return res, tx.Commit()
}

func insertRaw(ctx context.Context, tx *sql.Tx, tenant string, msg RawMessage, state, errText string, body []byte) (int64, bool, error) {
	result, err := tx.ExecContext(ctx, `
		INSERT INTO raw_report (tenant_id, checksum, feeder, source_ref, message_id, filename, received_at, state, error, body)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id, checksum) DO NOTHING`,
		tenant, msg.Checksum(), msg.Feeder, msg.SourceRef, msg.MessageID, msg.Filename,
		msg.Received.Unix(), state, errText, body)
	if err != nil {
		return 0, false, fmt.Errorf("insert raw message: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, false, fmt.Errorf("insert raw message: %w", err)
	}
	if affected == 0 {
		return 0, false, nil
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, false, fmt.Errorf("insert raw message: %w", err)
	}
	return id, true, nil
}

// storeReport writes one normalized report and its rows. It reports whether the
// report was new; an existing identity is a no-op rather than an error.
func (s *Store) storeReport(ctx context.Context, tx *sql.Tx, rawID int64, rep *report.Report) (bool, error) {
	tenant := s.tenant
	policy := rep.Policy
	if policy == nil {
		policy = &report.DMARCPolicy{Pct: 100}
	}

	result, err := tx.ExecContext(ctx, `
		INSERT INTO report (tenant_id, identity, format, reporter, reporter_mail, report_ref, domain,
		                    begin_at, end_at, ingested_at, raw_report_id,
		                    policy_p, policy_sp, policy_adkim, policy_aspf, policy_pct)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id, identity) DO NOTHING`,
		tenant, rep.Identity(), string(rep.Format), rep.Reporter, rep.Email, rep.ReportID, rep.Domain,
		rep.Begin.Unix(), rep.End.Unix(), time.Now().Unix(), rawID,
		policy.P, policy.SP, policy.ADKIM, policy.ASPF, policy.Pct)
	if err != nil {
		return false, fmt.Errorf("insert report: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("insert report: %w", err)
	}
	if affected == 0 {
		return false, nil
	}
	reportID, err := result.LastInsertId()
	if err != nil {
		return false, fmt.Errorf("insert report: %w", err)
	}

	for _, row := range rep.DMARCRows {
		reasons, _ := json.Marshal(row.Reasons)
		dkimAuth, _ := json.Marshal(row.DKIMAuth)
		spfAuth, _ := json.Marshal(row.SPFAuth)

		// end_at and domain are denormalized onto the row so the exporter can
		// scan one window without joining. Reports are immutable once written,
		// so there is nothing to keep in sync.
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO dmarc_row (tenant_id, report_id, domain, end_at, source_ip, message_count,
			                       disposition, dkim, spf, header_from, envelope_from,
			                       reasons, dkim_auth, spf_auth)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			tenant, reportID, rep.Domain, rep.End.Unix(), row.SourceIP.String(), row.Count,
			row.Disposition, row.DKIM, row.SPF, row.HeaderFrom, row.EnvelopeFrom,
			string(reasons), string(dkimAuth), string(spfAuth)); err != nil {
			return false, fmt.Errorf("insert dmarc row: %w", err)
		}
	}

	for _, policy := range rep.TLSPolicies {
		mxHosts, _ := json.Marshal(policy.MXHosts)
		failures, _ := json.Marshal(policy.Failures)

		// A TLS report may cover several domains; each policy is attributed to
		// its own, not to the report-level label.
		domain := policy.PolicyDomain
		if domain == "" {
			domain = rep.Domain
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO tlsrpt_policy (tenant_id, report_id, domain, end_at, policy_type,
			                           mx_hosts, successful, failed, failures)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			tenant, reportID, domain, rep.End.Unix(), policy.PolicyType,
			string(mxHosts), policy.Successful, policy.Failed, string(failures)); err != nil {
			return false, fmt.Errorf("insert tls policy: %w", err)
		}
	}

	if rep.Failure != nil {
		if err := s.storeFailure(ctx, tx, reportID, rep); err != nil {
			return false, err
		}
	}

	day := time.Now().UTC().Format("2006-01-02")
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO ingest_usage (tenant_id, day, format, reports) VALUES (?, ?, ?, 1)
		ON CONFLICT (tenant_id, day, format) DO UPDATE SET reports = reports + 1`,
		tenant, day, string(rep.Format)); err != nil {
		return false, fmt.Errorf("record usage: %w", err)
	}

	return true, nil
}

// failureContent is the PII block of a failure report, JSON-encoded and sealed
// before it reaches disk.
type failureContent struct {
	OriginalMailFrom string   `json:"original_mail_from,omitempty"`
	OriginalRcptTo   []string `json:"original_rcpt_to,omitempty"`
	FeedbackReport   []byte   `json:"feedback_report,omitempty"`
	OriginalMessage  []byte   `json:"original_message,omitempty"`
}

// storeFailure writes the failure_report row hanging off a report. Without a
// sealer the content is dropped, not written in the clear: the envelope
// columns alone are no more sensitive than an aggregate report.
func (s *Store) storeFailure(ctx context.Context, tx *sql.Tx, reportID int64, rep *report.Report) error {
	f := rep.Failure

	var (
		blob      []byte
		encrypted int
	)
	if s.sealer != nil {
		plain, err := json.Marshal(failureContent{
			OriginalMailFrom: f.OriginalMailFrom,
			OriginalRcptTo:   f.OriginalRcptTo,
			FeedbackReport:   f.FeedbackReport,
			OriginalMessage:  f.OriginalMessage,
		})
		if err != nil {
			return fmt.Errorf("encode failure content: %w", err)
		}
		if blob, err = s.sealer.Seal(plain); err != nil {
			return fmt.Errorf("seal failure content: %w", err)
		}
		encrypted = 1
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO failure_report (tenant_id, report_id, domain, end_at,
		                            auth_failure, source_ip, reporting_mta, delivery,
		                            arrival_at, encrypted, content)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.tenant, reportID, rep.Domain, rep.End.Unix(),
		f.AuthFailure, f.SourceIP, f.ReportingMTA, f.Delivery,
		f.Arrival.Unix(), encrypted, blob); err != nil {
		return fmt.Errorf("insert failure report: %w", err)
	}
	return nil
}

// IngestReport stores one already-parsed report together with its source
// bytes, for submission paths that arrive without a mail envelope. It shares
// both dedupe levels with Ingest: identical bytes by checksum, identical
// reports by identity.
func (s *Store) IngestReport(ctx context.Context, msg RawMessage, rep *report.Report) (IngestResult, error) {
	var res IngestResult
	if msg.Received.IsZero() {
		msg.Received = time.Now()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("begin ingest: %w", err)
	}
	defer tx.Rollback()

	rawID, inserted, err := insertRaw(ctx, tx, s.tenant, msg, StateParsed, "", nil)
	if err != nil {
		return res, err
	}
	if !inserted {
		res.Duplicate = true
		res.State = StateParsed
		return res, tx.Commit()
	}

	stored, err := s.storeReport(ctx, tx, rawID, rep)
	if err != nil {
		return res, err
	}
	if stored {
		res.Stored++
	} else {
		res.Skipped++
	}
	res.State = StateParsed
	return res, tx.Commit()
}

// SeenChecksum reports whether message bytes with this checksum are already
// ingested. Feeders without an incremental cursor — maildir — use it to make a
// full rescan cost a hash per file rather than a decode. It is an optimization
// only: Ingest stays idempotent without it.
func (s *Store) SeenChecksum(ctx context.Context, checksum string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM raw_report WHERE tenant_id = ? AND checksum = ?`,
		s.tenant, checksum).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check checksum: %w", err)
	}
	return true, nil
}

// Cursor is a feeder's position in a mailbox.
type Cursor struct {
	UIDValidity uint32
	LastUID     uint32
}

// Cursor returns the stored position for a feeder. A missing cursor is the zero
// value, which means "start from the beginning".
func (s *Store) Cursor(ctx context.Context, feeder string) (Cursor, error) {
	var c Cursor
	err := s.db.QueryRowContext(ctx,
		`SELECT uid_validity, last_uid FROM feeder_cursor WHERE tenant_id = ? AND feeder = ?`,
		s.tenant, feeder).Scan(&c.UIDValidity, &c.LastUID)
	if errors.Is(err, sql.ErrNoRows) {
		return Cursor{}, nil
	}
	if err != nil {
		return Cursor{}, fmt.Errorf("read feeder cursor: %w", err)
	}
	return c, nil
}

// SetCursor records a feeder's position.
func (s *Store) SetCursor(ctx context.Context, feeder string, c Cursor) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO feeder_cursor (tenant_id, feeder, uid_validity, last_uid, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id, feeder) DO UPDATE
		SET uid_validity = excluded.uid_validity,
		    last_uid     = excluded.last_uid,
		    updated_at   = excluded.updated_at`,
		s.tenant, feeder, c.UIDValidity, c.LastUID, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("write feeder cursor: %w", err)
	}
	return nil
}

// Retention holds per-class retention windows.
type Retention struct {
	Raw       time.Duration
	Aggregate time.Duration
	Forensic  time.Duration
}

// SweepResult reports what a retention sweep removed.
type SweepResult struct {
	RawBodies int64
	Reports   int64
	Failures  int64
}

// Sweep enforces retention.
//
// Quarantined messages are exempt from the raw-body sweep: they exist precisely
// because something needs fixing, and discarding them on a timer would destroy
// the evidence before anyone looked.
func (s *Store) Sweep(ctx context.Context, r Retention, now time.Time) (SweepResult, error) {
	var res SweepResult

	rawCutoff := now.Add(-r.Raw).Unix()
	result, err := s.db.ExecContext(ctx, `
		UPDATE raw_report SET body = NULL
		WHERE tenant_id = ? AND received_at < ? AND body IS NOT NULL AND state != ?`,
		s.tenant, rawCutoff, StateQuarantined)
	if err != nil {
		return res, fmt.Errorf("sweep raw bodies: %w", err)
	}
	res.RawBodies, _ = result.RowsAffected()

	// Failure reports age out on their own, shorter window. The delete targets
	// the report row; the sealed content follows by cascade.
	forensicCutoff := now.Add(-r.Forensic).Unix()
	result, err = s.db.ExecContext(ctx, `
		DELETE FROM report WHERE tenant_id = ? AND format = ? AND end_at < ?`,
		s.tenant, string(report.FormatDMARCFailure), forensicCutoff)
	if err != nil {
		return res, fmt.Errorf("sweep failure reports: %w", err)
	}
	res.Failures, _ = result.RowsAffected()

	aggCutoff := now.Add(-r.Aggregate).Unix()
	result, err = s.db.ExecContext(ctx, `
		DELETE FROM report WHERE tenant_id = ? AND end_at < ?`, s.tenant, aggCutoff)
	if err != nil {
		return res, fmt.Errorf("sweep reports: %w", err)
	}
	res.Reports, _ = result.RowsAffected()

	// Raw rows whose reports are gone carry no remaining value.
	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM raw_report
		WHERE tenant_id = ? AND received_at < ? AND state = ?
		  AND id NOT IN (SELECT raw_report_id FROM report WHERE raw_report_id IS NOT NULL)`,
		s.tenant, aggCutoff, StateParsed); err != nil {
		return res, fmt.Errorf("sweep orphaned raw rows: %w", err)
	}

	return res, nil
}
