package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// FailureSummary is the metadata view of one failure report: the envelope
// facts, never the content. This view carries nothing the aggregate path does
// not, which is why reading it is not access-logged.
type FailureSummary struct {
	ID           int64  `json:"id"`
	Domain       string `json:"domain"`
	AuthFailure  string `json:"auth_failure"`
	SourceIP     string `json:"source_ip,omitempty"`
	ReportingMTA string `json:"reporting_mta,omitempty"`
	Delivery     string `json:"delivery,omitempty"`
	Reporter     string `json:"reporter,omitempty"`
	ArrivalAt    string `json:"arrival_at"`
	// HasContent says whether sealed content exists to be requested. False
	// means no key was configured at ingest time and the PII was dropped.
	HasContent bool `json:"has_content"`
}

// FailureContent is the decrypted PII block of one failure report.
type FailureContent struct {
	OriginalMailFrom string   `json:"original_mail_from,omitempty"`
	OriginalRcptTo   []string `json:"original_rcpt_to,omitempty"`
	FeedbackReport   string   `json:"feedback_report,omitempty"`
	OriginalMessage  string   `json:"original_message,omitempty"`
}

// Failures lists failure reports in the window, newest first.
func (s *Store) Failures(ctx context.Context, since time.Time, limit int) ([]FailureSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT f.id, f.domain, f.auth_failure, f.source_ip, f.reporting_mta,
		       f.delivery, r.reporter, f.arrival_at,
		       f.content IS NOT NULL
		FROM failure_report f
		JOIN report r ON r.id = f.report_id
		WHERE f.tenant_id = ? AND f.end_at >= ?
		ORDER BY f.arrival_at DESC, f.id DESC
		LIMIT ?`,
		s.tenant, since.Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("query failures: %w", err)
	}
	defer rows.Close()

	var out []FailureSummary
	for rows.Next() {
		var (
			f       FailureSummary
			arrival int64
		)
		if err := rows.Scan(&f.ID, &f.Domain, &f.AuthFailure, &f.SourceIP,
			&f.ReportingMTA, &f.Delivery, &f.Reporter, &arrival, &f.HasContent); err != nil {
			return nil, fmt.Errorf("scan failure: %w", err)
		}
		f.ArrivalAt = time.Unix(arrival, 0).UTC().Format(time.RFC3339)
		out = append(out, f)
	}
	return out, rows.Err()
}

// FailureContents decrypts the content of the given failure reports and logs
// the access — in the same transaction, so there is no path where content
// leaves the store without its log row. Reports without content are simply
// absent from the result.
func (s *Store) FailureContents(ctx context.Context, ids []int64, peer string) (map[int64]FailureContent, error) {
	if s.sealer == nil {
		return nil, fmt.Errorf("no failure key configured")
	}
	if len(ids) == 0 {
		return map[int64]FailureContent{}, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin failure read: %w", err)
	}
	defer tx.Rollback()

	out := make(map[int64]FailureContent, len(ids))
	read := make([]int64, 0, len(ids))
	for _, id := range ids {
		var blob []byte
		err := tx.QueryRowContext(ctx, `
			SELECT content FROM failure_report
			WHERE tenant_id = ? AND id = ? AND content IS NOT NULL`,
			s.tenant, id).Scan(&blob)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read failure %d: %w", id, err)
		}

		plain, err := s.sealer.Open(blob)
		if err != nil {
			return nil, fmt.Errorf("failure %d: %w", id, err)
		}
		var content failureContent
		if err := json.Unmarshal(plain, &content); err != nil {
			return nil, fmt.Errorf("decode failure %d: %w", id, err)
		}
		out[id] = FailureContent{
			OriginalMailFrom: content.OriginalMailFrom,
			OriginalRcptTo:   content.OriginalRcptTo,
			FeedbackReport:   string(content.FeedbackReport),
			OriginalMessage:  string(content.OriginalMessage),
		}
		read = append(read, id)
	}

	if len(read) > 0 {
		encoded, _ := json.Marshal(read)
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO failure_access_log (tenant_id, at, peer, report_ids)
			VALUES (?, ?, ?, ?)`,
			s.tenant, time.Now().Unix(), peer, string(encoded)); err != nil {
			return nil, fmt.Errorf("log failure access: %w", err)
		}
	}

	return out, tx.Commit()
}
