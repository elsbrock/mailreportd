package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/elsbrock/mailreportd/internal/report"
)

// DMARCSource is authentication volume from one source address, grouped by
// outcome. The exporter reads these, classifies each address, and only then
// aggregates — which is how per-source detail stays out of Prometheus while
// still informing the exported series.
type DMARCSource struct {
	Domain      string
	SourceIP    netip.Addr
	Disposition string
	DKIM        string
	SPF         string
	Count       int64
}

// DMARCSources returns aggregate volume for reports whose window ended at or
// after since.
func (s *Store) DMARCSources(ctx context.Context, since time.Time) ([]DMARCSource, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT domain, source_ip, disposition, dkim, spf, SUM(message_count)
		FROM dmarc_row
		WHERE tenant_id = ? AND end_at >= ?
		GROUP BY domain, source_ip, disposition, dkim, spf`,
		s.tenant, since.Unix())
	if err != nil {
		return nil, fmt.Errorf("query dmarc sources: %w", err)
	}
	defer rows.Close()

	var out []DMARCSource
	for rows.Next() {
		var (
			src DMARCSource
			ip  string
		)
		if err := rows.Scan(&src.Domain, &ip, &src.Disposition, &src.DKIM, &src.SPF, &src.Count); err != nil {
			return nil, fmt.Errorf("scan dmarc source: %w", err)
		}
		if addr, err := netip.ParseAddr(ip); err == nil {
			src.SourceIP = addr
		}
		out = append(out, src)
	}
	return out, rows.Err()
}

// TLSSummary is session volume for one domain and policy type.
type TLSSummary struct {
	Domain     string
	PolicyType string
	Successful int64
	Failed     int64
}

// TLSSummaries returns TLS session volume over the window.
func (s *Store) TLSSummaries(ctx context.Context, since time.Time) ([]TLSSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT domain, policy_type, SUM(successful), SUM(failed)
		FROM tlsrpt_policy
		WHERE tenant_id = ? AND end_at >= ?
		GROUP BY domain, policy_type`,
		s.tenant, since.Unix())
	if err != nil {
		return nil, fmt.Errorf("query tls summaries: %w", err)
	}
	defer rows.Close()

	var out []TLSSummary
	for rows.Next() {
		var t TLSSummary
		if err := rows.Scan(&t.Domain, &t.PolicyType, &t.Successful, &t.Failed); err != nil {
			return nil, fmt.Errorf("scan tls summary: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TLSFailureCount is a failure volume for one domain and result type.
type TLSFailureCount struct {
	Domain     string
	ResultType string
	Count      int64
}

// TLSFailures returns failure volume broken down by result type. Result types
// are a small closed set from RFC 8460, so this is safe to export as labels.
func (s *Store) TLSFailures(ctx context.Context, since time.Time) ([]TLSFailureCount, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT domain, failures FROM tlsrpt_policy
		WHERE tenant_id = ? AND end_at >= ? AND failures != '[]'`,
		s.tenant, since.Unix())
	if err != nil {
		return nil, fmt.Errorf("query tls failures: %w", err)
	}
	defer rows.Close()

	totals := map[TLSFailureCount]int64{}
	for rows.Next() {
		var (
			domain string
			blob   string
		)
		if err := rows.Scan(&domain, &blob); err != nil {
			return nil, fmt.Errorf("scan tls failures: %w", err)
		}
		var failures []report.TLSFailure
		if err := json.Unmarshal([]byte(blob), &failures); err != nil {
			continue
		}
		for _, f := range failures {
			key := TLSFailureCount{Domain: domain, ResultType: f.ResultType}
			totals[key] += f.Count
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]TLSFailureCount, 0, len(totals))
	for key, count := range totals {
		key.Count = count
		out = append(out, key)
	}
	return out, nil
}

// LastReport records when a report for a domain and format was last received.
type LastReport struct {
	Domain   string
	Format   string
	Received time.Time
}

// LastReports returns the most recent ingest time per domain and format.
//
// This is the series that makes "no data" distinguishable from "healthy". A
// panel showing a zero failure rate because nothing was ingested looks
// identical to one showing zero because nothing failed, and that is exactly how
// a broken mail stack stays invisible.
func (s *Store) LastReports(ctx context.Context) ([]LastReport, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT domain, format, MAX(ingested_at) FROM report
		WHERE tenant_id = ? GROUP BY domain, format`, s.tenant)
	if err != nil {
		return nil, fmt.Errorf("query last reports: %w", err)
	}
	defer rows.Close()

	var out []LastReport
	for rows.Next() {
		var (
			l  LastReport
			ts int64
		)
		if err := rows.Scan(&l.Domain, &l.Format, &ts); err != nil {
			return nil, fmt.Errorf("scan last report: %w", err)
		}
		l.Received = time.Unix(ts, 0).UTC()
		out = append(out, l)
	}
	return out, rows.Err()
}

// StateCounts returns the number of raw messages in each ingest state.
func (s *Store) StateCounts(ctx context.Context) (map[string]int64, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT state, COUNT(*) FROM raw_report WHERE tenant_id = ? GROUP BY state`, s.tenant)
	if err != nil {
		return nil, fmt.Errorf("query state counts: %w", err)
	}
	defer rows.Close()

	out := map[string]int64{}
	for rows.Next() {
		var (
			state string
			count int64
		)
		if err := rows.Scan(&state, &count); err != nil {
			return nil, fmt.Errorf("scan state count: %w", err)
		}
		out[state] = count
	}
	return out, rows.Err()
}

// SourceDetail is the per-source view the read API serves and Prometheus must
// not carry.
type SourceDetail struct {
	SourceIP    string `json:"source_ip"`
	Domain      string `json:"domain"`
	Total       int64  `json:"total"`
	Passing     int64  `json:"passing"`
	Failing     int64  `json:"failing"`
	Quarantined int64  `json:"quarantined"`
	Rejected    int64  `json:"rejected"`
	FirstSeen   string `json:"first_seen"`
	LastSeen    string `json:"last_seen"`
}

// Sources returns per-source totals over the window, worst offenders first.
//
// "Failing" counts messages where neither DKIM nor SPF aligned. That is the
// only definition that matters to a domain owner: a valid signature from an
// unaligned domain still fails DMARC.
func (s *Store) Sources(ctx context.Context, since time.Time, domain string, limit int) ([]SourceDetail, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT source_ip, domain,
		       SUM(message_count),
		       SUM(CASE WHEN dkim = 'pass' OR spf = 'pass' THEN message_count ELSE 0 END),
		       SUM(CASE WHEN dkim != 'pass' AND spf != 'pass' THEN message_count ELSE 0 END),
		       SUM(CASE WHEN disposition = 'quarantine' THEN message_count ELSE 0 END),
		       SUM(CASE WHEN disposition = 'reject' THEN message_count ELSE 0 END),
		       MIN(end_at), MAX(end_at)
		FROM dmarc_row
		WHERE tenant_id = ? AND end_at >= ? AND (? = '' OR domain = ?)
		GROUP BY source_ip, domain
		ORDER BY SUM(CASE WHEN dkim != 'pass' AND spf != 'pass' THEN message_count ELSE 0 END) DESC,
		         SUM(message_count) DESC
		LIMIT ?`,
		s.tenant, since.Unix(), domain, domain, limit)
	if err != nil {
		return nil, fmt.Errorf("query sources: %w", err)
	}
	defer rows.Close()

	var out []SourceDetail
	for rows.Next() {
		var (
			d                   SourceDetail
			firstSeen, lastSeen int64
		)
		if err := rows.Scan(&d.SourceIP, &d.Domain, &d.Total, &d.Passing, &d.Failing,
			&d.Quarantined, &d.Rejected, &firstSeen, &lastSeen); err != nil {
			return nil, fmt.Errorf("scan source: %w", err)
		}
		d.FirstSeen = time.Unix(firstSeen, 0).UTC().Format(time.RFC3339)
		d.LastSeen = time.Unix(lastSeen, 0).UTC().Format(time.RFC3339)
		out = append(out, d)
	}
	return out, rows.Err()
}

// QuarantineEntry is a message that could not be parsed.
type QuarantineEntry struct {
	ID        int64  `json:"id"`
	Feeder    string `json:"feeder"`
	SourceRef string `json:"source_ref"`
	MessageID string `json:"message_id"`
	Received  string `json:"received"`
	Error     string `json:"error"`
	Size      int    `json:"size"`
}

// Quarantine lists messages awaiting diagnosis, newest first.
func (s *Store) Quarantine(ctx context.Context, limit int) ([]QuarantineEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, feeder, source_ref, message_id, received_at, error, COALESCE(LENGTH(body), 0)
		FROM raw_report
		WHERE tenant_id = ? AND state = ?
		ORDER BY received_at DESC LIMIT ?`,
		s.tenant, StateQuarantined, limit)
	if err != nil {
		return nil, fmt.Errorf("query quarantine: %w", err)
	}
	defer rows.Close()

	var out []QuarantineEntry
	for rows.Next() {
		var (
			e  QuarantineEntry
			ts int64
		)
		if err := rows.Scan(&e.ID, &e.Feeder, &e.SourceRef, &e.MessageID, &ts, &e.Error, &e.Size); err != nil {
			return nil, fmt.Errorf("scan quarantine entry: %w", err)
		}
		e.Received = time.Unix(ts, 0).UTC().Format(time.RFC3339)
		out = append(out, e)
	}
	return out, rows.Err()
}

// DomainSummary is the headline view for one domain.
type DomainSummary struct {
	Domain        string  `json:"domain"`
	Messages      int64   `json:"messages"`
	Passing       int64   `json:"passing"`
	Failing       int64   `json:"failing"`
	PassRate      float64 `json:"pass_rate"`
	Sources       int64   `json:"sources"`
	Reports       int64   `json:"reports"`
	Policy        string  `json:"policy"`
	TLSSuccessful int64   `json:"tls_successful"`
	TLSFailed     int64   `json:"tls_failed"`
	LastReportAt  string  `json:"last_report_at"`
}

// DomainSummaries returns one row per domain seen in the window.
func (s *Store) DomainSummaries(ctx context.Context, since time.Time) ([]DomainSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT domain,
		       SUM(message_count),
		       SUM(CASE WHEN dkim = 'pass' OR spf = 'pass' THEN message_count ELSE 0 END),
		       SUM(CASE WHEN dkim != 'pass' AND spf != 'pass' THEN message_count ELSE 0 END),
		       COUNT(DISTINCT source_ip)
		FROM dmarc_row
		WHERE tenant_id = ? AND end_at >= ?
		GROUP BY domain ORDER BY SUM(message_count) DESC`,
		s.tenant, since.Unix())
	if err != nil {
		return nil, fmt.Errorf("query domain summaries: %w", err)
	}
	defer rows.Close()

	var out []DomainSummary
	for rows.Next() {
		var d DomainSummary
		if err := rows.Scan(&d.Domain, &d.Messages, &d.Passing, &d.Failing, &d.Sources); err != nil {
			return nil, fmt.Errorf("scan domain summary: %w", err)
		}
		if d.Messages > 0 {
			d.PassRate = float64(d.Passing) / float64(d.Messages)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range out {
		if err := s.decorateDomain(ctx, &out[i], since); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) decorateDomain(ctx context.Context, d *DomainSummary, since time.Time) error {
	var (
		reports sql.NullInt64
		policy  sql.NullString
		last    sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*), MAX(ingested_at),
		       (SELECT policy_p FROM report
		         WHERE tenant_id = ? AND domain = ? AND policy_p != ''
		         ORDER BY end_at DESC LIMIT 1)
		FROM report WHERE tenant_id = ? AND domain = ? AND end_at >= ?`,
		s.tenant, d.Domain, s.tenant, d.Domain, since.Unix()).Scan(&reports, &last, &policy)
	if err != nil {
		return fmt.Errorf("decorate domain %q: %w", d.Domain, err)
	}
	d.Reports = reports.Int64
	d.Policy = policy.String
	if last.Valid {
		d.LastReportAt = time.Unix(last.Int64, 0).UTC().Format(time.RFC3339)
	}

	var successful, failed sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `
		SELECT SUM(successful), SUM(failed) FROM tlsrpt_policy
		WHERE tenant_id = ? AND domain = ? AND end_at >= ?`,
		s.tenant, d.Domain, since.Unix()).Scan(&successful, &failed); err != nil {
		return fmt.Errorf("decorate domain tls %q: %w", d.Domain, err)
	}
	d.TLSSuccessful = successful.Int64
	d.TLSFailed = failed.Int64

	return nil
}
