package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/elsbrock/mailreportd/internal/report"
)

// DMARCSource is authentication volume from one source address, grouped by
// outcome. The exporter reads these, classifies each address, and only then
// aggregates — which is how per-source detail stays out of Prometheus while
// still informing the exported series.
type DMARCSource struct {
	Domain string
	// Reporter is the reporting organization, normalized by reporterExpr.
	// Anyone can mail the rua address, so it is as attacker-chosen as the
	// source address and the exporter bounds it before it becomes a label.
	Reporter    string
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
		SELECT r.domain, `+reporterExpr+`, r.source_ip, r.disposition, r.dkim, r.spf, SUM(r.message_count)
		FROM dmarc_row r JOIN report rep ON rep.id = r.report_id
		WHERE r.tenant_id = ? AND r.end_at >= ?
		GROUP BY 1, 2, 3, 4, 5, 6`,
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
		if err := rows.Scan(&src.Domain, &src.Reporter, &ip, &src.Disposition, &src.DKIM, &src.SPF, &src.Count); err != nil {
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
	DKIMPass    int64  `json:"dkim_pass"`
	SPFPass     int64  `json:"spf_pass"`
	Quarantined int64  `json:"quarantined"`
	Rejected    int64  `json:"rejected"`
	FirstSeen   string `json:"first_seen"`
	LastSeen    string `json:"last_seen"`
}

// Sources returns per-source totals over the window, worst offenders first.
//
// "Failing" counts messages where neither DKIM nor SPF aligned. That is the
// only definition that matters to a domain owner: a valid signature from an
// unaligned domain still fails DMARC. DKIMPass and SPFPass split it back up,
// because a source passing DMARC on SPF alone has lost DKIM, and nothing in
// Passing says so.
//
// A non-empty reporter narrows the result to what one receiver reported.
func (s *Store) Sources(ctx context.Context, since time.Time, domain, reporter string, limit int) ([]SourceDetail, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.source_ip, r.domain,
		       SUM(r.message_count),
		       SUM(CASE WHEN r.dkim = 'pass' OR r.spf = 'pass' THEN r.message_count ELSE 0 END),
		       SUM(CASE WHEN r.dkim != 'pass' AND r.spf != 'pass' THEN r.message_count ELSE 0 END),
		       SUM(CASE WHEN r.dkim = 'pass' THEN r.message_count ELSE 0 END),
		       SUM(CASE WHEN r.spf = 'pass' THEN r.message_count ELSE 0 END),
		       SUM(CASE WHEN r.disposition = 'quarantine' THEN r.message_count ELSE 0 END),
		       SUM(CASE WHEN r.disposition = 'reject' THEN r.message_count ELSE 0 END),
		       MIN(r.end_at), MAX(r.end_at)
		FROM dmarc_row r JOIN report rep ON rep.id = r.report_id
		WHERE r.tenant_id = ? AND r.end_at >= ? AND (? = '' OR r.domain = ?)
		  AND (? = '' OR `+reporterExpr+` = `+reporterParam+`)
		GROUP BY r.source_ip, r.domain
		ORDER BY SUM(CASE WHEN r.dkim != 'pass' AND r.spf != 'pass' THEN r.message_count ELSE 0 END) DESC,
		         SUM(r.message_count) DESC
		LIMIT ?`,
		s.tenant, since.Unix(), domain, domain, reporter, reporter, limit)
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
			&d.DKIMPass, &d.SPFPass, &d.Quarantined, &d.Rejected, &firstSeen, &lastSeen); err != nil {
			return nil, fmt.Errorf("scan source: %w", err)
		}
		d.FirstSeen = time.Unix(firstSeen, 0).UTC().Format(time.RFC3339)
		d.LastSeen = time.Unix(lastSeen, 0).UTC().Format(time.RFC3339)
		out = append(out, d)
	}
	return out, rows.Err()
}

// reporterExpr normalizes the reporting organization of the report joined as
// rep. Receivers are inconsistent about case and padding ("Outlook.com",
// "outlook.com"), and one receiver must group as one.
const reporterExpr = `LOWER(TRIM(rep.reporter))`

// reporterParam is the same normalization applied to a query parameter.
const reporterParam = `LOWER(TRIM(?))`

// ReporterDetail is what one receiver reported about one domain. A receiver
// reporting on several domains is one row per domain.
type ReporterDetail struct {
	Reporter  string `json:"reporter"`
	Domain    string `json:"domain"`
	Reports   int64  `json:"reports"`
	Total     int64  `json:"total"`
	Passing   int64  `json:"passing"`
	Failing   int64  `json:"failing"`
	DKIMPass  int64  `json:"dkim_pass"`
	SPFPass   int64  `json:"spf_pass"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// ReporterTotals is the collapsed remainder the limit cut off.
type ReporterTotals struct {
	Reporters int64 `json:"reporters"`
	Messages  int64 `json:"messages"`
}

// Reporters returns per-receiver totals over the window, busiest first, plus
// the remainder the limit cut off.
//
// The reporter is whatever org_name the report claims, and anyone can mail
// the rua address. Grouping stays in SQL and the limit bounds what leaves it,
// for the same reason as Signers.
func (s *Store) Reporters(ctx context.Context, since time.Time, domain string, limit int) ([]ReporterDetail, ReporterTotals, error) {
	if limit <= 0 {
		limit = 100
	}
	const from = `
		FROM dmarc_row r JOIN report rep ON rep.id = r.report_id
		WHERE r.tenant_id = ? AND r.end_at >= ? AND (? = '' OR r.domain = ?)`

	var totals ReporterTotals
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(SUM(m), 0) FROM (
			SELECT SUM(r.message_count) AS m`+from+`
			GROUP BY `+reporterExpr+`, r.domain)`,
		s.tenant, since.Unix(), domain, domain).Scan(&totals.Reporters, &totals.Messages)
	if err != nil {
		return nil, ReporterTotals{}, fmt.Errorf("count reporters: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT `+reporterExpr+`, r.domain,
		       COUNT(DISTINCT r.report_id),
		       SUM(r.message_count),
		       SUM(CASE WHEN r.dkim = 'pass' OR r.spf = 'pass' THEN r.message_count ELSE 0 END),
		       SUM(CASE WHEN r.dkim != 'pass' AND r.spf != 'pass' THEN r.message_count ELSE 0 END),
		       SUM(CASE WHEN r.dkim = 'pass' THEN r.message_count ELSE 0 END),
		       SUM(CASE WHEN r.spf = 'pass' THEN r.message_count ELSE 0 END),
		       MIN(r.end_at), MAX(r.end_at)`+from+`
		GROUP BY 1, 2
		ORDER BY SUM(r.message_count) DESC, 1, 2
		LIMIT ?`,
		s.tenant, since.Unix(), domain, domain, limit)
	if err != nil {
		return nil, ReporterTotals{}, fmt.Errorf("query reporters: %w", err)
	}
	defer rows.Close()

	var out []ReporterDetail
	for rows.Next() {
		var (
			d                   ReporterDetail
			firstSeen, lastSeen int64
		)
		if err := rows.Scan(&d.Reporter, &d.Domain, &d.Reports, &d.Total, &d.Passing, &d.Failing,
			&d.DKIMPass, &d.SPFPass, &firstSeen, &lastSeen); err != nil {
			return nil, ReporterTotals{}, fmt.Errorf("scan reporter: %w", err)
		}
		d.FirstSeen = time.Unix(firstSeen, 0).UTC().Format(time.RFC3339)
		d.LastSeen = time.Unix(lastSeen, 0).UTC().Format(time.RFC3339)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, ReporterTotals{}, err
	}

	for _, d := range out {
		totals.Messages -= d.Total
	}
	totals.Reporters -= int64(len(out))
	totals.Reporters = max(totals.Reporters, 0)
	totals.Messages = max(totals.Messages, 0)
	return out, totals, nil
}

// SignerDetail is one DKIM signing identity seen signing mail for a domain.
//
// Messages counts every message the signature appeared on. SignaturePass counts
// those where the signature itself verified, and EvaluatedPass those where the
// receiver's own aligned DKIM verdict passed. The two differ precisely when a
// signature is valid but unaligned, which is the case this endpoint exists to
// make visible.
type SignerDetail struct {
	SigningDomain string `json:"signing_domain"`
	Selector      string `json:"selector"`
	Domain        string `json:"domain"`
	Relationship  string `json:"relationship"`
	Messages      int64  `json:"messages"`
	SignaturePass int64  `json:"signature_pass"`
	EvaluatedPass int64  `json:"evaluated_dkim_pass"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
	// Days breaks the counts down by report day, oldest first, so drift in
	// either pass count shows as a trend rather than a window total. Only days
	// with mail are listed.
	Days []SignerDay `json:"days"`
}

// SignerDay is one signer's counts for the reports covering one UTC day.
type SignerDay struct {
	Day           string `json:"day"`
	Messages      int64  `json:"messages"`
	SignaturePass int64  `json:"signature_pass"`
	EvaluatedPass int64  `json:"evaluated_dkim_pass"`
}

// SignerTotals is the collapsed remainder: everything the top-N cut off.
type SignerTotals struct {
	Signers  int64 `json:"signers"`
	Messages int64 `json:"messages"`
}

// Relationship values. Deliberately not called "aligned": relaxed alignment is
// equality of organizational domains, which needs a public suffix list to
// compute. The receiver already evaluated real alignment and we report that
// verdict separately, in EvaluatedPass.
const (
	// RelationExact is a signing domain identical to the policy domain.
	RelationExact = "exact"
	// RelationSubdomain is one a label or more below the other, either way
	// around. Under relaxed alignment — the default — this aligns.
	RelationSubdomain = "subdomain"
	// RelationForeign shares no suffix with the policy domain. Under relaxed
	// alignment it may still align if both sit under one organizational
	// domain, which is the case a suffix rule alone cannot see.
	RelationForeign = "foreign"
)

const signerFrom = `
	FROM dmarc_row r JOIN report rep ON rep.id = r.report_id, json_each(r.dkim_auth) j
	WHERE r.tenant_id = ? AND r.end_at >= ? AND (? = '' OR r.domain = ?)
	  AND (? = '' OR ` + reporterExpr + ` = ` + reporterParam + `)`

// signerDay attributes a report to the UTC day its window covers. Windows
// commonly end exactly at midnight, which belongs to the day before.
const signerDay = `date(r.end_at - 1, 'unixepoch')`

// Signers returns the DKIM signing identities seen over the window, busiest
// first, plus the remainder the limit cut off.
//
// Grouping happens in SQL over json_each rather than by scanning rows into Go,
// because the signing domain is chosen by whoever sent the message: a spoofer
// can emit a distinct d= per message, and the row set is the one thing here
// that an outsider can inflate at will. The aggregate never leaves the
// database unbounded, and the caller's limit bounds what does.
func (s *Store) Signers(ctx context.Context, since time.Time, domain, reporter string, limit int) ([]SignerDetail, SignerTotals, error) {
	if limit <= 0 {
		limit = 100
	}
	var totals SignerTotals
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(SUM(m), 0) FROM (
			SELECT SUM(r.message_count) AS m`+signerFrom+`
			GROUP BY json_extract(j.value, '$.Domain'),
			         json_extract(j.value, '$.Selector'), r.domain)`,
		s.tenant, since.Unix(), domain, domain, reporter, reporter).Scan(&totals.Signers, &totals.Messages)
	if err != nil {
		return nil, SignerTotals{}, fmt.Errorf("count signers: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT COALESCE(json_extract(j.value, '$.Domain'), ''),
		       COALESCE(json_extract(j.value, '$.Selector'), ''),
		       r.domain,
		       SUM(r.message_count),
		       SUM(CASE WHEN json_extract(j.value, '$.Result') = 'pass'
		                THEN r.message_count ELSE 0 END),
		       SUM(CASE WHEN r.dkim = 'pass' THEN r.message_count ELSE 0 END),
		       MIN(r.end_at), MAX(r.end_at)`+signerFrom+`
		GROUP BY 1, 2, 3
		ORDER BY SUM(r.message_count) DESC, 1, 2, 3
		LIMIT ?`,
		s.tenant, since.Unix(), domain, domain, reporter, reporter, limit)
	if err != nil {
		return nil, SignerTotals{}, fmt.Errorf("query signers: %w", err)
	}
	defer rows.Close()

	var out []SignerDetail
	for rows.Next() {
		var (
			d                   SignerDetail
			firstSeen, lastSeen int64
		)
		if err := rows.Scan(&d.SigningDomain, &d.Selector, &d.Domain, &d.Messages,
			&d.SignaturePass, &d.EvaluatedPass, &firstSeen, &lastSeen); err != nil {
			return nil, SignerTotals{}, fmt.Errorf("scan signer: %w", err)
		}
		d.Relationship = Relationship(d.SigningDomain, d.Domain)
		d.FirstSeen = time.Unix(firstSeen, 0).UTC().Format(time.RFC3339)
		d.LastSeen = time.Unix(lastSeen, 0).UTC().Format(time.RFC3339)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, SignerTotals{}, err
	}

	if err := s.signerDays(ctx, since, domain, reporter, limit, out); err != nil {
		return nil, SignerTotals{}, err
	}

	// What the limit cut off, so a truncated answer never reads as a complete
	// one.
	for _, d := range out {
		totals.Messages -= d.Messages
	}
	totals.Signers -= int64(len(out))
	if totals.Signers < 0 {
		totals.Signers = 0
	}
	if totals.Messages < 0 {
		totals.Messages = 0
	}
	return out, totals, nil
}

// signerDays fills in the per-day breakdown of the top signers. The top set is
// recomputed in SQL with the same ordering and limit as Signers, so the day
// rows of signers the limit cut off never leave the database.
func (s *Store) signerDays(ctx context.Context, since time.Time, domain, reporter string, limit int, signers []SignerDetail) error {
	if len(signers) == 0 {
		return nil
	}
	type key struct{ signing, selector, domain string }
	index := make(map[key]int, len(signers))
	for i, d := range signers {
		index[key{d.SigningDomain, d.Selector, d.Domain}] = i
		signers[i].Days = []SignerDay{}
	}

	const signer = `COALESCE(json_extract(j.value, '$.Domain'), ''),
		       COALESCE(json_extract(j.value, '$.Selector'), ''),
		       r.domain`
	rows, err := s.db.QueryContext(ctx, `
		WITH top (signing, selector, domain) AS (
			SELECT `+signer+signerFrom+`
			GROUP BY 1, 2, 3
			ORDER BY SUM(r.message_count) DESC, 1, 2, 3
			LIMIT ?)
		SELECT `+signer+`, `+signerDay+`,
		       SUM(r.message_count),
		       SUM(CASE WHEN json_extract(j.value, '$.Result') = 'pass'
		                THEN r.message_count ELSE 0 END),
		       SUM(CASE WHEN r.dkim = 'pass' THEN r.message_count ELSE 0 END)`+signerFrom+`
		  AND (`+signer+`) IN (SELECT signing, selector, domain FROM top)
		GROUP BY 1, 2, 3, 4
		ORDER BY 4`,
		s.tenant, since.Unix(), domain, domain, reporter, reporter, limit,
		s.tenant, since.Unix(), domain, domain, reporter, reporter)
	if err != nil {
		return fmt.Errorf("query signer days: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			k   key
			day SignerDay
		)
		if err := rows.Scan(&k.signing, &k.selector, &k.domain, &day.Day,
			&day.Messages, &day.SignaturePass, &day.EvaluatedPass); err != nil {
			return fmt.Errorf("scan signer day: %w", err)
		}
		if i, ok := index[k]; ok {
			signers[i].Days = append(signers[i].Days, day)
		}
	}
	return rows.Err()
}

// Relationship classifies a signing domain against the policy domain it signed
// for. Comparison is case-insensitive and ignores a trailing root dot, both of
// which reporters emit inconsistently.
func Relationship(signing, policy string) string {
	a := normalizeDomain(signing)
	b := normalizeDomain(policy)
	switch {
	case a == "" || b == "":
		return RelationForeign
	case a == b:
		return RelationExact
	case strings.HasSuffix(a, "."+b), strings.HasSuffix(b, "."+a):
		return RelationSubdomain
	default:
		return RelationForeign
	}
}

func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
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
	DKIMPass      int64   `json:"dkim_pass"`
	SPFPass       int64   `json:"spf_pass"`
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
		       SUM(CASE WHEN dkim = 'pass' THEN message_count ELSE 0 END),
		       SUM(CASE WHEN spf = 'pass' THEN message_count ELSE 0 END),
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
		if err := rows.Scan(&d.Domain, &d.Messages, &d.Passing, &d.Failing,
			&d.DKIMPass, &d.SPFPass, &d.Sources); err != nil {
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
