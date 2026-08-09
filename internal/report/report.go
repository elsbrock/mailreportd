// Package report holds the normalized representation of every report format
// the daemon ingests, and the parsers that produce it.
//
// Parsing is deliberately separated from transport: a parser takes bytes and a
// format hint, and knows nothing about how those bytes arrived. This is what
// lets an IMAP poll, a maildir scan and an HTTPS submission share one core.
package report

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Format identifies a report format.
type Format string

const (
	FormatDMARCAggregate Format = "dmarc_aggregate"
	FormatDMARCFailure   Format = "dmarc_failure"
	FormatTLSRPT         Format = "tlsrpt"
)

// Report is the normalized envelope shared by all formats. Format-specific
// detail hangs off the corresponding slice; exactly one is populated.
type Report struct {
	Format   Format
	Reporter string // reporting organization
	Email    string // reporter contact
	ReportID string
	Domain   string // policy domain the report concerns
	Begin    time.Time
	End      time.Time

	Policy      *DMARCPolicy
	DMARCRows   []DMARCRow
	TLSPolicies []TLSPolicy
}

// Identity is the deduplication key for a report. Reporters resend, mailboxes
// get reprocessed, and the same report routinely arrives twice; ingest must be
// idempotent on this tuple.
//
// ReportID alone is not sufficient: it is only required to be unique per
// reporting organization, and some reporters reuse it across windows.
func (r *Report) Identity() string {
	return fmt.Sprintf("%s|%s|%s|%d", r.Format, strings.ToLower(r.Reporter), r.ReportID, r.Begin.Unix())
}

// DMARCPolicy is the policy the reporter observed in DNS at evaluation time.
// It is worth storing because a report evaluated against a stale policy
// explains results that otherwise look wrong.
type DMARCPolicy struct {
	Domain          string
	ADKIM           string // r or s
	ASPF            string // r or s
	P               string // none, quarantine, reject
	SP              string
	Pct             int
	FailureOptions  string
}

// DMARCRow is one aggregate record: a count of messages from one source IP
// that shared an evaluation outcome.
type DMARCRow struct {
	SourceIP    netip.Addr
	Count       int64
	Disposition string // none, quarantine, reject
	DKIM        string // aligned result: pass or fail
	SPF         string // aligned result: pass or fail
	Reasons     []PolicyOverride
	HeaderFrom  string
	EnvelopeTo  string
	EnvelopeFrom string
	DKIMAuth    []DKIMAuth
	SPFAuth     []SPFAuth
}

// Aligned reports whether both mechanisms passed DMARC alignment. This is the
// only pass/fail that matters for the domain owner: a message can carry a valid
// DKIM signature and still fail DMARC if the signing domain is not aligned.
func (r DMARCRow) Aligned() bool {
	return r.DKIM == "pass" || r.SPF == "pass"
}

// PolicyOverride records why a receiver applied something other than the
// published policy.
type PolicyOverride struct {
	Type    string // forwarded, sampled_out, trusted_forwarder, mailing_list, local_policy, other
	Comment string
}

// DKIMAuth is one DKIM signature evaluation.
type DKIMAuth struct {
	Domain   string
	Selector string
	Result   string
	Human    string
}

// SPFAuth is one SPF evaluation.
type SPFAuth struct {
	Domain string
	Scope  string // mfrom or helo
	Result string
}

// TLSPolicy is one policy result from an SMTP TLS report.
type TLSPolicy struct {
	PolicyType   string // sts, tlsa, no-policy-found
	PolicyDomain string
	MXHosts      []string
	Successful   int64
	Failed       int64
	Failures     []TLSFailure
}

// TLSFailure is one failure detail group within a policy result.
type TLSFailure struct {
	ResultType          string
	SendingMTAIP        string
	ReceivingMXHostname string
	ReceivingMXHelo     string
	ReceivingIP         string
	Count               int64
	FailureReasonCode   string
	AdditionalInfoURI   string
}

// normalize lowercases and trims a result token. Reporters are inconsistent
// about case and padding, and comparing raw values silently splits metrics
// across "Pass" and "pass".
func normalize(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
