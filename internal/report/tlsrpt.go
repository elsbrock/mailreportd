package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ParseTLSRPT parses an RFC 8460 SMTP TLS report.
//
// Unlike DMARC aggregates, these arrive as JSON and are comparatively
// well-behaved, but the policy string field is polymorphic in the wild: the RFC
// specifies an array of strings and some senders emit a single string.
func ParseTLSRPT(data []byte) (*Report, error) {
	var doc tlsrptDoc
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode tls report json: %w", err)
	}

	if doc.ReportID == "" && doc.OrganizationName == "" {
		return nil, fmt.Errorf("not a tls report: no report identity")
	}

	rep := &Report{
		Format:   FormatTLSRPT,
		Reporter: strings.TrimSpace(doc.OrganizationName),
		Email:    strings.TrimSpace(doc.ContactInfo),
		ReportID: strings.TrimSpace(doc.ReportID),
		Begin:    doc.DateRange.Start,
		End:      doc.DateRange.End,
	}

	for _, p := range doc.Policies {
		policy := TLSPolicy{
			PolicyType:   normalize(p.Policy.PolicyType),
			PolicyDomain: normalizeDomain(p.Policy.PolicyDomain),
			MXHosts:      p.Policy.MXHost.values(),
			Successful:   p.Summary.Successful,
			Failed:       p.Summary.Failed,
		}
		for _, f := range p.FailureDetails {
			policy.Failures = append(policy.Failures, TLSFailure{
				ResultType:          normalize(f.ResultType),
				SendingMTAIP:        strings.TrimSpace(f.SendingMTAIP),
				ReceivingMXHostname: normalizeDomain(f.ReceivingMXHostname),
				ReceivingMXHelo:     normalizeDomain(f.ReceivingMXHelo),
				ReceivingIP:         strings.TrimSpace(f.ReceivingIP),
				Count:               f.FailedSessionCount,
				FailureReasonCode:   strings.TrimSpace(f.FailureReasonCode),
				AdditionalInfoURI:   strings.TrimSpace(f.AdditionalInfoURI),
			})
		}
		rep.TLSPolicies = append(rep.TLSPolicies, policy)
	}

	if len(rep.TLSPolicies) == 0 {
		return nil, fmt.Errorf("tls report has no policy results")
	}

	// TLS reports carry no report-level domain; the policy domain is the
	// attribution point. Reports covering several of our domains are split at
	// storage time, so the report-level value is only a label.
	rep.Domain = rep.TLSPolicies[0].PolicyDomain
	if rep.Domain == "" {
		return nil, fmt.Errorf("tls report has no policy domain")
	}

	return rep, nil
}

// ParseTLSRPTSubmission parses one HTTPS-submitted report body per RFC 8460
// §5.3: the payload alone, optionally gzipped, with no mail envelope around it.
// Compression is sniffed rather than read from Content-Type, as everywhere
// else: labels are conventional.
func ParseTLSRPTSubmission(body []byte) (*Report, error) {
	if isGzip(body) {
		data, err := gunzip(body)
		if err != nil {
			return nil, fmt.Errorf("decompress submission: %w", err)
		}
		body = data
	}
	if !looksLikeTLSRPT(body) {
		return nil, fmt.Errorf("body is not an RFC 8460 report")
	}
	return ParseTLSRPT(body)
}

// Domains lists every distinct policy domain covered by a TLS report.
func (r *Report) Domains() []string {
	if r.Format != FormatTLSRPT {
		return []string{r.Domain}
	}
	seen := make(map[string]bool, len(r.TLSPolicies))
	out := make([]string, 0, len(r.TLSPolicies))
	for _, p := range r.TLSPolicies {
		if p.PolicyDomain == "" || seen[p.PolicyDomain] {
			continue
		}
		seen[p.PolicyDomain] = true
		out = append(out, p.PolicyDomain)
	}
	return out
}

// --- wire types -------------------------------------------------------------

type tlsrptDoc struct {
	OrganizationName string          `json:"organization-name"`
	DateRange        tlsrptDateRange `json:"date-range"`
	ContactInfo      string          `json:"contact-info"`
	ReportID         string          `json:"report-id"`
	Policies         []tlsrptPolicy  `json:"policies"`
}

type tlsrptDateRange struct {
	Start time.Time `json:"start-datetime"`
	End   time.Time `json:"end-datetime"`
}

type tlsrptPolicy struct {
	Policy         tlsrptPolicyBody `json:"policy"`
	Summary        tlsrptSummary    `json:"summary"`
	FailureDetails []tlsrptFailure  `json:"failure-details"`
}

type tlsrptPolicyBody struct {
	PolicyType   string      `json:"policy-type"`
	PolicyString stringOrArr `json:"policy-string"`
	PolicyDomain string      `json:"policy-domain"`
	MXHost       stringOrArr `json:"mx-host"`
}

type tlsrptSummary struct {
	Successful int64 `json:"total-successful-session-count"`
	Failed     int64 `json:"total-failure-session-count"`
}

type tlsrptFailure struct {
	ResultType          string `json:"result-type"`
	SendingMTAIP        string `json:"sending-mta-ip"`
	ReceivingMXHostname string `json:"receiving-mx-hostname"`
	ReceivingMXHelo     string `json:"receiving-mx-helo"`
	ReceivingIP         string `json:"receiving-ip"`
	FailedSessionCount  int64  `json:"failed-session-count"`
	FailureReasonCode   string `json:"failure-reason-code"`
	AdditionalInfoURI   string `json:"additional-information"`
}

// stringOrArr accepts both the specified array form and the single-string form
// that some senders emit.
type stringOrArr []string

func (v *stringOrArr) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}
	if data[0] == '[' {
		var arr []string
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*v = arr
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*v = []string{s}
	return nil
}

func (v stringOrArr) values() []string {
	out := make([]string, 0, len(v))
	for _, s := range v {
		if s = normalizeDomain(s); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// looksLikeTLSRPT reports whether data is plausibly an RFC 8460 report.
func looksLikeTLSRPT(data []byte) bool {
	probe := data
	if len(probe) > 2048 {
		probe = probe[:2048]
	}
	return bytes.Contains(probe, []byte("\"policies\"")) ||
		bytes.Contains(probe, []byte("\"organization-name\""))
}
