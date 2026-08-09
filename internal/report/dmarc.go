package report

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-message/charset"
)

// ParseDMARCAggregate parses an RFC 7489 aggregate feedback document.
//
// Real reporters deviate from the published schema in small, consistent ways:
// integers arrive padded or empty, timestamps arrive as either Unix seconds or
// ISO 8601, and character sets are declared that Go does not handle natively.
// The parser tolerates all of these because rejecting a report means losing a
// day of visibility for that receiver, and there is no way to ask for it again.
func ParseDMARCAggregate(data []byte) (*Report, error) {
	var fb xmlFeedback

	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.CharsetReader = charset.Reader
	dec.Strict = false
	if err := dec.Decode(&fb); err != nil {
		return nil, fmt.Errorf("decode aggregate xml: %w", err)
	}

	if fb.Metadata.ReportID == "" && fb.Metadata.OrgName == "" {
		return nil, fmt.Errorf("not a dmarc aggregate report: no report metadata")
	}

	rep := &Report{
		Format:   FormatDMARCAggregate,
		Reporter: strings.TrimSpace(fb.Metadata.OrgName),
		Email:    strings.TrimSpace(fb.Metadata.Email),
		ReportID: strings.TrimSpace(fb.Metadata.ReportID),
		Domain:   normalizeDomain(fb.Policy.Domain),
		Begin:    fb.Metadata.DateRange.Begin.Time(),
		End:      fb.Metadata.DateRange.End.Time(),
		Policy: &DMARCPolicy{
			Domain:         normalizeDomain(fb.Policy.Domain),
			ADKIM:          normalize(fb.Policy.ADKIM),
			ASPF:           normalize(fb.Policy.ASPF),
			P:              normalize(fb.Policy.P),
			SP:             normalize(fb.Policy.SP),
			Pct:            fb.Policy.Pct.IntOr(100),
			FailureOptions: normalize(fb.Policy.FO),
		},
	}

	// A report with no policy domain is unusable: nothing can be attributed.
	// Fall back to the first header_from seen rather than dropping it, since
	// some reporters omit policy_published entirely.
	if rep.Domain == "" && len(fb.Records) > 0 {
		rep.Domain = normalizeDomain(fb.Records[0].Identifiers.HeaderFrom)
	}
	if rep.Domain == "" {
		return nil, fmt.Errorf("aggregate report has no policy domain")
	}

	rep.DMARCRows = make([]DMARCRow, 0, len(fb.Records))
	for _, rec := range fb.Records {
		row, err := rec.normalized()
		if err != nil {
			// One malformed record must not discard the rest of the report.
			// The count is what matters, and losing a source is better than
			// losing every source the receiver told us about.
			continue
		}
		rep.DMARCRows = append(rep.DMARCRows, row)
	}
	if len(rep.DMARCRows) == 0 {
		return nil, fmt.Errorf("aggregate report has no usable records")
	}

	return rep, nil
}

func (rec xmlRecord) normalized() (DMARCRow, error) {
	ip, err := parseIP(rec.Row.SourceIP)
	if err != nil {
		return DMARCRow{}, err
	}

	row := DMARCRow{
		SourceIP:     ip,
		Count:        rec.Row.Count.Int64(),
		Disposition:  normalize(rec.Row.PolicyEvaluated.Disposition),
		DKIM:         normalize(rec.Row.PolicyEvaluated.DKIM),
		SPF:          normalize(rec.Row.PolicyEvaluated.SPF),
		HeaderFrom:   normalizeDomain(rec.Identifiers.HeaderFrom),
		EnvelopeFrom: normalizeDomain(rec.Identifiers.EnvelopeFrom),
		EnvelopeTo:   normalizeDomain(rec.Identifiers.EnvelopeTo),
	}

	// An absent disposition means the policy was not applied, which is "none".
	if row.Disposition == "" {
		row.Disposition = "none"
	}
	// A record with no count still describes at least one message.
	if row.Count <= 0 {
		row.Count = 1
	}

	for _, r := range rec.Row.PolicyEvaluated.Reasons {
		row.Reasons = append(row.Reasons, PolicyOverride{
			Type:    normalize(r.Type),
			Comment: strings.TrimSpace(r.Comment),
		})
	}
	for _, d := range rec.AuthResults.DKIM {
		row.DKIMAuth = append(row.DKIMAuth, DKIMAuth{
			Domain:   normalizeDomain(d.Domain),
			Selector: strings.TrimSpace(d.Selector),
			Result:   normalize(d.Result),
			Human:    strings.TrimSpace(d.HumanResult),
		})
	}
	for _, s := range rec.AuthResults.SPF {
		row.SPFAuth = append(row.SPFAuth, SPFAuth{
			Domain: normalizeDomain(s.Domain),
			Scope:  normalize(s.Scope),
			Result: normalize(s.Result),
		})
	}

	return row, nil
}

// parseIP accepts what reporters actually send: padded addresses, IPv4-mapped
// IPv6 forms, and addresses carrying a zone that is meaningless to us.
func parseIP(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, fmt.Errorf("empty source ip")
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse source ip %q: %w", s, err)
	}
	addr = addr.WithZone("")
	// Normalize ::ffff:1.2.3.4 to 1.2.3.4 so the same source is never counted
	// as two distinct addresses.
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	return addr, nil
}

func normalizeDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.TrimSuffix(s, ".")
}

// --- wire types -------------------------------------------------------------

type xmlFeedback struct {
	XMLName  xml.Name     `xml:"feedback"`
	Metadata xmlMetadata  `xml:"report_metadata"`
	Policy   xmlPolicy    `xml:"policy_published"`
	Records  []xmlRecord  `xml:"record"`
}

type xmlMetadata struct {
	OrgName   string       `xml:"org_name"`
	Email     string       `xml:"email"`
	ReportID  string       `xml:"report_id"`
	DateRange xmlDateRange `xml:"date_range"`
}

type xmlDateRange struct {
	Begin flexTime `xml:"begin"`
	End   flexTime `xml:"end"`
}

type xmlPolicy struct {
	Domain string  `xml:"domain"`
	ADKIM  string  `xml:"adkim"`
	ASPF   string  `xml:"aspf"`
	P      string  `xml:"p"`
	SP     string  `xml:"sp"`
	Pct    flexInt `xml:"pct"`
	FO     string  `xml:"fo"`
}

type xmlRecord struct {
	Row         xmlRow         `xml:"row"`
	Identifiers xmlIdentifiers `xml:"identifiers"`
	AuthResults xmlAuthResults `xml:"auth_results"`
}

type xmlRow struct {
	SourceIP        string             `xml:"source_ip"`
	Count           flexInt            `xml:"count"`
	PolicyEvaluated xmlPolicyEvaluated `xml:"policy_evaluated"`
}

type xmlPolicyEvaluated struct {
	Disposition string      `xml:"disposition"`
	DKIM        string      `xml:"dkim"`
	SPF         string      `xml:"spf"`
	Reasons     []xmlReason `xml:"reason"`
}

type xmlReason struct {
	Type    string `xml:"type"`
	Comment string `xml:"comment"`
}

type xmlIdentifiers struct {
	HeaderFrom   string `xml:"header_from"`
	EnvelopeFrom string `xml:"envelope_from"`
	EnvelopeTo   string `xml:"envelope_to"`
}

type xmlAuthResults struct {
	DKIM []xmlDKIM `xml:"dkim"`
	SPF  []xmlSPF  `xml:"spf"`
}

type xmlDKIM struct {
	Domain      string `xml:"domain"`
	Selector    string `xml:"selector"`
	Result      string `xml:"result"`
	HumanResult string `xml:"human_result"`
}

type xmlSPF struct {
	Domain string `xml:"domain"`
	Scope  string `xml:"scope"`
	Result string `xml:"result"`
}

// flexInt tolerates padded, empty and float-formatted integers.
type flexInt int64

func (v *flexInt) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var s string
	if err := d.DecodeElement(&s, &start); err != nil {
		return err
	}
	s = strings.TrimSpace(s)
	if s == "" {
		*v = 0
		return nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		*v = flexInt(n)
		return nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		*v = flexInt(f)
		return nil
	}
	// Unparseable counts are treated as absent rather than fatal.
	*v = 0
	return nil
}

func (v flexInt) Int64() int64 { return int64(v) }

func (v flexInt) IntOr(fallback int) int {
	if v == 0 {
		return fallback
	}
	return int(v)
}

// flexTime accepts Unix seconds, which the schema specifies, and ISO 8601,
// which several reporters send anyway.
type flexTime struct{ t time.Time }

func (v *flexTime) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var s string
	if err := d.DecodeElement(&s, &start); err != nil {
		return err
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		v.t = time.Unix(n, 0).UTC()
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			v.t = t.UTC()
			return nil
		}
	}
	return nil
}

func (v flexTime) Time() time.Time { return v.t }

// looksLikeAggregate reports whether data is plausibly a DMARC aggregate
// document, used to pick a parser when the transport gave no usable hint.
func looksLikeAggregate(data []byte) bool {
	probe := data
	if len(probe) > 2048 {
		probe = probe[:2048]
	}
	return bytes.Contains(probe, []byte("<feedback"))
}
