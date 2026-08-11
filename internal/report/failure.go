package report

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/mail"
	"net/textproto"
	"strings"
	"time"

	"github.com/emersion/go-message"
)

// FailureDetail is the parsed content of one DMARC failure report (RFC 6591).
//
// The fields split in two. The envelope facts — failure type, source, arrival,
// reporter — are no more sensitive than what aggregate reports already carry.
// Everything below the PII marker names recipients or contains message content,
// and must only ever reach disk encrypted.
type FailureDetail struct {
	AuthFailure  string // dkim, spf, dmarc, bodyhash, revoked, signature
	SourceIP     string
	ReportingMTA string
	Delivery     string // delivery-result: delivered, spam, policy, reject, other
	Arrival      time.Time

	// PII from here on.
	OriginalMailFrom string
	OriginalRcptTo   []string
	FeedbackReport   []byte // the raw machine-readable part, as sent
	OriginalMessage  []byte // message/rfc822 or rfc822-headers part, as sent
}

// ParseDMARCFailure parses one ARF message carrying an auth-failure report.
// It takes the whole raw message rather than an attachment, because ARF is a
// message structure — the report is the MIME tree itself.
func ParseDMARCFailure(raw []byte) (*Report, error) {
	entity, err := message.Read(bytes.NewReader(raw))
	if err != nil && entity == nil {
		return nil, fmt.Errorf("read arf message: %w", err)
	}

	fb, orig := failureParts(entity)
	if fb == nil {
		return nil, fmt.Errorf("no message/feedback-report part")
	}

	fields := feedbackFields(fb)
	if !strings.EqualFold(fields.Get("Feedback-Type"), "auth-failure") {
		return nil, fmt.Errorf("feedback type %q is not auth-failure", fields.Get("Feedback-Type"))
	}

	domain := normalizeDomain(fields.Get("Reported-Domain"))
	if domain == "" {
		return nil, fmt.Errorf("failure report names no reported domain")
	}

	detail := &FailureDetail{
		AuthFailure:      normalize(fields.Get("Auth-Failure")),
		SourceIP:         strings.TrimSpace(fields.Get("Source-IP")),
		ReportingMTA:     reportingMTA(fields.Get("Reporting-MTA")),
		Delivery:         normalize(fields.Get("Delivery-Result")),
		OriginalMailFrom: cleanAddress(fields.Get("Original-Mail-From")),
		FeedbackReport:   fb,
		OriginalMessage:  orig,
	}
	for _, rcpt := range fields.Values("Original-Rcpt-To") {
		if addr := cleanAddress(rcpt); addr != "" {
			detail.OriginalRcptTo = append(detail.OriginalRcptTo, addr)
		}
	}
	if t, err := mail.ParseDate(fields.Get("Arrival-Date")); err == nil {
		detail.Arrival = t
	} else if t, err := mail.ParseDate(entity.Header.Get("Date")); err == nil {
		detail.Arrival = t
	} else {
		detail.Arrival = time.Now()
	}

	reporter := detail.ReportingMTA
	if reporter == "" {
		reporter = parseFrom(entity.Header.Get("From"))
	}

	// Failure reports carry no report ID of their own. The message ID is the
	// dedupe identity, with a content hash for the reporter that omits both.
	reportID := strings.Trim(entity.Header.Get("Message-Id"), "<> ")
	if reportID == "" {
		sum := sha256.Sum256(raw)
		reportID = hex.EncodeToString(sum[:16])
	}

	return &Report{
		Format:   FormatDMARCFailure,
		Reporter: reporter,
		ReportID: reportID,
		Domain:   domain,
		Begin:    detail.Arrival,
		End:      detail.Arrival,
		Failure:  detail,
	}, nil
}

// arfPayload recognizes an ARF auth-failure report and claims the whole raw
// message as its payload. Non-auth-failure ARF — spam complaints — is left
// unclaimed, so it is recorded as ignored rather than quarantined.
func arfPayload(raw []byte, msg *Message) bool {
	entity, err := message.Read(bytes.NewReader(raw))
	if err != nil && entity == nil {
		return false
	}
	fb, _ := failureParts(entity)
	if fb == nil {
		return false
	}
	if !strings.EqualFold(feedbackFields(fb).Get("Feedback-Type"), "auth-failure") {
		return false
	}
	msg.Payloads = append(msg.Payloads, Payload{Format: FormatDMARCFailure, Data: raw})
	return true
}

// failureParts walks the MIME tree for the two parts that matter in an ARF
// message: the machine-readable feedback report and the original message.
func failureParts(entity *message.Entity) (fb, orig []byte) {
	mr := entity.MultipartReader()
	if mr == nil {
		return nil, nil
	}
	for {
		part, err := mr.NextPart()
		if err != nil {
			return fb, orig
		}
		mediaType, _, _ := part.Header.ContentType()
		switch mediaType {
		case "message/feedback-report":
			if fb == nil {
				fb, _ = io.ReadAll(io.LimitReader(part.Body, MaxPayloadSize))
			}
		case "message/rfc822", "text/rfc822-headers", "message/rfc822-headers":
			if orig == nil {
				orig, _ = io.ReadAll(io.LimitReader(part.Body, MaxPayloadSize))
			}
		default:
			nfb, norig := failureParts(part)
			if fb == nil {
				fb = nfb
			}
			if orig == nil {
				orig = norig
			}
		}
		if fb != nil && orig != nil {
			return fb, orig
		}
	}
}

// feedbackFields parses the header-shaped body of a feedback-report part. A
// part that ends without a blank line still yields the fields read so far,
// which is the tolerant thing: reporters routinely omit the terminator.
func feedbackFields(fb []byte) textproto.MIMEHeader {
	r := textproto.NewReader(bufio.NewReader(bytes.NewReader(append(fb, '\r', '\n'))))
	fields, _ := r.ReadMIMEHeader()
	return fields
}

// reportingMTA strips the RFC 3464 type prefix: "dns; mx.example.org" names
// the host, and the prefix is transport detail.
func reportingMTA(v string) string {
	if _, host, ok := strings.Cut(v, ";"); ok {
		v = host
	}
	return normalizeDomain(v)
}

// cleanAddress strips the angle brackets some reporters keep around addresses.
func cleanAddress(v string) string {
	return strings.Trim(strings.TrimSpace(v), "<>")
}
