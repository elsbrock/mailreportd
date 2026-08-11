package report

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/elsbrock/mailreportd/internal/imaptest"
)

func arrival() time.Time {
	return time.Date(2026, 8, 10, 8, 15, 0, 0, time.UTC)
}

func TestDecodeRecognizesARF(t *testing.T) {
	raw := imaptest.FailureMail(t, "arf-1", "example.org", "victim@dest.example", arrival())

	msg, err := DecodeMessage(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(msg.Payloads) != 1 {
		t.Fatalf("payloads = %d, want 1", len(msg.Payloads))
	}
	if msg.Payloads[0].Format != FormatDMARCFailure {
		t.Fatalf("format = %q, want %q", msg.Payloads[0].Format, FormatDMARCFailure)
	}
}

func TestParseDMARCFailure(t *testing.T) {
	raw := imaptest.FailureMail(t, "arf-1", "example.org", "victim@dest.example", arrival())

	rep, err := ParseDMARCFailure(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if rep.Format != FormatDMARCFailure {
		t.Errorf("format = %q", rep.Format)
	}
	if rep.Domain != "example.org" {
		t.Errorf("domain = %q", rep.Domain)
	}
	if rep.Reporter != "mx.receiver.example" {
		t.Errorf("reporter = %q", rep.Reporter)
	}
	if rep.ReportID != "arf-1@receiver.example" {
		t.Errorf("report id = %q", rep.ReportID)
	}
	if !rep.Begin.Equal(arrival()) {
		t.Errorf("begin = %v, want %v", rep.Begin, arrival())
	}

	f := rep.Failure
	if f == nil {
		t.Fatal("no failure detail")
	}
	if f.AuthFailure != "dmarc" || f.Delivery != "reject" {
		t.Errorf("auth_failure = %q delivery = %q", f.AuthFailure, f.Delivery)
	}
	if f.SourceIP != "198.51.100.7" {
		t.Errorf("source ip = %q", f.SourceIP)
	}
	if f.OriginalMailFrom != "bounce@example.org" {
		t.Errorf("mail from = %q", f.OriginalMailFrom)
	}
	if len(f.OriginalRcptTo) != 1 || f.OriginalRcptTo[0] != "victim@dest.example" {
		t.Errorf("rcpt to = %v", f.OriginalRcptTo)
	}
	if !strings.Contains(string(f.OriginalMessage), "the original message") {
		t.Error("original message not captured")
	}
	if !strings.Contains(string(f.FeedbackReport), "Feedback-Type: auth-failure") {
		t.Error("feedback report not captured")
	}
}

func TestSpamComplaintIsNotClaimed(t *testing.T) {
	raw := imaptest.SpamComplaintMail(t, "abuse-1")

	_, err := DecodeMessage(raw)
	if !errors.Is(err, ErrNoPayload) {
		t.Fatalf("err = %v, want ErrNoPayload so the message is recorded as ignored", err)
	}
}

// A failure report identity must be stable across redelivery of the same
// message, and distinct across different reports from the same reporter.
func TestFailureIdentity(t *testing.T) {
	a1, _ := ParseDMARCFailure(imaptest.FailureMail(t, "arf-1", "example.org", "v@dest.example", arrival()))
	a2, _ := ParseDMARCFailure(imaptest.FailureMail(t, "arf-1", "example.org", "v@dest.example", arrival()))
	b, _ := ParseDMARCFailure(imaptest.FailureMail(t, "arf-2", "example.org", "v@dest.example", arrival()))

	if a1.Identity() != a2.Identity() {
		t.Error("same message produced different identities")
	}
	if a1.Identity() == b.Identity() {
		t.Error("different messages share an identity")
	}
}
