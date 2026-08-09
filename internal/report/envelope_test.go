package report

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func zipBytes(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// multipartMessage builds a realistic report mail: a text part the operator
// would read, plus one base64 attachment.
func multipartMessage(subject, filename, contentType string, attachment []byte) []byte {
	var b strings.Builder
	b.WriteString("From: noreply-dmarc-support@google.com\r\n")
	b.WriteString("To: dmarc@example.org\r\n")
	b.WriteString("Message-Id: <test-message-id@google.com>\r\n")
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"SEP\"\r\n\r\n")

	b.WriteString("--SEP\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	b.WriteString("This is an aggregate report.\r\n\r\n")

	b.WriteString("--SEP\r\n")
	fmt.Fprintf(&b, "Content-Type: %s; name=\"%s\"\r\n", contentType, filename)
	fmt.Fprintf(&b, "Content-Disposition: attachment; filename=\"%s\"\r\n", filename)
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")

	enc := base64.StdEncoding.EncodeToString(attachment)
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteString("\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc)
	b.WriteString("\r\n\r\n--SEP--\r\n")

	return []byte(b.String())
}

func TestDecodeMessageGzipAttachment(t *testing.T) {
	raw := multipartMessage(
		"Report Domain: example.org",
		"google.com!example.org!1754006400!1754092799.xml.gz",
		"application/gzip",
		gzipBytes(t, []byte(googleAggregate)),
	)

	msg, err := DecodeMessage(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msg.MessageID != "test-message-id@google.com" {
		t.Errorf("message id = %q", msg.MessageID)
	}
	if msg.From != "noreply-dmarc-support@google.com" {
		t.Errorf("from = %q", msg.From)
	}
	if len(msg.Payloads) != 1 {
		t.Fatalf("payloads = %d, want 1", len(msg.Payloads))
	}
	if strings.HasSuffix(msg.Payloads[0].Filename, ".gz") {
		t.Errorf("filename should lose the .gz suffix: %q", msg.Payloads[0].Filename)
	}

	rep, err := Parse(msg.Payloads[0])
	if err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if rep.Domain != "example.org" || len(rep.DMARCRows) != 2 {
		t.Errorf("report = %+v", rep)
	}
}

func TestDecodeMessageZipAttachment(t *testing.T) {
	raw := multipartMessage(
		"Report Domain: example.org",
		"report.zip",
		"application/zip",
		zipBytes(t, "report.xml", []byte(googleAggregate)),
	)

	msg, err := DecodeMessage(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(msg.Payloads) != 1 {
		t.Fatalf("payloads = %d, want 1", len(msg.Payloads))
	}
	if _, err := Parse(msg.Payloads[0]); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
}

func TestDecodeMessageMislabeledContentType(t *testing.T) {
	// Reporters routinely label gzip as octet-stream, or as text/plain. Content
	// type must not be trusted; sniffing the magic bytes is what works.
	for _, ct := range []string{"application/octet-stream", "text/plain", "application/x-gzip"} {
		t.Run(ct, func(t *testing.T) {
			raw := multipartMessage("r", "report.xml.gz", ct, gzipBytes(t, []byte(googleAggregate)))
			msg, err := DecodeMessage(raw)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(msg.Payloads) != 1 {
				t.Fatalf("payloads = %d, want 1", len(msg.Payloads))
			}
		})
	}
}

func TestDecodeMessageTLSRPT(t *testing.T) {
	raw := multipartMessage(
		"Report Domain: example.org Submitter: google.com",
		"google.com!example.org!1754006400!1754092799.json.gz",
		"application/tlsrpt+gzip",
		gzipBytes(t, []byte(tlsReport)),
	)

	msg, err := DecodeMessage(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(msg.Payloads) != 1 {
		t.Fatalf("payloads = %d", len(msg.Payloads))
	}
	rep, err := Parse(msg.Payloads[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rep.Format != FormatTLSRPT {
		t.Errorf("format = %q", rep.Format)
	}
}

func TestDecodeMessageNoPayload(t *testing.T) {
	// A mailbox collects autoreplies and spam. These must be reported as
	// "nothing here" rather than as parse failures, or the quarantine fills
	// with noise and stops being a useful signal.
	raw := []byte("From: someone@example.com\r\n" +
		"Subject: Out of office\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"I am away until Monday.\r\n")

	_, err := DecodeMessage(raw)
	if !errors.Is(err, ErrNoPayload) {
		t.Fatalf("err = %v, want ErrNoPayload", err)
	}
}

func TestDecodeMessagePartialFailure(t *testing.T) {
	// One unreadable attachment must not cost us the readable one.
	var b strings.Builder
	b.WriteString("From: r@example.com\r\nSubject: r\r\nMIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"SEP\"\r\n\r\n")
	b.WriteString("--SEP\r\nContent-Type: application/gzip; name=\"broken.gz\"\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	b.WriteString(base64.StdEncoding.EncodeToString([]byte{0x1f, 0x8b, 0x08, 0x00, 0xff, 0xff}))
	b.WriteString("\r\n\r\n--SEP\r\nContent-Type: application/xml; name=\"good.xml\"\r\n\r\n")
	b.WriteString(googleAggregate)
	b.WriteString("\r\n--SEP--\r\n")

	msg, err := DecodeMessage([]byte(b.String()))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(msg.Payloads) != 1 {
		t.Fatalf("payloads = %d, want the one good attachment", len(msg.Payloads))
	}
	if _, err := Parse(msg.Payloads[0]); err != nil {
		t.Fatalf("parse: %v", err)
	}
}

func TestDecodeMessageRejectsOversize(t *testing.T) {
	if _, err := DecodeMessage(make([]byte, MaxMessageSize+1)); err == nil {
		t.Fatal("expected an error for an oversize message")
	}
}

func TestParseUnknownFormat(t *testing.T) {
	if _, err := Parse(Payload{Filename: "x.txt", Data: []byte("hello")}); err == nil {
		t.Fatal("expected an error")
	}
}
