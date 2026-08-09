// Package imaptest provides a real in-memory IMAP server for tests, plus
// report fixtures.
//
// The feeder's correctness lives in protocol details — UID semantics, peeking
// rather than marking read, UIDVALIDITY changes — and a hand-rolled fake would
// simply agree with whatever the feeder does. Tests here drive the real client
// against a real server over a real socket.
package imaptest

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

// testMailbox is a real IMAP server over a real socket.
//
// The feeder's correctness lives in protocol details — UID semantics, peeking
// rather than marking read, UIDVALIDITY changes — and a hand-rolled fake would
// simply agree with whatever the feeder does. This exercises the actual client
// against an actual server.
type Mailbox struct {
	addr     string
	user     *imapmemserver.User
	username string
	password string
}

func NewMailbox(t *testing.T) *Mailbox {
	t.Helper()

	const (
		username = "dmarc@example.org"
		password = "correct-horse"
		mailbox  = "INBOX"
	)

	user := imapmemserver.NewUser(username, password)
	if err := user.Create(mailbox, nil); err != nil {
		t.Fatalf("create mailbox: %v", err)
	}

	memServer := imapmemserver.New()
	memServer.AddUser(user)

	server := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return memServer.NewSession(), nil, nil
		},
		// The test connects over loopback without TLS.
		InsecureAuth: true,
		Logger:       log.New(io.Discard, "", 0),
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go server.Serve(listener)
	t.Cleanup(func() {
		server.Close()
		listener.Close()
	})

	return &Mailbox{
		addr:     listener.Addr().String(),
		user:     user,
		username: username,
		password: password,
	}
}

func (m *Mailbox) HostPort(t *testing.T) (string, int) {
	t.Helper()
	host, port, err := net.SplitHostPort(m.addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	var n int
	if _, err := fmt.Sscanf(port, "%d", &n); err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return host, n
}

// deliver appends a message to the mailbox over the wire, as a real MTA would.
func (m *Mailbox) Deliver(t *testing.T, body []byte) {
	t.Helper()

	client, err := imapclient.DialInsecure(m.addr, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	if err := client.Login(m.username, m.password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}

	cmd := client.Append("INBOX", int64(len(body)), nil)
	if _, err := cmd.Write(body); err != nil {
		t.Fatalf("append write: %v", err)
	}
	if err := cmd.Close(); err != nil {
		t.Fatalf("append close: %v", err)
	}
	if _, err := cmd.Wait(); err != nil {
		t.Fatalf("append: %v", err)
	}
	client.Logout().Wait()
}

// feederConfig returns a config pointing at this mailbox.
func (m *Mailbox) Credentials() (username, password string) {
	return m.username, m.password
}

// Addr is the host:port the server is listening on.
func (m *Mailbox) Addr() string { return m.addr }

// --- report fixtures --------------------------------------------------------

// aggregateXML reports a window ending twelve hours ago so fixtures always fall
// inside the daemon's aggregation window, whenever the suite runs.
func AggregateXML(reportID, domain string, pass, fail int) string {
	end := time.Now().Add(-12 * time.Hour)
	begin := end.Add(-24 * time.Hour)

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>%s</report_id>
    <date_range><begin>%d</begin><end>%d</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>%s</domain><adkim>r</adkim><aspf>r</aspf><p>reject</p><pct>100</pct>
  </policy_published>
  <record>
    <row><source_ip>203.0.113.10</source_ip><count>%d</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>%s</header_from></identifiers>
    <auth_results><dkim><domain>%s</domain><selector>selector1</selector><result>pass</result></dkim></auth_results>
  </record>
  <record>
    <row><source_ip>192.0.2.66</source_ip><count>%d</count>
      <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>%s</header_from></identifiers>
  </record>
</feedback>`, reportID, begin.Unix(), end.Unix(), domain, pass, domain, domain, fail, domain)
}

func TLSJSON(reportID, domain string, successful, failed int) string {
	end := time.Now().Add(-12 * time.Hour)
	begin := end.Add(-24 * time.Hour)

	return fmt.Sprintf(`{
  "organization-name": "Google Inc.",
  "date-range": {"start-datetime": %q, "end-datetime": %q},
  "contact-info": "smtp-tls-reporting@google.com",
  "report-id": %q,
  "policies": [{
    "policy": {"policy-type": "sts", "policy-domain": %q, "mx-host": ["mail.%s"]},
    "summary": {"total-successful-session-count": %d, "total-failure-session-count": %d},
    "failure-details": [{
      "result-type": "certificate-expired",
      "sending-mta-ip": "209.85.220.41",
      "receiving-mx-hostname": "mail.%s",
      "failed-session-count": %d
    }]
  }]
}`, begin.Format(time.RFC3339), end.Format(time.RFC3339), reportID, domain, domain,
		successful, failed, domain, failed)
}

// reportMail wraps a payload in a realistic multipart message with a gzip
// attachment, which is how every large receiver actually sends these.
func ReportMail(t *testing.T, subject, filename, payload string) []byte {
	t.Helper()

	var gzbuf bytes.Buffer
	zw := gzip.NewWriter(&gzbuf)
	if _, err := zw.Write([]byte(payload)); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	var b strings.Builder
	b.WriteString("From: noreply-dmarc-support@google.com\r\n")
	b.WriteString("To: dmarc@example.org\r\n")
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Message-Id: <%s@google.com>\r\n", filename)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"SEP\"\r\n\r\n")
	b.WriteString("--SEP\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	b.WriteString("This is a report.\r\n\r\n")
	b.WriteString("--SEP\r\n")
	fmt.Fprintf(&b, "Content-Type: application/gzip; name=%q\r\n", filename)
	fmt.Fprintf(&b, "Content-Disposition: attachment; filename=%q\r\n", filename)
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")

	enc := base64.StdEncoding.EncodeToString(gzbuf.Bytes())
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n\r\n--SEP--\r\n")

	return []byte(b.String())
}

func PlainMail(subject, body string) []byte {
	return []byte(fmt.Sprintf(
		"From: someone@example.com\r\nTo: dmarc@example.org\r\nSubject: %s\r\n"+
			"Message-Id: <%s@example.com>\r\nContent-Type: text/plain\r\n\r\n%s\r\n",
		subject, subject, body))
}
