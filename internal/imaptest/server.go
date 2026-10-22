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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
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

	mu      sync.Mutex
	folders []folder // in creation order, INBOX first
}

type folder struct {
	name       string
	specialUse []imap.MailboxAttr
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

	m := &Mailbox{
		user:     user,
		username: username,
		password: password,
		folders:  []folder{{name: mailbox}},
	}

	server := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return &session{Session: memServer.NewSession(), mailbox: m}, nil, nil
		},
		// SPECIAL-USE as well, because real servers such as Stalwart
		// advertise it and the feeder finds \Junk through it.
		Caps: imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapSpecialUse: {}, imap.CapCreateSpecialUse: {}},
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

	m.addr = listener.Addr().String()
	return m
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

// CreateMailbox adds a folder, optionally marked with RFC 6154 special-use
// attributes such as \Junk.
func (m *Mailbox) CreateMailbox(t *testing.T, name string, specialUse ...imap.MailboxAttr) {
	t.Helper()
	if err := m.user.Create(name, &imap.CreateOptions{SpecialUse: specialUse}); err != nil {
		t.Fatalf("create mailbox %q: %v", name, err)
	}
	m.mu.Lock()
	m.folders = append(m.folders, folder{name: name, specialUse: specialUse})
	m.mu.Unlock()
}

// session answers LIST itself, because imapmemserver (v2.0.0-beta.8) drops the
// special-use attributes given at create time. Everything else is the real
// server.
type session struct {
	imapserver.Session
	mailbox *Mailbox
}

func (s *session) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	if len(patterns) == 0 {
		return w.WriteList(&imap.ListData{Attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect}, Delim: '/'})
	}

	s.mailbox.mu.Lock()
	folders := slices.Clone(s.mailbox.folders)
	s.mailbox.mu.Unlock()

	for _, f := range folders {
		if !slices.ContainsFunc(patterns, func(p string) bool { return imapserver.MatchList(f.name, '/', ref, p) }) {
			continue
		}
		if options.SelectSpecialUse && len(f.specialUse) == 0 {
			continue
		}
		data := &imap.ListData{Mailbox: f.name, Delim: '/'}
		if options.ReturnSpecialUse || options.SelectSpecialUse {
			data.Attrs = f.specialUse
		}
		if err := w.WriteList(data); err != nil {
			return err
		}
	}
	return nil
}

// deliver appends a message to the mailbox over the wire, as a real MTA would.
func (m *Mailbox) Deliver(t *testing.T, body []byte) {
	t.Helper()
	m.DeliverTo(t, "INBOX", body)
}

// DeliverTo appends a message to a named folder, as a spam filter filing a
// report would.
func (m *Mailbox) DeliverTo(t *testing.T, mailbox string, body []byte) {
	t.Helper()

	client, err := imapclient.DialInsecure(m.addr, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	if err := client.Login(m.username, m.password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}

	cmd := client.Append(mailbox, int64(len(body)), nil)
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

// FailureMail builds an RFC 6591 auth-failure report: a multipart/report
// message whose report is the MIME structure itself — a feedback-report part
// beside the original message.
func FailureMail(t *testing.T, msgID, domain, rcpt string, arrival time.Time) []byte {
	t.Helper()

	var b strings.Builder
	b.WriteString("From: noreply@receiver.example\r\n")
	b.WriteString("To: dmarc@example.org\r\n")
	b.WriteString("Subject: Authentication failure report\r\n")
	fmt.Fprintf(&b, "Message-Id: <%s@receiver.example>\r\n", msgID)
	fmt.Fprintf(&b, "Date: %s\r\n", arrival.Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/report; report-type=feedback; boundary=\"ARF\"\r\n\r\n")

	b.WriteString("--ARF\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	b.WriteString("This is an authentication failure report.\r\n\r\n")

	b.WriteString("--ARF\r\nContent-Type: message/feedback-report\r\n\r\n")
	b.WriteString("Feedback-Type: auth-failure\r\n")
	b.WriteString("User-Agent: imaptest/1.0\r\n")
	b.WriteString("Version: 1\r\n")
	fmt.Fprintf(&b, "Original-Mail-From: <bounce@%s>\r\n", domain)
	fmt.Fprintf(&b, "Original-Rcpt-To: %s\r\n", rcpt)
	fmt.Fprintf(&b, "Arrival-Date: %s\r\n", arrival.Format(time.RFC1123Z))
	b.WriteString("Source-IP: 198.51.100.7\r\n")
	fmt.Fprintf(&b, "Reported-Domain: %s\r\n", domain)
	b.WriteString("Reporting-MTA: dns; mx.receiver.example\r\n")
	b.WriteString("Auth-Failure: dmarc\r\n")
	b.WriteString("Delivery-Result: reject\r\n\r\n")

	b.WriteString("--ARF\r\nContent-Type: message/rfc822\r\n\r\n")
	fmt.Fprintf(&b, "From: news@%s\r\n", domain)
	fmt.Fprintf(&b, "To: %s\r\n", rcpt)
	b.WriteString("Subject: the original message\r\n")
	fmt.Fprintf(&b, "DKIM-Signature: v=1; a=rsa-sha256; d=%s; s=mail; b=broken\r\n", domain)
	b.WriteString("\r\nHello, this is the message that failed.\r\n")

	b.WriteString("\r\n--ARF--\r\n")
	return []byte(b.String())
}

// SpamComplaintMail builds an ARF message whose feedback type is not
// auth-failure, which the daemon must record as ignored.
func SpamComplaintMail(t *testing.T, msgID string) []byte {
	t.Helper()

	var b strings.Builder
	b.WriteString("From: complaints@receiver.example\r\n")
	b.WriteString("To: dmarc@example.org\r\n")
	b.WriteString("Subject: Abuse report\r\n")
	fmt.Fprintf(&b, "Message-Id: <%s@receiver.example>\r\n", msgID)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/report; report-type=feedback; boundary=\"ARF\"\r\n\r\n")
	b.WriteString("--ARF\r\nContent-Type: text/plain\r\n\r\nThis is spam.\r\n")
	b.WriteString("--ARF\r\nContent-Type: message/feedback-report\r\n\r\n")
	b.WriteString("Feedback-Type: abuse\r\nUser-Agent: imaptest/1.0\r\nVersion: 1\r\n")
	b.WriteString("\r\n--ARF--\r\n")
	return []byte(b.String())
}
