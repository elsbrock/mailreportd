package store

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// The aggregate fixture reports 15 messages for example.org: 12 authenticating
// cleanly from our own relay, and 3 failing from an unrelated source.
const aggregateXML = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>7233348299885243956</report_id>
    <date_range><begin>1754006400</begin><end>1754092799</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.org</domain><adkim>r</adkim><aspf>r</aspf>
    <p>reject</p><sp>reject</sp><pct>100</pct>
  </policy_published>
  <record>
    <row><source_ip>2001:db8:98c0::103</source_ip><count>12</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.org</header_from></identifiers>
    <auth_results><dkim><domain>example.org</domain><result>pass</result><selector>selector1</selector></dkim>
      <spf><domain>example.org</domain><result>pass</result></spf></auth_results>
  </record>
  <record>
    <row><source_ip>203.0.113.44</source_ip><count>3</count>
      <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.org</header_from></identifiers>
    <auth_results><spf><domain>bounce.example.net</domain><scope>mfrom</scope><result>softfail</result></spf></auth_results>
  </record>
</feedback>`

// The relayed fixture is the production shape that motivated Signers: mail
// leaving through a relay carries two passing signatures, and only one of them
// is aligned. The receiver's own verdict is dkim=pass, earned entirely by the
// example.org signature; the relay's own d= contributes nothing to DMARC despite
// verifying. A third record signs from a subdomain, which relaxed alignment
// accepts and a suffix rule can see.
const relayedAggregateXML = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>fastmail pty ltd</org_name>
    <email>reports@fastmaildmarc.com</email>
    <report_id>2108667705</report_id>
    <date_range><begin>1754006400</begin><end>1754092799</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.org</domain><p>reject</p><sp>reject</sp><pct>100</pct>
  </policy_published>
  <record>
    <row><source_ip>192.0.2.114</source_ip><count>7</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.org</header_from></identifiers>
    <auth_results>
      <dkim><domain>relay-smtp.net</domain><result>pass</result><selector>rly2024-1</selector></dkim>
      <dkim><domain>example.org</domain><result>pass</result><selector>selector1</selector></dkim>
      <spf><domain>bounce.example.org</domain><scope>mfrom</scope><result>pass</result></spf>
    </auth_results>
  </record>
  <record>
    <row><source_ip>198.51.100.9</source_ip><count>2</count>
      <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.org</header_from></identifiers>
    <auth_results>
      <dkim><domain>relay-smtp.net</domain><result>fail</result><selector>rly2024-1</selector></dkim>
    </auth_results>
  </record>
  <record>
    <row><source_ip>203.0.113.7</source_ip><count>4</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.org</header_from></identifiers>
    <auth_results>
      <dkim><domain>news.example.org</domain><result>pass</result><selector>mktg</selector></dkim>
    </auth_results>
  </record>
</feedback>`

func relayedAggregateMessage(t *testing.T) []byte {
	t.Helper()
	return mimeMessage("Report Domain: example.org relayed", "relayed.xml.gz", gz(t, relayedAggregateXML))
}

const tlsJSON = `{
  "organization-name": "Google Inc.",
  "date-range": {"start-datetime": "2026-08-01T00:00:00Z", "end-datetime": "2026-08-01T23:59:59Z"},
  "contact-info": "smtp-tls-reporting@google.com",
  "report-id": "2026-08-01T00:00:00Z_example.org",
  "policies": [{
    "policy": {"policy-type": "sts", "policy-domain": "example.org", "mx-host": ["mail.example.org"]},
    "summary": {"total-successful-session-count": 412, "total-failure-session-count": 3},
    "failure-details": [{
      "result-type": "certificate-expired",
      "sending-mta-ip": "209.85.220.41",
      "receiving-mx-hostname": "mail.example.org",
      "failed-session-count": 3
    }]
  }]
}`

func gz(t *testing.T, data string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(data)); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func mimeMessage(subject, filename string, attachment []byte) []byte {
	var b strings.Builder
	b.WriteString("From: noreply-dmarc-support@google.com\r\n")
	b.WriteString("To: dmarc@example.org\r\n")
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Message-Id: <%s@google.com>\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"SEP\"\r\n\r\n")
	b.WriteString("--SEP\r\nContent-Type: text/plain\r\n\r\nReport attached.\r\n\r\n")
	b.WriteString("--SEP\r\n")
	fmt.Fprintf(&b, "Content-Type: application/gzip; name=\"%s\"\r\n", filename)
	fmt.Fprintf(&b, "Content-Disposition: attachment; filename=\"%s\"\r\n", filename)
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	b.WriteString(base64.StdEncoding.EncodeToString(attachment))
	b.WriteString("\r\n\r\n--SEP--\r\n")
	return []byte(b.String())
}

func aggregateMessage(t *testing.T) []byte {
	t.Helper()
	return mimeMessage("Report Domain: example.org", "report.xml.gz", gz(t, aggregateXML))
}

func aggregateMessageWithSubject(t *testing.T, subject string) []byte {
	t.Helper()
	return mimeMessage(subject, "report.xml.gz", gz(t, aggregateXML))
}

func tlsMessage(t *testing.T) []byte {
	t.Helper()
	return mimeMessage("Report Domain: example.org TLS", "report.json.gz", gz(t, tlsJSON))
}

// brokenReportMessage carries something that announces itself as a report and
// is not one: XML that parses but has no usable records.
func brokenReportMessage(t *testing.T) []byte {
	t.Helper()
	broken := `<feedback><report_metadata><org_name>broken.example</org_name>
	<report_id>999</report_id><date_range><begin>1</begin><end>2</end></date_range>
	</report_metadata><policy_published><domain>example.org</domain></policy_published></feedback>`
	return mimeMessage("Report Domain: example.org", "broken.xml.gz", gz(t, broken))
}
