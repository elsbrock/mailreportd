package report

import "testing"

const tlsReport = `{
  "organization-name": "Google Inc.",
  "date-range": {
    "start-datetime": "2026-08-01T00:00:00Z",
    "end-datetime": "2026-08-01T23:59:59Z"
  },
  "contact-info": "smtp-tls-reporting@google.com",
  "report-id": "2026-08-01T00:00:00Z_example.org",
  "policies": [
    {
      "policy": {
        "policy-type": "sts",
        "policy-string": ["version: STSv1", "mode: enforce", "mx: mail.example.org", "max_age: 604800"],
        "policy-domain": "example.org",
        "mx-host": ["mail.example.org"]
      },
      "summary": {
        "total-successful-session-count": 412,
        "total-failure-session-count": 3
      },
      "failure-details": [
        {
          "result-type": "certificate-expired",
          "sending-mta-ip": "209.85.220.41",
          "receiving-mx-hostname": "mail.example.org",
          "receiving-ip": "2001:db8:4f8::1",
          "failed-session-count": 3
        }
      ]
    }
  ]
}`

func TestParseTLSRPT(t *testing.T) {
	rep, err := ParseTLSRPT([]byte(tlsReport))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if rep.Format != FormatTLSRPT {
		t.Errorf("format = %q", rep.Format)
	}
	if rep.Reporter != "Google Inc." {
		t.Errorf("reporter = %q", rep.Reporter)
	}
	if rep.Domain != "example.org" {
		t.Errorf("domain = %q", rep.Domain)
	}
	if rep.Begin.Year() != 2026 {
		t.Errorf("begin = %v", rep.Begin)
	}

	if len(rep.TLSPolicies) != 1 {
		t.Fatalf("policies = %d", len(rep.TLSPolicies))
	}
	p := rep.TLSPolicies[0]
	if p.PolicyType != "sts" || p.Successful != 412 || p.Failed != 3 {
		t.Errorf("policy = %+v", p)
	}
	if len(p.MXHosts) != 1 || p.MXHosts[0] != "mail.example.org" {
		t.Errorf("mx hosts = %v", p.MXHosts)
	}
	if len(p.Failures) != 1 || p.Failures[0].ResultType != "certificate-expired" {
		t.Errorf("failures = %+v", p.Failures)
	}
	if p.Failures[0].Count != 3 {
		t.Errorf("failure count = %d", p.Failures[0].Count)
	}
}

func TestParseTLSRPTSingleStringPolicy(t *testing.T) {
	// The RFC specifies arrays; some senders emit bare strings. Both must work
	// or those senders become invisible.
	doc := `{
	  "organization-name": "Example",
	  "date-range": {"start-datetime": "2026-08-01T00:00:00Z", "end-datetime": "2026-08-01T23:59:59Z"},
	  "report-id": "abc",
	  "policies": [{
	    "policy": {"policy-type": "tlsa", "policy-string": "3 1 1 abcdef", "policy-domain": "Example.COM.", "mx-host": "mx.example.com"},
	    "summary": {"total-successful-session-count": 1, "total-failure-session-count": 0}
	  }]
	}`

	rep, err := ParseTLSRPT([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rep.Domain != "example.com" {
		t.Errorf("domain = %q, want normalized", rep.Domain)
	}
	if got := rep.TLSPolicies[0].MXHosts; len(got) != 1 || got[0] != "mx.example.com" {
		t.Errorf("mx hosts = %v", got)
	}
}

func TestParseTLSRPTMultiDomain(t *testing.T) {
	doc := `{
	  "organization-name": "Example",
	  "date-range": {"start-datetime": "2026-08-01T00:00:00Z", "end-datetime": "2026-08-01T23:59:59Z"},
	  "report-id": "multi",
	  "policies": [
	    {"policy": {"policy-type": "sts", "policy-domain": "a.example"},
	     "summary": {"total-successful-session-count": 1, "total-failure-session-count": 0}},
	    {"policy": {"policy-type": "sts", "policy-domain": "b.example"},
	     "summary": {"total-successful-session-count": 2, "total-failure-session-count": 1}}
	  ]
	}`

	rep, err := ParseTLSRPT([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	domains := rep.Domains()
	if len(domains) != 2 || domains[0] != "a.example" || domains[1] != "b.example" {
		t.Errorf("domains = %v", domains)
	}
}

func TestParseTLSRPTRejects(t *testing.T) {
	for _, doc := range []string{
		`not json`,
		`{"organization-name": "x", "report-id": "y", "policies": []}`,
	} {
		if _, err := ParseTLSRPT([]byte(doc)); err == nil {
			t.Errorf("expected an error for %q", doc)
		}
	}
}
