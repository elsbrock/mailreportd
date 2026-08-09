package report

import (
	"strings"
	"testing"
	"time"
)

const googleAggregate = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <extra_contact_info>https://support.google.com/a/answer/2466580</extra_contact_info>
    <report_id>7233348299885243956</report_id>
    <date_range>
      <begin>1754006400</begin>
      <end>1754092799</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.org</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>reject</p>
    <sp>reject</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>2001:db8:98c0::103</source_ip>
      <count>12</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.org</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.org</domain>
        <result>pass</result>
        <selector>selector1</selector>
      </dkim>
      <spf>
        <domain>example.org</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>203.0.113.44</source_ip>
      <count>3</count>
      <policy_evaluated>
        <disposition>reject</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
        <reason>
          <type>local_policy</type>
          <comment>arc=pass</comment>
        </reason>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>EXAMPLE.ORG.</header_from>
    </identifiers>
    <auth_results>
      <spf>
        <domain>bounce.example.net</domain>
        <scope>mfrom</scope>
        <result>softfail</result>
      </spf>
    </auth_results>
  </record>
</feedback>`

func TestParseDMARCAggregate(t *testing.T) {
	rep, err := ParseDMARCAggregate([]byte(googleAggregate))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if rep.Format != FormatDMARCAggregate {
		t.Errorf("format = %q, want %q", rep.Format, FormatDMARCAggregate)
	}
	if rep.Reporter != "google.com" {
		t.Errorf("reporter = %q", rep.Reporter)
	}
	if rep.ReportID != "7233348299885243956" {
		t.Errorf("report id = %q", rep.ReportID)
	}
	if rep.Domain != "example.org" {
		t.Errorf("domain = %q", rep.Domain)
	}
	if got, want := rep.Begin, time.Unix(1754006400, 0).UTC(); !got.Equal(want) {
		t.Errorf("begin = %v, want %v", got, want)
	}
	if rep.Policy.P != "reject" || rep.Policy.Pct != 100 {
		t.Errorf("policy = %+v", rep.Policy)
	}

	if len(rep.DMARCRows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rep.DMARCRows))
	}

	first := rep.DMARCRows[0]
	if first.SourceIP.String() != "2001:db8:98c0::103" {
		t.Errorf("source ip = %q", first.SourceIP)
	}
	if first.Count != 12 || first.DKIM != "pass" || first.SPF != "pass" {
		t.Errorf("first row = %+v", first)
	}
	if !first.Aligned() {
		t.Error("first row should be aligned")
	}
	if len(first.DKIMAuth) != 1 || first.DKIMAuth[0].Selector != "selector1" {
		t.Errorf("dkim auth = %+v", first.DKIMAuth)
	}

	second := rep.DMARCRows[1]
	if second.Disposition != "reject" {
		t.Errorf("disposition = %q", second.Disposition)
	}
	if second.Aligned() {
		t.Error("second row should not be aligned")
	}
	// Trailing dot and upper case must normalize, or the same domain splits
	// into several series.
	if second.HeaderFrom != "example.org" {
		t.Errorf("header from = %q, want normalized", second.HeaderFrom)
	}
	if len(second.Reasons) != 1 || second.Reasons[0].Type != "local_policy" {
		t.Errorf("reasons = %+v", second.Reasons)
	}
}

func TestParseDMARCAggregateTolerance(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want func(*testing.T, *Report)
	}{
		{
			name: "padded and empty integers",
			doc: `<feedback><report_metadata><org_name>x</org_name><report_id>1</report_id>
			<date_range><begin> 1754006400 </begin><end></end></date_range></report_metadata>
			<policy_published><domain>example.com</domain><p>none</p></policy_published>
			<record><row><source_ip> 198.51.100.7 </source_ip><count> 5 </count>
			<policy_evaluated><disposition>none</disposition><dkim>PASS</dkim><spf>Fail</spf>
			</policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers>
			</record></feedback>`,
			want: func(t *testing.T, r *Report) {
				if r.DMARCRows[0].Count != 5 {
					t.Errorf("count = %d, want 5", r.DMARCRows[0].Count)
				}
				if r.DMARCRows[0].DKIM != "pass" || r.DMARCRows[0].SPF != "fail" {
					t.Errorf("results not normalized: %+v", r.DMARCRows[0])
				}
				// pct is absent and must default to 100, not 0, or every
				// report without it looks like a 0% rollout.
				if r.Policy.Pct != 100 {
					t.Errorf("pct = %d, want default 100", r.Policy.Pct)
				}
			},
		},
		{
			name: "iso8601 date range",
			doc: `<feedback><report_metadata><org_name>x</org_name><report_id>2</report_id>
			<date_range><begin>2026-08-01T00:00:00Z</begin><end>2026-08-01T23:59:59Z</end></date_range>
			</report_metadata><policy_published><domain>example.com</domain></policy_published>
			<record><row><source_ip>198.51.100.7</source_ip><count>1</count>
			<policy_evaluated><disposition>none</disposition></policy_evaluated></row>
			<identifiers><header_from>example.com</header_from></identifiers></record></feedback>`,
			want: func(t *testing.T, r *Report) {
				if r.Begin.Year() != 2026 || r.Begin.Month() != time.August {
					t.Errorf("begin = %v", r.Begin)
				}
			},
		},
		{
			name: "ipv4-mapped ipv6 normalizes",
			doc: `<feedback><report_metadata><org_name>x</org_name><report_id>3</report_id>
			<date_range><begin>1</begin><end>2</end></date_range></report_metadata>
			<policy_published><domain>example.com</domain></policy_published>
			<record><row><source_ip>::ffff:198.51.100.7</source_ip><count>1</count>
			<policy_evaluated><disposition>none</disposition></policy_evaluated></row>
			<identifiers><header_from>example.com</header_from></identifiers></record></feedback>`,
			want: func(t *testing.T, r *Report) {
				if got := r.DMARCRows[0].SourceIP.String(); got != "198.51.100.7" {
					t.Errorf("source ip = %q, want unmapped", got)
				}
			},
		},
		{
			name: "one bad record does not lose the report",
			doc: `<feedback><report_metadata><org_name>x</org_name><report_id>4</report_id>
			<date_range><begin>1</begin><end>2</end></date_range></report_metadata>
			<policy_published><domain>example.com</domain></policy_published>
			<record><row><source_ip>not-an-ip</source_ip><count>9</count>
			<policy_evaluated><disposition>none</disposition></policy_evaluated></row>
			<identifiers><header_from>example.com</header_from></identifiers></record>
			<record><row><source_ip>198.51.100.7</source_ip><count>4</count>
			<policy_evaluated><disposition>none</disposition></policy_evaluated></row>
			<identifiers><header_from>example.com</header_from></identifiers></record></feedback>`,
			want: func(t *testing.T, r *Report) {
				if len(r.DMARCRows) != 1 || r.DMARCRows[0].Count != 4 {
					t.Errorf("rows = %+v, want only the good one", r.DMARCRows)
				}
			},
		},
		{
			name: "missing policy domain falls back to header from",
			doc: `<feedback><report_metadata><org_name>x</org_name><report_id>5</report_id>
			<date_range><begin>1</begin><end>2</end></date_range></report_metadata>
			<record><row><source_ip>198.51.100.7</source_ip><count>1</count>
			<policy_evaluated><disposition>none</disposition></policy_evaluated></row>
			<identifiers><header_from>fallback.example</header_from></identifiers></record></feedback>`,
			want: func(t *testing.T, r *Report) {
				if r.Domain != "fallback.example" {
					t.Errorf("domain = %q", r.Domain)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep, err := ParseDMARCAggregate([]byte(tt.doc))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			tt.want(t, rep)
		})
	}
}

func TestParseDMARCAggregateRejects(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{"not xml", "this is not a report"},
		{"no metadata", `<feedback><policy_published><domain>x.example</domain></policy_published></feedback>`},
		{"no usable records", `<feedback><report_metadata><org_name>x</org_name><report_id>1</report_id>
			<date_range><begin>1</begin><end>2</end></date_range></report_metadata>
			<policy_published><domain>example.com</domain></policy_published></feedback>`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseDMARCAggregate([]byte(tt.doc)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestReportIdentity(t *testing.T) {
	rep, err := ParseDMARCAggregate([]byte(googleAggregate))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Identity must be stable across reparses, which is what makes reprocessing
	// a mailbox from scratch safe.
	again, err := ParseDMARCAggregate([]byte(googleAggregate))
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if rep.Identity() != again.Identity() {
		t.Errorf("identity is not stable: %q vs %q", rep.Identity(), again.Identity())
	}

	// Reporter case must not produce two identities for one report.
	upper, err := ParseDMARCAggregate([]byte(strings.Replace(googleAggregate, "google.com", "GOOGLE.COM", 1)))
	if err != nil {
		t.Fatalf("parse upper: %v", err)
	}
	if rep.Identity() != upper.Identity() {
		t.Errorf("identity is case sensitive: %q vs %q", rep.Identity(), upper.Identity())
	}
}
