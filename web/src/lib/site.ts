/**
 * Site-wide constants.
 *
 * The origin is needed at build time for canonical links, alternates and the
 * sitemap, and a prerendered site has no request to derive it from. Override it
 * with PUBLIC_SITE_URL when building for a different host.
 */
import { env } from '$env/dynamic/public';

export const siteUrl = (env.PUBLIC_SITE_URL ?? 'https://mailreportd.iodev.org').replace(/\/+$/, '');

export const site = {
	name: 'mailreportd',
	version: '0.1.0',
	url: siteUrl,
	ogImage: `${siteUrl}/og.png`,
	links: {
		spec: '/docs/specs/report-ingest.md',
		readme: '/README.md'
	},
	standards: [
		{ label: 'RFC 7489 — DMARC', href: 'https://www.rfc-editor.org/rfc/rfc7489' },
		{ label: 'RFC 8460 — SMTP TLS Reporting', href: 'https://www.rfc-editor.org/rfc/rfc8460' },
		{ label: 'RFC 7208 — SPF', href: 'https://www.rfc-editor.org/rfc/rfc7208' },
		{ label: 'RFC 6376 — DKIM', href: 'https://www.rfc-editor.org/rfc/rfc6376' }
	]
} as const;

/**
 * Metric families shown in the exported-metrics table. The help strings are
 * the exporter's own HELP text, verbatim, so the page and the exposition
 * cannot drift apart silently.
 */
export const metricRows = [
	{
		metric: 'mailreport_dmarc_messages',
		labels: 'tenant, domain, disposition, dkim, spf, source_class',
		help: 'Messages reported in the aggregation window, by evaluation outcome and source class.'
	},
	{
		metric: 'mailreport_tlsrpt_sessions',
		labels: 'tenant, domain, policy_type, result',
		help: 'SMTP TLS sessions reported in the aggregation window.'
	},
	{
		metric: 'mailreport_tlsrpt_failures',
		labels: 'tenant, domain, result_type',
		help: 'SMTP TLS session failures in the aggregation window, by RFC 8460 result type.'
	},
	{
		metric: 'mailreport_report_last_received_timestamp_seconds',
		labels: 'tenant, domain, format',
		help: 'Unix timestamp of the most recently ingested report, by domain and format.'
	},
	{
		metric: 'mailreport_raw_messages',
		labels: 'tenant, state',
		help: 'Messages seen by the ingest pipeline, by outcome state.'
	},
	{
		metric: 'mailreport_spf_lookups',
		labels: 'tenant, domain',
		help: 'DNS-querying mechanisms consumed by the domain’s SPF record.'
	},
	{
		metric: 'mailreport_spf_lookup_limit_exceeded',
		labels: 'tenant, domain',
		help: '1 when the domain’s SPF record needs more than the RFC 7208 limit of ten DNS lookups.'
	},
	{
		metric: 'mailreport_spf_resolvable',
		labels: 'tenant, domain',
		help: '1 when the domain’s SPF record could be resolved.'
	},
	{
		metric: 'mailreport_dmarc_policy',
		labels: 'tenant, domain, p',
		help: 'Published DMARC policy last observed by a reporter, as a label set with value 1.'
	},
	{
		metric: 'mailreport_dkim_record_state',
		labels: 'tenant, domain, selector, state',
		help: 'Published DKIM selector state as a label set with value 1: missing, revoked, malformed, weak or ok.'
	},
	{
		metric: 'mailreport_dkim_key_bits',
		labels: 'tenant, domain, selector',
		help: 'RSA modulus size of the published DKIM key. Receivers reject keys below 1024 bits.'
	},
	{
		metric: 'mailreport_dkim_record_testing',
		labels: 'tenant, domain, selector',
		help: '1 when the selector publishes t=y, which asks receivers to treat a failure as unsigned.'
	},
	{
		metric: 'mailreport_dmarc_record_valid',
		labels: 'tenant, domain',
		help: '1 when the domain publishes a parseable DMARC record.'
	},
	{
		metric: 'mailreport_dmarc_record_policy',
		labels: 'tenant, domain, p, sp',
		help: 'Currently published DMARC policy, as a label set with value 1. sp is resolved, so it reflects the policy that actually applies to subdomains.'
	},
	{
		metric: 'mailreport_dmarc_record_pct',
		labels: 'tenant, domain',
		help: 'Published DMARC pct=, defaulting to 100.'
	},
	{
		metric: 'mailreport_dmarc_rua_authorized',
		labels: 'tenant, domain, rua_domain',
		help: '1 when an external rua destination publishes the RFC 7489 §7.1 authorization record.'
	},
	{
		metric: 'mailreport_mtasts_record_valid',
		labels: 'tenant, domain',
		help: '1 when the domain publishes a parseable MTA-STS policy reachable over HTTPS.'
	},
	{
		metric: 'mailreport_mtasts_policy',
		labels: 'tenant, domain, mode',
		help: 'Published MTA-STS mode as a label set with value 1. testing generates reports and enforces nothing.'
	},
	{
		metric: 'mailreport_mtasts_mx_covered',
		labels: 'tenant, domain',
		help: '1 when every live MX host matches an mx: pattern in the policy. Drift makes enforcing senders refuse delivery.'
	},
	{
		metric: 'mailreport_mtasts_max_age_seconds',
		labels: 'tenant, domain',
		help: 'Published MTA-STS max_age, which is how long senders cache the policy.'
	},
	{
		metric: 'mailreport_mtasts_stale_id',
		labels: 'tenant, domain',
		help: '1 when the policy body changed while its id did not, so senders keep the old policy until max_age expires.'
	},
	{
		metric: 'mailreport_policy_check_timestamp_seconds',
		labels: 'tenant, domain',
		help: 'Unix timestamp of the last completed policy check for the domain.'
	},
	{
		metric: 'mailreport_policy_check_errors_total',
		labels: 'tenant, domain, check',
		help: 'Checks that could not be completed, which is not the same as a check that failed.'
	},
	{
		metric: 'mailreport_ingest_messages_total',
		labels: 'tenant, feeder, result',
		help: 'Messages processed by a feeder, by outcome.'
	},
	{
		metric: 'mailreport_ingest_reports_total',
		labels: 'tenant, feeder',
		help: 'Reports stored by a feeder.'
	},
	{
		metric: 'mailreport_ingest_errors_total',
		labels: 'tenant, feeder',
		help: 'Feeder run failures, which mean reports are not arriving at all.'
	},
	{
		metric: 'mailreport_ingest_last_success_timestamp_seconds',
		labels: 'tenant, feeder',
		help: 'Unix timestamp of the last successful feeder run.'
	},
	{
		metric: 'mailreport_refresh_timestamp_seconds',
		labels: '—',
		help: 'Unix timestamp of the last successful metric refresh.'
	},
	{
		metric: 'mailreport_refresh_duration_seconds',
		labels: '—',
		help: 'Duration of the last metric refresh.'
	},
	{
		metric: 'mailreport_build_info',
		labels: 'version',
		help: 'Build information, always 1.'
	}
] as const;

export const endpoints = {
	public: [
		{ method: 'GET', path: '/healthz' },
		{ method: 'POST', path: '/tlsrpt' }
	],
	private: [
		{ method: 'GET', path: '/metrics' },
		{ method: 'GET', path: '/api/v1/domains' },
		{ method: 'GET', path: '/api/v1/sources' },
		{ method: 'GET', path: '/api/v1/signers' },
		{ method: 'GET', path: '/api/v1/failures' },
		{ method: 'GET', path: '/api/v1/quarantine' }
	]
} as const;

export const snippets = {
	metrics: `mailreport_dmarc_messages{domain="example.org",dkim="pass",
  spf="pass",disposition="none",source_class="self"} 4213

mailreport_dmarc_messages{domain="example.org",dkim="fail",
  spf="fail",disposition="reject",source_class="unknown"} 37

mailreport_tlsrpt_sessions{domain="example.org",
  policy_type="sts",result="failed"} 3

mailreport_spf_lookups{domain="example.org"} 7`,

	config: `tenants:
  - id: default
    domains: [example.org]

feeders:
  - name: mailbox
    type: imap
    host: mail.example.org
    username: dmarc@example.org
    password_env: MAILREPORTD_IMAP_PASSWORD
    interval: 5m`,

	run: `$ mailreportd -config config.yaml -check
config ok

$ mailreportd -config config.yaml
level=INFO msg=starting tenants=1 feeders=1
level=INFO msg=listening server=private addr=:9188
level=INFO msg="feeder run complete" messages=14 reports=14`
} as const;
