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
	/** Per-locale social card, so a shared German link previews in German. */
	ogImage: { en: `${siteUrl}/og.png`, de: `${siteUrl}/og.de.png` },
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

/** Metric families shown in the exported-metrics table. */
export const metricRows = [
	{ metric: 'mailreport_dmarc_messages', labels: 'tenant, domain, disposition, dkim, spf, source_class' },
	{ metric: 'mailreport_tlsrpt_sessions', labels: 'tenant, domain, policy_type, result' },
	{ metric: 'mailreport_tlsrpt_failures', labels: 'tenant, domain, result_type' },
	{ metric: 'mailreport_report_last_received_timestamp_seconds', labels: 'tenant, domain, format' },
	{ metric: 'mailreport_raw_messages', labels: 'tenant, state' },
	{ metric: 'mailreport_spf_lookups', labels: 'tenant, domain' },
	{ metric: 'mailreport_spf_lookup_limit_exceeded', labels: 'tenant, domain' },
	{ metric: 'mailreport_dmarc_policy', labels: 'tenant, domain, p' },
	{ metric: 'mailreport_dkim_record_state', labels: 'tenant, domain, selector, state' },
	{ metric: 'mailreport_dkim_key_bits', labels: 'tenant, domain, selector' },
	{ metric: 'mailreport_dmarc_record_policy', labels: 'tenant, domain, p, sp' },
	{ metric: 'mailreport_dmarc_record_pct', labels: 'tenant, domain' },
	{ metric: 'mailreport_dmarc_rua_authorized', labels: 'tenant, domain, rua_domain' },
	{ metric: 'mailreport_mtasts_policy', labels: 'tenant, domain, mode' },
	{ metric: 'mailreport_mtasts_mx_covered', labels: 'tenant, domain' },
	{ metric: 'mailreport_mtasts_stale_id', labels: 'tenant, domain' },
	{ metric: 'mailreport_policy_check_errors_total', labels: 'tenant, domain, check' },
	{ metric: 'mailreport_ingest_messages_total', labels: 'tenant, feeder, result' },
	{ metric: 'mailreport_ingest_last_success_timestamp_seconds', labels: 'tenant, feeder' }
] as const;

export const endpoints = {
	public: [{ method: 'GET', path: '/healthz' }],
	private: [
		{ method: 'GET', path: '/metrics' },
		{ method: 'GET', path: '/api/v1/domains' },
		{ method: 'GET', path: '/api/v1/sources' },
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
