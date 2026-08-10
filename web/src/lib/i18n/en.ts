/**
 * The English catalogue is the source of truth. Its shape becomes the
 * `Messages` type, so any other locale that omits or misnames a key fails to
 * compile rather than silently rendering `undefined` in production.
 */
export const en = {
	meta: {
		title: 'mailreportd — DMARC and TLS report ingest for your own mail stack',
		description:
			'A single binary that ingests DMARC aggregate and SMTP TLS reports from a mailbox, classifies every sender against your own SPF record, and exports bounded Prometheus metrics. No SaaS, no data leaves your network.',
		ogAlt: 'mailreportd — DMARC and SMTP TLS report ingest',
		localeName: 'English'
	},
	nav: {
		skipToContent: 'Skip to content',
		capabilities: 'Capabilities',
		matrix: 'Feature matrix',
		cardinality: 'Cardinality',
		metrics: 'Metrics',
		start: 'Quick start',
		themeToggle: 'Switch colour theme',
		languageLabel: 'Language'
	},
	hero: {
		eyebrow: 'Self-hosted mail observability',
		title: 'Your mail stack fails quietly.',
		titleAccent: 'This tells you.',
		lede: 'mailreportd reads the DMARC and SMTP TLS reports that receivers already send you, and turns them into metrics you can alert on. One binary, one config file, one mailbox.',
		primaryCta: 'Read the quick start',
		secondaryCta: 'See what it exports',
		terminalCaption: 'Ingesting from a live mailbox',
		badges: {
			selfHosted: 'Runs on your hardware',
			noEgress: 'No data egress',
			singleBinary: 'Single static binary'
		}
	},
	problem: {
		heading: 'Silence is not the same as health',
		lede: 'Authentication breaks in ways that produce no error on your side. The receiver knows. You do not — unless something is reading what the receiver sends back.',
		items: [
			{
				title: 'TLS quietly stops negotiating',
				body: 'A certificate rotation, a stale policy, a firewall change. Senders fall back or fail, and your logs show nothing at all, because the failure happens on their side of the connection.'
			},
			{
				title: 'Signatures fail at the receiver',
				body: 'Mail leaves correctly and arrives unauthenticated. A rotated key, an unaligned signing domain, a relay that rewrites headers. Your MTA reported a successful handoff.'
			},
			{
				title: 'Someone else is sending as you',
				body: 'Spoofing and forgotten legacy senders both show up only in aggregate reports. Without parsing them, moving to an enforcing policy is guesswork.'
			}
		]
	},
	capabilities: {
		heading: 'What it reads',
		lede: 'Two RFC-defined report formats, from any receiver that sends them, with no cooperation required from your MTA.',
		items: [
			{
				tag: 'RFC 7489',
				title: 'DMARC aggregate reports',
				body: 'Parsed into per-source authentication results, deliberately tolerant of the ways real reporters deviate from the published schema — padded integers, ISO timestamps where Unix seconds belong, unexpected character sets.'
			},
			{
				tag: 'RFC 8460',
				title: 'SMTP TLS reports',
				body: 'Session counts and failure detail by result type, so a sender failing to negotiate TLS with you becomes a number on a dashboard instead of a silence.'
			},
			{
				tag: 'RFC 7208',
				title: 'Sender classification from SPF',
				body: 'Every reporting source is resolved against your domain’s own published SPF record and bucketed as yours, a forwarder, or unknown. Nothing about your infrastructure is hardcoded, so it stays correct when your infrastructure changes.'
			},
			{
				tag: 'Ten-lookup limit',
				title: 'SPF record health',
				body: 'The same expansion counts the DNS lookups your record consumes. Above ten it is a permanent error at real receivers — a live deliverability fault, reported as a metric rather than discovered during an incident.'
			}
		]
	},
	matrix: {
		heading: 'Feature matrix',
		lede: 'Two capability classes. Reports tell you what receivers made of your mail yesterday; policy checks tell you what you are publishing right now. Neither substitutes for the other.',
		tableCaption: 'Supported standards and capabilities',
		columns: { feature: 'Capability', standard: 'Standard', status: 'Status' },
		status: {
			supported: 'Supported',
			planned: 'Planned',
			declined: 'Not planned'
		},
		declinedNote:
			'“Not planned” means decided against, not overlooked. Each one carries its reason, because a matrix that lists only wins tells you nothing about the edges.',
		groups: [
			{
				name: 'Report ingest',
				note: 'What receivers send you, hours to a day after the fact.',
				items: [
					{
						name: 'DMARC aggregate reports',
						standard: 'RFC 7489',
						status: 'supported',
						note: 'Per-source authentication results, tolerant of the ways real reporters deviate from the schema.'
					},
					{
						name: 'SMTP TLS reports, over mail',
						standard: 'RFC 8460',
						status: 'supported',
						note: 'Session and failure counts by result type, including whether the policy in play was STS or DANE.'
					},
					{
						name: 'SMTP TLS reports, over HTTPS',
						standard: 'RFC 8460',
						status: 'planned',
						note: 'Some reporters submit to an endpoint rather than to a mailbox.'
					},
					{
						name: 'DMARC failure reports',
						standard: 'RFC 6591',
						status: 'planned',
						note: 'Carries recipient addresses and message content, so it needs encryption at rest, a shorter retention and access logging before it ships.'
					}
				]
			},
			{
				name: 'Published policy health',
				note: 'What your DNS says right now, checked continuously.',
				items: [
					{
						name: 'SPF record and lookup budget',
						standard: 'RFC 7208',
						status: 'supported',
						note: 'Above ten DNS lookups a record permerrors at real receivers. SPF stops passing entirely rather than degrading.'
					},
					{
						name: 'DKIM selectors and key strength',
						standard: 'RFC 6376',
						status: 'supported',
						note: 'Missing, revoked, malformed, weak or valid, told apart — a withdrawn selector and one that never existed need different fixes.'
					},
					{
						name: 'DMARC record, pct and sp',
						standard: 'RFC 7489',
						status: 'supported',
						note: 'A pct below 100 reads as enforcement while enforcing on a sample. The subdomain policy is resolved rather than reported raw.'
					},
					{
						name: 'External destination authorisation',
						standard: 'RFC 7489 §7.1',
						status: 'supported',
						note: 'Without it a third-party rua receives nothing at all, and an empty mailbox looks exactly like a quiet week.'
					},
					{
						name: 'MTA-STS policy',
						standard: 'RFC 8461',
						status: 'supported',
						note: 'Mode, max_age, whether the mx list still matches your live MX, and whether the body changed without its id being bumped.'
					},
					{
						name: 'DANE / TLSA',
						standard: 'RFC 7672',
						status: 'declined',
						note: 'Meaningful only over DNSSEC, and validating it honestly needs a validating resolver rather than a stub. Reporting presence without validation would be worse than reporting nothing.'
					},
					{
						name: 'BIMI',
						standard: 'Draft',
						status: 'declined',
						note: 'Requires a verified mark certificate to mean anything. Vanity, not deliverability.'
					}
				]
			},
			{
				name: 'Inputs and outputs',
				note: 'How reports get in, and how signals get out.',
				items: [
					{
						name: 'IMAP mailbox',
						standard: 'Read-only',
						status: 'supported',
						note: 'Tracks its own cursor. Never flags, moves or deletes anything.'
					},
					{
						name: 'Maildir',
						standard: '—',
						status: 'planned',
						note: 'For deployments that deliver locally instead of exposing IMAP.'
					},
					{
						name: 'Prometheus exposition',
						standard: 'OpenMetrics',
						status: 'supported',
						note: 'Bounded series only, on the private listener.'
					},
					{
						name: 'JSON read API',
						standard: '—',
						status: 'supported',
						note: 'The per-source detail that must never become a label.'
					}
				]
			}
		]
	},
	cardinality: {
		heading: 'Source addresses are never labels',
		lede: 'A month of aggregate reports for a handful of domains contains tens of thousands of distinct source addresses, most of them seen exactly once. Exporting those as Prometheus labels would destroy the database you are trying to fill.',
		explanation:
			'So the store keeps the full detail and Prometheus receives bounded series only. Sources are classified into three buckets before anything is exported, and the per-address detail is served over a JSON API on the private listener instead.',
		assertion: 'This rule is asserted by a test that scans the entire exposition for source addresses.',
		pipeline: {
			caption: 'From mailbox to metrics',
			mailbox: 'Mailbox',
			mailboxNote: 'IMAP, read-only',
			decode: 'Decode',
			decodeNote: 'MIME, gzip, zip',
			parse: 'Parse',
			parseNote: 'RFC 7489 / 8460',
			store: 'Store',
			storeNote: 'SQLite, full detail',
			quarantine: 'Quarantine',
			quarantineNote: 'kept, never deleted',
			classify: 'Classify',
			classifyNote: 'against your SPF',
			metrics: 'Metrics',
			metricsNote: 'bounded series',
			api: 'JSON API',
			apiNote: 'per-source detail'
		},
		buckets: {
			heading: 'Three buckets, resolved from DNS',
			self: 'self',
			selfNote: 'Authorised by your SPF record, or by an explicit operator override.',
			forwarder: 'forwarder',
			forwarderNote: 'Not authorised, but carrying an aligned DKIM signature — the signature of forwarding, where SPF breaks across a hop and DKIM survives it.',
			unknown: 'unknown',
			unknownNote: 'Everything else. This is the bucket that actually needs attention.'
		}
	},
	metrics: {
		heading: 'What it exports',
		lede: 'Prometheus text on a private listener, alongside a JSON API for the detail that must not become labels.',
		gaugeNote: {
			title: 'Volumes are gauges, not counters',
			body: 'Reports arrive a day late and out of order, and retention deletes old ones. A counter would be non-monotonic and rate() would report nonsense. Alert on ratios within the window instead.'
		},
		stalenessNote: {
			title: 'Staleness is expressible',
			body: 'A zero failure rate because nothing was ingested looks identical to a zero failure rate because nothing failed. A last-received timestamp per domain and format is exported so you can tell those apart.'
		},
		tableCaption: 'Exported metric families',
		columns: { metric: 'Metric', labels: 'Labels' },
		alertsHeading: 'Worth alerting on',
		alerts: [
			{
				severity: 'warning',
				title: 'Authentication regression',
				body: 'The pass rate for your own sources drops over a sustained window. Your mail is failing somewhere.'
			},
			{
				severity: 'warning',
				title: 'TLS negotiation failures',
				body: 'Any failed session count above zero. There is no acceptable baseline for senders failing to reach you over TLS.'
			},
			{
				severity: 'never',
				title: 'Not report volume',
				body: 'Aggregate reports arriving late, or not at all, is entirely normal and not actionable. Alerting on it only teaches people to ignore the alerts.'
			}
		]
	},
	guarantees: {
		heading: 'Operational guarantees',
		items: [
			{
				title: 'Your mailbox is never modified',
				body: 'The feeder opens it read-only, peeks rather than marking messages read, and tracks its own position. The mailbox stays usable by a human or another tool.'
			},
			{
				title: 'Ingest is idempotent',
				body: 'Identical bytes are recognised by checksum, and the same report arriving under a different envelope by report identity. Reprocessing the entire mailbox is safe, and is the supported recovery path.'
			},
			{
				title: 'Nothing is deleted for failing to parse',
				body: 'Unparseable reports go to quarantine with the error and the original bytes, and survive retention sweeps. Autoreplies and spam are recorded as ignored, not as failures.'
			},
			{
				title: 'Protocols, not products',
				body: 'No MTA admin API, no delivery-provider API, no log tailing, and no assumption that you run any particular mail server, dashboard or deployment tool.'
			}
		]
	},
	start: {
		heading: 'Quick start',
		lede: 'Point it at the mailbox your rua= address already delivers to. The IMAP password is named by environment variable and never written to the file, so the config stays committable.',
		configCaption: 'config.yaml',
		runCaption: 'Run it',
		endpointsHeading: 'Two listeners',
		endpointsLede:
			'They carry different things. The read API exposes source addresses and reporter identities — together, your whole sending topology — which is why it is not on the public one.',
		publicLabel: 'Public',
		publicNote: 'safe to expose',
		privateLabel: 'Private',
		privateNote: 'keep internal'
	},
	footer: {
		tagline: 'Report ingest for people who run their own mail.',
		builtWith: 'Built in Go. Embedded SQLite. No external services.',
		sections: {
			project: 'Project',
			standards: 'Standards'
		},
		links: {
			spec: 'Design spec',
			readme: 'README',
			quickstart: 'Quick start'
		},
		rights: 'All rights reserved.'
	}
};

export type Messages = typeof en;
