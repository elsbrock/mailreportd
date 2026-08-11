<script lang="ts">
	import CodeBlock from '$lib/components/CodeBlock.svelte';
	import Pipeline from '$lib/components/Pipeline.svelte';
	import Seo from '$lib/components/Seo.svelte';
	import ThemeToggle from '$lib/components/ThemeToggle.svelte';
	import { endpoints, metricRows, site, snippets } from '$lib/site';

	const navLinks = [
		{ href: '#capabilities', label: 'Capabilities' },
		{ href: '#matrix', label: 'Feature matrix' },
		{ href: '#cardinality', label: 'Cardinality' },
		{ href: '#metrics', label: 'Metrics' },
		{ href: '#start', label: 'Quick start' }
	];

	const heroBadges = ['Runs on your hardware', 'No data egress', 'Single static binary'];

	const problems = [
		{
			title: 'TLS negotiation failures',
			body: 'A certificate rotation, a stale policy, or a firewall change can break TLS negotiation. The failure happens on the sender’s side of the connection, so it does not show up in your logs.'
		},
		{
			title: 'DKIM and SPF fail at the receiver',
			body: 'Mail can leave your MTA correctly and still arrive unauthenticated. A rotated key, an unaligned signing domain, or a relay that rewrites headers can break DKIM or SPF at the receiver, while your MTA only reported a successful handoff.'
		},
		{
			title: 'Spoofing and forgotten senders',
			body: 'Spoofing and forgotten legacy senders both show up only in aggregate reports. Parsing them is a prerequisite for moving to an enforcing DMARC policy.'
		}
	];

	const capabilities = [
		{
			tag: 'RFC 7489',
			title: 'DMARC aggregate reports',
			body: 'Parsed into per-source authentication results. The parser tolerates common schema deviations: padded integers, ISO timestamps where Unix seconds belong, and unexpected character sets.'
		},
		{
			tag: 'RFC 8460',
			title: 'SMTP TLS reports',
			body: 'Session counts and failure detail, broken down by result type and policy type.'
		},
		{
			tag: 'RFC 6591',
			title: 'DMARC failure reports',
			body: 'The failing message itself, not a count of it. The content is recipient PII, so it is encrypted at rest with a key you provide, kept seven days, and every content read is access-logged.'
		},
		{
			tag: 'RFC 7208',
			title: 'Sender classification from SPF',
			body: 'Every reporting source is resolved against your domain’s own published SPF record and classified as self, forwarder, or unknown. Nothing about your infrastructure is hardcoded.'
		},
		{
			tag: 'Ten-lookup limit',
			title: 'SPF record health',
			body: 'The same expansion counts the DNS lookups your record consumes. More than ten is a permanent error at real receivers, exported as a metric.'
		},
		{
			tag: 'Ingest',
			title: 'Mailbox, maildir, or HTTPS',
			body: 'An IMAP mailbox polled read-only, a locally delivered maildir, or reporters submitting straight to POST /tlsrpt. All three enter the same parse, dedupe and storage path.'
		}
	];

	const matrixGroups = [
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
					status: 'supported',
					note: 'POST /tlsrpt on the public listener, off by default. Enable it when your TLS-RPT record publishes an https rua.'
				},
				{
					name: 'DMARC failure reports',
					standard: 'RFC 6591',
					status: 'supported',
					note: 'The content is recipient PII, so it is encrypted at rest with a key you provide, kept seven days, and every content read is access-logged. Without a key, only the envelope is stored.'
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
					note: 'Distinguishes missing, revoked, malformed, weak, and valid selector states; each needs a different fix.'
				},
				{
					name: 'DMARC record, pct and sp',
					standard: 'RFC 7489',
					status: 'supported',
					note: 'A pct below 100 reads as enforcement while enforcing on a sample. The subdomain policy is resolved rather than reported raw.'
				},
				{
					name: 'External destination authorization',
					standard: 'RFC 7489 §7.1',
					status: 'supported',
					note: 'Verifies the record that authorizes a third-party rua address to receive your reports.'
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
					note: 'Only meaningful over DNSSEC, and validating it requires a validating resolver rather than a stub resolver.'
				},
				{
					name: 'BIMI',
					standard: 'Draft',
					status: 'declined',
					note: 'Requires a verified mark certificate and has no effect on deliverability.'
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
					status: 'supported',
					note: 'For deployments that deliver locally instead of exposing IMAP. Reads new/ and cur/; never renames, moves or deletes a file.'
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
					note: 'Per-source and per-signer detail that is too high-cardinality for metric labels.'
				}
			]
		}
	];

	const buckets = [
		{
			key: 'self',
			note: 'Authorized by your SPF record, or by an explicit operator override.',
			tone: 'pass'
		},
		{
			key: 'forwarder',
			note: 'Not authorized by SPF, but carrying an aligned DKIM signature. SPF breaks across a forwarding hop; DKIM survives it.',
			tone: 'warn'
		},
		{ key: 'unknown', note: 'Everything else: spoofing, misconfiguration, or senders you forgot about.', tone: 'fail' }
	];

	const metricNotes = [
		{
			title: 'Volumes are gauges, not counters',
			body: 'Reports arrive a day late and out of order, and retention deletes old ones. A counter would be non-monotonic and rate() would report nonsense. Alert on ratios within the window instead.'
		},
		{
			title: 'Staleness is a separate metric',
			body: 'A zero failure rate can mean nothing failed, or it can mean nothing was ingested. A last-received timestamp per domain and format distinguishes the two.'
		}
	];

	const alerts = [
		{
			severity: 'warning',
			title: 'Authentication regression',
			body: 'Alert when the pass rate for your own sources drops over a sustained window. It means your mail is failing somewhere.'
		},
		{
			severity: 'warning',
			title: 'TLS negotiation failures',
			body: 'Alert on any failed session count above zero. There is no acceptable baseline for senders failing to reach you over TLS.'
		},
		{
			severity: 'never',
			title: 'Not report volume',
			body: 'Aggregate reports arriving late, or not at all, is normal and not actionable. Alerting on it teaches people to ignore the alerts.'
		}
	];

	const guarantees = [
		{
			title: 'Your mailbox is never modified',
			body: 'The feeder opens it read-only, peeks rather than marking messages read, and tracks its own position. The mailbox stays usable by a human or another tool.'
		},
		{
			title: 'Ingest is idempotent',
			body: 'Identical bytes are recognized by checksum, and the same report arriving under a different envelope by report identity. Reprocessing the entire mailbox is safe, and is the supported recovery path.'
		},
		{
			title: 'Nothing is deleted for failing to parse',
			body: 'Unparseable reports go to quarantine with the error and the original bytes, and survive retention sweeps. Autoreplies and spam are recorded as ignored, not as failures.'
		},
		{
			title: 'Works with any mail setup',
			body: 'No MTA admin API, no delivery-provider API, no log tailing, and no assumption that you run any particular mail server, dashboard or deployment tool.'
		}
	];

	const endpointGroups = [
		{ label: 'Public', note: 'safe to expose', rows: endpoints.public, tone: 'pass' },
		{ label: 'Private', note: 'keep internal', rows: endpoints.private, tone: 'warn' }
	];

	const severityClass: Record<string, string> = {
		warning: 'border-warn/40 bg-warn-soft text-warn',
		never: 'border-line text-ink-faint'
	};

	const statusClass: Record<string, string> = {
		supported: 'border-pass/40 bg-pass-soft text-pass',
		planned: 'border-line-strong text-ink-muted',
		declined: 'border-line text-ink-faint'
	};

	const statusLabel: Record<string, string> = {
		supported: 'Supported',
		planned: 'Planned',
		declined: 'Not planned'
	};
</script>

<Seo path="/" />

<a
	href="#main"
	class="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-surface focus:px-4 focus:py-2 focus:text-ink focus:shadow-lg"
>
	Skip to content
</a>

<div class="min-h-screen bg-canvas">
	<header
		class="sticky top-0 z-40 border-b border-line bg-canvas/85 backdrop-blur supports-[backdrop-filter]:bg-canvas/70"
	>
		<div class="mx-auto flex h-16 max-w-6xl items-center gap-4 px-4 sm:px-6 lg:px-8">
			<a href="/" class="flex items-center gap-2.5 font-mono font-semibold text-ink">
				<span
					class="grid size-7 place-items-center rounded-md border border-accent/40 bg-accent-soft text-accent"
					aria-hidden="true"
				>
					<svg viewBox="0 0 24 24" class="size-4" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
						<path d="M3 7.5 12 13l9-5.5" />
						<rect x="3" y="5" width="18" height="14" rx="2.5" />
					</svg>
				</span>
				{site.name}
			</a>

			<nav class="ml-auto hidden items-center gap-6 md:flex" aria-label="Sections">
				{#each navLinks as link (link.href)}
					<a href={link.href} class="text-sm text-ink-muted transition-colors hover:text-ink">
						{link.label}
					</a>
				{/each}
			</nav>

			<div class="ml-auto flex items-center gap-2 md:ml-0">
				<ThemeToggle label="Switch color theme" />
			</div>
		</div>
	</header>

	<main id="main">
		<!-- Hero -->
		<section class="relative overflow-hidden border-b border-line">
			<div
				class="pointer-events-none absolute inset-0 opacity-[0.35]"
				style="background-image: radial-gradient(circle at 20% -10%, var(--color-accent-soft), transparent 55%), radial-gradient(circle at 85% 0%, var(--color-pass-soft), transparent 45%)"
				aria-hidden="true"
			></div>

			<div class="relative mx-auto max-w-6xl px-4 py-20 sm:px-6 sm:py-24 lg:px-8 lg:py-28">
				<div class="grid items-center gap-12 lg:grid-cols-[1.05fr_1fr] lg:gap-16">
					<div>
						<p
							class="inline-flex items-center gap-2 rounded-full border border-line bg-surface px-3 py-1 font-mono text-xs uppercase tracking-wider text-ink-muted"
						>
							<span class="size-1.5 rounded-full bg-pass" aria-hidden="true"></span>
							Self-hosted mail observability
						</p>

						<h1 class="mt-6 text-4xl font-semibold leading-[1.1] tracking-tight text-ink sm:text-5xl">
							<span class="block text-balance">Prometheus metrics from the mail reports</span>
							<span class="block text-accent">you already receive.</span>
						</h1>

						<p class="mt-6 max-w-xl text-lg leading-relaxed text-ink-muted">
							mailreportd reads DMARC and SMTP TLS reports from an IMAP mailbox, a local maildir, or
							HTTPS submission, and exports them as metrics: authentication results, TLS failures,
							and the health of the policies you publish in DNS.
						</p>

						<div class="mt-8 flex flex-wrap items-center gap-3">
							<a
								href="#start"
								class="inline-flex items-center gap-2 rounded-lg bg-accent px-5 py-2.5 text-sm font-medium text-canvas transition-opacity hover:opacity-90"
							>
								Read the quick start
								<svg viewBox="0 0 20 20" class="size-4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
									<path d="M4 10h11M11 6l4 4-4 4" />
								</svg>
							</a>
							<a
								href="#metrics"
								class="inline-flex items-center rounded-lg border border-line-strong px-5 py-2.5 text-sm font-medium text-ink transition-colors hover:bg-surface"
							>
								See what it exports
							</a>
						</div>

						<ul class="mt-8 flex flex-wrap gap-x-6 gap-y-2 text-sm text-ink-faint">
							{#each heroBadges as badge (badge)}
								<li class="flex items-center gap-2">
									<svg viewBox="0 0 20 20" class="size-4 text-pass" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
										<path d="m4 10.5 4 4 8-9" />
									</svg>
									{badge}
								</li>
							{/each}
						</ul>
					</div>

					<CodeBlock terminal caption="Ingesting from a live mailbox" code={snippets.run} />
				</div>
			</div>
		</section>

		<!-- The problem -->
		<section class="border-b border-line py-20 sm:py-24">
			<div class="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
				<div class="max-w-2xl">
					<h2 class="text-3xl font-semibold tracking-tight text-ink sm:text-4xl">
						What the reports catch
					</h2>
					<p class="mt-4 text-lg leading-relaxed text-ink-muted">
						Authentication failures often produce no error on the sending side. The receiver sees them
						and reports them back.
					</p>
				</div>

				<ul class="mt-12 grid gap-6 md:grid-cols-3">
					{#each problems as item (item.title)}
						<li class="rounded-card border border-line bg-surface p-6">
							<h3 class="flex items-start gap-2.5 text-base font-semibold text-ink">
								<svg viewBox="0 0 20 20" class="mt-0.5 size-4 shrink-0 text-fail" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" aria-hidden="true">
									<circle cx="10" cy="10" r="7.5" />
									<path d="M10 6v5M10 13.6v.4" />
								</svg>
								{item.title}
							</h3>
							<p class="mt-3 text-sm leading-relaxed text-ink-muted">{item.body}</p>
						</li>
					{/each}
				</ul>
			</div>
		</section>

		<!-- Capabilities -->
		<section id="capabilities" class="scroll-mt-20 border-b border-line py-20 sm:py-24">
			<div class="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
				<div class="max-w-2xl">
					<h2 class="text-3xl font-semibold tracking-tight text-ink sm:text-4xl">What it reads</h2>
					<p class="mt-4 text-lg leading-relaxed text-ink-muted">
						Three RFC-defined report formats, from any receiver that sends them, with no cooperation
						required from your MTA.
					</p>
				</div>

				<div class="mt-12 grid gap-6 sm:grid-cols-2">
					{#each capabilities as item (item.title)}
						<article class="rounded-card border border-line bg-surface p-6 sm:p-7">
							<p class="font-mono text-xs uppercase tracking-wider text-accent">{item.tag}</p>
							<h3 class="mt-3 text-lg font-semibold text-ink">{item.title}</h3>
							<p class="mt-3 text-sm leading-relaxed text-ink-muted">{item.body}</p>
						</article>
					{/each}
				</div>
			</div>
		</section>

		<!-- Feature matrix, including what is deliberately absent -->
		<section id="matrix" class="scroll-mt-20 border-b border-line py-20 sm:py-24">
			<div class="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
				<div class="max-w-2xl">
					<h2 class="text-3xl font-semibold tracking-tight text-ink sm:text-4xl">Feature matrix</h2>
					<p class="mt-4 text-lg leading-relaxed text-ink-muted">
						Report ingest covers what receivers observed about your mail. Policy checks cover what
						your DNS publishes right now.
					</p>
				</div>

				<div class="mt-12 overflow-hidden rounded-card border border-line bg-surface">
					<!-- Focusable, because on a narrow viewport this is the only way to
					     reach the right-hand columns without a pointer (WCAG 2.1.1). The
					     lint rule objects to tabindex on a non-interactive element; the
					     success criterion wins. -->
					<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
					<div class="scroll-x" tabindex="0" role="region" aria-label="Supported standards and capabilities">
						<table class="w-full min-w-[44rem] border-collapse text-left text-sm">
							<caption class="sr-only">Supported standards and capabilities</caption>
							<thead>
								<tr class="border-b border-line bg-surface-sunken">
									<th scope="col" class="px-5 py-3 font-medium text-ink-muted">Capability</th>
									<th scope="col" class="px-5 py-3 font-medium text-ink-muted">Standard</th>
									<th scope="col" class="px-5 py-3 font-medium text-ink-muted">Status</th>
								</tr>
							</thead>
							{#each matrixGroups as group (group.name)}
								<tbody>
									<tr class="border-b border-line bg-surface-sunken/60">
										<th
											scope="colgroup"
											colspan="3"
											class="px-5 py-2.5 text-left text-xs font-semibold uppercase tracking-wider text-ink"
										>
											{group.name}
											<span class="ml-2 font-normal normal-case tracking-normal text-ink-faint">
												{group.note}
											</span>
										</th>
									</tr>
									{#each group.items as item (item.name)}
										<tr class="border-b border-line last:border-0">
											<td class="px-5 py-3 align-top">
												<span class="font-medium text-ink">{item.name}</span>
												<span class="mt-1 block text-[0.8125rem] leading-relaxed text-ink-muted">
													{item.note}
												</span>
											</td>
											<td
												class="whitespace-nowrap px-5 py-3 align-top font-mono text-[0.8125rem] text-ink-faint"
											>
												{item.standard}
											</td>
											<td class="whitespace-nowrap px-5 py-3 align-top">
												<span
													class="inline-flex rounded-md border px-2 py-0.5 font-mono text-[0.6875rem] uppercase tracking-wider {statusClass[
														item.status
													]}"
												>
													{statusLabel[item.status] ?? item.status}
												</span>
											</td>
										</tr>
									{/each}
								</tbody>
							{/each}
						</table>
					</div>
				</div>

				<p class="mt-5 max-w-2xl text-sm leading-relaxed text-ink-faint">
					“Not planned” entries are deliberate decisions. The reason is listed with each one.
				</p>
			</div>
		</section>

		<!-- Cardinality: the actual argument -->
		<section id="cardinality" class="scroll-mt-20 border-b border-line bg-surface-sunken py-20 sm:py-24">
			<div class="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
				<div class="max-w-3xl">
					<h2 class="text-3xl font-semibold tracking-tight text-ink sm:text-4xl">
						Source addresses are never labels
					</h2>
					<p class="mt-4 text-lg leading-relaxed text-ink-muted">
						A month of aggregate reports for a handful of domains contains tens of thousands of
						distinct source addresses, most of them seen exactly once. Exporting those as Prometheus
						labels would create unbounded cardinality and overwhelm the metrics store.
					</p>
					<p class="mt-4 leading-relaxed text-ink-muted">
						So the store keeps the full detail and Prometheus receives bounded series only. Sources
						are classified into three buckets before anything is exported, and the per-address detail
						is served over a JSON API on the private listener instead.
					</p>
					<p class="mt-4 leading-relaxed text-ink-muted">
						DKIM signing domains follow the same rule, because whoever sends the mail chooses them.
						<span class="font-mono text-[0.9em] text-ink">/api/v1/signers</span> aggregates them in the
						store, keyed by signing domain and selector, and shows verification and alignment
						separately: a relay signing under its own domain verifies fine while contributing nothing
						to DMARC.
					</p>
					<p class="mt-4 flex items-start gap-2.5 rounded-lg border border-pass/30 bg-pass-soft px-4 py-3 text-sm text-ink">
						<svg viewBox="0 0 20 20" class="mt-0.5 size-4 shrink-0 text-pass" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
							<path d="m4 10.5 4 4 8-9" />
						</svg>
						This rule is asserted by a test that scans the entire exposition for source addresses.
					</p>
				</div>

				<div class="mt-12">
					<Pipeline />
				</div>

				<div class="mt-12">
					<h3 class="text-lg font-semibold text-ink">Three buckets, resolved from DNS</h3>
					<dl class="mt-5 grid gap-4 md:grid-cols-3">
						{#each buckets as bucket (bucket.key)}
							<div class="rounded-card border border-line bg-surface p-5">
								<dt class="flex items-center gap-2 font-mono text-sm font-semibold text-ink">
									<span
										class="size-2 rounded-full"
										style="background-color: var(--color-{bucket.tone})"
										aria-hidden="true"
									></span>
									{bucket.key}
								</dt>
								<dd class="mt-2.5 text-sm leading-relaxed text-ink-muted">{bucket.note}</dd>
							</div>
						{/each}
					</dl>
				</div>
			</div>
		</section>

		<!-- Metrics -->
		<section id="metrics" class="scroll-mt-20 border-b border-line py-20 sm:py-24">
			<div class="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
				<div class="max-w-2xl">
					<h2 class="text-3xl font-semibold tracking-tight text-ink sm:text-4xl">What it exports</h2>
					<p class="mt-4 text-lg leading-relaxed text-ink-muted">
						Prometheus text on a private listener, alongside a JSON API for the detail that must not
						become labels.
					</p>
				</div>

				<div class="mt-12 grid gap-8 lg:grid-cols-[1fr_1fr] lg:gap-10">
					<CodeBlock caption="/metrics" code={snippets.metrics} />

					<div class="space-y-4">
						{#each metricNotes as note (note.title)}
							<div class="rounded-card border border-line bg-surface p-5">
								<h3 class="text-sm font-semibold text-ink">{note.title}</h3>
								<p class="mt-2 text-sm leading-relaxed text-ink-muted">{note.body}</p>
							</div>
						{/each}
					</div>
				</div>

				<div class="mt-12 overflow-hidden rounded-card border border-line bg-surface">
					<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
					<div class="scroll-x" tabindex="0" role="region" aria-label="Exported metric families">
						<table class="w-full min-w-[36rem] border-collapse text-left text-sm">
							<caption class="sr-only">Exported metric families</caption>
							<thead>
								<tr class="border-b border-line bg-surface-sunken">
									<th scope="col" class="px-5 py-3 font-medium text-ink-muted">Metric</th>
									<th scope="col" class="px-5 py-3 font-medium text-ink-muted">Labels</th>
								</tr>
							</thead>
							<tbody>
								{#each metricRows as row (row.metric)}
									<tr class="border-b border-line last:border-0">
										<td class="whitespace-nowrap px-5 py-3 font-mono text-[0.8125rem] text-ink">
											{row.metric}
										</td>
										<td class="px-5 py-3 font-mono text-[0.8125rem] text-ink-faint">{row.labels}</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				</div>

				<h3 class="mt-14 text-lg font-semibold text-ink">Worth alerting on</h3>
				<ul class="mt-5 grid gap-4 md:grid-cols-3">
					{#each alerts as alert (alert.title)}
						<li class="rounded-card border border-line bg-surface p-5">
							<span
								class="inline-flex rounded-md border px-2 py-0.5 font-mono text-[0.6875rem] uppercase tracking-wider {severityClass[
									alert.severity
								]}"
							>
								<span class="sr-only">Severity:&nbsp;</span>{alert.severity}
							</span>
							<h4 class="mt-3 text-sm font-semibold text-ink">{alert.title}</h4>
							<p class="mt-2 text-sm leading-relaxed text-ink-muted">{alert.body}</p>
						</li>
					{/each}
				</ul>
			</div>
		</section>

		<!-- Guarantees -->
		<section class="border-b border-line bg-surface-sunken py-20 sm:py-24">
			<div class="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
				<h2 class="max-w-2xl text-3xl font-semibold tracking-tight text-ink sm:text-4xl">
					Operational guarantees
				</h2>

				<ul class="mt-12 grid gap-6 sm:grid-cols-2">
					{#each guarantees as item (item.title)}
						<li class="flex gap-4 rounded-card border border-line bg-surface p-6">
							<svg viewBox="0 0 20 20" class="mt-0.5 size-5 shrink-0 text-accent" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
								<path d="M10 2.5 3.5 5v5c0 3.4 2.7 6.4 6.5 7.5 3.8-1.1 6.5-4.1 6.5-7.5V5L10 2.5Z" />
								<path d="m7.4 10 1.9 1.9 3.5-3.8" />
							</svg>
							<div>
								<h3 class="text-base font-semibold text-ink">{item.title}</h3>
								<p class="mt-2 text-sm leading-relaxed text-ink-muted">{item.body}</p>
							</div>
						</li>
					{/each}
				</ul>
			</div>
		</section>

		<!-- Quick start -->
		<section id="start" class="scroll-mt-20 py-20 sm:py-24">
			<div class="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
				<div class="max-w-2xl">
					<h2 class="text-3xl font-semibold tracking-tight text-ink sm:text-4xl">Quick start</h2>
					<p class="mt-4 text-lg leading-relaxed text-ink-muted">
						Point it at the mailbox your rua= address already delivers to. The IMAP password is named
						by environment variable and never written to the file, so the config stays committable.
					</p>
				</div>

				<div class="mt-12 grid gap-6 lg:grid-cols-2">
					<CodeBlock caption="config.yaml" code={snippets.config} />
					<CodeBlock terminal caption="Run it" code={snippets.run} />
				</div>

				<div class="mt-16">
					<h3 class="text-lg font-semibold text-ink">Two listeners</h3>
					<p class="mt-3 max-w-2xl leading-relaxed text-ink-muted">
						The read API exposes source addresses, signing domains, and reporter identities, which
						together reveal your sending topology. That is why it runs on the private listener only.
					</p>

					<div class="mt-6 grid gap-6 md:grid-cols-2">
						{#each endpointGroups as group (group.label)}
							<div class="overflow-hidden rounded-card border border-line bg-surface">
								<div class="flex items-baseline gap-2 border-b border-line px-5 py-3">
									<span
										class="size-2 rounded-full"
										style="background-color: var(--color-{group.tone})"
										aria-hidden="true"
									></span>
									<h4 class="text-sm font-semibold text-ink">{group.label}</h4>
									<span class="text-xs text-ink-faint">— {group.note}</span>
								</div>
								<ul class="divide-y divide-line">
									{#each group.rows as row (row.path)}
										<li class="flex items-center gap-3 px-5 py-2.5 font-mono text-[0.8125rem]">
											<span class="text-ink-faint">{row.method}</span>
											<span class="text-ink">{row.path}</span>
										</li>
									{/each}
								</ul>
							</div>
						{/each}
					</div>
				</div>
			</div>
		</section>
	</main>

	<footer class="border-t border-line bg-surface-sunken">
		<div class="mx-auto max-w-6xl px-4 py-14 sm:px-6 lg:px-8">
			<div class="grid gap-10 sm:grid-cols-2 lg:grid-cols-4">
				<div class="lg:col-span-2">
					<p class="font-mono font-semibold text-ink">{site.name}</p>
					<p class="mt-3 max-w-sm text-sm leading-relaxed text-ink-muted">
						Report ingest for people who run their own mail.
					</p>
					<p class="mt-3 text-sm text-ink-faint">
						Built in Go. Embedded SQLite. No external services.
					</p>
				</div>

				<div>
					<h2 class="text-sm font-semibold text-ink">Project</h2>
					<ul class="mt-3 space-y-2 text-sm">
						<li>
							<a href="#start" class="text-ink-muted transition-colors hover:text-ink">Quick start</a>
						</li>
						<li>
							<a href="#metrics" class="text-ink-muted transition-colors hover:text-ink">Metrics</a>
						</li>
					</ul>
				</div>

				<div>
					<h2 class="text-sm font-semibold text-ink">Standards</h2>
					<ul class="mt-3 space-y-2 text-sm">
						{#each site.standards as standard (standard.href)}
							<li>
								<a
									href={standard.href}
									rel="noopener noreferrer"
									class="text-ink-muted transition-colors hover:text-ink"
								>
									{standard.label}
								</a>
							</li>
						{/each}
					</ul>
				</div>
			</div>

			<p class="mt-12 border-t border-line pt-6 text-xs text-ink-faint">
				© {new Date().getFullYear()} {site.name}. All rights reserved.
			</p>
		</div>
	</footer>
</div>
