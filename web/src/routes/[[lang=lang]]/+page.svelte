<script lang="ts">
	import CodeBlock from '$lib/components/CodeBlock.svelte';
	import LocaleSwitch from '$lib/components/LocaleSwitch.svelte';
	import Pipeline from '$lib/components/Pipeline.svelte';
	import Seo from '$lib/components/Seo.svelte';
	import ThemeToggle from '$lib/components/ThemeToggle.svelte';
	import { endpoints, metricRows, site, snippets } from '$lib/site';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const t = $derived(data.t);
	const locale = $derived(data.locale);

	const navLinks = $derived([
		{ href: '#capabilities', label: t.nav.capabilities },
		{ href: '#cardinality', label: t.nav.cardinality },
		{ href: '#metrics', label: t.nav.metrics },
		{ href: '#start', label: t.nav.start }
	]);

	const severityClass: Record<string, string> = {
		warning: 'border-warn/40 bg-warn-soft text-warn',
		never: 'border-line text-ink-faint'
	};
</script>

<Seo {locale} path="/" />

<a
	href="#main"
	class="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-surface focus:px-4 focus:py-2 focus:text-ink focus:shadow-lg"
>
	{t.nav.skipToContent}
</a>

<div class="min-h-screen bg-canvas">
	<header
		class="sticky top-0 z-40 border-b border-line bg-canvas/85 backdrop-blur supports-[backdrop-filter]:bg-canvas/70"
	>
		<div class="mx-auto flex h-16 max-w-6xl items-center gap-4 px-4 sm:px-6 lg:px-8">
			<a href={locale === 'de' ? '/de' : '/'} class="flex items-center gap-2.5 font-mono font-semibold text-ink">
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

			<nav class="ml-auto hidden items-center gap-6 md:flex" aria-label={t.nav.capabilities}>
				{#each navLinks as link (link.href)}
					<a href={link.href} class="text-sm text-ink-muted transition-colors hover:text-ink">
						{link.label}
					</a>
				{/each}
			</nav>

			<div class="ml-auto flex items-center gap-2 md:ml-0">
				<LocaleSwitch current={locale} label={t.nav.languageLabel} />
				<ThemeToggle label={t.nav.themeToggle} />
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
							{t.hero.eyebrow}
						</p>

						<h1 class="mt-6 text-4xl font-semibold leading-[1.1] tracking-tight text-ink sm:text-5xl lg:text-[3.4rem]">
							{t.hero.title}
							<span class="block text-accent">{t.hero.titleAccent}</span>
						</h1>

						<p class="mt-6 max-w-xl text-lg leading-relaxed text-ink-muted">
							{t.hero.lede}
						</p>

						<div class="mt-8 flex flex-wrap items-center gap-3">
							<a
								href="#start"
								class="inline-flex items-center gap-2 rounded-lg bg-accent px-5 py-2.5 text-sm font-medium text-canvas transition-opacity hover:opacity-90"
							>
								{t.hero.primaryCta}
								<svg viewBox="0 0 20 20" class="size-4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
									<path d="M4 10h11M11 6l4 4-4 4" />
								</svg>
							</a>
							<a
								href="#metrics"
								class="inline-flex items-center rounded-lg border border-line-strong px-5 py-2.5 text-sm font-medium text-ink transition-colors hover:bg-surface"
							>
								{t.hero.secondaryCta}
							</a>
						</div>

						<ul class="mt-8 flex flex-wrap gap-x-6 gap-y-2 text-sm text-ink-faint">
							{#each [t.hero.badges.selfHosted, t.hero.badges.noEgress, t.hero.badges.singleBinary] as badge (badge)}
								<li class="flex items-center gap-2">
									<svg viewBox="0 0 20 20" class="size-4 text-pass" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
										<path d="m4 10.5 4 4 8-9" />
									</svg>
									{badge}
								</li>
							{/each}
						</ul>
					</div>

					<CodeBlock terminal caption={t.hero.terminalCaption} code={snippets.run} />
				</div>
			</div>
		</section>

		<!-- The problem -->
		<section class="border-b border-line py-20 sm:py-24">
			<div class="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
				<div class="max-w-2xl">
					<h2 class="text-3xl font-semibold tracking-tight text-ink sm:text-4xl">
						{t.problem.heading}
					</h2>
					<p class="mt-4 text-lg leading-relaxed text-ink-muted">{t.problem.lede}</p>
				</div>

				<ul class="mt-12 grid gap-6 md:grid-cols-3">
					{#each t.problem.items as item (item.title)}
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
					<h2 class="text-3xl font-semibold tracking-tight text-ink sm:text-4xl">
						{t.capabilities.heading}
					</h2>
					<p class="mt-4 text-lg leading-relaxed text-ink-muted">{t.capabilities.lede}</p>
				</div>

				<div class="mt-12 grid gap-6 sm:grid-cols-2">
					{#each t.capabilities.items as item (item.title)}
						<article class="rounded-card border border-line bg-surface p-6 sm:p-7">
							<p class="font-mono text-xs uppercase tracking-wider text-accent">{item.tag}</p>
							<h3 class="mt-3 text-lg font-semibold text-ink">{item.title}</h3>
							<p class="mt-3 text-sm leading-relaxed text-ink-muted">{item.body}</p>
						</article>
					{/each}
				</div>
			</div>
		</section>

		<!-- Cardinality: the actual argument -->
		<section id="cardinality" class="scroll-mt-20 border-b border-line bg-surface-sunken py-20 sm:py-24">
			<div class="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
				<div class="max-w-3xl">
					<h2 class="text-3xl font-semibold tracking-tight text-ink sm:text-4xl">
						{t.cardinality.heading}
					</h2>
					<p class="mt-4 text-lg leading-relaxed text-ink-muted">{t.cardinality.lede}</p>
					<p class="mt-4 leading-relaxed text-ink-muted">{t.cardinality.explanation}</p>
					<p class="mt-4 flex items-start gap-2.5 rounded-lg border border-pass/30 bg-pass-soft px-4 py-3 text-sm text-ink">
						<svg viewBox="0 0 20 20" class="mt-0.5 size-4 shrink-0 text-pass" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
							<path d="m4 10.5 4 4 8-9" />
						</svg>
						{t.cardinality.assertion}
					</p>
				</div>

				<div class="mt-12">
					<Pipeline t={t.cardinality.pipeline} />
				</div>

				<div class="mt-12">
					<h3 class="text-lg font-semibold text-ink">{t.cardinality.buckets.heading}</h3>
					<dl class="mt-5 grid gap-4 md:grid-cols-3">
						{#each [{ key: t.cardinality.buckets.self, note: t.cardinality.buckets.selfNote, tone: 'pass' }, { key: t.cardinality.buckets.forwarder, note: t.cardinality.buckets.forwarderNote, tone: 'warn' }, { key: t.cardinality.buckets.unknown, note: t.cardinality.buckets.unknownNote, tone: 'fail' }] as bucket (bucket.key)}
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
					<h2 class="text-3xl font-semibold tracking-tight text-ink sm:text-4xl">
						{t.metrics.heading}
					</h2>
					<p class="mt-4 text-lg leading-relaxed text-ink-muted">{t.metrics.lede}</p>
				</div>

				<div class="mt-12 grid gap-8 lg:grid-cols-[1fr_1fr] lg:gap-10">
					<CodeBlock caption="/metrics" code={snippets.metrics} />

					<div class="space-y-4">
						{#each [t.metrics.gaugeNote, t.metrics.stalenessNote] as note (note.title)}
							<div class="rounded-card border border-line bg-surface p-5">
								<h3 class="text-sm font-semibold text-ink">{note.title}</h3>
								<p class="mt-2 text-sm leading-relaxed text-ink-muted">{note.body}</p>
							</div>
						{/each}
					</div>
				</div>

				<div class="mt-12 overflow-hidden rounded-card border border-line bg-surface">
					<div class="scroll-x">
						<table class="w-full min-w-[36rem] border-collapse text-left text-sm">
							<caption class="sr-only">{t.metrics.tableCaption}</caption>
							<thead>
								<tr class="border-b border-line bg-surface-sunken">
									<th scope="col" class="px-5 py-3 font-medium text-ink-muted">
										{t.metrics.columns.metric}
									</th>
									<th scope="col" class="px-5 py-3 font-medium text-ink-muted">
										{t.metrics.columns.labels}
									</th>
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

				<h3 class="mt-14 text-lg font-semibold text-ink">{t.metrics.alertsHeading}</h3>
				<ul class="mt-5 grid gap-4 md:grid-cols-3">
					{#each t.metrics.alerts as alert (alert.title)}
						<li class="rounded-card border border-line bg-surface p-5">
							<span
								class="inline-flex rounded-md border px-2 py-0.5 font-mono text-[0.6875rem] uppercase tracking-wider {severityClass[
									alert.severity
								]}"
							>
								{alert.severity}
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
					{t.guarantees.heading}
				</h2>

				<ul class="mt-12 grid gap-6 sm:grid-cols-2">
					{#each t.guarantees.items as item (item.title)}
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
					<h2 class="text-3xl font-semibold tracking-tight text-ink sm:text-4xl">
						{t.start.heading}
					</h2>
					<p class="mt-4 text-lg leading-relaxed text-ink-muted">{t.start.lede}</p>
				</div>

				<div class="mt-12 grid gap-6 lg:grid-cols-2">
					<CodeBlock caption={t.start.configCaption} code={snippets.config} />
					<CodeBlock terminal caption={t.start.runCaption} code={snippets.run} />
				</div>

				<div class="mt-16">
					<h3 class="text-lg font-semibold text-ink">{t.start.endpointsHeading}</h3>
					<p class="mt-3 max-w-2xl leading-relaxed text-ink-muted">{t.start.endpointsLede}</p>

					<div class="mt-6 grid gap-6 md:grid-cols-2">
						{#each [{ label: t.start.publicLabel, note: t.start.publicNote, rows: endpoints.public, tone: 'pass' }, { label: t.start.privateLabel, note: t.start.privateNote, rows: endpoints.private, tone: 'warn' }] as group (group.label)}
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
					<p class="mt-3 max-w-sm text-sm leading-relaxed text-ink-muted">{t.footer.tagline}</p>
					<p class="mt-3 text-sm text-ink-faint">{t.footer.builtWith}</p>
				</div>

				<div>
					<h2 class="text-sm font-semibold text-ink">{t.footer.sections.project}</h2>
					<ul class="mt-3 space-y-2 text-sm">
						<li>
							<a href="#start" class="text-ink-muted transition-colors hover:text-ink">
								{t.footer.links.quickstart}
							</a>
						</li>
						<li>
							<a href="#metrics" class="text-ink-muted transition-colors hover:text-ink">
								{t.nav.metrics}
							</a>
						</li>
					</ul>
				</div>

				<div>
					<h2 class="text-sm font-semibold text-ink">{t.footer.sections.standards}</h2>
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
				© {new Date().getFullYear()} {site.name}. {t.footer.rights}
			</p>
		</div>
	</footer>
</div>
