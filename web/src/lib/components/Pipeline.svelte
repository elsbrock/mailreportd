<script lang="ts">
	import type { Messages } from '$lib/i18n';

	interface Props {
		t: Messages['cardinality']['pipeline'];
	}

	let { t }: Props = $props();

	// One row of the happy path, with two things hanging off it: quarantine,
	// which is where failures are kept rather than dropped, and the JSON API,
	// which is how per-source detail leaves without passing through Prometheus.
	const step = 160;
	const boxW = 132;
	const boxH = 62;
	const row = 104;

	// Derived, so switching locale re-labels the diagram rather than freezing the
	// labels captured at first render.
	const stages = $derived([
		{ x: 8, label: t.mailbox, note: t.mailboxNote },
		{ x: 8 + step, label: t.decode, note: t.decodeNote },
		{ x: 8 + step * 2, label: t.parse, note: t.parseNote },
		{ x: 8 + step * 3, label: t.store, note: t.storeNote },
		{ x: 8 + step * 4, label: t.classify, note: t.classifyNote }
	]);

	const parseX = 8 + step * 2;
	const storeX = 8 + step * 3;
	const outX = 8 + step * 5;
	const lowerRow = 214;
</script>

<figure class="not-prose">
	<div class="scroll-x rounded-card border border-line bg-surface p-4 sm:p-6">
		<svg
			viewBox="0 56 960 236"
			class="h-auto w-full min-w-[46rem]"
			role="img"
			aria-labelledby="pipeline-title pipeline-desc"
		>
			<title id="pipeline-title">{t.caption}</title>
			<desc id="pipeline-desc">
				{t.mailbox} → {t.decode} → {t.parse} → {t.store} → {t.classify} → {t.metrics}. {t.parse}
				→ {t.quarantine}. {t.store} → {t.api}.
			</desc>

			<defs>
				<marker
					id="arrow"
					viewBox="0 0 10 10"
					refX="9"
					refY="5"
					markerWidth="6"
					markerHeight="6"
					orient="auto-start-reverse"
				>
					<path d="M 0 0 L 10 5 L 0 10 z" fill="var(--color-line-strong)" />
				</marker>
			</defs>

			<!-- Connectors are drawn first so the boxes sit on top of the line ends. -->
			<g stroke="var(--color-line-strong)" stroke-width="1.5" fill="none" marker-end="url(#arrow)">
				{#each stages.slice(0, -1) as stage, i (i)}
					<line
						x1={stage.x + boxW}
						y1={row + boxH / 2}
						x2={stage.x + step}
						y2={row + boxH / 2}
					/>
				{/each}

				<!-- Parse → Quarantine -->
				<path d={`M ${parseX + boxW / 2} ${row + boxH} V ${lowerRow}`} />

				<!-- Store → JSON API: detail leaves without ever passing through
				     classification or Prometheus. -->
				<path
					d={`M ${storeX + boxW / 2} ${row + boxH} V ${lowerRow + boxH / 2} H ${outX}`}
				/>
			</g>

			{#each stages as stage, i (i)}
				<g>
					<rect
						x={stage.x}
						y={row}
						width={boxW}
						height={boxH}
						rx="10"
						fill="var(--color-surface-sunken)"
						stroke="var(--color-line-strong)"
						stroke-width="1.5"
					/>
					<text
						x={stage.x + boxW / 2}
						y={row + 26}
						text-anchor="middle"
						fill="var(--color-ink)"
						font-size="14"
						font-weight="600">{stage.label}</text
					>
					<text
						x={stage.x + boxW / 2}
						y={row + 44}
						text-anchor="middle"
						fill="var(--color-ink-faint)"
						font-size="11">{stage.note}</text
					>
				</g>
			{/each}

			<!-- Metrics: the bounded output. -->
			<g>
				<rect
					x={outX}
					y={row - boxH / 2 - 6}
					width={boxW}
					height={boxH}
					rx="10"
					fill="var(--color-accent-soft)"
					stroke="var(--color-accent)"
					stroke-width="1.5"
				/>
				<text
					x={outX + boxW / 2}
					y={row - boxH / 2 + 20}
					text-anchor="middle"
					fill="var(--color-ink)"
					font-size="14"
					font-weight="600">{t.metrics}</text
				>
				<text
					x={outX + boxW / 2}
					y={row - boxH / 2 + 38}
					text-anchor="middle"
					fill="var(--color-ink-muted)"
					font-size="11">{t.metricsNote}</text
				>
			</g>

			<!-- Classify → Metrics. The metrics box sits slightly high, so this
			     connector rises to meet it. -->
			<line
				x1={stages[4].x + boxW}
				y1={row + boxH / 2}
				x2={outX}
				y2={row - boxH / 2 + 25}
				stroke="var(--color-accent)"
				stroke-width="1.5"
				marker-end="url(#arrow)"
			/>

			<!-- Quarantine: kept, never deleted. -->
			<g>
				<rect
					x={parseX}
					y={lowerRow}
					width={boxW}
					height={boxH}
					rx="10"
					fill="var(--color-warn-soft)"
					stroke="var(--color-warn)"
					stroke-width="1.5"
					stroke-dasharray="5 4"
				/>
				<text
					x={parseX + boxW / 2}
					y={lowerRow + 26}
					text-anchor="middle"
					fill="var(--color-ink)"
					font-size="14"
					font-weight="600">{t.quarantine}</text
				>
				<text
					x={parseX + boxW / 2}
					y={lowerRow + 44}
					text-anchor="middle"
					fill="var(--color-ink-muted)"
					font-size="11">{t.quarantineNote}</text
				>
			</g>

			<!-- JSON API: the per-source detail. -->
			<g>
				<rect
					x={outX}
					y={lowerRow}
					width={boxW}
					height={boxH}
					rx="10"
					fill="var(--color-surface-sunken)"
					stroke="var(--color-line-strong)"
					stroke-width="1.5"
				/>
				<text
					x={outX + boxW / 2}
					y={lowerRow + 26}
					text-anchor="middle"
					fill="var(--color-ink)"
					font-size="14"
					font-weight="600">{t.api}</text
				>
				<text
					x={outX + boxW / 2}
					y={lowerRow + 44}
					text-anchor="middle"
					fill="var(--color-ink-faint)"
					font-size="11">{t.apiNote}</text
				>
			</g>
		</svg>
	</div>
	<figcaption class="mt-3 text-center text-sm text-ink-faint">{t.caption}</figcaption>
</figure>
