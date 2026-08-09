<script lang="ts">
	interface Props {
		caption?: string;
		code: string;
		/** Renders macOS-style window dots and a monospace caption bar. */
		terminal?: boolean;
		label?: string;
	}

	let { caption, code, terminal = false, label }: Props = $props();
</script>

<figure class="overflow-hidden rounded-card border border-line bg-surface-sunken">
	{#if caption}
		<figcaption
			class="flex items-center gap-2 border-b border-line px-4 py-2.5 font-mono text-xs text-ink-faint"
		>
			{#if terminal}
				<span class="flex gap-1.5" aria-hidden="true">
					<span class="size-2.5 rounded-full bg-fail/60"></span>
					<span class="size-2.5 rounded-full bg-warn/60"></span>
					<span class="size-2.5 rounded-full bg-pass/60"></span>
				</span>
			{/if}
			<span>{caption}</span>
		</figcaption>
	{/if}
	<!-- Wide code scrolls inside its own box so the page body never scrolls
	     horizontally on a phone. -->
	<div class="scroll-x">
		<pre
			class="px-4 py-4 font-mono text-[0.8125rem] leading-relaxed text-ink"
			aria-label={label}><code>{code}</code></pre>
	</div>
</figure>
