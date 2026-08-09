<script lang="ts">
	import { onMount } from 'svelte';

	interface Props {
		label: string;
	}

	let { label }: Props = $props();

	type Theme = 'light' | 'dark';

	// Undefined means "follow the system", which is the state a visitor who has
	// never touched the toggle is in.
	let theme = $state<Theme | undefined>(undefined);

	onMount(() => {
		const stored = localStorage.getItem('theme');
		theme = stored === 'light' || stored === 'dark' ? stored : undefined;
	});

	function systemTheme(): Theme {
		return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
	}

	function toggle() {
		const next: Theme = (theme ?? systemTheme()) === 'dark' ? 'light' : 'dark';
		theme = next;
		document.documentElement.dataset.theme = next;
		try {
			localStorage.setItem('theme', next);
		} catch {
			// Storage can be unavailable in private modes; the toggle still works
			// for this page view, it simply will not be remembered.
		}
	}
</script>

<button
	type="button"
	onclick={toggle}
	class="inline-flex size-9 items-center justify-center rounded-lg border border-line text-ink-muted transition-colors hover:border-line-strong hover:text-ink"
	aria-label={label}
	title={label}
>
	<!-- Both glyphs are always in the DOM; CSS decides which is visible, so the
	     control is correct before hydration and needs no layout shift. -->
	<svg
		class="size-4 dark-hidden"
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		stroke-width="1.8"
		stroke-linecap="round"
		aria-hidden="true"
	>
		<circle cx="12" cy="12" r="4.2" />
		<path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.1 5.1l1.4 1.4M17.5 17.5l1.4 1.4M18.9 5.1l-1.4 1.4M6.5 17.5l-1.4 1.4" />
	</svg>
	<svg
		class="size-4 light-hidden"
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		stroke-width="1.8"
		stroke-linecap="round"
		stroke-linejoin="round"
		aria-hidden="true"
	>
		<path d="M20 14.2A8.2 8.2 0 0 1 9.8 4a8.2 8.2 0 1 0 10.2 10.2Z" />
	</svg>
	<span class="sr-only">{label}</span>
</button>

<style>
	/* The icon swap follows the resolved theme, matching the token layer: an
	   explicit choice wins, otherwise the system preference decides. */
	:global(:root[data-theme='dark']) .dark-hidden,
	:global(:root:not([data-theme='light'])) .dark-hidden {
		display: none;
	}
	:global(:root[data-theme='dark']) .light-hidden,
	:global(:root:not([data-theme='light'])) .light-hidden {
		display: block;
	}

	@media (prefers-color-scheme: light) {
		:global(:root:not([data-theme='dark'])) .dark-hidden {
			display: block;
		}
		:global(:root:not([data-theme='dark'])) .light-hidden {
			display: none;
		}
	}

	:global(:root[data-theme='light']) .dark-hidden {
		display: block;
	}
	:global(:root[data-theme='light']) .light-hidden {
		display: none;
	}
</style>
