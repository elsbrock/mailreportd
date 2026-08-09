<script lang="ts">
	import { page } from '$app/state';
	import { htmlLang, localePath, locales, messages, type Locale } from '$lib/i18n';

	interface Props {
		current: Locale;
		label: string;
	}

	let { current, label }: Props = $props();

	// The switch keeps the visitor on the page they are reading. With a single
	// page that is trivially the root, but the derivation is what makes adding a
	// second page a non-event.
	const currentPath = $derived.by(() => {
		const segment = page.url.pathname.split('/')[1];
		const isLocaleSegment = (locales as readonly string[]).includes(segment);
		const rest = isLocaleSegment ? `/${page.url.pathname.split('/').slice(2).join('/')}` : page.url.pathname;
		return rest.replace(/\/+$/, '') || '/';
	});
</script>

<nav class="flex items-center gap-0.5 rounded-lg border border-line p-0.5" aria-label={label}>
	{#each locales as locale (locale)}
		{@const active = locale === current}
		<a
			href={localePath(locale, currentPath)}
			hreflang={htmlLang[locale]}
			lang={htmlLang[locale]}
			aria-current={active ? 'true' : undefined}
			data-sveltekit-reload
			class="rounded-md px-2 py-1 text-xs font-medium uppercase tracking-wide transition-colors
				{active ? 'bg-surface-sunken text-ink' : 'text-ink-faint hover:text-ink'}"
			title={messages(locale).meta.localeName}
		>
			{locale}
			<span class="sr-only">— {messages(locale).meta.localeName}</span>
		</a>
	{/each}
</nav>
