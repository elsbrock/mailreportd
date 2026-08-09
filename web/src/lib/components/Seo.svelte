<script lang="ts">
	import { htmlLang, locales, localeUrl, messages, type Locale } from '$lib/i18n';
	import { site } from '$lib/site';

	interface Props {
		locale: Locale;
		path?: string;
	}

	let { locale, path = '/' }: Props = $props();

	const t = $derived(messages(locale));
	const canonical = $derived(localeUrl(site.url, locale, path));
	const ogImage = $derived(site.ogImage[locale]);

	/**
	 * Every locale advertises every other, including itself, and x-default points
	 * at the unprefixed root. Omitting the self-reference or x-default is the
	 * usual way hreflang sets get quietly ignored.
	 */
	const alternates = $derived(
		locales.map((l) => ({ hreflang: htmlLang[l], href: localeUrl(site.url, l, path) }))
	);

	const jsonLd = $derived(
		JSON.stringify({
			'@context': 'https://schema.org',
			'@type': 'SoftwareApplication',
			name: site.name,
			applicationCategory: 'DeveloperApplication',
			applicationSubCategory: 'Email infrastructure monitoring',
			operatingSystem: 'Linux, macOS, BSD',
			softwareVersion: site.version,
			description: t.meta.description,
			url: canonical,
			inLanguage: htmlLang[locale],
			offers: { '@type': 'Offer', price: '0', priceCurrency: 'EUR' },
			featureList: t.capabilities.items.map((item) => item.title)
		})
	);
</script>

<svelte:head>
	<title>{t.meta.title}</title>
	<meta name="description" content={t.meta.description} />
	<link rel="canonical" href={canonical} />

	{#each alternates as alternate (alternate.hreflang)}
		<link rel="alternate" hreflang={alternate.hreflang} href={alternate.href} />
	{/each}
	<link rel="alternate" hreflang="x-default" href={localeUrl(site.url, 'en', path)} />

	<meta property="og:type" content="website" />
	<meta property="og:site_name" content={site.name} />
	<meta property="og:title" content={t.meta.title} />
	<meta property="og:description" content={t.meta.description} />
	<meta property="og:url" content={canonical} />
	<meta property="og:locale" content={locale === 'de' ? 'de_DE' : 'en_US'} />
	<meta property="og:image" content={ogImage} />
	<meta property="og:image:width" content="1200" />
	<meta property="og:image:height" content="630" />
	<meta property="og:image:alt" content={t.meta.ogAlt} />

	<meta name="twitter:card" content="summary_large_image" />
	<meta name="twitter:title" content={t.meta.title} />
	<meta name="twitter:description" content={t.meta.description} />
	<meta name="twitter:image" content={ogImage} />
	<meta name="twitter:image:alt" content={t.meta.ogAlt} />

	{@html `<script type="application/ld+json">${jsonLd}</script>`}
</svelte:head>
