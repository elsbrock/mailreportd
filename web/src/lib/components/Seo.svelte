<script lang="ts">
	import { site } from '$lib/site';

	interface Props {
		path?: string;
	}

	let { path = '/' }: Props = $props();

	const title = 'mailreportd — Prometheus metrics from DMARC and TLS reports';
	const description =
		'A single self-hosted Go binary that reads DMARC aggregate and SMTP TLS reports from an IMAP mailbox and exports Prometheus metrics and a JSON API.';
	const ogAlt = 'mailreportd: DMARC and TLS report metrics for Prometheus';

	/** Mirrors the capability cards on the page. */
	const featureList = [
		'DMARC aggregate reports',
		'SMTP TLS reports',
		'Sender classification from SPF',
		'SPF record health'
	];

	const canonical = $derived(new URL(path, site.url).href);

	const jsonLd = $derived(
		JSON.stringify({
			'@context': 'https://schema.org',
			'@type': 'SoftwareApplication',
			name: site.name,
			applicationCategory: 'DeveloperApplication',
			applicationSubCategory: 'Email infrastructure monitoring',
			operatingSystem: 'Linux, macOS, BSD',
			softwareVersion: site.version,
			description,
			url: canonical,
			inLanguage: 'en',
			offers: { '@type': 'Offer', price: '0', priceCurrency: 'EUR' },
			featureList
		})
	);
</script>

<svelte:head>
	<title>{title}</title>
	<meta name="description" content={description} />
	<link rel="canonical" href={canonical} />

	<meta property="og:type" content="website" />
	<meta property="og:site_name" content={site.name} />
	<meta property="og:title" content={title} />
	<meta property="og:description" content={description} />
	<meta property="og:url" content={canonical} />
	<meta property="og:locale" content="en_US" />
	<meta property="og:image" content={site.ogImage} />
	<meta property="og:image:width" content="1200" />
	<meta property="og:image:height" content="630" />
	<meta property="og:image:alt" content={ogAlt} />

	<meta name="twitter:card" content="summary_large_image" />
	<meta name="twitter:title" content={title} />
	<meta name="twitter:description" content={description} />
	<meta name="twitter:image" content={site.ogImage} />
	<meta name="twitter:image:alt" content={ogAlt} />

	{@html `<script type="application/ld+json">${jsonLd}</script>`}
</svelte:head>
