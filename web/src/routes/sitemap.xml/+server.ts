import { htmlLang, locales, localeUrl } from '$lib/i18n';
import { site } from '$lib/site';

export const prerender = true;

/** Every page of the site, unprefixed for the default locale. */
const paths = ['/'];

export function GET() {
	const urls = paths
		.flatMap((path) =>
			locales.map((locale) => {
				// Each URL lists the full alternate set, which is what tells a
				// crawler the pages are translations rather than duplicates.
				const alternates = locales
					.map(
						(other) =>
							`\t\t<xhtml:link rel="alternate" hreflang="${htmlLang[other]}" href="${localeUrl(site.url, other, path)}" />`
					)
					.concat(
						`\t\t<xhtml:link rel="alternate" hreflang="x-default" href="${localeUrl(site.url, 'en', path)}" />`
					)
					.join('\n');

				return `\t<url>\n\t\t<loc>${localeUrl(site.url, locale, path)}</loc>\n${alternates}\n\t\t<changefreq>monthly</changefreq>\n\t\t<priority>${path === '/' ? '1.0' : '0.7'}</priority>\n\t</url>`;
			})
		)
		.join('\n');

	const body = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">
${urls}
</urlset>
`;

	return new Response(body, {
		headers: {
			'Content-Type': 'application/xml',
			'Cache-Control': 'max-age=0, s-maxage=3600'
		}
	});
}
