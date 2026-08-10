import { site } from '$lib/site';

export const prerender = true;

/** Every page of the site. */
const paths = ['/'];

export function GET() {
	const urls = paths
		.map((path) => {
			const loc = new URL(path, site.url).href;
			const priority = path === '/' ? '1.0' : '0.7';
			return `\t<url>\n\t\t<loc>${loc}</loc>\n\t\t<changefreq>monthly</changefreq>\n\t\t<priority>${priority}</priority>\n\t</url>`;
		})
		.join('\n');

	const body = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
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
