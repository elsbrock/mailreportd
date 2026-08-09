import { site } from '$lib/site';

export const prerender = true;

// Generated rather than kept as a static file so the sitemap URL cannot drift
// away from the configured origin.
export function GET() {
	const body = `User-agent: *
Allow: /

Sitemap: ${site.url}/sitemap.xml
`;

	return new Response(body, { headers: { 'Content-Type': 'text/plain' } });
}
