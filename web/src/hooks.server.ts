import type { Handle } from '@sveltejs/kit';
import { defaultLocale, htmlLang, isLocale } from '$lib/i18n';

/**
 * Sets the document language from the URL. It has to happen here rather than in
 * a component because the attribute lives on <html>, outside the app root, and
 * search engines and screen readers both rely on it being correct in the served
 * markup rather than patched in afterwards.
 */
export const handle: Handle = async ({ event, resolve }) => {
	const segment = event.url.pathname.split('/')[1];
	const locale = isLocale(segment) ? segment : defaultLocale;

	return resolve(event, {
		transformPageChunk: ({ html }) => html.replace('%lang%', htmlLang[locale])
	});
};
