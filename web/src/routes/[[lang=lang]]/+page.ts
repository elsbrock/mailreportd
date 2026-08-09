import { defaultLocale, locales } from '$lib/i18n';
import type { EntryGenerator } from './$types';

/**
 * Declared explicitly rather than left to the crawler, so a locale is still
 * built if nothing on the page happens to link to it.
 */
export const entries: EntryGenerator = () =>
	locales.map((locale) => ({ lang: locale === defaultLocale ? undefined : locale }));
