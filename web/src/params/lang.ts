import type { ParamMatcher } from '@sveltejs/kit';
import { defaultLocale, isLocale } from '$lib/i18n';

/**
 * Matches locale prefixes other than the default one. The default locale is
 * served unprefixed, so `/en` deliberately does not match: it would be a second
 * URL serving the same content as `/`.
 */
export const match: ParamMatcher = (param) => isLocale(param) && param !== defaultLocale;
