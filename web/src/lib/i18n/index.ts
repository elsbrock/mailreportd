import { de } from './de';
import { en, type Messages } from './en';

export type { Messages };

/**
 * The first locale is the default. It lives at the site root and is what
 * `hreflang="x-default"` points at, so changing this order changes the canonical
 * URL of the whole site.
 */
export const locales = ['en', 'de'] as const;
export type Locale = (typeof locales)[number];

export const defaultLocale: Locale = 'en';

const catalogues: Record<Locale, Messages> = { en, de };

/** BCP 47 tags for `lang` attributes and `hreflang`. */
export const htmlLang: Record<Locale, string> = { en: 'en', de: 'de' };

export function isLocale(value: string | undefined): value is Locale {
	return value !== undefined && (locales as readonly string[]).includes(value);
}

export function messages(locale: Locale): Messages {
	return catalogues[locale];
}

/**
 * Resolves the locale from an optional route parameter. The default locale has
 * no prefix, so an absent parameter is not an error.
 */
export function localeFromParam(param: string | undefined): Locale {
	return isLocale(param) ? param : defaultLocale;
}

/**
 * Builds a path for a locale. The default locale is unprefixed so that the
 * canonical URL of the site is `/` rather than `/en/`, which avoids having two
 * URLs that serve identical content.
 */
export function localePath(locale: Locale, path = '/'): string {
	const clean = path === '/' ? '' : path.replace(/\/+$/, '');
	if (locale === defaultLocale) {
		return clean === '' ? '/' : clean;
	}
	return `/${locale}${clean}`;
}

/** Absolute URL for a locale, used for canonical links and alternates. */
export function localeUrl(origin: string, locale: Locale, path = '/'): string {
	return new URL(localePath(locale, path), origin).href;
}
