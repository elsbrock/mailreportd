import { localeFromParam, messages } from '$lib/i18n';
import type { LayoutLoad } from './$types';

export const load: LayoutLoad = ({ params }) => {
	const locale = localeFromParam(params.lang);
	return { locale, t: messages(locale) };
};
