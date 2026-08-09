# mailreportd — landing page

SvelteKit 2 with Svelte 5 runes, Tailwind CSS v4, fully prerendered to static
files. English and German.

```console
$ pnpm install
$ pnpm dev          # http://localhost:5173
$ pnpm check        # svelte-check, must be clean
$ pnpm build        # → build/
$ pnpm preview
```

## Deployment

`pnpm build` emits plain files under `build/`, precompressed with gzip and
brotli. Any static host serves it. There is no server component.

Set the origin at build time — it is baked into canonical links, hreflang
alternates, the sitemap and `robots.txt`:

```console
$ PUBLIC_SITE_URL=https://example.org pnpm build
```

The default is `https://mailreportd.iodev.org`.

## Localisation

`src/lib/i18n/en.ts` is the source of truth. Its shape becomes the `Messages`
type, and `de.ts` is annotated with it — so a missing or misspelled key fails
`pnpm check` rather than rendering `undefined` in production.

Adding a locale means: add the catalogue, add the code to `locales` in
`src/lib/i18n/index.ts`, and add an Open Graph image at `static/og.<code>.png`.
Routing, `hreflang`, the sitemap and the language switcher all derive from that
list.

The default locale is served unprefixed (`/`), every other locale is prefixed
(`/de`). The param matcher in `src/params/lang.ts` deliberately rejects `/en`,
which would otherwise be a second URL serving identical content.

## SEO

- per-locale `<title>`, description, canonical
- `hreflang` alternates including a self-reference and `x-default`
- Open Graph and Twitter cards, with a per-locale social image
- `SoftwareApplication` JSON-LD
- generated `sitemap.xml` and `robots.txt`, both derived from the same origin
  and locale list so they cannot drift
- `<html lang>` set per locale in `hooks.server.ts`, in the served markup rather
  than patched in after hydration

## Theming

`src/app.css` defines the full light palette on bare `:root`, then redefines the
same token names for dark twice: once under `prefers-color-scheme` guarded by
`:not([data-theme='light'])`, and once under `[data-theme='dark']` so the toggle
wins in both directions. No component names a raw colour.

A small inline script in `app.html` applies a stored preference before first
paint, so a chosen theme never flashes the wrong one.

## Regenerating the social images

The cards are rendered from HTML with headless Chromium at 1200×630. The source
is not checked in; regenerate with any HTML-to-PNG path you prefer and drop the
result at `static/og.png` and `static/og.de.png`.

## Not done

The site is not wired into the repository's Nix flake. Packaging a pnpm project
reproducibly needs `pnpm.fetchDeps` and a lockfile hash, which is worth doing
when the site actually gets deployed rather than now.
