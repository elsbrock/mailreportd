import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [
		tailwindcss(),
		sveltekit({
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},

			// The site is fully prerendered: it is a landing page with no
			// server-side state, and static output runs on anything that can
			// serve files. That keeps deployment as unopinionated as the daemon
			// the site describes.
			adapter: adapter({
				fallback: undefined,
				precompress: true,
				strict: true
			})
		})
	]
});
