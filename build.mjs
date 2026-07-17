import { build } from 'esbuild';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';

import { stripForDeploy } from './strip.mjs';

// The CloudFront Function is deployed AS-WRITTEN (src/function/index.js): the
// runtime has a hard 10 KB source limit and no module system beyond its own
// built-ins, so bundler wrappers would only burn budget. It is copied verbatim.
const FUNCTION_SRC = 'src/function/index.js';
const FUNCTION_MAX_BYTES = 10240;

mkdirSync('dist/function', { recursive: true });
mkdirSync('dist/lambda', { recursive: true });

const functionSource = readFileSync(FUNCTION_SRC, 'utf8');

// The CloudFront Functions runtime rejects `await` inside a function call's
// arguments ("await in arguments not supported") — a COMPILE error that bricks
// the whole function at the edge. Node runs `f(a, await g())` fine, so tests
// can't catch it; guard the common comma-arg form at build time (on the SOURCE,
// before stripping) instead.
if (/,\s*await\b/.test(functionSource)) {
	console.error(
		'CloudFront Function has `await` inside call arguments (", await" found). ' +
			'The runtime rejects this — resolve the await into its own statement first.'
	);
	process.exit(1);
}

// Deploy a comment/whitespace-stripped copy (see strip.mjs) so the readable,
// heavily-commented source stays well under the hard 10 KB runtime limit.
const deployed = stripForDeploy(functionSource);
const functionSize = Buffer.byteLength(deployed, 'utf8');
if (functionSize > FUNCTION_MAX_BYTES) {
	console.error(
		`CloudFront Function is ${functionSize} bytes after stripping — over the ${FUNCTION_MAX_BYTES}-byte runtime limit.`
	);
	process.exit(1);
}

writeFileSync('dist/function/index.js', deployed);

// The Lambda@Edge handler bundles to a single CJS file; the dashboard injects
// config.json next to it in the deployment zip at deploy time.
await build({
	entryPoints: ['src/lambda/index.ts'],
	bundle: true,
	platform: 'node',
	target: 'node20',
	format: 'cjs',
	outfile: 'dist/lambda/index.js',
	external: ['./config.json'],
});

console.log(`function: ${functionSize} bytes (limit ${FUNCTION_MAX_BYTES}); lambda: bundled.`);
