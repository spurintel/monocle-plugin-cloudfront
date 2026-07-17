import { build } from 'esbuild';
import { copyFileSync, mkdirSync, statSync } from 'node:fs';

// The CloudFront Function is deployed AS-WRITTEN (src/function/index.js): the
// runtime has a hard 10 KB source limit and no module system beyond its own
// built-ins, so bundler wrappers would only burn budget. It is copied verbatim.
const FUNCTION_SRC = 'src/function/index.js';
const FUNCTION_MAX_BYTES = 10240;

mkdirSync('dist/function', { recursive: true });
mkdirSync('dist/lambda', { recursive: true });

const functionSize = statSync(FUNCTION_SRC).size;
if (functionSize > FUNCTION_MAX_BYTES) {
	console.error(
		`CloudFront Function source is ${functionSize} bytes — over the ${FUNCTION_MAX_BYTES}-byte runtime limit.`
	);
	process.exit(1);
}
copyFileSync(FUNCTION_SRC, 'dist/function/index.js');

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
