import { build } from 'esbuild';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';

import { EDGE_CONTRACT_BANNER, stripForDeploy } from './strip.mjs';

// The CloudFront Function is not bundled: the runtime has a hard 10 KB source
// limit and no module system beyond its own built-ins, so bundler wrappers would
// only burn budget. strip.mjs minifies src/function/index.js on its own.
const FUNCTION_SRC = 'src/function/index.js';
const FUNCTION_MAX_BYTES = 10240;

mkdirSync('dist/function', { recursive: true });
mkdirSync('dist/lambda', { recursive: true });

const functionSource = readFileSync(FUNCTION_SRC, 'utf8');

// Deploy a minified copy (see strip.mjs), which also refuses an `await` inside
// call arguments, so the readable, heavily-commented source stays well under the
// hard 10 KB runtime limit.
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
	target: 'node24',
	format: 'cjs',
	outfile: 'dist/lambda/index.js',
	external: ['./config.json'],
	banner: { js: `${EDGE_CONTRACT_BANNER}\n` },
});

const lambdaSource = readFileSync('dist/lambda/index.js', 'utf8');
if (!lambdaSource.includes('SignatureV4a')) {
	console.error(
		'Lambda bundle is missing the SigV4A signer; CloudFront KVS reads will 503 at the edge. ' +
			'Keep the `@aws-sdk/signature-v4a` side-effect import in src/lambda/kvs.ts.',
	);
	process.exit(1);
}

console.log(`function: ${functionSize} bytes (limit ${FUNCTION_MAX_BYTES}); lambda: bundled.`);
