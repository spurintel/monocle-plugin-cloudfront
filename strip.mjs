/**
 * Produces the deployable CloudFront Function from its readable source.
 *
 * Readable `src/function/index.js` is the source of truth. The runtime's hard
 * 10 KB cap is met by dropping comment-only lines, then mangling identifiers
 * (never `handler` or `cf`) without compress, so `await` stays in its own
 * statements. The dashboard matches the leading contract banner.
 */
import { minify_sync } from 'terser';

export const EDGE_CONTRACT_BANNER = '// Monocle edge contract: 2';

export function stripForDeploy(src) {
	const readable = src
		.split('\n')
		.filter((line) => !line.trim().startsWith('//'))
		.map((line) => line.replace(/^[ \t]+/, ''))
		.join('\n')
		.replace(/\n{2,}/g, '\n')
		.trim();
	const result = minify_sync(readable, {
		module: true,
		compress: false,
		mangle: { reserved: ['handler', 'cf', 'crypto'] },
		format: { comments: false },
	});
	if (!result.code) throw new Error('CloudFront Function minify produced no output');
	// The runtime rejects `await` inside call arguments. Mangle-only should not
	// move awaits; fail the build if a future Terser change does.
	if (/[,(]\s*await\b/.test(result.code)) {
		throw new Error('CloudFront Function minify moved `await` into call arguments');
	}
	if (!/\basync function handler\b/.test(result.code)) {
		throw new Error('CloudFront Function minify dropped `async function handler`');
	}
	return `${EDGE_CONTRACT_BANNER}\n${result.code}\n`;
}
