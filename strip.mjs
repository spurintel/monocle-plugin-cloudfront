/**
 * Produces the deployable CloudFront Function from its readable source.
 *
 * Readable `src/function/index.js` is the source of truth. The runtime's hard
 * 10 KB cap is met by minifying it: comments and whitespace go, and identifiers
 * are mangled (never `handler`, `cf` or `crypto`) without compress, so every
 * statement stays as written. The dashboard matches the leading contract banner.
 */
import { parse } from 'acorn';
import { minify_sync } from 'terser';

export const EDGE_CONTRACT_BANNER = '// Monocle edge contract: 2';

/**
 * Whether an `await` sits anywhere inside a call's arguments, `f(await g())` or
 * `f(a + await g())` alike. The Functions runtime refuses to compile one, and Node
 * runs it fine, so no test would notice. An async function passed as an argument
 * is a scope of its own.
 */
export function awaitInArguments(code) {
	let found = false;
	const walk = (node, inArguments) => {
		if (found || !node || typeof node.type !== 'string') return;
		if (node.type === 'AwaitExpression' && inArguments) {
			found = true;
			return;
		}
		const outer = /Function/.test(node.type) ? false : inArguments;
		const call = node.type === 'CallExpression' || node.type === 'NewExpression';
		for (const [key, child] of Object.entries(node)) {
			for (const next of Array.isArray(child) ? child : [child])
				if (next && typeof next === 'object') walk(next, outer || (call && key === 'arguments'));
		}
	};
	walk(parse(code, { ecmaVersion: 'latest', sourceType: 'module' }), false);
	return found;
}

export function stripForDeploy(src) {
	const result = minify_sync(src, {
		module: true,
		compress: false,
		mangle: { reserved: ['handler', 'cf', 'crypto'] },
		format: { comments: false },
	});
	if (!result.code) throw new Error('CloudFront Function minify produced no output');
	if (awaitInArguments(result.code)) {
		throw new Error(
			'CloudFront Function has `await` inside call arguments, which the runtime rejects. ' +
				'Resolve the await into its own statement first.'
		);
	}
	if (!/\basync function handler\b/.test(result.code)) {
		throw new Error('CloudFront Function minify dropped `async function handler`');
	}
	return `${EDGE_CONTRACT_BANNER}\n${result.code}\n`;
}
