import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { mintCookieValue } from '../src/shared/cookies';

const SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const FUNCTION_PATH = join(__dirname, '../src/function/index.js');
const source = readFileSync(FUNCTION_PATH, 'utf8');

/**
 * Loads the CloudFront Function into Node for testing: strips the runtime-only
 * `import cf from 'cloudfront'` line, injects a KVS stub, and maps require()
 * to Node's (the function only requires 'crypto', which Node provides with the
 * same createHmac surface the CF runtime documents).
 */
function loadHandler(kv: Record<string, string>) {
	const stripped = source.replace(/^import cf from 'cloudfront';/m, '');
	const cfStub = {
		kvs: () => ({
			get: async (key: string) => {
				if (key in kv) return kv[key];
				throw new Error(`KeyNotFound: ${key}`);
			},
		}),
	};
	const factory = new Function('cf', 'require', `${stripped}\nreturn handler;`);
	return factory(cfStub, createRequire(import.meta.url)) as (event: unknown) => Promise<unknown>;
}

function viewerEvent(overrides: {
	uri?: string;
	host?: string;
	ip?: string;
	cookie?: string;
}) {
	return {
		request: {
			method: 'GET',
			uri: overrides.uri ?? '/account',
			headers: { host: { value: overrides.host ?? 'www.example.com' } },
			cookies: overrides.cookie ? { MCLVALID: { value: overrides.cookie } } : {},
		},
		viewer: { ip: overrides.ip ?? '203.0.113.9' },
	};
}

const BASE_KV = {
	cookieSecret: SECRET,
	publishableKey: 'pk_live_123',
	protectedPaths: JSON.stringify({ 'www.example.com': ['/account*', '/login*'] }),
};

type FnResponse = {
	statusCode?: number;
	headers?: Record<string, { value: string }>;
	body?: string;
	// pass-through returns the request object instead
	uri?: string;
};

describe('CloudFront Function (viewer-request)', () => {
	it('stays under the 10 KB runtime source limit with headroom', () => {
		const size = Buffer.byteLength(source, 'utf8');
		expect(size).toBeLessThan(10240);
	});

	it('passes a request with a valid Lambda-minted cookie through untouched (cross-implementation pin)', async () => {
		const handler = loadHandler(BASE_KV);
		const cookie = mintCookieValue('203.0.113.9', SECRET);
		const event = viewerEvent({ cookie });
		const result = (await handler(event)) as FnResponse;
		// Pass-through returns the request object itself.
		expect(result).toBe(event.request);
	});

	it('challenges an unverified request on a protected path with a no-store interstitial', async () => {
		const handler = loadHandler(BASE_KV);
		const result = (await handler(viewerEvent({}))) as FnResponse;
		expect(result.statusCode).toBe(200);
		expect(result.headers?.['cache-control']?.value).toContain('no-store');
		expect(result.body).toContain('mcl.js?tk=pk_live_123');
		expect(result.body).toContain('/__mcl/verify');
	});

	it('rejects a tampered cookie and challenges', async () => {
		const handler = loadHandler(BASE_KV);
		const cookie = mintCookieValue('203.0.113.9', SECRET);
		const [payloadHex] = cookie.split('.');
		const forged = `${payloadHex}.${'0'.repeat(64)}`;
		const result = (await handler(viewerEvent({ cookie: forged }))) as FnResponse;
		expect(result.statusCode).toBe(200);
	});

	it('rejects a valid cookie presented from a different IP', async () => {
		const handler = loadHandler(BASE_KV);
		const cookie = mintCookieValue('203.0.113.9', SECRET);
		const result = (await handler(viewerEvent({ cookie, ip: '198.51.100.1' }))) as FnResponse;
		expect(result.statusCode).toBe(200);
	});

	it('passes unprotected paths through without a cookie', async () => {
		const handler = loadHandler(BASE_KV);
		const event = viewerEvent({ uri: '/about' });
		expect(await handler(event)).toBe(event.request);
	});

	it('never intercepts the verify endpoint', async () => {
		const handler = loadHandler(BASE_KV);
		const event = viewerEvent({ uri: '/__mcl/verify' });
		expect(await handler(event)).toBe(event.request);
	});

	it('fails OPEN (passes through, never 503s) if acquiring the KVS handle throws', async () => {
		// Simulate cf.kvs() itself throwing — the module-init hazard that caused a
		// live 503. The handler must swallow it and return the request untouched.
		const stripped = source.replace(/^import cf from 'cloudfront';/m, '');
		const cfStub = {
			kvs: () => {
				throw new Error('no key value store associated');
			},
		};
		const factory = new Function('cf', 'require', `${stripped}\nreturn handler;`);
		const handler = factory(cfStub, createRequire(import.meta.url)) as (
			event: unknown,
		) => Promise<unknown>;
		const event = viewerEvent({ uri: '/account' });
		expect(await handler(event)).toBe(event.request);
	});

	it('fails SAFE (challenges everything) when protectedPaths is missing or corrupt', async () => {
		for (const kv of [
			{ cookieSecret: SECRET, publishableKey: 'pk' },
			{ ...BASE_KV, protectedPaths: '{not json' },
		]) {
			const handler = loadHandler(kv as Record<string, string>);
			const result = (await handler(viewerEvent({ uri: '/anything' }))) as FnResponse;
			expect(result.statusCode).toBe(200);
		}
	});

	it('concatenates chunked protectedPaths continuation keys', async () => {
		const json = JSON.stringify({ 'www.example.com': ['/account*'] });
		const split = Math.floor(json.length / 2);
		const handler = loadHandler({
			cookieSecret: SECRET,
			publishableKey: 'pk',
			protectedPaths: json.slice(0, split),
			'protectedPaths.1': json.slice(split),
		});
		const protectedResult = (await handler(viewerEvent({ uri: '/account' }))) as FnResponse;
		expect(protectedResult.statusCode).toBe(200);
		const openEvent = viewerEvent({ uri: '/about' });
		expect(await handler(openEvent)).toBe(openEvent.request);
	});

	it('challenges (fails safe) when the cookie secret key is missing entirely', async () => {
		const handler = loadHandler({ publishableKey: 'pk', protectedPaths: BASE_KV.protectedPaths });
		const cookie = mintCookieValue('203.0.113.9', SECRET);
		const result = (await handler(viewerEvent({ cookie }))) as FnResponse;
		expect(result.statusCode).toBe(200);
	});

	it('percent-encoded and re-cased paths cannot evade protection', async () => {
		const handler = loadHandler(BASE_KV);
		const result = (await handler(viewerEvent({ uri: '/%61ccount' }))) as FnResponse;
		expect(result.statusCode).toBe(200);
		const upper = (await handler(viewerEvent({ uri: '/ACCOUNT' }))) as FnResponse;
		expect(upper.statusCode).toBe(200);
	});
});
