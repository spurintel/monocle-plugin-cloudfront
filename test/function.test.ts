import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';

import {
	bindingForm,
	COOKIE_SCOPE,
	mintVerdictCookie,
	packCidrSet,
} from '@spur.us/monocle-edge-core';
import { describe, expect, it } from 'vitest';

import { createHmacSealer } from '../src/shared/hmac-sealer';
// @ts-expect-error strip.mjs is untyped
import { EDGE_CONTRACT_BANNER, stripForDeploy } from '../strip.mjs';

const SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const PREV = 'ff'.repeat(32);
const CV = 'ab'.repeat(32);
const ID = 'deploy-1';
const HOST = 'www.example.com';
const DISTRIBUTION_DOMAIN = 'd111111abcdef8.cloudfront.net';
const IP = '203.0.113.9';
const FUNCTION_PATH = join(__dirname, '../src/function/index.js');
const source = readFileSync(FUNCTION_PATH, 'utf8');
const pathsCorpus = JSON.parse(
	readFileSync(
		join(__dirname, '../node_modules/@spur.us/monocle-edge-core/conformance/paths.v3.json'),
		'utf8'
	)
) as { vectors: { name: string; input: string; reject?: boolean }[] };

function loadHandler(kv: Record<string, string>) {
	const deployed = stripForDeploy(source);
	const body = deployed
		.replace(/^\/\/ Monocle edge contract: 2\n/, '')
		.replace(/^import cf from["']cloudfront["'];/, '');
	const cfStub = {
		kvs: () => ({
			get: async (key: string) => {
				if (key in kv) return kv[key];
				throw new Error(`KeyNotFound: ${key}`);
			},
		}),
	};
	const factory = new Function('cf', 'require', `${body}\nreturn handler;`);
	return factory(cfStub, createRequire(import.meta.url)) as (event: unknown) => Promise<unknown>;
}

function baseKv(extra: Record<string, string> = {}): Record<string, string> {
	return {
		v: '2',
		k: SECRET,
		cv: CV,
		id: ID,
		hosts: JSON.stringify([HOST]),
		's:/': 'a',
		...extra,
	};
}

function viewerEvent(overrides: {
	uri?: string;
	host?: string;
	ip?: string;
	cookie?: string;
	method?: string;
	secFetchMode?: string;
	accept?: string;
	upgrade?: string;
	cookies?: Record<string, { value: string; multiValue?: { value: string }[] }>;
} = {}) {
	const headers: Record<string, { value: string }> = {
		host: { value: overrides.host ?? HOST },
	};
	if (overrides.secFetchMode !== undefined) headers['sec-fetch-mode'] = { value: overrides.secFetchMode };
	else headers['sec-fetch-mode'] = { value: 'navigate' };
	if (overrides.accept) headers.accept = { value: overrides.accept };
	if (overrides.upgrade) headers.upgrade = { value: overrides.upgrade };
	return {
		request: {
			method: overrides.method ?? 'GET',
			uri: overrides.uri ?? '/page',
			querystring: {},
			headers,
			cookies: overrides.cookies
				? overrides.cookies
				: overrides.cookie
					? { [COOKIE_SCOPE.names.verdict]: { value: overrides.cookie } }
					: {},
		},
		viewer: { ip: overrides.ip ?? IP },
		context: { distributionDomainName: DISTRIBUTION_DOMAIN },
	};
}

async function mintCookie(ip = IP, verdict: 'allow' | 'block' = 'allow', key = SECRET) {
	const binding = bindingForm(ip);
	if (!binding) throw new Error('unbindable');
	const minted = await mintVerdictCookie({
		sealer: createHmacSealer(key),
		audience: ID,
		scope: COOKIE_SCOPE,
		ipBinding: binding,
		verdict,
		sid: 'sid-1',
		jti: 'jti-1',
		nowSeconds: Math.floor(Date.now() / 1000),
		clearanceVersion: CV,
	});
	return minted.setCookie.split(';')[0]!.slice(`${COOKIE_SCOPE.names.verdict}=`.length);
}

type FnResponse = {
	statusCode?: number;
	headers?: Record<string, { value: string }>;
	body?: string;
	uri?: string;
};

describe('CloudFront Function (viewer-request)', () => {
	it('stays under the 10 KB runtime limit once stripped for deploy', () => {
		const deployed = stripForDeploy(source);
		const size = Buffer.byteLength(deployed, 'utf8');
		expect(size).toBeLessThan(10240);
		expect(deployed.startsWith(`${EDGE_CONTRACT_BANNER}\n`)).toBe(true);
		expect(deployed).toContain('async function handler');
	});

	it('passes /__mcl and descendants untouched', async () => {
		const handler = loadHandler(baseKv());
		for (const uri of ['/__mcl', '/__mcl/verify', '/__mcl/challenge', '/__mcl/abc/mcl.js']) {
			const event = viewerEvent({ uri });
			expect(await handler(event)).toBe(event.request);
		}
	});

	it('fails open when the sealing key or contract version is missing', async () => {
		const noKey = { ...baseKv() };
		delete noKey.k;
		const event = viewerEvent();
		expect(await loadHandler(noKey)(event)).toBe(event.request);
		const old = viewerEvent();
		expect(await loadHandler(baseKv({ v: '1' }))(old)).toBe(old.request);
	});

	// Without id or cv no cookie can be opened, so a challenge could never be
	// passed and a refusal would hit every visitor rather than the ones the policy
	// flags. The request passes, marked, on assessed and enforced routes alike.
	it('passes every route, marked, when the cookie audience or clearance version is missing', async () => {
		for (const missing of ['id', 'cv'] as const) {
			for (const uri of ['/products', '/account']) {
				const kv = { ...baseKv({ 'p:/account': 'e' }) };
				delete kv[missing];
				const event = viewerEvent({ uri }) as {
					request: { headers: Record<string, { value: string }> };
				};
				expect(await loadHandler(kv)(event)).toBe(event.request);
				expect(event.request.headers['x-monocle-skip']?.value).toBe('no-config');
			}
		}
	});

	// A distribution is a site, so a deployment that names no hostname means every
	// name it answers on - including one added years after setup.
	it('protects every hostname the distribution serves when none are named', async () => {
		for (const host of ['www.example.com', 'shop.example.com', DISTRIBUTION_DOMAIN]) {
			const result = (await loadHandler({ ...baseKv(), hosts: '[]' })(
				viewerEvent({ host })
			)) as FnResponse;
			expect(result.statusCode).toBe(503);
		}
	});

	// Absent is a broken store, not a deployment choosing everything.
	it('passes through when the host list is missing entirely', async () => {
		const kv = { ...baseKv() };
		delete kv.hosts;
		const event = viewerEvent();
		expect(await loadHandler(kv)(event)).toBe(event.request);
	});

	// Anyone can reach an alias deployment by its *.cloudfront.net name. Passing
	// that through would make Monocle optional for whoever knows the domain.
	it("protects the distribution's own domain as well as the configured host", async () => {
		const result = (await loadHandler(baseKv())(
			viewerEvent({ host: DISTRIBUTION_DOMAIN })
		)) as FnResponse;
		expect(result.statusCode).toBe(503);
		expect(result.body).toContain('/__mcl/challenge?return=');
	});

	it('passes unlisted hosts untouched', async () => {
		const event = viewerEvent({ host: 'other.example.com' });
		expect(await loadHandler(baseKv())(event)).toBe(event.request);
	});

	it('challenges a cookieless assessed navigation with a 503 shell', async () => {
		const result = (await loadHandler(baseKv())(viewerEvent())) as FnResponse;
		expect(result.statusCode).toBe(503);
		expect(result.headers?.['cache-control']?.value).toBe('no-store');
		expect(result.headers?.['retry-after']?.value).toBe('5');
		expect(result.body).toContain('/__mcl/challenge?return=');
		expect(result.body).toContain('location.replace');
	});

	it('passes an assessed non-navigation without a cookie', async () => {
		const event = viewerEvent({ secFetchMode: 'cors' });
		expect(await loadHandler(baseKv())(event)).toBe(event.request);
	});

	it('passes a Lambda-minted allow cookie through on an enforce path', async () => {
		const cookie = await mintCookie();
		const event = viewerEvent({ uri: '/account', cookie });
		const kv = baseKv({ 'p:/account': 'e' });
		expect(await loadHandler(kv)(event)).toBe(event.request);
	});

	it('rejects a tampered cookie and challenges', async () => {
		const cookie = await mintCookie();
		const [pt] = cookie.split('.');
		const forged = `${pt}.${'A'.repeat(43)}`;
		const result = (await loadHandler(baseKv({ 'p:/page': 'e' }))(
			viewerEvent({ cookie: forged })
		)) as FnResponse;
		expect(result.statusCode).toBe(503);
	});

	it('rejects a valid cookie presented from a different IP', async () => {
		const cookie = await mintCookie(IP);
		const result = (await loadHandler(baseKv({ 'p:/page': 'e' }))(
			viewerEvent({ cookie, ip: '198.51.100.1' })
		)) as FnResponse;
		expect(result.statusCode).toBe(503);
	});

	// A cookie the store's key cannot open carries no verdict, so an enforced path
	// challenges rather than passing it through.
	it('refuses a cookie sealed with a key the store does not hold', async () => {
		const cookie = await mintCookie(IP, 'allow', PREV);
		const event = viewerEvent({ uri: '/account', cookie });
		const result = (await loadHandler(baseKv({ 'p:/account': 'e' }))(event)) as FnResponse;
		expect(result.statusCode).toBe(503);
	});

	it('answers a block verdict on a navigation with the blocked shell', async () => {
		const cookie = await mintCookie(IP, 'block');
		const result = (await loadHandler(baseKv({ 'p:/page': 'e' }))(
			viewerEvent({ cookie })
		)) as FnResponse;
		expect(result.statusCode).toBe(403);
		expect(result.body).toContain('/__mcl/blocked');
	});

	it('passes uncovered paths without a cookie', async () => {
		const kv = { ...baseKv() };
		delete kv['s:/'];
		const event = viewerEvent({ uri: '/about' });
		expect(await loadHandler(kv)(event)).toBe(event.request);
	});

	it('fails open if acquiring the KVS handle throws', async () => {
		const deployed = stripForDeploy(source)
			.replace(/^\/\/ Monocle edge contract: 2\n/, '')
			.replace(/^import cf from["']cloudfront["'];/, '');
		const cfStub = {
			kvs: () => {
				throw new Error('no key value store associated');
			},
		};
		const factory = new Function('cf', 'require', `${deployed}\nreturn handler;`);
		const handler = factory(cfStub, createRequire(import.meta.url)) as (
			event: unknown
		) => Promise<unknown>;
		const event = viewerEvent();
		expect(await handler(event)).toBe(event.request);
	});

	it('concatenates chunked hosts continuation keys', async () => {
		const json = JSON.stringify([HOST]);
		const split = Math.floor(json.length / 2);
		const kv = baseKv({
			hosts: json.slice(0, split),
			'hosts.1': json.slice(split),
		});
		const result = (await loadHandler(kv)(viewerEvent())) as FnResponse;
		expect(result.statusCode).toBe(503);
		const other = viewerEvent({ host: 'nope.example.com' });
		expect(await loadHandler(kv)(other)).toBe(other.request);
	});

	it('exempts a packed allow_ips hit on an enforce path', async () => {
		const packed = packCidrSet(['203.0.113.0/24']);
		const event = viewerEvent({ uri: '/account' });
		expect(
			await loadHandler(baseKv({ 'p:/account': 'e', ips: JSON.stringify(packed) }))(event)
		).toBe(event.request);
	});

	it('exempts a packed crawler on a safe method and ignores an expired snapshot', async () => {
		const packed = packCidrSet([IP]);
		const live = { ...packed, expiresAt: Math.floor(Date.now() / 1000) + 3600 };
		const event = viewerEvent({ uri: '/account' });
		expect(
			await loadHandler(baseKv({ 'p:/account': 'e', bots: JSON.stringify(live) }))(event)
		).toBe(event.request);
		const expired = { ...packed, expiresAt: Math.floor(Date.now() / 1000) - 10 };
		const challenged = (await loadHandler(
			baseKv({ 'p:/account': 'e', bots: JSON.stringify(expired) })
		)(event)) as FnResponse;
		expect(challenged.statusCode).toBe(503);
	});

	it('passes OPTIONS and infrastructure paths on assessed routes', async () => {
		const handler = loadHandler(baseKv());
		const options = viewerEvent({ method: 'OPTIONS' });
		expect(await handler(options)).toBe(options.request);
		const robots = viewerEvent({ uri: '/robots.txt' });
		expect(await handler(robots)).toBe(robots.request);
	});

	it('does not exempt a crawler WebSocket', async () => {
		const packed = packCidrSet([IP]);
		const result = (await loadHandler(
			baseKv({ 'p:/page': 'e', bots: JSON.stringify({ ...packed, expiresAt: Math.floor(Date.now() / 1000) + 3600 }) })
		)(viewerEvent({ upgrade: 'websocket' }))) as FnResponse;
		expect(result.statusCode).toBe(403);
		expect(result.body).toBeUndefined();
	});

	it('passes enforced traffic when the breaker is open', async () => {
		const event = viewerEvent({ uri: '/account' });
		const result = (await loadHandler(
			baseKv({ 'p:/account': 'e', brk: String(Math.floor(Date.now() / 1000) + 60) })
		)(event)) as { headers?: Record<string, { value: string }>; uri?: string };
		expect(result).toBe(event.request);
		expect(event.request.headers['x-monocle-degraded']?.value).toBe('1');
	});

	it('matches a wildcard-segment enforce pattern from w', async () => {
		const result = (await loadHandler(
			baseKv({
				w: JSON.stringify([{ p: '/shop/*/checkout', e: true }]),
			})
		)(viewerEvent({ uri: '/shop/sku/checkout' }))) as FnResponse;
		expect(result.statusCode).toBe(503);
	});

	it('rejects duplicate verdict cookies', async () => {
		const cookie = await mintCookie();
		const result = (await loadHandler(baseKv({ 'p:/page': 'e' }))(
			viewerEvent({
				cookies: {
					[COOKIE_SCOPE.names.verdict]: {
						value: cookie,
						multiValue: [{ value: cookie }, { value: cookie }],
					},
				},
			})
		)) as FnResponse;
		expect(result.statusCode).toBe(503);
	});

	it('pins IPv6 /64 binding against edge-core', async () => {
		const ip = '2001:db8:1:2:3:4:5:6';
		const cookie = await mintCookie(ip);
		const event = viewerEvent({ uri: '/account', cookie, ip });
		expect(await loadHandler(baseKv({ 'p:/account': 'e' }))(event)).toBe(event.request);
		const other = viewerEvent({
			uri: '/account',
			cookie,
			ip: '2001:db8:1:3::1',
		});
		const result = (await loadHandler(baseKv({ 'p:/account': 'e' }))(other)) as FnResponse;
		expect(result.statusCode).toBe(503);
	});

	it('keeps enforcement when an assessed exact path sits inside an enforced section', async () => {
		const handler = loadHandler(baseKv({ 's:/account': 'e', 'p:/account/help': 'a' }));
		const post = (await handler(
			viewerEvent({ uri: '/account/help', method: 'POST', secFetchMode: 'cors' })
		)) as FnResponse;
		expect(post.statusCode).toBe(403);
		expect(post.headers?.['x-monocle-challenge-required']?.value).toBe('1');
		const blocked = (await handler(
			viewerEvent({ uri: '/account/help', cookie: await mintCookie(IP, 'block') })
		)) as FnResponse;
		expect(blocked.statusCode).toBe(403);
		expect(blocked.body).toContain('/__mcl/blocked');
	});

	it('reads wildcard patterns across continuation keys', async () => {
		const list = Array.from({ length: 60 }, (_, i) => ({ p: `/section${i}/*/edit`, e: true }));
		const json = JSON.stringify(list);
		const kv: Record<string, string> = {};
		for (let i = 0, n = 0; i < json.length; i += 1024, n++) kv[n === 0 ? 'w' : `w.${n}`] = json.slice(i, i + 1024);
		expect(Object.keys(kv).length).toBeGreaterThan(1);
		const handler = loadHandler(baseKv(kv));
		const result = (await handler(
			viewerEvent({ uri: '/section59/abc/edit', method: 'POST', secFetchMode: 'cors' })
		)) as FnResponse;
		expect(result.statusCode).toBe(403);
	});

	it('honours the configured block status from a chunked cfg, on pages and JSON alike', async () => {
		const cfg = JSON.stringify({
			session_tracking: 'off',
			block_page: { title: 'x'.repeat(600), message: 'y'.repeat(600), status: 404 },
		});
		const handler = loadHandler(
			baseKv({ 'p:/checkout': 'e', cfg: cfg.slice(0, 1024), 'cfg.1': cfg.slice(1024) })
		);
		const cookie = await mintCookie(IP, 'block');
		const page = (await handler(viewerEvent({ uri: '/checkout', cookie }))) as FnResponse;
		expect(page.statusCode).toBe(404);
		const json = (await handler(
			viewerEvent({ uri: '/checkout', cookie, secFetchMode: 'cors' })
		)) as FnResponse;
		expect(json.statusCode).toBe(404);
		expect(json.headers?.['x-monocle-blocked']?.value).toBe('1');
	});

	it('sends a cookieless POST navigation to the resubmit page, not the challenge', async () => {
		const handler = loadHandler(baseKv({ 'p:/checkout': 'e' }));
		const result = (await handler(viewerEvent({ uri: '/checkout', method: 'POST' }))) as FnResponse;
		expect(result.statusCode).toBe(403);
		expect(result.body).toContain('/__mcl/resubmit');
		expect(result.body).not.toContain('/__mcl/challenge');
	});

	it('answers a differently-cased reserved path at the edge rather than the origin', async () => {
		const handler = loadHandler(baseKv());
		const result = (await handler(viewerEvent({ uri: '/__MCL/state' }))) as FnResponse;
		expect(result.statusCode).toBe(404);
	});

	it('returns 400 for the strict-v3 reject corpus and challenges valid paths', async () => {
		const handler = loadHandler(baseKv());
		for (const vector of pathsCorpus.vectors) {
			const event = viewerEvent({ uri: vector.input });
			const result = (await handler(event)) as FnResponse;
			if (vector.reject) {
				expect(result.statusCode, vector.name).toBe(400);
			} else {
				expect(result.statusCode ?? 0, vector.name).not.toBe(400);
			}
		}
	});
});
