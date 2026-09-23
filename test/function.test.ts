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

import { createHmacSealer } from '@spur.us/monocle-edge-core';
// @ts-expect-error strip.mjs is untyped
import { awaitInArguments, EDGE_CONTRACT_BANNER, stripForDeploy } from '../strip.mjs';

const SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const PREV = 'ff'.repeat(32);
const CV = 'ab'.repeat(32);
const ID = 'deploy-1';
const HOST = 'www.example.com';
const DISTRIBUTION_DOMAIN = 'd111111abcdef8.cloudfront.net';
const IP = '203.0.113.9';
const FUNCTION_PATH = join(__dirname, '../src/function/index.js');
const source = readFileSync(FUNCTION_PATH, 'utf8');
const corpus = (name: string) =>
	JSON.parse(
		readFileSync(join(__dirname, `../node_modules/@spur.us/monocle-edge-core/conformance/${name}`), 'utf8')
	);
const pathsCorpus = corpus('paths.v3.json') as {
	vectors: { name: string; input: string; canonical?: string; reject?: boolean }[];
};
const readingsCorpus = corpus('readings.v1.json') as {
	vectors: { name: string; input: string; readings?: string[]; reject?: boolean }[];
};

/** The readable source's own `readings`, which the deploy build renames. */
function loadReadings(): (path: string) => string[] {
	const body = source.replace(/^import cf from ["']cloudfront["'];?\n/, '');
	const factory = new Function('cf', 'require', `${body}\nreturn readings;`);
	return factory({}, createRequire(import.meta.url)) as (path: string) => string[];
}

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
	websocket?: boolean;
	querystring?: Record<string, { value: string; multiValue?: { value: string }[] }>;
	cookies?: Record<string, { value: string; multiValue?: { value: string }[] }>;
} = {}) {
	const headers: Record<string, { value: string }> = {
		host: { value: overrides.host ?? HOST },
	};
	if (overrides.secFetchMode !== undefined) headers['sec-fetch-mode'] = { value: overrides.secFetchMode };
	else headers['sec-fetch-mode'] = { value: 'navigate' };
	if (overrides.accept) headers.accept = { value: overrides.accept };
	// CloudFront never shows a function `Upgrade`; the handshake's own key is what arrives.
	if (overrides.websocket) headers['sec-websocket-key'] = { value: 'dGhlIHNhbXBsZSBub25jZQ==' };
	return {
		request: {
			method: overrides.method ?? 'GET',
			uri: overrides.uri ?? '/page',
			querystring: overrides.querystring ?? {},
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

async function mintCookie(
	ip = IP,
	verdict: 'allow' | 'block' = 'allow',
	key = SECRET,
	{ clearanceVersion = CV, ttlSeconds }: { clearanceVersion?: string; ttlSeconds?: number } = {}
) {
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
		clearanceVersion,
		ttlSeconds,
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
	// Node runs `f(await g())` fine and the Functions runtime refuses to compile it, so the
	// build parses for it rather than trusting a test run.
	it('refuses an await anywhere inside call arguments, and nothing else', () => {
		for (const code of ['f(await g())', 'f(a, await g())', 'f(a + await g())', 'new F({ x: await g() })'])
			expect(awaitInArguments(`async function h() { ${code} }`), code).toBe(true);
		for (const code of ['var x = await g(); f(x)', 'f(async function () { await g(); })', 'f(async () => await g())'])
			expect(awaitInArguments(`async function h() { ${code} }`), code).toBe(false);
		expect(() => stripForDeploy('async function handler(e) { return f(await g(e)); }')).toThrow(/await/);
	});

	it('stays under the 10 KB runtime limit once stripped for deploy', () => {
		const deployed = stripForDeploy(source);
		const size = Buffer.byteLength(deployed, 'utf8');
		expect(size).toBeLessThan(10240);
		expect(deployed.startsWith(`${EDGE_CONTRACT_BANNER}\n`)).toBe(true);
		expect(deployed).toContain('async function handler');
	});

	// The Lambda's behaviors match `/__mcl/*`, which `/__mcl` itself does not, so it
	// reaches this Function. Returning it early handed the origin whatever contract
	// headers the viewer sent; every reserved path is answered here instead.
	it('answers the reserved prefix at the edge rather than passing it to the origin', async () => {
		const handler = loadHandler(baseKv());
		for (const uri of ['/__mcl', '/__mcl/verify']) {
			const result = (await handler(viewerEvent({ uri }))) as FnResponse;
			expect(result.statusCode, uri).toBe(404);
		}
	});

	it('fails open, marked, when the sealing key or contract version is missing', async () => {
		const noKey = { ...baseKv() };
		delete noKey.k;
		for (const kv of [noKey, baseKv({ v: '1' })]) {
			const event = viewerEvent();
			expect(await loadHandler(kv)(event)).toBe(event.request);
			expect(event.request.headers['x-monocle-skip']?.value).toBe('config');
		}
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
				expect(event.request.headers['x-monocle-skip']?.value).toBe('config');
			}
		}
	});

	// CloudFront routes on the Host, so every name that reaches the Function is one the
	// distribution serves, and reaches the same origin. Passing an unlisted one through
	// made Monocle optional for whoever used the apex, an alias or *.cloudfront.net.
	it('protects every hostname the distribution serves, whatever the host list says', async () => {
		for (const hosts of [JSON.stringify([HOST]), '[]', undefined]) {
			for (const host of [HOST, 'shop.example.com', DISTRIBUTION_DOMAIN]) {
				const kv = hosts === undefined ? baseKv() : baseKv({ hosts });
				const result = (await loadHandler(kv)(viewerEvent({ host }))) as FnResponse;
				expect(result.statusCode, `${host} under ${hosts}`).toBe(503);
			}
		}
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

	// A Lambda that cannot read the store gives the ten-minute pass core gives when Policy
	// cannot answer, under an empty clearance version: accepted as that pass and nothing more.
	it('accepts the pass a Lambda that cannot read the store gives, and only that pass', async () => {
		const kv = baseKv({ 'p:/account': 'e' });
		const pass = await mintCookie(IP, 'allow', SECRET, { clearanceVersion: '', ttlSeconds: 600 });
		const event = viewerEvent({ uri: '/account', cookie: pass });
		expect(await loadHandler(kv)(event)).toBe(event.request);

		for (const cookie of [
			await mintCookie(IP, 'allow', SECRET, { clearanceVersion: '' }),
			await mintCookie(IP, 'block', SECRET, { clearanceVersion: '', ttlSeconds: 600 }),
			await mintCookie(IP, 'allow', SECRET, { clearanceVersion: 'other', ttlSeconds: 600 }),
		]) {
			const refused = (await loadHandler(kv)(viewerEvent({ uri: '/account', cookie }))) as FnResponse;
			expect(refused.statusCode).toBe(503);
		}
	});

	// A Lambda goes on minting against the version it holds until its store window ends, so for
	// two minutes a cookie on another version stands; one older than that is from before the
	// rotation, which it revokes.
	it('honours a cookie on another version minted in the last two minutes, and no older one', async () => {
		const kv = baseKv({ 'p:/account': 'e' });
		const fresh = await mintCookie(IP, 'allow', SECRET, { clearanceVersion: 'other' });
		const event = viewerEvent({ uri: '/account', cookie: fresh });
		expect(await loadHandler(kv)(event)).toBe(event.request);
		// Minted three minutes ago: the allow's hour, less those minutes.
		const older = await mintCookie(IP, 'allow', SECRET, { clearanceVersion: 'other', ttlSeconds: 3600 - 180 });
		const refused = (await loadHandler(kv)(viewerEvent({ uri: '/account', cookie: older }))) as FnResponse;
		expect(refused.statusCode).toBe(503);
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
		expect(event.request.headers['x-monocle-skip']?.value).toBe('error');
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

	// A viewer-request Function cannot drop the origin's body, so the preflight pass
	// edge-core gives would hand anyone the page an origin serves for OPTIONS.
	it('holds an OPTIONS on an enforced path to a verdict, preflight or not', async () => {
		const kv = baseKv({ 'p:/account': 'e' });
		const preflight = viewerEvent({ uri: '/account', method: 'OPTIONS', secFetchMode: 'cors' });
		preflight.request.headers.origin = { value: 'https://app.example' };
		preflight.request.headers['access-control-request-method'] = { value: 'POST' };
		expect(((await loadHandler(kv)(preflight)) as FnResponse).statusCode).toBe(403);
		const cleared = viewerEvent({
			uri: '/account',
			method: 'OPTIONS',
			secFetchMode: 'cors',
			cookie: await mintCookie(),
		});
		expect(await loadHandler(kv)(cleared)).toBe(cleared.request);
	});

	it('does not exempt a crawler WebSocket', async () => {
		const packed = packCidrSet([IP]);
		const result = (await loadHandler(
			baseKv({ 'p:/page': 'e', bots: JSON.stringify({ ...packed, expiresAt: Math.floor(Date.now() / 1000) + 3600 }) })
		)(viewerEvent({ websocket: true }))) as FnResponse;
		expect(result.statusCode).toBe(403);
		expect(result.body).toBeUndefined();
	});

	// Only verify passes anyone now, so a breaker key an older Lambda left in the store
	// must not open enforcement to a request that never asked.
	it('ignores a breaker key left in the store by an older Lambda', async () => {
		const result = (await loadHandler(
			baseKv({ 'p:/account': 'e', brk: String(Math.floor(Date.now() / 1000) + 60) })
		)(viewerEvent({ uri: '/account' }))) as FnResponse;
		expect(result.statusCode).toBe(503);
		expect(result.body).toContain('/__mcl/challenge?return=');
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

	// Edge-core decides each reading on its own and keeps the strictest. An allow-listed address
	// passes an enforced reading, and still meets the challenge an assessed one asks for.
	it('challenges an allow-listed address when another reading is only assessed', async () => {
		const packed = packCidrSet([IP]);
		const kv = baseKv({ 's:/': 'a', 's:/account': 'e', ips: JSON.stringify(packed) });
		const handler = loadHandler(kv);
		const plain = viewerEvent({ uri: '/account/x' });
		expect(await handler(plain)).toBe(plain.request);
		const twoWays = (await handler(viewerEvent({ uri: '//account/x' }))) as FnResponse;
		expect(twoWays.statusCode).toBe(503);
		expect(twoWays.body).toContain('/__mcl/challenge?return=');
	});

	// Only a reading something covers counts against the infrastructure pass.
	it('passes an infrastructure path whose other readings nothing covers', async () => {
		const kv = baseKv({ 's:/': '', 's:/.well-known': 'a' });
		delete kv['s:/'];
		const event = viewerEvent({ uri: '/.well-known/../foo' });
		expect(await loadHandler(kv)(event)).toBe(event.request);
	});

	// Read leniently, `:1::` was `::`, and a cookie bound to that /64 opened for it.
	it('reads a malformed IPv6 head as edge-core does, unbindable', async () => {
		const cookie = await mintCookie('::1');
		const result = (await loadHandler(baseKv({ 'p:/account': 'e' }))(
			viewerEvent({ uri: '/account', cookie, ip: ':1::' })
		)) as FnResponse;
		expect(result.statusCode).toBe(503);
	});

	// Edge-core reads an IPv4-mapped address as the IPv4 one, and the Lambda mints for that.
	it('binds an IPv4-mapped address as edge-core does', async () => {
		for (const ip of ['::ffff:203.0.113.9', '::ffff:cb00:7109']) {
			const cookie = await mintCookie(ip);
			const event = viewerEvent({ uri: '/account', cookie, ip });
			expect(await loadHandler(baseKv({ 'p:/account': 'e' }))(event), ip).toBe(event.request);
			const plain = viewerEvent({ uri: '/account', cookie, ip: IP });
			expect(await loadHandler(baseKv({ 'p:/account': 'e' }))(plain), ip).toBe(plain.request);
		}
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

	describe("edge-core's path readings", () => {
		const readings = loadReadings();

		it('reads every corpus path exactly as edge-core does', () => {
			for (const vector of readingsCorpus.vectors) {
				if (vector.reject) expect(() => readings(vector.input), vector.name).toThrow();
				else expect([...readings(vector.input)].sort(), vector.name).toEqual(vector.readings);
			}
		});

		it('gives every strict path exactly its canonical form', () => {
			for (const vector of pathsCorpus.vectors) {
				if (!vector.reject) expect(readings(vector.input), vector.name).toEqual([vector.canonical]);
			}
		});

		// Run through the deploy build, which renames `readings`: each reading enforced on
		// its own must refuse the request, so none an origin takes walks past.
		it('enforces a path if any one of its readings is enforced', async () => {
			for (const vector of readingsCorpus.vectors) {
				if (vector.reject) {
					const result = (await loadHandler(baseKv())(viewerEvent({ uri: vector.input }))) as FnResponse;
					expect(result.statusCode, vector.name).toBe(400);
					continue;
				}
				for (const reading of vector.readings!) {
					// Nothing else is covered, so a reading the Function missed would pass.
					const kv = baseKv({ [`p:${reading}`]: 'e' });
					delete kv['s:/'];
					const result = (await loadHandler(kv)(viewerEvent({ uri: vector.input }))) as FnResponse;
					expect(result.statusCode, `${vector.name} via ${reading}`).toBe(503);
				}
			}
		});
	});

	// A servlet container drops the parameter, so this is the enforced page, and the
	// strict rule used to answer 400 for it on every page of the site.
	it('enforces a path carrying ;jsessionid as the page it names', async () => {
		const kv = baseKv({ 's:/members': 'e' });
		const result = (await loadHandler(kv)(viewerEvent({ uri: '/members;jsessionid=ABC/page' }))) as FnResponse;
		expect(result.statusCode).toBe(503);
	});

	it('passes an unprotected path whatever its spelling', async () => {
		const kv = baseKv();
		delete kv['s:/'];
		for (const uri of ['/blog;jsessionid=ABC', '/files/a%2Fb.txt', '/a//b']) {
			const event = viewerEvent({ uri });
			expect(await loadHandler(kv)(event), uri).toBe(event.request);
		}
	});

	// The canonical path is lower-cased and slash-trimmed for comparison only.
	// Returning the visitor to it 404s on any case-sensitive origin.
	it('returns the visitor to the URI they asked for, not its folded form', async () => {
		const handler = loadHandler(baseKv());
		const result = (await handler(viewerEvent({ uri: '/Account/Profile/' }))) as FnResponse;
		expect(result.statusCode).toBe(503);
		expect(result.body).toContain(encodeURIComponent('/Account/Profile/'));
	});

	// Buffer.from is lenient, so a truncated key verifies as a DIFFERENT key and
	// rejects every cookie the Lambda minted: a challenge loop with no way out.
	it('passes traffic marked when the sealing key is not a 64-hex secret', async () => {
		for (const bad of [SECRET.slice(0, 63), 'not-hex', '']) {
			const handler = loadHandler(baseKv({ k: bad }));
			const event = viewerEvent({ uri: '/page' });
			expect(await handler(event), JSON.stringify(bad)).toBe(event.request);
			expect(event.request.headers['x-monocle-skip']?.value).toBe('config');
		}
	});

	// Some stacks serve the path these name instead of the one we assessed. No browser sends one.
	it('never forwards a path override or a cookie of ours to the origin', async () => {
		const event = viewerEvent({ uri: '/page', secFetchMode: 'cors' });
		event.request.headers['x-original-url'] = { value: '/account' };
		event.request.headers['x-rewrite-url'] = { value: '/account' };
		event.request.cookies = {
			'__Secure-mcl_x': { value: 'forged' },
			'__Host-mcl_skip': { value: '1' },
			theme: { value: 'dark' },
		};
		const result = (await loadHandler(baseKv())(event)) as {
			headers: Record<string, unknown>;
			cookies: Record<string, unknown>;
		};
		expect(result).toBe(event.request);
		expect(result.headers['x-original-url']).toBeUndefined();
		expect(result.headers['x-rewrite-url']).toBeUndefined();
		expect(Object.keys(result.cookies)).toEqual(['theme']);
	});

	// The challenge page leaves this when our script could not load. Forged, it gains only
	// what a request that is not a navigation already has.
	it('serves an assessed navigation carrying the assess marker', async () => {
		const event = viewerEvent({ cookies: { '__Host-mcl_skip': { value: '1' } } });
		expect(await loadHandler(baseKv())(event)).toBe(event.request);
	});

	it('never lets the assess marker past an enforced path', async () => {
		const event = viewerEvent({ uri: '/account', cookies: { '__Host-mcl_skip': { value: '1' } } });
		const result = (await loadHandler(baseKv({ 'p:/account': 'e' }))(event)) as FnResponse;
		expect(result.statusCode).toBe(503);
		expect(result.body).toContain('/__mcl/challenge?return=');
	});

	// CloudFront hands query values over still percent-encoded; encoding them again sent the
	// visitor back to a different URL, which breaks OAuth callbacks and search links.
	it('returns the visitor to the query string they sent, encoded once', async () => {
		const result = (await loadHandler(baseKv())(
			viewerEvent({
				uri: '/search',
				querystring: {
					q: { value: 'caf%C3%A9%20au%20lait' },
					next: { value: '%2Faccount' },
					tag: { value: 'a', multiValue: [{ value: 'a' }, { value: 'b%2Bc' }] },
				},
			})
		)) as FnResponse;
		const target = /return=([^"]+)"/.exec(result.body ?? '')![1]!;
		expect(decodeURIComponent(target)).toBe('/search?q=caf%C3%A9%20au%20lait&next=%2Faccount&tag=a&tag=b%2Bc');
	});

	// A fail-open return must not hand the origin headers or cookies the viewer set.
	it('strips contract headers and our cookies even when it fails open', async () => {
		const handler = loadHandler(baseKv({ k: '' }));
		const event = viewerEvent({ uri: '/page' });
		event.request.headers['x-monocle-skip'] = { value: 'spoofed' };
		event.request.cookies = { '__Host-mcl_c': { value: 'forged' } };
		const result = (await handler(event)) as { headers?: Record<string, unknown>; cookies?: Record<string, unknown> };
		expect(result.headers?.['x-monocle-skip']).toEqual({ value: 'config' });
		expect(result.cookies?.['__Host-mcl_c']).toBeUndefined();
	});

	describe('the block page redirect', () => {
		// The block page is only reached on an enforced route.
		const blocked = async (redirect: string, extra: Record<string, string> = {}) => {
			const cookie = await mintCookie(IP, 'block');
			const handler = loadHandler(
				baseKv({
					's:/members': 'e',
					cfg: JSON.stringify({ block_page: { status: 403, redirect } }),
					...extra,
				})
			);
			return (await handler(viewerEvent({ uri: '/members/area', cookie }))) as FnResponse;
		};

		it('redirects to a path on this host', async () => {
			const result = await blocked('/denied');
			expect(result.statusCode).toBe(307);
			expect(result.headers?.location?.value).toBe('/denied');
		});

		// A browser folds the backslash to a slash, so this leaves the site.
		it('refuses a target a browser would resolve off-site', async () => {
			const result = await blocked('/\\evil.example');
			expect(result.statusCode).toBe(403);
		});

		// Blocking the block page redirects it to itself, for ever.
		it('refuses a target inside an enforced subtree', async () => {
			const result = await blocked('/members/denied');
			expect(result.statusCode).toBe(403);
			expect(result.headers?.location).toBeUndefined();
		});
	});
});
