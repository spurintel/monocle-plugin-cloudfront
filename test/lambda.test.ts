import { afterEach, describe, expect, it, vi } from 'vitest';

import {
	COOKIE_SCOPE,
	evaluateForEdge,
	FAILURE_THRESHOLD,
	mintVerdictCookie,
	packCidrSet,
	safeReturn,
	scriptSegment,
	UNVERIFIED_PASS_SECONDS,
	validateVerdictCookie,
} from '@spur.us/monocle-edge-core';

import { resetBreaker } from '../src/lambda/breaker';
import type { BakedConfig } from '../src/lambda/config';
import { CRAWLER_FEEDS, refreshCrawlerRanges } from '../src/lambda/crawler';
import { handleOriginRequest, handler } from '../src/lambda/index';
import { MemoryKvs, readChunks, writeChunks } from '../src/lambda/kvs';
import { getRuntime, resetRuntimeCache } from '../src/lambda/runtime';
import { createHmacSealer } from '@spur.us/monocle-edge-core';

const SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const CV = 'ab'.repeat(32);
const ID = 'deploy-1';
const IP = '203.0.113.9';

const BAKED: BakedConfig = {
	secretKey: 'sk_test',
	cookieSecret: SECRET,
	publishableKey: 'pk_live_123',
	deploymentId: ID,
	kvsArn: 'arn:aws:cloudfront::123:key-value-store/abc',
};

/**
 * A deployment naming one hostname, which is what most of these cases are about.
 * Pass `hosts: '[]'` for the deployment that protects every hostname the
 * distribution serves.
 */
function liveKvs(extra: Record<string, string> = {}) {
	return new MemoryKvs({
		cv: CV,
		cfg: JSON.stringify({ session_tracking: 'off' }),
		hosts: JSON.stringify(['www.example.com']),
		...extra,
	});
}

function originEvent(overrides: {
	uri?: string;
	method?: string;
	ip?: string;
	host?: string;
	distributionDomainName?: string;
	body?: unknown;
	headers?: Record<string, string>;
	querystring?: string;
	truncated?: boolean;
} = {}) {
	const headers: Record<string, { key: string; value: string }[]> = {
		host: [{ key: 'Host', value: overrides.host ?? 'www.example.com' }],
		origin: [{ key: 'Origin', value: `https://${(overrides.host ?? 'www.example.com').split(':')[0]}` }],
		'content-type': [{ key: 'Content-Type', value: 'application/json' }],
	};
	for (const [name, value] of Object.entries(overrides.headers ?? {})) {
		headers[name.toLowerCase()] = [{ key: name, value }];
	}
	const hasBody = overrides.body !== undefined;
	return {
		Records: [
			{
				cf: {
					config: {
						distributionDomainName:
							overrides.distributionDomainName ?? overrides.host ?? 'www.example.com',
					},
					request: {
						method: overrides.method ?? (hasBody ? 'POST' : 'GET'),
						uri: overrides.uri ?? '/__mcl/verify',
						querystring: overrides.querystring ?? '',
						clientIp: overrides.ip ?? IP,
						headers,
						body: hasBody
							? {
									data: Buffer.from(
										typeof overrides.body === 'string' ? overrides.body : JSON.stringify(overrides.body),
										'utf8'
									).toString('base64'),
									encoding: 'base64' as const,
									inputTruncated: overrides.truncated ?? false,
								}
							: undefined,
					},
				},
			},
		],
	};
}

function policyResponse(allowed: boolean, ip = IP, extra: Record<string, unknown> = {}) {
	return new Response(
		JSON.stringify({
			allowed,
			decisionId: 'decision',
			assessment: {
				id: 'assessment',
				ip,
				ipv6: '',
				complete: true,
				ts: new Date().toISOString(),
				...extra,
			},
		}),
		{ status: 200, headers: { 'Content-Type': 'application/json' } }
	);
}

function setCookies(result: { headers?: Record<string, { value: string }[]> }): string[] {
	return (result.headers?.['set-cookie'] ?? []).map((h) => h.value);
}

function cookieValue(header: string, name: string): string | undefined {
	if (!header.startsWith(`${name}=`)) return undefined;
	return header.slice(name.length + 1, header.indexOf(';'));
}

afterEach(() => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
	resetRuntimeCache();
	resetBreaker();
});

describe('handleOriginRequest /__mcl/*', () => {
	it('rejects a cross-origin verify before Policy', async () => {
		const fetchMock = vi.fn();
		vi.stubGlobal('fetch', fetchMock);
		const result = await handleOriginRequest(
			originEvent({
				body: { captchaData: 'bundle' },
				headers: { Origin: 'https://attacker.example' },
			}),
			{ config: BAKED, kvs: liveKvs() }
		);
		expect(result.status).toBe('403');
		expect(JSON.parse(result.body ?? '{}').error).toBe('origin');
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it('accepts verify when Host is the S3 origin and Origin is the distribution domain', async () => {
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(policyResponse(true)));
		const result = await handleOriginRequest(
			originEvent({
				host: 'mybucket.s3.us-east-1.amazonaws.com',
				distributionDomainName: 'd3j0fpqqpfv61o.cloudfront.net',
				body: { captchaData: 'bundle' },
				headers: { Origin: 'https://d3j0fpqqpfv61o.cloudfront.net' },
			}),
			{ config: BAKED, kvs: liveKvs() }
		);
		expect(result.status).toBe('200');
		expect(JSON.parse(result.body ?? '{}').verdict).toBe('allow');
	});

	// A deployment protecting every hostname the distribution serves has no list to
	// match an Origin against, so the browser's own same-origin statement is what
	// stands in - and a cross-site caller cannot truthfully make it.
	it('accepts a same-origin verify from any hostname when none are named', async () => {
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(policyResponse(true)));
		const result = await handleOriginRequest(
			originEvent({
				body: { captchaData: 'bundle' },
				headers: {
					Origin: 'https://anything.example.com',
					'Sec-Fetch-Site': 'same-origin',
				},
			}),
			{ config: BAKED, kvs: liveKvs({ hosts: '[]' }) }
		);
		expect(result.status).toBe('200');
	});

	// The Function protects every name the distribution serves, so a visitor on an alias
	// the list leaves out has to be able to pass the challenge there too.
	it('accepts a same-origin verify from an alias the host list does not name', async () => {
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(policyResponse(true)));
		const result = await handleOriginRequest(
			originEvent({
				body: { captchaData: 'bundle' },
				headers: { Origin: 'https://shop.example.com', 'Sec-Fetch-Site': 'same-origin' },
			}),
			{ config: BAKED, kvs: liveKvs() }
		);
		expect(result.status).toBe('200');
	});

	it('still refuses a verify that does not claim same-origin when none are named', async () => {
		const fetchMock = vi.fn();
		vi.stubGlobal('fetch', fetchMock);
		for (const site of ['cross-site', 'same-site', 'none']) {
			const result = await handleOriginRequest(
				originEvent({
					body: { captchaData: 'bundle' },
					headers: { Origin: 'https://attacker.example', 'Sec-Fetch-Site': site },
				}),
				{ config: BAKED, kvs: liveKvs({ hosts: '[]' }) }
			);
			expect(result.status).toBe('403');
		}
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it('accepts verify Origin that matches a protected host in KVS', async () => {
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(policyResponse(true)));
		const result = await handleOriginRequest(
			originEvent({
				host: 'mybucket.s3.us-east-1.amazonaws.com',
				distributionDomainName: 'd3j0fpqqpfv61o.cloudfront.net',
				body: { captchaData: 'bundle' },
				headers: { Origin: 'https://www.example.com' },
			}),
			{ config: BAKED, kvs: liveKvs({ hosts: JSON.stringify(['www.example.com']) }) }
		);
		expect(result.status).toBe('200');
	});

	it('rejects a missing or malformed verify body', async () => {
		vi.stubGlobal('fetch', vi.fn());
		expect(
			(await handleOriginRequest(originEvent({ body: 'not json' }), { config: BAKED, kvs: liveKvs() }))
				.status
		).toBe('400');
		expect(
			(await handleOriginRequest(originEvent({ body: {} }), { config: BAKED, kvs: liveKvs() })).status
		).toBe('400');
	});

	it('mints an allow cookie the Function verifier accepts', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue(policyResponse(true))
		);
		const result = await handleOriginRequest(originEvent({ body: { captchaData: 'bundle' } }), {
			config: BAKED,
			kvs: liveKvs(),
		});
		expect(result.status).toBe('200');
		expect(JSON.parse(result.body ?? '{}').verdict).toBe('allow');
		const header = setCookies(result)[0];
		expect(header).toBeTruthy();
		const value = cookieValue(header!, COOKIE_SCOPE.names.verdict);
		const state = await validateVerdictCookie({
			sealer: createHmacSealer(SECRET),
			audience: ID,
			cookieValue: value,
			ipBinding: IP,
			nowSeconds: Math.floor(Date.now() / 1000),
			clearanceVersion: CV,
		});
		expect(state.status).toBe('allow');
	});

	it('returns needs_complete without minting', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue(
				new Response(
					JSON.stringify({
						allowed: false,
						reason: 'Assessment is incomplete',
						decisionId: 'decision',
						assessment: {
							id: 'assessment',
							ip: IP,
							complete: false,
							ts: new Date().toISOString(),
						},
					}),
					{ status: 200, headers: { 'Content-Type': 'application/json' } }
				)
			)
		);
		const result = await handleOriginRequest(originEvent({ body: { captchaData: 'bundle' } }), {
			config: BAKED,
			kvs: liveKvs(),
		});
		expect(result.status).toBe('202');
		expect(setCookies(result)).toEqual([]);
	});

	it('serves a cacheable challenge page that reads return client-side', async () => {
		const result = await handleOriginRequest(originEvent({ uri: '/__mcl/challenge', method: 'GET' }), {
			config: BAKED,
			kvs: liveKvs(),
		});
		expect(result.status).toBe('200');
		expect(result.body).toContain('/__mcl/verify');
		expect(result.body).toContain('pk_live_123');
		expect(result.body).toContain("location.search");
		expect(result.body).not.toContain('return=%2Faccount');
	});

	it('serves /__mcl/state JSON and 403 unbindable without a bindable IP', async () => {
		const ok = await handleOriginRequest(originEvent({ uri: '/__mcl/state', method: 'GET' }), {
			config: BAKED,
			kvs: liveKvs(),
		});
		expect(ok.status).toBe('200');
		expect(JSON.parse(ok.body ?? '{}').hint.verdict).toBeNull();
		const bad = await handleOriginRequest(
			originEvent({ uri: '/__mcl/state', method: 'GET', ip: 'not-an-ip' }),
			{ config: BAKED, kvs: liveKvs() }
		);
		expect(bad.status).toBe('403');
		expect(JSON.parse(bad.body ?? '{}').error).toBe('unbindable');
	});

	it('serves the block page and the resident script at the derived segment', async () => {
		const kvs = liveKvs({
			cfg: JSON.stringify({
				session_tracking: 'off',
				block_page: { title: 'Nope', message: 'Denied' },
			}),
		});
		const blocked = await handleOriginRequest(originEvent({ uri: '/__mcl/blocked', method: 'GET' }), {
			config: BAKED,
			kvs,
		});
		expect(blocked.status).toBe('403');
		expect(blocked.body).toContain('Nope');
		expect(blocked.body).toContain('Denied');
		// The segment depends on the deployment and core host only, never the block page.
		const segment = await scriptSegment(ID);
		const script = await handleOriginRequest(
			originEvent({ uri: `/__mcl/${segment}/mcl.js`, method: 'GET' }),
			{ config: BAKED, kvs }
		);
		expect(script.status).toBe('200');
		expect(script.body).toContain('/__mcl/verify');
		expect(script.headers?.['cache-control']?.[0]?.value).toBe('public, max-age=300');
		const missing = await handleOriginRequest(
			originEvent({ uri: '/__mcl/deadbeef/mcl.js', method: 'GET' }),
			{ config: BAKED, kvs }
		);
		expect(missing.status).toBe('404');
	});
});

describe('fixes from the audit', () => {
	it('caches the challenge page but never the unavailable page', async () => {
		const page = await handleOriginRequest(originEvent({ uri: '/__mcl/challenge', method: 'GET' }), {
			config: BAKED,
			kvs: liveKvs(),
		});
		expect(page.status).toBe('200');
		expect(page.headers?.['cache-control']?.[0]?.value).toBe('public, max-age=300');
		// A public object keyed by URL alone must not advertise variants.
		expect(page.headers?.['vary']).toBeUndefined();
		const unbindable = await handleOriginRequest(
			originEvent({ uri: '/__mcl/challenge', method: 'GET', ip: 'not-an-ip' }),
			{ config: BAKED, kvs: liveKvs() }
		);
		expect(unbindable.status).toBe('503');
		expect(unbindable.headers?.['cache-control']?.[0]?.value).toBe('no-store');
	});

	it('serves the resubmit page for a cookieless unsafe navigation', async () => {
		const result = await handleOriginRequest(originEvent({ uri: '/__mcl/resubmit', method: 'GET' }), {
			config: BAKED,
			kvs: liveKvs(),
		});
		expect(result.status).toBe('403');
		expect(result.body).toContain('Your session has expired');
		expect(result.headers?.['cache-control']?.[0]?.value).toBe('no-store');
		const head = await handleOriginRequest(originEvent({ uri: '/__mcl/resubmit', method: 'HEAD' }), {
			config: BAKED,
			kvs: liveKvs(),
		});
		expect(head.status).toBe('403');
		expect(head.body).toBeUndefined();
	});

	it('does not accept the origin-request Host as a verify Origin', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => policyResponse(true)));
		const result = await handleOriginRequest(
			originEvent({
				host: 'origin.internal.example',
				distributionDomainName: 'd123.cloudfront.net',
				body: { captchaData: 'bundle' },
				headers: { Origin: 'https://origin.internal.example' },
			}),
			{ config: BAKED, kvs: liveKvs({ hosts: JSON.stringify(['www.example.com']) }) }
		);
		expect(result.status).toBe('403');
		expect(JSON.parse(result.body ?? '{}').error).toBe('origin');
	});

	// Our failure never answers the visitor. Nothing is written to the store: the pass
	// travels in the visitor's own cookie, which the Function already opens.
	it('passes the visitor for ten minutes when Policy cannot answer', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => new Response('down', { status: 503 })));
		const kvs = liveKvs();
		const update = vi.spyOn(kvs, 'update');
		const result = await handleOriginRequest(originEvent({ body: { captchaData: 'bundle' } }), {
			config: BAKED,
			kvs,
		});
		expect(result.status).toBe('200');
		expect(setCookies(result)[0]).toContain(`Max-Age=${UNVERIFIED_PASS_SECONDS}`);
		expect(update).not.toHaveBeenCalled();
	});

	it('stops asking a Policy that keeps failing, and still passes visitors', async () => {
		const policy = vi.fn(async () => new Response('down', { status: 503 }));
		vi.stubGlobal('fetch', policy);
		const deps = { config: BAKED, kvs: liveKvs() };
		const verify = () => handleOriginRequest(originEvent({ body: { captchaData: 'bundle' } }), deps);
		for (let i = 0; i < FAILURE_THRESHOLD; i++) await verify();
		const asked = policy.mock.calls.length;
		expect((await verify()).status).toBe('200');
		expect(policy.mock.calls.length).toBe(asked);
	});

	// Verify mints against the clearance version. A container still holding the one
	// from before a rotation minted cookies the Function refuses.
	it('mints against a clearance version rotated inside the cache window', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => policyResponse(true)));
		const kvs = liveKvs();
		const deps = { config: BAKED, kvs };
		await handleOriginRequest(originEvent({ uri: '/__mcl/state', method: 'GET' }), deps);
		const rotated = 'cd'.repeat(32);
		kvs.store.cv = rotated;
		const result = await handleOriginRequest(originEvent({ body: { captchaData: 'bundle' } }), deps);
		const value = cookieValue(setCookies(result)[0]!, COOKIE_SCOPE.names.verdict);
		const state = await validateVerdictCookie({
			sealer: createHmacSealer(SECRET),
			audience: ID,
			cookieValue: value,
			ipBinding: IP,
			nowSeconds: Math.floor(Date.now() / 1000),
			clearanceVersion: rotated,
		});
		expect(state.status).toBe('allow');
	});

	// A store that cannot be read is ours. A container with a runtime keeps using it, however old;
	// one without still serves every page that needs no store, and refuses only to mint or read a
	// cookie without the clearance version, which would loop the visitor.
	it('keeps the last runtime, whatever its age, when the store cannot be read', async () => {
		const kvs = liveKvs();
		const first = await getRuntime(BAKED, kvs, { now: 1_000 });
		vi.spyOn(kvs, 'get').mockRejectedValue(new Error('ThrottlingException'));
		expect(await getRuntime(BAKED, kvs, { now: 1_000 + 3_600_000 })).toBe(first);
		expect(await getRuntime(BAKED, kvs, { now: 1_000 + 3_600_000, freshClearance: true })).toBe(first);
	});

	it('serves the pages that need no store on a cold container that cannot read it', async () => {
		const kvs = liveKvs();
		vi.spyOn(kvs, 'get').mockRejectedValue(new Error('ThrottlingException'));
		const deps = { config: BAKED, kvs };
		for (const uri of ['/__mcl/challenge', '/__mcl/resubmit', '/__mcl/blocked'])
			expect((await handleOriginRequest(originEvent({ uri, method: 'GET' }), deps)).status, uri).toMatch(/^(200|403)$/);
		const segment = await scriptSegment(ID);
		expect(
			(await handleOriginRequest(originEvent({ uri: `/__mcl/${segment}/mcl.js`, method: 'GET' }), deps)).status
		).toBe('200');
		expect((await handleOriginRequest(originEvent({ uri: '/__mcl/state', method: 'GET' }), deps)).status).toBe('503');
		const verify = await handleOriginRequest(originEvent({ body: { captchaData: 'bundle' } }), deps);
		expect(verify.status).toBe('503');
		expect(setCookies(verify)).toEqual([]);
	});

	// Another container's verify minted against the rotated version; the challenge page asks
	// this one, still holding the old version, to confirm the cookie.
	it('reads a cookie minted against a clearance version rotated inside the cache window', async () => {
		const kvs = liveKvs();
		const deps = { config: BAKED, kvs };
		await handleOriginRequest(originEvent({ uri: '/__mcl/challenge', method: 'GET' }), deps);
		const rotated = 'cd'.repeat(32);
		kvs.store.cv = rotated;
		const minted = await mintVerdictCookie({
			sealer: createHmacSealer(SECRET),
			audience: ID,
			scope: COOKIE_SCOPE,
			ipBinding: IP,
			verdict: 'allow',
			sid: 'sid-1',
			jti: 'jti-1',
			nowSeconds: Math.floor(Date.now() / 1000),
			clearanceVersion: rotated,
		});
		const state = await handleOriginRequest(
			originEvent({ uri: '/__mcl/state', method: 'GET', headers: { Cookie: minted.setCookie.split(';')[0]! } }),
			deps
		);
		expect(JSON.parse(state.body ?? '{}').hint.verdict).toBe('allow');
	});

	// A verify already warm in this container keeps the version it holds when the store
	// cannot answer the re-read, rather than failing the visitor.
	it('verifies against the cached clearance version when the store cannot be read', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => policyResponse(true)));
		const kvs = liveKvs();
		const deps = { config: BAKED, kvs };
		await handleOriginRequest(originEvent({ uri: '/__mcl/state', method: 'GET' }), deps);
		vi.spyOn(kvs, 'get').mockRejectedValue(new Error('ThrottlingException'));
		const result = await handleOriginRequest(originEvent({ body: { captchaData: 'bundle' } }), deps);
		expect(result.status).toBe('200');
		const state = await validateVerdictCookie({
			sealer: createHmacSealer(SECRET),
			audience: ID,
			cookieValue: cookieValue(setCookies(result)[0]!, COOKIE_SCOPE.names.verdict),
			ipBinding: IP,
			nowSeconds: Math.floor(Date.now() / 1000),
			clearanceVersion: CV,
		});
		expect(state.status).toBe('allow');
	});

	// A Fetch header refuses text above U+00FF, and a site that keeps UTF-8 in its own
	// cookies must not cost its visitors verify.
	it('verifies a visitor whose site cookies hold UTF-8', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => policyResponse(true)));
		const result = await handleOriginRequest(
			originEvent({ body: { captchaData: 'bundle' }, headers: { Cookie: 'name=中文; theme=dark' } }),
			{ config: BAKED, kvs: liveKvs() }
		);
		expect(result.status).toBe('200');
		expect(setCookies(result)[0]).toContain(`${COOKIE_SCOPE.names.verdict}=`);
	});

	it('reads our own cookies from among the site cookies', async () => {
		const kvs = liveKvs({ cfg: JSON.stringify({ session_tracking: 'session' }) });
		const first = await handleOriginRequest(originEvent({ uri: '/__mcl/state', method: 'GET' }), {
			config: BAKED,
			kvs,
		});
		const sid = JSON.parse(first.body ?? '{}').sid as string;
		const session = setCookies(first).find((h) => h.startsWith(`${COOKIE_SCOPE.names.session}=`))!.split(';')[0]!;
		const again = await handleOriginRequest(
			originEvent({
				uri: '/__mcl/state',
				method: 'GET',
				headers: { Cookie: `name=中文; ${session}; theme=dark` },
			}),
			{ config: BAKED, kvs }
		);
		expect(JSON.parse(again.body ?? '{}').sid).toBe(sid);
	});

	// One UpdateKeys call takes 50 keys, and the refresh writes the snapshot in one call.
	it('refuses a crawler snapshot too large for one store update', async () => {
		// Every other /64, so no two ranges merge when packed, and within edge-core's 1,000.
		const huge = Array.from({ length: 900 }, (_, i) => `2001:db8:0:${(i * 2).toString(16)}::/64`);
		vi.stubGlobal(
			'fetch',
			vi.fn(async (url: string) =>
				new Response(
					JSON.stringify({
						creationTime: new Date().toISOString(),
						prefixes: url.includes('bing')
							? [{ ipv4Prefix: '157.55.39.0/24' }]
							: huge.map((ipv6Prefix) => ({ ipv6Prefix })),
					}),
					{ status: 200, headers: { 'Content-Type': 'application/json' } }
				)
			)
		);
		await expect(refreshCrawlerRanges(new MemoryKvs())).rejects.toThrow(/one store update/);
	});

	it('writeChunks removes every stale continuation key', async () => {
		const kvs = new MemoryKvs();
		await writeChunks(kvs, 'bots', 'x'.repeat(1024 * 12 + 1));
		expect(kvs.store['bots.12']).toBeDefined();
		await writeChunks(kvs, 'bots', 'y'.repeat(1024 * 2 + 1));
		expect(kvs.store['bots.2']).toBeDefined();
		expect(kvs.store['bots.3']).toBeUndefined();
		expect(kvs.store['bots.12']).toBeUndefined();
		expect(await readChunks(kvs, 'bots')).toBe('y'.repeat(1024 * 2 + 1));
	});
});

describe('session tracking', () => {
	it('state hands out the session id and mints the cookie when tracking is on', async () => {
		const kvs = liveKvs({ cfg: JSON.stringify({ session_tracking: 'session' }) });
		const first = await handleOriginRequest(originEvent({ uri: '/__mcl/state', method: 'GET' }), {
			config: BAKED,
			kvs,
		});
		expect(first.status).toBe('200');
		const sid = JSON.parse(first.body ?? '{}').sid as string;
		expect(sid).toMatch(/^[0-9a-f-]{36}$/);
		const cookie = setCookies(first).find((h) => h.startsWith(`${COOKIE_SCOPE.names.session}=`));
		expect(cookie).toBeDefined();
		// Presenting the cookie returns the same id and mints nothing.
		const again = await handleOriginRequest(
			originEvent({
				uri: '/__mcl/state',
				method: 'GET',
				headers: { Cookie: cookie!.split(';')[0]! },
			}),
			{ config: BAKED, kvs }
		);
		expect(JSON.parse(again.body ?? '{}').sid).toBe(sid);
		expect(setCookies(again)).toHaveLength(0);
	});

	it('state carries no session id and no cookie when tracking is off', async () => {
		const result = await handleOriginRequest(originEvent({ uri: '/__mcl/state', method: 'GET' }), {
			config: BAKED,
			kvs: liveKvs(),
		});
		expect(JSON.parse(result.body ?? '{}').sid).toBeNull();
		expect(setCookies(result)).toHaveLength(0);
	});

	it('the resident script and challenge page tag the core URL with cpd client-side', async () => {
		const kvs = liveKvs();
		const script = await handleOriginRequest(
			originEvent({ uri: `/__mcl/${await scriptSegment(ID)}/mcl.js`, method: 'GET' }),
			{ config: BAKED, kvs }
		);
		expect(script.body).toContain("'&cpd='");
		const page = await handleOriginRequest(originEvent({ uri: '/__mcl/challenge', method: 'GET' }), {
			config: BAKED,
			kvs,
		});
		expect(page.body).toContain("'&cpd='");
		expect(page.body).toContain("edgeRequest('/__mcl/state')");
	});
});

describe('crawler refresh', () => {
	it('packs both feeds into KVS bots', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(async (url: string) => {
				const prefix = String(url).includes('google') ? '66.249.66.1' : '40.77.167.1';
				return new Response(JSON.stringify({ prefixes: [{ ipv4Prefix: `${prefix}/32` }] }), {
					status: 200,
					headers: { 'Content-Type': 'application/json' },
				});
			})
		);
		const kvs = new MemoryKvs();
		await refreshCrawlerRanges(kvs);
		const raw = kvs.store.bots;
		expect(raw).toBeTruthy();
		const snapshot = JSON.parse(raw!) as { v4: unknown[]; v6: unknown; expiresAt: number };
		expect(Array.isArray(snapshot.v4)).toBe(true);
		expect(snapshot.v4.length).toBeGreaterThan(0);
		expect(snapshot.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
		expect(CRAWLER_FEEDS).toHaveLength(2);
		const packed = packCidrSet(['66.249.66.1/32', '40.77.167.1/32']);
		expect(snapshot.v4).toEqual(packed?.v4);
	});

	it('runs from the EventBridge payload', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(async () => {
				return new Response(JSON.stringify({ prefixes: [{ ipv4Prefix: '66.249.66.1/32' }] }), {
					status: 200,
				});
			})
		);
		const kvs = new MemoryKvs();
		const result = await handler({ refresh: 'crawlers' }, { config: BAKED, kvs });
		expect(result).toEqual({ ok: true });
		expect(kvs.store.bots).toBeTruthy();
	});
});

describe('safeReturn', () => {
	it('rejects open redirects and the /__mcl prefix', () => {
		expect(safeReturn('/account?x=1')).toBe('/account?x=1');
		expect(safeReturn('//evil.example')).toBe('/');
		expect(safeReturn('/__mcl/challenge')).toBe('/');
		expect(safeReturn('https://evil.example')).toBe('/');
	});
});

describe('evaluateForEdge wiring', () => {
	it('is the Policy client the Lambda calls', async () => {
		const fetchMock = vi.fn().mockResolvedValue(policyResponse(true));
		vi.stubGlobal('fetch', fetchMock);
		await evaluateForEdge('bundle', IP, 'sk_test');
		expect(fetchMock).toHaveBeenCalledWith(
			'https://decrypt.mcl.spur.us/api/v1/policy',
			expect.objectContaining({
				method: 'POST',
				headers: expect.objectContaining({ TOKEN: 'sk_test' }),
			})
		);
	});
});
