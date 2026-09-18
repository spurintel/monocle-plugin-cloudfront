import { afterEach, describe, expect, it, vi } from 'vitest';

import {
	COOKIE_SCOPE,
	evaluateForEdge,
	packCidrSet,
	validateVerdictCookie,
} from '@spur.us/monocle-edge-core';

import { OPEN_GRACE_MS, recordPolicyFailure, resetBreaker } from '../src/lambda/breaker';
import { resetPersistedBreaker } from '../src/lambda/endpoints';
import type { BakedConfig } from '../src/lambda/config';
import { CRAWLER_FEEDS, refreshCrawlerRanges } from '../src/lambda/crawler';
import { handleOriginRequest, handler } from '../src/lambda/index';
import { MemoryKvs, readChunks, writeChunks } from '../src/lambda/kvs';
import { deriveScriptSegment, resetRuntimeCache } from '../src/lambda/runtime';
import { createHmacSealer } from '../src/shared/hmac-sealer';
import { safeReturn } from '../src/lambda/templates';

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
	resetPersistedBreaker();
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
		const segment = deriveScriptSegment(ID);
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

	it('persists the breaker on transitions only', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(async () => new Response('down', { status: 503 }))
		);
		const kvs = liveKvs();
		const update = vi.spyOn(kvs, 'update');
		const verify = () =>
			handleOriginRequest(originEvent({ body: { captchaData: 'bundle' } }), { config: BAKED, kvs });
		// Open the breaker from the outside; the next failure would write anyway.
		for (let i = 0; i < 19; i++) recordPolicyFailure();
		await verify();
		expect(kvs.store.brk).toBeDefined();
		expect(Number(kvs.store.brk)).toBeGreaterThan(Math.floor(Date.now() / 1000));
		expect(Number(kvs.store.brk)).toBeLessThanOrEqual(
			Math.floor((Date.now() + OPEN_GRACE_MS) / 1000)
		);
		const writes = update.mock.calls.length;
		await verify();
		await verify();
		expect(update.mock.calls.length).toBe(writes);
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
			originEvent({ uri: `/__mcl/${deriveScriptSegment(ID)}/mcl.js`, method: 'GET' }),
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
