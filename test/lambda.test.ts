import { afterEach, describe, expect, it, vi } from 'vitest';

import { handleVerify } from '../src/lambda/index';
import { validateCookieValue } from '../src/shared/cookies';
import { COOKIE_NAME } from '../src/shared/constants';
import type { MonocleLambdaConfig } from '../src/lambda/config';

const CONFIG: MonocleLambdaConfig = {
	secretKey: 'sk_test',
	cookieSecret: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
};

function verifyEvent(body: unknown, method = 'POST') {
	return {
		Records: [
			{
				cf: {
					request: {
						method,
						uri: '/__mcl/verify',
						clientIp: '203.0.113.9',
						headers: {},
						body: {
							data: Buffer.from(typeof body === 'string' ? body : JSON.stringify(body), 'utf8').toString(
								'base64'
							),
							encoding: 'base64',
						},
					},
				},
			},
		],
	};
}

function mockPolicy(response: { ok: boolean; status?: number; json?: unknown }) {
	const fetchMock = vi.fn().mockResolvedValue({
		ok: response.ok,
		status: response.status ?? (response.ok ? 200 : 500),
		statusText: 'mock',
		json: async () => response.json,
	});
	vi.stubGlobal('fetch', fetchMock);
	return fetchMock;
}

function setCookieValue(result: { headers?: Record<string, { value: string }[]> }): string | undefined {
	const header = result.headers?.['set-cookie']?.[0]?.value;
	return header?.slice(`${COOKIE_NAME}=`.length, header.indexOf(';'));
}

afterEach(() => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe('handleVerify', () => {
	it('rejects non-POST requests', async () => {
		const result = await handleVerify(verifyEvent({ captchaData: 'x' }, 'GET'), CONFIG);
		expect(result.status).toBe('405');
	});

	it('rejects a missing or malformed body', async () => {
		expect((await handleVerify(verifyEvent('not json'), CONFIG)).status).toBe('400');
		expect((await handleVerify(verifyEvent({}), CONFIG)).status).toBe('400');
	});

	it('allows and mints a valid cookie on an allow decision (200, never a bodied 204)', async () => {
		const fetchMock = mockPolicy({ ok: true, json: { allowed: true } });
		const result = await handleVerify(verifyEvent({ captchaData: 'assessment' }), CONFIG);

		expect(result.status).toBe('200');
		expect(result.body).toBeTruthy();
		const cookie = setCookieValue(result as never);
		expect(validateCookieValue(cookie, '203.0.113.9', CONFIG.cookieSecret)).toBe(true);

		expect(fetchMock).toHaveBeenCalledWith(
			'https://decrypt.mcl.spur.us/api/v1/policy',
			expect.objectContaining({ method: 'POST', headers: expect.objectContaining({ TOKEN: 'sk_test' }) })
		);
	});

	it('returns plain 403 Blocked on deny with no block config', async () => {
		mockPolicy({ ok: true, json: { allowed: false } });
		const result = await handleVerify(verifyEvent({ captchaData: 'assessment' }), CONFIG);
		expect(result.status).toBe('403');
		expect(result.headers?.['set-cookie']).toBeUndefined();
	});

	it('returns the html block page with X-Block-Action on deny', async () => {
		mockPolicy({ ok: true, json: { allowed: false } });
		const result = await handleVerify(verifyEvent({ captchaData: 'assessment' }), {
			...CONFIG,
			blockResponseType: 'html',
			blockStatusCode: '451',
			blockPageTitle: 'No <entry>',
			blockResponseBody: 'Denied & gone',
		});
		expect(result.status).toBe('451');
		expect(result.headers?.['x-block-action']?.[0]?.value).toBe('html');
		expect(result.body).toContain('No &lt;entry&gt;');
		expect(result.body).toContain('Denied &amp; gone');
	});

	it('returns the redirect block action on deny', async () => {
		mockPolicy({ ok: true, json: { allowed: false } });
		const result = await handleVerify(verifyEvent({ captchaData: 'assessment' }), {
			...CONFIG,
			blockResponseType: 'redirect',
			blockRedirectUrl: 'https://example.com/blocked',
		});
		expect(result.status).toBe('403');
		expect(result.headers?.['x-block-action']?.[0]?.value).toBe('redirect:https://example.com/blocked');
	});

	it('fails open WITH a cookie when the policy API errors', async () => {
		mockPolicy({ ok: false, status: 500 });
		const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
		const result = await handleVerify(verifyEvent({ captchaData: 'assessment' }), CONFIG);
		expect(result.status).toBe('200');
		expect(validateCookieValue(setCookieValue(result as never), '203.0.113.9', CONFIG.cookieSecret)).toBe(true);
		expect(errorSpy).toHaveBeenCalled();
	});

	it('fails open silently on 404 (no policy configured)', async () => {
		mockPolicy({ ok: false, status: 404 });
		const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
		const result = await handleVerify(verifyEvent({ captchaData: 'assessment' }), CONFIG);
		expect(result.status).toBe('200');
		expect(errorSpy).not.toHaveBeenCalled();
	});

	it('fails open on a malformed 2xx policy body instead of hard-blocking', async () => {
		mockPolicy({ ok: true, json: { unexpected: 'shape' } });
		const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
		const result = await handleVerify(verifyEvent({ captchaData: 'assessment' }), CONFIG);
		expect(result.status).toBe('200');
		expect(errorSpy).toHaveBeenCalled();
	});

	it('DENIES (never mints) when the policy API rejects the request with a 4xx', async () => {
		// A 4xx means the API is reachable and rejected THIS request (undecryptable
		// assessment or bad secret key). Minting here would let an attacker POST
		// junk and be waved through, so it must deny, not fail open.
		mockPolicy({ ok: false, status: 400 });
		const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
		const result = await handleVerify(verifyEvent({ captchaData: 'junk' }), CONFIG);
		expect(result.status).toBe('403');
		expect(result.headers?.['set-cookie']).toBeUndefined();
		expect(errorSpy).toHaveBeenCalled();
	});

	it('DENIES with the configured block page on a 4xx and never sets a cookie', async () => {
		mockPolicy({ ok: false, status: 422 });
		vi.spyOn(console, 'error').mockImplementation(() => {});
		const result = await handleVerify(verifyEvent({ captchaData: 'junk' }), {
			...CONFIG,
			blockResponseType: 'html',
			blockStatusCode: '403',
		});
		expect(result.headers?.['set-cookie']).toBeUndefined();
		expect(result.body).toBeTruthy();
	});

	it('falls back to the block page for an unsafe (javascript:) redirect URL', async () => {
		mockPolicy({ ok: true, json: { allowed: false } });
		const result = await handleVerify(verifyEvent({ captchaData: 'assessment' }), {
			...CONFIG,
			blockResponseType: 'redirect',
			blockRedirectUrl: 'javascript:alert(1)',
		});
		const action = result.headers?.['x-block-action']?.[0]?.value;
		expect(action).toBe('html');
		expect(action).not.toContain('javascript:');
	});

	it('falls back to the block page for a redirect URL with a control byte', async () => {
		// A NUL (or any control byte) would throw on the header and route the block
		// through fail-open; it must fall back to the html block instead.
		mockPolicy({ ok: true, json: { allowed: false } });
		const result = await handleVerify(verifyEvent({ captchaData: 'assessment' }), {
			...CONFIG,
			blockResponseType: 'redirect',
			blockRedirectUrl: 'https://example.com/\u0000evil',
		});
		expect(result.headers?.['x-block-action']?.[0]?.value).toBe('html');
		expect(result.headers?.['set-cookie']).toBeUndefined();
	});

	it('clamps a 2xx block status to 403 (a 2xx would loop the interstitial)', async () => {
		mockPolicy({ ok: true, json: { allowed: false } });
		const result = await handleVerify(verifyEvent({ captchaData: 'assessment' }), {
			...CONFIG,
			blockResponseType: 'html',
			blockStatusCode: '200',
		});
		expect(result.status).toBe('403');
	});

	it('FAILS OPEN (not deny) on a transient 429 from the policy API', async () => {
		// 408/429 are transient, not "this request was rejected", so they mint like
		// any other outage rather than hard-denying a real visitor.
		mockPolicy({ ok: false, status: 429 });
		vi.spyOn(console, 'error').mockImplementation(() => {});
		const result = await handleVerify(verifyEvent({ captchaData: 'assessment' }), CONFIG);
		expect(result.status).toBe('200');
		expect(validateCookieValue(setCookieValue(result as never), '203.0.113.9', CONFIG.cookieSecret)).toBe(true);
	});
});

describe('assessment logging', () => {
	it('logs nothing when logAssessment is absent from the config', async () => {
		mockPolicy({ ok: true, json: { allowed: true, ip: '203.0.113.9' } });
		const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		await handleVerify(verifyEvent({ captchaData: 'assessment' }), CONFIG);
		expect(logSpy).not.toHaveBeenCalled();
	});

	it('logs one JSON line with the decision fields when logAssessment is true', async () => {
		mockPolicy({ ok: true, json: { allowed: true, ip: '203.0.113.9', service: 'vpn' } });
		const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		await handleVerify(verifyEvent({ captchaData: 'assessment' }), { ...CONFIG, logAssessment: true });

		expect(logSpy).toHaveBeenCalledTimes(1);
		const line = logSpy.mock.calls[0][0] as string;
		expect(line).toContain('"monocle":"assessment"');
		expect(JSON.parse(line)).toEqual({
			monocle: 'assessment',
			allowed: true,
			ip: '203.0.113.9',
			service: 'vpn',
		});
	});

	it('logs the decision on deny too (before the allow/deny branch)', async () => {
		mockPolicy({ ok: true, json: { allowed: false } });
		const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		const result = await handleVerify(verifyEvent({ captchaData: 'assessment' }), {
			...CONFIG,
			logAssessment: true,
		});
		expect(result.status).toBe('403');
		expect(logSpy).toHaveBeenCalledTimes(1);
		expect(JSON.parse(logSpy.mock.calls[0][0] as string)).toEqual({ monocle: 'assessment', allowed: false });
	});

	it('logs nothing on the fail-open path (no decision exists to log)', async () => {
		mockPolicy({ ok: false, status: 500 });
		vi.spyOn(console, 'error').mockImplementation(() => {});
		const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		const result = await handleVerify(verifyEvent({ captchaData: 'assessment' }), {
			...CONFIG,
			logAssessment: true,
		});
		expect(result.status).toBe('200');
		expect(logSpy).not.toHaveBeenCalled();
	});
});
