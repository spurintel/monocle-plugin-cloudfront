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
});
