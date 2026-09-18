import { COOKIE_SCOPE, mintVerdictCookie, validateVerdictCookie } from '@spur.us/monocle-edge-core';
import { describe, expect, it } from 'vitest';

import { createHmacSealer } from '../src/shared/hmac-sealer';

const SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const PREV = 'ff'.repeat(32);
const CV = 'ab'.repeat(32);
const ID = 'deploy-1';

describe('createHmacSealer', () => {
	it('round-trips plaintext', async () => {
		const sealer = createHmacSealer(SECRET);
		const sealed = await sealer.seal('hello');
		expect(sealed).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
		expect(await sealer.open(sealed)).toBe('hello');
	});

	it('rejects a payload sealed with another key', async () => {
		const sealed = await createHmacSealer(PREV).seal('other');
		expect(await createHmacSealer(SECRET).open(sealed)).toBeNull();
	});

	it('rejects a tampered payload', async () => {
		const sealer = createHmacSealer(SECRET);
		const sealed = await sealer.seal('hello');
		const [pt] = sealed.split('.');
		expect(await sealer.open(`${pt}.${'A'.repeat(43)}`)).toBeNull();
	});

	it('refuses a malformed sealing key', () => {
		expect(() => createHmacSealer('not-hex')).toThrow(/Invalid sealing key/);
	});
});

describe('mintVerdictCookie / validateVerdictCookie', () => {
	it('round-trips an allow cookie for the same IP binding and audience', async () => {
		const sealer = createHmacSealer(SECRET);
		const minted = await mintVerdictCookie({
			sealer,
			audience: ID,
			scope: COOKIE_SCOPE,
			ipBinding: '203.0.113.9',
			verdict: 'allow',
			sid: 'sid',
			jti: 'jti',
			nowSeconds: Math.floor(Date.now() / 1000),
			clearanceVersion: CV,
		});
		expect(minted.setCookie.startsWith(`${COOKIE_SCOPE.names.verdict}=`)).toBe(true);
		expect(minted.setCookie).toContain('Secure');
		expect(minted.setCookie).toContain('HttpOnly');
		expect(minted.setCookie).toContain('Partitioned');
		const value = minted.setCookie.split(';')[0]!.slice(`${COOKIE_SCOPE.names.verdict}=`.length);
		const state = await validateVerdictCookie({
			sealer,
			audience: ID,
			cookieValue: value,
			ipBinding: '203.0.113.9',
			nowSeconds: Math.floor(Date.now() / 1000),
			clearanceVersion: CV,
		});
		expect(state.status).toBe('allow');
	});

	it('is absent for the wrong IP, audience, or clearance version', async () => {
		const sealer = createHmacSealer(SECRET);
		const minted = await mintVerdictCookie({
			sealer,
			audience: ID,
			scope: COOKIE_SCOPE,
			ipBinding: '203.0.113.9',
			verdict: 'allow',
			sid: 'sid',
			jti: 'jti',
			nowSeconds: Math.floor(Date.now() / 1000),
			clearanceVersion: CV,
		});
		const value = minted.setCookie.split(';')[0]!.slice(`${COOKIE_SCOPE.names.verdict}=`.length);
		const now = Math.floor(Date.now() / 1000);
		expect(
			(
				await validateVerdictCookie({
					sealer,
					audience: ID,
					cookieValue: value,
					ipBinding: '198.51.100.1',
					nowSeconds: now,
					clearanceVersion: CV,
				})
			).status
		).toBe('absent');
		expect(
			(
				await validateVerdictCookie({
					sealer,
					audience: 'other',
					cookieValue: value,
					ipBinding: '203.0.113.9',
					nowSeconds: now,
					clearanceVersion: CV,
				})
			).status
		).toBe('absent');
		expect(
			(
				await validateVerdictCookie({
					sealer,
					audience: ID,
					cookieValue: value,
					ipBinding: '203.0.113.9',
					nowSeconds: now,
					clearanceVersion: '00'.repeat(32),
				})
			).status
		).toBe('absent');
	});
});
