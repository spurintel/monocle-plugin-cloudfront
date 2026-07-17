import { describe, expect, it, vi, afterEach } from 'vitest';

import { buildSetCookie, mintCookieValue, validateCookieValue } from '../src/shared/cookies';
import { COOKIE_NAME } from '../src/shared/constants';

const SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const OTHER_SECRET = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

afterEach(() => {
	vi.restoreAllMocks();
});

describe('mintCookieValue / validateCookieValue', () => {
	it('round-trips: a minted cookie validates for the same IP and secret', () => {
		const value = mintCookieValue('203.0.113.9', SECRET);
		expect(validateCookieValue(value, '203.0.113.9', SECRET)).toBe(true);
	});

	it('uses the <payloadHex>.<hmacHex> wire format over clientIp|expiry', () => {
		vi.spyOn(Date, 'now').mockReturnValue(1_700_000_000_000);
		const value = mintCookieValue('203.0.113.9', SECRET);
		const [payloadHex, sig] = value.split('.');
		expect(Buffer.from(payloadHex!, 'hex').toString('utf8')).toBe('203.0.113.9|1700003600');
		expect(sig).toMatch(/^[0-9a-f]{64}$/);
	});

	it('rejects a tampered payload', () => {
		const value = mintCookieValue('203.0.113.9', SECRET);
		const [payloadHex, sig] = value.split('.');
		const forged = Buffer.from('203.0.113.9|9999999999', 'utf8').toString('hex');
		expect(forged).not.toBe(payloadHex);
		expect(validateCookieValue(`${forged}.${sig}`, '203.0.113.9', SECRET)).toBe(false);
	});

	it('rejects a cookie signed with a different secret', () => {
		const value = mintCookieValue('203.0.113.9', OTHER_SECRET);
		expect(validateCookieValue(value, '203.0.113.9', SECRET)).toBe(false);
	});

	it('rejects a bound cookie presented from a different IP', () => {
		const value = mintCookieValue('203.0.113.9', SECRET);
		expect(validateCookieValue(value, '198.51.100.1', SECRET)).toBe(false);
	});

	it('skips the IP check for an IP-unbound cookie (null at mint time)', () => {
		const value = mintCookieValue(null, SECRET);
		expect(validateCookieValue(value, '198.51.100.1', SECRET)).toBe(true);
	});

	it('rejects an expired cookie', () => {
		vi.spyOn(Date, 'now').mockReturnValue(1_700_000_000_000);
		const value = mintCookieValue('203.0.113.9', SECRET, 60);
		vi.spyOn(Date, 'now').mockReturnValue(1_700_000_061_000);
		expect(validateCookieValue(value, '203.0.113.9', SECRET)).toBe(false);
	});

	it('fails malformed values instead of throwing', () => {
		expect(validateCookieValue(undefined, '1.2.3.4', SECRET)).toBe(false);
		expect(validateCookieValue('', '1.2.3.4', SECRET)).toBe(false);
		expect(validateCookieValue('nodot', '1.2.3.4', SECRET)).toBe(false);
		expect(validateCookieValue('zz.zz', '1.2.3.4', SECRET)).toBe(false);
		expect(validateCookieValue(mintCookieValue('1.2.3.4', SECRET), '1.2.3.4', 'not-hex')).toBe(false);
	});
});

describe('buildSetCookie', () => {
	it('emits the full Set-Cookie header with security attributes', () => {
		const header = buildSetCookie('203.0.113.9', SECRET);
		expect(header.startsWith(`${COOKIE_NAME}=`)).toBe(true);
		expect(header).toContain('Secure');
		expect(header).toContain('HttpOnly');
		expect(header).toContain('Path=/');
		expect(header).toContain('SameSite=Lax');
	});
});
