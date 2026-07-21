import { createHmac } from 'node:crypto';

import { COOKIE_NAME } from './constants';

/**
 * The cookie payload (`<clientIp>|<expiryUnixSeconds>`) is not secret; it only
 * needs to be tamper-proof so a client cannot forge or extend it. It is signed
 * with HMAC-SHA256, hex wire format `<payloadHex>.<hmacHex>`, keyed with the
 * HEX-DECODED cookie secret: the exact scheme monocle-plugin-fastly uses, so
 * cookies stay consistent across edge plugins.
 *
 * HMAC (not AES-GCM like the Cloudflare worker) is necessity as well as
 * parity: the CloudFront Functions runtime that VERIFIES this cookie on every
 * request exposes only `crypto.createHmac`/`createHash`, no AES. This module
 * (the Lambda@Edge side) MINTS with node:crypto so both compute the identical
 * digest.
 */
export function mintCookieValue(clientIp: string | null, cookieSecretHex: string, ttlSeconds = 3600): string {
	const expiryTime = Math.floor(Date.now() / 1000) + ttlSeconds;
	// An empty IP issues an IP-unbound cookie rather than baking in a literal
	// unmatchable value: a cookie that can never validate would trap the visitor
	// in an endless challenge loop. The signature and expiry still apply.
	const payload = `${clientIp ?? ''}|${expiryTime}`;
	const signature = createHmac('sha256', Buffer.from(cookieSecretHex, 'hex')).update(payload).digest('hex');
	return `${Buffer.from(payload, 'utf8').toString('hex')}.${signature}`;
}

/** Builds the full Set-Cookie header value for a freshly minted cookie. */
export function buildSetCookie(clientIp: string | null, cookieSecretHex: string): string {
	return `${COOKIE_NAME}=${mintCookieValue(clientIp, cookieSecretHex)}; Secure; HttpOnly; Path=/; SameSite=Lax`;
}

/**
 * Validates a cookie VALUE (`<payloadHex>.<hmacHex>`): verifies the HMAC, then
 * the bound client IP and expiry. Mirrors the CloudFront Function's inline
 * verifier (src/function/index.js); test/function.test.ts pins the two against
 * the same vectors so they cannot drift.
 */
export function validateCookieValue(
	value: string | undefined,
	clientIp: string | null,
	cookieSecretHex: string
): boolean {
	if (!value) return false;
	const [payloadHex, signatureHex] = value.split('.');
	if (!payloadHex || !signatureHex) return false;

	// Everything runs inside the try: a bad/empty secret or malformed hex must
	// fail the cookie (re-challenge), never throw out of here as a 500.
	try {
		const payload = Buffer.from(payloadHex, 'hex');
		const expected = createHmac('sha256', Buffer.from(cookieSecretHex, 'hex')).update(payload).digest('hex');
		if (expected !== signatureHex.toLowerCase()) return false;

		const [clientIpAddress, expiryTime] = payload.toString('utf8').split('|');
		// An empty stored IP means the cookie was issued without an IP binding;
		// skip the comparison rather than failing a cookie that could never match.
		if (clientIpAddress !== '' && clientIp !== clientIpAddress) return false;
		if (Math.floor(Date.now() / 1000) >= parseInt(expiryTime ?? '0', 10)) return false;
		return true;
	} catch {
		return false;
	}
}
