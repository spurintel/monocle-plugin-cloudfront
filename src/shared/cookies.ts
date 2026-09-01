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
export function mintCookieValue(
	clientIp: string,
	cookieSecretHex: string,
	ttlSeconds = 3600
): string {
	const expiryTime = Math.floor(Date.now() / 1000) + ttlSeconds;
	const payload = `${clientIp}|${expiryTime}`;
	const signature = createHmac('sha256', Buffer.from(cookieSecretHex, 'hex')).update(payload).digest('hex');
	return `${Buffer.from(payload, 'utf8').toString('hex')}.${signature}`;
}

/**
 * Builds the full Set-Cookie header value for a freshly minted cookie, or null
 * when no client IP is available.
 *
 * Previously an absent IP minted with an EMPTY ip field, and both verifiers then
 * SKIPPED the IP comparison for any cookie whose stored IP was empty, producing
 * a portable bearer token valid from any address for its full lifetime. The IP
 * binding is what the whole cookie model rests on, so its absence must fail
 * closed rather than mint something unbindable.
 */
export function buildSetCookie(clientIp: string | null, cookieSecretHex: string): string | null {
	if (!clientIp) {
		console.error('No client IP available; refusing to mint an IP-unbound cookie.');
		return null;
	}
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
	const parts = value.split('.');
	if (parts.length !== 2 || !parts[0] || !parts[1]) return false;
	const [payloadHex, signatureHex] = parts;

	// Everything runs inside the try: a bad/empty secret or malformed hex must
	// fail the cookie (re-challenge), never throw out of here as a 500.
	try {
		const payload = Buffer.from(payloadHex, 'hex');
		const expected = createHmac('sha256', Buffer.from(cookieSecretHex, 'hex')).update(payload).digest('hex');
		if (expected !== signatureHex.toLowerCase()) return false;

		const [clientIpAddress, expiryTime] = payload.toString('utf8').split('|');
		// No empty-IP exemption. Nothing mints an IP-unbound cookie any more, and a
		// stored empty IP must NOT skip this comparison: doing so is what turned such
		// a cookie into a token valid from anywhere.
		if (!clientIpAddress || clientIp !== clientIpAddress) return false;
		if (Math.floor(Date.now() / 1000) >= parseInt(expiryTime || '0', 10)) return false;
		return true;
	} catch {
		return false;
	}
}
