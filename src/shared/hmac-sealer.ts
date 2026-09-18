/** HMAC-SHA256 sealer: base64url(plaintext).base64url(hmac). */

import { createHmac, timingSafeEqual } from 'node:crypto';

import type { Sealer } from '@spur.us/monocle-edge-core';

function b64url(buf: Buffer): string {
	return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unb64url(value: string): Buffer | null {
	try {
		const pad = value.replace(/-/g, '+').replace(/_/g, '/');
		return Buffer.from(pad + '==='.slice((pad.length + 3) % 4), 'base64');
	} catch {
		return null;
	}
}

function mac(key: Buffer, data: Buffer): Buffer {
	return createHmac('sha256', key).update(data).digest();
}

export function createHmacSealer(keyHex: string): Sealer {
	if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) throw new Error('Invalid sealing key');
	const current = Buffer.from(keyHex, 'hex');
	return {
		async seal(plaintext: string) {
			const pt = Buffer.from(plaintext, 'utf8');
			return `${b64url(pt)}.${b64url(mac(current, pt))}`;
		},
		async open(sealed: string) {
			if (typeof sealed !== 'string' || sealed.length > 8192) return null;
			const dot = sealed.lastIndexOf('.');
			if (dot < 1) return null;
			const pt = unb64url(sealed.slice(0, dot));
			const sig = unb64url(sealed.slice(dot + 1));
			if (!pt || !sig || sig.length !== 32) return null;
			const expected = mac(current, pt);
			if (expected.length !== sig.length || !timingSafeEqual(expected, sig)) return null;
			return pt.toString('utf8');
		},
	};
}
