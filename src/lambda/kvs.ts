// Side-effect import: registers the pure-JS SigV4A signer the KVS data-plane
// client requires (its endpoint is multi-region). Without it the SDK throws
// "Neither CRT nor JS SigV4a implementation is available" and every /__mcl/*
// request 503s at Lambda@Edge.
import '@aws-sdk/signature-v4a';
import {
	CloudFrontKeyValueStoreClient,
	DescribeKeyValueStoreCommand,
	GetKeyCommand,
	UpdateKeysCommand,
} from '@aws-sdk/client-cloudfront-keyvaluestore';

import { KVS_VALUE_BYTES } from '../shared/constants';
import type { Kvs } from './types';

const client = new CloudFrontKeyValueStoreClient({ region: 'us-east-1' });

function isMissing(error: unknown): boolean {
	const name = error && typeof error === 'object' && 'name' in error ? String(error.name) : '';
	return (
		name === 'ResourceNotFoundException' ||
		name === 'KeyValueStoreKeysNotFound' ||
		name.includes('NotFound')
	);
}

export function createKvs(kvsArn: string): Kvs {
	return {
		async get(key: string) {
			try {
				const out = await client.send(new GetKeyCommand({ KvsARN: kvsArn, Key: key }));
				return out.Value ?? null;
			} catch (error) {
				if (isMissing(error)) return null;
				throw error;
			}
		},
		async update(puts, deletes = []) {
			const desc = await client.send(new DescribeKeyValueStoreCommand({ KvsARN: kvsArn }));
			await client.send(
				new UpdateKeysCommand({
					KvsARN: kvsArn,
					IfMatch: desc.ETag,
					Puts: puts.map((p) => ({ Key: p.key, Value: p.value })),
					Deletes: deletes.map((key) => ({ Key: key })),
				})
			);
		},
	};
}

export async function readChunks(kvs: Kvs, key: string): Promise<string | null> {
	const first = await kvs.get(key);
	if (first === null) return null;
	let raw = first;
	for (let i = 1; i < MAX_CHUNKS; i++) {
		const chunk = await kvs.get(`${key}.${i}`);
		if (chunk === null) break;
		raw += chunk;
	}
	return raw;
}

/** Continuation keys a reader will follow before giving up. */
export const MAX_CHUNKS = 128;

/**
 * Splits a value across `key`, `key.1`, … and deletes every continuation key the
 * previous value used beyond the new length, so a reader never concatenates a
 * stale tail onto the new value.
 */
export async function writeChunks(kvs: Kvs, key: string, value: string): Promise<void> {
	const puts: { key: string; value: string }[] = [];
	for (let offset = 0, i = 0; offset < value.length || i === 0; offset += KVS_VALUE_BYTES, i++) {
		puts.push({ key: i === 0 ? key : `${key}.${i}`, value: value.slice(offset, offset + KVS_VALUE_BYTES) });
	}
	if (puts.length > MAX_CHUNKS) throw new Error(`${key} exceeds ${MAX_CHUNKS} chunks`);
	const deletes: string[] = [];
	for (let i = puts.length; i < MAX_CHUNKS; i++) {
		if ((await kvs.get(`${key}.${i}`)) === null) break;
		deletes.push(`${key}.${i}`);
	}
	await kvs.update(puts, deletes);
}

export class MemoryKvs implements Kvs {
	constructor(readonly store: Record<string, string> = {}) {}
	async get(key: string) {
		return Object.prototype.hasOwnProperty.call(this.store, key) ? this.store[key]! : null;
	}
	async update(puts: { key: string; value: string }[], deletes: string[] = []) {
		for (const key of deletes) delete this.store[key];
		for (const p of puts) this.store[p.key] = p.value;
	}
}
