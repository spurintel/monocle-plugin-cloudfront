import { CRAWLER_FEEDS, fetchCrawlerRanges, packCidrSet } from '@spur.us/monocle-edge-core';

import { writeChunks } from './kvs';
import type { Kvs } from './types';

export { CRAWLER_FEEDS };

/** Stores one packed snapshot; replaced only after every feed has validated. */
export async function refreshCrawlerRanges(kvs: Kvs): Promise<void> {
	const { ranges, expiresAt, source } = await fetchCrawlerRanges();
	const packed = packCidrSet(ranges);
	if (!packed) throw new Error('Invalid crawler prefix');
	const snapshot = JSON.stringify({ v4: packed.v4, v6: packed.v6, expiresAt, source });
	if (snapshot.length > 100_000) throw new Error('Crawler snapshot exceeds limit');
	await writeChunks(kvs, 'bots', snapshot);
}
