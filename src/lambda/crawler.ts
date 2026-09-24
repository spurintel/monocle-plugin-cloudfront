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
	// One UpdateKeys call takes at most 50 keys, and writeChunks makes one so a reader never
	// joins a new head to an old tail: 25 chunks written, and at most the 24 an earlier
	// snapshot left, fit. Today's feeds pack into about 2 KB.
	if (snapshot.length > 25 * 1024) throw new Error('Crawler snapshot exceeds one store update');
	await writeChunks(kvs, 'bots', snapshot);
}
