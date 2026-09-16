import { packCidrSet, parseCidr, readBoundedJson, PolicyFailure } from '@spur.us/monocle-edge-core';

import { writeChunks } from './kvs';
import type { Kvs } from './types';

export const CRAWLER_FEEDS = [
	'https://developers.google.com/static/crawling/ipranges/common-crawlers.json',
	'https://www.bing.com/toolbox/bingbot.json',
] as const;

export async function refreshCrawlerRanges(kvs: Kvs): Promise<void> {
	const feeds = await Promise.all(
		CRAWLER_FEEDS.map(async (url) => {
			const response = await fetch(url, {
				redirect: 'manual',
				signal: AbortSignal.timeout(5000),
				headers: { Accept: 'application/json', 'Cache-Control': 'no-cache' },
			});
			if (!response.ok) {
				void response.body?.cancel();
				throw new Error('Crawler feed unavailable');
			}
			let data: { prefixes?: unknown } | null;
			try {
				data = (await readBoundedJson(response, 100_000)) as { prefixes?: unknown } | null;
			} catch (error) {
				throw error instanceof PolicyFailure ? new Error('Invalid crawler feed') : error;
			}
			if (!Array.isArray(data?.prefixes) || !data.prefixes.length)
				throw new Error('Invalid crawler feed');
			return data.prefixes.map((entry: unknown) => {
				const { ipv4Prefix, ipv6Prefix } = (entry ?? {}) as {
					ipv4Prefix?: unknown;
					ipv6Prefix?: unknown;
				};
				const prefix = ipv4Prefix ?? ipv6Prefix;
				const cidr = typeof prefix === 'string' ? parseCidr(prefix) : null;
				if (!cidr || cidr.prefixLength === 0) throw new Error('Invalid crawler prefix');
				return prefix as string;
			});
		})
	);
	const ranges = [...new Set(feeds.flat())];
	if (ranges.length > 1000) throw new Error('Crawler snapshot exceeds limit');
	const packed = packCidrSet(ranges);
	if (!packed) throw new Error('Invalid crawler prefix');
	const expiresAt = Math.floor(Date.now() / 1000) + 86400;
	const snapshot = JSON.stringify({
		v4: packed.v4,
		v6: packed.v6,
		expiresAt,
		source: CRAWLER_FEEDS.join(' '),
	});
	if (snapshot.length > 100_000) throw new Error('Crawler snapshot exceeds limit');
	await writeChunks(kvs, 'bots', snapshot);
}
