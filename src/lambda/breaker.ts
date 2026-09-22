/** One breaker per container, mirrored into KVS for the Function whenever its deadline moves. */

import { createMemoryBreaker, type Breaker } from '@spur.us/monocle-edge-core';

import type { Kvs } from './types';

let memory = createMemoryBreaker();
/** The deadline last written to KVS; null once the key is gone. */
let persistedUntil: number | null = null;

/**
 * Every container has its own breaker and every write competes with the dashboard's ETag
 * chain, so a write per verify would churn; a lost write costs at most a grace period of
 * degraded passes. The deadline is what is compared, not open against closed: a failed
 * probe re-opens the breaker with a later one, and a Function still reading the first stops
 * failing open in the middle of the outage.
 */
export function persistingBreaker(kvs: Kvs): Breaker {
	async function persist(): Promise<void> {
		const until = await memory.openUntil();
		if (until === persistedUntil) return;
		try {
			if (until !== null) await kvs.update([{ key: 'brk', value: String(until) }]);
			else await kvs.update([], ['brk']);
			persistedUntil = until;
		} catch (error) {
			console.error(`Failed to persist breaker: ${String(error)}`);
		}
	}
	return {
		isOpen: (now) => memory.isOpen(now),
		takeProbe: (now) => memory.takeProbe(now),
		openUntil: (now) => memory.openUntil(now),
		async recordSuccess() {
			await memory.recordSuccess();
			await persist();
		},
		async recordFailure(now) {
			await memory.recordFailure(now);
			await persist();
		},
	};
}

/** Test hook. */
export function resetBreaker(): void {
	memory = createMemoryBreaker();
	persistedUntil = null;
}
