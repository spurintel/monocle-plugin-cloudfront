/** One breaker per container, mirrored into KVS for the Function on transitions only. */

import { createMemoryBreaker, type Breaker } from '@spur.us/monocle-edge-core';

import type { Kvs } from './types';

let memory = createMemoryBreaker();
let persistedOpen = false;

/**
 * Every container has its own breaker and every write competes with the dashboard's ETag
 * chain, so a write per verify would churn; a lost write costs at most a grace period of
 * degraded passes.
 */
export function persistingBreaker(kvs: Kvs): Breaker {
	async function persist(): Promise<void> {
		const until = await memory.openUntil();
		const open = until !== null;
		if (open === persistedOpen) return;
		try {
			if (open) await kvs.update([{ key: 'brk', value: String(until) }]);
			else await kvs.update([], ['brk']);
			persistedOpen = open;
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
	persistedOpen = false;
}
