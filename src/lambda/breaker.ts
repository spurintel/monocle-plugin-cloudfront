/** One breaker per container. It only decides whether verify asks Policy; nothing else reads it. */

import { createMemoryBreaker, type Breaker } from '@spur.us/monocle-edge-core';

let breaker = createMemoryBreaker();

export function containerBreaker(): Breaker {
	return breaker;
}

/**
 * For a container that cannot read the store: verify never asks Policy, and gives the
 * ten-minute pass core gives when Policy cannot answer.
 */
export const UNREAD_BREAKER: Breaker = {
	recordSuccess: async () => {},
	recordFailure: async () => {},
	takeProbe: async () => null,
};

/** Test hook. */
export function resetBreaker(): void {
	breaker = createMemoryBreaker();
}
