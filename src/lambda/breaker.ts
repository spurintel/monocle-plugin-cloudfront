/** One breaker per container. It only decides whether verify asks Policy; nothing else reads it. */

import { createMemoryBreaker, type Breaker } from '@spur.us/monocle-edge-core';

let breaker = createMemoryBreaker();

export function containerBreaker(): Breaker {
	return breaker;
}

/** Test hook. */
export function resetBreaker(): void {
	breaker = createMemoryBreaker();
}
