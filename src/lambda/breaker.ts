/** Isolate-local Policy outage recovery. Mirrors the Cloudflare worker breaker. */

export type BreakerStatus = 'closed' | 'open' | 'half-open';

interface BreakerState {
	status: BreakerStatus;
	failures: number[];
	successes: number;
	openedAt: number;
}

const FAILURE_WINDOW_MS = 60_000;
export const FAILURE_THRESHOLD = 20;
export const OPEN_RETRY_MS = 15_000;
const HALF_OPEN_SUCCESSES_TO_CLOSE = 3;
const PROBE_LEASE_MS = 10_000;

const breaker: BreakerState = {
	status: 'closed',
	failures: [],
	successes: 0,
	openedAt: 0,
};

let probeLeaseAt: number | null = null;

export function breakerOpen(now = Date.now()): boolean {
	if (breaker.status === 'open' && now - breaker.openedAt >= OPEN_RETRY_MS) {
		breaker.status = 'half-open';
		breaker.successes = 0;
	}
	return breaker.status !== 'closed';
}

export function recordPolicySuccess(): void {
	breaker.failures = [];
	if (breaker.status === 'half-open') {
		breaker.successes += 1;
		if (breaker.successes >= HALF_OPEN_SUCCESSES_TO_CLOSE) breaker.status = 'closed';
	} else {
		breaker.status = 'closed';
	}
}

export function recordPolicyFailure(now = Date.now()): void {
	if (breaker.status === 'half-open') {
		breaker.status = 'open';
		breaker.openedAt = now;
		return;
	}
	breaker.failures = breaker.failures.filter((t) => now - t < FAILURE_WINDOW_MS);
	breaker.failures.push(now);
	if (breaker.failures.length >= FAILURE_THRESHOLD) {
		breaker.status = 'open';
		breaker.openedAt = now;
		breaker.failures = [];
	}
}

export function takeAvailabilityProbe(now = Date.now()): (() => void) | null {
	breakerOpen(now);
	if (breaker.status === 'closed') return () => {};
	if (breaker.status === 'open') return null;
	if (probeLeaseAt !== null && now - probeLeaseAt < PROBE_LEASE_MS) return null;
	const held = now;
	probeLeaseAt = held;
	return () => {
		if (probeLeaseAt === held) probeLeaseAt = null;
	};
}

/** How long the Function keeps failing open after the breaker opens; covers half-open probing. */
export const OPEN_GRACE_MS = 90_000;

/** Epoch seconds the Function should treat as open-until; null when closed. */
export function breakerOpenUntil(now = Date.now()): number | null {
	if (!breakerOpen(now)) return null;
	return Math.floor((breaker.openedAt + OPEN_GRACE_MS) / 1000);
}

export function resetBreaker(): void {
	breaker.status = 'closed';
	breaker.openedAt = 0;
	breaker.failures = [];
	breaker.successes = 0;
	probeLeaseAt = null;
}
