import { POLICY_API_URL } from './constants';

/**
 * Raised when the Monocle Policy API returns a non-2xx response. The status is
 * kept so callers can special-case it (e.g. 404 = no policy configured).
 */
export class MonocleAPIError extends Error {
	status: number;
	constructor(status: number, statusText: string) {
		super(`Monocle API error: status ${status} ${statusText}`);
		this.name = 'MonocleAPIError';
		this.status = status;
	}
}

export interface MonoclePolicyDecision {
	allowed: boolean;
	/** Present on a real Policy response; `ts` is the assessment's generation time. */
	assessment?: { ts?: string; [key: string]: unknown };
	[key: string]: unknown;
}

/**
 * Evaluates an encrypted assessment against the account's Monocle policy.
 * Same call the Fastly/Cloudflare plugins make; Lambda@Edge has unrestricted
 * outbound network access, so the Policy API is reached directly with the
 * runtime's global fetch (Node 18+).
 */
export async function evaluateAssessment(
	assessment: string,
	secretKey: string
): Promise<MonoclePolicyDecision> {
	const response = await fetch(POLICY_API_URL, {
		method: 'POST',
		headers: {
			'Content-Type': 'text/plain; charset=utf-8',
			'User-Agent': 'monocle-plugin-cloudfront',
			TOKEN: secretKey,
		},
		body: JSON.stringify({ assessment }),
		// The Lambda runs as a viewer-request trigger with a hard 5 s cap: a HUNG
		// (vs refused) Policy API would blow that cap and CloudFront would 503,
		// bypassing the caller's fail-open catch entirely. Abort well inside the
		// cap so a hang surfaces as a TimeoutError that fails open like any other
		// outage.
		signal: AbortSignal.timeout(3000),
	});

	if (!response.ok) {
		throw new MonocleAPIError(response.status, response.statusText);
	}

	// Validate the shape rather than trusting the cast: an unexpected-but-2xx
	// body would otherwise read `allowed: undefined` (falsy) and hard-BLOCK the
	// visitor, while an outright API failure fails open. Throwing here routes a
	// malformed success through the same fail-open handling as other errors.
	const decision = (await response.json().catch(() => null)) as MonoclePolicyDecision | null;
	if (decision === null || typeof decision !== 'object' || typeof decision.allowed !== 'boolean') {
		throw new MonocleAPIError(response.status, 'malformed policy response');
	}
	return decision;
}

/** Maximum age of an assessment we will accept as proof of a live browser. */
export const ASSESSMENT_MAX_AGE_SECONDS = 5;

/** Tolerance for a client or edge clock running slightly ahead. */
const CLOCK_SKEW_TOLERANCE_SECONDS = 5;

/**
 * Whether an assessment timestamp is recent enough to mint against.
 *
 * Without an age check the bundle is a durable bearer credential: one solved
 * challenge can be replayed to mint unlimited cookies, from any number of
 * addresses, for as long as the attacker keeps presenting it.
 *
 * Fails closed on a timestamp it cannot read, since an unparseable `ts` is not
 * evidence of recency and treating it as fresh would make the check bypassable.
 * A MISSING timestamp is handled by the caller, because that is an API-shape
 * question rather than a client input.
 */
export function isAssessmentFresh(
	ts: string | undefined,
	maxAgeSeconds: number = ASSESSMENT_MAX_AGE_SECONDS
): boolean {
	if (!ts) return false;

	const generatedAt = new Date(ts).getTime();
	if (Number.isNaN(generatedAt)) return false;

	const ageSeconds = (Date.now() - generatedAt) / 1000;
	if (ageSeconds < -CLOCK_SKEW_TOLERANCE_SECONDS) return false;

	return ageSeconds <= maxAgeSeconds;
}
