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
