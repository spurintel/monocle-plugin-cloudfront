import { describe, it, expect } from 'vitest';
import { isAssessmentFresh, ASSESSMENT_MAX_AGE_SECONDS } from '../src/shared/policy';

/**
 * Assessment freshness. Previously the Policy path minted on any `allowed`
 * verdict regardless of the assessment's age, so one solved bundle was a durable
 * credential replayable to mint cookies from any number of addresses.
 */
describe('isAssessmentFresh', () => {
	const at = (secondsAgo: number) => new Date(Date.now() - secondsAgo * 1000).toISOString();

	it('accepts an assessment generated just now', () => {
		expect(isAssessmentFresh(at(0))).toBe(true);
	});

	it('accepts an assessment inside the window', () => {
		expect(isAssessmentFresh(at(ASSESSMENT_MAX_AGE_SECONDS - 1))).toBe(true);
	});

	it('rejects an assessment older than the window', () => {
		expect(isAssessmentFresh(at(ASSESSMENT_MAX_AGE_SECONDS + 1))).toBe(false);
	});

	it('rejects a long-stale replayed assessment', () => {
		expect(isAssessmentFresh(at(3600))).toBe(false);
	});

	it('rejects an unparseable timestamp rather than treating it as fresh', () => {
		// Fail closed on a value the client supplied: a ts we cannot read is not
		// evidence of recency, and treating it as fresh would make the check
		// bypassable by sending garbage.
		for (const value of ['', 'not-a-date', 'NaN']) {
			expect(isAssessmentFresh(value)).toBe(false);
		}
	});

	it('rejects a timestamp implausibly far in the future', () => {
		expect(isAssessmentFresh(at(-3600))).toBe(false);
	});

	it('tolerates small negative skew', () => {
		expect(isAssessmentFresh(at(-1))).toBe(true);
	});
});
