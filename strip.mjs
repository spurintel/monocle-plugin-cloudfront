/**
 * Produces the deployable CloudFront Function from its readable source: drop
 * comment-only lines and collapse blank lines to fit the hard 10 KB runtime
 * limit. NOTE: the stripped artifact is currently ~10.2 KB, close to the cap;
 * the build (build.mjs) fails if it exceeds 10240 bytes, so keep the interstitial
 * and logic lean when editing.
 *
 * Line-based and deliberately conservative — it only removes lines whose
 * TRIMMED text starts with `//` (so `//` inside string literals, e.g. the
 * https:// URLs in the interstitial, is never touched) and drops leading
 * indentation (safe: the function has no multi-line template literals, so no
 * string content lives in leading whitespace). Shared by build.mjs and
 * test/function.test.ts so the size gate and the deployed artifact never drift.
 */
export function stripForDeploy(src) {
	return (
		src
			.split('\n')
			.filter((line) => !line.trim().startsWith('//'))
			.map((line) => line.replace(/^[ \t]+/, ''))
			.join('\n')
			.replace(/\n{2,}/g, '\n')
			.trim() + '\n'
	);
}
