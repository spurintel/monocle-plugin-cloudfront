import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Deploy-time configuration baked into the Lambda bundle.
 *
 * Lambda@Edge supports NO environment variables and cannot read the CloudFront
 * KeyValueStore, so the Monocle dashboard writes a `config.json` next to the
 * built handler inside the deployment zip (the same bake-at-deploy approach the
 * Akamai plan settled on). Block-config changes therefore republish the Lambda;
 * path changes do not touch it (paths live in the KeyValueStore, read by the
 * CloudFront Function).
 */
export interface MonocleLambdaConfig {
	/** Monocle secret key: the Policy API bearer token. */
	secretKey: string;
	/** Hex HMAC key for the session cookie; the CloudFront Function verifies with the same value. */
	cookieSecret: string;
	/** Optional block response shown on a deny decision. */
	blockResponseType?: 'html' | 'redirect';
	blockStatusCode?: string;
	blockPageTitle?: string;
	blockResponseBody?: string;
	blockRedirectUrl?: string;
	/**
	 * When true, log the raw Policy API decision to CloudWatch (one JSON line
	 * per verify). Default off; toggled from the dashboard via Lambda republish.
	 */
	logAssessment?: boolean;
}

let cached: MonocleLambdaConfig | null = null;

export function loadConfig(): MonocleLambdaConfig {
	if (cached) return cached;
	// Read lazily (not import-time) so a malformed bake fails the request with a
	// log rather than killing the container at init, and so tests can inject.
	const raw = readFileSync(join(__dirname, 'config.json'), 'utf8');
	cached = JSON.parse(raw) as MonocleLambdaConfig;
	return cached;
}
