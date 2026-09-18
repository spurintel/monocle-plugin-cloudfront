import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Deploy-time configuration baked into the Lambda bundle.
 *
 * Lambda@Edge has no environment variables. Secrets and the store ARN are
 * written next to the handler as `config.json` at deploy; everything a save
 * can change is read from KVS.
 */
export interface BakedConfig {
	secretKey: string;
	cookieSecret: string;
	publishableKey: string;
	deploymentId: string;
	kvsArn: string;
}

let cached: BakedConfig | null = null;

export function loadConfig(): BakedConfig {
	if (cached) return cached;
	const raw = readFileSync(join(__dirname, 'config.json'), 'utf8');
	cached = JSON.parse(raw) as BakedConfig;
	return cached;
}

