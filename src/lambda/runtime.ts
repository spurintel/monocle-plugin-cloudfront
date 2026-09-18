/** Compile baked secrets with the live KVS config, cached per container. */

import { createHash } from 'node:crypto';

import { COOKIE_SCOPE, RESIDENT_SCRIPT_VERSION, type Sealer } from '@spur.us/monocle-edge-core';

import { DEFAULT_CORE_HOST, KVS_CACHE_MS } from '../shared/constants';
import { createHmacSealer } from '../shared/hmac-sealer';
import type { BakedConfig } from './config';
import { readChunks } from './kvs';
import type { Kvs } from './types';

export interface BlockPageLive {
	title?: string;
	message?: string;
	status?: number;
	redirect?: string;
}

export interface LiveConfig {
	sessionTracking: boolean;
	blockPage: BlockPageLive;
	customDomain?: string;
	clearanceVersion: string;
	cfgRaw: string;
	hosts: string[];
}

export interface Runtime {
	baked: BakedConfig;
	live: LiveConfig;
	sealer: Sealer;
	audience: string;
	scope: typeof COOKIE_SCOPE;
	scriptSegment: string;
	coreHost: string;
	coreScriptUrl: string;
}

let cached:
	| { until: number; identity: string; runtime: Runtime }
	| undefined;

export async function getRuntime(baked: BakedConfig, kvs: Kvs, now = Date.now()): Promise<Runtime> {
	const identity = `${baked.cookieSecret}|${baked.deploymentId}|${baked.publishableKey}`;
	if (cached && cached.identity === identity && now < cached.until) return cached.runtime;

	const cv = (await kvs.get('cv')) ?? '';
	const cfgRaw = (await readChunks(kvs, 'cfg')) ?? '{}';
	const hostsRaw = (await readChunks(kvs, 'hosts')) ?? '[]';
	let parsed: { session_tracking?: unknown; block_page?: unknown; custom_domain?: unknown } = {};
	try {
		parsed = JSON.parse(cfgRaw) as typeof parsed;
	} catch {
		parsed = {};
	}
	let hosts: string[] = [];
	try {
		const parsedHosts = JSON.parse(hostsRaw) as unknown;
		if (Array.isArray(parsedHosts)) {
			hosts = parsedHosts.filter((h): h is string => typeof h === 'string').map((h) => h.toLowerCase());
		}
	} catch {
		hosts = [];
	}
	const blockPage =
		parsed.block_page && typeof parsed.block_page === 'object'
			? (parsed.block_page as BlockPageLive)
			: {};
	const customDomain =
		typeof parsed.custom_domain === 'string' && parsed.custom_domain ? parsed.custom_domain : undefined;
	const live: LiveConfig = {
		sessionTracking: parsed.session_tracking === 'session' || parsed.session_tracking === true,
		blockPage,
		customDomain,
		clearanceVersion: cv,
		cfgRaw,
		hosts,
	};
	const coreHost = customDomain ?? DEFAULT_CORE_HOST;
	const runtime: Runtime = {
		baked,
		live,
		sealer: createHmacSealer(baked.cookieSecret),
		audience: baked.deploymentId,
		scope: COOKIE_SCOPE,
		scriptSegment: deriveScriptSegment(baked.deploymentId, customDomain),
		coreHost,
		coreScriptUrl: `https://${coreHost}/d/mcl.js?tk=${encodeURIComponent(baked.publishableKey)}`,
	};
	cached = { until: now + KVS_CACHE_MS, identity, runtime };
	return runtime;
}

/**
 * The resident script's URL segment: only what its content depends on, so a
 * block-page edit never rotates a tag the customer has embedded. The dashboard
 * computes the same value for the manual-include snippet.
 */
export function deriveScriptSegment(deploymentId: string, customDomain = ''): string {
	return createHash('sha256')
		.update(`${deploymentId}|${RESIDENT_SCRIPT_VERSION}|${customDomain}`)
		.digest('hex')
		.slice(0, 16);
}

export function resetRuntimeCache(): void {
	cached = undefined;
}
