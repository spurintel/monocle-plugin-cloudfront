/** Baked secrets and the live KVS config as the endpoint runtime, cached per container. */

import {
	BLOCK_STATUSES,
	COOKIE_SCOPE,
	coreScriptUrl,
	DEFAULT_CORE_HOST,
	scriptSegment,
	type BlockPageConfig,
	type BlockStatus,
	type EndpointRuntime,
} from '@spur.us/monocle-edge-core';

import { KVS_CACHE_MS } from '../shared/constants';
import { createHmacSealer } from '../shared/hmac-sealer';
import type { BakedConfig } from './config';
import { readChunks } from './kvs';
import type { Kvs } from './types';

export interface LiveConfig {
	sessionTracking: boolean;
	blockPage: BlockPageConfig | undefined;
	customDomain?: string;
	clearanceVersion: string;
	cfgRaw: string;
	hosts: string[];
}

export interface Runtime extends EndpointRuntime {
	baked: BakedConfig;
	live: LiveConfig;
}

let cached: { until: number; identity: string; runtime: Runtime } | undefined;

export async function getRuntime(baked: BakedConfig, kvs: Kvs, now = Date.now()): Promise<Runtime> {
	const identity = `${baked.cookieSecret}|${baked.deploymentId}|${baked.publishableKey}|${baked.secretKey}`;
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
	const customDomain =
		typeof parsed.custom_domain === 'string' && parsed.custom_domain ? parsed.custom_domain : undefined;
	const live: LiveConfig = {
		sessionTracking: parsed.session_tracking === 'session' || parsed.session_tracking === true,
		blockPage: blockPageOf(parsed.block_page),
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
		clearanceVersion: cv,
		scope: COOKIE_SCOPE,
		secretKey: baked.secretKey,
		sessionTracking: live.sessionTracking,
		blockPage: live.blockPage,
		// The Function cannot inject, so the resident script never carries a redirect target.
		blockAsyncRedirect: false,
		coreHost,
		coreScriptUrl: coreScriptUrl(coreHost, baked.publishableKey),
		scriptSegment: await scriptSegment(baked.deploymentId, customDomain),
	};
	cached = { until: now + KVS_CACHE_MS, identity, runtime };
	return runtime;
}

/** The dashboard's `cfg.block_page`, in the shape the shared pages read. Anything else is the default page. */
function blockPageOf(raw: unknown): BlockPageConfig | undefined {
	if (!raw || typeof raw !== 'object') return undefined;
	const page = raw as { title?: unknown; message?: unknown; status?: unknown; redirect?: unknown };
	if (typeof page.redirect === 'string' && page.redirect) return { redirect: page.redirect };
	const status = (BLOCK_STATUSES as readonly number[]).includes(page.status as number)
		? (page.status as BlockStatus)
		: undefined;
	return {
		title: typeof page.title === 'string' ? page.title : '',
		message: typeof page.message === 'string' ? page.message : '',
		status,
	};
}

export function resetRuntimeCache(): void {
	cached = undefined;
}
