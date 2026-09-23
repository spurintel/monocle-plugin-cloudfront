/** Baked secrets and the live KVS config as the endpoint runtime, cached per container. */

import {
	BLOCK_STATUSES,
	COOKIE_SCOPE,
	coreScriptUrl,
	createHmacSealer,
	DEFAULT_CORE_HOST,
	scriptSegment,
	type BlockPageConfig,
	type BlockStatus,
	type EndpointRuntime,
} from '@spur.us/monocle-edge-core';

import { KVS_CACHE_MS } from '../shared/constants';
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
	/**
	 * The store could not be read and this container had nothing to fall back on, so the
	 * rest is defaults and the clearance version is unknown (empty).
	 */
	unread?: boolean;
}

export interface Runtime extends EndpointRuntime {
	baked: BakedConfig;
	live: LiveConfig;
}

let cached: { until: number; identity: string; runtime: Runtime } | undefined;

/**
 * `freshClearance` re-reads the clearance version inside the cache window. Verify mints
 * against it and state validates against it, and a container holding the one from before a
 * rotation mints cookies the Function refuses, or reports a fresh one as absent.
 *
 * A store that cannot be read is ours to absorb: the runtime this container last built stands,
 * whatever its age, with the clearance version if that much was read, since verify mints
 * against it and the Function validates against it. A container with none gets defaults,
 * marked `unread` unless the clearance version was read.
 */
export async function getRuntime(
	baked: BakedConfig,
	kvs: Kvs,
	{ now = Date.now(), freshClearance = false }: { now?: number; freshClearance?: boolean } = {}
): Promise<Runtime> {
	const identity = `${baked.cookieSecret}|${baked.deploymentId}|${baked.publishableKey}|${baked.secretKey}`;
	const held = cached && cached.identity === identity ? cached : undefined;
	if (held && now < held.until) {
		if (!freshClearance) return held.runtime;
		const version = held.runtime.clearanceVersion;
		if (((await kvs.get('cv').catch(() => version)) ?? '') === version) return held.runtime;
	}

	let cv: string | undefined, cfgRaw: string, hostsRaw: string;
	try {
		cv = (await kvs.get('cv')) ?? '';
		cfgRaw = (await readChunks(kvs, 'cfg')) ?? '{}';
		hostsRaw = (await readChunks(kvs, 'hosts')) ?? '[]';
	} catch (error) {
		console.warn(`monocle store unreadable: ${error instanceof Error ? error.name : 'unknown'}`);
		if (held && (cv === undefined || cv === held.runtime.clearanceVersion)) return held.runtime;
		const live = held?.runtime.live;
		return build(baked, cv ?? '', live?.cfgRaw ?? '{}', JSON.stringify(live?.hosts ?? []), cv === undefined);
	}
	const runtime = await build(baked, cv, cfgRaw, hostsRaw, false);
	cached = { until: now + KVS_CACHE_MS, identity, runtime };
	return runtime;
}

async function build(
	baked: BakedConfig,
	cv: string,
	cfgRaw: string,
	hostsRaw: string,
	unread: boolean
): Promise<Runtime> {
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
		...(unread && { unread }),
	};
	const coreHost = customDomain ?? DEFAULT_CORE_HOST;
	const runtime: Runtime = {
		baked,
		live,
		sealer: createHmacSealer(baked.cookieSecret),
		audience: baked.deploymentId,
		clearanceVersion: cv,
		scope: COOKIE_SCOPE,
		secretKey: async () => baked.secretKey,
		sessionTracking: live.sessionTracking,
		blockPage: live.blockPage,
		// The Function cannot inject, so the resident script never carries a redirect target.
		blockAsyncRedirect: false,
		coreHost,
		coreScriptUrl: coreScriptUrl(coreHost, baked.publishableKey),
		scriptSegment: await scriptSegment(baked.deploymentId, customDomain),
	};
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
