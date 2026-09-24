/** Baked secrets and the live KVS config as the endpoint runtime, cached per container. */

import {
	ALLOW_TTL_SECONDS,
	BLOCK_STATUSES,
	BLOCK_TTL_SECONDS,
	COOKIE_SCOPE,
	coreScriptUrl,
	createHmacSealer,
	DEFAULT_CORE_HOST,
	scriptSegment,
	UNVERIFIED_PASS_SECONDS,
	type BlockPageConfig,
	type BlockStatus,
	type EndpointRuntime,
	type VerdictPayload,
} from '@spur.us/monocle-edge-core';

import { KVS_CACHE_MS, KVS_RETRY_MS, ROTATION_GRACE_SECONDS } from '../shared/constants';
import type { BakedConfig } from './config';
import { readChunks } from './kvs';
import type { Kvs } from './types';

export interface LiveConfig {
	sessionTracking: boolean;
	blockPage: BlockPageConfig | undefined;
	customDomain?: string;
	clearanceVersion: string;
	cfgRaw: string;
	/** Built without the store's config, so pages from it may be wrong for this site. */
	defaults?: boolean;
}

export interface Runtime extends EndpointRuntime {
	baked: BakedConfig;
	live: LiveConfig;
}

let cached: { until: number; identity: string; runtime: Runtime } | undefined;

/**
 * The store is read at most once per cache window: each read is a billed KeyValueStore API
 * call, and state is asked on every page view. A version rotated inside the window is
 * absorbed by the Function, which honours a cookie minted in the last six minutes on another
 * version, and by `honoursClearance`, which gives state and verify the same rule.
 *
 * A store that cannot be read is ours to absorb: the runtime this container last built stands,
 * whatever its age, with the clearance version if that much was read, since verify mints
 * against it and the Function validates against it. A container with none gets defaults, and
 * an empty clearance version unless it read one: verify still asks Policy, and core mints its
 * answer for ten minutes, which the Function accepts under an empty version. A visitor who
 * makes the store unreadable never skips Policy. The store is asked again only after
 * `KVS_RETRY_MS`, not on every request: each attempt may be billed, and a throttled store is
 * only throttled harder.
 */
export async function getRuntime(
	baked: BakedConfig,
	kvs: Kvs,
	{ now = Date.now() }: { now?: number } = {}
): Promise<Runtime> {
	const identity = `${baked.cookieSecret}|${baked.deploymentId}|${baked.publishableKey}|${baked.secretKey}`;
	const held = cached && cached.identity === identity ? cached : undefined;
	if (held && now < held.until) return held.runtime;

	let cv: string | undefined, cfgRaw: string;
	try {
		cv = (await kvs.get('cv')) ?? '';
		cfgRaw = (await readChunks(kvs, 'cfg')) ?? '{}';
	} catch (error) {
		console.warn(`monocle store unreadable: ${error instanceof Error ? error.name : 'unknown'}`);
		const live = held?.runtime.live;
		const runtime =
			held && (cv === undefined || cv === held.runtime.clearanceVersion)
				? held.runtime
				: await build(baked, cv ?? '', live?.cfgRaw ?? '{}', {
						defaults: !live || live.defaults === true,
					});
		cached = { until: now + KVS_RETRY_MS, identity, runtime };
		return runtime;
	}
	const runtime = await build(baked, cv, cfgRaw, {});
	cached = { until: now + KVS_CACHE_MS, identity, runtime };
	return runtime;
}

async function build(
	baked: BakedConfig,
	cv: string,
	cfgRaw: string,
	{ defaults = false }: { defaults?: boolean }
): Promise<Runtime> {
	let parsed: { session_tracking?: unknown; block_page?: unknown; custom_domain?: unknown } = {};
	try {
		parsed = JSON.parse(cfgRaw) as typeof parsed;
	} catch {
		parsed = {};
	}
	const customDomain =
		typeof parsed.custom_domain === 'string' && parsed.custom_domain ? parsed.custom_domain : undefined;
	const live: LiveConfig = {
		sessionTracking: parsed.session_tracking === 'session' || parsed.session_tracking === true,
		blockPage: blockPageOf(parsed.block_page),
		customDomain,
		clearanceVersion: cv,
		cfgRaw,
		...(defaults && { defaults }),
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

/**
 * The Function's rule for a verdict cookie on another clearance version, so state and verify
 * answer as it does: the pass a container that could not read the store gives, an allow with at
 * most ten minutes left, or a cookie minted in the last six minutes, by a container that had
 * not yet read a rotation.
 */
export function honoursClearance(payload: VerdictPayload, nowSeconds: number): boolean {
	if (payload.clearanceVersion === '')
		return payload.verdict === 'allow' && payload.exp <= nowSeconds + UNVERIFIED_PASS_SECONDS;
	const ttl = payload.verdict === 'allow' ? ALLOW_TTL_SECONDS : BLOCK_TTL_SECONDS;
	return payload.exp > nowSeconds + ttl - ROTATION_GRACE_SECONDS;
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
