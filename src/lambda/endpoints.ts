/** `/__mcl/*` origin-request handlers. Never forward to origin. */

import { randomUUID } from 'node:crypto';

import {
	COOKIE_SCOPE,
	evaluateForEdge,
	mintSessionCookie,
	mintVerdictCookie,
	parseCookieHeader,
	PolicyFailure,
	readSessionCookie,
	validateVerdictCookie,
	type Verdict,
	type VerdictState,
	breakerOpen,
	breakerOpenUntil,
	recordPolicyFailure,
	recordPolicySuccess,
	takeAvailabilityProbe,
	residentScript,
} from '@spur.us/monocle-edge-core';

import { MAX_VERIFY_BODY_BYTES, SCRIPT_CACHE_SECONDS } from '../shared/constants';
import {
	cookieHeader,
	edgeResponse,
	headerValue,
	jsonResponse,
	originHeaderAllowed,
	REFUSAL_HEADERS,
	toHeaders,
} from './http';
import type { Kvs } from './types';
import { blockPageResponse, coreUrlFor, interstitialResponse, resubmitResponse } from './responses';
import type { Runtime } from './runtime';
import type { EdgeRequest, EdgeResponse } from './types';

export interface EndpointContext {
	runtime: Runtime;
	kvs: Kvs;
	request: EdgeRequest;
	connectingIp: string | null;
	ipBinding: string | null;
	distributionDomainName?: string;
	canonicalPath: string;
}

interface StateHint {
	verdict: 'allow' | 'block' | null;
	validUntil: number | null;
	renewalDue: boolean;
}

function stateHint(verdict: VerdictState, nowSeconds: number): StateHint {
	if (verdict.status === 'absent') return { verdict: null, validUntil: null, renewalDue: false };
	return {
		verdict: verdict.status,
		validUntil: verdict.payload.exp,
		renewalDue: verdict.status === 'allow' && verdict.payload.exp - nowSeconds < 300,
	};
}

function cookiesOf(request: EdgeRequest): Record<string, string> {
	return parseCookieHeader(cookieHeader(request.headers));
}

function readVerdict(ctx: EndpointContext, cookies: Record<string, string>, nowSeconds: number) {
	return validateVerdictCookie({
		sealer: ctx.runtime.sealer,
		audience: ctx.runtime.audience,
		cookieValue: cookies[COOKIE_SCOPE.names.verdict],
		ipBinding: ctx.ipBinding,
		nowSeconds,
		clearanceVersion: ctx.runtime.live.clearanceVersion,
	});
}

export async function handleMclEndpoint(ctx: EndpointContext): Promise<EdgeResponse> {
	const method = (ctx.request.method || 'GET').toUpperCase();
	if (ctx.canonicalPath === '/__mcl/verify' && method === 'POST') {
		const origin = headerValue(ctx.request.headers, 'origin');
		const site = (headerValue(ctx.request.headers, 'sec-fetch-site') ?? '').toLowerCase();
		// The deployment's hosts, plus the distribution's own domain. Never the
		// origin-request Host, which names the customer's origin, not a viewer host.
		const allowed = [...ctx.runtime.live.hosts];
		if (ctx.distributionDomainName) allowed.push(ctx.distributionDomainName.toLowerCase());
		const anyHostname = ctx.runtime.live.hosts.length === 0;
		if (!originHeaderAllowed(origin, site, allowed, anyHostname))
			return jsonResponse({ error: 'origin' }, 403);
		return handleVerify(ctx);
	}
	if (ctx.canonicalPath === '/__mcl/state' && method === 'GET') return handleState(ctx);
	if (ctx.canonicalPath === '/__mcl/challenge' && (method === 'GET' || method === 'HEAD')) {
		return interstitialResponse(ctx.runtime, method, ctx.ipBinding, 200);
	}
	if (ctx.canonicalPath === '/__mcl/blocked' && (method === 'GET' || method === 'HEAD')) {
		return blockPageResponse(ctx.runtime, method);
	}
	// A navigation-shaped unsafe method without clearance: the action has not run.
	if (ctx.canonicalPath === '/__mcl/resubmit' && (method === 'GET' || method === 'HEAD')) {
		return resubmitResponse(method);
	}
	if (
		ctx.canonicalPath === `/__mcl/${ctx.runtime.scriptSegment}/mcl.js` &&
		method === 'GET'
	)
		return handleEdgeBundle(ctx);

	return edgeResponse(404, toHeaders({ 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex' }), null);
}

/**
 * Renewal timing, confirmation the browser kept its cookie, and the session id.
 * Issues no clearance. The challenge page and resident script are cacheable on
 * CloudFront, so unlike the Worker they cannot carry the session tag in their
 * URL; they read `sid` here and append `cpd` themselves before loading the core.
 * The session cookie is attribution only, never a credential.
 */
async function handleState(ctx: EndpointContext): Promise<EdgeResponse> {
	const nowSeconds = Math.floor(Date.now() / 1000);
	const cookies = cookiesOf(ctx.request);
	const hint = stateHint(await readVerdict(ctx, cookies, nowSeconds), nowSeconds);
	if (ctx.ipBinding === null) return jsonResponse({ error: 'unbindable', hint }, 403);
	const session = await sessionTag(ctx, cookies, nowSeconds);
	const extra = session.setCookie ? [{ key: 'Set-Cookie', value: session.setCookie }] : [];
	return edgeResponse(
		200,
		toHeaders({ ...REFUSAL_HEADERS, 'Content-Type': 'application/json' }, extra),
		// `ip` is the address this Lambda evaluates the assessment against and binds
		// the cookie to - the caller's own, so it reveals nothing to them. It is here
		// so a live deployment can be checked with one curl when a verdict looks wrong.
		JSON.stringify({ hint, degraded: breakerOpen(), sid: session.sid, ip: ctx.connectingIp })
	);
}

/** The session id to tag assessments with, minting the cookie when none is held. Null when tracking is off. */
async function sessionTag(
	ctx: EndpointContext,
	cookies: Record<string, string>,
	nowSeconds: number
): Promise<{ sid: string | null; setCookie: string | null }> {
	if (!ctx.runtime.live.sessionTracking) return { sid: null, setCookie: null };
	const session = await readSessionCookie({
		sealer: ctx.runtime.sealer,
		audience: ctx.runtime.audience,
		cookieValue: cookies[COOKIE_SCOPE.names.session],
		nowSeconds,
	});
	if (session) return { sid: session.sid, setCookie: null };
	const sid = randomUUID();
	return {
		sid,
		setCookie: await mintSessionCookie({
			sealer: ctx.runtime.sealer,
			audience: ctx.runtime.audience,
			scope: COOKIE_SCOPE,
			sid,
			nowSeconds,
		}),
	};
}

async function handleVerify(ctx: EndpointContext): Promise<EdgeResponse> {
	const nowSeconds = Math.floor(Date.now() / 1000);
	if (ctx.ipBinding === null || ctx.connectingIp === null)
		return jsonResponse({ error: 'unbindable' }, 403);

	const contentType = (headerValue(ctx.request.headers, 'content-type') ?? '').split(';')[0]!.trim();
	if (contentType !== 'application/json') return jsonResponse({ error: 'content_type' }, 415);

	if (ctx.request.body?.inputTruncated) return jsonResponse({ error: 'invalid' }, 413);
	let raw: Buffer;
	try {
		raw = Buffer.from(ctx.request.body?.data ?? '', ctx.request.body?.encoding === 'base64' ? 'base64' : 'utf8');
	} catch {
		return jsonResponse({ error: 'invalid' }, 400);
	}
	if (raw.byteLength > MAX_VERIFY_BODY_BYTES) return jsonResponse({ error: 'invalid' }, 413);

	let body: unknown;
	try {
		body = JSON.parse(raw.toString('utf8'));
	} catch {
		return jsonResponse({ error: 'invalid' }, 400);
	}
	const captchaData =
		body && typeof body === 'object' && !Array.isArray(body)
			? (body as { captchaData?: unknown }).captchaData
			: undefined;
	if (typeof captchaData !== 'string' || !captchaData) return jsonResponse({ error: 'invalid' }, 400);

	const cookies = cookiesOf(ctx.request);
	const verdictState = await readVerdict(ctx, cookies, nowSeconds);
	if (verdictState.status === 'block') {
		return jsonResponse({ blocked: true, reason: 'policy_block' }, 403);
	}
	if (verdictState.status === 'allow' && verdictState.payload.exp - nowSeconds >= 300)
		return jsonResponse({ verdict: 'allow', hint: stateHint(verdictState, nowSeconds) }, 200);

	const session = await readSessionCookie({
		sealer: ctx.runtime.sealer,
		audience: ctx.runtime.audience,
		cookieValue: cookies[COOKIE_SCOPE.names.session],
		nowSeconds,
	});
	const sid =
		(verdictState.status === 'allow' ? verdictState.payload.sid : session?.sid) ?? randomUUID();

	const releaseProbe = takeAvailabilityProbe();
	if (!releaseProbe) return jsonResponse({ retryable: true, degraded: true }, 503, { 'Retry-After': '15' });

	let verdict: Verdict;
	try {
		try {
			const result = await evaluateForEdge(captchaData, ctx.connectingIp, ctx.runtime.baked.secretKey);
			recordPolicySuccess();
			if (result === 'needs_complete') return jsonResponse({ needsComplete: true }, 202);
			verdict = result;
		} catch (error) {
			if (error instanceof PolicyFailure && error.availability) {
				recordPolicyFailure();
				return jsonResponse({ retryable: true, degraded: breakerOpen() }, 503, { 'Retry-After': '5' });
			}
			const status = error instanceof PolicyFailure && error.status === 429 ? 429 : 422;
			return jsonResponse({ error: 'assessment_rejected', retryable: status === 429 }, status, {
				'Retry-After': '5',
			});
		}
	} finally {
		releaseProbe();
		await persistBreaker(ctx.kvs);
	}

	const minted = await mintVerdictCookie({
		sealer: ctx.runtime.sealer,
		audience: ctx.runtime.audience,
		scope: COOKIE_SCOPE,
		ipBinding: ctx.ipBinding,
		verdict,
		sid,
		jti: randomUUID(),
		nowSeconds,
		clearanceVersion: ctx.runtime.live.clearanceVersion,
	});
	const extra = [{ key: 'Set-Cookie', value: minted.setCookie }];
	if (ctx.runtime.live.sessionTracking && !session) {
		extra.push({
			key: 'Set-Cookie',
			value: await mintSessionCookie({
				sealer: ctx.runtime.sealer,
				audience: ctx.runtime.audience,
				scope: COOKIE_SCOPE,
				sid,
				nowSeconds,
			}),
		});
	}

	if (verdict === 'block') {
		return edgeResponse(
			403,
			toHeaders({ ...REFUSAL_HEADERS, 'Content-Type': 'application/json' }, extra),
			JSON.stringify({ blocked: true, reason: 'policy_block' })
		);
	}
	const hint: StateHint = { verdict: 'allow', validUntil: minted.payload.exp, renewalDue: false };
	return edgeResponse(
		200,
		toHeaders({ ...REFUSAL_HEADERS, 'Content-Type': 'application/json' }, extra),
		JSON.stringify({ verdict: 'allow', hint })
	);
}

/**
 * Mirrors the breaker into KVS for the Function, on transitions only. Every
 * container has its own breaker and every write competes with the dashboard's
 * ETag chain, so a write per verify would churn; a lost write costs at most a
 * grace period of degraded passes.
 */
let persistedOpen = false;
async function persistBreaker(kvs: Kvs): Promise<void> {
	const until = breakerOpenUntil();
	const open = until !== null;
	if (open === persistedOpen) return;
	try {
		if (open) await kvs.update([{ key: 'brk', value: String(until) }]);
		else await kvs.update([], ['brk']);
		persistedOpen = open;
	} catch (error) {
		console.error(`Failed to persist breaker: ${String(error)}`);
	}
}

/** Test hook. */
export function resetPersistedBreaker(): void {
	persistedOpen = false;
}

async function handleEdgeBundle(ctx: EndpointContext): Promise<EdgeResponse> {
	const script = residentScript(coreUrlFor(ctx.runtime.coreScriptUrl), null);
	return edgeResponse(
		200,
		toHeaders({
			'Content-Type': 'text/javascript',
			// Static per segment: the segment rotates whenever the script would differ.
			'Cache-Control': `public, max-age=${SCRIPT_CACHE_SECONDS}`,
			'X-Content-Type-Options': 'nosniff',
		}),
		script
	);
}
