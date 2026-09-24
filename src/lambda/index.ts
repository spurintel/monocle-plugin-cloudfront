/**
 * Lambda@Edge origin-request handler for `/__mcl/*`, plus the hourly crawler refresh when
 * EventBridge Scheduler invokes the same function in us-east-1. The endpoints are edge-core's;
 * this file converts CloudFront's event shapes and supplies the platform pieces.
 */

import {
	bindingForm,
	canonicalizePath,
	handleMclEndpoint,
	InvalidPathError,
	isMclPath,
	unavailablePage,
} from '@spur.us/monocle-edge-core';

import { SCRIPT_CACHE_SECONDS } from '../shared/constants';
import { containerBreaker } from './breaker';
import { loadConfig, type BakedConfig } from './config';
import { refreshCrawlerRanges } from './crawler';
import { edgeResponse, fromResponse, headerValue, jsonResponse, toHeaders, toRequest } from './http';
import { createKvs } from './kvs';
import { getRuntime, honoursClearance } from './runtime';
import type { CloudFrontOriginRequestEvent, EdgeResponse, Kvs } from './types';

export interface HandlerDeps {
	config: BakedConfig;
	kvs: Kvs;
}

function isCrawlerRefresh(event: unknown): boolean {
	return !!event && typeof event === 'object' && (event as { refresh?: unknown }).refresh === 'crawlers';
}

function isOriginRequest(event: unknown): event is CloudFrontOriginRequestEvent {
	return !!event && typeof event === 'object' && Array.isArray((event as CloudFrontOriginRequestEvent).Records);
}

export async function handler(event: unknown, deps?: HandlerDeps): Promise<EdgeResponse | { ok: true }> {
	// The schedule's own retry and dead-letter handling are the only thing watching
	// the refresh, and they read a returned value as success. A refresh that failed
	// must therefore fail the invocation: a snapshot silently left to expire stops
	// exempting search engines a day later, with nothing logged to say why.
	if (isCrawlerRefresh(event)) {
		const config = deps?.config ?? loadConfig();
		const kvs = deps?.kvs ?? createKvs(config.kvsArn);
		await refreshCrawlerRanges(kvs);
		return { ok: true };
	}
	try {
		if (!isOriginRequest(event)) {
			console.error('Monocle Lambda received an unknown event shape');
			return jsonResponse({ error: 'invalid' }, 400);
		}
		return await handleOriginRequest(event, deps);
	} catch (error) {
		console.error(`Monocle Lambda failed: ${String(error)}`);
		return edgeResponse(
			503,
			toHeaders({
				'Cache-Control': 'no-store',
				'Content-Type': 'text/html; charset=utf-8',
			}),
			unavailablePage(),
		);
	}
}

/** Core logic with config injected: the unit-testable seam. */
export async function handleOriginRequest(
	event: CloudFrontOriginRequestEvent,
	deps?: HandlerDeps
): Promise<EdgeResponse> {
	const config = deps?.config ?? loadConfig();
	const kvs = deps?.kvs ?? createKvs(config.kvsArn);
	const record = event.Records[0];
	const request = record?.cf.request;
	if (!request) return jsonResponse({ error: 'invalid' }, 400);

	let canonicalPath: string;
	try {
		canonicalPath = canonicalizePath(request.uri || '/');
	} catch (error) {
		if (error instanceof InvalidPathError) {
			return edgeResponse(400, toHeaders({ 'Cache-Control': 'no-store', 'Content-Type': 'text/plain; charset=utf-8' }), '');
		}
		throw error;
	}

	if (!isMclPath(canonicalPath)) {
		return jsonResponse({ error: 'not_found' }, 404);
	}
	// A body CloudFront truncated is never handed to verify: a fragment would parse as a bad bundle.
	if (request.body?.inputTruncated) return jsonResponse({ error: 'invalid' }, 413);

	const runtime = await getRuntime(config, kvs);
	const connectingIp = request.clientIp || null;
	const distributionDomain = record.cf.config?.distributionDomainName?.toLowerCase();
	// The distribution's names at deploy, the deployment's own among them, and its domain. Never
	// the origin-request Host, which names the customer's origin, not a viewer host. An alias
	// added since passes on the browser's same-origin statement, which edge-core accepts alongside.
	const allowedOrigins = [...new Set([...(config.hosts ?? []), ...(distributionDomain ? [distributionDomain] : [])])];
	// CloudFront keeps one cache entry for GET and HEAD, so a HEAD answered without a body on a
	// cached page would leave it empty for every GET until it expired. There a HEAD is answered
	// as a GET, and CloudFront sends the viewer the headers alone.
	const cachedPage = canonicalPath === '/__mcl/challenge' || /^\/__mcl\/[^/]+\/mcl\.js$/.test(canonicalPath);
	const viewerRequest = toRequest(
		cachedPage && (request.method || '').toUpperCase() === 'HEAD' ? { ...request, method: 'GET' } : request,
		distributionDomain ?? headerValue(request.headers, 'host') ?? 'localhost'
	);
	const response = await handleMclEndpoint(canonicalPath, {
		runtime,
		// The challenge page and the resident script sit in the CloudFront cache, which keeps even
		// a no-store answer for its minimum TTL under a key without the query, so they are always
		// the shared kind, carrying nothing of one visitor's. Built from defaults, they may be
		// wrong for the site, so they are cached for no longer than that minimum.
		platform: {
			breaker: containerBreaker(),
			sharedPages: { maxAgeSeconds: runtime.live.defaults ? 0 : SCRIPT_CACHE_SECONDS },
			acceptsClearance: honoursClearance,
		},
		request: viewerRequest,
		url: new URL(viewerRequest.url),
		connectingIp,
		ipBinding: connectingIp ? bindingForm(connectingIp) : null,
		allowedOrigins,
	});
	return fromResponse(response);
}

export type { BakedConfig };
