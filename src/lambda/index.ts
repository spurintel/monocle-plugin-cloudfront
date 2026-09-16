/**
 * Lambda@Edge origin-request handler for `/__mcl/*`, plus the hourly crawler
 * refresh when EventBridge Scheduler invokes the same function in us-east-1.
 */

import { bindingForm, canonicalizePath, InvalidPathError, isMclPath } from '@spur.us/monocle-edge-core';

import { loadConfig, type BakedConfig } from './config';
import { refreshCrawlerRanges } from './crawler';
import { handleMclEndpoint } from './endpoints';
import { edgeResponse, jsonResponse, toHeaders } from './http';
import { createKvs } from './kvs';
import { getRuntime } from './runtime';
import { unavailablePage } from './templates';
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
	try {
		if (isCrawlerRefresh(event)) {
			const config = deps?.config ?? loadConfig();
			const kvs = deps?.kvs ?? createKvs(config.kvsArn);
			await refreshCrawlerRanges(kvs);
			return { ok: true };
		}
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
	const request = event.Records[0]?.cf.request;
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

	const runtime = await getRuntime(config, kvs);
	const connectingIp = request.clientIp || null;
	return handleMclEndpoint({
		runtime,
		kvs,
		request,
		connectingIp,
		ipBinding: connectingIp ? bindingForm(connectingIp) : null,
		distributionDomainName: event.Records[0]?.cf.config?.distributionDomainName,
		canonicalPath,
	});
}

export { handleMclEndpoint };
export type { BakedConfig };
