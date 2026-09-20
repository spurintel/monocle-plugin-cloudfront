/** Challenge, block and JSON pages for `/__mcl/*`. */

import { SCRIPT_CACHE_SECONDS } from '../shared/constants';
import { REFUSAL_HEADERS, edgeResponse, toHeaders } from './http';
import type { Runtime } from './runtime';
import { blockPage, interstitialPage, resubmitPage, unavailablePage } from '@spur.us/monocle-edge-core';
import type { EdgeResponse } from './types';

export function coreUrlFor(coreScriptUrl: string, sid?: string): string {
	return sid ? `${coreScriptUrl}&cpd=${encodeURIComponent(sid)}` : coreScriptUrl;
}

export function interstitialResponse(
	runtime: Runtime,
	method: string,
	ipBinding: string | null,
	status: 503 | 200
): EdgeResponse {
	const headers: Record<string, string> = {
		...REFUSAL_HEADERS,
		'Content-Type': 'text/html; charset=utf-8',
	};
	if (status === 503) headers['Retry-After'] = '5';
	if (ipBinding === null) {
		headers['Retry-After'] = '10';
		return edgeResponse(
			503,
			toHeaders(headers),
			method === 'HEAD' ? null : unavailablePage()
		);
	}
	// The page at /__mcl/challenge is the same for every visitor (it reads its
	// return path client-side), so it can sit in the CloudFront cache. Vary is the
	// refusal set's, meaningless on a public object keyed by URL alone.
	if (status === 200) {
		headers['Cache-Control'] = `public, max-age=${SCRIPT_CACHE_SECONDS}`;
		delete headers['Vary'];
	}
	return edgeResponse(
		status,
		toHeaders(headers),
		method === 'HEAD' ? null : interstitialPage({ coreUrl: coreUrlFor(runtime.coreScriptUrl) })
	);
}

/** The Function's 403 shell lands here for a cookieless POST navigation. */
export function resubmitResponse(method: string): EdgeResponse {
	return edgeResponse(
		403,
		toHeaders({ ...REFUSAL_HEADERS, 'Content-Type': 'text/html; charset=utf-8' }),
		method === 'HEAD' ? null : resubmitPage()
	);
}

export function blockPageResponse(runtime: Runtime, method: string): EdgeResponse {
	const blockConfig = runtime.live.blockPage;
	const title = blockConfig.title || 'Access denied';
	const message =
		blockConfig.message || 'This request has been blocked by the site’s security policy.';
	return edgeResponse(
		blockStatus(runtime),
		toHeaders({ ...REFUSAL_HEADERS, 'Content-Type': 'text/html; charset=utf-8' }),
		method === 'HEAD' ? null : blockPage(title, message)
	);
}

function blockStatus(runtime: Runtime): number {
	const status = runtime.live.blockPage.status;
	return status === 401 || status === 404 ? status : 403;
}
