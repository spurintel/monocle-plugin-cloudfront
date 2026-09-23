/** CloudFront event shapes to and from the Fetch API the shared endpoints speak. */

import { jsonResponse as coreJsonResponse } from '@spur.us/monocle-edge-core';

import type { EdgeHeaders, EdgeRequest, EdgeResponse } from './types';

const STATUS_TEXT: Record<string, string> = {
	'200': 'OK',
	'202': 'Accepted',
	'303': 'See Other',
	'307': 'Temporary Redirect',
	'400': 'Bad Request',
	'401': 'Unauthorized',
	'403': 'Forbidden',
	'404': 'Not Found',
	'413': 'Payload Too Large',
	'415': 'Unsupported Media Type',
	'422': 'Unprocessable Entity',
	'429': 'Too Many Requests',
	'503': 'Service Unavailable',
};

export function toHeaders(
	base: Record<string, string>,
	extra: { key: string; value: string }[] = []
): EdgeHeaders {
	const headers: EdgeHeaders = {};
	for (const [key, value] of Object.entries(base)) {
		headers[key.toLowerCase()] = [{ key, value }];
	}
	for (const h of extra) {
		const name = h.key.toLowerCase();
		(headers[name] ??= []).push({ key: h.key, value: h.value });
	}
	return headers;
}

export function edgeResponse(
	status: number,
	headers: EdgeHeaders,
	body: string | null
): EdgeResponse {
	const code = String(status);
	const response: EdgeResponse = {
		status: code,
		statusDescription: STATUS_TEXT[code] ?? 'OK',
		headers,
	};
	if (body !== null) response.body = body;
	return response;
}

/** Edge-core's JSON answer, with the headers every Monocle response carries. */
export function jsonResponse(body: unknown, status: number): Promise<EdgeResponse> {
	return fromResponse(coreJsonResponse(body, status));
}

export function headerValue(headers: EdgeHeaders, name: string): string | undefined {
	return headers[name.toLowerCase()]?.[0]?.value;
}

/**
 * The viewer's request as a Fetch API Request. `host` is only for the URL; nothing routes on
 * it. CloudFront hands over header values as text, and a Fetch header refuses one above
 * U+00FF, so a value it cannot hold is left out rather than failing the request: a site
 * cookie in UTF-8 must never cost the visitor verify.
 */
export function toRequest(request: EdgeRequest, host: string): Request {
	const headers = new Headers();
	const keep = (name: string, value: string) => {
		try {
			headers.append(name, value);
		} catch {
			// No endpoint reads a value a Fetch header cannot hold.
		}
	};
	for (const [name, values] of Object.entries(request.headers)) {
		if (name !== 'cookie') for (const header of values) keep(header.key ?? name, header.value);
	}
	// The endpoints read only our own cookies, whose values are plain ASCII. CloudFront may
	// split the header into several entries, and one Cookie header joins them with `; `.
	const ours = (request.headers.cookie ?? [])
		.flatMap((h) => h.value.split(';'))
		.map((part) => part.trim())
		.filter((cookie) => /^__(Host|Secure)-mcl_[\x21-\x7e]*$/.test(cookie));
	if (ours.length) keep('Cookie', ours.join('; '));
	const method = (request.method || 'GET').toUpperCase();
	const body =
		request.body?.data !== undefined && method !== 'GET' && method !== 'HEAD'
			? Buffer.from(request.body.data, request.body.encoding === 'base64' ? 'base64' : 'utf8')
			: undefined;
	const query = request.querystring ? `?${request.querystring}` : '';
	return new Request(`https://${host}${request.uri}${query}`, { method, headers, body });
}

/** A Fetch API Response as a CloudFront generated response. */
export async function fromResponse(response: Response): Promise<EdgeResponse> {
	const headers: EdgeHeaders = {};
	response.headers.forEach((value, name) => {
		if (name !== 'set-cookie') headers[name] = [{ key: headerKey(name), value }];
	});
	for (const value of response.headers.getSetCookie()) {
		(headers['set-cookie'] ??= []).push({ key: 'Set-Cookie', value });
	}
	const body = await response.text();
	return edgeResponse(response.status, headers, body.length ? body : null);
}

function headerKey(name: string): string {
	return name
		.split('-')
		.map((part) => part.charAt(0).toUpperCase() + part.slice(1))
		.join('-');
}
