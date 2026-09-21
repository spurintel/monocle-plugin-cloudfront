/** CloudFront event shapes to and from the Fetch API the shared endpoints speak. */

import type { EdgeHeaders, EdgeRequest, EdgeResponse } from './types';

const STATUS_TEXT: Record<string, string> = {
	'200': 'OK',
	'202': 'Accepted',
	'303': 'See Other',
	'307': 'Temporary Redirect',
	'400': 'Bad Request',
	'403': 'Forbidden',
	'404': 'Not Found',
	'413': 'Payload Too Large',
	'415': 'Unsupported Media Type',
	'422': 'Unprocessable Entity',
	'429': 'Too Many Requests',
	'503': 'Service Unavailable',
};

export const REFUSAL_HEADERS: Record<string, string> = {
	'Cache-Control': 'no-store',
	'X-Robots-Tag': 'noindex',
	'Vary': 'Sec-Fetch-Mode, Accept',
	'X-Frame-Options': 'DENY',
	'Content-Security-Policy': "frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
	'Referrer-Policy': 'no-referrer',
	'X-Content-Type-Options': 'nosniff',
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

export function jsonResponse(
	body: unknown,
	status: number,
	extra: Record<string, string> = {}
): EdgeResponse {
	return edgeResponse(
		status,
		toHeaders({ ...REFUSAL_HEADERS, 'Content-Type': 'application/json', ...extra }),
		JSON.stringify(body)
	);
}

export function headerValue(headers: EdgeHeaders, name: string): string | undefined {
	return headers[name.toLowerCase()]?.[0]?.value;
}

/** The viewer's request as a Fetch API Request. `host` is only for the URL; nothing routes on it. */
export function toRequest(request: EdgeRequest, host: string): Request {
	const headers = new Headers();
	for (const [name, values] of Object.entries(request.headers)) {
		// CloudFront may split cookies into several entries; a Cookie header joins with `; `.
		if (name === 'cookie') headers.set('Cookie', values.map((h) => h.value).join('; '));
		else for (const header of values) headers.append(header.key ?? name, header.value);
	}
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
