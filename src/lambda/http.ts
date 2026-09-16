import type { EdgeHeaders, EdgeResponse } from './types';

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

export function cookieHeader(headers: EdgeHeaders): string | null {
	const values = headers.cookie;
	if (!values?.length) return null;
	return values.map((h) => h.value).join('; ');
}

/** Viewer Host to HTTPS origin, matching how the Function strips a non-IPv6 port. */
export function requestOrigin(host: string): string {
	let name = host.toLowerCase();
	const colon = name.lastIndexOf(':');
	if (colon > 0 && name.indexOf(']') === -1) name = name.slice(0, colon);
	return `https://${name}`;
}

/** Origin-request Host is the origin's domain (S3) unless an origin-request policy forwards the viewer Host. */
export function isAwsOriginHostname(host: string): boolean {
	const name = host.toLowerCase().split(':')[0] ?? '';
	return name.endsWith('.amazonaws.com');
}

/** Site origin the browser used: viewer Host, else the distribution domain. */
export function viewerOrigin(hostHeader: string, distributionDomainName?: string): string {
	const host = isAwsOriginHostname(hostHeader)
		? (distributionDomainName ?? hostHeader)
		: hostHeader || distributionDomainName || '';
	return requestOrigin(host);
}

/** CSRF gate for POST /__mcl/verify. `site` is Sec-Fetch-Site, lowercased. */
export function originHeaderAllowed(
	originHeader: string | undefined,
	site: string,
	allowedHostnames: string[]
): boolean {
	if (site === 'cross-site' || site === 'same-site') return false;
	if (!originHeader) return false;
	let hostname: string;
	try {
		const url = new URL(originHeader);
		if (url.protocol !== 'https:') return false;
		hostname = url.hostname.toLowerCase();
	} catch {
		return false;
	}
	return allowedHostnames.includes(hostname);
}
