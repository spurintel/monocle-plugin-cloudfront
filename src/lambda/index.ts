import { buildSetCookie } from '../shared/cookies';
import { escapeHtml } from '../shared/escape';
import { evaluateAssessment, MonocleAPIError } from '../shared/policy';
import { loadConfig, type MonocleLambdaConfig } from './config';

/**
 * Lambda@Edge (viewer-request, `IncludeBody: true`) for the `/__mcl/verify`
 * cache behavior, the ONLY behavior this function is associated with. The
 * interstitial served by the CloudFront Function POSTs the Monocle assessment
 * here; this calls the Policy API and mints the HMAC session cookie the
 * CloudFront Function validates on every subsequent request.
 *
 * Response rules that matter here (docs.aws.amazon.com/AmazonCloudFront/latest/
 * DeveloperGuide/lambda-generating-http-responses.html):
 *  - a generated 204 that carries a body is rejected as a 502, so success is
 *    `200` with a small text body;
 *  - viewer-request generated responses are capped at 40 KB (block pages are
 *    tiny);
 *  - the POSTed body arrives base64-encoded and truncated at 40 KB, ample for
 *    an encrypted Monocle assessment.
 */

// Minimal structural types for the Lambda@Edge event; only what's read here.
interface EdgeHeaders {
	[name: string]: { key?: string; value: string }[];
}
interface EdgeRequestEvent {
	Records: {
		cf: {
			request: {
				method: string;
				uri: string;
				clientIp: string;
				headers: EdgeHeaders;
				body?: { data?: string; encoding?: string; inputTruncated?: boolean };
			};
		};
	}[];
}
interface EdgeResponse {
	status: string;
	statusDescription?: string;
	headers?: EdgeHeaders;
	body?: string;
	bodyEncoding?: 'text' | 'base64';
}

export async function handler(event: EdgeRequestEvent): Promise<EdgeResponse> {
	let config: MonocleLambdaConfig;
	try {
		config = loadConfig();
	} catch (error) {
		console.error(`Monocle config missing/malformed in bundle: ${String(error)}`);
		return textResponse('500', 'Configuration error');
	}
	return handleVerify(event, config);
}

/** Core logic with config injected: the unit-testable seam. */
export async function handleVerify(
	event: EdgeRequestEvent,
	config: MonocleLambdaConfig
): Promise<EdgeResponse> {
	const request = event.Records[0]?.cf.request;
	if (!request || request.method !== 'POST') {
		return textResponse('405', 'Method not allowed');
	}

	let captchaData: string | undefined;
	try {
		const raw = Buffer.from(request.body?.data ?? '', 'base64').toString('utf8');
		captchaData = (JSON.parse(raw) as { captchaData?: string }).captchaData;
	} catch {
		return textResponse('400', 'Invalid request');
	}
	if (!captchaData) return textResponse('400', 'Invalid request');

	try {
		const decision = await evaluateAssessment(captchaData, config.secretKey);
		if (!decision.allowed) {
			return denyResponse(config);
		}
		return allowResponse(request.clientIp, config);
	} catch (error) {
		// A 4xx (other than the transient ones below) means the API is REACHABLE
		// and rejected THIS request: an undecryptable/invalid assessment or a bad
		// secretKey. Never mint on that; it would let an attacker POST junk to
		// /__mcl/verify and be waved through, and would silently disable the
		// challenge site-wide on a misconfigured key. Deny instead. 404 (no policy
		// = allow), 408 (request timeout) and 429 (rate limited) are transient, so
		// they stay fail-open below.
		if (
			error instanceof MonocleAPIError &&
			error.status >= 400 &&
			error.status < 500 &&
			![404, 408, 429].includes(error.status)
		) {
			console.error(`Policy API rejected the request (status ${error.status}); denying.`);
			return denyResponse(config);
		}
		// Genuine outage only (network/timeout/5xx), no policy (404), or a malformed
		// 2xx body: fail open and CRITICALLY set the cookie so the visitor isn't
		// trapped re-challenging while the API is down.
		if (!(error instanceof MonocleAPIError && error.status === 404)) {
			console.error(`Policy API error, failing open: ${String(error)}`);
		}
		return allowResponse(request.clientIp, config);
	}
}

/** Deny: the configured block response, or a plain 403 when none is set. */
function denyResponse(config: MonocleLambdaConfig): EdgeResponse {
	return config.blockResponseType ? buildBlockResponse(config) : textResponse('403', 'Blocked');
}

function allowResponse(clientIp: string | null, config: MonocleLambdaConfig): EdgeResponse {
	return {
		// 200 with a body, NEVER a bodied 204 (Lambda@Edge turns that into a 502).
		status: '200',
		statusDescription: 'OK',
		headers: {
			'set-cookie': [{ key: 'Set-Cookie', value: buildSetCookie(clientIp, config.cookieSecret) }],
			'cache-control': [{ key: 'Cache-Control', value: 'no-store' }],
		},
		body: 'Captcha validated successfully',
	};
}

function textResponse(status: string, body: string): EdgeResponse {
	return {
		status,
		headers: { 'cache-control': [{ key: 'Cache-Control', value: 'no-store' }] },
		body,
	};
}

/**
 * A block-redirect target is customer config, but must still be a plain http(s)
 * URL with no control bytes: a `javascript:`/`data:` value would run in the
 * interstitial's `location.href`, and any control byte (NUL, CR, LF) would
 * corrupt the header. An unsafe value falls back to the HTML block page instead.
 */
function isSafeRedirectUrl(url: string): boolean {
	if (/[\u0000-\u001f\u007f]/.test(url)) return false;
	try {
		const parsed = new URL(url);
		return parsed.protocol === 'http:' || parsed.protocol === 'https:';
	} catch {
		return false;
	}
}

/**
 * Deny response consumed by the interstitial's fetch handler (never a
 * navigation): X-Block-Action carries `redirect:<url>` or `html`, the same
 * contract as the Fastly/Cloudflare plugins.
 */
function buildBlockResponse(config: MonocleLambdaConfig): EdgeResponse {
	if (
		config.blockResponseType === 'redirect' &&
		config.blockRedirectUrl &&
		isSafeRedirectUrl(config.blockRedirectUrl)
	) {
		return {
			status: '403',
			headers: {
				'x-block-action': [{ key: 'X-Block-Action', value: `redirect:${config.blockRedirectUrl}` }],
				'cache-control': [{ key: 'Cache-Control', value: 'no-store' }],
			},
			body: '',
		};
	}

	// Block status must be 4xx/5xx: a 2xx makes the interstitial treat the block
	// as success (its `if (r.ok)` reload path) and loop instead of blocking.
	const parsedStatus = parseInt(config.blockStatusCode ?? '403', 10);
	const statusCode = String(parsedStatus >= 400 && parsedStatus <= 599 ? parsedStatus : 403);
	const title = escapeHtml(config.blockPageTitle ?? 'Access Denied');
	const body = escapeHtml(config.blockResponseBody ?? 'This request has been blocked');

	const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>${title}</title>
  <style>
    body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#fff;color:#000}
    .container{text-align:center;max-width:500px;padding:2rem}
    h1{font-size:1.3rem;font-weight:300;margin:0}
    p{color:#6b7280}
    @media(prefers-color-scheme:dark){body{background:#000;color:#fff}}
  </style>
</head>
<body>
  <div class="container">
    <h1>${title}</h1>
    <p>${body}</p>
  </div>
</body>
</html>`;

	return {
		status: statusCode,
		headers: {
			'content-type': [{ key: 'Content-Type', value: 'text/html' }],
			'x-block-action': [{ key: 'X-Block-Action', value: 'html' }],
			'cache-control': [{ key: 'Cache-Control', value: 'no-store' }],
		},
		body: html,
	};
}
