import cf from 'cloudfront';

// CloudFront Function (viewer-request, JS runtime 2.0) — the per-request hot
// path. Validates the Monocle cookie's HMAC and either passes the request
// through untouched (verified / unprotected -> cache and origin behave exactly
// as before Monocle) or serves a minimal interstitial that runs the Monocle
// assessment and POSTs it to /__mcl/verify (a separate cache behavior handled
// by the Lambda@Edge half of this plugin, which mints the cookie).
//
// Constraints shaping this file (docs.aws.amazon.com/AmazonCloudFront/latest/
// DeveloperGuide/functions-javascript-runtime-20.html):
//  - hard 10 KB source limit (test/function.test.ts enforces headroom), so the
//    interstitial below is deliberately spartan and this file has no imports
//    beyond the runtime's own 'cloudfront' and 'crypto' modules;
//  - no network and no request-body access (that is why verification lives in
//    Lambda@Edge);
//  - crypto exposes ONLY createHash/createHmac — hence the HMAC cookie scheme
//    shared with monocle-plugin-fastly, never AES;
//  - Date.now() is frozen at function start, which is fine for an expiry check.
//
// Config comes from the associated CloudFront KeyValueStore (keys written by
// the Monocle dashboard; values <= 1 KB each, so protectedPaths overflows into
// numbered continuation keys):
//  - cookieSecret     hex HMAC key (also baked into the Lambda, which mints)
//  - publishableKey   Monocle publishable key for the interstitial script tag
//  - protectedPaths   JSON: { "<host>": ["/pattern*", ...] } (+ .1, .2, ... chunks)

var crypto = require('crypto');

var COOKIE_NAME = 'MCLVALID';
var VERIFY_PATH = '/__mcl/verify';

var kvs = cf.kvs();

async function handler(event) {
	var request = event.request;

	// Never intercept the verify endpoint. Its own cache behavior (Lambda@Edge)
	// should be the only route here, but if this function is ever attached to a
	// behavior that covers it, intercepting would dead-loop the challenge.
	if (request.uri === VERIFY_PATH) return request;

	var secret = await kvGet('cookieSecret');
	var cookie = request.cookies && request.cookies[COOKIE_NAME];
	if (secret && cookie && isValidCookie(cookie.value, event.viewer.ip, secret)) {
		return request;
	}

	var host = request.headers.host ? request.headers.host.value : '';
	if (!isProtected(host, request.uri, await readProtectedPaths())) return request;

	var publishableKey = (await kvGet('publishableKey')) || '';
	return {
		statusCode: 200,
		statusDescription: 'OK',
		headers: {
			'content-type': { value: 'text/html' },
			// Per-request and security-sensitive: never let a browser or
			// intermediary cache and re-serve a stale interstitial.
			'cache-control': { value: 'no-store, no-cache, must-revalidate' },
			pragma: { value: 'no-cache' }
		},
		body: interstitial(publishableKey)
	};
}

async function kvGet(key) {
	try {
		return await kvs.get(key);
	} catch (e) {
		return null;
	}
}

// protectedPaths may exceed the 1 KB KeyValueStore value cap; the dashboard
// then writes numbered continuation keys and this concatenates them in order.
async function readProtectedPaths() {
	var raw = await kvGet('protectedPaths');
	if (raw === null) return undefined;
	var i = 1;
	while (true) {
		var chunk = await kvGet('protectedPaths.' + i);
		if (chunk === null) break;
		raw += chunk;
		i++;
	}
	try {
		return JSON.parse(raw);
	} catch (e) {
		// Corrupt config fails SAFE (undefined => everything protected below);
		// it must never silently disable Monocle.
		return undefined;
	}
}

// Mirrors shared/cookies.ts validateCookieValue — the Lambda mints, this
// verifies. test/function.test.ts pins both against the same vectors.
function isValidCookie(value, clientIp, secretHex) {
	try {
		var parts = value.split('.');
		if (parts.length !== 2 || !parts[0] || !parts[1]) return false;
		var payload = Buffer.from(parts[0], 'hex');
		var expected = crypto
			.createHmac('sha256', Buffer.from(secretHex, 'hex'))
			.update(payload)
			.digest('hex');
		if (expected !== parts[1].toLowerCase()) return false;

		var decoded = payload.toString('utf8').split('|');
		var boundIp = decoded[0];
		var expiry = parseInt(decoded[1] || '0', 10);
		// An empty bound IP means the cookie was issued IP-unbound; skip the
		// comparison rather than failing a cookie that could never match.
		if (boundIp !== '' && boundIp !== clientIp) return false;
		if (Math.floor(Date.now() / 1000) >= expiry) return false;
		return true;
	} catch (e) {
		return false;
	}
}

// Compact copy of shared/paths.ts semantics: '*' wildcards; missing config or
// unlisted host fails SAFE (protected); case- and percent-insensitive.
function isProtected(host, path, protectedPaths) {
	if (!protectedPaths) return true;
	var patterns = protectedPaths[host.toLowerCase()];
	if (!patterns) return true;
	try {
		path = decodeURIComponent(path);
	} catch (e) {}
	path = path.toLowerCase();
	for (var i = 0; i < patterns.length; i++) {
		if (matchPattern(path, patterns[i].toLowerCase())) return true;
	}
	return false;
}

function matchPattern(path, pattern) {
	var parts = pattern.split('*');
	if (parts.length === 1) return path === pattern;
	if (path.indexOf(parts[0]) !== 0) return false;
	var last = parts[parts.length - 1];
	var limit = path.length;
	if (last !== '') {
		if (path.slice(-last.length) !== last) return false;
		limit = path.length - last.length;
	}
	var index = parts[0].length;
	for (var i = 1; i < parts.length - 1; i++) {
		var part = parts[i];
		if (part === '') continue;
		var found = path.indexOf(part, index);
		if (found === -1 || found + part.length > limit) return false;
		index = found + part.length;
	}
	return index <= limit;
}

// Minimal challenge page: run Monocle, POST the assessment to /__mcl/verify,
// then reload (the fresh request carries the newly minted cookie and passes
// straight through). Response contract matches the Fastly interstitial:
// X-Block-Action redirect:/html, 403 => denial text, anything else fails open.
function interstitial(publishableKey) {
	return '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Checking your connection</title><style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#fff;color:#000}.c{text-align:center;max-width:500px;padding:2rem}h1{font-size:1.1rem;font-weight:300}p{color:#6b7280}@media(prefers-color-scheme:dark){body{background:#000;color:#fff}}</style></head><body><div class="c"><h1>Checking your connection&hellip;</h1><p id="s">This only takes a moment.</p></div><script>function _mclDone(d){fetch("' +
		VERIFY_PATH +
		'",{method:"POST",headers:{"Content-Type":"application/json","X-MCL-Validate":"1"},body:JSON.stringify({captchaData:d})}).then(function(r){if(r.ok){location.reload();return}var a=r.headers.get("X-Block-Action");if(a&&a.indexOf("redirect:")===0){location.href=a.slice(9);return}if(a==="html"){r.text().then(function(h){document.open();document.write(h);document.close()});return}if(r.status===403){r.text().then(function(m){document.getElementById("s").textContent="Validation failed. "+(m&&m.trim()!==""?m:"Please disable any VPNs or proxies and try again")+"."});return}location.reload()}).catch(function(){document.getElementById("s").textContent="An error occurred. Please refresh and try again."})}var _t=document.createElement("script");_t.src="https://mcl.spur.us/d/mcl.js?tk=' +
		encodeURIComponent(publishableKey) +
		'";_t.id="_mcl";_t.async=true;_t.onload=function(){if(window.MCL)MCL.configure({onBundle:_mclDone})};document.head.appendChild(_t);</script></body></html>';
}
