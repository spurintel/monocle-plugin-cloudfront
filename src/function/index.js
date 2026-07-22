import cf from 'cloudfront';

// CloudFront Function (viewer-request, JS runtime 2.0): the per-request hot
// path. Validates the Monocle cookie's HMAC and either passes the request
// through untouched (cache and origin behave exactly as before Monocle) or
// serves a minimal interstitial that runs Monocle and POSTs the assessment to
// /__mcl/verify, a separate cache behavior handled by this plugin's
// Lambda@Edge half, which mints the cookie.
//
// Runtime constraints shaping this file (docs.aws.amazon.com/AmazonCloudFront/
// latest/DeveloperGuide/functions-javascript-runtime-20.html):
//  - hard 10240-byte limit on the STRIPPED artifact (build.mjs fails over it; we
//    sit ~9740 bytes, having rounded the wordmark SVG coordinates to free room for
//    the Inter webfont link), so keep the interstitial lean and imports to 'cloudfront'/'crypto';
//  - no network and no request-body access, which is why verification lives
//    in Lambda@Edge;
//  - crypto exposes ONLY createHash/createHmac, hence the HMAC cookie scheme
//    shared with monocle-plugin-fastly, never AES;
//  - Date.now() is frozen at function start (fine for an expiry check);
//  - the KVS handle is acquired INSIDE the handler, never at module top level:
//    a throw during module init makes the function "invalid or could not run"
//    and 503s EVERY request, so all fallible work stays inside the fail-open try.
//
// Config comes from the associated CloudFront KeyValueStore (written by the
// Monocle dashboard; values <= 1 KB each, so protectedPaths overflows into
// numbered continuation keys):
//  - cookieSecret     hex HMAC key (also baked into the minting Lambda)
//  - publishableKey   Monocle publishable key for the interstitial script tag
//  - protectedPaths   JSON: { "<host>": ["/pattern*", ...] } (+ .1, .2, ... chunks)

var crypto = require('crypto');

var COOKIE_NAME = 'MCLVALID';
var VERIFY_PATH = '/__mcl/verify';

async function handler(event) {
	var request = event.request;
	try {
		// Never intercept the verify endpoint: if this function is ever attached
		// to a behavior covering it, intercepting would dead-loop the challenge.
		if (request.uri === VERIFY_PATH) return request;

		var kvs = cf.kvs();

		var secret = await kvGet(kvs, 'cookieSecret');
		var cookie = request.cookies && request.cookies[COOKIE_NAME];
		if (secret && cookie && isValidCookie(cookie.value, event.viewer.ip, secret)) {
			return request;
		}

		var host = request.headers.host ? request.headers.host.value : '';
		// NB: this runtime rejects `await` inside a call's arguments ("await in
		// arguments not supported"), a COMPILE error no try/catch can rescue. So
		// every await resolves into its own statement (build.mjs guards this).
		var paths = await readProtectedPaths(kvs);
		if (!isProtected(host, request.uri, paths)) return request;

		var publishableKey = (await kvGet(kvs, 'publishableKey')) || '';
		return {
			statusCode: 200,
			headers: {
				'content-type': { value: 'text/html' },
				// Per-request and security-sensitive: never let a browser or
				// intermediary cache and re-serve a stale interstitial. no-store is
				// the authoritative directive; legacy Pragma is dropped for size.
				'cache-control': { value: 'no-store, no-cache, must-revalidate' }
			},
			body: interstitial(publishableKey)
		};
	} catch (e) {
		// A broken function must NEVER take the customer's whole site down: on
		// any unexpected error fail OPEN (continue to cache/origin, degraded and
		// unprotected) rather than 503. Mirrors the Policy API fail-open stance.
		return request;
	}
}

async function kvGet(kvs, key) {
	try {
		return await kvs.get(key);
	} catch (e) {
		return null;
	}
}

// protectedPaths may exceed the 1 KB KeyValueStore value cap; the dashboard
// then writes numbered continuation keys and this concatenates them in order.
async function readProtectedPaths(kvs) {
	var raw = await kvGet(kvs, 'protectedPaths');
	if (raw === null) return undefined;
	var i = 1;
	while (true) {
		var chunk = await kvGet(kvs, 'protectedPaths.' + i);
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

// Mirrors shared/cookies.ts validateCookieValue (the Lambda mints, this
// verifies); test/function.test.ts pins both against the same vectors.
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
	// Wrong-typed patterns (not a clean string[]) fail SAFE: protection must
	// never silently drop, and a `.toLowerCase()` throw on a non-string would
	// escape to the outer catch, which fails OPEN. Only a clean string list
	// with no match lets the request through.
	if (!Array.isArray(patterns)) return true;
	try {
		path = decodeURIComponent(path);
	} catch (e) {}
	// Collapse . / .. / empty segments before matching. CloudFront gives the
	// function the RAW un-normalised URI (and forwards it raw to the origin), so
	// without this a request like /x/../admin or //admin evades a /admin* scope
	// yet resolves to /admin at a normalising origin. Trailing slash preserved so
	// /checkout/ still matches a /checkout/* scope, identical to the Fastly plugin.
	path = collapsePath(path).toLowerCase();
	for (var i = 0; i < patterns.length; i++) {
		if (typeof patterns[i] !== 'string') return true;
		if (matchPattern(path, patterns[i].toLowerCase())) return true;
	}
	return false;
}

function collapsePath(p) {
	var out = [], segs = p.split('/');
	for (var i = 0; i < segs.length; i++) {
		var s = segs[i];
		if (s !== '' && s !== '.') s === '..' ? out.pop() : out.push(s);
	}
	return '/' + out.join('/') + (out.length && /\/$/.test(p) ? '/' : '');
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

// Spur wordmark, inlined so the interstitial makes no external image request.
// Matches the Cloudflare/Fastly captcha_page.html wordmark; path coordinates are
// rounded to 3 decimals (a sub-pixel, invisible change) to free budget for the
// Inter webfont link so this interstitial matches the Cloudflare page's type.
var SPUR_LOGO =
	'<svg width="103" height="31" viewBox="0 0 103 31" stroke="currentColor"><path d="M19.785 0C20.115 5.074 20.293 10.152 20.293 15.226C20.293 20.3 20.114 25.374 19.785 30.448H18.77C18.452 25.374 18.263 20.3 18.263 15.226C18.263 10.152 18.452 5.074 18.77 0H19.785ZM15.731 13.696C16.022 14.129 16.238 14.605 16.239 15.105C16.238 15.605 16.022 16.054 15.731 16.487L8.12 27.398H7.104C7.117 27.375 12.434 17.501 13.448 16.994V16.233C11.926 16.233 0 15.726 0 15.726V14.711C0 14.711 11.926 14.203 13.448 14.203V13.442C12.433 12.427 7.104 3.039 7.104 3.039H8.12L15.731 13.696ZM31.46 3.039C31.46 3.039 26.131 12.427 25.116 13.442V14.203C26.639 14.203 38.565 14.711 38.565 14.711V15.726C38.565 15.726 26.639 16.233 25.116 16.233V16.994C26.13 18.008 31.448 27.377 31.46 27.398H30.444L22.833 16.487C22.543 16.054 22.327 15.605 22.325 15.105C22.326 14.605 22.543 14.129 22.833 13.696L30.444 3.039H31.46Z" fill="currentColor" stroke="none"/><path d="M55.101 4.305C57.344 4.305 59.141 4.916 60.352 5.914C61.435 6.806 62.074 8.026 62.15 9.472H60.765C60.662 8.283 60.351 7.262 59.512 6.539C58.582 5.738 57.117 5.401 54.953 5.401C53.097 5.401 51.711 5.681 50.787 6.38C49.826 7.107 49.467 8.204 49.467 9.56C49.467 10.677 49.697 11.563 50.457 12.24C51.171 12.877 52.292 13.265 53.872 13.618V13.619L57.413 14.419H57.414C59.277 14.837 60.549 15.43 61.352 16.187C62.136 16.925 62.514 17.856 62.514 19.064C62.514 20.701 61.836 22.116 60.594 23.132C59.345 24.153 57.495 24.793 55.132 24.793C52.765 24.793 50.878 24.166 49.605 23.135C48.462 22.208 47.789 20.934 47.704 19.411H49.092C49.213 20.668 49.568 21.739 50.466 22.496C51.455 23.33 52.994 23.691 55.248 23.691C57.209 23.691 58.666 23.396 59.637 22.678C60.646 21.931 61.03 20.805 61.03 19.415C61.03 18.269 60.791 17.377 60.023 16.697C59.303 16.059 58.175 15.669 56.598 15.301H56.597L52.909 14.446H52.91C51.136 14.028 49.923 13.451 49.156 12.713C48.409 11.993 48.045 11.082 48.045 9.886C48.045 8.278 48.704 6.9 49.895 5.914C51.092 4.923 52.86 4.305 55.101 4.305Z" fill="currentColor"/><path d="M66.499 10.649V11.927H67.701C67.654 11.974 67.608 12.022 67.564 12.073C67.116 12.594 66.851 13.289 66.694 14.168C66.537 15.047 66.48 16.154 66.48 17.536C66.48 18.918 66.537 20.026 66.694 20.907C66.851 21.788 67.115 22.487 67.561 23.01C67.615 23.072 67.671 23.13 67.728 23.186H66.5L66.499 23.686L66.493 29.942L65.45 29.939L65.456 10.649H66.499ZM72.568 9.984C74.528 9.984 76.026 10.637 77.043 11.851C78.071 13.078 78.665 14.945 78.665 17.474C78.665 19.996 78.038 21.904 76.982 23.173C75.936 24.43 74.427 25.112 72.537 25.112C70.564 25.112 69.278 24.523 68.446 23.693C68.718 23.83 69.015 23.933 69.338 24.008C70.047 24.171 70.905 24.212 71.912 24.212C72.92 24.212 73.782 24.169 74.496 24.003C75.222 23.834 75.827 23.533 76.288 23.001C76.742 22.477 77.014 21.779 77.177 20.898C77.34 20.017 77.4 18.911 77.4 17.536C77.4 16.153 77.34 15.045 77.177 14.165C77.014 13.285 76.741 12.589 76.286 12.069C75.824 11.542 75.218 11.248 74.493 11.085C73.78 10.925 72.919 10.885 71.912 10.885C70.905 10.885 70.048 10.924 69.339 11.085C69.037 11.153 68.758 11.246 68.501 11.368C69.364 10.546 70.677 9.984 72.568 9.984Z" fill="currentColor"/><path d="M82.778 10.653V19.816C82.778 20.642 82.813 21.337 82.932 21.906C83.052 22.482 83.267 22.969 83.655 23.341C84.041 23.71 84.546 23.915 85.149 24.031C85.749 24.147 86.487 24.185 87.379 24.185C88.455 24.185 89.343 24.105 90.048 23.864C89.237 24.523 88.09 25.01 86.426 25.01C84.913 25.01 83.748 24.625 82.963 23.882C82.251 23.209 81.789 22.181 81.713 20.7V10.653H82.778ZM93.133 24.619H92.152V23.27H91.079C91.111 23.241 91.144 23.211 91.175 23.18C91.944 22.386 92.097 21.143 92.097 19.521V10.651L93.133 10.649V24.619Z" fill="currentColor"/><path d="M97.441 10.65V11.914H98.529C98.509 11.932 98.488 11.948 98.469 11.967C97.668 12.736 97.483 13.961 97.483 15.588L97.443 24.615H96.411V10.65H97.441ZM102.5 11.02H102.262C101.149 11.02 100.228 11.097 99.501 11.354C100.247 10.713 101.197 10.167 102.5 10.021V11.02Z" fill="currentColor"/></svg>';

// Branded challenge page, matching the Cloudflare/Fastly captcha_page.html
// (Spur wordmark, animated "Testing your connection", terms links, dark mode).
// Runs Monocle, POSTs the assessment to /__mcl/verify, then reloads; the fresh
// request carries the minted cookie and passes straight through. Response
// contract: X-Block-Action redirect:<url> or html, 403 => denial text, else
// fail open (reload).
function interstitial(publishableKey) {
	return (
		'<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Checking Connection…</title><link href="https://fonts.googleapis.com/css2?family=Inter&display=swap" rel="stylesheet"><style>' +
		'body,html{height:100%;margin:0;font-family:"Inter",system-ui,sans-serif;display:flex;justify-content:center;align-items:center;background:#fff;color:#000}' +
		'a{color:#000}' +
		'.c{text-align:center;display:flex;flex-direction:column;align-items:center;gap:1rem}' +
		'.logo{margin-bottom:9px}' +
		'.s,.sn{font-size:1.3rem;margin:0}' +
		'.s::after{content:"";animation:dots 4s infinite}' +
		'@keyframes dots{50%{content:"."}75%{content:".."}100%{content:"..."}}' +
		'.t{font-size:.8rem;color:#888}.t a{color:#888;text-decoration:underline}' +
		'@media(prefers-color-scheme:dark){body,html{background:#000;color:#fff}a{color:#fff}}' +
		'</style></head><body><div class="c">' +
		'<a class="logo" href="https://spur.us/platform/session-enrichment" target="_blank" rel="noreferrer">' +
		SPUR_LOGO +
		'</a><p class="s" id="s">Testing your connection</p>' +
		'<div class="t">See our <a href="https://spur.us/terms" target="_blank" rel="noreferrer">Terms</a> and <a href="https://spur.us/privacy" target="_blank" rel="noreferrer">Privacy Policy</a></div>' +
		'</div><script>function _err(m){var s=document.getElementById("s");s.className="sn";s.textContent=m}function _mclDone(d){fetch("' +
		VERIFY_PATH +
		'",{method:"POST",headers:{"Content-Type":"application/json","X-MCL-Validate":"1"},body:JSON.stringify({captchaData:d})}).then(function(r){if(r.ok){location.reload();return}var a=r.headers.get("X-Block-Action");if(a&&a.indexOf("redirect:")===0){location.href=a.slice(9);return}if(a==="html"){r.text().then(function(h){document.open();document.write(h);document.close()});return}if(r.status===403){r.text().then(function(m){_err("Validation failed. "+(m&&m.trim()!==""?m:"Please disable any VPNs or proxies and try again")+".")});return}location.reload()}).catch(function(){_err("An error occurred. Please refresh and try again.")})}var _t=document.createElement("script");_t.src="https://mcl.spur.us/d/mcl.js?tk=' +
		encodeURIComponent(publishableKey) +
		'";_t.id="_mcl";_t.async=true;_t.onload=function(){if(window.MCL)MCL.configure({onBundle:_mclDone})};document.head.appendChild(_t);</script></body></html>'
	);
}
