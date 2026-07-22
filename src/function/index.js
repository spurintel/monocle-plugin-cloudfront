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
//  - hard 10240-byte limit on the STRIPPED artifact (build.mjs fails over it;
//    we currently sit ~10235 bytes, so headroom is only a few bytes), which is
//    why the interstitial is spartan and the only imports are 'cloudfront' and 'crypto';
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
// Identical to the Cloudflare/Fastly captcha_page.html for brand parity.
var SPUR_LOGO =
	'<svg width="103" height="31" viewBox="0 0 103 31" stroke="currentColor"><path d="M19.7852 0C20.1147 5.07404 20.293 10.1515 20.293 15.2256C20.293 20.2996 20.114 25.3742 19.7852 30.4482H18.7705C18.4517 25.3742 18.2627 20.2996 18.2627 15.2256C18.2627 10.1515 18.4517 5.07404 18.7705 0H19.7852ZM15.7314 13.6963C16.0219 14.1289 16.2379 14.6054 16.2393 15.1055C16.2378 15.6054 16.0219 16.0541 15.7314 16.4873L8.12012 27.3975H7.10449C7.11677 27.3747 12.4345 17.501 13.4482 16.9941V16.2334C11.9258 16.2334 0 15.7256 0 15.7256V14.7109C0 14.7109 11.9258 14.2031 13.4482 14.2031V13.4424C12.4333 12.4274 7.10449 3.03906 7.10449 3.03906H8.12012L15.7314 13.6963ZM31.46 3.03906C31.46 3.03906 26.1312 12.4274 25.1162 13.4424V14.2031C26.6386 14.2031 38.5645 14.7109 38.5645 14.7109V15.7256C38.5645 15.7256 26.6386 16.2334 25.1162 16.2334V16.9941C26.1301 18.008 31.4485 27.3772 31.46 27.3975H30.4443L22.833 16.4873C22.5426 16.0541 22.3266 15.6054 22.3252 15.1055C22.3265 14.6055 22.5425 14.1289 22.833 13.6963L30.4443 3.03906H31.46Z" fill="currentColor" stroke="none"/><path d="M55.1006 4.30478C57.3442 4.30478 59.1414 4.91644 60.3525 5.91415C61.4354 6.80621 62.0735 8.02574 62.1504 9.47177H60.7646C60.6621 8.28297 60.3506 7.26242 59.5117 6.53915C58.5822 5.7377 57.1174 5.40146 54.9531 5.40146C53.0971 5.40148 51.7113 5.68071 50.7871 6.37997C49.8259 7.10722 49.4668 8.20368 49.4668 9.55966C49.4668 10.6771 49.6973 11.5631 50.457 12.2403C51.1714 12.877 52.2923 13.2647 53.8721 13.6183V13.6192L57.4131 14.419H57.4141C59.2766 14.8373 60.549 15.4299 61.3525 16.1866C62.1365 16.9249 62.5136 17.8563 62.5137 19.0645C62.5137 20.7006 61.8356 22.1164 60.5938 23.1319C59.3448 24.1533 57.4945 24.793 55.1318 24.7931C52.7652 24.7931 50.8782 24.1665 49.6055 23.1349C48.4619 22.2078 47.7894 20.9337 47.7041 19.4112H49.0918C49.2128 20.6678 49.5676 21.7387 50.4658 22.4962C51.4547 23.3299 52.9937 23.6905 55.248 23.6905C57.2092 23.6905 58.6665 23.3959 59.6367 22.6778C60.6458 21.9309 61.0303 20.8054 61.0303 19.4151C61.0302 18.2689 60.7913 17.3773 60.0234 16.6974C59.3026 16.0592 58.175 15.6691 56.5977 15.3009H56.5967L52.9092 14.4464H52.9102C51.1363 14.0285 49.923 13.4509 49.1562 12.713C48.4086 11.9933 48.045 11.0821 48.0449 9.88583C48.0449 8.27841 48.7036 6.89983 49.8945 5.91415C51.0923 4.9229 52.8597 4.30484 55.1006 4.30478Z" fill="currentColor"/><path d="M66.499 10.6494V11.9268H67.7012C67.6543 11.9738 67.6077 12.0219 67.5635 12.0732C67.116 12.5936 66.8514 13.2894 66.6943 14.168C66.5373 15.0467 66.4795 16.1542 66.4795 17.5361C66.4795 18.918 66.5373 20.0263 66.6943 20.9072C66.8513 21.788 67.1149 22.4866 67.5615 23.0098C67.6145 23.0718 67.6707 23.1297 67.7275 23.1855H66.5L66.499 23.6855L66.4932 29.9424L65.4502 29.9385L65.4561 10.6494H66.499ZM72.5684 9.98438C74.5285 9.98441 76.0257 10.6369 77.043 11.8506C78.0714 13.0776 78.665 14.945 78.665 17.4736C78.665 19.9956 78.0376 21.9043 76.9824 23.1729C75.9365 24.4302 74.4272 25.1123 72.5371 25.1123C70.5635 25.1123 69.2779 24.5235 68.4463 23.6934C68.718 23.8297 69.0152 23.9335 69.3379 24.0078C70.0471 24.171 70.9049 24.2119 71.9121 24.2119C72.9204 24.2119 73.7816 24.1687 74.4961 24.0029C75.2225 23.8344 75.8272 23.5331 76.2881 23.001C76.7418 22.4771 77.0139 21.7786 77.1768 20.8975C77.3395 20.0169 77.4004 18.9113 77.4004 17.5361C77.4004 16.1533 77.3395 15.045 77.1768 14.165C77.0139 13.2847 76.7414 12.5888 76.2861 12.0693C75.8238 11.5418 75.2182 11.248 74.4932 11.085C73.7798 10.9246 72.9191 10.8848 71.9121 10.8848C70.9053 10.8848 70.0476 10.9244 69.3389 11.085C69.0375 11.1533 68.7582 11.2463 68.501 11.3682C69.364 10.5458 70.6765 9.98438 72.5684 9.98438Z" fill="currentColor"/><path d="M82.7783 10.6533V19.8164C82.7783 20.642 82.8128 21.3371 82.9316 21.9062C83.052 22.4823 83.2668 22.9693 83.6553 23.3408C84.0413 23.7099 84.5465 23.9146 85.1494 24.0312C85.7487 24.1472 86.4868 24.1846 87.3789 24.1846C88.4548 24.1846 89.343 24.1055 90.0479 23.8643C89.2365 24.5233 88.0898 25.0098 86.4258 25.0098C84.9127 25.0097 83.7482 24.6245 82.9629 23.8818C82.2511 23.2086 81.7888 22.1814 81.7129 20.7002V10.6533H82.7783ZM93.1328 24.6191H92.1523V23.2705H91.0791C91.1113 23.2407 91.1441 23.2113 91.1748 23.1797C91.9439 22.3864 92.0967 21.1426 92.0967 19.5215V10.6514L93.1328 10.6494V24.6191Z" fill="currentColor"/><path d="M97.4409 10.6504V11.9141H98.5288C98.5091 11.9318 98.4884 11.9484 98.4692 11.9668C97.6676 12.7364 97.483 13.9608 97.4829 15.5879L97.4429 24.6152H96.4106V10.6504H97.4409ZM102.5 11.0195H102.262C101.149 11.0195 100.228 11.0965 99.5015 11.3535C100.247 10.7126 101.197 10.1666 102.5 10.0215V11.0195Z" fill="currentColor"/></svg>';

// Branded challenge page, matching the Cloudflare/Fastly captcha_page.html
// (Spur wordmark, animated "Testing your connection", terms links, dark mode).
// Runs Monocle, POSTs the assessment to /__mcl/verify, then reloads; the fresh
// request carries the minted cookie and passes straight through. Response
// contract: X-Block-Action redirect:<url> or html, 403 => denial text, else
// fail open (reload).
function interstitial(publishableKey) {
	return (
		'<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Checking Connection…</title><style>' +
		'body,html{height:100%;margin:0;font-family:system-ui;display:flex;justify-content:center;align-items:center;background:#fff;color:#000}' +
		'a{color:#000}' +
		'.c{text-align:center;display:flex;flex-direction:column;align-items:center;gap:1rem}' +
		'.logo{margin-bottom:9px}' +
		'.s,.sn{font-size:1.3rem;margin:0}' +
		'.s::after{content:"";animation:dots 4s infinite}' +
		'@keyframes dots{0%,25%{content:""}50%{content:"."}75%{content:".."}100%{content:"..."}}' +
		'.t{font-size:.8rem;color:#888}.t a{color:#888;text-decoration:underline}' +
		'@media(prefers-color-scheme:dark){body,html{background:#000;color:#fff}a{color:#fff}}' +
		'</style></head><body><div class="c">' +
		'<a class="logo" href="https://spur.us/platform/session-enrichment" target="_blank" rel="noreferrer">' +
		SPUR_LOGO +
		'</a><h1 class="s" id="s">Testing your connection</h1>' +
		'<div class="t">See our <a href="https://spur.us/terms" target="_blank" rel="noreferrer">Terms</a> and <a href="https://spur.us/privacy" target="_blank" rel="noreferrer">Privacy Policy</a></div>' +
		'</div><script>function _err(m){var s=document.getElementById("s");s.className="sn";s.textContent=m}function _mclDone(d){fetch("' +
		VERIFY_PATH +
		'",{method:"POST",headers:{"Content-Type":"application/json","X-MCL-Validate":"1"},body:JSON.stringify({captchaData:d})}).then(function(r){if(r.ok){location.reload();return}var a=r.headers.get("X-Block-Action");if(a&&a.indexOf("redirect:")===0){location.href=a.slice(9);return}if(a==="html"){r.text().then(function(h){document.open();document.write(h);document.close()});return}if(r.status===403){r.text().then(function(m){_err("Validation failed. "+(m&&m.trim()!==""?m:"Please disable any VPNs or proxies and try again")+".")});return}location.reload()}).catch(function(){_err("An error occurred. Please refresh and try again.")})}var _t=document.createElement("script");_t.src="https://mcl.spur.us/d/mcl.js?tk=' +
		encodeURIComponent(publishableKey) +
		'";_t.id="_mcl";_t.async=true;_t.onload=function(){if(window.MCL)MCL.configure({onBundle:_mclDone})};document.head.appendChild(_t);</script></body></html>'
	);
}
