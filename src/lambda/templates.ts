/**
 * Lambda-served pages: challenge, resubmit, block and unavailable.
 * Customer text is HTML-escaped at the sink; script-context values go
 * through JSON.stringify.
 */

import { escapeHtml } from '../shared/escape';
import { edgeRequestJs } from './browser-shared';

const SPUR_LOGO_SVG = `<svg width="39" height="31" viewBox="0 0 38.5645 30.4482" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M19.7852 0C20.1147 5.07404 20.293 10.1515 20.293 15.2256C20.293 20.2996 20.114 25.3742 19.7852 30.4482H18.7705C18.4517 25.3742 18.2627 20.2996 18.2627 15.2256C18.2627 10.1515 18.4517 5.07404 18.7705 0H19.7852ZM15.7314 13.6963C16.0219 14.1289 16.2379 14.6054 16.2393 15.1055C16.2378 15.6054 16.0219 16.0541 15.7314 16.4873L8.12012 27.3975H7.10449C7.11677 27.3747 12.4345 17.501 13.4482 16.9941V16.2334C11.9258 16.2334 0 15.7256 0 15.7256V14.7109C0 14.7109 11.9258 14.2031 13.4482 14.2031V13.4424C12.4333 12.4274 7.10449 3.03906 7.10449 3.03906H8.12012L15.7314 13.6963ZM31.46 3.03906C31.46 3.03906 26.1312 12.4274 25.1162 13.4424V14.2031C26.6386 14.2031 38.5645 14.7109 38.5645 14.7109V15.7256C38.5645 15.7256 26.6386 16.2334 25.1162 16.2334V16.9941C26.1301 18.008 31.4485 27.3772 31.46 27.3975H30.4443L22.833 16.4873C22.5426 16.0541 22.3266 15.6054 22.3252 15.1055C22.3265 14.6055 22.5425 14.1289 22.833 13.6963L30.4443 3.03906H31.46Z" fill="currentColor"/></svg>`;

const BASE_STYLE = `body,html{height:100%;margin:0;font-family:system-ui,-apple-system,sans-serif;display:flex;justify-content:center;align-items:center;background:#fff;color:#000}.center{text-align:center;display:flex;flex-direction:column;align-items:center;gap:1rem;max-width:520px;padding:2rem}h1{font-size:1.3rem;font-weight:400;margin:0}p{color:#6b7280;margin:0}.terms{font-size:.8rem;color:#888}.terms a{color:#888}a{color:inherit}@media(prefers-color-scheme:dark){body,html{background:#000;color:#fff}}`;

function toScriptLiteral(value: unknown): string {
	return JSON.stringify(value).replace(/</g, '\\u003c');
}

/** Same-origin return path: one leading slash, never `//host` or `/__mcl`. */
export function safeReturn(value: string | null | undefined): string {
	if (
		!value ||
		!value.startsWith('/') ||
		value.startsWith('//') ||
		/[\\\x00-\x20]/.test(value) ||
		value.startsWith('/__mcl')
	)
		return '/';
	return value;
}

/** Cacheable challenge page. The return path is read from `?return=` in the browser. */
export function interstitialPage(coreUrl: string): string {
	const config = toScriptLiteral({
		verify: '/__mcl/verify',
		core: coreUrl,
	});
	return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex">
<title>Checking your connection…</title>
<style>${BASE_STYLE}
@keyframes dots{0%,25%{content:""}50%{content:"."}75%{content:".."}100%{content:"..."}}
.loading::after{content:"";animation:dots 2s infinite}</style>
</head>
<body>
<div class="center">
<a href="https://spur.us/platform/session-enrichment" target="_blank" rel="noreferrer">${SPUR_LOGO_SVG}</a>
<h1 class="loading" id="status">Checking your connection</h1>
<div class="terms">See our <a href="https://spur.us/terms" target="_blank" rel="noreferrer">Terms</a> and <a href="https://spur.us/privacy" target="_blank" rel="noreferrer">Privacy Policy</a></div>
</div>
<script>
(function () {
	var cfg = ${config};
	cfg.reload = (function (value) {
		if (!value || value.charAt(0) !== '/' || value.indexOf('//') === 0 || /[\\\\\\x00-\\x20]/.test(value) || value.indexOf('/__mcl') === 0)
			return '/';
		return value;
	})(new URLSearchParams(location.search).get('return'));
	var status = document.getElementById('status');
	var attempts = 0,
		inFlight = false,
		latestBundle = null,
		started = false;
	function fail(message) {
		status.className = '';
		status.textContent = message;
	}
${edgeRequestJs('fetch')}
	function reload() {
		try {
			var previous = Number(sessionStorage.getItem('mcl:challenge-reload') || '0');
			if (Date.now() - previous < 60000) {
				fail('Verification is unavailable. Please try again shortly.');
				return;
			}
			sessionStorage.setItem('mcl:challenge-reload', String(Date.now()));
		} catch (_) {
			fail('Please refresh to continue.');
			return;
		}
		window.location.replace(cfg.reload);
	}
	function verify() {
		if (inFlight || !latestBundle || attempts >= 5) return;
		inFlight = true;
		attempts++;
		var sentBundle = latestBundle,
			needsComplete = false;
		edgeRequest(cfg.verify, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ captchaData: sentBundle }),
		})
			.then(function (response) {
				var data = response.data;
				if (data === null) {
					fail('Verification is unavailable. Please refresh and try again.');
					return;
				}
				if (
					(response.status === 200 && data.verdict === 'allow') ||
					(response.status === 403 && data.blocked === true)
				) {
					return edgeRequest('/__mcl/state').then(function (state) {
						if (state.data === null) {
							fail('Verification is unavailable. Please refresh and try again.');
							return;
						}
						var hint = state.data.hint;
						if (state.status !== 200 || !hint ||
							(hint.verdict !== 'allow' && hint.verdict !== 'block')) {
							fail('Verification could not be saved. Please enable cookies and refresh.');
							return;
						}
						window.location.replace(cfg.reload);
					});
				}
				if (response.status === 503 && data.degraded === true) {
					reload();
					return;
				}
				if (response.status === 202 && data.needsComplete) {
					needsComplete = true;
					fail('Waiting for verification to complete');
					return;
				}
				if (response.status === 429 && attempts < 5) {
					fail('High traffic, retrying shortly');
					setTimeout(verify, 5000 + Math.random() * 5000);
					return;
				}
				fail('Verification could not be completed. Please refresh and try again.');
			})
			.catch(function () {
				fail('Verification is unavailable. Please refresh and try again.');
			})
			.then(function () {
				inFlight = false;
				if (needsComplete && latestBundle !== sentBundle) verify();
			});
	}
	function loadCore(sid) {
		var core = document.createElement('script');
		core.id = '_mcl';
		core.src = sid ? cfg.core + '&cpd=' + encodeURIComponent(sid) : cfg.core;
		core.onerror = function () {
			fail('Verification failed to load. Please refresh.');
		};
		core.onload = function () {
			if (!window.MCL || !MCL.configure) {
				fail('Verification failed to load.');
				return;
			}
			function receive(bundle) {
				if (bundle === latestBundle) return;
				latestBundle = bundle;
				verify();
			}
			MCL.configure({ onAssessment: receive, onBundle: receive });
		};
		document.head.appendChild(core);
	}
	function start() {
		if (started) return;
		started = true;
		// This page is cached, so the session tag cannot be baked in; state hands it out.
		edgeRequest('/__mcl/state')
			.then(function (state) {
				var data = state.data;
				loadCore(data && typeof data.sid === 'string' ? data.sid : null);
			})
			.catch(function () {
				loadCore(null);
			});
		setTimeout(function () {
			if (attempts === 0) fail('Verification timed out. Please refresh.');
		}, 20000);
	}
	start();
})();
</script>
</body>
</html>`;
}

export function unavailablePage(): string {
	return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="robots" content="noindex"><title>One moment…</title></head>
<body><p>Verification is unavailable. Please retry shortly.</p></body>
</html>`;
}

export function resubmitPage(): string {
	return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="robots" content="noindex"><title>Session expired</title><style>${BASE_STYLE}</style></head>
<body><div class="center">${SPUR_LOGO_SVG}<h1>Your session has expired</h1><p>Please go back, refresh the page, and submit again.</p></div></body>
</html>`;
}

export function blockPage(title: string, message: string): string {
	return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="robots" content="noindex"><title>${escapeHtml(title)}</title><style>${BASE_STYLE}</style></head>
<body><div class="center"><a href="https://spur.us" target="_blank" rel="noreferrer">${SPUR_LOGO_SVG}</a><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p></div></body>
</html>`;
}
