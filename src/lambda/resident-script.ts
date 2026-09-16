/** Browser orchestration for assessment, renewal, bounded fetch recovery and the optional blocked-request redirect. HttpOnly cookies remain server-owned. */

import { edgeRequestJs } from './browser-shared';

export function residentScript(coreUrl: string, blockRedirect: string | null = null): string {
	return `
(function () {
	'use strict';
	if (window.__mclResident) return; // one resident per page
	window.__mclResident = true;

	var STATE_URL = '/__mcl/state';
	var VERIFY_URL = '/__mcl/verify';
	var CORE_URL = ${JSON.stringify(coreUrl).replace(/</g, '\\u003c')};
	var BLOCK_REDIRECT = ${JSON.stringify(blockRedirect).replace(/</g, '\\u003c')};
	var RENEWAL_LEAD_S = 300;
	var REPLAY_BODY_CAP = 262144; // 256KB; larger bodies are not held for replay

	var nativeFetch = window.fetch.bind(window);
	var blockNavigated = false; // navigate to the block page at most once
	var hint = null; // latest edge state hint
	var sid = null; // session id from state, tags the assessment as cpd
	var verifying = null; // in-flight verify promise (per-tab single flight)
	var renewalTimer = null;
	var coreLoading = null;
	var gathering = null;
	var started = false;
	var queuedBundleAt = 0;
	var queuedBundle = null;
	var incompleteRetries = 0;

	function absorb(payload) {
		if (!payload) return;
		if (payload.hint) {
			hint = payload.hint;
			schedule();
		}
		if (typeof payload.sid === 'string' && payload.sid) sid = payload.sid;
	}

${edgeRequestJs('nativeFetch')}

	function fetchState() {
		return edgeRequest(STATE_URL).then(function (response) {
			if (response.status !== 200) return null;
			absorb(response.data);
			return response.data;
		}).catch(function () { return null; });
	}

	function loadCore() {
		if (window.MCL) return Promise.resolve();
		if (coreLoading) return coreLoading;
		coreLoading = new Promise(function (resolve, reject) {
			var el = document.createElement('script');
			el.id = '_mcl';
			el.src = sid ? CORE_URL + '&cpd=' + encodeURIComponent(sid) : CORE_URL;
			el.async = true;
			var timer = setTimeout(function () {
				el.remove();
				coreLoading = null;
				reject(new Error('core load timeout'));
			}, 15000);
			el.onload = function () {
				clearTimeout(timer);
				resolve();
			};
			el.onerror = function () {
				clearTimeout(timer);
				coreLoading = null;
				reject(new Error('core load failed'));
			};
			(document.head || document.documentElement).appendChild(el);
		});
		return coreLoading;
	}

	function gatherBundle() {
		if (queuedBundle && Date.now() - queuedBundleAt < 240000) {
			var saved = queuedBundle;
			queuedBundle = null;
			return Promise.resolve(saved);
		}
		queuedBundle = null;
		if (gathering) return gathering;
		// One collection feeds both page assessment and verification.
		gathering = loadCore().then(function () {
			return new Promise(function (resolve, reject) {
				if (!window.MCL || !window.MCL.configure) {
					reject(new Error('core missing'));
					return;
				}
				var done = false;
				var seen = null;
				// onAssessment supersedes onBundle; older cores only know the latter.
				function receive(bundle) {
					if (bundle === seen) return;
					seen = bundle;
					if (done) {
						queuedBundle = bundle;
						queuedBundleAt = Date.now();
						return;
					}
					done = true;
					resolve(bundle);
				}
				window.MCL.configure({ onAssessment: receive, onBundle: receive });
				// configure only registers the handler. The first gather rides the core's
				// own start-up assessment; a later one has none coming, so ask for it.
				setTimeout(function () {
					if (done || !window.MCL || typeof window.MCL.refresh !== 'function') return;
					try {
						window.MCL.refresh();
					} catch (e) {}
				}, 3000);
				setTimeout(function () {
					if (!done) {
						done = true;
						reject(new Error('bundle timeout'));
					}
				}, 15000);
			});
		});
		gathering = gathering.then(
			function (bundle) {
				gathering = null;
				return bundle;
			},
			function (error) {
				gathering = null;
				throw error;
			},
		);
		return gathering;
	}

	function verify(force) {
		if (verifying) return verifying;
		var run = function () {
			return fetchState().then(function () {
				return verifyUnlocked(force);
			});
		};
		verifying = (
			navigator.locks && navigator.locks.request
				? navigator.locks.request('mcl:verify', run)
				: run()
		)
			.catch(function () {
				return false;
			})
			.then(function (ok) {
				verifying = null;
				return ok;
			});
		return verifying;
	}
	function verifyUnlocked(force) {
		if (hint && hint.verdict === 'block' && hint.validUntil * 1000 > Date.now())
			return Promise.resolve(false); // A valid block remains authoritative until expiry.
		if (
			!force &&
			hint &&
			hint.verdict === 'allow' &&
			hint.validUntil * 1000 - Date.now() > RENEWAL_LEAD_S * 1000
		)
			return Promise.resolve(true);
		// Per-tab single flight; localStorage is not an atomic lock.

		return gatherBundle()
			.then(function (bundle) {
				return edgeRequest(VERIFY_URL, {
					method: 'POST',
					credentials: 'same-origin',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ captchaData: bundle }),
				});
			})
			.then(function (response) {
				if (response.status === 503) {
					// Jittered retry while degraded.
					scheduleRetry(30000 + Math.random() * 60000);
					return false;
				}
				var data = response.data;
				absorb(data);
				if (data && data.needsComplete && incompleteRetries++ < 3) scheduleRetry(1000);
				if (response.status === 200) {
					queuedBundle = null;
					incompleteRetries = 0;
				}
				if (response.status === 429) scheduleRetry(5000 + Math.random() * 5000);
				return response.status === 200 && data && data.verdict === 'allow';
			})
			.catch(function () {
				return false;
			});
	}

	function schedule() {
		if (renewalTimer) {
			clearTimeout(renewalTimer);
			renewalTimer = null;
		}
		if (!hint || hint.verdict !== 'allow' || !hint.validUntil) return;
		var dueInMs = (hint.validUntil - RENEWAL_LEAD_S) * 1000 - Date.now();
		renewalTimer = setTimeout(
			function () {
				if (document.visibilityState === 'visible') verify(false);
			},
			Math.max(dueInMs, 1000),
		);
	}

	function scheduleRetry(delayMs) {
		if (renewalTimer) clearTimeout(renewalTimer);
		renewalTimer = setTimeout(function () {
			verify(false);
		}, delayMs);
	}

	document.addEventListener('visibilitychange', function () {
		if (
			document.visibilityState === 'visible' &&
			hint &&
			hint.validUntil * 1000 - Date.now() <= RENEWAL_LEAD_S * 1000
		)
			verify(false);
	});

	function isSameOrigin(url) {
		try {
			return new URL(url, window.location.href).origin === window.location.origin;
		} catch (e) {
			return false;
		}
	}

	function isMclUrl(url) {
		try {
			return new URL(url, window.location.href).pathname.indexOf('/__mcl/') === 0;
		} catch (e) {
			return false;
		}
	}

	// Observation only: the caller still receives its response unchanged. The marker
	// header identifies a block whatever status the customer chose for it.
	function blockGuard(response) {
		if (!BLOCK_REDIRECT || blockNavigated) return response;
		if (!response.redirected && response.headers.get('X-Monocle-Blocked') === '1') {
			blockNavigated = true;
			window.location.assign(BLOCK_REDIRECT);
		}
		return response;
	}
	function watched(promise) {
		return BLOCK_REDIRECT ? promise.then(blockGuard) : promise;
	}

	window.fetch = function (input, init) {
		var url =
			typeof input === 'string' || input instanceof URL
				? String(input)
				: (input && input.url) || '';
		if (!isSameOrigin(url) || isMclUrl(url)) return nativeFetch(input, init);
		// A service worker owns replay semantics; blocks are still observed.
		if (navigator.serviceWorker && navigator.serviceWorker.controller)
			return watched(nativeFetch(input, init));
		// A Request body is already a stream; never tee unbounded input.
		if (input instanceof Request && input.body) return watched(nativeFetch(input, init));
		var body = init && init.body;
		var size = 0;
		if (body != null) {
			if (typeof body === 'string') size = new TextEncoder().encode(body).byteLength;
			else if (body instanceof URLSearchParams)
				size = new TextEncoder().encode(body.toString()).byteLength;
			else if (body instanceof Blob) size = body.size;
			else if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) size = body.byteLength;
			// FormData/streams: explicit application recovery only.
			else return watched(nativeFetch(input, init));
		}
		if (size > REPLAY_BODY_CAP) return watched(nativeFetch(input, init));
		var request;
		try {
			request = new Request(input, init);
		} catch (_) {
			return watched(nativeFetch(input, init));
		}
		var replayable = request.clone(); // bounded above before any tee
		return watched(nativeFetch(request).then(function (response) {
			if (
				response.status !== 403 ||
				response.redirected ||
				response.url !== request.url ||
				response.headers.get('X-Monocle-Challenge-Required') !== '1'
			)
				return response;
			if (request.signal.aborted) return response;
			return verify(true).then(function (cleared) {
				if (!cleared || request.signal.aborted) return response;
				return nativeFetch(replayable);
			});
		}));
	};

	// XHR recovery stays untouched, so a failed request is visible to normal
	// listeners. The block redirect only observes: the load event still fires.
	if (BLOCK_REDIRECT && window.XMLHttpRequest && window.XMLHttpRequest.prototype) {
		var nativeSend = window.XMLHttpRequest.prototype.send;
		window.XMLHttpRequest.prototype.send = function () {
			var xhr = this;
			xhr.addEventListener('load', function () {
				try {
					if (blockNavigated) return;
					var finalUrl = xhr.responseURL;
					if (!finalUrl || !isSameOrigin(finalUrl) || isMclUrl(finalUrl)) return;
					if (xhr.getResponseHeader('X-Monocle-Blocked') !== '1') return;
					blockNavigated = true;
					window.location.assign(BLOCK_REDIRECT);
				} catch (e) {
					/* Observation must never break the application's request. */
				}
			});
			return nativeSend.apply(this, arguments);
		};
	}

	window.addEventListener('mcl:recover', function () {
		verify(true).then(function (ok) {
			window.dispatchEvent(new CustomEvent('mcl:recovered', { detail: { cleared: !!ok } }));
		});
	});

	function boot() {
		if (started) return;
		started = true;
		// State first: it carries the session id the core URL is tagged with.
		fetchState().then(function () {
			gatherBundle()
				.then(function (bundle) {
					if (!queuedBundle) {
						queuedBundle = bundle;
						queuedBundleAt = Date.now();
					}
				})
				.catch(function () {
					/* Recovery can retry collection if it is needed. */
				});
			if (!hint || hint.verdict === null) {
				verify(false);
			} else if (hint.renewalDue) {
				verify(false);
			}
		});
	}
	boot();
})();
`;
}
