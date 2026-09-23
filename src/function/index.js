import cf from 'cloudfront';

var crypto = require('crypto');

async function handler(event) {
	var req = event.request;
	try {
		var uri = typeof req.uri === 'string' ? req.uri : '/';
		// Before any return: a viewer must not be able to hand the origin a
		// contract header or one of our cookies just because a later check fails
		// open. The verdict is read out first, since strip removes it.
		var held = req.cookies && req.cookies['__Host-mcl_c'];
		strip(req);
		var kvs = cf.kvs();
		var ver = await g(kvs, 'v');
		var key = await g(kvs, 'k');
		// Buffer.from is lenient: a truncated or non-hex value would become a
		// DIFFERENT key and reject every cookie the Lambda minted, leaving the
		// visitor in a challenge loop. An unusable key fails open instead.
		if (!key || !/^[0-9a-f]{64}$/i.test(key) || ver !== '2') return skip(req, 'config');
		// No host check: CloudFront routes on the Host, so every one that arrives is
		// a name this distribution serves. An alias the deployment does not list, or
		// the *.cloudfront.net name, reaches the same origin and is the same site.
		var paths;
		try {
			paths = readings(uri);
		} catch (e) {
			return resp(400, H('text/plain; charset=utf-8'), '');
		}
		// Each reading an origin might serve is resolved and the strictest stands:
		// enforced if any is, an infrastructure pass only if all are.
		var hit = null,
			inf = true;
		for (var i = 0; i < paths.length; i++) {
			if (paths[i] === '/__mcl' || paths[i].indexOf('/__mcl/') === 0) return resp(404, H(), null);
			var h = await resolve(kvs, paths[i]);
			if (h === 'e' || !hit) hit = h;
			if (!infra(paths[i])) inf = false;
		}
		var ck = held && held.multiValue && held.multiValue.length > 1 ? null : held;
		var cookieVal = ck ? ck.value : '';
		if (!hit) return req;
		var method = (req.method || 'GET').toUpperCase();
		var hd = req.headers;
		var ws = hd.upgrade && hd.upgrade.value.toLowerCase().indexOf('websocket') !== -1;
		var sec = hd['sec-fetch-mode'] ? hd['sec-fetch-mode'].value : '';
		var acc = hd.accept ? hd.accept.value : '';
		var nav = !ws && (sec.toLowerCase() === 'navigate' || acc.indexOf('application/xhtml+xml') !== -1);
		var safe = method === 'GET' || method === 'HEAD';
		var ip = event.viewer && event.viewer.ip ? event.viewer.ip : '';
		var bind = binding(ip);
		var cv = await g(kvs, 'cv');
		var id = await g(kvs, 'id');
		// Without id/cv no cookie can open, so no challenge could ever be passed
		// and a refusal would hit every visitor, not the ones the policy flags.
		// Pass, marked, so the origin and a curl can see the store is
		// inconsistent; the fix is the missing keys, never a challenge loop.
		if (!id || !cv) return skip(req, 'config');
		var verdict = cookieVal ? openVerdict(cookieVal, key, id, cv, bind) : null;
		if (safe && !ws) {
			var botsRaw = await readChunks(kvs, 'bots');
			if (botsRaw && inPacked(ip, botsRaw)) return req;
			if (hit !== 'e' && inf) return req;
		}
		// No preflight pass, unlike edge-core, which returns only a preflight's
		// headers. A viewer-request Function cannot drop the origin's body, so an
		// OPTIONS here needs a verdict like any other method.
		if (hit === 'e') {
			var ipsRaw = await readChunks(kvs, 'ips');
			if (ipsRaw && inPacked(ip, ipsRaw)) return req;
			if (verdict === 'block') return await blockResp(kvs, req, nav, method);
			if (verdict === 'allow') return req;
			// Refused only for want of a verdict, which verify always gives: when
			// Policy cannot answer, the Lambda passes the visitor there.
			return refuse(req, method, nav, ws, safe, uri);
		}
		if (!verdict && nav && safe) return bounce(503, challenge(uri, qstr(req.querystring)), method, 1);
		return req;
	} catch (e) {
		return skip(req, 'error');
	}
}

// A pass through with Monocle out of the way, marked for the origin. strip()
// has already removed any value the viewer sent under this name.
function skip(req, why) {
	req.headers['x-monocle-skip'] = { value: why };
	return req;
}

async function g(kvs, key) {
	try {
		return await kvs.get(key);
	} catch (e) {
		return null;
	}
}

async function readChunks(kvs, key) {
	var raw = await g(kvs, key);
	if (raw === null) return null;
	var i = 1,
		ch;
	while (true) {
		ch = await g(kvs, key + '.' + i);
		if (ch === null) break;
		raw += ch;
		i++;
	}
	return raw;
}

function strip(req) {
	for (var n in req.headers) {
		if (n.indexOf('x-monocle-') === 0 || n.indexOf('x-mcl-') === 0) delete req.headers[n];
	}
	if (!req.cookies) return;
	for (var c in req.cookies) if (c.indexOf('__Host-mcl_') === 0) delete req.cookies[c];
}

// Every path an origin might take the request path to mean: decoded up to twice,
// with `;params` kept or dropped, slashes merged or not, dot segments resolved or
// not, cut at a decoded `?` or `#` or not. Mirrors edge-core's pathReadings; the
// shared corpus pins them together. Throws for what no ordinary client sends.
function readings(raw) {
	if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') > 8192 || raw.charAt(0) !== '/' || /[\\\x00-\x1f\x7f?#]/.test(raw))
		throw 1;
	var forms = [],
		form = raw,
		depth = 0,
		d;
	while (/%[0-9a-f]{2}/i.test(form)) {
		if (depth === 2) throw 1;
		try {
			d = form.replace(/(?:%[0-9a-f]{2})+/gi, decodeURIComponent);
		} catch (e) {
			if (depth === 0) throw 1;
			break;
		}
		if (/%(?:2f|5c|3b|3f|23|25|2e)/i.test(form)) forms.push(form);
		form = d;
		depth++;
	}
	forms.push(form);
	var out = [],
		list,
		i,
		j,
		f;
	for (i = 0; i < forms.length; i++) {
		if (/[\x00-\x1f\x7f]/.test(forms[i])) throw 1;
		list = vary([forms[i]], /[?#]/, function (p) {
			return p.replace(/[?#].*$/, '');
		});
		list = vary(list, /;/, function (p) {
			return p
				.split('/')
				.map(function (s) {
					return s.split(';')[0];
				})
				.join('/');
		});
		list = vary(list, /\/\/|\\/, function (p) {
			return p.replace(/[\\/]+/g, '/');
		});
		list = vary(list, /\/\.\.?(?:\/|$)/, dots);
		for (j = 0; j < list.length; j++) {
			f = (list[j] || '/').replace(/[A-Z]+/g, function (s) {
				return s.toLowerCase();
			});
			if (f.length > 1 && f.charAt(f.length - 1) === '/') f = f.slice(0, -1);
			if (out.indexOf(f) === -1) out.push(f);
		}
	}
	return out;
}

function vary(list, test, alt) {
	var r = [],
		i;
	for (i = 0; i < list.length; i++) {
		r.push(list[i]);
		if (test.test(list[i])) r.push(alt(list[i]));
	}
	return r;
}

function dots(p) {
	var kept = [],
		s = p.slice(1).split('/'),
		i;
	for (i = 0; i < s.length; i++) {
		if (s[i] === '..') kept.pop();
		else if (s[i] !== '.') kept.push(s[i]);
	}
	return '/' + kept.join('/');
}

async function resolve(kvs, path) {
	var e = false,
		a = false,
		pHit = await g(kvs, 'p:' + path);
	if (pHit === 'e') e = true;
	else if (pHit === 'a') a = true;
	var cur = path;
	while (true) {
		var sHit = await g(kvs, 's:' + cur);
		if (sHit === 'e') e = true;
		else if (sHit === 'a') a = true;
		if (cur === '/') break;
		var i = cur.lastIndexOf('/');
		cur = i <= 0 ? '/' : cur.slice(0, i);
	}
	var wRaw = await readChunks(kvs, 'w');
	if (wRaw) {
		try {
			var list = JSON.parse(wRaw);
			for (var j = 0; j < list.length && j < 100; j++) {
				var w = list[j];
				if (!w || typeof w.p !== 'string' || !matchWild(path, w.p)) continue;
				if (w.e) e = true;
				else a = true;
			}
		} catch (err) {}
	}
	return e ? 'e' : a ? 'a' : null;
}

function matchWild(path, pat) {
	var sub = pat.length > 1 && pat.slice(-2) === '/*';
	var base = sub ? pat.slice(0, -2) || '/' : pat;
	var ps = base === '/' ? [] : base.slice(1).split('/');
	var rs = path === '/' ? [] : path.slice(1).split('/');
	if (!(sub ? rs.length >= ps.length : rs.length === ps.length)) return false;
	for (var i = 0; i < ps.length; i++) if (ps[i] !== '*' && ps[i] !== rs[i]) return false;
	return true;
}
function infra(p) {
	if (
		p === '/robots.txt' ||
		p === '/favicon.ico' ||
		p === '/ads.txt' ||
		p === '/app-ads.txt' ||
		p === '/apple-app-site-association' ||
		p === '/.well-known' ||
		p.indexOf('/.well-known/') === 0
	)
		return true;
	var s = p.slice(1);
	return s.indexOf('/') === -1 && /^sitemap[^/]*\.xml$/.test(s);
}

function b64url(buf) {
	return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64(s) {
	try {
		s = s.replace(/-/g, '+').replace(/_/g, '/');
		while (s.length % 4) s += '=';
		return Buffer.from(s, 'base64');
	} catch (e) {
		return null;
	}
}

function openVerdict(sealed, key, aud, cv, bind) {
	if (!sealed || sealed.length > 8192 || bind === null) return null;
	var d = sealed.lastIndexOf('.');
	if (d < 1) return null;
	var pt = unb64(sealed.slice(0, d));
	var sig = sealed.slice(d + 1);
	if (!pt) return null;
	if (!same(b64url(crypto.createHmac('sha256', Buffer.from(key, 'hex')).update(pt).digest()), sig)) return null;
	var env;
	try {
		env = JSON.parse(pt.toString('utf8'));
	} catch (e) {
		return null;
	}
	var p = env && env.payload;
	var now = Math.floor(Date.now() / 1000);
	var ttl = p && p.verdict === 'allow' ? 3600 : 600;
	if (
		!env ||
		env.v !== 2 ||
		env.kind !== 'verdict' ||
		env.aud !== aud ||
		!p ||
		(p.verdict !== 'allow' && p.verdict !== 'block') ||
		typeof p.ip !== 'string' ||
		typeof p.exp !== 'number' ||
		p.exp > now + ttl ||
		typeof p.sid !== 'string' ||
		!p.sid ||
		p.sid.length > 128 ||
		typeof p.jti !== 'string' ||
		!p.jti ||
		p.jti.length > 128 ||
		p.clearanceVersion !== cv ||
		now >= p.exp ||
		p.ip !== bind
	)
		return null;
	return p.verdict;
}

function same(a, b) {
	if (a.length !== b.length) return false;
	var d = 0;
	for (var i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return d === 0;
}

function v4(s) {
	var p = s.split('.'),
		o = [],
		i,
		n;
	if (p.length !== 4) return null;
	for (i = 0; i < 4; i++) {
		if (!/^(0|[1-9]\d{0,2})$/.test(p[i])) return null;
		n = parseInt(p[i], 10);
		if (n > 255) return null;
		o.push(n);
	}
	return o;
}

function v6hex(addr) {
	var dc = addr.indexOf('::');
	if (dc !== addr.lastIndexOf('::')) return null;
	var head = (dc === -1 ? addr : addr.slice(0, dc)).split(':');
	var tail = dc === -1 ? [] : addr.slice(dc + 2).split(':');
	if (head[0] === '') head = [];
	if (tail[0] === '') tail = [];
	var n = head.length + tail.length,
		g = [],
		i,
		z;
	if (dc === -1 ? n !== 8 : n > 7) return null;
	for (i = 0; i < head.length; i++) g.push(head[i]);
	for (z = 0; z < 8 - n; z++) g.push('0');
	for (i = 0; i < tail.length; i++) g.push(tail[i]);
	var hex = '';
	for (i = 0; i < 4; i++) {
		if (!/^[0-9a-fA-F]{1,4}$/.test(g[i])) return null;
		hex += ('000' + parseInt(g[i], 16).toString(16)).slice(-4);
	}
	return hex;
}

function binding(ip) {
	if (!ip) return null;
	if (ip.indexOf(':') === -1) {
		var a = v4(ip);
		return a ? a.join('.') : null;
	}
	var hex = v6hex(ip);
	if (!hex) return null;
	var g = [],
		i;
	for (i = 0; i < 4; i++) g.push(parseInt(hex.slice(i * 4, i * 4 + 4), 16).toString(16));
	return g.join(':') + '::/64';
}

function inPacked(ip, raw) {
	var set;
	try {
		set = JSON.parse(raw);
	} catch (e) {
		return false;
	}
	if (!set || !set.v4 || !set.v6) return false;
	if (typeof set.expiresAt === 'number' && Math.floor(Date.now() / 1000) >= set.expiresAt) return false;
	if (ip.indexOf(':') === -1) {
		var a = v4(ip);
		return a ? has(set.v4, ((a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3]) >>> 0) : false;
	}
	var hex = v6hex(ip);
	return hex ? has(set.v6, hex) : false;
}

function has(r, n) {
	var lo = 0,
		hi = r.length - 1,
		m;
	while (lo <= hi) {
		m = (lo + hi) >> 1;
		if (n < r[m][0]) hi = m - 1;
		else if (n > r[m][1]) lo = m + 1;
		else return true;
	}
	return false;
}

function H(ct, extra) {
	var h = {
		'cache-control': { value: 'no-store' },
		'x-robots-tag': { value: 'noindex' },
		vary: { value: 'Sec-Fetch-Mode, Accept' },
		'x-frame-options': { value: 'DENY' },
		'content-security-policy': { value: "frame-ancestors 'none'; base-uri 'none'; object-src 'none'" },
		'referrer-policy': { value: 'no-referrer' },
		'x-content-type-options': { value: 'nosniff' }
	};
	if (ct) h['content-type'] = { value: ct };
	if (extra) for (var k in extra) h[k] = extra[k];
	return h;
}

function resp(code, headers, body) {
	var o = { statusCode: code, headers: headers };
	if (body !== null) o.body = body;
	return o;
}

function qstr(qs) {
	if (!qs) return '';
	var p = [],
		k,
		i,
		mv;
	for (k in qs) {
		// A repeated parameter arrives as multiValue; reading .value alone dropped
		// every occurrence after the first from the page the visitor returns to.
		mv = qs[k].multiValue;
		if (mv && mv.length) for (i = 0; i < mv.length; i++) p.push(encodeURIComponent(k) + '=' + encodeURIComponent(mv[i].value));
		else p.push(encodeURIComponent(k) + '=' + encodeURIComponent(qs[k].value));
	}
	return p.length ? '?' + p.join('&') : '';
}

function html(to) {
	return (
		'<!doctype html><meta charset=utf-8><meta name=robots content=noindex><script>location.replace("' +
		to +
		'")</script><noscript><a href="' +
		to +
		'">Continue</a></noscript>'
	);
}

function bounce(code, to, method, retry) {
	return resp(
		code,
		H('text/html; charset=utf-8', retry ? { 'retry-after': { value: '5' } } : null),
		method === 'HEAD' ? null : html(to)
	);
}

function challenge(path, qs) {
	return '/__mcl/challenge?return=' + encodeURIComponent(path + qs);
}

// `uri` is the request's own path, not the canonical one: the canonical form is
// lower-cased and slash-trimmed for comparison, and sending a visitor back to it
// 404s on any origin that treats paths as case-sensitive.
function refuse(req, method, nav, ws, safe, uri) {
	if (ws) return resp(403, H(), null);
	if (nav && safe) return bounce(503, challenge(uri, qstr(req.querystring)), method, 1);
	if (nav && (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE'))
		return bounce(403, '/__mcl/resubmit', method, 0);
	var ch = safe || method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
	return resp(
		403,
		H('application/json', ch ? { 'x-monocle-challenge-required': { value: '1' } } : null),
		method === 'HEAD' ? null : '{"challenge":true}'
	);
}

/**
 * Whether a blocked navigation may be sent to the configured page. The rule is
 * edge-core's safeReturn: a path on this host, never protocol-relative and never
 * one a browser folds into an off-site address (`/\\evil.example` resolves to
 * `https://evil.example/`). A target inside an enforced subtree is refused as
 * well, because blocking it would redirect to itself for ever.
 */
async function redirectable(kvs, to) {
	if (typeof to !== 'string' || to.charAt(0) !== '/' || to.indexOf('//') === 0) return false;
	if (/[\\\x00-\x20]/.test(to) || to === '/__mcl' || to.indexOf('/__mcl/') === 0) return false;
	var targets;
	try {
		targets = readings(to);
	} catch (e) {
		return false;
	}
	for (var i = 0; i < targets.length; i++) {
		var hit = await resolve(kvs, targets[i]);
		if (hit === 'e') return false;
	}
	return true;
}

async function blockResp(kvs, req, nav, method) {
	var cfgRaw = await readChunks(kvs, 'cfg');
	var cfg;
	try {
		cfg = JSON.parse(cfgRaw || '{}');
	} catch (e) {
		cfg = {};
	}
	var bp = cfg.block_page || {};
	var code = bp.status === 401 || bp.status === 404 ? bp.status : 403;
	if (!nav)
		return resp(
			code,
			H('application/json', { 'x-monocle-blocked': { value: '1' } }),
			method === 'HEAD' ? null : '{"blocked":true,"reason":"policy_block"}'
		);
	// Kept out of the `if` head: this runtime rejects `await` in an argument
	// position, and the minifier will move it there.
	var mayRedirect = await redirectable(kvs, bp.redirect);
	if (mayRedirect) {
		var st = method === 'GET' || method === 'HEAD' ? 307 : 303;
		return resp(st, H(null, { location: { value: bp.redirect } }), null);
	}
	return resp(code, H('text/html; charset=utf-8'), method === 'HEAD' ? null : html('/__mcl/blocked'));
}
