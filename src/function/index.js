import cf from 'cloudfront';

var crypto = require('crypto');

async function handler(event) {
	var req = event.request;
	try {
		var uri = typeof req.uri === 'string' ? req.uri : '/';
		if (uri === '/__mcl' || uri.indexOf('/__mcl/') === 0) return req;
		var kvs = cf.kvs();
		var ver = await g(kvs, 'v');
		var key = await g(kvs, 'k');
		if (!key || ver !== '2') return req;
		var host = req.headers.host ? req.headers.host.value : '';
		var c = host.lastIndexOf(':');
		if (c > 0 && host.indexOf(']') === -1) host = host.slice(0, c);
		host = host.toLowerCase();
		var hostsRaw = await readChunks(kvs, 'hosts');
		// Absent is a store we cannot use, which fails open like the rest of them.
		// An empty list is a deployment that says every hostname this distribution
		// serves - a distribution is a site, so that is the safe default, and it
		// covers an alias added long after setup.
		if (!hostsRaw) return req;
		var hosts;
		try {
			hosts = JSON.parse(hostsRaw);
		} catch (e) {
			return req;
		}
		// The distribution's own *.cloudfront.net name reaches the same origin and
		// config, so an alias deployment would be bypassable through it. Treated as
		// the configured host, not a second one; the Lambda's verify Origin agrees.
		if (!Array.isArray(hosts)) return req;
		var own = event.context && event.context.distributionDomainName;
		if (hosts.length && hosts.indexOf(host) === -1 && host !== (own ? own.toLowerCase() : null))
			return req;
		var path;
		try {
			path = canon(uri);
		} catch (e) {
			return resp(400, H('text/plain; charset=utf-8'), '');
		}
		if (path === '/__mcl' || path.indexOf('/__mcl/') === 0) return resp(404, H(), null);
		var ck = req.cookies && req.cookies['__Host-mcl_c'];
		if (ck && ck.multiValue && ck.multiValue.length > 1) ck = null;
		var cookieVal = ck ? ck.value : '';
		strip(req);
		var hit = await resolve(kvs, path);
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
		if (!id || !cv) {
			req.headers['x-monocle-skip'] = { value: 'no-config' };
			return req;
		}
		var verdict = cookieVal ? openVerdict(cookieVal, key, id, cv, bind) : null;
		if (safe && !ws) {
			var botsRaw = await readChunks(kvs, 'bots');
			if (botsRaw && inPacked(ip, botsRaw)) return req;
			if (hit !== 'e' && infra(path)) return req;
		}
		if (method === 'OPTIONS') return req;
		if (hit === 'e') {
			var ipsRaw = await readChunks(kvs, 'ips');
			if (ipsRaw && inPacked(ip, ipsRaw)) return req;
			if (verdict === 'block') return await blockResp(kvs, req, nav, method);
			if (verdict === 'allow') return req;
			var brk = await g(kvs, 'brk');
			if (brk && Math.floor(Date.now() / 1000) < parseInt(brk, 10)) {
				req.headers['x-monocle-degraded'] = { value: '1' };
				return req;
			}
			return refuse(req, method, nav, ws, safe, path);
		}
		if (!verdict && nav && safe) {
			var brk2 = await g(kvs, 'brk');
			if (!(brk2 && Math.floor(Date.now() / 1000) < parseInt(brk2, 10)))
				return bounce(503, challenge(path, qstr(req.querystring)), method, 1);
		}
		return req;
	} catch (e) {
		return req;
	}
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

function canon(raw) {
	if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') > 8192 || raw.charAt(0) !== '/' || /[\\\x00-\x20\x7f?#;]/.test(raw))
		throw 1;
	var d;
	try {
		d = decodeURIComponent(raw);
	} catch (e) {
		throw 1;
	}
	if (/%(?:[0-7][0-9a-f])/i.test(raw) || /[\\\x00-\x20\x7f?#;%]/.test(d) || d.indexOf('//') !== -1) throw 1;
	var segs = d.split('/');
	for (var i = 1; i < segs.length; i++) if (segs[i] === '.' || segs[i] === '..') throw 1;
	var f = d.replace(/[A-Z]+/g, function (s) {
		return s.toLowerCase();
	});
	return f.length > 1 && f.charAt(f.length - 1) === '/' ? f.slice(0, -1) : f;
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
		k;
	for (k in qs) p.push(encodeURIComponent(k) + '=' + encodeURIComponent(qs[k].value));
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

function refuse(req, method, nav, ws, safe, path) {
	if (ws) return resp(403, H(), null);
	if (nav && safe) return bounce(503, challenge(path, qstr(req.querystring)), method, 1);
	if (nav && (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE'))
		return bounce(403, '/__mcl/resubmit', method, 0);
	var ch = safe || method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
	return resp(
		403,
		H('application/json', ch ? { 'x-monocle-challenge-required': { value: '1' } } : null),
		method === 'HEAD' ? null : '{"challenge":true}'
	);
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
	if (bp.redirect && typeof bp.redirect === 'string' && bp.redirect.charAt(0) === '/' && bp.redirect.indexOf('//') !== 0) {
		var st = method === 'GET' || method === 'HEAD' ? 307 : 303;
		return resp(st, H(null, { location: { value: bp.redirect } }), null);
	}
	return resp(code, H('text/html; charset=utf-8'), method === 'HEAD' ? null : html('/__mcl/blocked'));
}
