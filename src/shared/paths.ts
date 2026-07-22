/**
 * Matches a pathname against a route pattern where `*` matches any sequence of
 * characters (the same semantics as Cloudflare worker route patterns, e.g.
 * "/api/*" or "/login*"). Patterns are normalised by the web app to start with
 * "/" and end with "*", so this is usually a prefix match.
 *
 * Copied from monocle-plugin-fastly/src/paths.ts so all edge plugins scope
 * paths identically. The CloudFront Function inlines a compact copy of this
 * logic (it cannot import bundled modules); paths.test.ts covers this module and
 * function.test.ts exercises the inline copy through the handler over the same
 * classes of case (traversal, trailing slash, casing/encoding), so they can't drift.
 */
export function matchesPathPattern(pathname: string, pattern: string): boolean {
	const parts = pattern.split('*');
	if (parts.length === 1) return pathname === pattern;
	if (!pathname.startsWith(parts[0])) return false;

	// Without a trailing '*', the final literal must anchor at the END of the
	// path (endsWith), not at its first occurrence: "/shop/*/checkout" must match
	// "/shop/1/checkout/checkout", where the first "/checkout" is mid-path.
	const last = parts[parts.length - 1];
	let limit = pathname.length;
	if (last !== '') {
		if (!pathname.endsWith(last)) return false;
		limit = pathname.length - last.length;
	}

	// Middle literals match greedily left-to-right and must fit before the
	// end-anchored final literal.
	let index = parts[0].length;
	for (let i = 1; i < parts.length - 1; i++) {
		const part = parts[i];
		if (part === '') continue; // consecutive '*' matches anything
		const found = pathname.indexOf(part, index);
		if (found === -1 || found + part.length > limit) return false;
		index = found + part.length;
	}
	return index <= limit;
}

/**
 * Collapses `.` / `..` / empty segments (RFC 3986 remove-dot-segments, simplified).
 * CloudFront hands the function the RAW un-normalised URI and forwards it raw to
 * the origin, so without this `/x/../admin` or `//admin` evades a `/admin*` scope
 * yet resolves to `/admin` at a normalising origin. A trailing slash is preserved
 * (so `/checkout/` still matches a `/checkout/*` scope) to stay identical to the
 * Fastly oracle. Kept in sync with the inline `collapsePath` in the deployed function.
 */
function collapseDotSegments(path: string): string {
	const leadingSlash = path.startsWith("/");
	const trailingSlash = path.length > 1 && path.endsWith("/");
	const out: string[] = [];
	for (const seg of path.split("/")) {
		if (seg === "" || seg === ".") continue;
		if (seg === "..") out.pop();
		else out.push(seg);
	}
	let result = out.join("/");
	if (leadingSlash) result = `/${result}`;
	if (trailingSlash && out.length > 0) result += "/";
	return result || (leadingSlash ? "/" : "");
}

/**
 * Canonicalises a pathname for scoping: percent-decode once, collapse dot/empty
 * segments, then lower-case, so a request can't slip past a scoped pattern with
 * `/%61dmin`, `/ADMIN`, `/x/../admin`, or `//admin` when the origin would
 * canonicalise it back to a protected path. Best-effort: malformed encoding is
 * matched as-is (still collapsed + lower-cased) rather than throwing.
 */
function canonicalisePath(pathname: string): string {
	let decoded: string;
	try {
		decoded = decodeURIComponent(pathname);
	} catch {
		decoded = pathname;
	}
	return collapseDotSegments(decoded).toLowerCase();
}

/**
 * Whether a request falls inside the protected path patterns for its host.
 * No configuration at all, or a host with no entry, fails SAFE (protected),
 * so a missing/corrupt config item can never silently disable Monocle. The path
 * and patterns are matched case- and percent-encoding-insensitively so scoping
 * can't be evaded by re-casing or encoding the URL.
 */
export function isProtectedPath(
	hostname: string,
	pathname: string,
	protectedPaths: Record<string, string[]> | undefined
): boolean {
	if (!protectedPaths) return true;
	const patterns = protectedPaths[hostname.toLowerCase()];
	if (!patterns) return true;
	const path = canonicalisePath(pathname);
	return patterns.some(pattern => matchesPathPattern(path, pattern.toLowerCase()));
}
