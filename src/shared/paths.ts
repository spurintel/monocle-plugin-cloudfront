/**
 * Matches a pathname against a route pattern where `*` matches any sequence of
 * characters (the same semantics as Cloudflare worker route patterns, e.g.
 * "/api/*" or "/login*"). Patterns are normalised by the web app to start with
 * "/" and end with "*", so this is usually a prefix match.
 *
 * Copied from monocle-plugin-fastly/src/paths.ts so all edge plugins scope
 * paths identically. The CloudFront Function inlines a compact copy of this
 * logic (it cannot import bundled modules); test/function.test.ts pins the two
 * implementations against the same cases so they cannot drift.
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
 * Canonicalises a pathname for scoping: percent-decode once, then lower-case, so
 * a request can't slip past a scoped pattern with `/%61dmin` or `/ADMIN` when the
 * origin would canonicalise it back to a protected path. Best-effort: malformed
 * encoding is matched as-is (still lower-cased) rather than throwing.
 */
function canonicalisePath(pathname: string): string {
	try {
		return decodeURIComponent(pathname).toLowerCase();
	} catch {
		return pathname.toLowerCase();
	}
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
