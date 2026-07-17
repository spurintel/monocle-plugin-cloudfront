import { describe, expect, it } from 'vitest';

import { isProtectedPath, matchesPathPattern } from '../src/shared/paths';

describe('matchesPathPattern', () => {
	it('matches exact paths with no wildcard', () => {
		expect(matchesPathPattern('/login', '/login')).toBe(true);
		expect(matchesPathPattern('/login/x', '/login')).toBe(false);
	});

	it('matches prefix patterns', () => {
		expect(matchesPathPattern('/api/users', '/api/*')).toBe(true);
		expect(matchesPathPattern('/login2', '/login*')).toBe(true);
		expect(matchesPathPattern('/other', '/api/*')).toBe(false);
	});

	it('anchors a trailing literal at the end of the path', () => {
		expect(matchesPathPattern('/shop/1/checkout/checkout', '/shop/*/checkout')).toBe(true);
		expect(matchesPathPattern('/shop/1/checkout/extra', '/shop/*/checkout')).toBe(false);
	});

	it('matches middle literals greedily within the anchored limit', () => {
		expect(matchesPathPattern('/a/x/b/y/c', '/a/*/b/*/c')).toBe(true);
		expect(matchesPathPattern('/a/x/y/c', '/a/*/b/*/c')).toBe(false);
	});
});

describe('isProtectedPath', () => {
	const paths = { 'www.example.com': ['/login*', '/api/*'] };

	it('protects matching paths and passes the rest', () => {
		expect(isProtectedPath('www.example.com', '/login', paths)).toBe(true);
		expect(isProtectedPath('www.example.com', '/api/users', paths)).toBe(true);
		expect(isProtectedPath('www.example.com', '/about', paths)).toBe(false);
	});

	it('fails SAFE with no config or an unlisted host', () => {
		expect(isProtectedPath('www.example.com', '/about', undefined)).toBe(true);
		expect(isProtectedPath('other.example.com', '/about', paths)).toBe(true);
	});

	it('cannot be evaded by re-casing or percent-encoding', () => {
		expect(isProtectedPath('WWW.EXAMPLE.COM', '/LOGIN', paths)).toBe(true);
		expect(isProtectedPath('www.example.com', '/%6Cogin', paths)).toBe(true);
	});
});
