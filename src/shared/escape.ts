/**
 * Encodes the five HTML-significant characters so customer-supplied block-page
 * text (title/body) is rendered as literal text, never parsed as markup. This is
 * the injection defence for the block page: the values arrive as arbitrary
 * strings and are interpolated into HTML at the sink, so they MUST be escaped
 * here. `&` is replaced first so the entities we introduce aren't re-encoded.
 */
export function escapeHtml(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}
