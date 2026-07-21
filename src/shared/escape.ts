/**
 * Encodes the five HTML-significant characters so customer-supplied block-page
 * text (title/body) renders as literal text, never markup: the block page's
 * injection defence. `&` is replaced first so the entities introduced here
 * aren't re-encoded.
 */
export function escapeHtml(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}
