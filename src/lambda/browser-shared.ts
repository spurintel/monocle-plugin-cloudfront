/** Browser-side source shared by the challenge page and the resident script. */

/** Fetches a Worker endpoint under one 15 s budget; a non-JSON body reads as null. */
export function edgeRequestJs(fetchIdent: 'fetch' | 'nativeFetch'): string {
	return `
	function edgeRequest(url, options) {
		var controller = new AbortController();
		var timer = setTimeout(function () { controller.abort(); }, 15000);
		return ${fetchIdent}(url, Object.assign({}, options, {
			credentials: 'same-origin', signal: controller.signal,
		})).then(function (response) {
			return response.json().catch(function () { return null; }).then(function (data) {
				return { status: response.status, data: data };
			});
		}).finally(function () { clearTimeout(timer); });
	}`;
}
