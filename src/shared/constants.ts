/** Shared constants for the CloudFront port. Cookie names live in edge-core. */

export const EDGE_CONTRACT = '// Monocle edge contract: 2';

/** Host the assessment core loads from when `cfg.custom_domain` is absent. */
export const DEFAULT_CORE_HOST = 'js.mcl.io';

/** Bump when resident-script behaviour changes; feeds the `/__mcl/{segment}/mcl.js` URL. */
export const SCRIPT_VERSION = '8';

export const MAX_VERIFY_BODY_BYTES = 32 * 1024;
export const KVS_VALUE_BYTES = 1024;
export const KVS_CACHE_MS = 60_000;
/** Browser and CloudFront cache lifetime for the resident script and challenge page. */
export const SCRIPT_CACHE_SECONDS = 300;
