/** Shared constants for the CloudFront port. Cookie names and the core host live in edge-core. */

export const KVS_VALUE_BYTES = 1024;
export const KVS_CACHE_MS = 60_000;
/**
 * How long a verdict cookie minted on another clearance version stands: longer than a
 * container can go on holding the version from before a rotation. The Function writes it as
 * a literal.
 */
export const ROTATION_GRACE_SECONDS = 120;
/** Browser and CloudFront cache lifetime for the resident script and challenge page. */
export const SCRIPT_CACHE_SECONDS = 300;
