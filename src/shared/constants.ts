/** Shared constants for the CloudFront port. Cookie names and the core host live in edge-core. */

export const KVS_VALUE_BYTES = 1024;
/** How long a container uses what it read from the store: each read is billed, $1 per 1,000 calls. */
export const KVS_CACHE_MS = 300_000;
/** How long a container waits to ask a store it could not read again. */
export const KVS_RETRY_MS = 10_000;
/**
 * How long a verdict cookie minted on another clearance version stands: longer than a
 * container can go on holding the version from before a rotation. The Function writes it as
 * a literal.
 */
export const ROTATION_GRACE_SECONDS = 360;
/** Browser and CloudFront cache lifetime for the resident script and challenge page. */
export const SCRIPT_CACHE_SECONDS = 300;
