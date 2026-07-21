export const COOKIE_NAME = 'MCLVALID';

// The dedicated verify endpoint. The web app creates a CloudFront cache
// behavior for this exact path (AllowedMethods ALL, CachingDisabled) with the
// Lambda@Edge viewer-request association: the ONLY place the Lambda runs,
// keeping the expensive runtime off the per-request hot path.
export const VERIFY_PATH = '/__mcl/verify';

// Host for the Monocle Policy API. Note the `decrypt.` prefix: the backend
// SDK targets `https://decrypt.<baseDomain>/api/v1/policy`. Lambda@Edge has
// unrestricted outbound network access, so this is called directly (unlike
// Akamai, no CDN-fronted origin indirection is needed).
export const POLICY_API_URL = 'https://decrypt.mcl.spur.us/api/v1/policy';
