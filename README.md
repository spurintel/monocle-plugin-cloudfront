# Monocle CloudFront Integration

Monocle edge assessment and policy blocking for **Amazon CloudFront**, deployed
click-to-deploy from the Monocle dashboard into the customer's own AWS account
(cross-account IAM role). The customer pays AWS for the edge compute, exactly as
Fastly/Cloudflare customers pay for Compute/Workers.

## Architecture

Two runtimes split the work (see `src/`):

| | CloudFront Function (`src/function/index.js`) | Lambda@Edge (`src/lambda/`) |
|---|---|---|
| Trigger | viewer-request on every behavior covering protected paths | viewer-request on the dedicated `/__mcl/verify` behavior only |
| Job | validate the session cookie's HMAC; pass through or serve the interstitial | call the Monocle Policy API; mint the cookie; serve block responses |
| Cost/latency | sub-millisecond, runs on every request | runs once per session |

**Flow**: unverified visitor on a protected path → CloudFront Function serves a
minimal interstitial → browser runs Monocle (`mcl.js`) → POSTs the assessment to
`/__mcl/verify` → Lambda@Edge calls the Policy API → allow ⇒ `200` +
HMAC-signed cookie, deny ⇒ block response → browser reloads → CloudFront
Function validates the cookie and passes the request straight through to
**cache/origin untouched**.

That last property is the point of the split: verified traffic (and every
unprotected path) keeps CloudFront's edge caching, because a viewer-request
CloudFront Function can `return request` — unlike Akamai's `responseProvider`,
which must proxy the origin.

## Platform constraints this design encodes

Validated against AWS docs (July 2026):

- **CloudFront Functions** ([runtime 2.0](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/functions-javascript-runtime-20.html)):
  10 KB source limit (`build.mjs` and `test/function.test.ts` enforce it — the
  file is deployed as-written, no bundler), no network, no request body, crypto
  is `createHmac`/`createHash` **only** — hence the HMAC cookie scheme shared
  with `monocle-plugin-fastly`, never AES-GCM (the Cloudflare worker's scheme).
- **Lambda@Edge** ([restrictions](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-at-edge-function-restrictions.html)):
  us-east-1 only, numbered versions only, **no environment variables** — config
  is baked as `config.json` into the deployment zip by the dashboard
  (`src/lambda/config.ts`). A generated 204 with a body becomes a 502, so the
  verify success response is a `200`. Request body arrives base64, truncated at
  40 KB (ample for an assessment).
- **KeyValueStore** ([quotas](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-limits.html)):
  values ≤ 1 KB — `protectedPaths` overflows into `protectedPaths.1`, `.2`, …
  continuation keys. KVS updates apply WITHOUT redeploying, so protected-path
  edits are instant; block-config edits republish the Lambda.
- A cache behavior takes **one function per event type**: the CloudFront
  Function and Lambda@Edge live on different behaviors, and the dashboard
  pre-flights existing viewer-request associations before deploying.
- **Free flat-rate-plan distributions cannot attach a KVS-backed CloudFront
  Function** ([plan feature matrix](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/flat-rate-pricing-plan.html)) —
  verified live: the attach fails with "You can't associate this CloudFront
  Function to a distribution on a Free plan tier." Customers need a Pro+ plan
  or classic pay-as-you-go (cancelling a Free plan takes effect immediately).
  Lambda@Edge itself is allowed on every tier.

## KeyValueStore keys (read by the CloudFront Function)

| Key | Value |
|---|---|
| `cookieSecret` | hex HMAC key (also baked into the Lambda config, which mints) |
| `publishableKey` | Monocle publishable key for the interstitial script tag |
| `protectedPaths` | JSON `{ "<host>": ["/pattern*", …] }`, chunked into `.1`, `.2`, … when > 1 KB |

## Lambda `config.json` (baked at deploy)

```json
{
	"secretKey": "<monocle secret key>",
	"cookieSecret": "<hex hmac key>",
	"blockResponseType": "html | redirect (optional)",
	"blockStatusCode": "403",
	"blockPageTitle": "…",
	"blockResponseBody": "…",
	"blockRedirectUrl": "…"
}
```

## Develop

```sh
npm install
npm test        # vitest — includes the 10 KB size gate and a cross-implementation
                # pin: cookies minted by the Lambda code must validate in the
                # CloudFront Function source (loaded via an eval harness)
npm run build   # dist/function/index.js (verbatim copy, size-checked)
                # dist/lambda/index.js  (esbuild CJS bundle for node20)
```
