# Monocle CloudFront Integration

Monocle assess/enforce edge protection for **Amazon CloudFront**, deployed click-to-deploy
from the Monocle dashboard into the customer's own AWS account (cross-account IAM role).
The customer pays AWS for the edge compute, exactly as Fastly and Cloudflare customers pay
for Compute and Workers.

The shared contract lives in `@spur.us/monocle-edge-core`; the Cloudflare Worker is the
reference implementation. This plugin is the CloudFront port of that contract, with the
differences the platform forces listed below.

## Architecture

Two runtimes split the work (see `src/`):

| | CloudFront Function (`src/function/index.js`) | Lambda@Edge (`src/lambda/`) |
|---|---|---|
| Trigger | viewer-request on the default behavior and every customer behavior | origin-request on the `/__mcl/*` behaviors only |
| Job | the guard ladder: path readings, verdict cookie, crawler and allow-list passes, refusal shells | `/__mcl/state`, `/__mcl/verify` (Policy call and cookie minting), the challenge, resubmit and block pages, the resident script, the hourly crawler refresh |
| Cost and latency | sub-millisecond, runs on every request | runs only inside the challenge flow |

**Flow**: a visitor without a valid decision opens an assessed page. The Function answers
a 503 shell that navigates to `/__mcl/challenge?return=<path>`. The challenge page runs
Monocle, POSTs the assessment to `/__mcl/verify`, the Lambda calls the Policy API and mints
an HMAC-sealed `__Host-mcl_c` cookie (allow one hour, block ten minutes), the page reloads
the return path, and the Function passes the request through to **cache and origin
untouched**. Enforced paths refuse a cookieless request by shape (challenge shell, resubmit
shell, challenge JSON, or an empty 403 for WebSockets) and answer a block verdict with the
customer's block page, redirect or JSON. When Policy cannot answer a verify (down, erroring,
refusing our key or too slow), the Lambda passes the visitor for ten minutes instead: our
failure never answers them, and nothing about it is written to the store.

The Function protects every hostname the distribution serves. CloudFront routes on the Host,
so an alias the deployment does not list, or the `*.cloudfront.net` name, reaches the same
origin and is the same site. `OPTIONS` needs a verdict on an enforced path like any other
method: the edge core passes a CORS preflight and returns only its headers, but a
viewer-request Function cannot drop the origin's body.

Verified traffic and every uncovered path keep CloudFront's edge caching, because a
viewer-request Function can `return request`.

## Platform constraints this design encodes

- **CloudFront Functions** ([runtime 2.0](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/functions-javascript-runtime-20.html)):
  10 KB source limit (`build.mjs` and `test/function.test.ts` enforce it on the stripped
  artifact), no network, no request body, crypto is `createHmac`/`createHash` only. So the
  cookie seal is HMAC-SHA256 over the edge core's v2 envelope, not AES-GCM, and the
  challenge page is not inlined: the Function serves a 300-byte shell that navigates to
  tier two. No injection is possible, so `injection` is always `off` on CloudFront.
- **Lambda@Edge** ([restrictions](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-at-edge-function-restrictions.html)):
  us-east-1 only, numbered versions only, no environment variables. Secrets are baked as
  `config.json` into the deployment zip; everything a dashboard save can change is read
  from the KeyValueStore. The origin-request trigger is used because it allows 30 seconds
  and 1 MB bodies; viewer-request's 5 seconds cannot hold a Policy call.
- **KeyValueStore** ([quotas](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-limits.html)):
  values at most 1 KB, so long values chunk into `.1`, `.2`, … continuation keys. Updates
  apply without redeploying, so path, block-page and policy edits are live within seconds.
- A cache behavior takes **one function per event type**: the Function and the Lambda
  live on different behaviors, and the dashboard pre-flights existing viewer-request
  associations before deploying.
- **Free flat-rate-plan distributions cannot attach a KVS-backed CloudFront Function**
  ([plan feature matrix](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/flat-rate-pricing-plan.html)).
  Customers need a Pro+ plan or classic pay-as-you-go.

## Behaviors the dashboard attaches

| Path pattern | Cache policy | Lambda | Purpose |
|---|---|---|---|
| `/__mcl/*/mcl.js` | CachingOptimized | origin-request | The resident script for the manual include; cached per segment |
| `/__mcl/challenge` | CachingOptimized | origin-request | The visible check page; static, reads `return` client-side |
| `/__mcl/*` | CachingDisabled | origin-request, IncludeBody | state, verify, blocked, resubmit |

All three use the AllViewerExceptHostHeader origin-request policy so the Lambda sees the
viewer's Origin, Cookie and Sec-Fetch headers.

Session tracking differs from the Worker in one place. The Worker tags the core URL with
`cpd=<sid>` when it serves the challenge page or resident script; here both are cached and
identical for every visitor, so `GET /__mcl/state` returns `{hint, sid}`, mints
the session cookie when tracking is on and none is held, and the scripts append `cpd`
themselves before loading the core. The session cookie is attribution only.

## KeyValueStore keys (read by the Function unless noted; `cv` and `cfg` by the Lambda too)

| Key | Value | Writer |
|---|---|---|
| `v` | `2` | dashboard |
| `hosts` | Lambda only: JSON array of lowercase hostnames verify accepts an `Origin` from, besides the distribution's own domain and any browser stating `Sec-Fetch-Site: same-origin` | dashboard |
| `k` | sealing key hex | dashboard |
| `cv` | clearance version, 64 lowercase hex | dashboard |
| `id` | deployment id, the cookie audience | dashboard |
| `cfg` | JSON `{session_tracking, block_page, custom_domain}` | dashboard |
| `ips` | packed `allow_ips` ranges | dashboard |
| `w` | wildcard-segment patterns `[{p, e}]`, at most 100 | dashboard |
| `p:<path>` | `e` enforced exact, `a` assessed exact | dashboard |
| `s:<prefix>` | `e` enforced subtree, `a` assessed subtree | dashboard |
| `bots` | packed crawler ranges plus `expiresAt` | Lambda, hourly |

Route resolution is a walk: for `/a/b/c` the Function reads `p:/a/b/c`, then `s:/a/b/c`,
`s:/a/b`, `s:/a`, `s:/`, then scans `w`. Enforcement applies if any `e` matches; assessment
if any `a` matches. There is no specificity contest between the two, as in the edge core.

## Lambda `config.json` (baked at deploy)

```json
{
	"secretKey": "<monocle secret key>",
	"cookieSecret": "<hex sealing key>",
	"publishableKey": "<monocle publishable key>",
	"deploymentId": "<app id>",
	"kvsArn": "arn:aws:cloudfront::<account>:key-value-store/<id>"
}
```

The Lambda's execution role needs `cloudfront-keyvaluestore:DescribeKeyValueStore`,
`GetKey` and `UpdateKeys` on that store. An EventBridge Scheduler rule invokes the same
function hourly with `{"refresh":"crawlers"}` to rewrite `bots`.

## Develop

```sh
npm install
npm test        # vitest: the 10 KB size gate, the strict-v3 path corpus run through the
                # Function, the cross-pin that the Function opens what the Lambda mints,
                # and the endpoint contract
npm run build   # dist/function/index.js (stripped, size-checked, contract banner)
                # dist/lambda/index.js  (esbuild CJS bundle for node20, contract banner)
```

Both artifacts begin with `// Monocle edge contract: 2`; the dashboard refuses artifacts
without it.
