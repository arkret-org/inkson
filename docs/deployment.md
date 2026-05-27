# yougen Deployment Guide

yougen is a client artifact. Deployment means packaging a desktop or web build
and pointing it at already deployed Contrix services.

## Service pairing

Configure the Principal Server base URL in the Settings view or local config.
For local release testing, run soland first and use an externally reachable
origin for web builds:

```powershell
cd ../soland
cargo run -- --bind local.host:443
```

Web deployments must satisfy all of the following:

- The soland origin is allowed by CORS.
- Discovery returns the Principal Server, coauth, and push-gateway endpoints.
- TLS is valid for the browser origin used by the client.
- The UI is served from the web image or a static host that preserves the
  Dioxus generated asset paths.

## Push gateway wiring

The client reads push-gateway capability data from service discovery and then
registers device metadata with chime using a coauth session grant. Web builds
use the browser Push API. Native builds expect host code to pass real FCM/APNs
tokens into `set_fcm_push_token` or `set_apns_push_token`; local desktop tests
may inject the same values through `YOUGEN_FCM_PUSH_TOKEN`,
`YOUGEN_APNS_PUSH_TOKEN`, `FCM_PUSH_TOKEN`, `APNS_DEVICE_TOKEN`, or
`CHASK_PUSH_KEY`.

Required deployment inputs:

- soland push registration endpoint enabled.
- chime gateway reachable from the client network.
- coauth session grant persisted in local state before `register_device`.
- Platform push credentials configured on the gateway, not embedded in yougen.
- The client principal server URL and device ID match the persisted grant; the
  registration path fails closed on mismatch.

Privacy requirements:

- Push payloads must remain wakeup-only.
- Message content, actor names, realm names, and recovery material must not be
  placed in push payloads.
- Device tokens are secrets and should be rotated when a device is revoked.

## Desktop deployment

Build locally:

```powershell
cargo build --release
powershell -ExecutionPolicy Bypass -File scripts/signing-dry-run.ps1
```

The signing dry-run records local evidence under `dist/signing/`. It is safe to
run in CI because it does not submit to Apple, Microsoft timestamp authorities,
or external signing services.

## Web deployment

Prepare the sibling checkout context and build the image:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/prepare-docker-context.ps1
docker build -f docker-context/yougen/Dockerfile -t yougen-web:local docker-context
```

Generate local image evidence:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/web-image-evidence.ps1 -SkipBuild
```

The image is local-only. Do not push it to GHCR or another registry as part of
the phase-3 local release plan.

## Mobile build setup

The phase-3 local milestone ships desktop plus web. Mobile remains out of the
local 1.0 scope, so no iOS `.ipa` or Android APK is produced by this plan. If a
future phase accepts mobile scope, prepare:

- macOS runner with Xcode and iOS signing material for ad-hoc `.ipa` builds.
- Android SDK, NDK, Gradle, and a local signing keystore for APK builds.
- Real Android Keystore and iOS Keychain implementations in
  `src/secure_key_store.rs`.
- Thin host adapters that forward FCM/APNs tokens into the Rust bridge before
  push registration.

---

## Production hardening — CSP / CORS / TLS / update channel

Everything in this section is **production-only**. Local dev defaults are
permissive enough for the dev loop but unfit for any internet-facing host.

### Content Security Policy

The web image ships with the following CSP. Set it as an HTTP response
header (preferred) or, only if your host cannot, as a `<meta http-equiv>`
tag:

```text
default-src 'self';
script-src 'self' 'wasm-unsafe-eval';
style-src 'self' 'unsafe-inline';
img-src 'self' data: blob:;
connect-src 'self' https://<your-soland-origin> https://<your-chime-origin>;
font-src 'self' data:;
frame-ancestors 'none';
base-uri 'self';
form-action 'self';
report-uri /csp-report;
```

Notes:

- `wasm-unsafe-eval` is required — Dioxus loads the WebAssembly bundle.
- `style-src 'unsafe-inline'` is required by Dioxus's runtime `style="..."`
  prop interpolation. **TODO(P5-impl)**: migrate to scoped style tags so we
  can drop `unsafe-inline`.
- Enumerate the soland + chime origins explicitly in `connect-src`. Do
  **not** ship `connect-src *`.
- `frame-ancestors 'none'` prevents click-jacking. yougen is a top-level
  app, not an embed.
- `dangerous_inner_html` is permanently disabled at the source level — see
  `crate::content` and `pulldown-cmark` configuration.

### CORS

soland sets the CORS policy; yougen is the browser caller. Required
soland response headers for the yougen web origin:

```text
Access-Control-Allow-Origin: https://<yougen-web-origin>
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: authorization, content-type, idempotency-key,
                              x-contrix-request-id, dpop
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Expose-Headers: x-contrix-request-id
Access-Control-Max-Age: 600
```

`Access-Control-Allow-Origin: *` is **forbidden** because the browser
also sends DPoP-bound credentials and the `cx.session.grant` cookie.

### TLS

- Minimum: TLS 1.2; prefer 1.3.
- Reject SHA-1 cert chains.
- Use a separate certificate per origin (soland, chime, the static
  yougen host). Wildcards are acceptable when scoped to a single trust
  boundary.
- HSTS: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
  for the yougen web origin.
- OCSP stapling on the soland edge to reduce a fingerprinting vector.
- Certificate transparency: rely on your CA. yougen does not currently
  pin certificates — that is a deferred mobile-only concern.

### Update channel

Desktop releases are distributed via the same dry-run dance documented
in [`build-per-platform.md`](build-per-platform.md). Until codesign /
notarization graduate out of dry-run, **do not** ship an auto-update
channel to end users — there is no signed manifest to verify.

For pre-prod cohorts:

- Publish artifacts to a private object store with TLS + auth.
- Pin the artifact sha256 in a separate signed manifest under your
  control.
- Run `scripts/codesign-dryrun.{ps1,sh}` against each artifact to record
  evidence of what was (or was not) signed.
- Ship a manual "Check for updates" UI surface that pulls the manifest
  and warns when the local artifact sha differs.

The web build naturally rolls forward on next page load; cache-bust by
versioning the asset path (Dioxus does this by default).

