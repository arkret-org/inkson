# inkson Deployment Guide

inkson is a client artifact. Deployment means packaging a desktop or web build
and pointing it at already deployed Arkret services.

## Service pairing

Configure the Station base URL in the Settings view or local config.
For local release testing, run coland first and use an externally reachable
origin for web builds:

```powershell
cd ../coland
cargo run -- --bind local.host:443
```

Web deployments must satisfy all of the following:

- The coland origin is allowed by CORS.
- Discovery returns the Station, coauth, and push-gateway endpoints.
- TLS is valid for the browser origin used by the client.
- The UI is served from the web image or a static host that preserves the
  Dioxus generated asset paths.

## Push gateway wiring

The client reads push-gateway capability data from service discovery and then
registers device metadata with chime using a coauth session grant. Web builds
use the browser Push API. Native builds expect host code to pass real FCM/APNs
tokens into `set_fcm_push_token` or `set_apns_push_token`; local desktop tests
may inject the same values through `INKSON_FCM_PUSH_TOKEN`,
`INKSON_APNS_PUSH_TOKEN`, `FCM_PUSH_TOKEN`, `APNS_DEVICE_TOKEN`, or
`CHASK_PUSH_KEY`.

Required deployment inputs:

- coland push registration endpoint enabled.
- chime gateway reachable from the client network.
- coauth session grant persisted in local state before `register_device`.
- Platform push credentials configured on the gateway, not embedded in inkson.
- The client Station URL and device ID match the persisted grant; the
  registration path fails closed on mismatch.

Privacy requirements:

- Push payloads must remain wakeup-only.
- Message content, actor names, realm names, and recovery material must not be
  placed in push payloads.
- Device tokens are secrets and should be rotated when a device is revoked.

## Desktop deployment

Build locally:

```powershell
cargo build --release --features desktop
powershell -ExecutionPolicy Bypass -File scripts/signing-dry-run.ps1
```

The signing dry-run records local evidence under `dist/signing/`. It is safe to
run in CI because it does not submit to Apple, Microsoft timestamp authorities,
or external signing services.

## Web deployment

Prepare the sibling checkout context and build the image:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/prepare-docker-context.ps1
docker build -f docker-context/inkson/Dockerfile -t inkson-web:local docker-context
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
  `src/secure_key_store/`.
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
connect-src 'self' https://<your-coland-origin> https://<your-chime-origin>;
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
- Enumerate the coland + chime origins explicitly in `connect-src`. Do
  **not** ship `connect-src *`.
- `frame-ancestors 'none'` prevents click-jacking. inkson is a top-level
  app, not an embed.
- `dangerous_inner_html` is permanently disabled at the source level — see
  `crate::content` and `pulldown-cmark` configuration.

### CORS

coland sets the CORS policy; inkson is the browser caller. Required
coland response headers for the inkson web origin:

```text
Access-Control-Allow-Origin: https://<inkson-web-origin>
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: authorization, content-type, idempotency-key,
                              x-arkret-request-id, dpop
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Expose-Headers: x-arkret-request-id
Access-Control-Max-Age: 600
```

`Access-Control-Allow-Origin: *` is **forbidden** because the browser
also sends DPoP-bound credentials and the `ak.session.grant` cookie.

### TLS

- Minimum: TLS 1.2; prefer 1.3.
- Reject SHA-1 cert chains.
- Use a separate certificate per origin (coland, chime, the static
  inkson host). Wildcards are acceptable when scoped to a single trust
  boundary.
- HSTS: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
  for the inkson web origin.
- OCSP stapling on the coland edge to reduce a fingerprinting vector.
- Certificate transparency: rely on your CA. inkson does not currently
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

## macOS notarization gate (no version bump)

inkson's R3 sync is a no-version-bump release: the binary identity stays
the same, but the contents change. Apple's notarization service does NOT
require a version bump, but it DOES require that every distributed
binary has been notarized and stapled. The "no version bump" constraint
means you must re-notarize the rebuilt artifact without changing
`CFBundleShortVersionString`.

Steps for a no-bump notarization:

1. **Hardened-runtime build.** Build the release binary, then create the app
   bundle with `pwsh scripts/macos-bundle-local.ps1`. Apply hardened-runtime
   signing in the following codesign step.
2. **Codesign** with the Developer ID Application certificate:
   ```sh
   codesign --force --sign "Developer ID Application: Acroidea LLC (TEAMID)" \
       --options runtime \
       --entitlements deploy/macos/entitlements.plist \
       --timestamp \
       target/release/inkson.app
   ```
3. **Submit to notary**:
   ```sh
   xcrun notarytool submit inkson.zip \
       --apple-id "release@acroidea.com" \
       --team-id TEAMID \
       --password "$NOTARY_APP_SPECIFIC_PASSWORD" \
       --wait
   ```
   Typical turnaround: 5–30 minutes.
4. **Staple**:
   ```sh
   xcrun stapler staple target/release/inkson.app
   xcrun stapler validate target/release/inkson.app
   ```
5. **Re-zip and publish** the stapled `.app` to the distribution
   channel.

Failure modes:

- **"Invalid hardened runtime"** — the `--options runtime` flag was
  missing at codesign. Re-sign and resubmit.
- **"App contains a non-codesigned framework"** — a vendored framework
  (commonly the WebRTC or media-decode framework) was added without
  signing. Sign the framework separately before signing the app bundle.
- **"Submission queued for hours"** — Apple Notary occasional capacity
  issue; no escalation path. Plan your release window accordingly.

Notarization gate as part of CI: the GH Actions workflow runs notarization
on tagged builds only. For no-bump releases, run the workflow manually
with `workflow_dispatch` and pin the artifact SHA in the release evidence
note.

## Windows code-signing

Windows code-signing uses an EV (Extended Validation) certificate to
establish SmartScreen reputation. Without EV, SmartScreen prompts users
on first launch even after the cert is "valid"; with EV, prompts are
suppressed after the first ~100 installs build reputation.

Setup:

1. EV cert lives on a hardware token (the issuer ships a USB-attached
   token; the private key MUST NOT leave the token).
2. Build the release binary, then create the local MSI artifact with
   `pwsh scripts/windows-msi-local.ps1`.
3. Sign with `signtool`:
   ```powershell
   signtool sign /n "Acroidea LLC" `
       /fd SHA256 `
       /tr http://timestamp.digicert.com `
       /td SHA256 `
       target/release/inkson.exe
   ```
4. Verify:
   ```powershell
   signtool verify /pa /v target/release/inkson.exe
   ```

No-version-bump constraints:

- Windows treats two binaries with the same `FileVersion` and `ProductVersion`
  but different SHA-256 as distinct executables; SmartScreen reputation
  attaches to the **SHA-256**, not the version string. A no-bump rebuild
  resets SmartScreen reputation for the new SHA.
- Mitigation: ship the no-bump rebuild only to existing installs via the
  in-app updater (which checks the publisher cert directly and bypasses
  SmartScreen). New downloads SHOULD use a versioned build.

EV token operational concerns:

- The token is single-actor. Only one signer at a time; serialize signing
  through the release human.
- Token PIN entry is required per-signing-session; do NOT script the PIN.
- Backup token is kept in a separate safe at the office. Rotate the
  signing operator (not the cert) quarterly.

## iOS / Android publish gate notes

### iOS

- **TestFlight** for pre-prod cohorts; production via App Store Connect.
- Both gates require:
  - Notarization-equivalent signing (provisioning profile + distribution
    cert).
  - App Store review (1–7 days first submission; faster for updates).
  - Privacy manifest declaring data collection — for inkson, declare:
    "Contact info: collected for account creation; not linked to user
    across apps; not used for tracking".
- No-bump constraint: App Store Connect REQUIRES a version-string bump
  for every new build accepted into review. To honor the no-bump policy,
  do NOT submit no-bump R3 rebuilds to App Store Connect; ship them
  through enterprise distribution / TestFlight internal-only.
- Export compliance: inkson uses E2EE (MLS + SFrame); declare under the
  export-compliance section. Exemption category: "App uses standard,
  publicly-available encryption (TLS, MLS RFC 9420, SFrame draft)".

### Android

- **Internal testing track** via Play Console for pre-prod cohorts;
  production via the production track.
- Both require:
  - Play App Signing enrollment (Google holds the production signing
    key; you upload signed APK/AAB with an upload key).
  - Data safety form declaring data collection (mirror the iOS privacy
    manifest declarations).
- No-bump constraint: Play Console requires a `versionCode` bump for
  every uploaded build. Same workaround as iOS: do NOT publish no-bump
  rebuilds through Play; ship via enterprise / sideload-only channels.
- Target API level: inkson pins target SDK at the Play-required minimum
  (currently 34, may rise per Play schedule).
- Sideload distribution: produce APK + signed APKM manifest with
  SHA-256; users add inkson's update channel URL to the in-app updater
  to receive sideload-distributed updates.

### Publish-gate quick reference

| Platform | Store-required version bump? | No-bump distribution path |
|---|---|---|
| macOS | No (notarization is content-addressed) | Notarize + staple + push via in-app updater |
| Windows | No (SmartScreen is content-addressed) | Sign + push via in-app updater |
| iOS | **Yes** (App Store Connect) | Skip Store; TestFlight internal / enterprise distribution |
| Android | **Yes** (Play Console versionCode) | Skip Play; sideload via in-app updater |
| Web | N/A | Cache-bust asset path |
