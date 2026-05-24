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
