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
registers device metadata with soland. For phase 3, live OS token bridges and
chime server-grant minting remain tracked separately in `_yougen_todos.md`.

Required deployment inputs:

- soland push registration endpoint enabled.
- chime gateway reachable from the client network.
- coauth grant mint API available before `register_device`.
- Platform push credentials configured on the gateway, not embedded in yougen.

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

Mobile release scope is still a phase-3 decision item. If mobile remains in
scope, prepare:

- macOS runner with Xcode and iOS signing material for ad-hoc `.ipa` builds.
- Android SDK, NDK, Gradle, and a local signing keystore for APK builds.
- Real Android Keystore and iOS Keychain implementations in
  `src/secure_key_store.rs`.
- Real FCM/APNs token bridges before push registration can be considered
  production-ready.

Until that decision closes, the release target is desktop plus web.
