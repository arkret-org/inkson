# yougen Threat Model

## Scope

This model covers the yougen client: web, desktop, and the planned mobile
surface. Server authorization, federation, and push gateway internals are
owned by soland, coauth, and chime, but yougen is responsible for preserving
their security properties at the client boundary.

## Assets

- Principal session tokens and refresh state.
- DPoP private keys and proof material.
- Local device identity and cross-signing state.
- Local encryption keys and secure-store handles.
- Recovery keys and recovery-flow state.
- Push tokens and push registration identifiers.
- Cached plaintext message content and attachments.

## Trust boundaries

- Browser or desktop renderer to local storage.
- yougen to soland HTTP API.
- yougen to coauth OIDC and grant endpoints.
- yougen to chime push registration path.
- Local OS secure storage boundary.
- Clipboard, filesystem import/export, and crash/log output.

## Local key storage risks

Threats:

- A renderer XSS or compromised dependency reads IndexedDB/local storage.
- Desktop filesystem compromise reads fallback state.
- Mobile stubs bypass platform secure storage.
- Logs accidentally include DPoP proofs, key identifiers, or recovery data.

Controls:

- Prefer OS secure storage for long-lived keys.
- Keep browser storage scoped and avoid plaintext secret duplication.
- Keep recovery material out of logs, UI telemetry, and crash reports.
- Replace mobile secure-store stubs before mobile release scope is accepted.

Open phase-3 items:

- IndexedDB key-store hardening is tracked in `_yougen_todos.md` §20.
- Android Keystore and iOS Keychain work is out of the desktop/web local
  milestone and remains tracked behind the mobile scope gate in §5-§8.

## Push privacy risks

Threats:

- Push payload reveals message content, actor identity, realm name, or recovery
  state to a platform push provider.
- Device tokens leak through logs or diagnostics.
- A stale token continues receiving wakeups after device revocation.

Controls:

- Push payloads are wakeup-only.
- Token values are treated as secrets.
- Device revocation must clear local push registration state.
- Gateway credentials stay server-side.

Controls now in place:

- WebPush uses the browser Push API, and native FCM/APNs providers accept only
  host-supplied or local-env injected real tokens.
- chime registration loads the persisted coauth grant, validates principal
  server and device binding, mints introspection proof headers, and fails
  closed when grant material is missing or mismatched.

## Recovery flow risks

Threats:

- A malicious or stale recovery path restores keys onto the wrong device.
- Partial bootstrap state is accepted as complete.
- Late-recovered content appears without user-visible context.

Controls:

- Recovery should require explicit user action and device verification.
- Partial snapshot/bootstrap state must fail clearly until chunked import is
  fully implemented.
- Late-recovery banners must remain visible when older content decrypts after
  arrival.

Open phase-3 items:

- Partial bootstrap behavior is tracked in §13.
- OIDC callback and passkey completion is tracked in §18.

## Supply-chain and release risks

Threats:

- A web image is built from an unscanned dependency set.
- A local artifact is mistaken for a signed/notarized public release.
- A workflow pushes an image or publishes a tag unintentionally.

Controls:

- Docker workflow is local-build-only and uploads scan/SBOM evidence.
- Signing dry-run evidence records that remote submit, timestamping, and
  transparency-log upload are disabled.
- Release checklist explicitly forbids tags, registry pushes, and crates.io
  publication for this local phase.
