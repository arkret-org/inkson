# Security Policy

## Supported versions

| Version | Status |
| --- | --- |
| Unreleased local 0.9.x | Supported for local release-readiness testing |
| Older local builds | Best-effort only |

## Reporting

Report vulnerabilities privately to the project maintainers through the
repository's private security channel or direct maintainer contact. Do not file
public issues for suspected credential exposure, key-storage weaknesses,
authorization bypasses, or push-token leaks.

Include:

- Affected commit or local build identifier.
- Platform and renderer (`web`, `desktop`, future `mobile`).
- Reproduction steps.
- Whether real credentials, device tokens, recovery keys, or message content
  were exposed.

## Handling expectations

- Treat local config files, secure-store records, push tokens, DPoP keys, and
  recovery material as secrets.
- Do not attach production tokens or private keys to bug reports.
- Rotate any token or key that was copied into logs, crash dumps, screenshots,
  or test fixtures.

## Release security gates

Before a local milestone is recorded:

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test --locked`
- `npm run e2e`
- Web image Trivy scan evidence under `dist/web-image/`
- SBOM evidence under `dist/web-image/`
- Signing dry-run evidence under `dist/signing/`
- Lighthouse budget report under `dist/lighthouse/`

## Concrete protections shipped today

The following are NOT plans — they are guarantees enforced by the
current branch:

### Dev token guard (`tests/dev_token_guard.rs`)

The integration test asserts that no committed source file under
`src/` references the dev-only placeholder tokens
(`yougen-dev-placeholder-token`, `desktop:yougen-dev-placeholder-token`,
or the `a..b` JWS marker) outside the `dev_proof` cfg-gated paths.
Production binaries built with `--no-default-features` never attach
the placeholder to an envelope.

### Push token redaction

`crate::push::ensure_production_register_request` rejects any
register-device request whose `push_key` matches the documented
placeholder markers BEFORE the body crosses the wire. The chime
orchestrator (`crate::push_registration::register_via_chime`) calls
this guard between resolving the real provider token and posting to
the principal server; a buggy provider that returns a placeholder
trips a `PushRegistrationError::PlaceholderTokenRejected` fail-closed
error rather than leaking the marker to floria.

### Local OS keychain handoff

On native targets, `crate::secure_key_store::KeyringSecureKeyStore`
routes signing-key persistence through macOS Keychain Services /
freedesktop Secret Service / Windows Credential Manager via the
`keyring 3.6.x` `Entry` API. The wasm32 build falls back to
`LocalStorageSecureKeyStore` / `IndexedDbSecureKeyStore`; the browser
"no symmetric-secret tier" trade-off is called out in the keystore
module docs. There is no code path that writes signing material to a
plain-text file on disk.

### Telemetry default OFF

Crash telemetry is opt-in (`CrashTelemetryPrefs::default()` is `false`).
The toggle lives in the settings page; turning it on requires an
explicit user gesture. No crash payload leaves the device until the
user flips the toggle.
