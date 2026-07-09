# Security Policy

## Supported versions

| Version | Status |
| --- | --- |
| Unreleased local 0.3.x | Supported for local release-readiness testing |
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

### Private reporting channel

Use the lowest-bandwidth channel that still lets you attach repro steps.

> **Pre-release notice:** inkson has not been publicly released, so the
> dedicated security email and PGP key below are **not yet provisioned**.
> Until they are, report privately through GitHub Private Vulnerability
> Reporting on the canonical repository, or via direct maintainer contact.
> This file is updated with a real address + PGP fingerprint as part of the
> public-release checklist.

- **Email**: not yet provisioned (a dedicated `security@` address with a
  published PGP key ships with the first public release).
- **PGP fingerprint**: not yet generated (see the pre-release notice above).
- **GitHub Private Vulnerability Reporting**: preferred channel until the
  email/PGP channel is provisioned.

Reports are acknowledged within 3 business days. If you do not receive an
acknowledgement, your message did not arrive — please retry through a
different channel (mention "inkson security" in the subject line).

What to expect:

1. **Acknowledgement** (≤ 3 business days) — confirms receipt + assigns
   a private tracking ID.
2. **Triage** (≤ 10 business days) — severity rating + initial
   reproduction.
3. **Fix window** — coordinated disclosure timeline shared privately.
   Critical issues may ship a hotfix before public disclosure.
4. **Public note** — once a fix lands, the issue is documented in
   `CHANGELOG.md` with credit to the reporter unless they opt out.

Do **not** include real production tokens, private keys, or message
content in the report. Reproduce against a throwaway account when
possible.

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

The integration test asserts that the dev-only placeholder push tokens
(`inkson-dev-…`, `placeholder`) are always recognised by the production
guard so they can never reach a real push gateway. Event envelopes carry
NO placeholder proof: `OperationBuilder::build()` always emits
`proofs: Vec::new()` and the submit guard stays fail-closed in
`ProofMode::Production` until a real signer is installed.

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
`LocalStorageSecureKeyStore` for first paint, then upgrades to
`IndexedDbSecureKeyStore` once IndexedDB and SubtleCrypto are available.
The first-paint localStorage tier stores the AEAD wrapping seed and
ciphertext under the same origin, so an XSS, extension, or browser profile
dump during that window can decrypt secrets offline. After the async upgrade succeeds,
the seed and migrated ciphertext are removed from localStorage and
new reads use IndexedDB plus a non-extractable SubtleCrypto key. Browsers
that deny IndexedDB/SubtleCrypto keep the weaker localStorage fallback only
for low-value first-paint secrets; signing seeds, account MLS secrets, and
session credentials fail closed unless a test build explicitly enables the
`wasm-localstorage-secrets-test` feature. There is no runtime localStorage
switch that can opt production builds into sensitive localStorage writes, and
no code path writes signing material to a plain-text file on disk.

### Device revocation boundary

Revoking a device removes it from the active device set, asks MLS groups to
remove the leaf, invalidates future KeyPackages, unregisters push wakeups, and
rotates the account MLS history secret for future backups. This is not a
remote wipe: it cannot remotely erase secrets, plaintext cache, or old
`mls_history` backups that were already
copied onto the revoked device. Users should treat a lost or compromised
device as able to read anything it retained before revocation until account
secret versioning/rotation evidence proves otherwise.

### Telemetry default OFF

Crash telemetry is opt-in (`CrashTelemetryPrefs::default()` is `false`).
The toggle lives in the settings page; turning it on requires an
explicit user gesture. No crash payload leaves the device until the
user flips the toggle.
