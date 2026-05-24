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
