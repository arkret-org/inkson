# yougen

Cross-platform Contrix client built with Dioxus 0.7. Licensed under
[Apache-2.0](LICENSE). Vulnerability reporting and threat model live in
[SECURITY.md](SECURITY.md); contributor workflow in
[CONTRIBUTING.md](CONTRIBUTING.md).

## Targets

- Web: `dx serve --platform web`
- Desktop Windows/Linux: `dx serve --platform desktop`
- iOS/mobile: `dx serve --platform mobile`

Platform notes:

- Web builds use the Dioxus web renderer and must talk to `soland` through an HTTP(S) origin allowed by the Principal Server CORS configuration. Keep `CLIENTX_SERVER_URL` or the settings panel pointed at the externally reachable server URL, not an internal desktop-only loopback address.
- Windows and Linux desktop builds use the Dioxus desktop renderer. Local development defaults to `http://127.0.0.1:8787` and stores the last server/account/device/session settings in the local config store.
- iOS/mobile builds use the Dioxus mobile renderer. Device builds require the platform toolchain (`dx`, Xcode/iOS signing on macOS for iOS, platform SDKs for other mobile targets). Treat loopback URLs as emulator-local; use a LAN or tunneled server URL when testing against a desktop serverx process.
- All platforms use the same typed API client, bounded retry/backoff policy, Contrix error envelope decoding, and encrypted-payload preservation path.

The Rust crate also runs normal verification:

```powershell
cargo test
```

Browser workflow verification uses Playwright with mocked Contrix HTTP endpoints:

```powershell
npm install
npm run e2e
```

The Playwright runner starts `dx serve --platform web --port 4527 --open false` and exercises the web shell against mocked `/api/v1/*` responses. Use `CLIENTX_E2E_BASE_URL=http://127.0.0.1:<port>` when testing an already-running web build.

The UI compile guard is included in `cargo test` and verifies the exported Dioxus root component signature used by `src/main.rs`.

The release gate used by CI is available locally:

```powershell
npm install
npm run release:check
```

## Configuration

The client resolves its bootstrap config in this order: **persisted settings**
(written by the in-app settings panel) > **environment variables** > **compile-time
defaults**. Once the user saves anything in the settings panel, env vars no
longer override on subsequent launches.

| Variable                | Default                  | Purpose                                                     | Build target           |
| ----------------------- | ------------------------ | ----------------------------------------------------------- | ---------------------- |
| `CLIENTX_SERVER_URL`    | `http://127.0.0.1:8787`  | serverx (`soland`) base URL. Must be HTTPS or loopback.     | desktop / mobile       |
| `CLIENTX_ACCOUNT_DID`   | `did:web:alice.example`  | Default account DID for dev-login bootstrap.                | desktop / mobile       |
| `CLIENTX_DEVICE_ID`     | `dev_yougen`             | Device handle persisted next to the session token.          | desktop / mobile       |
| `CLIENTX_SESSION_TOKEN` | _(empty)_                | Pre-seed a session grant for CI / scripted runs. Do not commit. | desktop / mobile  |
| `CLIENTX_CONFIG_PATH`   | `<app-data>/yougen/config.json` | Override the config file location.                  | desktop / mobile       |
| `CLIENTX_STATE_PATH`    | `<app-data>/yougen/state.json`  | Override the local-state cache location.            | desktop / mobile       |
| `CHASK_PUSH_GATEWAY`    | (chime default)          | Push gateway URL.                                           | desktop / mobile       |
| `CHASK_PUSH_KEY`        | development placeholder  | Platform push token (APNs / FCM / Web Push).                | desktop / mobile       |
| `CLIENTX_E2E_BASE_URL`  | _(unset)_                | Point Playwright at an already-running web build.           | e2e harness            |

Web builds (`wasm32`) read configuration from `localStorage` only — env vars do not apply
in the browser. Set the server URL through the in-app settings panel for browser builds.

> **Security:** Private preferences (locale, theme, …) are sealed with ChaCha20-Poly1305
> keyed off the account DID before they hit `localStorage`. Session tokens, sync cursors,
> and the operation cache are still plaintext, so production deployments must serve the
> web build over HTTPS only and lock down third-party scripts. Treat `CLIENTX_SESSION_TOKEN`
> as a secret; the `views/settings.rs` panel surfaces an in-app warning that mirrors this.
> See [SECURITY.md](SECURITY.md) for the full threat model and how to report a vulnerability.

## CI

### GitHub Actions

The repository includes CI for:

- `Typos`: spell checking through `crate-ci/typos`.
- `CI`: Rust format, clippy, tests, and Dioxus web build on Ubuntu.
- `Packages`: release binary artifacts for Linux, Windows, and macOS runners. On a `v*` tag push, the workflow also produces archived (`.zip` / `.tar.gz`) bundles, computes `SHA256SUMS`, and publishes a GitHub Release through `softprops/action-gh-release`.
- `Docker`: web image build on pull requests and GHCR push on `main`, `master`, or `v*` tags. Pushes are multi-arch (`linux/amd64` + `linux/arm64`), keyless-signed with `cosign`, ship a SBOM, and have build provenance attested through `actions/attest-build-provenance`. Verify with `cosign verify ghcr.io/<owner>/yougen-web@<digest> --certificate-identity-regexp '.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com`.
- `Dependabot`: weekly updates for GitHub Actions, Cargo, npm, and Docker.

CI checks out `contrix-rust-sdk` and `chime` next to `yougen` because `Cargo.toml` uses sibling path dependencies. The expected GitHub repository names are `${OWNER}/contrix-rust-sdk` and `${OWNER}/chime`.

### Gitea Actions

The Gitea smoke workflow lives in `.gitea/workflows/smoke.yml`. It follows the lightweight Rust-check structure used by the related synpad workflows and checks out `yougen`, `contrix-rust-sdk`, and `chime` as sibling directories so the local path dependencies resolve.

The smoke job installs the Linux desktop build packages and runs:

```powershell
cargo fmt --check
cargo check --locked --all-targets
cargo test --locked
```

The expected Gitea repository names are `${OWNER}/contrix-rust-sdk` and `${OWNER}/chime`.

The Docker image serves the Dioxus web build with nginx. Build it from a clean context containing `yougen`, `contrix-rust-sdk`, and `chime`:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/prepare-docker-context.ps1
docker build -f docker-context/yougen/Dockerfile -t yougen-web docker-context
```

By default the UI points at `http://127.0.0.1:8787`. Start `soland` first:

```powershell
cd ../soland
cargo run -- --bind 127.0.0.1:8787
```

The client probes server discovery, Event Envelope write-plane readiness (`cx.profile.core_event_store.v1`, `cx.events.describe`, `cx.events.submit`), sync, directory search/resolve, index query, repo compatibility, sync backfill, authz check, profile presence, and push registration so the first screen can verify that the reference server surface is coherent.

## Product Shell

The first screen is the client shell, not a landing page. It includes:

- Space list and exact directory resolve.
- Timeline/composer surface with plaintext development mode and encrypted payload preservation.
- Sync status, device queue count, Event Envelope/repo-compatibility audit status, directory browser, settings, devices, push registration, and moderation report controls.
- Development login bootstrap using `POST /api/v1/auth/dev-login`; production identity and recovery flows remain tracked in `_todos.md`.
