# clientx

Cross-platform Contrix client built with Dioxus 0.7.

## Targets

- Web: `dx serve --platform web`
- Desktop Windows/Linux: `dx serve --platform desktop`
- iOS/mobile: `dx serve --platform mobile`

Platform notes:

- Web builds use the Dioxus web renderer and must talk to serverx through an HTTP(S) origin allowed by serverx CORS configuration. Keep `CLIENTX_SERVER_URL` or the settings panel pointed at the externally reachable server URL, not an internal desktop-only loopback address.
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

## GitHub CI

The repository includes CI for:

- `Typos`: spell checking through `crate-ci/typos`.
- `CI`: Rust format, clippy, tests, and Dioxus web build on Ubuntu.
- `Packages`: release binary artifacts for Linux, Windows, and macOS runners.
- `Docker`: web image build on pull requests and GHCR push on `main`, `master`, or `v*` tags.
- `Dependabot`: weekly updates for GitHub Actions, Cargo, npm, and Docker.

CI checks out `contrix-rust-sdk` next to `clientx` because `Cargo.toml` uses `../contrix-rust-sdk` as a path dependency. The expected GitHub repository name is `${OWNER}/contrix-rust-sdk`.

The Docker image serves the Dioxus web build with nginx. Build it from a clean context containing both repositories:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/prepare-docker-context.ps1
docker build -f docker-context/clientx/Dockerfile -t clientx-web docker-context
```

By default the UI points at `http://127.0.0.1:8787`. Start serverx first:

```powershell
cd ../serverx
cargo run -- --bind 127.0.0.1:8787
```

The client probes server discovery, sync, directory search/resolve, index query, repo describe, sync backfill, authz check, profile presence, and push registration so the first screen can verify that the reference server surface is coherent.

## Product Shell

The first screen is the client shell, not a landing page. It includes:

- Space list and exact directory resolve.
- Timeline/composer surface with plaintext development mode and encrypted payload preservation.
- Sync status, device queue count, repo/audit status, directory browser, settings, devices, push registration, and moderation report controls.
- Development login bootstrap using `POST /api/v1/auth/dev-login`; production identity and recovery flows remain tracked in `_todos.md`.
