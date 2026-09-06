# inkson

> **Spec target**: the current Arkret v1 protocol in the sibling [arkret-spec](../arkret-spec) repository.

Cross-platform Arkret client built with Dioxus 0.7.

## Pre-commit hook setup

After cloning, enable the project's pre-commit hooks:

```sh
git config core.hooksPath .githooks
```

The hook runs `cargo fmt --all -- --check` and `cargo clippy --all-targets
--no-deps -- -D warnings` on staged Rust changes (matching CI's
`--all-targets` clippy scope). If `.githooks/pre-commit` is missing on
a branch, copy it from
[`arkret-rust-sdk`](https://github.com/arkret-org/arkret-rust-sdk) and
adapt to your local toolchain.

## Realm vs Space

Current Realm / Space vocabulary:

- **Realm:** security boundary — membership, capability, E2EE, federation.
  Surfaced in the UI as **Realm** in every locale; it has no alternate product alias.
- **Space:** navigation container — board, list, section, calendar bucket
  inside a Realm. Surfaced in the UI as **Space** (zh: 空间).

The friendly UI strings live under the `friendly.realm.*` / `friendly.space.*`
i18n keys in `src/i18n/` (`en.rs` / `zh.rs`); protocol-level identifiers stay reachable via
**Show technical details** on every actor / object surface.

## Round R4 (protocol review closures)

Spec round 4 (`arkret-spec` range `2a4d39b..a77b995`, 8 commits) brings
several client-visible changes. The canonical wire-breaking list is this
section plus the protocol spec history in `../arkret-spec/spec/v1/`.

- **`ak.call.signal` v2** — 13 signal types, required device `proof`,
  per-`(realm, call, actor, device)` monotonic `seq`. Seq rollback
  aborts the call.
- **Typed `EventsSubscribe` frames** — NDJSON parser switched to
  `EventsSubscribeFrame`; `dropped` resumes from the embedded cursor,
  `resync_required` triggers full re-sync, `epoch_rotation` refreshes
  session keys.
- **`ServiceDescribe` v2 consumer** — registration requires 17 fields;
  `trust_domain` mismatch fails the handshake; missing
  `plaintext_visibility` is treated as untrusted.
- **`observed_dots` consent revoke UI** — the dot list is rendered;
  revoking is an explicit user action (no implicit cascade).
- **`SnapshotBootstrap`** — query response with snapshot hint is
  accepted; full chunked import is staged.
- **Late-recovery banner** — sourced from
  `late_recovery_original_event_id`.

## User-facing protocol surfaces

See the protocol spec tree (`../arkret-spec/spec/v1/`) for the normative source.

- **Signal routing** — typing / receipts / presence / call-signal do not
  travel through the durable `ak.self.events.command.submit.v1` path. They are
  encrypted inside `SignalEnvelope` and sent with
  `ak.self.signal.command.send.v1`; device verification uses
  `ak.schema.device_message.v1`.
- **Late-recovery banner** — when older messages are decrypted after
  the fact (key shared by a recovering device, audit profile late
  emission), the timeline renders an inline banner explaining the lag:
  "Older messages were just decrypted, X minutes after they arrived."
- **Realm destroyed banner** — destroyed Realms surface a permanent
  "This realm has been permanently retired" banner; composer + Send
  are disabled.

## Cross-project task tracking

Per-project task lists are consolidated upstream — see
the arkret-work specs for the active cross-project task plan.

## Targets

- Web: `just web`
- Desktop Windows/Linux: `just desktop`
- iOS/mobile: `just mobile`

The `just` recipes wrap the underlying Dioxus commands:

- Web: `python scripts/dev_dioxus.py --platform web --port 8080`
- Desktop Windows/Linux: `python scripts/dev_dioxus.py --platform desktop`
- iOS/mobile: `python scripts/dev_dioxus.py --platform mobile`

The wrapper fails fast when the generated Arkret SDK registry does not match
the canonical spec artifact. It also bridges changes from sibling Cargo path
dependencies into Inkson's workspace so Dioxus performs a full Rust rebuild;
running bare `dx serve` can miss those changes with Dioxus 0.7.

Platform notes:

- Web builds use the Dioxus web renderer and must talk to `soland` through an HTTP(S) origin allowed by the Station CORS configuration. Keep the settings panel pointed at the externally reachable server URL, not an internal desktop-only loopback address.
- Windows and Linux desktop builds use the Dioxus desktop renderer. Local development defaults to `https://local.host` and stores the last server/account/device/session settings in the local config store.
- iOS/mobile builds use the Dioxus mobile renderer. Device builds require the platform toolchain (`dx`, Xcode/iOS signing on macOS for iOS, platform SDKs for other mobile targets). Treat loopback URLs as emulator-local; use a LAN or tunneled server URL when testing against a desktop server process.
- All platforms use the same typed API client, bounded retry/backoff policy, Arkret error envelope decoding, and encrypted-payload preservation path.

Station presets can be added to the local config file with `stations`. The login screen shows these values as selectable suggestions while still accepting a custom URL:

```json
{
  "server_url": "https://local.host",
  "stations": [
    "https://local.host",
    "https://stage.example",
    "https://prod.example"
  ],
  "account_did": "",
  "device_id": "ak:device:01964137-0000-7000-8000-000000000000",
  "session_credential": ""
}
```

The Rust crate also runs normal verification:

```powershell
cargo test
```

Browser workflow verification uses Playwright with mocked Arkret HTTP endpoints:

```powershell
npm install
npm run e2e
```

The Playwright runner builds the web bundle with `dx build --platform web --profile joint-e2e --features wasm-localstorage-secrets-test` (into `target/playwright-e2e`) and serves it via `node tests/e2e/staticServer.mjs` on port 4727, exercising the web shell against mocked `/_arkret/*` responses. Use `INKSON_E2E_BASE_URL=http://127.0.0.1:<port>` when testing an already-running web build.

That validation runs on its own too, without a browser and without the WASM build:

```powershell
npm run contract
```

`tests/contract/` drives the mock's route handler directly and checks every response the embedded OpenAPI inventory names, in about half a minute. Reach for it whenever the spec moves: a stale mock field otherwise costs a full `dx build` to discover, and the next stale field costs another, because each rejection stops at the first. Set `INKSON_WIRE_BIN` to a prebuilt `inkson-wire` so the check does not `cargo run` once per response.

The e2e suite under `tests/e2e/` is **mock-only**: every mocked JSON response is validated against the SDK's embedded OpenAPI and schema artifacts before it reaches inkson, and the suite never speaks to a real Arkret server. Full UI ↔ real-server integration lives in the sibling [`cotest`](../cotest) joint suite (`cotest/e2e/`), which boots both `inkson` and a real `soland` process. Any test that needs a live server should be added there, not here.

The UI compile guard is included in `cargo test` and verifies the exported Dioxus root component signature used by `src/main.rs`.

The release gate used by CI is available locally:

```powershell
npm install
npm run release:check
```

## CI

### GitHub Actions

The repository includes CI for:

- `Typos`: spell checking through `crate-ci/typos`.
- `CI`: Rust format, clippy, tests, Dioxus web build, and Lighthouse budget on Ubuntu.
- `Packages`: release binary artifacts and local signing dry-run evidence for Linux, Windows, and macOS runners.
- `Docker`: local web image build, Trivy scan, SBOM evidence, and local cosign blob evidence when a local key is supplied. It does not push to GHCR or any registry.
- `Dependabot`: weekly updates for GitHub Actions, Cargo, npm, and Docker.

CI checks out `arkret-rust-sdk`, `garth`, and `chime` next to `inkson` because `Cargo.toml` uses sibling path dependencies. The expected GitHub repository names use those three names under `${OWNER}`.

`yoface` is not one of them: it is a private cargo git dependency (`git = "https://github.com/arkret-org/yoface"`, branch `main`), so cargo fetches it instead of reading a sibling checkout. `.cargo/config.toml` sets `net.git-fetch-with-cli` so the fetch goes through git and picks up credentials; every workflow installs a `url.…insteadOf` rewrite backed by `CI_REPO_TOKEN` (GitHub Actions) or `GITHUB_COM_TOKEN` (Gitea, which needs a GitHub PAT because a Gitea token cannot authenticate against github.com). The image build receives the same token as the `github_token` build secret.

### Gitea Actions

The Gitea smoke workflow lives in `.gitea/workflows/smoke.yml`. It follows the lightweight Rust-check structure used by the related synpad workflows and checks out `inkson`, `arkret-rust-sdk`, `garth`, and `chime` as sibling directories so the local path dependencies resolve. `yoface` is fetched from GitHub instead, using the `GITHUB_COM_TOKEN` secret.

The smoke job installs the Linux desktop build packages and runs:

```powershell
cargo fmt --check
cargo check --locked --all-targets
cargo test --locked
```

The expected Gitea repository names use the three dependency repository names under `${OWNER}`.

The Docker image serves the Dioxus web build with nginx. Build it from a clean context containing `inkson`, `arkret-rust-sdk`, `garth`, and `chime`. The build fetches `yoface` from GitHub, so it needs a token with read access to `arkret-org/yoface` mounted as the `github_token` build secret:

```powershell
$env:GITHUB_TOKEN = "<pat>"
powershell -ExecutionPolicy Bypass -File scripts/prepare-docker-context.ps1
docker build -f docker-context/inkson/Dockerfile --secret id=github_token,env=GITHUB_TOKEN -t inkson-web docker-context
```

Local release evidence commands are documented in [`docs/RELEASING.md`](docs/RELEASING.md). The release plan is local-only: no tag creation, registry push, crates.io publish, notarization submit, ticket stapling, timestamp authority, or Sigstore transparency-log upload is part of the phase-3 workflow.

By default the UI points at `https://local.host`. Start `soland` first:

```powershell
cd ../soland
cargo run -- --bind local.host:443
```

The Connect action probes server discovery first. Authenticated sync, directory, device, and push strands run only after a real session is available.

## Product Shell

Unauthenticated users see only the login or registration entry screen. After a real server session is established, the client shell includes:

- Space list and exact directory resolve.
- Timeline/composer surface with plaintext development mode and encrypted payload preservation.
- Sync status, device queue count, Event Envelope audit status, directory browser, settings, devices, push registration, and moderation report controls.
- Server-owned OIDC/coauth sign-in and registration. The client opens the authorization URL from server discovery and completes the callback into a Station session.

---
