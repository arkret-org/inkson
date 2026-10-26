# inkson

> **Spec target**: the current Arkret v1 protocol in the sibling [arkret-spec](../arkret-spec) repository.

Cross-platform Arkret client built with Glory and Sapid.

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
  per-`(realm, call, actor, device)` monotonic `sequence`. Seq rollback
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

- **Circles** — open a Realm row menu and choose **Circles**. Create a
  boundary with its own short name, directory visibility, join rule and history
  policy; directory previews offer public join or an approval request. Members
  can leave, and Circle managers can edit metadata, manage membership,
  archive/restore, restrict history and permanently retire the Circle. History
  restriction and retirement require explicit confirmation. The short name,
  controlled colour and symbol identify the scope; an E2EE label requires a
  verified accepted MLS binding. A directory preview never exposes private
  titles, short names or member identities.
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

- Web: `just web` or `python scripts/dev_glory.py --platform web --port 8080`.
- Native desktop: `just desktop` or `python scripts/dev_glory.py --platform desktop`.
- Release Web bundle: `python scripts/build_web.py --release`.
- Release desktop binary and local assets: `python scripts/build_desktop.py --release`.

The developer runner repairs stale SDK registry projections through the SDK’s `tools/sync-spec.ps1`, verifies the canonical registry, and rebuilds after application or local path dependency changes. `python scripts/dev_glory.py --check` is read-only. PowerShell and the SDK generator must be available for automatic repair.

Windows tooling uses `D:/BuildCache/inkson-glory` for build output, temporary files and caches; Cargo metadata verifies the resolved target. WSL builds must use a verified D-drive mount. Glory and Sapid resolve from their GitHub `main` branches at the exact revisions in `Cargo.lock`; local path overrides are not used.

The browser host uses Glory Web and Sapid semantic controls. The desktop host uses Glory/Blitz and the same application state and stylesheet layers. It loads assets beside the executable, or from `Contents/Resources/assets` in a macOS bundle. The development runner sets an explicit repository asset directory. Native file and clipboard actions use OS services.

Mobile host-bridge stub checks remain available with `just check-mobile-stubs`; this repository does not ship a new native mobile launcher. Responsive Web pages remain part of browser validation. All hosts retain the typed API client, retry policy, error decoding, encrypted payload storage and account/session fences.

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
$env:CARGO_HOME = "D:/BuildCache/cargo"
$env:CARGO_TARGET_DIR = "D:/BuildCache/inkson-glory/target"
$env:TEMP = "D:/BuildCache/inkson-glory/tmp"
$env:TMP = $env:TEMP
New-Item -ItemType Directory -Force -Path $env:TEMP | Out-Null
cargo test --locked --features app
```

Browser workflow verification uses Playwright with mocked Arkret HTTP endpoints:

```powershell
$env:CARGO_HOME = "D:/BuildCache/cargo"
$env:CARGO_TARGET_DIR = "D:/BuildCache/inkson-glory/target"
$env:TEMP = "D:/BuildCache/inkson-glory/tmp"
$env:TMP = $env:TEMP
New-Item -ItemType Directory -Force -Path $env:TEMP | Out-Null
$inksonMetadata = cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json
cargo build --locked --profile joint-e2e --no-default-features --features spec-conformance --bin inkson-wire
$env:INKSON_WIRE_BIN = Join-Path $inksonMetadata.target_directory "joint-e2e/inkson-wire.exe"
npm ci
npm run e2e
```

The language-sync regression sends its fixture secret only through an in-memory pipe to the prebuilt verifier and checks the real SDK AEAD result. It requires `INKSON_WIRE_BIN`; it does not use the generic file-backed fixture helper for secrets.

The Playwright runner invokes `scripts/serve_e2e.mjs`, builds the real Web artifact with the `joint-e2e` profile and test-only fixture feature, then starts the static host on port 4727. Windows E2E output lives under `D:/BuildCache/inkson-glory/playwright-e2e`. Use `INKSON_E2E_BASE_URL=http://127.0.0.1:<port>` for an already-running build. The production bundle never enables the fixture feature.

That validation runs on its own too, without a browser and without the WASM build:

```powershell
npm run contract
```

`tests/contract/` drives the mock's route handler directly and checks every response the embedded OpenAPI inventory names, in about half a minute. Reach for it whenever the spec moves: a stale mock field otherwise costs a full Web build to discover, and the next stale field costs another, because each rejection stops at the first. Set `INKSON_WIRE_BIN` to a prebuilt `inkson-wire` so the check does not `cargo run` once per response.

The e2e suite under `tests/e2e/` is **mock-only**: every mocked JSON response is validated against the SDK's embedded OpenAPI and schema artifacts before it reaches inkson, and the suite never speaks to a real Arkret server. Full UI ↔ real-server integration lives in the sibling [`cotest`](../cotest) joint suite (`cotest/e2e/`), which boots both `inkson` and a real `coland` process. Any test that needs a live server should be added there, not here.

The UI compile guard is included in `cargo test` and verifies the exported Glory root factory signature used by `src/main.rs`.

The release gate used by CI is available locally:

```powershell
npm ci
npm run release:check
```

## CI

### GitHub Actions

The repository includes CI for:

- `Typos`: spell checking through `crate-ci/typos`.
- `CI`: Rust format, clippy, tests, and Glory/Sapid Web build on Ubuntu.
- `Packages` (manual `workflow_dispatch`): native Linux, Windows and macOS artifacts, actual platform startup probes, advisory checks and local signing evidence. Historical renderer receipts describe their original fixed source; a framework migration requires fresh platform evidence.
- `Docker`: local web image build, Trivy scan, SBOM evidence, and local cosign blob evidence when a local key is supplied. It does not push to GHCR or any registry.
- `Dependabot`: weekly updates for GitHub Actions, Cargo, npm, and Docker.

CI checks out `arkret-rust-sdk`, `garth`, and `chime` next to `inkson` because `Cargo.toml` uses sibling path dependencies. The expected GitHub repository names use those three names under `${OWNER}`.

Library consumers keep the default renderer-free feature set. The `app` feature enables application code, `web` selects the browser host, and `desktop` selects the native host. Cargo fetches Glory/Sapid from the exact GitHub revisions recorded in Cargo.lock. The desktop graph uses the reviewed renderer sources recorded in Cargo.lock; see [desktop dependency maintenance](docs/desktop-dependency-maintenance.md). Library or Web success alone does not establish native desktop startup or authenticated UI acceptance.

### Gitea Actions

The Gitea smoke workflow lives in `.gitea/workflows/smoke.yml`. It follows the lightweight Rust-check structure used by the related synpad workflows and checks out `inkson`, `arkret-rust-sdk`, `garth`, and `chime` as sibling directories so the local path dependencies resolve. Glory/Sapid are checked out as public UI dependencies.

The smoke job installs the Linux desktop build packages and runs:

```powershell
cargo +nightly fmt -p inkson -- --check
cargo check --locked --features app --all-targets
cargo test --locked --features app
```

The expected Gitea repository names use the three dependency repository names under `${OWNER}`.

The Docker image serves the Glory/Sapid Web bundle with nginx and SPA deep-link fallback. Prepare the sibling application/SDK/spec context; Cargo fetches the locked Glory/Sapid Git dependencies during the build. On Windows, verify that the builder stores its data on D: or a remote host before building:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/prepare-docker-context.ps1
docker build -f docker-context/inkson/Dockerfile -t inkson-web docker-context
```

Local release evidence commands are documented in [`docs/RELEASING.md`](docs/RELEASING.md). The release plan is local-only: no tag creation, registry push, crates.io publish, notarization submit, ticket stapling, timestamp authority, or Sigstore transparency-log upload is part of the phase-3 workflow.

By default the UI points at `https://local.host`. Start `coland` first:

```powershell
cd ../coland
cargo run -- --bind local.host:443
```

The Connect action probes server discovery first. Authenticated sync, directory, device, and push flows run only after a real session is available.

## Product Shell

Unauthenticated users see only the login or registration entry screen. After a real server session is established, the client shell includes:

- Space list and exact directory resolve.
- Timeline/composer surface with plaintext development mode and encrypted payload preservation.
- Sync status, device queue count, Event Envelope audit status, directory browser, settings, devices, push registration, and moderation report controls.
- Server-owned OIDC/coauth sign-in and registration. The client opens the authorization URL from server discovery and completes the callback into a Station session.

---

Applet 安装已同步正式 Service-only 合同：管理员原签 registration／grants，Station preview 返回 plan，确认时提交原 basis 与 plan_digest；安装不向 Applet author 一个默认 Bot。独立 Bot／Ghost 创建、管理审批产品流程仍需后续接线。已有客户端原生 MLS／Welcome／Blob 路径保持独立，Applet HTTPS base_url 不接收群内容。
