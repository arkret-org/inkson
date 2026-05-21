# yougen

Cross-platform Contrix client built with Dioxus 0.7.

## Realm vs Space

After the Phase 1–4 terminology inversion (Round R1.x):

- **Realm:** security boundary — membership, capability, E2EE, federation.
  Surfaced in the UI as **Workspace** (zh: 工作区).
- **Space:** navigation container — board, list, section, calendar bucket
  inside a Realm. Surfaced in the UI as **Space** (zh: 空间).

The friendly UI strings live under the `friendly.realm.*` / `friendly.space.*`
i18n keys in `src/i18n.rs`; protocol-level identifiers stay reachable via
**Show technical details** on every actor / object surface.

## Round R4 (protocol review closures)

Spec round 4 (`contrix-spec` range `2a4d39b..a77b995`, 8 commits) brings
several client-visible changes. See [`CHANGELOG.md`](CHANGELOG.md)
`[Unreleased]` and [`../_todos.md`](../_todos.md) for the canonical
wire-breaking list.

- **`cx.call.signal` v2** — 13 signal types, required device `proof`,
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

## Round R2/R3 user-facing surfaces

Spec rounds 2+3 (2026-05-20) added a handful of end-user changes — see
[`CHANGELOG.md`](CHANGELOG.md) `[Unreleased]` and
[`../contrix-spec/CHANGELOG.md`](../contrix-spec/CHANGELOG.md) for the
normative source.

- **Ephemeral signal routing change** — typing / receipts / presence /
  call-signal no longer travel through the durable `cx.events.submit`
  path. They go through a dedicated `cx.schema.ephemeral_envelope.v1`
  channel (broadcast) or `cx.schema.device_message.v1` (to-device key
  verification). This is transparent to end users but is a
  wire-breaking change for any third-party client built against the
  old yougen behaviour.
- **Moderation appeal flow** — when a moderation decision blocks a
  member, they can now file an appeal directly from the timeline.
  Status surfaces back to the appellant as `Submitted → UnderReview →
  Decided → Closed`.
- **Late-recovery banner** — when older messages are decrypted after
  the fact (key shared by a recovering device, audit profile late
  emission), the timeline renders an inline banner explaining the lag:
  "Older messages were just decrypted, X minutes after they arrived."
- **Realm destroyed banner** — destroyed Realms surface a permanent
  "This realm has been permanently retired" banner; composer + Send
  are disabled.

## Cross-project task tracking

Per-project task lists are consolidated upstream — see
[`../_todos.md`](../_todos.md) for the active cross-project task plan.

## Targets

- Web: `dx serve --platform web`
- Desktop Windows/Linux: `dx serve --platform desktop`
- iOS/mobile: `dx serve --platform mobile`

Platform notes:

- Web builds use the Dioxus web renderer and must talk to `soland` through an HTTP(S) origin allowed by the Principal Server CORS configuration. Keep `CLIENTX_SERVER_URL` or the settings panel pointed at the externally reachable server URL, not an internal desktop-only loopback address.
- Windows and Linux desktop builds use the Dioxus desktop renderer. Local development defaults to `https://local.host` and stores the last server/account/device/session settings in the local config store.
- iOS/mobile builds use the Dioxus mobile renderer. Device builds require the platform toolchain (`dx`, Xcode/iOS signing on macOS for iOS, platform SDKs for other mobile targets). Treat loopback URLs as emulator-local; use a LAN or tunneled server URL when testing against a desktop server process.
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

## CI

### GitHub Actions

The repository includes CI for:

- `Typos`: spell checking through `crate-ci/typos`.
- `CI`: Rust format, clippy, tests, and Dioxus web build on Ubuntu.
- `Packages`: release binary artifacts for Linux, Windows, and macOS runners.
- `Docker`: web image build on pull requests and GHCR push on `main`, `master`, or `v*` tags.
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

By default the UI points at `https://local.host`. Start `soland` first:

```powershell
cd ../soland
cargo run -- --bind local.host:443
```

The Connect action probes server discovery first. Authenticated sync, directory, device, and push flows run only after a real session is available.

## Product Shell

Unauthenticated users see only the login or registration entry screen. After a real server session is established, the client shell includes:

- Space list and exact directory resolve.
- Timeline/composer surface with plaintext development mode and encrypted payload preservation.
- Sync status, device queue count, Event Envelope audit status, directory browser, settings, devices, push registration, and moderation report controls.
- Server-owned OIDC/coauth sign-in and registration. The client opens the authorization URL from server discovery and completes the callback into a Principal Server session.
