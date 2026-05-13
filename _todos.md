# Claude Design Alignment Todos

Primary reference:
- `claude-design/desktop/home.html`
- `claude-design/desktop/settings.html`
- `claude-design/desktop/directory.html`
- `claude-design/styles.css`

Secondary reference:
- `D:\Works\contrix-dev\sodmin` may be referenced for icon/component style only.

Protocol rules to preserve:
- `Contrix` is the product/protocol brand.
- `Acme Inc.` is the current Organization Principal.
- Principal Server is a delegated service boundary, not the Organization itself.
- Space navigation may show Acme-backed grouping, but child Spaces keep independent policy, membership, history, and E2EE boundary.
- Avoid the vague `External` label; use controlled cross-organization collaboration with explicit federation/security labels.

## Implementation Tasks
- [x] Re-read `claude-design` desktop HTML and shared stylesheet as the source design.
- [x] Re-read current Dioxus shell, dashboard, right panel, and existing selector contracts.
- [x] Load `claude-design/styles.css` into the app and add only compatibility overrides needed by the live Dioxus views.
- [x] Replace the live root chrome with the design稿 structure: `.app.three-col`, canonical `.sidebar`, `.workspace`, `.workspace-header`, `.workspace-body`, `.right-panel`.
- [x] Rewrite the left sidebar to match `claude-design`: Contrix logo area, Organization context, Principal Server context, Search/Directory, Personal, Acme-backed Spaces, Controlled cross-org, Personal Spaces, footer identity.
- [x] Keep live route/test affordances reachable: Timeline, Kanban, Chat, Audit, Settings, Devices, Readiness, Product/Create, server connect controls.
- [x] Rewrite the Dashboard content to use design稿 primitives: `.spread`, `.metric-grid`, `.callout`, `.surface`, `.m-list-item`, `.tbl`, `.settings-row`.
- [x] Reduce explanatory copy in Dashboard and shell; keep only protocol-critical labels and warnings.
- [x] Bring the right panel visually under the design稿 `.right-panel` model without changing its data/test contract.
- [x] Run `cargo fmt --check`.
- [x] Run `cargo check`.
- [x] Browser-verify desktop home/settings and mobile shell behavior if the local app can be served.

Verification notes:
- `cargo check` passed.
- `rustfmt --edition 2024 --check src\app.rs src\views\dashboard.rs` passed.
- Full `cargo fmt --check` was executed, but it is blocked by pre-existing newline style issues in `src/api.rs`, `src/capability.rs`, `src/coauth.rs`, `src/discovery.rs`, and `tests/serverx_contract.rs`.
- Playwright affected smoke passed: `settings can update account`, `mobile viewport`, and `visual smoke`.

# Auth Registration And Recovery Todos

Primary boundary decision:
- `soland` remains the pure Principal Server and embedded `did:webvh` provider.
- `coauth` owns account registration, email verification, optional password setup, lost-password/account recovery, notification settings, and the trusted call into soland's embedded webvh registration endpoint.
- `yougen` owns client-side routing, form state, local key generation, and showing the returned `did:webvh` / key metadata to the user.

## Implementation Tasks
- [x] Fix `/login` and `/register` auth card centering after the `claude-design` stylesheet is loaded.
- [x] Replace email-or-DID registration entry with two explicit paths: bind an existing DID, or create a new soland-backed `did:webvh`.
- [x] Keep existing DID registration DID-first; do not require a username before DID control proof.
- [x] For new `did:webvh`, collect username first, then email, then verification code; allow dev/test deployments to bypass actual email delivery.
- [x] Keep email delivery bypass out of the user UI; coauth config decides whether dev/test email is skipped.
- [x] Generate separate client key material for the DID Document controller key and the `did:webvh` update key; send only public multibase keys through coauth to soland.
- [x] Add a post-registration account backup download containing account metadata, DID metadata, public keys, and both locally generated private seeds.
- [x] Split the soland embedded `did:webvh` key model: DID authentication/assertion uses the DID controller key, while `did:webvh` `updateKeys[0]` uses a separate update key.
- [x] Add the password step after email verification; make password optional only when coauth reports a passwordless/passkey-capable policy.
- [x] Surface registration completion with `did:webvh`, key id, key log head, document/log URLs, and clear local-key ownership wording.
- [x] Add lost-password/account recovery entry points; account recovery accepts email and routes through coauth.
- [x] Add yougen API types/methods for the coauth registration/recovery contract and update Playwright mocks.
- [x] Check whether coauth already stores email/recovery settings in its own DB/config; add or adjust config for test email bypass if missing.
- [x] Check soland's embedded webvh provider stays business-logic-free; only adjust describe/register metadata if needed.
- [x] Align the browser flow with the spec boundary: discover `auth_metadata.auth_server_url` from the Principal Server, then call coauth for registration and recovery.
- [x] Make soland advertise the public Auth / Account Server URL without adding password, email, or lost-account business endpoints to soland.
- [x] Split local HTTPS proxying so `local.host` serves soland and `auth.local.host` serves coauth, with dev CORS on both origins.
- [x] Shorten soland embedded `did:webvh` names so the DID path is `webvh:{local_id}` instead of the internal API route path.
- [x] Replace simplified embedded `did:webvh` SCID generation with spec-style SCID derived from the preliminary log entry containing `{SCID}` placeholders.
- [x] Add embedded `did:webvh` entry-hash generation and a real log-entry proof signed by the update key supplied by the client.
- [x] Apply the same two-key controller/update model and spec-style webvh log generation to `starid` if it owns a webvh provider implementation.
- [x] Run `cargo fmt --check`, `cargo check`, and targeted Playwright auth/registration tests.

Verification notes:
- `cargo check` passed in `yougen`.
- `cargo check --target wasm32-unknown-unknown` passed in `yougen`.
- `cargo fmt --check` passed in `yougen` with existing rustfmt config warnings about nightly-only options.
- `cargo fmt --check` passed in `coauth`.
- `cargo check -p coauth-backend -p coauth-config -p coauth-data` passed in `coauth` with existing warnings.
- `cargo check -p coauth-backend` passed after the two-key finish contract change.
- `cargo test -p coauth-config loads_registration_email_delivery_bypass_from_env --lib` passed.
- `cargo check` passed in `soland` with existing warnings.
- `cargo test --test http_api server_describe_advertises_auth_server_url_when_configured` passed in `soland`.
- `CARGO_TARGET_DIR=%TEMP%\soland-codex-target cargo test --test http_api embedded_webvh_provider_registers_and_serves_identity` passed in `soland`; this verifies separate DID/update public keys and rejects reused key material.
- `cargo test embedded_webvh_provider_registers_and_serves_identity --test http_api -- --nocapture` passed in `soland`; this verifies SCID-from-placeholder-log, multibase entry hash, and client-signed update-key log proof.
- `cargo check -p coauth-backend` passed after forwarding `webvh_version_time` and `webvh_proof`.
- `cargo check --target wasm32-unknown-unknown` passed in `yougen` after adding client-side webvh log proof signing.
- `cargo test -p starid webvh -- --nocapture` passed after switching SCID and entry hashes to base58btc sha2-256 multihash.
- `cargo test -p starid production_mode --test http_api -- --nocapture` passed, including a production create test with a valid client-signed inception proof.
- `cargo fmt --check` passed in `soland`, `coauth`, `starid`, and `yougen`; the rustfmt config still emits existing nightly-only option warnings.
- Local dev services were restarted on `127.0.0.1:4527`, `127.0.0.1:7080`, and `127.0.0.1:8698`; health checks returned 200.
- Playwright opened `http://127.0.0.1:4527/register`; no build-failed overlay or console errors were present.
- Playwright passed: `npx playwright test tests/e2e/clientx.flows.spec.ts -g "login page|registration"`; this now verifies the downloaded account backup JSON contains separate public/private DID controller and update keys.
- Caddy was reloaded from `D:\Works\contrix-dev\soland\Caddyfile`; `OPTIONS https://auth.local.host/api/v1/auth/register/webvh/start` returns 204 with CORS headers.
- Live local services were rebuilt/restarted on `127.0.0.1:8698` and `127.0.0.1:7080`; a direct coauth webvh registration returned separate DID controller and update keys.

# Server-First OIDC Login Todos

Boundary decision:
- `yougen` should first choose the Principal Server, like Matrix Element choosing a homeserver.
- The actual account/password UI belongs to `coauth` and is reached through the coauth OIDC authorization page discovered from the Principal Server.
- `yougen` registration may keep client-side key generation/backup locally, because DID private keys must not be generated by or disclosed to coauth/soland.

## Implementation Tasks
- [ ] Remove the Account/Login hint input from `yougen` sign-in.
- [ ] Start login by resolving `auth_metadata.auth_server_url` from the Principal Server, then inspect coauth OIDC metadata.
- [ ] Redirect the browser to coauth `/authorize` with PKCE and no `login_hint`.
- [ ] Make coauth OIDC bridge/exchange accept an omitted `login_hint`; infer the user from the fulfilled coauth browser session.
- [ ] Add a dev static OIDC client for yougen in coauth config so `/authorize` accepts loopback callback URLs.
- [ ] Verify coauth `/login`, `/register`, OIDC discovery, and an `/authorize` redirect target open normally.
- [ ] Update Playwright mocks/tests for the server-first login shape.
