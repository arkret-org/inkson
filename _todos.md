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
- [x] Remove the Account/Login hint input from `yougen` sign-in.
- [x] Start login by resolving `auth_metadata.auth_server_url` from the Principal Server, then inspect coauth OIDC metadata.
- [x] Redirect the browser to coauth `/authorize` with PKCE and no `login_hint`.
- [x] Make coauth OIDC bridge/exchange accept an omitted `login_hint`; infer the user from the fulfilled coauth browser session.
- [x] Add a dev static OIDC client for yougen in coauth config so `/authorize` accepts loopback callback URLs.
- [x] Verify coauth `/login`, `/register`, OIDC discovery, and an `/authorize` redirect target open normally.
- [x] Update Playwright mocks/tests for the server-first login shape.
- [x] Build and serve the coauth frontend assets so coauth `/login` does not 404 on `coauth-frontend.js`.
- [x] Serve a coauth favicon so browser default `/favicon.ico` requests do not show as 404.
- [x] Make coauth's SPA shell CSP-safe: inject config as inert JSON, allow Dioxus WASM compilation, and remove external Google Fonts.
- [x] Make coauth backend pick the newest hashed frontend entrypoint when multiple Dioxus build outputs exist.
- [x] Preserve OIDC callback query parameters in yougen even when the Dioxus router normalizes `/auth/callback?code=...&state=...` to `/auth/callback`.
- [x] Remove yougen's local account registration/recovery page and direct coauth registration helpers; account creation and lost-account flows now live behind the coauth OIDC UI.
- [x] Accept coauth's current OIDC exchange viewer response shape (`principal_id`) and remove the historical Matrix viewer id from yougen's response model.
- [x] Normalize legacy principal bridge paths in yougen and make soland advertise `/api/v1/auth/session-grant/exchange` instead of a non-fetchable `legacy:` URI.
- [x] Replace yougen's old `dev_yougen` device id with protocol `cx:device:<uuidv7>` ids; sanitize persisted legacy ids and clear stale tokens.
- [x] Bind coauth-issued principal session grants to the same protocol device id via `urn:contrix:client:device:<device_id>`.

Verification notes:
- `cargo check --target wasm32-unknown-unknown` passed in `yougen`.
- `cargo check -p coauth-backend` passed in `coauth` with existing warnings.
- `coauth config sync` was run from `config.dev.yaml`; the running coauth service was then rebuilt and restarted.
- Live services are listening on `127.0.0.1:4527` for yougen and `127.0.0.1:7080` for coauth.
- `https://auth.local.host/.well-known/openid-configuration`, `/login`, `/register`, `https://local.host/api/v1/server/describe`, and `https://auth.local.host/api/v1/server/describe` all returned 200.
- A direct `/authorize` probe with the yougen static client returned 303 instead of 400/502.
- Playwright passed: `npx playwright test tests/e2e/clientx.flows.spec.ts -g "login page|registration"`.
- Built coauth frontend with `dx build -p coauth-frontend --release`, copied the output to `D:\Works\contrix-dev\coauth\dist`, and restarted coauth.
- Updated coauth `just dev` and `just backend` to ensure frontend assets exist before starting the backend.
- `https://auth.local.host/login?...` now references `/assets/coauth-frontend-dxhc43fada7b0f3bf77.js`; that script returns 200.
- `https://auth.local.host/favicon.ico` returns 200 with an SVG favicon response.
- A headless browser run through real `/authorize -> /login` reported no failed requests and no 4xx responses.
- `https://auth.local.host/login` now returns CSP `script-src 'self' 'wasm-unsafe-eval'`; the server config is injected through `<script id="coauth-app-config" type="application/json">`, with no executable `window.APP_CONFIG` inline script.
- Browser verification through real `/authorize -> /login` loaded `/assets/coauth-frontend-dxh46786a4822a265c.js`, `/assets/coauth-frontend_bg-dxh651736119b7fdd34.wasm`, and `/assets/main-dxh60c5d01dec76bc9.css` with 200 responses; current console had no errors or warnings.
- Browser resource inspection showed no `fonts.googleapis.com`, `fonts.gstatic.com`, or other external font requests.
- Direct browser verification against `http://127.0.0.1:8080/auth/callback?code=test-code&state=test-state` confirmed Dioxus still strips the address-bar query, but yougen now falls back to the initial navigation entry; the failure advances to the expected missing-scaffold state instead of `Could not read callback URL`.
- Yougen `/login` no longer renders local `Create account` or `Lost password or account` buttons; the OIDC destination page is responsible for those actions.
- Playwright passed: `npx playwright test tests/e2e/clientx.flows.spec.ts -g "login page delegates"`.
- The latest live coauth authorization grants were fulfilled and exchanged, confirming the callback reached `/api/v1/auth/oidc/exchange`; the failure was yougen-side response decoding.
- `cargo test login_response_accepts_current_coauth_viewer_shape --lib` passed.
- `cargo test endpoint_join_accepts_legacy_bridge_paths --lib` and `cargo test endpoint_join_keeps_api_paths_under_base_url --lib` passed.
- `cargo check` passed in `soland` with existing warnings after updating the principal bridge descriptor.
- `cargo test config::tests:: --lib` passed in `yougen`; this verifies protocol device id defaults and legacy device id replacement.
- `cargo test -p coauth-backend oidc_bridge::tests` passed in `coauth`; this verifies coauth device id validation and session-grant device scope binding.
- `cargo check --target wasm32-unknown-unknown` passed in `yougen`.
- `cargo check -p coauth-backend` passed in `coauth` with existing warnings.
- Playwright passed: `npx playwright test tests/e2e/clientx.flows.spec.ts -g "login page delegates|settings can update"`.
