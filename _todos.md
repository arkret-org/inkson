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
- [x] For new `did:webvh`, collect username first, then email, then verification code; allow dev/test deployments to bypass actual email delivery.
- [x] Generate/prepare client key material for the webvh update key and send only the public multibase key through coauth to soland.
- [x] Add the password step after email verification; make password optional only when coauth reports a passwordless/passkey-capable policy.
- [x] Surface registration completion with `did:webvh`, key id, key log head, document/log URLs, and clear local-key ownership wording.
- [x] Add lost-password/account recovery entry points; account recovery accepts email and routes through coauth.
- [x] Add yougen API types/methods for the coauth registration/recovery contract and update Playwright mocks.
- [x] Check whether coauth already stores email/recovery settings in its own DB/config; add or adjust config for test email bypass if missing.
- [x] Check soland's embedded webvh provider stays business-logic-free; only adjust describe/register metadata if needed.
- [x] Run `cargo fmt --check`, `cargo check`, and targeted Playwright auth/registration tests.

Verification notes:
- `cargo check` passed in `yougen`.
- `rustfmt --edition 2024 --check src\app.rs src\views\register.rs src\views\login.rs src\coauth.rs` passed; full `yougen` `cargo fmt --check` is still blocked by pre-existing newline style issues in `src\capability.rs`, `src\discovery.rs`, and `tests\serverx_contract.rs`.
- `cargo fmt --check` passed in `coauth`.
- `cargo check -p coauth-backend -p coauth-config -p coauth-data` passed in `coauth` with existing warnings.
- `cargo test -p coauth-config loads_registration_email_delivery_bypass_from_env --lib` passed.
- Playwright passed: `npx playwright test tests/e2e/clientx.flows.spec.ts -g "login page|registration"`.
