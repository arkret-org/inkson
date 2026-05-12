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
