# Contrix Design Implementation Todos

Source of truth:
- `claude-design/desktop/*.html` and `claude-design/styles.css` are the visual reference.
- `contrix-spec` is the protocol source of truth when the static design is ambiguous.
- Keep existing app test contracts where possible, especially `data-testid` selectors used by `tests/e2e/clientx.flows.spec.ts`.

Protocol semantics to preserve:
- `Contrix` is the product/protocol brand.
- `Acme Inc.` is the current Organization Principal, not the Principal Server.
- Principal Server is a delegated service boundary, shown as service context, not as actor identity.
- Space hierarchy is navigation/discoverability only; child Space keeps independent policy, membership, history, and E2EE boundary.
- External collaboration should be represented as controlled cross-organization collaboration with explicit federation/security labels, not as loose "External".
- Personal Space should use `purpose=personal`; avoid implying a new protocol `kind=personal`.

## Phase 0 - Baseline and contracts
- [x] Inspect Dioxus app entry points and route/view structure.
- [x] Identify current E2E selectors that must remain stable.
- [x] Run a baseline build/check before broad visual edits if current tree permits it.

## Phase 1 - Global shell and navigation
- [x] Replace the old "yougen" chrome with `Contrix` product branding.
- [x] Add clear context block for Organization Principal (`Acme Inc.`) and Principal Server service boundary.
- [x] Restructure left navigation into Personal, Acme-backed Spaces, Controlled cross-org, and Personal Spaces groups.
- [x] Keep Settings, Directory, Inbox, Devices, Readiness, and core route links reachable.
- [x] Align colors, spacing, card surfaces, badges, and responsive behavior with the design稿.
- [x] Keep mobile shell usable and preserve `sidebar`, `main-view`, and nav button test IDs.

## Phase 2 - Home / Dashboard
- [x] Replace verbose explanatory hero copy with concise operational cards.
- [x] Surface protocol-correct Space cards: Acme-backed, controlled cross-org, and personal-purpose Space.
- [x] Show sync health, local queue, repo frontier, pinned inbox, and recent board summaries in cleaner design language.
- [x] Keep quick actions and dashboard test IDs intact.

## Phase 3 - Settings
- [x] Rework Settings navigation to match design categories without losing existing sections.
- [x] Ensure every visible Settings tab has a rendered panel.
- [x] Add/clarify Principal Server service settings and local client/device identity.
- [x] Remove non-essential explanatory paragraphs while preserving critical protocol warnings.
- [x] Preserve `settings-panel`, account/device inputs, `language-settings`, and section selectors used by tests.

## Phase 4 - Directory / Discovery
- [x] Clean up Directory top area and search card.
- [x] Keep the three independent discovery axes visible, but reduce paragraph density.
- [x] Improve result cards for Spaces, Organizations, Actors, Handles, and Applets.

## Phase 5 - Secondary surfaces
- [x] Review Timeline, Kanban, Chat, Notifications, Devices, Audit, Space Admin, Product, and Readiness for shell compatibility.
- [x] Remove overly verbose subtitles where the global shell already gives context.
- [x] Add protocol boundary labels only where they affect user decisions.

## Phase 6 - Verification
- [x] `cargo fmt --check`
- [x] `cargo check`
- [x] Run available E2E or smoke tests if the local environment supports it.
- [x] Browser-verify desktop home and settings layouts.
- [x] Browser-verify mobile width shell behavior.

Notes:
- Targeted affected Playwright smoke passed: bootstrap/right-panel/registration/settings/kanban/directory/mobile/visual smoke.
- Full `npm run e2e` was attempted twice but exceeded the command timeout; latest failure contexts were outside the visual redesign surface (audit decode, product/timeline operation id, chat payload, move replay).
