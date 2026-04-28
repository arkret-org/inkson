# clientx Product TODOs

本项目为对 E:\Works\contrix-dev\contrix-spec 协议的实现. 本程序为前端跨平台应用. 应该包含 web, ios, linux, windows 等版本. 对应后端实现是 E:\Works\contrix-dev\serverx.

## Product Baseline

- [x] Scaffold Dioxus 0.7 cross-platform client with web, iOS/mobile, Windows, and Linux desktop build features.
- [x] Implement initial API client, UI metrics, and contract tests against serverx skeleton.
- [x] Replace status-demo UI with a usable Contrix client shell: spaces, timeline, composer, directory, settings, devices, and sync status.
- [x] Add persisted client configuration for server URL, account DID, device ID, and session token.
- [x] Add robust loading, empty, error, reconnecting, and offline states.
- [x] Add platform notes for web, Windows/Linux desktop, and iOS/mobile.

## Protocol Alignment Follow-ups

- [x] Verify client endpoint coverage against `contrix-spec/en/sync/service-http-binding.md` common client API namespaces.
- [x] Align E2EE client behavior with `contrix-spec/en/crypto-media/encrypted-envelope-schema.md`: MLS envelope generation, digest verification, pending ciphertext preservation, and joined-group decrypt flow.
- [x] Use SDK OpenMLS helpers rather than custom crypto for KeyPackage, Welcome, Commit, encrypted payload compose, and decrypt-or-preserve.

## API Client and Auth

- [x] Implement typed client calls for every serverx product endpoint.
- [x] Add bearer session handling and auth failure recovery.
- [x] Add request timeout, retry, and backoff policies.
- [x] Add standard Contrix error decoding.
- [x] Add local session/device bootstrap flow.

## E2EE and Local State

- [x] Integrate SDK MLS helpers for device identity and encrypted message payloads.
- [x] Create local encrypted message compose flow.
- [x] Create local decrypt flow for joined MLS groups.
- [x] Preserve encrypted payloads when a key is unavailable.
- [x] Add local stores for raw operations, sync cursors, projections, and drafts.
- [x] Add device/key management screens.

## UI Features

- [x] Space list with directory search and exact resolve.
- [x] Space timeline with message, redaction, reaction, and backfill support.
- [x] Message composer supporting plaintext dev mode and encrypted mode.
- [x] Sync status panel showing next batch, backfill cursor, and device queue counts.
- [x] Repo/audit panel for commits and operation history.
- [x] Directory browser for spaces, organizations, actors, and handles.
- [x] Settings for server, account, device, encryption, and push.
- [x] Push registration controls.
- [x] Moderation report action from timeline item.

## Tests and Documentation

- [x] Add contract tests for all typed API calls.
- [x] Add client/server E2EE workflow test.
- [x] Add UI compile tests for desktop/web feature set.
- [x] Add docs for running each platform, auth bootstrap, E2EE workflow, and known limits.
- [x] Run `cargo fmt`, `cargo test`, and server integration smoke before marking complete.

## Business Workflow Inventory

- [x] Define current supported account bootstrap flow: dev-login session bootstrap, DID/device binding, token persistence, auth failure visibility.
- [x] Define current supported discovery flow: server connect, directory search, exact space resolve, select space, sync timeline and backfill.
- [x] Define current supported messaging flow: plaintext dev compose, local MLS encrypted compose, pending encrypted payload preservation, moderation report, to-device queue send.
- [x] Define current supported device/security flow: key upload/query/claim, device messages receive, push register/unregister, device queue metrics.
- [x] Define current supported data lifecycle flow: repo describe, commits/operations/sync, blob upload/download, audit/status panels.
- [x] Capture missing product flows that need serverx/protocol endpoints before UI completion: production registration, password/passkey login, device verification UX, contacts/friends, create/update/delete Space, invite/add/kick member, leave Space, account recovery, Space archival/deletion.

## Playwright E2E Flow Design

- [x] Add stable UI selectors for shell, settings, directory, composer, device, status, timeline, and metric regions.
- [x] Add Playwright project configuration and npm scripts for local web e2e.
- [x] Add mocked Contrix API fixture covering server describe, dev-login, sync, directory, repo, authz, keys, device messages, push, moderation, and blob paths.
- [x] Test bootstrap/login/sync flow from offline state to connected shell with token, space, timeline, repo, push, and device metrics.
- [x] Test settings identity/device update flow before bootstrap.
- [x] Test directory search, exact resolve, and selected space navigation.
- [x] Test plaintext compose and local MLS encrypted compose in the timeline.
- [x] Test moderation report and to-device queue request from the timeline action.
- [x] Test devices/security panel after bootstrap.
- [x] Test invalid server URL error state.
- [x] Document Playwright execution in README.

## Production Release Readiness

- [x] Add release-readiness inventory in code so major unsupported business flows are visible in the product, not only in notes.
- [x] Add UI panel for production blockers: registration, production login, device verification, contacts/friends, create Space, invite/add/kick member, leave/archive/delete Space, canonical message persistence, and release packaging.
- [x] Add Playwright coverage that the product explicitly says it is not production-ready while those blockers remain.
- [x] Add typed client bindings for serverx account registration, account/me, logout, contact request/respond/list, Space create/add/remove/delete, and canonical message send endpoints.
- [x] Add Product workflow panel for basic account registration, contacts, Space lifecycle, member management, and server-backed message persistence.
- [x] Add Product workflow contact response controls for accept/reject, backed by `POST /api/v1/contacts/respond`.
- [x] Add real config/local-state persistence for native file storage and web localStorage: server/account/device/session, sync cursor, projections, drafts, and raw message operations.
- [x] Add Playwright coverage for persisted settings, persisted drafts, and the basic product workflow: connect, register, request/list/accept contact, create Space, add/remove member, persist message, update sync/repo metrics, and delete Space.
- [x] Harden Playwright release gate to run serially against Dioxus dev server and avoid flaky first-load parallelism.
- [x] Add a reusable release gate command that runs Rust format/tests, web build, and Playwright E2E from one script.
- [x] Add GitHub typo checking, Dependabot, Rust/web CI, cross-OS package artifact builds, and Docker image build/push workflows.

---

## Page Architecture — Split Monolith into View Modules

The current `app.rs` is a 1247-line monolith containing all 6 views plus the root shell. Each view needs its own module.

- [ ] Create `src/views/mod.rs` with view module declarations and the `View` enum.
- [ ] Extract `TimelinePanel` into `src/views/timeline.rs` (timeline events, composer, sync status).
- [ ] Extract `DirectoryPanel` into `src/views/directory.rs` (space/org/actor/handle search).
- [ ] Extract `ProductPanel` into `src/views/product.rs` (account, contacts, space lifecycle, messages).
- [ ] Extract `SettingsPanel` into `src/views/settings.rs` (server/account/device config).
- [ ] Extract `DevicesPanel` into `src/views/devices.rs` (keys, trust, verification).
- [ ] Extract `ReadinessPanel` into `src/views/readiness.rs` (release blockers).
- [ ] Keep `App` root shell in `src/app.rs` — sidebar, topbar, right panel, view router only.
- [ ] Add shared `src/components/mod.rs` with reusable components: `Metric`, `StatusBadge`, `ActionButton`, `EmptyState`, `ErrorBanner`, `LoadingSpinner`.
- [ ] Add `src/components/form.rs` with reusable form widgets: `TextInput`, `TextArea`, `Select`, `Toggle`, `SearchInput`.

---

## Login Page (`design/login.html` → `src/views/login.rs`)

Currently collapsed into the sidebar "Connect" button. Design requires a standalone login page.

- [ ] Create `src/views/login.rs` with standalone `LoginPanel` component.
- [ ] Add server URL input with connection test (calls `GET /health`).
- [ ] Add account DID input field with format validation.
- [ ] Add passkey login button — calls `POST /api/v1/auth/passkey/challenge` then `POST /api/v1/auth/passkey/verify`.
- [ ] Add OIDC login button — opens OIDC redirect flow, receives callback token.
- [ ] Add dev-login button (existing) for development mode only.
- [ ] Add session state panel: connected account DID, device ID, token expiry, session state (active/soft-logged-out/locked).
- [ ] Add token refresh logic: detect 401 → attempt refresh → re-show login on failure.
- [ ] Add soft-logout recovery: preserve local state, show re-auth prompt with recovery options.
- [ ] Add new `View::Login` variant to the view enum.
- [ ] Route to `Login` when no session token exists or token is expired.

---

## Registration Page (`design/register.html` → `src/views/register.rs`)

Currently embedded in ProductPanel. Design requires a standalone registration flow.

- [ ] Create `src/views/register.rs` with standalone `RegisterPanel` component.
- [ ] Add DID generation step — select DID method (`did:uuid`, `did:web`, `did:key`).
- [ ] Add handle input with availability check — `POST /api/v1/identity/resolve`.
- [ ] Add display name and device label inputs.
- [ ] Add DID proof challenge step — server sends challenge, client signs with new DID key.
- [ ] Add recovery policy selection — recovery key, backup phrase, passkey recovery.
- [ ] Add device bootstrap — generate device keys, upload via `POST /api/v1/keys/upload`.
- [ ] Add automatic device verification prompt after registration.
- [ ] Add `View::Register` variant.
- [ ] Route to `Register` from login page "Create Account" link.

---

## Device Verification Page (`design/verify-device.html` → `src/views/verify_device.rs`)

Currently completely missing. No QR/SAS verification UX exists.

- [ ] Create `src/views/verify_device.rs` with `VerifyDevicePanel` component.
- [ ] Add QR code verification flow — generate QR from device key material, scan partner device QR.
- [ ] Add SAS (Short Authentication String) flow — display 6-digit code, confirm match on both devices.
- [ ] Add device trust table — list all devices with trust state (unverified/verified/blocked).
- [ ] Add verify action per device — triggers QR or SAS flow for selected device.
- [ ] Add revoke action per device — calls device revocation endpoint, removes key material.
- [ ] Add cross-signing state display — shows master/signing/device key relationships.
- [ ] Add `View::VerifyDevice` variant.
- [ ] Route to `VerifyDevice` from devices page "Verify" button.

---

## Dashboard Page (`design/dashboard.html` → `src/views/dashboard.rs`)

Currently no dedicated dashboard — sidebar + right panel metrics are scattered.

- [ ] Create `src/views/dashboard.rs` with `DashboardPanel` component.
- [ ] Add spaces summary list with unread count badges per space.
- [ ] Add quick-action bar: Create Space, New Message, Search, Settings.
- [ ] Add device queue status card — pending to-device messages, push state.
- [ ] Add repo head card — current commit hash, last sync time, operations count.
- [ ] Add protocol health table — server version, sync status, MLS epoch, federation state.
- [ ] Add recent activity feed — last N sync events across all spaces.
- [ ] Add `View::Dashboard` variant.
- [ ] Make Dashboard the default view after login (instead of Timeline).

---

## Space Timeline (`design/space.html` → expand `src/views/timeline.rs`)

Current timeline is basic — no reply, reaction, redaction, threads, or blob attachment.

- [ ] Add reply-to indicator on timeline events — show quoted parent message with jump link.
- [ ] Add reply action — composer prefills with reply-to reference, sends `cx.message.reply` relation.
- [ ] Add reaction picker — emoji grid, sends `cx.reaction.add` / `cx.reaction.remove`.
- [ ] Add reaction summary display — show reaction counts per event with reactor avatars.
- [ ] Add redaction action — confirm dialog, sends `cx.redaction` event.
- [ ] Add message editing — sends `cx.message.update` with new content.
- [ ] Add thread selector — click message to open thread view in right panel.
- [ ] Add blob attachment — file picker, calls `POST /api/v1/blob/upload`, embeds blob_ref in message.
- [ ] Add image preview — inline display for image blob attachments.
- [ ] Add encrypted composer toggle — switch between plaintext and MLS-encrypted mode.
- [ ] Add typing indicator — send `cx.typing` on keystroke, display others' typing state.
- [ ] Add read receipts — send `cx.receipt.read` on scroll-to-bottom, display read-by list.
- [ ] Add message search within space — filter timeline by keyword.
- [ ] Add jump-to-message — deep link from notification or search result to specific event position.

---

## Contacts Page (`design/contacts.html` → `src/views/contacts.rs`)

Currently embedded in ProductPanel as a sub-flow. Design requires standalone page.

- [ ] Create `src/views/contacts.rs` with `ContactsPanel` component.
- [ ] Add search by DID / handle with privacy-preserving lookup option.
- [ ] Add send contact request with optional note field.
- [ ] Add incoming requests table — accept / reject / block actions.
- [ ] Add outgoing requests table — cancel action, status display.
- [ ] Add contacts list — display name, DID, handle, trust state, last seen.
- [ ] Add block action — move contact to blocked list, remove from contacts.
- [ ] Add blocked list — view and unblock contacts.
- [ ] Add contact detail view — profile card, shared spaces, mutual contacts.
- [ ] Add `View::Contacts` variant.

---

## Space Admin Page (`design/space-admin.html` → `src/views/space_admin.rs`)

Currently embedded in ProductPanel as a sub-flow. Design requires standalone admin page.

- [ ] Create `src/views/space_admin.rs` with `SpaceAdminPanel` component.
- [ ] Add space metadata editor — name, topic, avatar, description.
- [ ] Add join policy selector — open / invite / request / restricted.
- [ ] Add history visibility selector — world_readable / shared / joined / invited.
- [ ] Add member table — DID, role, joined_at, MLS epoch, actions (kick/ban/promote/demote).
- [ ] Add invite member action — DID input, role selector, send invite.
- [ ] Add accept/reject incoming space invites.
- [ ] Add leave space action with confirmation.
- [ ] Add MLS epoch rotation — trigger key rotation, display epoch history.
- [ ] Add danger zone section — archive space, tombstone/destroy space (irreversible).
- [ ] Add space discovery toggle — public / private listing.
- [ ] Add `View::SpaceAdmin` variant.

---

## Directory Page (`design/directory.html` → expand `src/views/directory.rs`)

Current directory only handles space search. Design requires org/actor/handle search.

- [ ] Add organization search tab — search by name/description, display org card.
- [ ] Add actor search tab — search by DID, display actor profile card.
- [ ] Add handle resolution — input handle, resolve to DID via `POST /api/v1/identity/resolve`.
- [ ] Add contact action from directory result — send contact request directly.
- [ ] Add space preview card — member count, topic, join policy, preview button.
- [ ] Add "Open Space" action — navigate to space timeline.
- [ ] Add pagination for search results.

---

## Devices & Keys Page (`design/devices.html` → expand `src/views/devices.rs`)

Current devices page is read-only summary only. Design requires full management.

- [ ] Add current device detail card — device ID, label, created_at, last_seen.
- [ ] Add one-time keys display — remaining count, upload button.
- [ ] Add pending to-device message inbox — list messages, mark processed.
- [ ] Add push notification controls — register/unregister, platform, token display.
- [ ] Add device trust table — list all devices with trust state and actions.
- [ ] Add verify button per device — routes to verify-device page.
- [ ] Add revoke button per device — confirmation dialog, calls revocation endpoint.
- [ ] Add key rotation button — rotate device signing key, upload new key package.
- [ ] Add MLS epoch display — current epoch, group membership count.
- [ ] Add `View::Devices` variant (expand existing).

---

## Audit / Sync Inspector Page (`design/audit.html` → `src/views/audit.rs`)

Currently completely missing — repo/audit endpoints are called during connect but not surfaced.

- [ ] Create `src/views/audit.rs` with `AuditPanel` component.
- [ ] Add next batch display — sync cursor, batch size, space positions.
- [ ] Add raw operations table — operation kind, actor, timestamp, content preview.
- [ ] Add conflict display — conflicting operations with resolution state.
- [ ] Add snapshots table — snapshot hash, timestamp, state summary.
- [ ] Add commits table — commit hash, author, operations count, signature status.
- [ ] Add inspect action — expand row to show full JSON content.
- [ ] Add verify action — re-verify commit signature, operation digest.
- [ ] Add refresh action — re-fetch latest repo state.
- [ ] Add `View::Audit` variant.
- [ ] Route to `Audit` from right panel "Inspect" link.

---

## Settings Page (`design/settings.html` → expand `src/views/settings.rs`)

Current settings has server/account/device. Missing: storage, encryption, CI/release gates.

- [ ] Add storage table — list local stores (config, state, crypto, blobs) with size and platform (native vs web).
- [ ] Add storage risk indicators — warn about web localStorage limitations.
- [ ] Add encryption settings — MLS group policy, key backup status, rotation schedule.
- [ ] Add push notification preferences — per-space mute, notification rules.
- [ ] Add privacy settings — presence visibility, read receipt visibility, directory listing.
- [ ] Add theme selector — light/dark/system.
- [ ] Add CI/release gate status — show which gates pass/fail from `workflows.rs`.
- [ ] Add secure crypto store controls — backup/restore key material (native only).
- [ ] Add account recovery section — backup phrase display, recovery key management.
- [ ] Add `View::Settings` variant (expand existing).

---

## API Client — Missing Endpoints

The current API client has 45 endpoints. Several spec-required endpoints are missing.

### Authentication Endpoints
- [ ] Add `passkey_challenge` — `POST /api/v1/auth/passkey/challenge`.
- [ ] Add `passkey_verify` — `POST /api/v1/auth/passkey/verify`.
- [ ] Add `oidc_authorize` — `GET /api/v1/auth/oidc/authorize`.
- [ ] Add `oidc_callback` — `POST /api/v1/auth/oidc/callback`.
- [ ] Add `token_refresh` — `POST /api/v1/auth/token/refresh`.
- [ ] Add `account_recovery` — `POST /api/v1/account/recovery`.

### Identity & Directory Endpoints
- [ ] Add `search_organizations` — `POST /api/v1/directory/search-organizations`.
- [ ] Add `search_actors` — `POST /api/v1/directory/search-actors`.
- [ ] Add `resolve_handle` — `POST /api/v1/identity/resolve-handle`.
- [ ] Add `search_users` — `POST /api/v1/directory/search-users`.

### Space Management Endpoints
- [ ] Add `update_space` — `PATCH /api/v1/spaces/{id}`.
- [ ] Add `archive_space` — `POST /api/v1/spaces/{id}/archive`.
- [ ] Add `set_space_policy` — `PUT /api/v1/spaces/{id}/policy`.
- [ ] Add `invite_to_space` — `POST /api/v1/spaces/{id}/invite`.
- [ ] Add `accept_space_invite` — `POST /api/v1/spaces/{id}/invite/accept`.
- [ ] Add `reject_space_invite` — `POST /api/v1/spaces/{id}/invite/reject`.
- [ ] Add `leave_space` — `POST /api/v1/spaces/{id}/leave`.
- [ ] Add `ban_member` — `POST /api/v1/spaces/{id}/members/{member}/ban`.

### Messaging Endpoints
- [ ] Add `edit_message` — `PATCH /api/v1/messages/{id}`.
- [ ] Add `redact_message` — `POST /api/v1/messages/{id}/redact`.
- [ ] Add `add_reaction` — `POST /api/v1/messages/{id}/reactions`.
- [ ] Add `remove_reaction` — `DELETE /api/v1/messages/{id}/reactions/{key}`.
- [ ] Add `send_typing` — `POST /api/v1/typing`.
- [ ] Add `send_receipt` — `POST /api/v1/receipts`.

### Device & Crypto Endpoints
- [ ] Add `revoke_device` — `POST /api/v1/devices/{id}/revoke`.
- [ ] Add `rotate_keys` — `POST /api/v1/keys/rotate`.
- [ ] Add `get_device_trust` — `GET /api/v1/devices/trust`.
- [ ] Add `verify_device` — `POST /api/v1/devices/{id}/verify`.
- [ ] Add `get_mls_epoch` — `GET /api/v1/mls/epoch`.
- [ ] Add `rotate_mls_epoch` — `POST /api/v1/mls/rotate`.

### Moderation & Policy Endpoints
- [ ] Add `get_moderation_reports` — `GET /api/v1/moderation/reports`.
- [ ] Add `resolve_moderation_report` — `POST /api/v1/moderation/reports/{id}/resolve`.
- [ ] Add `get_policy` — `GET /api/v1/policy/{resource}`.

---

## E2EE Web Crypto Store

Current web E2EE uses placeholder envelope compose. Need real WebCrypto-backed store.

- [ ] Implement `WebCryptoStore` using WebCrypto API for key generation and storage.
- [ ] Store device identity keys in IndexedDB (persistent across sessions).
- [ ] Store MLS group state in IndexedDB (epoch secrets, tree, transcript hash).
- [ ] Implement key package serialization/deserialization for web.
- [ ] Replace `compose_local_encrypted_message` wasm fallback with real WebCrypto encrypt.
- [ ] Implement decrypt path using IndexedDB-stored epoch secrets.
- [ ] Add key backup/restore for web (export encrypted key bundle, import with passphrase).
- [ ] Test E2EE round-trip on wasm32 target.

---

## Production Auth Flow

Currently only dev-login exists. Need full production authentication.

- [ ] Implement DID proof challenge flow: server sends nonce → client signs with DID key → server verifies and issues session.
- [ ] Implement passkey/WebAuthn registration: generate credential, store in browser authenticator.
- [ ] Implement passkey/WebAuthn login: get challenge, sign with stored credential.
- [ ] Implement OIDC redirect flow: redirect to provider, handle callback, exchange code for token.
- [ ] Implement token refresh: detect expiry (or 401), call refresh endpoint, update stored token.
- [ ] Implement soft-logout: preserve local state on session expiry, show re-auth prompt.
- [ ] Implement account recovery: recovery key input, passphrase derivation, key material restoration.
- [ ] Implement session-to-DID binding: verify session token matches expected DID and device.

---

## Offline & Sync Resilience

Currently no offline support. Need queue, retry, and reconciliation.

- [ ] Add offline detection — monitor network state, show offline indicator.
- [ ] Add message queue — store pending messages locally when offline.
- [ ] Add retry with reconciliation — on reconnect, replay queued messages, handle conflicts.
- [ ] Add crash-safe drafts — persist composer content to local store on every keystroke.
- [ ] Add sync resume — on app restart, resume from last stored sync cursor.
- [ ] Add conflict resolution UI — show conflicting operations, let user choose resolution.
- [ ] Add background sync — periodic sync even when app is in background (native).

---

## Spec-Required Views Without Design Pages

These views are required by the contrix-spec but have no design prototype yet. Create design + implementation.

### Kanban Board (`View::Kanban`)
- [ ] Create `design/kanban.html` design prototype.
- [ ] Create `src/views/kanban.rs` — column-based board with drag-and-drop entity cards.
- [ ] Add column management — add/remove/reorder columns.
- [ ] Add card detail modal — entity fields, assignees, labels, due dates.
- [ ] Add `View::Kanban` variant.

### Chat / Channel View (`View::Chat`)
- [ ] Create `design/chat.html` design prototype.
- [ ] Create `src/views/chat.rs` — channel-based chat with message list and composer.
- [ ] Add channel list sidebar — DMs, group channels, space channels.
- [ ] Add channel creation — name, kind (chat/announce/support/activity), visibility.
- [ ] Add `View::Chat` variant.

### Forum View (`View::Forum`)
- [ ] Create `design/forum.html` design prototype.
- [ ] Create `src/views/forum.rs` — threaded forum with topic list and reply chains.
- [ ] Add topic creation — title, initial post, tags.
- [ ] Add nested reply display — collapsible reply tree.
- [ ] Add `View::Forum` variant.

### Social Feed (`View::SocialFeed`)
- [ ] Create `design/social_feed.html` design prototype.
- [ ] Create `src/views/social_feed.rs` — social post feed with audience policy controls.
- [ ] Add post composer — rich text, media attach, audience selector.
- [ ] Add feed filtering — by circle, by contact, by topic.
- [ ] Add `View::SocialFeed` variant.

### Memory Review (`View::MemoryReview`)
- [ ] Create `design/memory_review.html` design prototype.
- [ ] Create `src/views/memory_review.rs` — agent memory review with accept/edit/reject.
- [ ] Add memory layer filter — working/episodic/semantic/task.
- [ ] Add confidence score display and manual override.
- [ ] Add `View::MemoryReview` variant.

### Agent Runs (`View::AgentRuns`)
- [ ] Create `design/agent_runs.html` design prototype.
- [ ] Create `src/views/agent_runs.rs` — agent run timeline with step-by-step trace.
- [ ] Add run detail — input, output, tool calls, duration, status.
- [ ] Add run comparison — side-by-side diff of two runs.
- [ ] Add `View::AgentRuns` variant.

### Notification Inbox (`View::Notifications`)
- [ ] Create `design/notifications.html` design prototype.
- [ ] Create `src/views/notifications.rs` — notification list with action buttons.
- [ ] Add notification grouping — by space, by type, by time.
- [ ] Add mark-read/unread, archive, bulk actions.
- [ ] Add notification rules — per-space, per-type muting.
- [ ] Add `View::Notifications` variant.

### Document Editor (`View::Document`)
- [ ] Create `design/document.html` design prototype.
- [ ] Create `src/views/document.rs` — rich document editor with collaborative editing.
- [ ] Add block-based editing — paragraphs, headings, lists, code blocks, images.
- [ ] Add real-time collaboration indicators — cursors, selections from other users.
- [ ] Add version history — timeline of document revisions.
- [ ] Add `View::Document` variant.

### Voice / Video Calls (`WebRtcManager` integration)
- [ ] Create `design/call.html` design prototype.
- [ ] Create `src/views/call.rs` — call UI with audio/video controls.
- [ ] Add ICE server configuration from `GET /api/v1/media/ice-config`.
- [ ] Add call initiation — offer/answer SDP exchange via to-device messages.
- [ ] Add call accept/reject/decline flows.
- [ ] Add screen sharing support.
- [ ] Add `View::Call` variant.

---

## Release Engineering

- [ ] Implement signed desktop builds — code signing for Windows (Authenticode), macOS (notarization), Linux (GPG).
- [ ] Add web deployment config — WASM build, service worker, asset hosting.
- [ ] Add auto-updater — check for new version, download, prompt restart (native).
- [ ] Add crash telemetry — panic hook, crash report upload (opt-in).
- [ ] Add privacy/security review checklist — data at rest encryption, network TLS pinning, key storage audit.
- [ ] Add release channels — stable, beta, nightly.
- [ ] Add mobile build targets — iOS (Xcode project), Android (NDK target).
- [ ] Add store submission — App Store, Microsoft Store, Flathub, web PWA manifest.
