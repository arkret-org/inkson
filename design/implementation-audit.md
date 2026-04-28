# Design vs Current Implementation Audit

This audit compares the static design pages in `design/` with the current Dioxus app, API client, server interaction, and test coverage.

Status legend:

- `Implemented`: usable in the current Dioxus UI with real typed API calls or local state.
- `Partial`: some UI/API exists, but the designed page or production workflow is incomplete.
- `Missing`: not represented as a product page or not wired to real protocol behavior.

| Design page | Intended product screen | Current frontend | Client logic/API | Backend interaction | Test coverage | Status |
| --- | --- | --- | --- | --- | --- | --- |
| `login.html` | Production login with server URL, passkey/OIDC, dev bootstrap fallback, session state | No standalone login page. Login is only `Connect` in sidebar. | `dev_login`; fallback `register_account` then retry `dev_login`; bearer token persisted. No passkey/OIDC/token refresh. | `POST /api/v1/auth/dev-login`; `POST /api/v1/account/register`; `POST /api/v1/auth/logout` exists in API client. | Bootstrap login and settings tests. No production auth tests. | Partial |
| `register.html` | Registration with DID, handle, device binding, proof challenge, recovery policy | No standalone registration page. Basic register button lives in `ProductPanel`. | `register_account` typed call exists. No DID proof challenge, recovery setup, or production verification flow. | `POST /api/v1/account/register` exists. Proof/recovery endpoints not implemented in client. | Product workflow test covers basic register. | Partial |
| `verify-device.html` | QR/SAS verification, trust state, device revocation | No verification page. `DevicesPanel` is read-only status. | Key upload/query/claim and local MLS helpers exist. No SAS/QR, cross-signing, trust graph, revocation UX. | Keys and device message endpoints are called during connect. No production verification endpoint flow. | Devices panel test only verifies status after bootstrap. | Missing |
| `dashboard.html` | Main board with spaces, health, sync, device queue, release status | Current shell has sidebar status, space list, timeline, right metrics. No dedicated dashboard view. | Connect probes describe, sync, repo, identity, index, authz, keys, push, blob. | Broad endpoint probing exists. Some calls are fire-and-forget and not surfaced as rich page state. | Bootstrap/sync test covers core metrics. | Partial |
| `space.html` | Space timeline, encrypted composer, reply/reaction/redaction/moderation/backfill | Timeline and composer exist. Directory select and backfill button exist. | Plain local send, local encrypted compose, server-backed `send_message` only in Product panel. Draft persistence exists. No reply/reaction/redaction UI behavior. | `messages/send`, `sync/backfill`, moderation report, blob upload/download are typed. | Plain/encrypted compose and moderation endpoint tests. No reaction/redaction/backfill assertions. | Partial |
| `contacts.html` | Contact search/request/list/accept/reject/block/privacy | Basic controls exist inside `ProductPanel`, not a standalone page. | `request_contact`, `respond_contact`, `list_contacts` exist. No block, privacy-preserving lookup, notifications, contact detail states. | Contacts request/respond/list endpoints exist. Block/privacy endpoints not wired. | Product workflow covers request/list/accept only. | Partial |
| `space-admin.html` | Create/edit metadata/policy/invite/add/remove/leave/archive/delete/tombstone | Basic create/add/remove/delete controls exist in `ProductPanel`, not a dedicated admin page. | `create_space`, `add_space_member`, `remove_space_member`, `delete_space` exist. No metadata edit, policy editor, invite accept, leave, archive, retention confirmation, MLS removal rotation UX. | Server has basic lifecycle endpoints. Production policy/tombstone/history behavior not represented in client. | Product workflow covers create/add/remove/delete. | Partial |
| `directory.html` | Search/resolve spaces, organizations, actors, handles | `DirectoryPanel` only supports space search and exact space resolve. | `search_spaces`, `resolve_space`, `directory_describe` exist. API client lacks UI for org/actor/user/handle search even if server routes exist. | Space directory endpoints used. Other directory endpoints not surfaced. | Directory search/resolve test. | Partial |
| `devices.html` | Device trust, keys, MLS group state, to-device, push controls | `DevicesPanel` shows summary only. Push registration is hidden in connect flow, not controllable. | Key upload/query/claim, receive to-device, send to-device, push register/unregister are typed/called. No device management actions, revocation, trust decisions, MLS group browser. | Keys, device messages, push endpoints are exercised. | Devices panel and report/to-device tests. | Partial |
| `audit.html` | Repo commits, operations, snapshots, backfill, conflicts, raw local state | No standalone audit page. Right panel only shows repo head string. | `repo_describe`, commits, operations, repo sync, snapshot head, backfill exist. Local raw operation store exists. No inspector UI. | Repo/sync endpoints are called, mostly not surfaced. | Contract/unit tests cover parsing; no audit UI test. | Missing |
| `settings.html` | Server/account/device/storage/encryption/release readiness | `SettingsPanel` supports server/account/device and session status. `ReadinessPanel` separately lists blockers. | Config persistence works native/web. Local state persistence works. No secure encrypted storage settings, web crypto store controls, release gate UI. | Settings are local. No server-side settings interaction. | Settings persistence and readiness tests. | Partial |

## Cross-cutting findings

1. The current Dioxus UI has only six app views: `Timeline`, `Directory`, `Product`, `Settings`, `Devices`, and `Readiness`. The design calls for distinct product pages for login, registration, verification, dashboard, contacts, Space admin, directory, devices, audit, and settings.
2. Basic server-backed product workflows exist, but many are grouped in `ProductPanel`. That makes tests pass for core calls, but the UX is not yet a product-quality page model.
3. The API client is ahead of the UI for several areas: repo/audit, keys, push, blobs, authz, and contacts have typed calls but limited or no user-facing controls.
4. Production identity remains the largest blocker: no DID proof challenge UX, passkey/OIDC, refresh token flow, recovery policy, device revocation, or cross-device verification.
5. E2EE is still split by platform: native uses SDK MLS helpers, but web still relies on placeholder envelope compose rather than a production WebCrypto-backed key store.
6. Playwright covers the current shell flows, not the full page set in `design/`.

## Recommended implementation order

1. Split onboarding into `LoginPage`, `RegisterPage`, and `VerifyDevicePage`, preserving dev bootstrap but making production blockers explicit in-page.
2. Convert `ProductPanel` into real `ContactsPage` and `SpaceAdminPage`.
3. Add `AuditPage` that exposes repo commits, operations, snapshots, backfill, local raw operations, and sync conflicts.
4. Expand `DirectoryPage` to organizations, actors, users, and handle resolution.
5. Turn `DevicesPanel` into a management page with key upload/query/claim, to-device inbox, push controls, trust state, and revocation placeholders.
6. Add Playwright tests per designed page, not just per endpoint.
