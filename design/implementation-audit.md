# Design vs Current Implementation Audit

Updated: 2026-04-29

This audit compares the static pages in `design/` with the current Dioxus frontend, typed API client, backend interactions, and Playwright coverage.

| Design page | Current frontend | Client/backend wiring | Playwright coverage | Status |
| --- | --- | --- | --- | --- |
| `login.html` | `/login` standalone page with server health, DID/device inputs, passkey, OIDC, dev login, session state, token refresh. | Calls `health`, `passkey_challenge`, `oidc_authorize`, `dev_login`, `token_refresh`; WebAuthn/OIDC callback ceremony still not production-complete. | Covered by `login page covers connection auth methods and token refresh`. | Partial |
| `register.html` | `/register` wizard for DID method, handle, display name, proof placeholder, recovery selection, device bootstrap. | Calls `register_account`; handle check uses `resolve_handle`; proof/recovery are UI placeholders, not signed production proof. | Covered by `registration wizard completes account bootstrap`. | Partial |
| `dashboard.html` | `/` dashboard with spaces summary, quick actions, device queue, repo head, protocol health, activity feed. | Uses sync/space/repo state from shell; health action is wired. | Covered by bootstrap sync flow. | Implemented |
| `space.html` | `/timeline` and `/timeline/:space_id` with message search, composer, local plaintext, local MLS compose, blob attach, moderation/to-device actions. | Calls `send_message`, `send_typing`, `upload_blob`, `report_moderation`, `send_to_device`; timeline local render bug fixed. | Covered by bootstrap timeline, plaintext/local MLS compose, moderation/to-device tests. | Partial |
| `contacts.html` | `/contacts` standalone tabs for search, incoming, outgoing, all, blocked, contact detail. | Calls `search_users`, `request_contact`, `list_contacts`, `respond_contact`; block/cancel/unblock currently reuse `respond_contact` action strings and need backend contract confirmation. | Covered by contacts search/request/accept test. | Partial |
| `space-admin.html` | `/space/:space_id/admin` page with metadata, policy, invite, members, invites, discovery, MLS rotation, leave, archive, delete. | Calls `update_space`, `set_space_policy`, `invite_to_space`, `remove_space_member`, `ban_member`, `rotate_mls_epoch`, `leave_space`, `archive_space`, `delete_space`; member loading still shallow. | Covered by metadata/invite/MLS/archive test plus Product lifecycle compatibility flow. | Partial |
| `directory.html` | `/directory` tabs for spaces, organizations, actors, handles. | Space search/resolve wired; org/actor/handle tabs have API client support but need richer product interactions. | Covered by directory search/resolve test. | Partial |
| `devices.html` | `/devices` page with summary, OTK upload/rotation, to-device inbox, push controls, trust table, MLS epoch controls. | Calls keys, device messages, push, device trust, verify/revoke, MLS epoch endpoints. | Covered by devices summary test; deeper device actions still need tests. | Partial |
| `verify-device.html` | `/devices/verify` page with QR/SAS UI, trust table, cross-signing setup placeholder. | Calls device trust, verify, revoke flows where available; QR/SAS data is not a real cryptographic ceremony yet. | Not yet covered separately. | Partial |
| `audit.html` | `/audit` page with repo head, commits, operations, conflicts, snapshots sections. | Calls `repo_describe`, `list_commits`, `get_operations`, `get_commit`; operation IDs are visible. Conflicts/snapshots are display scaffolds pending real data feed. | Covered by audit repo operations/commits test. | Partial |
| `settings.html` | `/settings` page with server/account/device, session, storage, encryption, push, privacy, theme, release, recovery sections. | Local config/state persistence works; push/recovery/encryption controls are partial. | Covered by settings persistence and release readiness tests. | Partial |

## Main Product Flows Now Covered

- [x] Connect/bootstrap sync: server describe, dev login, directory search, sync cursor, repo/push/key probes.
- [x] Login: health, passkey challenge, OIDC redirect, dev login, token refresh.
- [x] Registration: DID generation, profile/device input, proof placeholder, recovery choice, account creation.
- [x] Contacts: user search, contact request, incoming refresh, accept.
- [x] Space lifecycle: create, add/remove member, persist message, delete through Product compatibility flow.
- [x] Space administration: metadata update, invite, MLS epoch rotation, archive.
- [x] Timeline: plaintext message, local MLS compose, moderation report, to-device queue.
- [x] Directory: search public spaces, select, resolve.
- [x] Devices: queue/push/crypto summary after bootstrap.
- [x] Audit: repo commits and operations visible.
- [x] Release readiness: blockers remain visible instead of falsely claiming production readiness.

## Remaining Release Blockers

1. Production authentication is still incomplete: real WebAuthn, OIDC callback handling, token storage, recovery proof, and DID ownership proofs are not finished.
2. Web E2EE is not production-grade: WebCrypto, IndexedDB MLS state, key backup/recovery, and audited encrypted envelopes remain blockers.
3. Federation, Applet, AI agent, and sovereign deployment paths are not end-to-end validated.
4. Several pages expose controls before all backend semantics are production hardened, especially block/unblock, invite lifecycle, device revocation, conflict/snapshot audit, and policy explanations.
5. CI/build release engineering still needs signed desktop packaging, notarization, auto-update, crash telemetry, SBOM/vulnerability policy, and mobile distribution work.
