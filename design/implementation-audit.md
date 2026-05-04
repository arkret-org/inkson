# Design vs Current Implementation Audit

Updated: 2026-05-02

This audit compares the refreshed full application design pages with the current Dioxus implementation.

| Design page | Current frontend area | Current state | Follow-up |
| --- | --- | --- | --- |
| `login.html` | `/login` | Existing login surface covers health, passkey challenge, OIDC redirect, dev login, token refresh. | Align visual layout with new auth design and keep production WebAuthn callback work separate. |
| `register.html` | `/register` | Existing registration wizard covers DID method, handle, profile, proof placeholder, recovery selection, account creation. | Replace placeholder proof/recovery with production ceremony when backend is ready. |
| `dashboard.html` | `/` dashboard | Existing dashboard and shell show spaces, sync, queue, repo and readiness state. | Add recent Board and Inbox sections from design. |
| `space.html` | `/timeline/:space_id` and right panel | Current Space view is timeline-first. | Add Space overview projection for Boards, Rooms, activity and lazy links. |
| `board-room-workbench.html` | `/kanban` | Current `src/views/kanban.rs` is local demo state. | Implement AppView board projection from `board/list/card/contains relation`; use `cx.flow.move` / `cx.flow.reorder`. |
| `card-detail.html` | Not yet first-class | Current Kanban modal is minimal. | Build Card drawer with fields, linked Rooms, primary Room chat, activity and audit. |
| `room.html` | `/chat`, `/forum`, `/timeline` | Current chat page still uses `cx:flow` and `cx.flow.create`. | Migrate to standard `flow(kind="room")` / `message` objects and `cx.flow.branch.*` / `cx.message.*`. |
| `notifications.html` | `/notifications` | Existing notification panel supports projection and mute rules. | Add Card/Room permission re-check and conflict notifications. |
| `directory.html` | `/directory` | Existing directory handles spaces/orgs/actors and generic facets. | Add Card/Room search result shapes and locked lazy link behavior. |
| `contacts.html` | Removed from current nav | Actor relationship is partly represented through directory and admin flows. | Decide whether contact relationships remain product scope or fold into Directory/Profiles. |
| `space-admin.html` | `/space/:space_id/admin` | Existing admin covers metadata, invites, members, MLS rotation and archive. | Add Room-scoped external admission and grant explanation UI. |
| `devices.html` | `/devices` | Existing devices page covers queues, push and crypto summaries. | Add richer key package, SAS and revocation impacts. |
| `verify-device.html` | `/devices/verify` | Existing verify route exists. | Align QR/SAS ceremony and trust impact copy. |
| `audit.html` | `/audit` | Existing audit page covers repo commits and operations. | Add projection origin, authz explanation and board position conflict detail. |
| `settings.html` | `/settings` | Existing settings cover server, storage, encryption, MIMI, push, privacy, theme, release, recovery. | Separate actor-private view preferences from shared `cx.view.update`. |

## Main Gaps

1. Board is not yet protocol-backed. The implementation should stop treating Kanban as local-only demo state.
2. Chat should move from `cx:flow` to standard `room` and `message` objects.
3. Card click needs a real drawer with primary Room, linked Rooms, locked Room handling, activity and audit.
4. Projection permissions need to explicitly distinguish Card visibility from Room visibility.
5. Offline optimistic writes need pending, accepted and conflict UI states across Board/Card/Room.
