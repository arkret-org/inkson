# Design vs Current Implementation Audit

Updated: 2026-05-04

This audit compares the refreshed full application design pages with the current Dioxus implementation.

> 2026-05-04 update: 增补的 `claude-design/`（基于 `contrix-spec/spec/v1/zh/` 协议规范的客户端 UI 设计稿）覆盖了桌面与移动两个版本，并把 Onboarding / Recovery / Applets / Trust Bundle 等本仓库尚未承载的页面补齐。详细任务列表见仓库根 [`_todos.md`](../_todos.md)。本审计表的 follow-up 列在持续追踪中，新发现的 gap 优先记入 `_todos.md`。

| Design page | Current frontend area | Current state | Follow-up |
| --- | --- | --- | --- |
| `login.html` | `/login` | Existing login surface covers health, passkey challenge, OIDC redirect, dev login, token refresh. | Align visual layout with new auth design and keep production WebAuthn callback work separate. |
| `register.html` | `/register` | Existing registration wizard covers DID method, handle, profile, proof placeholder, recovery selection, account creation. | Replace placeholder proof/recovery with production ceremony when backend is ready. |
| `dashboard.html` | `/` dashboard | Existing dashboard and shell show spaces, sync, queue, repo and readiness state. | Add recent Board and Inbox sections from design. |
| `space.html` | `/timeline/:space_id` and right panel | Current Space view is timeline-first. | Add Space overview projection for Boards, Rooms, activity and lazy links. |
| `board-room-workbench.html` | `/kanban` | Current `src/views/kanban.rs` is local demo state. | Implement AppView board projection from `board/list/card/contains relation`; use `cx.flow.move` / `cx.flow.reorder`. |
| `card-detail.html` | Not yet first-class | Current Kanban modal is minimal. | Build Card drawer with fields, linked Rooms, primary Room chat, activity and audit. |
| `room.html` | `/chat`, `/forum`, `/timeline` | Current chat page still uses `cx:flow` and `cx.flow.create`. | Migrate to standard `flow(kind="room")` / `message` objects and `cx.flow.track.*` / `cx.message.*`. |
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

## 2026-05-04 — claude-design 引入的新增页面

| claude-design 页面 | 现状 | 跟进 |
| --- | --- | --- |
| `desktop/onboarding.html` | 当前 `/register` 一站式承担注册；DID method 选择 + 首设备 + recovery 没有专属步进。 | 拆出 `/onboarding`，用步进式覆盖 DID method / handle / device key / recovery（_todos.md T12）。 |
| `desktop/recovery.html` | 设置中存在 recovery 占位，但 Argon2id / SSS guardian / Recovery Key 不可见。 | 新增 `views/recovery.rs` + Route（_todos.md T10）。 |
| `desktop/applets.html` | 没有 applet / agent / portal 管理页。 | 新增 `views/applets.rs` + Route（_todos.md T11）。 |
| `desktop/space-admin.html`（trust bundle / grant explanation） | 现有 admin 偏 metadata + invite。 | 增补 grant 决策 trail、approval_constraint 进度、trust_bundle 导入面板（_todos.md T13）。 |
| `desktop/audit.html`（projection origin / conflict trail） | audit 已展示 commit + operation。 | 加 projection origin、authz explanation、conflict winner/superseded（_todos.md T14）。 |
| `desktop/board.html` 多 renderer 切换 | Kanban 是单一 renderer。 | 头部加多 renderer 占位（board / list / table / calendar / timeline / graph）（_todos.md T5）。 |
| Permission pill 三独立维度 | directory / admin / kanban 各自手写 | 抽出 `components/permission_pill.rs`（_todos.md T8）。 |
