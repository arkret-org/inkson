# Yougen — 与最新协议对齐的任务表

依据：`E:/Works/contrix-dev/contrix-spec`（commit `fc7da5b`，2026-05-05 多轮简化后的状态）。

> 上次会话：`ca02ebd` (21 项) + `ea266be` (14 项与最新 spec 对齐) 已 push 到 `origin/main`，cargo check exit=0。
>
> 标记说明：🅿 = 单文件可独立完成；🔒 = 多文件接线；⚠ = 需要 reducer / SDK 协同。

---

## A. 注册表覆盖缺口（57/109 event kinds 仅在 `known_event_kinds()` 出现）

通过 `python diff` 扫出 57 个有 canonical event 但 yougen 视图层零接触的 kind。其中下列项目有清晰的用户面：

- [ ] 🅿 **T80. 渐进披露面板**（`views/settings.rs` Privacy 段）：surface `cx.identity.disclosure_policy` / `cx.identity.disclosure_receipt` / `cx.identity.presentation_request` / `cx.identity.presentation_response` 的 UI 入口与解释。`identity-handles.md §16`。
- [ ] 🅿 **T81. Actor-private View 偏好**（`views/settings.rs` 新段）：`cx.account_data.set` 写入路径（actor-private V iew prefs，与 shared `cx.view.update` 拆开），claude-design 已经在头表中提到。
- [ ] 🅿 **T82. Invite lifecycle 扩展**（`views/space_admin.rs` Invites 段）：标注 `cx.invite.{create,accept,claim,cancel,revoke,third_party}` 6 个 event 的状态转移。
- [ ] 🅿 **T83. Organization / Sovereign 治理**（`views/space_admin.rs` 新段）：surface `cx.space.organization` / `cx.organization.discovery` / `cx.organization.moderation_policy` / `cx.sovereign.did_policy` 四个 event；指向 `identity/identity-did.md §6` + `sync/sovereign-deployment.md`。
- [ ] 🅿 **T84. Policy 事件链**（`views/space_admin.rs` Policy 段）：`cx.policy.{rule,action,set}` 三 event 的写入路径解释。
- [ ] 🅿 **T85. MLS lifecycle 完整列表**（`views/devices.rs`）：`cx.mls.{genesis,keypackage,proposal,commit,commit_failed,welcome}` 6 event 的角色解释（welcome 已显示）。
- [ ] 🅿 **T86. Space hierarchy 入口**（`views/space_admin.rs` 新段）：`cx.space.{child,parent,upgrade,lifecycle.set}` event。`models/space-hierarchy.md`。
- [ ] 🅿 **T87. Presence / typing 指示器**（`views/chat.rs` 或 claude-design `desktop/discussion.html`）：`cx.presence` / `cx.typing` 是 ephemeral channel events，UI 上需要展示但不写入 history。
- [ ] 🅿 **T88. Call 信令事件**（`views/call.rs`）：在协议 banner 中点出 `cx.call.{signal,state,recording.start}` 三 event 的边界（signal/state ephemeral；recording.start durable + capability gated）。
- [ ] 🅿 **T89. Applet / Agent protocol session 事件**（`views/applets.rs`）：`cx.applet.protocol_session.{start,status}` + `cx.agent.protocol_session.{start,status,result}` + `cx.applet.bridge_error` 的 UI 解释。
- [ ] 🅿 **T90. Schema 演进**（`views/audit.rs` 新区段）：`cx.schema.define` / `cx.schema.update` event 在 audit 流中暴露，便于排查 schema drift。
- [ ] 🅿 **T91. Inbox Blocklist 入口**（`views/notifications.rs` 或 settings）：`cx.account.blocklist` event 写入路径，已经在 inbox 提到 individual blocklist，但未链到 event kind。
- [ ] 🅿 **T92. Member state 与 invite/knock**（`views/space_admin.rs` Members 段）：`cx.member.state` event 的 5 个 MembershipState 变体（Joined/Invited/Left/Banned/Knocked）；空间允许 knock 时给 UI。

## B. 暂不做（reducer / SDK 协同）

- ⚠ Kanban 协议化（替换 seed_columns 为 API-derived projection）
- ⚠ Chat 从 `cx:flow:*` 迁移到 `flow(kind=room)` / message canonical
- ⚠ Device 撤销 → MLS Remove + Epoch++ 完整链路
- 🔒 Onboarding 路由从 register 拆出
- ⚠ Branch update / morph update / relation update / capability.derived（reducer 内部计算）

这些都需要 SDK / 服务端协同，留待独立 PR。

---

## 已完成（最近会话）

- 2026-05-04 / 2026-05-05 round 1-5（commit `ca02ebd`）：21 项 — UI 信息架构对齐 claude-design + 4 项 pre-existing 阻塞修复。
- 2026-05-05 round 6（commit `ea266be`）：14 项 — 与 spec fc7da5b 对齐（路径迁移 / event registry resync / DID 默认值 / profile tier / audited E2EE / constraint family / notification 派生化 / transport 锁定）。
