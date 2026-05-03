# yougen Active TODO

更新时间: 2026-05-03

`yougen` 是 Contrix 跨平台客户端。2026-05-03 的协议更新把 `subject` / `room` / `card` 的 wire identity 收敛为统一 `flow`，所以此前已完成的原型能力需要按 `flow + branch + Event Envelope` 重新收口，不能继续把 `room_id` / `card_id` 当作 canonical 协议主键。

## 执行顺序

- [ ] Block A: 先完成客户端领域模型和写入路径迁移，确保所有新写入只产生 `cx:flow:*`、`cx.flow.*` 和 `flow.branch.*` 相关状态。
- [ ] Block B: 再完成同步、投影和 UI 状态机，把 Board、discussion、audit 全部改成 `flow_id` 驱动。
- [ ] Block C: 最后接真实 `coauth` / `soland` / `starid` / MLS 服务，补齐生产登录、DID 绑定、设备与推送。

## 可并行 Lane

- [ ] Lane 1: `app state` / routes / DTO 映射。
- [ ] Lane 2: Event builder / offline queue / sync runtime。
- [ ] Lane 3: Board / discussion / audit UI。
- [ ] Lane 4: 身份、设备、推送、E2EE 集成。
- [ ] Lane 5: Playwright / contract replay / visual QA。

## P0: Flow-Centric Domain Model

- [ ] 移除客户端 canonical 状态里的独立 `room_id` / `card_id` / `subject_id` 主键语义。
- [ ] 统一使用 `flow_id + kind + semantic_kind + primary_branch + branches` 表达对象身份和默认入口。
- [ ] 路由、深链、缓存键、草稿键、选中态、最近访问记录统一改成 `flow_id`。
- [ ] 保留 UI 上的“卡片视图”“讨论视图”概念，但它们只能是同一 `flow` 的不同投影，不得再映射成不同 wire object。
- [ ] 所有本地 mock、fixture、demo data、storybook-like 示例数据停止生成 `cx:room:` / `cx:card:` / `cx:subject:`。

## P0: Event Write Path and Offline Queue

- [ ] Flow 相关 builder 只发出活跃 contract:
- [ ] `cx.flow.create` / `cx.flow.update` / `cx.flow.archive` / `cx.flow.restore`。
- [ ] `cx.flow.move` / `cx.flow.reorder` / `cx.flow.convert`。
- [ ] `cx.flow.branch.member` / `cx.flow.branch.history_visibility` / `cx.flow.branch.policy_components`。
- [ ] 消息路径严格绑定 `flow discussion branch`，`cx.message.create` / `revise` / `redact` 在 branch disabled 时 fail closed。
- [ ] offline queue、重试、幂等键、actor_seq 恢复、conflict 展示全部以 `Event Envelope` 为唯一共享历史单元。
- [ ] 本地被拒绝、soft-failed、quarantined、duplicate-conflict 的错误解释改成 `flow` 语义，不再引用 room/card 旧术语。

## P0: Sync and Projection Runtime

- [ ] client sync DTO、timeline、collection projection、search result、notification projection 统一改成 `flow_id` 引用。
- [ ] Board 投影使用 `Board Space -> List Space -> Flow(kind="card")`，而不是 `Board/List/Card` 三套独立身份。
- [ ] discussion 入口由 `flow.discussion branch` 决定；“主讨论室”“关联房间”等旧概念改成 branch enabled / primary branch state。
- [ ] `state_after`、`timeline.limited`、gap repair、expired cursor 恢复、`X-Contrix-Wait-For` read-your-writes 流程全部落到真实 sync 模型。
- [ ] access explanation、locked discussion、metadata-only 视图必须继续 fail closed，不泄露 branch 已禁用或对象不可见时的额外信息。

## P0: UI and Interaction Surfaces

- [ ] Board 页面把“卡片”明确渲染为 `flow(kind="card")` 的投影。
- [ ] discussion 页面把“房间”明确渲染为 `flow(kind="room")` 或 `flow.discussion branch` 的投影。
- [ ] Flow detail / side panel 同时展示 `kind`、`semantic_kind`、branch 状态、capability、event frontier。
- [ ] convert、move、reorder、archive、discussion enablement 等交互全部对齐新的 reducer 语义，不做本地旧 contract alias。
- [ ] Audit / protocol inspector 展示 `event_id`、`flow_id`、`prev_refs`、`auth_refs`、schema/reducer profile、proof 校验状态。

## P1: Identity, Account and Discovery

- [ ] 接入真实 `coauth` authorization code + PKCE、refresh rotation、soft logout、session revoke。
- [ ] DID 绑定 UX 对齐 `starid` / resolver / receipt 流程，按 DID method 显示 proof challenge、verification method、audience、expiry。
- [ ] handle、claim、org membership、progressive disclosure 全部作为展示和授权解释输入，不得成为本地主键。
- [ ] Directory / profile / actor surfaces 区分 public DID、pairwise DID、private disclosure 结果。

## P1: Device, Push and E2EE

- [ ] 使用 `chime` 完成 register/unregister、token rotation、本地注册状态持久化。
- [ ] push UI 只显示 blind wakeup / generic notification，不把 message body、room name、attachment filename 当作服务端可信字段。
- [ ] MLS state、KeyPackage publish/fetch、device revoke epoch advance、unable-to-decrypt、backup/recovery 流程接真实服务。
- [ ] revoked device、stale session、key missing、history sharing policy 变化时的客户端行为全部按规范 fail closed。

## P1: QA and Release Gates

- [ ] 替换所有仍引用 room/card/subject typed ID 的快照、测试名、fixture 名、截图文案。
- [ ] Playwright 覆盖:
- [ ] 登录、初始 sync、发送消息、拖拽 Flow、convert Flow、拒绝写入、离线重放、push 注册。
- [ ] contract replay 覆盖 `soland` 的 sync / events / authz 响应。
- [ ] visual regression 补充 desktop/mobile、高对比、密度模式、discussion-branch-disabled 场景。

## Definition of Done

- [ ] 生产写路径不再发出 `cx:room:` / `cx:card:` / `cx:subject:` 或 `cx.room.*` / `cx.card.*` / `cx.subject.*`。
- [ ] 客户端所有 canonical store、路由键、缓存键、projection DTO 统一使用 `flow_id`。
- [ ] `coauth`、`soland`、`chime`、`starid` 的真实 contract 至少完成一条端到端 happy path。
- [ ] Playwright 和本地 contract replay 覆盖 Board、discussion、audit 三条主链路。
