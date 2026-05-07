# yougen TODO

> 整理日期: 2026-05-07
> 范围: Contrix 跨平台客户端。当前重点是从协议展示/脚手架切到真实服务链路。

## 当前状态摘要

- event kind surface 已对齐 110 active kinds + hermetic diff 测试 + 同步脚本。
- UI 层已暴露 flow / recovery / device / audit / policy 概念；recovery/restore scaffold surface 已被 cotest release gate 覆盖。
- push placeholder 已被 `tests/dev_token_guard.rs` + `push::ensure_production_register_request()` 锁住。
- 主线目标: `coauth -> soland session grant -> chime/floria push -> soland recovery/device` 不再依赖手写 preview payload。

## 标记说明

- `[ ]` 未完成
- `[~]` 部分完成 / 等服务端或 SDK
- `🅿` parallel-safe
- `🔒` 多文件接线
- `⚠` 需要服务端 / SDK / 安全协同

## P0 · v1 wire model rework 客户端适配 ⚠ — **大部分作废 (2026-05-08)**

> ⚠ **Supersession 通知 (2026-05-08)**：`contrix-spec` 已用 **Move / Anchor / Lattice** 三原语替换旧 state slot / hub-writer / host endorsement 模型（见 [`../contrix-spec/_state_todos.md`](../contrix-spec/_state_todos.md) 与根 [`../_todos.md` C10.D](../_todos.md)）。本节中：
>
> - **W1（active event kinds 110 → 129）** — 阈值放宽到 134；
> - **W2（移除 state_key 字段）** — 仍有效（envelope state_key 字段 spec 已移除）；
> - **W3（hub Space 写入路径）** — **整体作废**；改为 Move 提交路径（统一 POST `/api/v1/moves`，不再分 hub / peer_mesh）；
> - **W4（host_endorsement 接收侧验证）** — **整体作废**；改为 Anchor view 同步 + anchorer_sig 校验；
> - **W5（pending_mls_binding UI 信号）** — 改为 `covered_frontier_cell` 当前 join 值 / Move 状态 `pending_anchor` UI；
> - **W6（Consent UI）** — 仍要做，底层从 `cx.consent.grant/revoke` 改为 consent cell or-set Move（grant=add tag, revoke=remove tag）；
> - **W7（host transfer 监控 UI）** — **整体作废**；改为 anchorer cell 切换 admin 视图（在 sodmin 而非 yougen，普通客户端无此 UI）。
>
> **新工作请见下方 P0 · Move / Anchor / Lattice 客户端适配章节。**

> 历史 Source: `contrix-spec` 2026-05-07 完成 Phase 1-5。

---

## P0 · Move / Anchor / Lattice 客户端适配（取代旧 P0）⚠

> 起源：`contrix-spec` 2026-05-08 用 Move/Anchor/Lattice 替换旧模型。详见根 [`../_todos.md` C10.D](../_todos.md)。
>
> Gate：依赖 contrix-rust-sdk M0-M12（typed Move/Anchor/Lattice）+ soland MAL-2/MAL-4/MAL-10（Move 提交入口 / Anchor 接收 / sync 状态字段）。

| # | 状态 | 任务 | 文件 | 依赖 |
|---|---|---|---|---|
| M0 ⚠ | `[ ]` | 删除旧 W3/W4/W7 占位（`src/views/space_admin/host_transfer.rs` 如已 scaffold）；移除 `space_writer_model` / `space_host` UI 引用。 | `src/views/space_admin*` | 根 C11 |
| M1 ⚠ | `[ ]` | event surface diff 同步：active event kinds 阈值更新到 134；hermetic diff 测试与同步脚本更新；新增 cx.move.v1 / cx.anchor.v1 typed surface 识别。 | `src/conformance.rs` | SDK M11 |
| M2 ⚠ | `[ ]` | `Move` 提交路径替代直发 event：`src/api.rs` 中所有写入操作（消息 / 状态 / 撤回 / 反应 / 邀请 / 容器更新）改为构造 Move（preconditions + effects + anchor_ref + refs）→ POST `/api/v1/moves`；不再直发 event envelope。 | `src/api.rs` | SDK M1, soland MAL-2 |
| M3 ⚠ | `[ ]` | Anchor view 同步：`src/sync.rs` 从 `/sync` 拉取最新 Anchor leaves + frontier + state_root；本地 `effective_anchor_view` 计算；query 走 effective state。 | `src/sync.rs` | SDK M2/M10, soland MAL-4 |
| M4 | `[ ]` | Move 状态 UI 信号：pending_anchor / effective / failed_precondition / failed_bottom / rejected_anchor / anchorer_paused 状态在消息 / state event UI 上区分；anchorer_paused = "Space 暂停推进，等待 recovery anchorer"。 | `src/views/chat.rs`、`src/views/space_admin.rs` | soland MAL-10 |
| M5 | `[ ]` | `bottom` UI 暴露：`bottom=expose` cell 的 query 返回 `{status:"conflict", heads:[...]}`，UI 展示为"该状态存在并发候选，需冲突修复"。 | `src/views/space_admin.rs` | SDK M5 |
| M6 ⚠ | `[ ]` | consent UI 改写为 consent cell Move：邀请前置 gate / 已授予 consent 列表 / 撤销按钮全部走 Move(consent cell or-set)；MIMI consent 互译保持。 | 新 `src/views/consent.rs`、`src/views/inbox.rs` | SDK M8 |
| M7 ⚠ | `[ ]` | MLS message Move + covered_frontier 状态：E2EE 消息发送时构造 MLS commit Move（含 covered_frontier 写入）+ message Move（含 covered_frontier 检查）。 | `src/views/chat.rs`、`src/mls.rs` | SDK M9 |
| M8 | `[ ]` | 冲突修复 UI（admin / moderator）：head_in 修复 Move 构造器 + recovery_capability 选择 UI（仅 admin 看见）。 | `src/views/space_admin.rs` | SDK M1 |

---

## P0 · 真实登录 / session / push 主链路

| # | 状态 | 任务 | 文件 | 依赖 |
|---|---|---|---|---|
| A1 ⚠ | `[~]` | OIDC browser flow 去 scaffold | `src/coauth.rs`、`src/views/login.rs` | `build_oidc_scaffold_bundle` 现在用 cryptographic RNG（`getrandom::fill`）生成 state / nonce / PKCE verifier，code_challenge 走真正的 S256（RFC 7636 §4.1），unit test 钉住 RFC 7636 Appendix B 测试向量。剩余：coauth 服务端持久化 state/nonce/PKCE、callback 自动捕获、真实 token endpoint code exchange。 |
| A2 ⚠ | `[~]` | session-grant exchange 真实化 | `src/coauth.rs`、`src/api.rs`、auth/session store | 已能接收 coauth grant id 并向 soland exchange API 携带可选 introspection proof；剩余：根据 grant id / challenge 生成 session-key JWS proof、持久化 token 生命周期、去掉 dev-token fallback。 |
| A3 ⚠ | `[~]` | push register 替换 dev token / 手写 body | `src/push.rs`、`src/api.rs`、`src/views/login.rs` | 已落地：`PushTokenSource` trait + `DevPlaceholderTokenSource` 默认实现 + 注入点；register/unregister 端到端走 `chime::ContrixPushClient::{register,unregister}_device_with_request`，bridge-discovered path 由 `with_register_device_path` 注入。剩余：真实 OS / Web Push token 接入。 |
| A4 🔒 | `[ ]` | 主会话 token 生命周期 | auth store / app shell | 提前 refresh、logout 清理、跨窗口状态同步，和 sodmin/coauth 安全策略对齐。 |

## P1 · Recovery / Device / Crypto

| # | 状态 | 任务 | 文件 | 依赖 |
|---|---|---|---|---|
| R1 ⚠ | `[~]` | key-backup UI 从 scaffold 切 durable API | `src/views/settings.rs` | `soland` key-backup durable store；SDK restore-ticket client。 |
| R2 ⚠ | `[~]` | restore-ticket lifecycle 接真实状态机 | `src/views/settings.rs` | `soland` RecoveryTicket / RestoreExecutor；`coauth` principal cache。 |
| R3 ⚠ | `[~]` | device verification 写入 device_messages | `src/views/devices.rs`、`src/views/verify_device.rs` | `ContrixApi::send_device_message_envelope(txn_id, target_actor, target_device, type, content)` 已落地，`build_device_message_envelope` 钉住 `cx.schema.device_message.v1` wire shape；devices.rs 的 `queue-verification-{request,ready,done}` 三个按钮现在真正 PUT `/api/v1/device_messages/{txn}`。剩余：verify_device.rs 的 SAS-match / QR 完成路径接 `cx.key.verification.{accept,key,mac,start,cancel}` 链路、配 SDK helper 生成 SAS / QR signed envelope。 |
| R4 ⚠ | `[~]` | device revoke -> MLS Remove + Epoch++ | `src/views/devices.rs`、MLS state | T31 wire-up 已落地：`device_revoke::DeviceRevokePlan` 编排完整事件链（local revoke → `cx.device.revoked` → 每 group 的 `cx.mls.proposal/commit/welcome` → KeyPackage 失效 → push 取消注册），UI 先展示步骤再确认；`LocalMlsDevice::remove_member_by_principal` SDK helper 已暴露。剩余：app 层把 (principal, device) 映射到具体 MLS group state 后调 helper、把 commit envelope 喂给 server federation push、push gateway 真正去注册。 |
| R5 ⚠ | `[ ]` | browser encryption production boundary | `src/app.rs`、crypto storage | 现在提示 WebCrypto/IndexedDB MLS state 是 development-only；需要真实 secure backup/recovery 后放开。 |

## P2 · Flow-first 产品面

| # | 状态 | 任务 | 文件 | 说明 |
|---|---|---|---|---|
| F1 ⚠ | `[~]` | Kanban 协议化 | `src/views/kanban.rs` | T20 wire-up 已落地：`ContrixApi::collection_projection` + `collection_projection_to_columns` 适配器 + 进入 view 时 auto-refresh，显示 API-derived/seed fallback 来源指示。剩余：移除 seed fallback、对 `cx.flow.move`/`cx.flow.reorder` 走 reducer、监听 sync 推送时增量重投 projection。 |
| F2 ⚠ | `[~]` | Chat/message canonical 切换 | `src/views/chat.rs`、message builder | T21 wire-up 已落地：discussion 创建走 typed `Flow::discussion()`（`cx_ops::discussion_flow_create`），消息发送走真实 `cx.message.create`（`api.send_message`），UI banner 区分 wire kind=discussion 与 UI category。剩余：UI category 持久化为 `Flow.fields.category`、message edit/redact/reaction 走 typed helpers、history paging。 |

## P3 · 测试 / 发布质量

| # | 状态 | 任务 | 文件 | 说明 |
|---|---|---|---|---|
| Q1 🅿 | `[ ]` | e2e 覆盖 OIDC -> session grant -> push register | `tests/e2e/*` | 先走 compose harness。 |
| Q2 🅿 | `[ ]` | recovery happy path e2e | `tests/e2e/*` | 依赖 soland/coauth durable recovery。 |

## 跨项目登记

| 根任务 | 本仓责任 |
|---|---|
| C3 | 已具备携带 introspection proof 的 API surface；剩余 JWS proof 生成、session store 和 UI 流程替换。 |
| C4 | 用 chime/floria 做真实 push register 和 token rotation。 |
| C5 | recovery/key-backup/device verification UI 已有 scaffold API 调用面；剩余是接 durable API 和真实 device verification。 |
| C6 | 当 soland 暴露 optional StarID resolver profile 时，客户端需要展示 resolver/profile 状态但不把 `did:webvh` 当 v1 core 必选。 |
| C8 | 给 cotest/example-stack 提供 headless happy path。 |
| C10.D | **客户端适配 spec 2026-05-08 Move/Anchor/Lattice rewrite**——新 P0 M0-M8 是本仓全部 C10 任务。旧 W1-W7 中 W3/W4/W7 整体作废（hub Space / host_endorsement / host transfer UI），W1/W2/W5/W6 重新映射到新模型。需要 SDK M0-M12 先就位。 |
| C11 | 删除 `src/views/space_admin/host_transfer.rs`（如已 scaffold）；移除 `space_writer_model` / `space_host` UI 引用。 |

## 已完成（changelog）

- `[x]` T80-T92 的协议 surface 展示。
- `[x]` Onboarding 路由拆分、chat 词汇对齐 `flow(kind=room)`、最后一批 event kind surface。
- `[x]` 旧 card/room-first 视图已基本迁到 flow-first 信息架构。
- `[x]` F3 Presence / typing ephemeral runtime。
- `[x]` F4 Call signaling runtime。
- `[x]` F5 profile/event coverage diff 自动化（snapshot 测试 + 同步脚本）。
- `[x]` Q3 privacy/dev-token regression tests（`push::is_placeholder_push_key` + `ensure_production_register_request` + `tests/dev_token_guard.rs`）。
- `[x]` T20 wire-up — Kanban board 通过 SDK `CollectionProjectionResponse` + `ContrixApi::collection_projection` 消费真实 view projection（F1 部分完成，详见上表）。
- `[x]` T21 wire-up — Chat discussion 创建走 typed `Flow::discussion()`、message send 走真实 `cx.message.create`（F2 部分完成）。
- `[x]` T31 wire-up — Device revoke plan executor 编排完整 `cx.device.revoked` + 每 group MLS 步骤（R4 部分完成）。
- `[x]` Kanban auto-refresh-on-mount —`KanbanPanel` mount 时自动调 `collection_projection`，API-derived 成默认（F1 部分完成）。
- `[x]` OIDC scaffold 去掉 `(actor_did, device_id)` 派生的确定性 state/nonce/verifier，改用 `getrandom::fill` 32-byte 随机 verifier + S256 challenge；新 5 条 `coauth::tests` 钉住 RFC 7636 Appendix B 测试向量（A1 部分完成）。
- `[x]` `ContrixApi::send_device_message_envelope` + `build_device_message_envelope` 助手钉住 `cx.schema.device_message.v1` wire shape，devices.rs 的 verification.{request,ready,done} 三个按钮真正 PUT `/api/v1/device_messages/{txn}`（R3 部分完成）。
