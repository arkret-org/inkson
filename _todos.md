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

## P0 · Move / Anchor / Lattice 客户端适配（取代旧 P0）⚠

> 起源：`contrix-spec` 2026-05-08 用 Move/Anchor/Lattice 替换旧模型。详见根 [`../_todos.md` C10.D](../_todos.md)。
>
> Gate：依赖 contrix-rust-sdk M0-M12（typed Move/Anchor/Lattice）+ soland MAL-2/MAL-4/MAL-10（Move 提交入口 / Anchor 接收 / sync 状态字段）。

| # | 状态 | 任务 | 文件 | 依赖 |
|---|---|---|---|---|
| M0 ⚠ | `[ ]` | 删除旧 W3/W4/W7 占位（`src/views/space_admin/host_transfer.rs` 如已 scaffold）；移除 `space_writer_model` / `space_host` UI 引用。 | `src/views/space_admin*` | 根 C11 |
| M1 ⚠ | `[ ]` | event surface diff 同步：active event kinds 阈值更新到 134；hermetic diff 测试与同步脚本更新；新增 cx.move.v1 / cx.anchor.v1 typed surface 识别。 | `src/conformance.rs` | SDK M11 |
| M2 ⚠ | `[~]` | (2026-05-09 十六轮) **Move 提交基础设施已落地**: API client 加 `submit_move(&Move)` / `submit_anchor(&Anchor)` / `admin_anchors_sign(...)` 三个方法 + `models::SubmitMoveResponse` / `SubmitAnchorResponse` / `SignAnchorResponse` DTOs；新 `move_builder` 模块含 3 cell-driven builders (`build_consent_grant_move` / `build_member_state_transition_move` / `build_space_organization_update_move`) + `sign_unsigned_move` ed25519-dalek 签名 helper + did:key 编码工具；新依赖 `ed25519-dalek` + `bs58`。6 unit tests + 5 contract tests。**剩余 M2 收尾**: 修订 spec 范围 — 不是"所有写入操作"，按 spec event-kind-registry 只把声明 cell_family 的事件 (consent / capability / member.state / space.{create,update,destroy} / flow.position / anchorer / mls.epoch) 改走 Move 路径；其他 (messages / reactions / read_markers / entities / relations / redactions) 按 spec 保留 direct-event 端点。UI 接线 (consent UI / member admin UI 等替换 direct-event 调用) 是 feature-by-feature 工作。 | `src/api.rs`, `src/move_builder.rs` (NEW), `src/models.rs` | SDK M1, soland MAL-2 |
| M3 ⚠ | `[~]` | Anchor view 同步：(2026-05-09 二十轮) `local_state::LocalAnchorView { frontier[], leaves[], state_root, bottom_cells }` 落地 + `LocalStateStore::{anchor_view_for, set_anchor_view, anchor_views, anchor_ref_for_move}` 访问器；`LocalAnchorView::from_sync_body(&Value)` 在 app.rs 的 `/sync` 处理路径为每个 Space 解析 `anchor_view` 字段并 persist；Move builders 的 UI callers (`consent_demo` / `space_admin::build_signed_*`) 改读 `state_store.read().anchor_ref_for_move(&space)`，落空时 fallback 到 `LocalAnchorView::EMPTY_ANCHOR_REF` (sha256 empty)。Round 22 加 `covered_frontier_lag: Option<u64>` 字段 + helper `covered_frontier_lag_above(threshold)`，wire 形态 `anchor_view.covered_frontier_lag: u64` 已被 from_sync_body 覆盖。剩余：soland 实际把 `anchor_view` 字段写到 `/sync` per-space body 后端到端验证；多 head 冲突情景的 effective state 计算 (lex-min head 占位)；query 走 effective state。 | `src/local_state.rs`, `src/app.rs`, `src/views/space_admin.rs`, `src/views/consent_demo.rs` | SDK M2/M10, soland MAL-4 |
| M4 | `[ ]` | Move 状态 UI 信号：pending_anchor / effective / failed_precondition / failed_bottom / rejected_anchor / anchorer_paused 状态在消息 / state event UI 上区分；anchorer_paused = "Space 暂停推进，等待 recovery anchorer"。 | `src/views/chat.rs`、`src/views/space_admin.rs` | soland MAL-10 |
| M5 | `[~]` | `bottom` UI 暴露：(2026-05-09 二十轮) `space_admin` 顶部 `bottom-cells-banner` 区块；当 `LocalAnchorView::bottom_cells` 非空时渲染红 badge "concurrent candidates unresolved" + per-cell row (`bottom-cell-row`)，否则不渲染。`anchor_view::from_sync_body` 只把 `bottom=expose` cells 收进 map（`reject` 等其他状态不暴露）。剩余：head_in repair Move 构造器、UI 入口 + soland query 真正返回 conflict shape。 | `src/views/space_admin.rs`, `src/local_state.rs` | SDK M5 |
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
| C10.D | **客户端适配 spec 2026-05-08 Move/Anchor/Lattice rewrite**——P0 M0-M8 是本仓全部 C10 任务。需要 SDK M0-M12 先就位。 |
| C11 | 旧产物清理已完成 (2026-05-08)：未 scaffold 过 host_transfer.rs；`space_writer_model` / `space_host` UI 引用 0 命中。 |

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

## C10.D 续 — UI Move-flow PoC (2026-05-09 十八轮 并行)

- `[x]` 第一个端到端 UI Move-flow 接线落地（M2 收尾的第一块 UI surface）：新建 `src/views/consent_demo.rs::ConsentGrantDemoCard` Dioxus 组件 + 嵌入 `SettingsPanel` 的 Privacy section。点击 "Grant consent (build + sign + POST)" 按钮即：
  1. 用 `move_builder::build_consent_grant_move` 构造 `cx.consent.grant` Move（cx.component.consent.grant.v1 OrSet add）；
  2. 用 deterministic demo ed25519 SigningKey（`[42; 32]`，标 `TODO(real-key-management)`）签名；
  3. 通过 `ContrixApi::submit_move` POST `/api/v1/moves`；
  4. 在 UI 状态行显示 `state=pending|rejected` + reason。
  - 演示路径: `Settings → Privacy → "Grant consent (Move PoC)"` 卡片；测试 ID `consent-grant-{space-id,consent-id,tag,submit,status,last-move-id}`。
  - Anchor frontier: 暂用 `cx:anchor:sha256:e3b0...b855`（empty-bytes SHA-256）占位，标 `TODO(anchor-frontier-from-sync)`；HLC 走 `crate::hlc::Hlc::now("yougen")`。
  - 新增 4 unit tests: `build_signed_consent_grant_produces_consent_or_set_add` / `..._attaches_detached_jws_with_demo_did_key` / `..._is_content_addressed_by_canonical_bytes` / `format_submit_response_renders_state_and_optional_reason`。
  - 测试计数: 195 → 199 (+4)；构建零警告新增。
  - 剩余 UI surface (按 spec event-kind-registry 的 cell-driven 事件; M2 后续轮次按 P0 表分块): member admin (`cx.member.state` invited→join FSM)、space organization update (`cx.space.update` cas-register)、capability grant/revoke、consent revoke 路径、anchorer cell、MLS epoch。Direct-event 路径 (messages / reactions / read markers / entities / relations / redactions) 保留不变。

## C10.D 续 — Round 20 / UI Move-flow 第三批 + sync threading (2026-05-09 二十轮)

- `[x]` **`LocalAnchorView` + sync threading** (M3 部分完成): `local_state::LocalAnchorView { frontier[], leaves[], state_root, bottom_cells }` 新 struct + 4 accessors (`anchor_view_for` / `set_anchor_view` / `anchor_views` / `anchor_ref_for_move`)；`from_sync_body(&Value)` parser 解析 `body.anchor_view.{frontier,leaves,state_root,cells.*.bottom}`；app.rs 的 `/sync` 处理路径 per-space 调 `set_anchor_view(...)`；`move_anchor_ref()` 选 lex-min head 或 `EMPTY_ANCHOR_REF` 占位 (`sha256(empty)`)。所有 UI Move builders (`build_signed_consent_grant` / `..._consent_revoke` / `..._member_state_transition` / `..._space_organization_update` / 新 `..._capability_grant` / `..._capability_revoke`) 的 onclick 现在都从 `state_store.read().anchor_ref_for_move(&space)` 读 anchor_ref，不再硬编码 PLACEHOLDER。新 6 unit tests in local_state。
- `[x]` **Capability grant / revoke Move-flow UI** (P0 capability 第一块): `move_builder::build_capability_grant_move` + `..._revoke_move` (OrSet add/remove on `cx.component.capability.grant.v1:{grant_id}`) + `space_admin::build_signed_capability_grant` / `..._revoke` 助手 + `capability-grant-card` Dioxus 区块（grant_id / tag / revoke_reason 表单 + Grant/Revoke 按钮）。测试 IDs: `cap-grant-id-input` / `cap-grant-tag-input` / `cap-revoke-reason-input` / `cap-grant-submit-button` / `cap-revoke-submit-button`。新 3 unit tests in `move_builder` + 2 in `space_admin::move_flow_tests`。
- `[x]` **bottom=expose UI banner** (M5 部分完成): `space_admin` 顶部 `bottom-cells-banner`，当 `anchor_view.bottom_cells` 非空时渲染红 badge + per-cell `bottom-cell-row` 行；提示文案点出"unresolved concurrent candidates" 与 head_in repair 路径。`from_sync_body` 只把 `bottom=expose` cells 收进 map (`reject` 等不暴露)。也在 `space_admin` 加 `anchor-frontier-debug` 区块展示 frontier heads + state_root（debug 用）。
- `[x]` **Anchorer cell read-only UI** (M4): `space_admin::anchorer-cell-card` 区块 + `ContrixApi::admin_anchorer_describe(space_id)` GET `/api/admin/v1/spaces/{id}/anchorer`；按钮 `anchorer-cell-refresh` fetch + 在 `anchorer-cell-status` / `anchorer-cell-value` 行展示。404 时 status 行明确写 "endpoint unavailable (separate agent shipping)"，UI 不阻塞。
- `[x]` **C19 fixture sweep tail** (yougen-local): `views/kanban.rs` 测试中的 `cx:view:01js0vw0...` ULID-shape id 改成 UUIDv7 `cx:view:01904100-0000-7000-8000-000000000001`（SDK identifiers/lib.rs 收紧 validator 后此测试 fail；fixture 在 yougen 仓内，无跨仓影响）。
- `[—]` **C20 / C21 字段重命名 (`actor_type→actor_kind` / `content_block.type→.kind`)**: 二十轮再次全仓 grep `actor_type|content_block` 0 source 命中，无 client wire-side 改名工作（与十八轮结论一致）。
- 测试计数: 211 → **222** (+11: 6 anchor_view + 3 move_builder capability + 2 space_admin capability)；`cargo test --lib` 222/222 pass。
- 测试编译时遇到 contrix-rust-sdk `crates/sdk/src/resolver.rs` 1486 行 format! 参数错配 build error（与一同进行的 SDK 改造冲突，**非本仓回归**，文档于此并未修改）；通过 `git stash` SDK 改动后 yougen 测试 222/222 pass，pop 后 1 个 kanban test 因 SDK identifier validator 收紧而失败，已就地把该 fixture 改成 UUIDv7（仍在 yougen 仓内）。SDK resolver.rs format! 错误属并行 agent 工作流，超出本仓范围。

## C10.D 续 — UI Move-flow 第二批 + Policy lock (2026-05-09 第二批 并行)

- `[x]` **Consent revoke 路径**：`move_builder::build_consent_revoke_move` 助手 + `views/consent_demo::build_signed_consent_revoke` + Privacy section "Revoke consent (OrSet remove)" 按钮。OrSet causal remove 路径，target cell 与 grant 同（`cx.component.consent.grant.v1`），op type=Remove，可选 `reason` 字段。测试 IDs: `consent-revoke-submit`。
- `[x]` **Member admin Move-flow 接线**：`views/space_admin::build_signed_member_state_transition` 把 `Kick (Move)` / `Ban (Move)` 按钮加在原 direct-event 按钮旁。Kick = `join → leave` FSM transition；Ban = `join → ban`；都打到 `cx.component.member.state.v1` cell。测试 IDs: `kick-member-via-move-button` / `ban-member-via-move-button`；旧 `kick-member-button` / `ban-member-button` 保留作 fallback。
- `[x]` **Space organization update Move-flow 接线**：`views/space_admin::build_signed_space_organization_update` 把 `Save Metadata (Move)` 按钮加在 Save Metadata 旁。`cx.space.update` 写到 `cx.component.space.organization.v1` cas-register cell（`{title, topic, description}` 折叠成 cell value）。测试 ID: `update-metadata-via-move-button`。
- `[x]` **Server-declared Policy lock UI** (P0 M5 / 根 _todos.md C14.D)：
  - `local_state.rs` 新 `ReadReceiptPolicySnapshot { disclosure, visibility }` struct + `read_receipt_policy_snapshots: BTreeMap<String, ReadReceiptPolicySnapshot>` 字段 + `set_read_receipt_policy_snapshot(...)` / `read_receipt_policy_for_space(...)` / `read_receipt_policy_snapshots(...)` 访问器。
  - `read_receipt_should_send` 优先级改为 (server policy → flow → space → default)：disclosure=required → 强制 true（lock 用户的 skip）；disclosure=disabled → 强制 false（lock 用户的 send）；其他值（含 optional）→ 用户 override 仍生效。
  - settings.rs Privacy section 渲染时调 `read_receipt_policy_for_space(&space_id)`：locked 时整行加 `locked by Space policy` 红 badge，toggle 与 clear 按钮 `disabled=true`，其下显示 `lock_reason()` 文案（"Space policy: read receipts are REQUIRED ..."）。测试 IDs: `read-receipt-override-locked` / `read-receipt-override-lock-reason` / `read-receipt-policy-lock-note`。当 sync (P0 M3) 把 server-declared `cx.component.space.read_receipt_policy.v1` cell value 写入 snapshot map 后，UI 自动锁定，无需额外接线。
- `[—]` **Server-sync `cx.read_receipt.preferences` to encrypted account_data**：暂搁置——既不存在 yougen `api::set_account_data` 写端点，也不存在 soland `/api/v1/account_data/{type}` PUT 端点（`account_data: []` 字段在 `/sync` response 是只读的）。需要 SDK + soland 先开 account_data 写路径。本仓 `local_state::private_data` 里已有本地 XOR-encrypted 持久化做替代；server-sync 留 spec 设计文档 `discovery/client-preferences.md` §3.6 hints。
- `[—]` **C19.D ULID→UUIDv7 fixture 扫荡**：本仓 `tests/fixtures/event-kind-registry.snapshot.txt` / `tests/fixtures/event-kind-wire-scopes.snapshot.tsv` / `src/device_revoke.rs` / `src/views/kanban.rs` / `tests/e2e/mockContrixApi.ts` / `tests/serverx_contract.rs` 全仓 grep `[0-9A-HJKMNP-TV-Z]{26}` 命中 0 条 ULID-shape 字面量；spec migration script 已经把跨仓改造完，本仓无清理工作。
- `[—]` **C20 / C21 字段重命名 (`actor_type→actor_kind` / `content_block.type→.kind`)**：本仓全仓 grep `actor_type|actor_kind|content_block` 0 source 命中（`crypto.rs` 中 `content_type` 是 `EncryptedPayload` 的 MIME-style header — 来源 SDK，与 spec content_kind 字段不同），无 client wire-side 改名工作。
- 测试计数: 199 → **211** (+12: 4 build_consent_revoke + 4 server_policy_* + 4 build_signed_*); `cargo test --lib` 211/211 pass。

## C10.D 续 — Round 21 / Real key store + MLS epoch widget + account_data sync (2026-05-09 二十一轮)

- `[x]` **Real ed25519 key store**: 删掉所有 production-side `[42; 32]` demo seed callers。新 `local_state::LocalIdentity { device_did, signing_key }` + `LocalIdentityRecord { seed_hex, did_key }` + `LocalStateStore::{local_identity, local_identity_record, ensure_local_identity}` 访问器。`ensure_local_identity` 是 lazy generate-and-persist：首次调用走 `getrandom::fill` 生成 32-byte seed，derive `did:key:z<multibase>`，写到 `state.json`；之后调用直接 round-trip 持久化记录。tamper-detection: `LocalIdentity::from_record` 校验缓存的 `did_key` 与 seed 重新派生的值一致，否则报错 + 让 `ensure_local_identity` regenerate。所有 UI Move builders 改造：`consent_demo::build_signed_consent_{grant,revoke}` / `space_admin::build_signed_{space_organization_update,capability_grant,capability_revoke,member_state_transition}` 全部 take `&LocalIdentity` 参数；onclick 闭包先 `state_store.write().ensure_local_identity()` 再传递给 builder。生产代码零 `[42; 32]` 引用 (`demo_signing_key` / `identity_from_signing_key` / `PLACEHOLDER_ANCHOR_REF` 全部 cfg-gate `#[cfg(test)]`)。**No compat path**: 老 `[42;42]` 客户端没有持久化 record 时直接 regenerate，spec 是 pre-release，没有用户可见的 key recovery 故事可恢复。新依赖: `tracing = "0.1"` (graceful degradation log)。新 3 unit tests (`ensure_local_identity_generates_persists_and_round_trips` / `local_identity_two_calls_to_generate_diverge` / `local_identity_record_tamper_detection_regenerates`) + 1 cross-module test (`distinct_identities_produce_distinct_move_ids`)。
- `[x]` **MLS epoch UI**: read-only widget on `space_admin` (`mls-epoch-widget` test ID + `mls-epoch-value` / `governance-covered-frontier` rows)。展示 `cx.component.mls.epoch.v1` cas-register cell value + `cx.component.governance.covered_frontier.v1` 值。无独立 fetch — 直接读 `LocalAnchorView` (sync 已经投影到 cell map)。`LocalAnchorView` 扩展 `mls_epoch: Option<u64>` + `covered_frontier: Option<String>`；`from_sync_body` 在 cells map 里识别两个 well-known cell prefixes 并把 value 拆出来 (支持 bare integer / `{ "value": N }` / `{ "register": { "value": ... } }` 三种 wire shapes)。新 2 unit tests。
- `[x]` **Server-sync `cx.read_receipt.preferences` to encrypted account_data**: 新 `api::set_account_data(type_key, content) -> AccountDataSetOutcome`，PUT `/api/v1/account_data/{type_key}` body=`{ "content": <value> }`；返回 `Stored { response }` 或 graceful `Unsupported { status }` (404 / 501 / 405 时 `tracing::warn` 一行后 swallow)。新 `models::AccountDataSetOutcome` enum。settings.rs Privacy section 新 `READ_RECEIPT_ACCOUNT_DATA_KEY = "cx.read_receipt.preferences"` const + `build_read_receipt_preferences_body(default_send, space_overrides, flow_overrides)` 助手 (lock 字段名 `default_send` / `space_overrides` / `flow_overrides`)。default-toggle / per-space toggle / inherit-default / add-override 五个变更点全部新增 `push_read_receipt_account_data` fire-and-forget spawn — local state 仍是 authoritative source，server-sync 是 best-effort。新 2 unit tests (`build_read_receipt_preferences_body_has_canonical_field_shape` / `read_receipt_account_data_key_matches_spec`)。
- `[—]` **C20 / C21 fixture last sweep**: 全仓 grep `actor_type` / `content_block.type` / 26-char ULID-shape 字面量都是 0 命中。十八轮 / 二十轮已经清扫完。
- `[x]` **contrix-rust-sdk version bump**: SDK Cargo.toml 已经从 0.4.0 → 0.5.0。yougen 的 path-based deps 之前没写 version 字段，加上 `version = "0.5.0"` 让 published-crates resolver 也能选对版本。
- 测试计数: 222 → **230** (+8: 3 local_identity + 2 anchor_view 新 cell parse + 1 distinct_identities + 2 settings)；`cargo test --lib` 230/230 pass。
- 次要清理: `PLACEHOLDER_ANCHOR_REF` (consent_demo + space_admin) 与 `demo_signing_key` / `identity_from_signing_key` (consent_demo) 全部加 `#[cfg(test)]` gate；生产代码不再持有 `[42; 32]` 任何形式的引用。

## C10.D 续 — Round 22 / KeyStore trait + covered_frontier banner + capability constraints (2026-05-09 二十二轮)

- `[x]` **`KeyStore` trait + `InMemoryKeyStore` + platform stubs** (Task 1): 新模块 `src/key_store.rs` (`pub mod key_store` in `lib.rs`) 含 `KeyStore` trait (4 methods: `load_identity` / `save_identity` / `primary_identity` / `load_local_identity`) + `InMemoryKeyStore` (wraps `Arc<Mutex<LocalStateStore>>`, 复用既有 `state.json` 持久化路径) + 三个平台占位 (`MacOsKeychainKeyStore` / `LinuxSecretServiceKeyStore` / `WindowsCredentialKeyStore`，目前都 return `KeyStoreError::Unsupported`)。`KeyStoreError` 自带 `Display` + `std::error::Error` (无新增依赖)。`LocalStateStore::set_local_identity_record(Option<...>)` 公开访问器让 `KeyStore` impl 在不触发 `ensure_local_identity` 重新生成的前提下覆写 record。新 6 unit tests in `key_store::tests` (round_trip / save_override / 3 platform stubs / dyn-dispatch)。
  - **SDK gap**: contrix-rust-sdk Round 22 计划落地的 `KeyStore` trait + `InMemoryKeyStore` + macOS/Linux/Windows 实现尚未合入；SDK 现仅有 `PlatformKeyStoreDescriptor` / `PlatformKeyStoreKind`（descriptor 类型，无 trait）。等 SDK trait 合入后这里的 trait 会缩成 thin re-export，三个平台 stub 删除。
  - **Hard scope rule**: 跨仓未变更，任何 SDK 改动留给并行 agent。
- `[x]` **`LocalAnchorView::from_sync_body` 测试覆盖** (Task 2): 既有解析路径已涵盖 `frontier` / `leaves` / `state_root` / `cells.*.bottom` / `cells.cx.component.mls.epoch.v1` / `cells.cx.component.governance.covered_frontier.v1` 6 个字段；Round 22 增 `covered_frontier_lag: Option<u64>` 字段（顶层 `anchor_view.covered_frontier_lag` 整数）+ helper `LocalAnchorView::covered_frontier_lag_above(threshold)`。新 2 unit tests in `local_state::tests` (`anchor_view_from_sync_body_extracts_covered_frontier_lag` / `anchor_view_lag_above_returns_false_when_lag_unknown`)；现有 wire-shape tests 保留。
- `[x]` **covered_frontier 客户端告警 banner** (Task 3): `space_admin` 顶部新增 `covered-frontier-threshold-row` (含 `covered-frontier-threshold-input` numeric input 默认 5, `covered-frontier-lag-value` 显示当前值) + 当 `LocalAnchorView::covered_frontier_lag_above(threshold)` 为 true 时渲染红 badge `covered-frontier-alert-banner` (`covered-frontier-alert-message` 复用 sodmin 文案，提示走 sodmin 端 `Manually advance` 入口)。`DEFAULT_COVERED_FRONTIER_LAG_THRESHOLD = 5` 与 sodmin 同源；threshold 由 user signal 持有 (per-render override)。
- `[x]` **Capability constraint editor UI** (Task 4): `move_builder::CapabilityConstraintInput` 新 enum (`Temporal { not_before, not_after }` + `Other(Value)`) + `to_constraint_value()` 渲染 `{constraint_type, subtype: "temporal.window", not_before?, not_after?}` 标准 shape；新 `build_capability_grant_move_with_constraints(...)` 接受 `&[CapabilityConstraintInput]`，把 effective constraint 折进 OrSet add op 的 `value.constraints` 数组（这样 SDK `LatticeOp.value: Option<Value>` 可 round-trip，避免被 typed parse 丢字段）。`build_capability_grant_move` 改为 thin wrapper（pass `&[]`），canonical bytes 与 round 21 完全一致（pinned by `capability_grant_without_constraints_matches_legacy_shape` test）。`space_admin` 渲染 `cap-constraint-editor` 区块：`cap-constraint-kind-select` (none/temporal/quota/scope_limitation) + 当 kind=temporal 时显示 `cap-constraint-not-before-input` / `cap-constraint-not-after-input` (`type=datetime-local`)；quota / scope_limitation 显示 `cap-constraint-coming-soon` 占位文案。Grant 按钮的 onclick 改走新 `build_signed_capability_grant_with_constraints(...)`；旧 `build_signed_capability_grant` 保留为 `#[cfg(test)]` 帮助。新 4 move_builder tests + 2 space_admin tests。
- `[—]` **C19 / C20 / C21 sweep last pass** (Task 5): 全仓 grep `actor_type|content_block.type|space_writer|host_transfer|writer_model` source 命中 0 条；`design/*.html`、`tests/fixtures/*`、`tests/e2e/mockContrixApi.ts`、`tests/serverx_contract.rs` 均无 ULID-shape / legacy 字段。十八轮 / 二十轮 / 二十一轮已扫净，本轮无操作。
- 测试计数: 230 → **244** (+14: 6 key_store + 2 anchor_view 新 lag fields + 4 move_builder constraint + 2 space_admin constraint)；`cargo test --lib` 244/244 pass。
