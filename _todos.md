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

## P0 · v1 wire model rework 客户端适配 ⚠

> 起源：`contrix-spec` 2026-05-07 完成 Phase 1-5。详见根 [`../_todos.md` C10.D](../_todos.md)。
>
> Gate：依赖 contrix-rust-sdk W1-W13 升级（typed model）。本仓 client 端不要先于 SDK 在 raw JSON 上做 wire 改动。

| # | 状态 | 任务 | 文件 | 依赖 |
|---|---|---|---|---|
| W1 ⚠ | `[ ]` | event surface diff 同步：active event kinds **110 → 129**（17 个 per-facet `cx.space.<facet>` + `cx.space.host` + `cx.space.host.transfer` + `cx.consent.grant` + `cx.consent.revoke`）；`src/conformance.rs` 的 hermetic diff 测试与同步脚本更新。 | `src/conformance.rs`、`src/views/space_admin.rs` (现有 1 处 stale state_key 引用)、`src/views/mod.rs` | SDK W12（major bump） |
| W2 ⚠ | `[ ]` | 移除 client wire 中的 `state_key` 字段 / 旧聚合 kind 引用；跟随 SDK 升级一次性切换。 | `src/api.rs`、`src/sync.rs`、`src/views/space_admin.rs` | SDK W1-W4 |
| W3 ⚠ | `[ ]` | **hub Space 写入路径**：`src/api.rs` 检测目标 Space 的 `space_writer_model`，hub Space 提交事件改走 `cx.space.host.payload.host_endpoint`（host endpoint 来自 `Space.space_host` DID Document service entry）。peer_mesh Space 保持当前直发 Principal Server 路径。 | `src/api.rs`、`src/sync.rs` | SDK W7-W8 |
| W4 ⚠ | `[ ]` | **host_endorsement 接收侧验证**：`src/sync.rs` 收到 hub Space state event 后调 SDK helper `verify_host_endorsement`；缺失 endorsement 或 host_did 不匹配 → 标记 `proof_missing` / `host_mismatch` 不进入本地 state。 | `src/sync.rs` | SDK W6 |
| W5 ⚠ | `[ ]` | **`pending_mls_binding` UI 信号**：E2EE Space 中"已 accepted 但 MLS 未 covered"过渡状态展示。例如 ban 已生效但密钥未轮换时 UI 提示"权限变更生效中…"。同时区分 `decryption_pending`（消息待密钥）与 `pending_mls_binding`（状态待绑定）。 | `src/views/chat.rs`、`src/views/space_admin.rs` | SDK W10 |
| W6 ⚠ | `[ ]` | **Consent UI 完整面板**：(a) 邀请前置 gate——陌生人 invite 进 quarantine inbox，UI 提示 "X 想邀请你进 Y，是否同意？" 接受 → 写 `cx.consent.grant`；(b) 已授予 consent 列表 + scope 显示 + 撤销按钮（`cx.consent.revoke`）；(c) MIMI consent 互译走 SDK，不要自定义形态。 | 新 `src/views/consent.rs`、`src/views/inbox.rs`、`src/api.rs` | SDK W5 |
| W7 | host transfer 监控 UI（仅 admin 角色看见）：smooth transfer 触发后等 dual-sign / emergency transfer quorum 收集进度。普通用户视角不需要这些。 | 新 `src/views/space_admin/host_transfer.rs` | SDK W7 |

---

## P0 · 真实登录 / session / push 主链路

| # | 状态 | 任务 | 文件 | 依赖 |
|---|---|---|---|---|
| A1 ⚠ | `[ ]` | OIDC browser flow 去 scaffold | `src/coauth.rs`、`src/views/login.rs` | `coauth` 持久化 state/nonce/PKCE、真实 code exchange。 |
| A2 ⚠ | `[~]` | session-grant exchange 真实化 | `src/coauth.rs`、`src/api.rs`、auth/session store | 已能接收 coauth grant id 并向 soland exchange API 携带可选 introspection proof；剩余：根据 grant id / challenge 生成 session-key JWS proof、持久化 token 生命周期、去掉 dev-token fallback。 |
| A3 ⚠ | `[~]` | push register 替换 dev token / 手写 body | `src/push.rs`、`src/api.rs`、`src/views/login.rs` | 已落地：`PushTokenSource` trait + `DevPlaceholderTokenSource` 默认实现 + 注入点；register/unregister 端到端走 `chime::ContrixPushClient::{register,unregister}_device_with_request`，bridge-discovered path 由 `with_register_device_path` 注入。剩余：真实 OS / Web Push token 接入。 |
| A4 🔒 | `[ ]` | 主会话 token 生命周期 | auth store / app shell | 提前 refresh、logout 清理、跨窗口状态同步，和 sodmin/coauth 安全策略对齐。 |

## P1 · Recovery / Device / Crypto

| # | 状态 | 任务 | 文件 | 依赖 |
|---|---|---|---|---|
| R1 ⚠ | `[~]` | key-backup UI 从 scaffold 切 durable API | `src/views/settings.rs` | `soland` key-backup durable store；SDK restore-ticket client。 |
| R2 ⚠ | `[~]` | restore-ticket lifecycle 接真实状态机 | `src/views/settings.rs` | `soland` RecoveryTicket / RestoreExecutor；`coauth` principal cache。 |
| R3 ⚠ | `[ ]` | device verification 写入 device_messages | `src/views/devices.rs`、`src/views/verify_device.rs` | `soland /api/v1/device_messages/*` + SDK helper。 |
| R4 ⚠ | `[ ]` | device revoke -> MLS Remove + Epoch++ | `src/views/devices.rs`、MLS state | `soland` reducer A13/A15；SDK MLS helper。 |
| R5 ⚠ | `[ ]` | browser encryption production boundary | `src/app.rs`、crypto storage | 现在提示 WebCrypto/IndexedDB MLS state 是 development-only；需要真实 secure backup/recovery 后放开。 |

## P2 · Flow-first 产品面

| # | 状态 | 任务 | 文件 | 说明 |
|---|---|---|---|---|
| F1 ⚠ | `[ ]` | Kanban 协议化 | `src/views/kanban.rs` | 替换 seed columns 为 API-derived flow/view projection。 |
| F2 ⚠ | `[ ]` | Chat/message canonical 切换 | `src/views/chat.rs`、message builder | 从展示 `flow(kind=room)` 词汇推进到真实 message canonical write/read。 |

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
| C10.D | **客户端适配 spec Phase 1-5 wire 改动**——P0 W1-W7 是本仓全部 C10 任务。需要 SDK W1-W13 先就位；之后 P0 主链路（A1-A4）可与 W3/W4/W6 并行。 |

## 已完成（changelog）

- `[x]` T80-T92 的协议 surface 展示。
- `[x]` Onboarding 路由拆分、chat 词汇对齐 `flow(kind=room)`、最后一批 event kind surface。
- `[x]` 旧 card/room-first 视图已基本迁到 flow-first 信息架构。
- `[x]` F3 Presence / typing ephemeral runtime。
- `[x]` F4 Call signaling runtime。
- `[x]` F5 profile/event coverage diff 自动化（snapshot 测试 + 同步脚本）。
- `[x]` Q3 privacy/dev-token regression tests（`push::is_placeholder_push_key` + `ensure_production_register_request` + `tests/dev_token_guard.rs`）。
