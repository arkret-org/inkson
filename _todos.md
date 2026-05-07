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

## 已完成（changelog）

- `[x]` T80-T92 的协议 surface 展示。
- `[x]` Onboarding 路由拆分、chat 词汇对齐 `flow(kind=room)`、最后一批 event kind surface。
- `[x]` 旧 card/room-first 视图已基本迁到 flow-first 信息架构。
- `[x]` F3 Presence / typing ephemeral runtime。
- `[x]` F4 Call signaling runtime。
- `[x]` F5 profile/event coverage diff 自动化（snapshot 测试 + 同步脚本）。
- `[x]` Q3 privacy/dev-token regression tests（`push::is_placeholder_push_key` + `ensure_production_register_request` + `tests/dev_token_guard.rs`）。
