# yougen TODO

> 整理日期: 2026-05-07
> 范围: Contrix 跨平台客户端。当前重点是从协议展示/脚手架切到真实服务链路。

## 当前状态摘要

- event kind surface 已对齐 `contrix-spec` 110 active kinds（新增 `cx.profile.create`），并落地 `tests/fixtures/event-kind-registry.snapshot.txt` + `event-kind-wire-scopes.snapshot.tsv` 的 hermetic diff 测试 + `scripts/sync-event-kind-registry.ps1` 同步脚本；spec 漂移由 conformance 测试触发 tripwire。
- UI 层已经大量暴露 flow / recovery / device / audit / policy 概念；recovery/restore scaffold surface 已被 cotest release gate 覆盖；push placeholder 现已被 `tests/dev_token_guard.rs` + `push::ensure_production_register_request()` 锁住，不会无声 ship；OIDC、recovery durable state、device verification 仍有 scaffold 路径。
- 客户端主线目标: `coauth -> soland session grant -> chime/floria push -> soland recovery/device` 不再依赖手写 preview payload。当前 session-grant API 已能携带 soland introspection proof；本地 JWS proof 生成和真实 token 生命周期仍未完成。

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
| A3 ⚠ | `[ ]` | push register 替换 dev token / 手写 body | `src/push.rs`、`src/views/login.rs` | `chime::ContrixPushClient`、OS/WebPush real token、`floria` bridge describe。 |
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
| F3 🅿 | `[x]` | Presence / typing ephemeral runtime | `src/views/chat.rs` | 展示不写 durable history，和 sync runtime 区分。chat banner 现在从 `conformance::ephemeral_event_kinds()` 派生，typed `EventKindWireScope` 由 wire-scope 快照测试守住。 |
| F4 🅿 | `[x]` | Call signaling runtime | `src/views/call.rs` | `cx.call.signal/state` ephemeral；`recording.start` capability-gated durable。call banner 改用 `event_kind_wire_scope()` 渲染 scope 标签；同时纠正了 `cx.call.state` 在 wire 上其实是 durable 的旧错。 |
| F5 🅿 | `[x]` | profile/event coverage diff 自动化 | tests / scripts | 跟随 `contrix-spec` artifact count 变化，避免再出现覆盖数字过期。`tests/fixtures/event-kind-registry.snapshot.txt` + `event-kind-wire-scopes.snapshot.tsv` + `scripts/sync-event-kind-registry.ps1`；conformance 里跑 hermetic diff 测试。 |

## P3 · 测试 / 发布质量

| # | 状态 | 任务 | 文件 | 说明 |
|---|---|---|---|---|
| Q1 🅿 | `[ ]` | e2e 覆盖 OIDC -> session grant -> push register | `tests/e2e/*` | 先走 compose harness。 |
| Q2 🅿 | `[ ]` | recovery happy path e2e | `tests/e2e/*` | 依赖 soland/coauth durable recovery。 |
| Q3 🅿 | `[x]` | privacy/dev-token regression tests | `tests/*` | production build 不得发送 placeholder push token / dev-proof。`push::is_placeholder_push_key` + `ensure_production_register_request` + `tests/dev_token_guard.rs` 五项断言锁住 placeholder 不会无声 ship；登录链路接入仍归 A3。 |

## 跨项目登记

| 根任务 | 本仓责任 |
|---|---|
| C3 | 已具备携带 introspection proof 的 API surface；剩余 JWS proof 生成、session store 和 UI 流程替换。 |
| C4 | 用 chime/floria 做真实 push register 和 token rotation。 |
| C5 | recovery/key-backup/device verification UI 已有 scaffold API 调用面，cotest release gate 覆盖 soland restore surface；剩余是接 durable API 和真实 device verification。 |
| C6 | 当 soland 暴露 optional StarID resolver profile 时，客户端需要展示 resolver/profile 状态但不把 `did:webvh` 当 v1 core 必选。 |
| C8 | 给 cotest/example-stack 提供 headless happy path。 |

## 已完成（短 changelog）

- `[x]` T80-T92 的协议 surface 展示已经完成；原列表不再作为开放任务保留。
- `[x]` Onboarding 路由拆分、chat 词汇对齐 `flow(kind=room)`、最后一批 event kind surface 已完成。
- `[x]` 旧 card/room-first 视图已基本迁到 flow-first 信息架构；真实数据面仍由 P0/P1/P2 跟进。
- `[x]` 2026-05-07 — F5 / Q3 / F3 / F4：补 `cx.profile.create` 至 110 kinds、新增 wire-scope typed classifier 与两份 hermetic snapshot 测试、PowerShell 同步脚本；push placeholder 守卫 + 5 条 regression test；chat / call banner 切到从 `conformance` 派生 scope 标签。
