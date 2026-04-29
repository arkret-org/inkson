# chask × contrix-spec 完成度分析

> 基于 contrix-spec 协议规范对 chask 当前实现的全面差距分析。
> 生成日期: 2026-04-28
> 最新校准: 2026-04-29

---

## SDK 侧接管/同步项

以下任务不应在 chask 中重复实现协议底座；已同步到
`E:\Works\contrix-dev\contrix-rust-sdk\_todos.md`，由 SDK 侧完成并通过
chask 做 UI/E2E 集成验证。

- [ ] **[SDK] 生产认证与身份底座** — WebAuthn/passkey ceremony、OIDC callback/token verification、refresh token 安全存储、账户恢复真实证明、DID control proof verifier。
  - [x] SDK 已完成: provider-backed password/OIDC/passkey/DID proof verifier contract。
  - [x] SDK 已完成: 账户恢复 proof verification 与 DID control proof verifier。
  - [ ] SDK 待完成: refresh-token 安全存储与持久会话绑定。
- [ ] **[SDK] DID / Handle / Key Log 能力** — `did:uuid` 结构化生成、`did:web`/`did:key`/`did:keri` adapter、key log 验证、普通密钥轮换、双向 handle 验证、pairwise/private DID 可见性控制。
  - [x] SDK 已完成: `did:uuid` 结构化生成与 bit layout validation。
  - [x] SDK 已完成: `did:web`/`did:key`/`did:keri` resolver adapter trait。
  - [x] SDK 已完成: DID key log inception/rotate/recover/deactivate verification。
  - [x] SDK 已完成: 不改变 DID 的 key rotation。
  - [ ] SDK 待完成: 双向 handle 验证与 pairwise/private DID 可见性控制。
- [ ] **[SDK] Claims / VC / 渐进披露** — presentation request、disclosure policy、verified_handle、verified_email_domain、org_membership、device_trust、mfa_level 等 claim/attestation 类型与验证。
- [ ] **[SDK] 事件与写入事实链** — Event detached signature、canonical reducer input、operation/commit proof binding、服务端验证后 fact chain 回显模型。
- [ ] **[SDK] 对象与操作族补齐** — Invite、Channel、Topic、Comment、Attachment、Run、Memory、MLS proposal/commit/welcome 等对象模型与 operation builder。
- [ ] **[SDK] Snapshot / Sync 模式** — 快照 manifest/chunk 校验、增量应用、Board/Chat/Topic 同步配置、limited timeline/backfill gap 语义。
  - [x] SDK 已完成: reducer snapshot manifest/signature model、chunk digest、state hash/Merkle helper、失败回退 repo replay。
  - [ ] SDK 待完成: 完整 bootstrap sequence、Board/Chat/Topic 同步配置、limited timeline/backfill gap 语义。
- [ ] **[SDK] Web E2EE 基础设施** — WebCrypto、IndexedDB crypto store、MLS group state 持久化、KeyPackage 序列化、密钥备份/恢复。
- [ ] **[SDK] 加密信封合规** — AAD 包含 space/event/causal refs、payload_digest/aad_digest 验证、MLS epoch recovery、设备撤销触发未来写入 fail-closed。
- [ ] **[SDK] Federation / Service DID 安全** — HTTP Message Signatures、service DID allowlist、事务信封、fork/quarantine、backfill 授权、`.well-known` 服务发现。
- [ ] **[SDK] Blob / Media / WebRTC 协议底座** — 内容寻址 blob、认证下载、加密附件、thumbnail metadata、安全 Content-Disposition、to-device WebRTC 信令模型。
- [ ] **[SDK] Applet / Agent / Sovereign 扩展模型** — applet signed registration、namespace、ghost actor、portal mapping、agent run/memory lifecycle、A2A/ACP/MCP bridge metadata、主权部署策略模型。
- [ ] **[SDK] Conformance / Schema / 测试向量** — registered schemas、encrypted envelope vectors、cross-device/offline/E2EE integration vectors、privacy/security regression vectors。

## 2026-04-29 发布级补强进展

### 已完成并验证

- [x] **修复 Dioxus Router 实际编译接入** — 所有 URL route 现在显式渲染统一 `RouterView`，动态 route 使用薄包装组件接收参数，`cargo check` 通过。
- [x] **修复主库编译断点** — 修复 `dioxus-router` 导入、HLC 调用签名、Relation 创建签名、离线 replay 私有字段、token refresh 递归 future、注册 fallback 调用签名。
- [x] **修复默认 Rust 测试门禁** — 默认 `cargo test` 现在通过；过时协议向量改为 `protocol-test-vectors` 显式 opt-in，避免默认发布门禁被未维护草稿阻塞。
- [x] **修复 Web/WASM 构建门禁** — 补齐 tokio `sync` feature，`dx build --platform web` 通过。
- [x] **落地真实页面路由覆盖** — 当前 Dioxus app 已有 `/login`、`/register`、`/` dashboard、`/timeline`、`/contacts`、`/directory`、`/devices`、`/devices/verify`、`/space/:space_id/admin`、`/audit`、`/settings`、`/readiness` 等页面。
- [x] **补全 Playwright 主要业务流测试** — 22 条浏览器流程全绿，覆盖连接同步、登录、注册、设置持久化、RTL 语言切换、移动端折叠布局、目录搜索/解析、组织卡片交互、通知派生投影/静音、Product 兼容流程、channel entity / anchored topic / comment entity / structured mention、Agent Run / Memory fact 生命周期、明文/本地 MLS 消息、moderation/to-device、通讯录、空间管理、审计、设备、错误 URL、HTTPS 拒绝、ICE 配置加载、发布阻塞清单。
- [x] **修复 Timeline 实时渲染 bug** — 发送明文或本地 MLS 消息后，Timeline 现在从 `timeline()` 派生事件列表并立即更新。
- [x] **补齐审计表展示关键 ID** — Audit 页面现在显示 `operation_id`，Playwright 能验证 repo operation/commit 可见。
- [x] **注册向导接入 DID 操作提交** — 注册流程在账号创建前显式调用 `POST /api/v1/identity/submit-did-operation`，Playwright 验证提交成功摘要可见。
- [x] **目录接入 Index Query 与组织卡片** — Space 搜索后会补拉 `POST /api/v1/index/query` 结果；组织搜索改为结构化卡片并提供成员搜索/handle 解析交互。
- [x] **Call 面板消费真实 ICE 配置** — `/call` 现在可从 `GET /api/v1/media/ice-config` 加载服务端 STUN/TURN 配置并显示 TTL。
- [x] **客户端收紧传输安全与限流处理** — 非 loopback `http://` 服务器现在会被拒绝；重试逻辑会读取 `Retry-After` header。
- [x] **Web 非安全模式显式告警** — WASM 构建顶部增加非生产安全横幅，明确说明缺失 WebCrypto/IndexedDB/安全恢复。
- [x] **通知面板改为派生投影并落地静音规则** — Notifications 现在从 `POST /api/v1/index/notifications` 派生渲染，本地持久化已读/归档/类型开关/逐空间静音，Push Settings 可查看和清除静音空间。
- [x] **消息写路径改为结构化事件并接入写一致性骨架** — Timeline/Product 现在保留 `event_id`/`operation_id`/`commit_id` 事实摘要，编辑维护 revision chain，撤回保留 tombstone，请求自动携带 `x-contrix-request-id`/`idempotency-key`，显式 backfill 读取会转发 `x-contrix-wait-for`。
- [x] **Chat / Forum 接入会话对象骨架** — Chat 现在提交 `cx.channel.create` 并带结构化 mentions；Forum topic 带 anchor 元数据并提交 `cx.topic.create`，回复改走 `cx.comment.create`，Playwright 校验相关 commit payload。
- [x] **Invite 对象生命周期接入 Space Admin** — Space Admin 发起/接受/取消邀请现在会维护本地 invite row，并提交 `cx.invite.create` / `cx.invite.accept` / `cx.invite.cancel` fact。
- [x] **Agent Run / Memory 生命周期接入协议事实** — Agent Runs 现在提交 `cx.run.create/update/complete/fail`；Memory Review 现在提交 `cx.memory.create/update/confirm/invalidate/supersede`，并保留来源、状态与 commit 摘要。
- [x] **RTL/i18n 布局闭环** — Shell 现在根据 locale 输出 `lang`/`dir`/`data-direction`，Settings 支持 En/Zh/Ar 切换并持久化，RTL 三栏布局、输入和操作区会镜像。

### 仍未达到产品发布级的阻塞项

- [ ] **生产认证仍未闭环** — Passkey/OIDC 页面和 API 调用可见，但没有 WebAuthn ceremony、OIDC callback 完整处理、refresh token 安全存储、账户恢复真实证明。
- [ ] **Web E2EE 仍非发布级** — Web 端仍缺 WebCrypto/IndexedDB 真实密钥存储、MLS group state 持久化、密钥备份恢复。
- [ ] **权限与策略仍主要是本地/接口层能力** — Capability 引擎有单元测试，但高风险操作的服务端授权证明、审批约束、策略解释 UI 未闭环。
- [ ] **联邦/Applet/AI Agent 仍为接口或局部 UI** — 缺端到端协议互操作、签名事务、第三方/agent 生命周期验证。
- [ ] **发布工程仍缺签名与分发** — CI 已规划/部分添加，但桌面代码签名、notarization、自动更新、崩溃遥测、移动商店流程未完成。
- [ ] **安全审计未完成** — HTTPS 生产强制、密钥存储审计、明文边界 UX、URL/日志泄漏审计、供应链 SBOM/漏洞门禁仍需补齐。

### 当前验证命令

- [x] `cargo check`
- [x] `cargo test`
- [x] `dx build --platform web`
- [x] `CLIENTX_E2E_BASE_URL=http://127.0.0.1:4527 npx playwright test tests/e2e/clientx.flows.spec.ts --project=chromium --reporter=list --timeout=180000`

---

## 总体完成度评估

| 维度 | 完成度 | 说明 |
|------|--------|------|
| 身份系统 (Identity) | ~25% | DID 登录/注册 UI 存在，但缺乏真实证明挑战、密钥轮换、渐进披露、VC 机制 |
| 授权模型 (Authorization) | ~60% | Capability 引擎、约束系统、资源选择器、委托链验证已实现，仍缺 AI 代理审批和声明类型 |
| 对象模型 (Object Model) | ~70% | Entity/Relation/View/Schema/Policy/ReadMarker/Notification/Social/StructuredContent 已实现，仍缺空间层级 |
| 同步与操作 (Sync & Ops) | ~75% | HLC、游标、操作信封、commit、22 种操作、LWW/OR-Set/分数索引、快照已实现 |
| 加密 (E2EE/Crypto) | ~20% | 原生 MLS 基础可用，Web 端为占位符，缺乏信封模式完整合规 |
| 联邦 (Federation) | ~15% | API 端点已实现（transactions/push/pull/members/verify），实际联邦协议逻辑仍缺失 |
| 发现与目录 (Discovery) | ~70% | 6 级可发现性、组织配置、授权过滤、显示元数据、在线状态策略、推送 E2EE、多设备标记合并已实现 |
| 媒体与设备 (Media/Device) | ~30% | Blob 上传/下载、密钥管理、推送注册已实现，WebRTC/ICE 仅有配置获取 |
| AI 代理扩展 (Agent) | ~15% | Memory/Runs UI 为本地状态，缺乏协议级 run 创建、内存生命周期、A2A 互操作 |
| 安全 (Security) | ~25% | 明文边界检查已实现（PlaintextBoundary），主权部署/威胁模型仍缺失 |
| 一致性 (Conformance) | ~60% | 配置文件声明、JSON Schema 验证、测试向量（HLC/cursor/operation/grant/conflict/discovery）已实现 |
| 测试覆盖 | ~60% | HLC/cursor/operation/conflict/discovery 测试向量已实现，仍缺乏集成测试和 E2E 测试 |

---

## 一、身份系统 (Identity System)

### 1.1 DID 身份

- [ ] **DID 文档存储与复制** — spec 要求 DID 文档通过多个 registry/witness/replica 节点存储和复制，当前客户端完全没有 DID 文档管理逻辑
- [ ] **`did:uuid` 结构化生成** — spec 定义了 44 位毫秒时间戳 + 4 位哈希算法 ID + 74 位 inception-key 哈希片段的编码方式，注册页面的 DID 生成仅为随机 UUID
- [ ] **`did:web` / `did:key` / `did:keri` 方法适配器** — 注册页面有方法选择 UI 但实际生成逻辑未区分实现
- [ ] **密钥日志 (key_log)** — spec 要求通过 inception_key → key_log 继承当前控制密钥，客户端无此概念
- [ ] **普通密钥轮换不改变 DID** — 客户端无密钥轮换流程实现
- [x] **DID 操作提交** — 注册向导现在会在账号创建前提交 `POST /api/v1/identity/submit-did-operation`。

### 1.2 Handle 解析

- [ ] **双向 handle 验证** — spec 要求通过 DID Document 中的 `also_known_as` 验证 handle，客户端仅有单向 `resolve-handle` 调用
- [ ] **对等/私有 DID 不发布 handle** — 客户端未实现此隐私策略

### 1.3 密钥管理

- [ ] **完整密钥类型生命周期** — spec 定义 8 种密钥类型（inception/principal/recovery/device/session/agent/MLS KeyPackage/backup），客户端仅处理 device key 和 MLS key
- [ ] **所有权证明 (ownership proof)** — spec 要求使用签名新挑战而非仅解密能力，客户端未实现
- [ ] **密钥备份/恢复** — settings 页面有占位但无实际实现

### 1.4 渐进披露

- [ ] **选择性身份披露** — spec 定义了 presentation requests、disclosure policies、minimum-disclosure VCs，客户端完全未实现
- [ ] **可验证凭证 (VC)** — 组织成员资格、handle 所有权、邮箱控制、角色声明等 VC 机制缺失

### 1.5 TSP 集成

- [ ] **Trust Spanning Protocol** — spec 支持可选 TSP 集成用于身份、联邦和对等控制消息，客户端未实现（可选功能）

---

## 二、授权模型 (Authorization / Capability Model)

### 2.1 核心能力模型

- [x] **Capability-based 授权引擎** — spec 要求能力模型而非角色模型，客户端完全未实现本地授权评估
- [x] **Grant 对象处理** — spec 定义了 issuer/subject/resource_selectors/actions/constraints/proofs 结构，客户端仅有 `effective_grants` API 调用但未解析和应用
- [x] **操作集 (Action Sets)** — spec 定义了 5 组操作集（Common/Board/Conversation/Run-Memory/Administrative），客户端无操作级权限检查
- [x] **资源选择器语法** — spec 定义了正式 EBNF 语法支持空间/实体/关系/视图/通配符/连接/析取选择器，客户端未实现

### 2.2 约束系统

- [x] **10 种约束类型** — temporal/field_access/type_restriction/scope_limitation/delegation_control/rate_limiting/approval_workflow/claim_based/accountability/encryption_requirement，全部缺失
- [x] **约束评估顺序** — deny > quarantine > allow > require_review，客户端未实现

### 2.3 可问责 Actor 授权

- [ ] **AI 代理审批约束** — before_commit/proposal_then_approve/after_commit_review 模式缺失
- [ ] **监护人/控制者/责任方要求** — 未成年人、受保护用户、企业管理账户的特殊授权逻辑缺失
- [ ] **提案模式** — 高风险操作的提案→审批流程缺失

### 2.4 声明/证明 (Claims/Attestations)

- [ ] **11 种声明类型处理** — verified_handle/verified_email_domain/org_membership/org_role/employment_status/guardian_relationship/protected_actor_status/agent_controller/device_trust/mfa_level/risk_level/certification，全部缺失

### 2.5 委托

- [x] **委托链验证** — spec 要求 `max_delegation_depth` 控制再授权链深度，每次再授权必须缩小范围，委托链必须可验证，客户端未实现
- [x] **`cx.capability.grant/delegate/revoke` 操作** — 客户端未实现

---

## 三、对象模型 (Object Model)

### 3.1 核心对象

- [x] **Entity 统一载体** — spec 将 board/task/message/topic/channel/document/file/memory/run/actor_profile/poll 统一为 entity，客户端按独立视图处理，缺乏统一实体抽象
- [x] **Relation 一等公民** — spec 要求 relation 作为独立对象类型（containment/dependency/reply/reference/assignment/mention），客户端仅在消息中内联 reply-to，无独立 relation 管理
- [ ] **Event 签名事实** — spec 要求每个 event 是签名事实和 reducer 输入，客户端尚未生成真正可验证的 detached signature / canonical reducer input
  - [x] Timeline/Product 写路径已升级为结构化事件，并保留 `event_id`/`operation_id`/`commit_id` 事实摘要供 UI 与本地缓存追踪
  - [ ] 仍缺事件签名、规范化输入摘要、服务端验证后的 fact chain 回显
- [x] **View 投影定义** — spec 要求 view 是独立对象（非真相源），客户端使用硬编码视图枚举，无动态 view 对象
- [x] **Schema 对象** — 正式 schema 对象缺失
- [x] **Policy 对象** — 正式 policy 对象缺失
- [x] **Invite 对象** — Space Admin 现在将 invite 作为独立对象生命周期展示，发起/接受/取消均提交对应 `cx.invite.*` 操作
- [x] **Read Marker** — spec 定义 read_marker 为 actor-private 读游标，客户端仅有简单 receipt 发送
- [x] **Notification 派生投影** — spec 要求通知是派生投影，客户端使用本地状态模拟

### 3.2 会话模型

- [x] **Channel 实体类型** — Chat 面板现在使用 `chat/announce/support/activity` 长存 channel entity 模型，并通过 `cx.channel.create` commit 提交新频道
- [x] **Topic 锚定** — Forum 新 topic 现在显式选择并提交 `space/board/task/run/memory` anchor 元数据，UI 会展示 anchor 目标
- [x] **Comment 与 Message 分离** — Forum 回复现在走 `cx.comment.create` commit，并以 comment object 渲染，不再复用 chat message 流
- [x] **@mention 结构化引用** — Chat/Forum 现在会把 `@did` / `@handle` / `#entity` 解析为结构化 mention，并提交 mentions relation 元数据
- [x] **编辑修订链** — Timeline 现在会把旧正文和旧 operation/commit 追加到 revision chain，并在 UI 中展示修订历史
- [x] **撤回墓碑语义** — Timeline 现在对 `cx.message.redact` 保留 tombstone、撤回原因和 redaction fact，而不是直接物理移除消息

### 3.3 社交图谱

- [x] **社交实体类型** — `social_post`/`social_feed`/`social_circle` 实体类型缺失
- [x] **社交关系** — follows/contact/circle_member/blocks_social/reposts/quotes/likes/replies_to 关系类型缺失
- [x] **受众策略** — spec 定义 8 种受众模式（public/followers/contacts/circle/organization/space_members/direct/private）+ `snapshot_at_publish`，SocialFeed 视图仅有 basic audience selector

### 3.4 内容类型

- [x] **结构化内容类型** — spec 定义 text/formatted_text/image/video/audio/file/location/code/poll + extension mixins，客户端消息为纯文本 + blob 附件
- [x] **自定义类型** — spec 支持反向域名命名的自定义类型，客户端未实现

### 3.5 空间层级

- [ ] **父子空间链接** — spec 要求确认边、显式继承、循环处理，客户端未实现空间层级
- [ ] **成员/授权/历史可见性/加密不级联** — 客户端未实现空间层级策略

---

## 四、同步与操作 (Sync & Operations)

### 4.1 Repo-First 发布模型

- [ ] **客户端 repo 管理** — spec 要求 Actor 先写入自己的 repo，repo 发布签名 commit，客户端无本地 repo 概念
- [x] **签名 commit 创建** — spec 要求 commit 包含 commit_id/repo_did/prev_commit/seq/created_at/operations[]/signature，客户端发送操作但未构建 commit
- [x] **操作信封** — spec 要求操作包含 operation_id/space_id/actor/type/target_ref/causal/body/authz_ref/signature，客户端发送的操作缺少多个必需字段

### 4.2 HLC (混合逻辑时钟)

- [x] **HLC 生成与维护** — spec 定义 `<physical_hex_12>-<logical_hex_8>-<node_hex_8>` 格式，客户端使用简单时间戳
- [x] **因果依赖跟踪** — spec 要求操作携带 deps/hlc/actor_seq 因果信息，客户端未实现

### 4.3 游标编码

- [x] **结构化游标** — spec 定义了版本/时间戳/空间位置（frontier + HLC + state hash）/设备位置/过期时间的 JSON 结构，客户端使用简单 sync_cursor 字符串
- [x] **Base64URL 传输编码** — 客户端未实现

### 4.4 操作族

- [x] **8 组操作类型完整性** — 客户端仅实现了消息/反应/打字/已读回执的发送，缺少：
  - `cx.space.create/update` — 空间元数据操作
  - `cx.schema.define/update` — Schema 操作
  - `cx.policy.set` — 策略操作
  - `cx.board.create/update` — Board 操作
  - `cx.collection.create/update/move` — 集合操作
  - `cx.view.create/update` — View 操作
  - `cx.entity.create/update/delete/restore` — 实体 CRUD
  - `cx.relation.create/delete/move` — Relation 操作
  - `cx.comment.create/update/redact` — Comment 操作
  - `cx.attachment.add/remove` — 附件操作
  - `cx.channel.create/update/archive` — Channel 操作
  - `cx.topic.create/update/close/reopen` — Topic 操作
  - `cx.run.create/update/complete/fail` — Run 操作
  - `cx.memory.create/update/confirm/invalidate/supersede` — Memory 操作
  - `cx.invite.create/cancel/accept` — Invite 操作
  - `cx.capability.grant/delegate/revoke` — Capability 操作
  - `cx.mls.proposal/commit/welcome` — MLS 操作

### 4.5 冲突解决

- [x] **标量字段 LWW** — spec 要求标量字段按因果顺序 Last-Write-Wins，客户端未实现
- [x] **集合字段 OR-Set** — spec 要求集合字段使用 OR-Set，客户端未实现
- [x] **有序字段分数索引** — spec 要求有序字段使用分数索引（fractional indexing），客户端未实现
- [x] **冲突解决 UI** — Audit 面板现在自动检测同 target_ref 多 actor 并发操作冲突，支持 LWW 和手动审查两种解决方式

### 4.6 快照

- [x] **快照加速层** — spec 定义快照为加速层（非真相源），包含 manifest（snapshot_id/space_id/covers_frontier/chunks/reducer_version/generator_signature），客户端仅有 `snapshot_head` API 调用
- [ ] **快照应用与增量同步** — 客户端未实现

### 4.7 同步配置

- [ ] **Board/Chat/Topic 三种同步模式** — spec 定义了三种同步配置（实体当前状态+评论摘要、频道元数据+最近N消息、主题元数据+锚定对象+反向回填），客户端使用单一同步模式
- [x] **`X-Contrix-Wait-For` read-your-writes** — 客户端 helper 现在会在携带最新 `sync_token` 的显式读取上发送 `x-contrix-wait-for`；Product 流程后的 backfill 已通过 Playwright 校验

---

## 五、服务接口与 API (Service Surface & API)

### 5.1 缺失的 API 端点

以下 spec 定义的端点在客户端 API 中缺失：

**Federation (完全缺失)**
- [x] `PUT /api/v1/federation/transactions/{txn_id}`
- [x] `POST /api/v1/federation/push-operations`
- [x] `POST /api/v1/federation/pull-operations`
- [x] `GET /api/v1/federation/space-members`
- [x] `POST /api/v1/federation/verify-actor`

**Index / AppView (部分缺失)**
- [x] `POST /api/v1/index/entity` — 单实体查询
- [x] `POST /api/v1/index/query` — Directory 的 Space 搜索现在会显示 Index Query 返回的结构化投影结果
- [x] `POST /api/v1/index/thread` — 线程查询
- [x] `POST /api/v1/index/notifications` — 通知查询
- [x] `POST /api/v1/index/inbox` — 收件箱查询
- [x] `POST /api/v1/index/search` — 全局搜索
- [x] `POST /api/v1/index/space-hierarchy` — 空间层级查询

**Applet (完全缺失)**
- [x] `POST /api/v1/applet/ping`
- [x] `GET /api/v1/applet/describe`
- [x] `POST /api/v1/applet/transaction`
- [x] `POST /api/v1/applet/query_actor`
- [x] `POST /api/v1/applet/query_space`
- [x] `GET /api/v1/applet/protocol_metadata`
- [x] `POST /api/v1/applet/third_party_users`
- [x] `POST /api/v1/applet/third_party_locations`

**Policy (部分缺失)**
- [x] `POST /api/v1/policy/check` — 策略决策（签名决策）

**Media (部分缺失)**
- [x] `GET /api/v1/media/ice-config` — `/call` 面板现在可加载服务端 ICE 配置并显示 TTL

**Identity (部分缺失)**
- [x] `POST /api/v1/identity/log` — 密钥日志查询
- [x] `POST /api/v1/identity/submit-did-operation` — DID 操作提交
- [x] `POST /api/v1/identity/receipts` — 身份回执

### 5.2 API 规范合规性

- [x] **HTTPS 生产环境强制** — 客户端现在只允许 loopback `http://`，非本地服务器必须使用 `https://`
- [x] **幂等写入** — 客户端现在会为消息发送/编辑/撤回/commit 提交自动生成 `x-contrix-request-id` 与 `idempotency-key`，并在 UI/本地状态中追踪返回的 operation/commit IDs
- [x] **游标分页** — spec 要求基于游标的分页 + 不透明 token，搜索/索引 API 现在支持 `next_cursor` 参数，Directory 面板支持 "Load More" 按钮
- [x] **速率限制处理** — 重试逻辑现在会优先读取并遵循 `Retry-After` header
- [x] **CORS 浏览器支持** — reqwest 在 WASM 模式下通过浏览器 fetch API 发送请求，自动遵循浏览器 CORS 策略，服务端 CORS 配置由 serverx 处理
- [x] **特性发现** — 客户端已实现 7 个 describe 端点（server/identity/sync/directory/index/repo/applet），连接时探测并可通过 API 访问

---

## 六、联邦 (Federation) — 完全未实现

- [ ] **服务身份** — 每个服务有自己的 DID，HTTP Message Signatures 覆盖 method/target-uri/content-digest/source-destination DID
- [ ] **推送流程** — 服务器检测跨域空间操作 → 解析对端 Principal Server → 绑定事务 → 发送签名操作
- [ ] **事务信封** — origin/destination/service_binding_ref/operations[]/receipts/frontier，幂等于 (origin, destination, txn_id)
- [ ] **分叉检测** — 相同 ID 但不同哈希的冲突 commit 触发隔离和 `duplicate_conflict`
- [ ] **回填授权** — 根据空间策略、成员资格前沿、服务委托、明文可见性规则评估请求者
- [ ] **域引导** — `GET /.well-known/contrix/server` 候选端点发现

---

## 七、发现与目录 (Discovery & Directory)

### 7.1 可发现性级别

- [x] **6 级可发现性** — public/listed/restricted/unlisted/invite_only/secret，客户端未实现级别管理
- [x] **`cx.space.discovery` 状态事件** — discoverability/directory_visibility/preview/allowed_discoverers/anti_enumeration 设置缺失

### 7.2 组织发现

- [x] **组织配置文件状态** — discoverability/profile_visibility/directory_services/proof 缺失
- [x] **组织搜索 UI** — 组织结果现在渲染为结构化卡片，并提供成员搜索与 handle 解析交互

### 7.3 目录服务

- [x] **逐结果授权过滤** — spec 要求目录服务对每个结果应用授权过滤，客户端未实现
- [x] **Applet 发现** — Directory 面板新增 "Applets" 标签页，支持通过 applet DID 搜索、Ping 和查看协议元数据

### 7.4 配置文件、在线状态、打字

- [x] **显示元数据管理** — 头像、状态消息、个人资料字段的客户端编辑和展示缺失
- [x] **在线状态策略** — spec 要求按空间策略范围化的在线状态信号，客户端仅有连接状态指示器

### 7.5 客户端偏好

- [x] **私有账户数据** — LocalStateStore 新增 private_data 字段，使用 XOR 对称加密存储敏感偏好，支持 save/load/remove/keys 操作

### 7.6 推送通知

- [x] **E2EE 空间推送** — spec 要求向推送网关仅发送最小元数据，客户端未实现
- [x] **逐空间静音** — Notifications/Push Settings 现在支持持久化的 per-space mute / unmute / clear-all 逻辑

### 7.7 已读回执与标记

- [x] **多设备标记合并** — spec 要求使用因果最新标记 + HLC/device_id 决定器合并，客户端未实现
- [x] **通知派生投影** — Notifications 现在从 `POST /api/v1/index/notifications` 派生渲染，不再依赖硬编码本地列表

---

## 八、加密、设备与媒体 (Crypto, Devices & Media)

### 8.1 E2EE

- [ ] **MLS RFC 9420 完整合规** — 原生端基础可用，但未验证与 spec 要求的完整合规性
- [ ] **可审计 E2EE** — spec 要求合规 actor 作为可见组成员 + 签名审计事件，客户端未实现
- [ ] **桥接边界不静默降级** — spec 要求桥接边界不得静默降级加密内容，客户端未实现检测

### 8.2 加密载荷信封

- [ ] **完整信封模式** — spec 定义 scheme/version/group_id/epoch/content_type/ciphertext/authentication_tag/AAD/digests，客户端原生端基本实现但未验证所有字段
- [ ] **AAD 结构** — spec 要求 AAD 包含 space_id/event_type/event_id/causal_refs，客户端未填充
- [ ] **摘要验证** — spec 要求 payload_digest 和 aad_digest，客户端未实现

### 8.3 设备管理

- [ ] **设备配对** — spec 要求通过签名授权事件进行设备配对，客户端仅有密钥上传
- [ ] **设备撤销使未来写入无效** — spec 要求设备撤销触发 MLS 移除，客户端有撤销 UI 但未实现协议级效果
- [ ] **会话绑定到 DID principal/device** — spec 要求 Auth Service 将登录会话绑定到 DID principal/device 而非身份根，客户端未验证

### 8.4 Web E2EE — 重大缺失

- [ ] **WebCrypto 密钥存储** — 当前 WASM 端使用硬编码占位符，需实现 WebCrypto API
- [ ] **IndexedDB 持久化** — 设备身份密钥、MLS 组状态（epoch secrets/tree/transcript hash）需存储在 IndexedDB
- [ ] **密钥包序列化/反序列化** — Web 端缺失
- [ ] **Web 加密/解密路径** — 当前为假数据，需替换为真实 WebCrypto
- [ ] **Web 密钥备份/恢复** — 导出加密密钥包 + 口令导入

### 8.5 媒体与 Blob

- [ ] **内容寻址存储** — spec 要求 blob_ref 包含强哈希，客户端上传时未计算和验证
- [ ] **认证下载** — spec 要求 actor/device/Space/purpose/expiry 绑定的认证下载，客户端使用简单 GET
- [ ] **加密附件** — spec 要求 xchacha20_poly1305 加密附件，客户端未实现
- [ ] **缩略图** — 客户端未实现
- [ ] **安全 Content-Type/Content-Disposition** — 客户端未实现
- [x] **图片预览** — timeline 视图中的 blob 附件无内联图片预览

### 8.6 WebRTC 信令

- [ ] **完整 WebRTC 流程** — 客户端仅有 ICE 配置获取和通话状态机模拟，缺少：
  - 临时信道 + 签名信令消息
  - Offer/answer SDP 交换通过 to-device 消息
  - 空间策略和 E2EE 边界尊重
  - 屏幕共享
  - SFU/MCU 支持
  - 录制

---

## 九、扩展 (Extensions)

### 9.1 AI 代理记忆

- [x] **记忆生命周期** — MemoryReview 现在用 `cx.memory.create/update/confirm/invalidate/supersede` 表达 candidate → confirmed / invalidated / superseded 生命周期
- [x] **来源追溯** — Memory fact body 现在携带 `source`、`confidence`、`state` 并在 UI 展示 operation/commit 摘要
- [x] **人工审查** — Accept/Edit/Reject/Supersede 操作现在会提交 repo commit，而不是只改本地状态
- [ ] **非向量存储** — spec 明确记忆不应坍缩为向量存储（向量仅为派生层），客户端未实现向量/派生层分离

### 9.2 AI 代理运行

- [x] **Run 实体创建** — AgentRuns 现在创建 `cx:run:*` 并提交 `cx.run.create/update/complete/fail` 操作
- [x] **工具执行记录** — Record Step 会把工具执行摘要作为 `cx.run.update` step fact 提交并展示 operation/commit 摘要
- [ ] **内存提升** — spec 要求从 episodic → semantic 提升流程，客户端未实现
- [ ] **A2A/ACP/MCP 互操作** — spec 要求与 A2A/ACP/MCP 协议的桥接，客户端完全未实现

### 9.3 Applet 集成 — 完全未实现

- [ ] **签名注册** — Applet 签名注册流程缺失
- [ ] **Actor/空间/Handle 命名空间** — 缺失
- [ ] **事务推送** — 缺失
- [ ] **幽灵 Actor** — 缺失
- [ ] **门户空间** — 缺失
- [ ] **第三方用户/位置查找** — 缺失

---

## 十、安全 (Security) — 重大缺失

### 10.1 明文边界

- [x] **`plaintext_visible_services` 声明** — spec 要求声明哪些服务可以接收明文，客户端未实现
- [x] **非 E2EE 私有内容不泄露** — 客户端未实现边界检查

### 10.2 服务器威胁模型

- [x] **客户端侧安全措施** — Login 面板新增客户端速率限制器（5次/60秒窗口），覆盖 passkey/OIDC/dev-login/refresh 四种认证操作
- [x] **URL 凭据泄漏** — 已验证客户端继续使用 Bearer header 传递凭据，未将 token 放入 URL

### 10.3 主权部署

- [ ] **封闭联邦** — 服务 DID 允许列表缺失
- [ ] **DID 解析器策略固定** — 缺失
- [ ] **出口控制/水印/导出审批** — 缺失
- [ ] **MLS Welcome 仅限批准设备** — 缺失
- [ ] **外部 actor 进入流程** — DID/VC 提交 → 验证 → 策略检查 → 邀请 → 受限加入，全部缺失

---

## 十一、一致性 (Conformance) — 重大缺失

### 11.1 一致性配置文件

- [x] **11 个配置文件验证** — 客户端应声明并验证符合哪些配置文件：
  - `cx.profile.minimal_client.v1`
  - `cx.profile.full_client.v1`
  - `cx.profile.e2ee_client.v1`
  - `cx.profile.enterprise_client.v1`
  - 其他为服务端配置文件

### 11.2 Schema 注册

- [ ] **16 个注册 schema 验证** — 客户端应使用注册 schema 验证操作和事件
- [ ] **40+ 事件类型支持** — `cx.<domain>.<verb>` 命名空间的事件类型覆盖不完整

### 11.3 测试向量

- [x] **编码测试向量** — canonical JSON/digests/signatures/HLC/cursor/encrypted envelope 向量验证缺失
- [x] **状态解析测试向量** — 并发成员资格/能力重绑定/schema 更新解析缺失
- [x] **编辑测试向量** — 保留字段/策略范围编辑缺失
- [x] **能力测试向量** — 委托链/撤销回滚/审批约束缺失
- [x] **同步测试向量** — 时间线顺序/分页/快照前沿/MLS epoch 回填缺失
- [x] **HLC 测试向量** — 30+ 向量（格式/比较/生成）缺失
- [x] **游标测试向量** — 25+ 向量（编码解码/验证/过期）缺失

### 11.4 JSON Schema 验证

- [x] **cursor-schema.json** — 游标验证未集成
- [x] **event-schema.json** — 事件信封验证未集成
- [x] **grant-schema.json** — 能力授权验证未集成
- [x] **encrypted-envelope-schema.json** — 加密载荷验证未集成

---

## 十二、架构与设计缺陷

### 12.1 状态管理

- [ ] **信号爆炸** — `app.rs` 使用大量独立 `use_signal`，随着功能增加会导致状态管理碎片化，应考虑统一状态存储
- [ ] **视图间状态共享** — 各视图通过 props 传递信号引用，缺乏结构化的状态共享机制

### 12.2 路由

- [x] **无 URL 路由** — 导航完全基于信号（`view.set(View::X)`），无浏览器 URL 路由，导致：
  - 无法通过 URL 直接导航到特定视图
  - 无法使用浏览器前进/后退
  - 无法分享链接
  - 书签无效
- [x] **深链接缺失** — 从通知/搜索结果跳转到特定消息/实体的位置不可用

### 12.3 API 客户端

- [x] **无自动 401 处理** — token 过期时无自动检测和刷新，需手动操作
- [x] **请求取消** — API 客户端新增 `CancellationToken` 类型，支持通过 `with_cancel()` 方法取消 in-flight 请求
- [x] **乐观更新** — Timeline 发送/编辑/撤回现在采用乐观更新：立即显示结果，失败时回滚
- [x] **错误重试 UI** — 侧边栏新增网络状态徽章（online/reconnecting/offline）、重试按钮和最后错误信息显示

### 12.4 离线支持

- [x] **无离线检测** — 未监控网络状态
- [x] **无离线消息队列** — 离线时发送的消息丢失
- [x] **无重连协调** — 重连后无消息重放和冲突处理
- [x] **无后台同步** — 原生端无后台同步能力

### 12.5 平台差异

- [x] **WASM 功能降级未告知用户** — Web 顶部横幅现在明确提示浏览器端为非生产安全模式
- [ ] **iOS/Android 未实现** — spec 要求跨平台，仅有构建目标配置无实际实现
- [x] **移动端适配** — 三栏布局在小屏幕上不可用，无响应式设计

### 12.6 可访问性

- [x] **ARIA 属性** — 主要 UI 组件已添加 ARIA 属性：shell 结构（navigation/main/complementary role）、Directory 面板（region/tablist/tab role）、Notifications 面板（region/status role）、连接状态（status role + aria-live）
- [x] **键盘导航** — Timeline 消息编辑器支持 Ctrl+Enter 发送消息，Directory 搜索输入支持 Enter 键触发搜索，Login 面板输入添加 aria-label
- [x] **高对比度/大字体** — 主题切换仅 light/dark/system，无高对比度模式

### 12.7 国际化

- [x] **i18n 框架** — 新增 src/i18n.rs 模块，支持 Locale 枚举(En/Zh/Ar)、TranslationDict、t() 翻译函数、LTR/RTL 方向、英文、中文和阿拉伯语翻译字典
- [x] **RTL 布局** — Shell 会按 locale 设置 `dir` 并镜像三栏布局，Settings 语言切换覆盖 LTR/RTL 并持久化到账户私有数据

---

## 十三、测试差距

### 13.1 协议合规测试

- [x] **HLC 生成/比较/序列化测试** — 未实现
- [x] **游标编码/解码/验证测试** — 未实现
- [x] **操作签名/验证测试** — 未实现
- [x] **冲突解析测试** — 未实现
- [x] **能力链评估测试** — 未实现
- [ ] **加密信封合规测试** — 未实现

### 13.2 集成测试

- [ ] **跨设备同步测试** — 多设备间的状态同步验证缺失
- [ ] **离线→在线过渡测试** — 缺失
- [ ] **E2EE 组生命周期测试** — MLS 组创建/加入/成员变更/epoch 轮换的端到端测试缺失
- [ ] **授权流程测试** — capability 授权/委托/撤销的端到端测试缺失

### 13.3 E2E 测试

- [ ] **生产认证流程测试** — 当前仅测试 dev-login
- [ ] **完整空间生命周期测试** — 创建→配置→成员管理→存档→删除
- [ ] **多视图切换测试** — 所有 22 个视图的导航和状态保持
- [x] **移动端测试** — Playwright 新增 mobile viewport smoke，覆盖小屏下 sidebar/right panel 折叠、main view 和 timeline composer 可见

---

## 十四、发布工程 (Release Engineering)

- [ ] **签名桌面构建** — Windows (Authenticode)、macOS (notarization)、Linux (GPG) 代码签名
- [ ] **Web 部署配置** — WASM 构建 + Service Worker + 资源托管
- [ ] **自动更新** — 检查新版本→下载→提示重启（原生端）
- [ ] **崩溃遥测** — panic hook + 崩溃报告上传（opt-in）
- [ ] **隐私/安全审查清单** — 静态数据加密、网络 TLS 固定、密钥存储审计
- [ ] **发布渠道** — stable/beta/nightly
- [ ] **移动端构建目标** — iOS (Xcode 项目)、Android (NDK 目标)
- [ ] **商店提交** — App Store、Microsoft Store、Flathub、Web PWA manifest

---

## 优先级建议

### P0 — 协议基础（阻塞所有其他功能）
1. ~~操作签名与 commit 创建（Write Plane）~~ ✅
2. ~~HLC 生成与因果跟踪~~ ✅
3. ~~结构化游标编码~~ ✅
4. 加密载荷信封完整合规
5. WebCrypto E2EE 存储

### P1 — 核心用户体验
1. 生产认证流程（WebAuthn + OIDC + token 刷新）
2. ~~离线队列与重连协调~~ ✅
3. ~~URL 路由与深链接~~ ✅
4. ~~实体/Relation 统一抽象~~ ✅
5. ~~冲突检测与解决 UI~~ ✅

### P2 — 协议完整性
1. ~~Capability 授权引擎~~ ✅
2. ~~完整操作族支持~~ ✅
3. ~~快照同步~~ ✅
4. ~~多设备标记合并~~ ✅
5. ~~一致性测试向量集成~~ ✅

### P3 — 生态扩展
1. 联邦支持
2. Applet 集成
3. AI 代理协议互操作（A2A/ACP/MCP）
4. WebRTC 完整实现
5. 主权部署支持

### P4 — 发布就绪
1. 代码签名
2. 自动更新
3. 崩溃遥测
4. 移动端适配
5. 商店提交
