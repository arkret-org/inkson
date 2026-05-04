# Claude Design — Contrix v1 客户端界面

本目录是 Contrix v1 协议（`contrix-spec`）的客户端 UI 设计稿。设计稿覆盖桌面（Desktop）与移动（Mobile）两个版本，目标是把协议在 `models/`、`identity/`、`authz/`、`sync/`、`discovery/`、`crypto-media/`、`extensions/` 各个平面定义的功能，转换为一组人类可操作、对 agent 友好的界面。

> 原型基于纯 HTML/CSS，全部页面引用根目录的 `styles.css`。每个页面是一个状态/场景快照，强调信息架构、交互形态与协议边界，而不是真实数据交互。

## 1. 协议功能清单（Spec → UI 映射）

### 1.1 身份与设备 (Identity / Devices)
| 协议主题 | 文档 | UI 落点 |
| --- | --- | --- |
| DID method 选择、Handle 绑定 | `identity/identity-did.md`、`identity-handles.md` | `desktop/onboarding.html`、`desktop/settings.html` |
| 渐进披露 (claim presentation) | `identity/progressive-disclosure.md` | `desktop/settings.html`（隐私披露面板） |
| Key management、Recovery | `identity/key-management.md`、`crypto-media/devices-and-auth.md` | `desktop/recovery.html` |
| 设备配对 / 撤销 | `crypto-media/devices-and-auth.md` | `desktop/devices.html`、`mobile/devices.html` |
| 设备验证 (SAS/QR) | `crypto-media/device-crypto-verification.md` | `desktop/verify-device.html` |
| Auth Gateway / SSO / Passkey | `crypto-media/devices-and-auth.md` §3 | `desktop/login.html`、`mobile/login.html` |

### 1.2 协作对象 (Collaboration Model)
| 协议主题 | 文档 | UI 落点 |
| --- | --- | --- |
| Space 边界 / kind=collaboration / personal / project | `models/object-model-core.md` §4 | `desktop/home.html`、`desktop/space.html` |
| Space (kind=board) / kind=list 工作流容器 | `overview/current-model.md` §4、`models/views.md` §6 | `desktop/board.html`、`mobile/board.html` |
| Flow（synthesis / discussion 双 branch） | `overview/current-model.md` §2-3 | `desktop/flow-detail.html`、`desktop/discussion.html` |
| Message / 编辑 / redaction | `models/conversation-model.md` | `desktop/discussion.html`、`mobile/discussion.html` |
| Morph / Relation / 跨 Space lazy link | `models/object-model-core.md` §10-11、§2.4.1 | 在 `flow-detail.html`、`directory.html` 中提示 |
| View 投影 (board / list / table / calendar / timeline / graph) | `models/views.md` §4 | `desktop/board.html`、`desktop/space.html`（视图切换） |

### 1.3 授权与治理 (Authz / Governance)
| 协议主题 | 文档 | UI 落点 |
| --- | --- | --- |
| Capability 模型、Grant、Delegation、Revoke | `authz/capabilities.md` | `desktop/space-admin.html` |
| Policy / Moderation / Approval | `authz/policy-server.md`、`authz/moderation.md` | `desktop/space-admin.html`（policy 面板） |
| Account lifecycle / 停用 | `authz/account-lifecycle.md` | `desktop/settings.html` |
| Discoverability / Join Rule / History Visibility | `discovery/discovery-directory.md` | `desktop/space-admin.html`、`desktop/directory.html` |
| 个人 blocklist / 通知偏好 | `discovery/client-preferences.md` | `desktop/settings.html` |

### 1.4 同步与服务 (Sync / Service)
| 协议主题 | 文档 | UI 落点 |
| --- | --- | --- |
| Event Envelope、actor event chain | `sync/operations-sync.md` | `desktop/audit.html` |
| Sync frontier / cursor / snapshot | `sync/client-sync.md`、`conformance/snapshot-schema.md` | `desktop/audit.html`、`desktop/home.html` (sync 健康) |
| Federation / 跨 Principal Server | `sync/federation.md` | `desktop/space-admin.html`（federation 配置） |
| Sovereign / Controlled Collaboration Space | `sync/sovereign-deployment.md` | `desktop/space-admin.html`（trust bundle） |
| Push notification（脱敏唤醒） | `discovery/push-notifications.md`、`crypto-media/devices-and-auth.md` §5 | `desktop/settings.html`、`mobile/inbox.html` |

### 1.5 加密与媒体 (Crypto / Media)
| 协议主题 | 文档 | UI 落点 |
| --- | --- | --- |
| MLS E2EE / branch-scoped encryption | `crypto-media/encryption-and-audit.md` | `desktop/discussion.html`（密钥 banner）、`flow-detail.html` |
| Blob / 媒体管线 / 缩略图 | `crypto-media/media-and-blob.md` | `desktop/flow-detail.html`（附件区） |
| WebRTC 通话 / 会议 | `crypto-media/webrtc-signaling.md` | `desktop/call.html`、`mobile/call.html`(链接) |

### 1.6 发现与目录 (Discovery)
| 协议主题 | 文档 | UI 落点 |
| --- | --- | --- |
| Space / Org / Actor / Applet directory | `discovery/discovery-directory.md` | `desktop/directory.html` |
| Profile / Presence / Typing | `discovery/profiles-presence.md` | `desktop/discussion.html`（成员侧栏） |
| Read receipts / Read marker | `discovery/read-receipts.md` | `desktop/discussion.html`、`inbox.html` |

### 1.7 扩展 / Agent / Applet
| 协议主题 | 文档 | UI 落点 |
| --- | --- | --- |
| Applet 注册 / Bot / Bridge / Portal Space | `extensions/applet-integration.md` | `desktop/applets.html` |
| Agent 协议互通 / A2A / ACP | `extensions/agent-protocol-interop.md` | `desktop/applets.html` (Agent tab)、`flow-detail.html`（agent 结果落点） |
| MIMI Provider Facade / 跨协议 | `extensions/mimi-interop.md` | `desktop/space-admin.html`（federation） |

## 2. 业务流程设计（用例覆盖）

每条流程对应一组页面，组合阅读即可看到协议各能力的协作面。

### 流程 A：新用户首次使用（Onboarding & 首次写入）
1. `desktop/login.html` → 选择登录方式（passkey / OIDC / 设备扫码 / dev login）。
2. `desktop/onboarding.html` → 创建/绑定 DID、选择 method、生成本设备 device key、设置 handle。
3. `desktop/recovery.html` → 配置加密云保险箱口令或社交恢复联系人。
4. `desktop/home.html` → 首次进入工作台，看到默认 personal Space、sync bootstrap 状态。
5. `desktop/space.html` → 创建/加入第一个协作 Space。

> 协议要点：DID 是身份根、Handle 只是入口；首次写入前 Auth Service 必须把 session 绑定到 DID + device；加密云保险箱默认 `xchacha20poly1305`、Argon2id KDF。

### 流程 B：日常协作（Board → Flow → Discussion）
1. `desktop/home.html` → 选择 Space、看到 boards / recent。
2. `desktop/board.html` → 看板视图，拖动卡片（写入 `cx.flow.move` / `cx.flow.reorder`）。
3. `desktop/flow-detail.html` → 编辑 Flow synthesis branch（标题、字段、状态、附件、关系）。
4. `desktop/discussion.html` → 在 Flow discussion branch 中讨论（独立成员、E2EE 边界）。
5. `desktop/inbox.html` → 处理 mention、assignment、approval。
6. `mobile/board.html` & `mobile/flow-detail.html` & `mobile/discussion.html` → 移动端同步体验。

> 协议要点：Flow 是统一对象，synthesis 与 discussion 共享 identity；branch 默认继承授权，独立成员只在 branch-scoped override 时生效；View 拖拽必须落到 `cx.flow.move`，而不是只更新 View。

### 流程 C：跨组织协作 / Controlled Collaboration Space
1. `desktop/space-admin.html` → 创建受控外部协作 Space（discoverability=invite_only、join_rule=restricted、E2EE 必须）。
2. `desktop/directory.html` → 受邀外部组织通过精确 ID/邀请链接发现。
3. `desktop/inbox.html` → 处理 invite，需通过 claim/VC 验证后才生效。
4. `desktop/audit.html` → 双方查看 federation transaction 与签名 event。

> 协议要点：discoverability ≠ join rule ≠ history visibility；invite 携带 `expires_at`；外部主体进入前必须验证 issuer 与 trust bundle。

### 流程 D：多设备 + 离线 + 冲突收敛
1. `desktop/devices.html` → 在新设备生成 device key、显示 QR。
2. `desktop/verify-device.html` → 主设备扫码、SAS 数字比对、签发 `cx.device.authorized`。
3. `mobile/devices.html` → 移动端确认密钥包同步、MLS Welcome 已收到。
4. `desktop/audit.html` → 离线写入回放、并发 `cx.flow.move` 冲突按 reducer 收敛、查看 sync frontier 与 snapshot。

> 协议要点：登录、设备授权、设备密钥验证三件事分开；设备撤销同时触发 MLS Remove 与 Epoch 更新；Sync Service 不可伪造 actor Event。

### 流程 E：实时音视频会议
1. `desktop/flow-detail.html` → 在 Flow 上发起 call (Call Morph)。
2. `desktop/call.html` → 全屏会议，SFU 模式，参会者来自 discussion branch 成员；录制需显式授权。
3. `mobile/call.html` (链接) → 手机端入会。

> 协议要点：实时信令是 Ephemeral；通话摘要、录制 artifact 才作为 Durable Event；TURN/SFU 不获得 Space 权限。

### 流程 F：Applet / Agent / 自动化
1. `desktop/applets.html` → 浏览受信 Applet、查看权限范围、注册新 Applet。
2. `desktop/space-admin.html` → 为 Applet 授予 capability（受 Space policy 约束）。
3. `desktop/flow-detail.html` → Agent 结果作为新的 Flow / Message / Morph 落到 Space。
4. `desktop/audit.html` → 查看 Applet/Agent transaction 与 ghost actor 操作链。

> 协议要点：Applet namespace ≠ 权限通过；ghost actor 必须可审计；agent 输出落地为 signed Event 才成为协议事实。

## 3. 设计原则

- **协议优先**：所有写入语义（拖拽、@、表单提交、状态切换）显示其对应 canonical event kind。
- **可见 vs 可读 vs 可写**：UI 在 Flow / Space 上明显区分 discoverable、readable synthesis、readable discussion、writable 四种状态。
- **隐式信任**：在每个跨 Space、跨 service 的入口上提示 plaintext-visible-services 与 trust boundary。
- **离线优先**：UI 显示当前 frontier、pending events、conflict pivot、reducer 收敛建议。
- **agent 一等公民**：界面用同一份信息架构服务 human reviewer 与 agent runtime（agent 视角通过 audit / applets 页面展开）。
- **桌面 vs 移动**：桌面强调多列工作台、并行视图；移动强调单列焦点 + 底部导航 + 滑动操作。

## 4. 文件索引

入口：`index.html` 是设计稿首页（包含桌面/移动版本的快速跳转链接）。所有页面共享 `styles.css`。

```text
claude-design/
├── README.md                # 本文件
├── index.html               # 设计稿导航
├── styles.css               # 共享样式
├── desktop/
│   ├── login.html           # 登录（passkey / OIDC / Device QR）
│   ├── onboarding.html      # DID / Handle / 首设备 / 恢复
│   ├── home.html            # 工作台首页 / Sync 健康
│   ├── space.html           # Space 概览 / 多视图切换
│   ├── board.html           # Board (kind=board) + Lists + Flows
│   ├── flow-detail.html     # Flow synthesis 详情
│   ├── discussion.html      # Flow discussion / chat / E2EE
│   ├── inbox.html           # Mention / Assignment / Approval
│   ├── directory.html       # Discovery / Spaces / Actors / Applets
│   ├── devices.html         # 设备列表 + 配对入口
│   ├── verify-device.html   # 新设备 SAS/QR 验证
│   ├── recovery.html        # 加密保险箱 / 社交恢复
│   ├── space-admin.html     # Policy / Members / Capability / Federation
│   ├── audit.html           # Events / Frontier / Conflict / Snapshot
│   ├── applets.html         # Applet / Bot / Bridge / Agent
│   ├── call.html            # WebRTC 会议
│   └── settings.html        # Profile / 隐私披露 / 通知 / Account lifecycle
└── mobile/
    ├── login.html
    ├── home.html
    ├── board.html
    ├── flow-detail.html
    ├── discussion.html
    ├── inbox.html
    └── devices.html
```
