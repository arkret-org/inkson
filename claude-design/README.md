# Claude Design — Contrix v1 客户端界面

本目录是 Contrix v1 协议（[`contrix-spec`](../../contrix-spec)）的客户端 UI 设计稿。设计稿覆盖桌面（Desktop）与移动（Mobile）两个版本。目标：把协议在 `models/` · `identity/` · `authz/` · `sync/` · `discovery/` · `crypto-media/` · `extensions/` 各个平面定义的功能，转换为一组人类可操作、对 agent 友好、可被实现者 1:1 复制的界面。

> 这一版本不是草稿。每一页停在协议某一稳定状态或流程某一步；每一处可点击元素都有真实的 href；每一种错误都有显示模式；每一处文案都有 zh / en 两版；每一页都支持 light / dark 主题。

## 0. 快速入门

| 文件 | 用途 |
| --- | --- |
| [`index.html`](index.html) | 设计稿入口（gallery） |
| [`styles.css`](styles.css) | 共享样式与主题 token（light + dark） |
| [`theme.js`](theme.js) | 持久化的主题 + 语言切换器，注入到每一页 |
| [`workflows.md`](workflows.md) | **17 条业务流程的实现契约**：每页停在哪一步、写哪些 Event |
| [`errors.md`](errors.md) | **错误码 → UI 模式映射**：toast / inline / modal / banner / 占位 |
| [`_sidebar.md`](_sidebar.md) | **统一侧栏 HTML 模板**：所有桌面 chrome 页面必须一致 |

每个 HTML 页面：
- `<html data-theme="..." data-lang="...">`
- 引用 `../styles.css` + `../theme.js`
- 桌面 chrome 页面统一使用 [`_sidebar.md`](_sidebar.md) 的侧栏模板

## 1. 设计原则

- **协议优先**：所有写入语义（拖拽、@、表单提交、状态切换）显示其对应 canonical event kind。
- **三轴独立**：`discoverability` × `join_rule` × `history_visibility` 永远是 3 个独立控件。
- **3 件事分开**：登录（`cx.session.grant`）/ 设备授权（`cx.device.authorized`）/ 密钥验证（SAS、QR）必须在 UI 上分开。
- **退化是一等公民**：`decryption_pending` / `webvh_unreachable` / `lazy_link` / `locked` / `quarantined` 不是错误，是状态。
- **agent 一等公民**：UI 显示 ghost actor 的 accountability；agent 输出落地为 signed Event 才算事实。
- **离线优先**：UI 显示 frontier、pending、conflict 收敛。
- **每个可点击元素都有 href**：用户名 → directory；Space 名 → space；avatar → settings 或 directory。

## 2. 协议功能清单（Spec → UI 映射）

### 2.1 身份与设备 (Identity / Devices)
| 协议主题 | 文档 | UI 落点 |
| --- | --- | --- |
| DID method 选择 / Handle 绑定 | `identity/identity-did.md` · `identity-handles.md` | [`onboarding.html`](desktop/onboarding.html) · [`settings.html?tab=identity`](desktop/settings.html) |
| 渐进披露 (claim presentation) | `identity/identity-handles.md` §16 | [`disclosure.html`](desktop/disclosure.html) · [`settings.html?tab=disclosure`](desktop/settings.html) |
| Key management / Recovery | `identity/key-management.md` · `crypto-media/device-lifecycle.md` §10-§13 | [`recovery.html`](desktop/recovery.html) |
| 设备配对 / 撤销 | `crypto-media/device-lifecycle.md` §1-§6 | [`devices.html`](desktop/devices.html) · [`mobile/devices.html`](mobile/devices.html) |
| 设备验证 (SAS/QR) | `crypto-media/device-lifecycle.md` §7-§9 | [`verify-device.html`](desktop/verify-device.html) |
| Auth Gateway / SSO / Passkey | `crypto-media/device-lifecycle.md` §3 | [`login.html`](desktop/login.html) · [`mobile/login.html`](mobile/login.html) |
| 账号生命周期 | `identity/account-lifecycle.md` | [`account-status.html`](desktop/account-status.html) · [`settings.html?tab=account`](desktop/settings.html) |

### 2.2 协作对象 (Collaboration Model)
| 协议主题 | 文档 | UI 落点 |
| --- | --- | --- |
| Space 边界（3 轴 + security_class + 加密 profile） | `models/space-and-place.md` | [`home.html`](desktop/home.html) · [`space.html`](desktop/space.html) · [`space-admin.html`](desktop/space-admin.html) |
| Place (board / list) | `models/space-and-place.md` §4 | [`board.html`](desktop/board.html) · [`mobile/board.html`](mobile/board.html) |
| Flow（synthesis / discussion track） | `models/flow-and-message.md` | [`flow-detail.html`](desktop/flow-detail.html) · [`discussion.html`](desktop/discussion.html) |
| Message / 编辑 / redaction / quarantine | `models/flow-and-message.md` §8 | [`discussion.html`](desktop/discussion.html) |
| Morph / Relation / 跨 Space lazy link | `models/morph.md` · `models/relation.md` | [`flow-detail.html`](desktop/flow-detail.html) · [`board.html`](desktop/board.html) |
| View 投影 (board / table / timeline / calendar) | `models/views.md` | [`board.html`](desktop/board.html) · [`space.html`](desktop/space.html) |

### 2.3 授权与治理 (Authz / Governance)
| 协议主题 | 文档 | UI 落点 |
| --- | --- | --- |
| Capability grant / delegation / revoke | `authz/capabilities.md` | [`space-admin.html?tab=capability`](desktop/space-admin.html) |
| Policy Server / Moderation / Approval | `authz/policy-server.md` · `governance/content-moderation.md` | [`moderation.html`](desktop/moderation.html) · [`space-admin.html?tab=moderation`](desktop/space-admin.html) |
| Discoverability / Join Rule / History Visibility | `discovery/discovery-directory.md` · `models/space-and-place.md` | [`space-admin.html?tab=boundary`](desktop/space-admin.html) · [`directory.html`](desktop/directory.html) |
| Application form (knock + review) | `models/space-and-place.md` §3 | [`space-admin.html?tab=applications`](desktop/space-admin.html) · [`inbox.html`](desktop/inbox.html) |
| Trust bundle / sovereign | `sync/sovereign-deployment.md` | [`space-admin.html?tab=federation`](desktop/space-admin.html) |
| 个人 blocklist | `discovery/client-preferences.md` §3.5 | [`settings.html?tab=blocklist`](desktop/settings.html) |

### 2.4 同步与服务 (Sync / Service)
| 协议主题 | 文档 | UI 落点 |
| --- | --- | --- |
| Event Envelope / actor event chain | `sync/operations-sync.md` | [`audit.html`](desktop/audit.html) |
| Sync frontier / cursor / snapshot | `sync/client-sync.md` · `conformance/snapshot-schema.md` | [`audit.html`](desktop/audit.html) · [`home.html`](desktop/home.html) |
| Federation / 跨 Principal Server | `sync/federation.md` | [`space-admin.html?tab=federation`](desktop/space-admin.html) |
| Sovereign / Controlled Collaboration Space | `sync/sovereign-deployment.md` | [`space-admin.html`](desktop/space-admin.html) · [`directory.html`](desktop/directory.html) |
| Push notification（脱敏 wakeup） | `discovery/push-notifications.md` · `crypto-media/device-lifecycle.md` §5 | [`settings.html?tab=push`](desktop/settings.html) · [`inbox.html`](desktop/inbox.html) |

### 2.5 加密与媒体 (Crypto / Media)
| 协议主题 | 文档 | UI 落点 |
| --- | --- | --- |
| MLS E2EE / branch-scoped encryption | `crypto-media/encryption-and-audit.md` | [`discussion.html`](desktop/discussion.html) · [`audit.html`](desktop/audit.html) |
| Secret storage / Cross-signing | `crypto-media/device-lifecycle.md` · `identity/key-management.md` §7 | [`recovery.html`](desktop/recovery.html) · [`settings.html?tab=encryption`](desktop/settings.html) · [`devices.html`](desktop/devices.html) |
| Blob / 媒体管线 | `crypto-media/media-and-blob.md` | [`flow-detail.html`](desktop/flow-detail.html) · [`discussion.html`](desktop/discussion.html) |
| WebRTC 通话 / 会议 | `crypto-media/webrtc-signaling.md` | [`call.html`](desktop/call.html) · [`mobile/call.html`](mobile/call.html) |

### 2.6 发现与目录 (Discovery)
| 协议主题 | 文档 | UI 落点 |
| --- | --- | --- |
| Space / Org / Actor / Applet directory | `discovery/discovery-directory.md` | [`directory.html`](desktop/directory.html) |
| Profile / Presence / Typing | `discovery/profiles-presence.md` | [`discussion.html`](desktop/discussion.html) · [`settings.html?tab=profile`](desktop/settings.html) |
| Read receipts | `discovery/read-receipts.md` | [`discussion.html`](desktop/discussion.html) · [`settings.html?tab=read-receipts`](desktop/settings.html) |

### 2.7 扩展 / Agent / Applet
| 协议主题 | 文档 | UI 落点 |
| --- | --- | --- |
| Applet 注册 / Bot / Bridge / Portal Space | `extensions/applet-integration.md` | [`applets.html`](desktop/applets.html) |
| Agent 协议互通 / A2A / ACP | `extensions/agent-protocol-interop.md` | [`agents.html`](desktop/agents.html) |
| MIMI Provider Facade | `extensions/mimi-interop.md` | [`applets.html`](desktop/applets.html) · [`space-admin.html?tab=federation`](desktop/space-admin.html) |

## 3. 业务流程（详见 [`workflows.md`](workflows.md)）

每条流程对应一组页面。组合阅读即可看到协议各能力的协作面。

| # | 流程 | 关键页面 |
| --- | --- | --- |
| A | 新用户首次注册 | [`onboarding.html`](desktop/onboarding.html) → [`recovery.html`](desktop/recovery.html) → [`home.html`](desktop/home.html) |
| B | 已有用户登录 | [`login.html`](desktop/login.html) → [`home.html`](desktop/home.html) |
| C | 二次校验（高风险动作） | modal · 触发自任意页面 |
| D | 新设备配对 + 验证 | [`devices.html`](desktop/devices.html) → [`verify-device.html`](desktop/verify-device.html) |
| E | 恢复 / 找回账号 | [`recovery.html`](desktop/recovery.html) |
| F | 创建 / 加入 Space | [`directory.html`](desktop/directory.html) → [`space-admin.html?new=1`](desktop/space-admin.html) |
| G | Flow 协作 | [`board.html`](desktop/board.html) → [`flow-detail.html`](desktop/flow-detail.html) → [`discussion.html`](desktop/discussion.html) |
| H | 看板拖拽 / 冲突 | [`board.html`](desktop/board.html) · [`audit.html`](desktop/audit.html) |
| I | 跨组织协作 / 受控跨组织 Space | [`space-admin.html`](desktop/space-admin.html) → [`directory.html`](desktop/directory.html) → [`inbox.html`](desktop/inbox.html) |
| J | 申请加入 (application_form) | [`directory.html`](desktop/directory.html) → [`space-admin.html?tab=applications`](desktop/space-admin.html) |
| K | 设备 / 账号生命周期 | [`settings.html`](desktop/settings.html) · [`account-status.html`](desktop/account-status.html) |
| L | Applet / Agent | [`applets.html`](desktop/applets.html) · [`agents.html`](desktop/agents.html) |
| M | WebRTC 会议 + 录制 | [`flow-detail.html`](desktop/flow-detail.html) → [`call.html`](desktop/call.html) |
| N | 内容审核 | [`moderation.html`](desktop/moderation.html) |
| O | 渐进式身份披露 | [`disclosure.html`](desktop/disclosure.html) |
| P | 切换默认 track | [`flow-detail.html`](desktop/flow-detail.html) |
| Q | 离线写入 / 冲突收敛 | [`audit.html`](desktop/audit.html) |

## 4. 设置项（[`settings.html`](desktop/settings.html) 完整目录）

settings 页面是用户的所有自定义入口，分为 6 个大类：

| 大类 | 子项 |
| --- | --- |
| **账户** | 个人资料（avatar / display name / bio / pronouns / presence / contact channels / VC claims）· 身份（DID / Handle 校验）· 隐私披露策略（默认策略 + 按审众）· 账号生命周期（active / soft_logged_out / locked / suspended / deactivated / erasure_pending） |
| **安全** | 设备 &amp; 密钥（含 cross-signing / 推送路由）· 会话（access / refresh token）· 恢复策略（phrase / passphrase / social / trusted service）· 加密（Secret storage + MLS group state） |
| **通知** | 规则（override / content / underride · server/client locus）· 推送通道（push_target_id + rotation period）· 免打扰（schedule + exceptions）· 个人 blocklist · 已读回执 |
| **外观与本地化** | 主题（light / dark / system）· 字体大小 · 界面密度 · 侧栏位置 · 动效 · 语言 · 时区 · 时间格式 · 日期格式 · 每周首日 · 无障碍 · 快捷键 |
| **服务与同步** | 绑定的服务（trust bundle / resolver policy）· 同步与频道 · 已授权 Applets · Agent sessions |
| **数据** | 导出 · 我的活动 / 审计 · 高级 / Dev |

## 5. 错误显示（详见 [`errors.md`](errors.md)）

每条协议错误码（来自 [`artifacts/registry/error-code-registry.json`](../../contrix-spec/spec/v1/artifacts/registry/error-code-registry.json)）都映射到一种显示模式：

- 字段级失败 → `.inline-error`
- 流程级阻断 → `.callout.danger` / `.callout.warn`
- 后台失败 → `.toast.danger`
- 严重错误 → `.modal-backdrop > .modal`
- 数据无法加载 / 解密 → `.empty-state` / 占位卡
- 账号级 → 全屏接管（[`account-status.html`](desktop/account-status.html)）

退化状态（不是错误）：`decryption_pending` / `webvh_unreachable` / `lazy_link` / `locked` / `accessible` / `parent_ref_dangling` / `moderated_hidden` / `degraded`。

## 6. 主题与语言

- **主题**：light / dark。通过 `[data-theme="light|dark"]` 在 `<html>` 上切换。右上角浮动按钮（来自 `theme.js`）实时切换并持久化到 `localStorage`。
- **语言**：zh / en。通过 `[data-lang="zh|en"]` 切换。每段双语文案用 `<span class="i18n"><span class="zh">中</span><span class="en">EN</span></span>` 双 span 并由 CSS 属性选择器决定显示。
- 切换器在每页右上角；选择跨页面持久化。

## 7. 文件索引

```
claude-design/
├── README.md                # 本文件
├── workflows.md             # 流程契约（A–Q 共 17 条）
├── errors.md                # 错误码 → UI 模式
├── _sidebar.md              # 统一侧栏 HTML 模板
├── index.html               # 设计稿入口（gallery）
├── styles.css               # 共享样式 + 主题 token
├── theme.js                 # 主题 / 语言切换
├── desktop/                 # 桌面版（14 + 4 新页面）
│   ├── login.html           # 登录（Passkey / OIDC / 设备扫码 / 恢复 / dev）
│   ├── onboarding.html      # 5 步引导
│   ├── recovery.html        # 短语 / 口令 / 社交 / 服务恢复
│   ├── verify-device.html   # SAS + QR（12 cancel codes）
│   ├── devices.html         # 设备管理 + cross-signing + push routes
│   ├── account-status.html  # 风险锁定 / 停用全屏接管
│   ├── disclosure.html      # 披露请求 modal（9 failure codes）
│   ├── home.html            # 工作台
│   ├── inbox.html           # mention / assignment / approval / invite / agent / quarantine
│   ├── directory.html       # 三轴独立的 Space / Org / Actor / Applet 发现
│   ├── space.html           # Space 概览（3 轴 + Places + recent flows）
│   ├── board.html           # 看板（WIP / 冲突 / locked / lazy_link）
│   ├── flow-detail.html     # synthesis track + 字段 + relations + 活动
│   ├── discussion.html      # discussion track + E2EE + decryption_pending + quarantine
│   ├── space-admin.html     # 3 轴独立 + capability + moderation + federation + applications
│   ├── moderation.html      # 审核队列 + 决议 + 申诉
│   ├── audit.html           # event chain + frontier + snapshot + conflicts + degraded
│   ├── applets.html         # Jira / Slack Bridge + Standup Bot + research-bot
│   ├── agents.html          # A2A / ACP session 状态机
│   ├── call.html            # WebRTC SFU + 录制授权
│   └── settings.html        # 6 大类 settings
└── mobile/                  # 移动版 (9)
    ├── login.html           # 方法选择 + QR 扫 + Passkey 进行中
    ├── home.html            # 5-tab + greeting + Spaces + recent + sync
    ├── inbox.html           # 6 种 inbox 项 + push hint
    ├── board.html           # 单列 + 列切换 + WIP warn + locked / lazy_link
    ├── flow-detail.html     # 紧凑字段 + track 切换 + 底部行动条
    ├── discussion.html      # E2EE chat + 全部消息状态
    ├── devices.html         # 设备列 + SAS 比对
    ├── settings.html        # 6 大类 settings 移动版
    └── call.html            # 2×2 tile + 5 控制按钮
```

## 8. 设计契约自检 checklist（每页）

完成一个页面时，请确认：

- [ ] `<html data-theme="..." data-lang="...">` 已设置。
- [ ] 引入 `../styles.css` + `../theme.js`。
- [ ] 桌面 chrome 页面侧栏与 [`_sidebar.md`](_sidebar.md) 一致。当前页在 `.nav-item.active`。
- [ ] 移动版底部 tab 与 home.html 同。当前 tab 在 `.phone-tab.active`。
- [ ] 所有人名、avatar、Space 名、device 名、flow 标题、面包屑都包成 `<a href="...">`。
- [ ] 双语文案：所有可见文本至少 zh + en 两种或 `data-i18n` 属性。
- [ ] 至少一处 `.callout.proto` 展示该页关联的 canonical event kind 或协议规则。
- [ ] 错误状态：表单字段或流程级失败显示 `.inline-error` / `.callout.danger`，错误码与 [`errors.md`](errors.md) 一致。
- [ ] light + dark 切换不破坏布局。

