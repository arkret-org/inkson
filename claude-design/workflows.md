# 流程开发指导 / Workflow Implementation Guide

> 本文档把每一个跨多页的业务流程拆解成实现级 step：每步的目的、所在页面/状态、用户输入、合法过渡、错误显示、协议事实（写入哪些 Event / 调用哪些 operation）。是设计与实现之间的 1:1 契约——前端按 step 实现，QA 按 step 测试。
>
> 阅读顺序：`workflows.md` 描述「怎么走」，[`errors.md`](errors.md) 描述「走错了如何回显」，每个页面 HTML 描述「停在某一步时长什么样」。
>
> 文末有英文摘要（章节 §X）。

---

## 流程总览

| 编号 | 流程 | 起点 → 终点 | 涉及页面 |
| --- | --- | --- | --- |
| A | 新用户首次注册 / Onboarding | 落地页 → 工作台 | `login` → `onboarding/*` → `recovery` → `home` |
| B | 已有用户登录（passkey / OIDC / 设备扫码 / 恢复） | 登录卡 → 工作台 | `login` → `home` |
| C | 二次校验：账号 / 设备 / 高风险动作 | 当前页 → 校验 modal → 回到原页 | 任意页面 |
| D | 新设备配对 + 验证 | 新设备 QR → 主设备扫码 → SAS → MLS Welcome | `verify-device` |
| E | 密钥恢复 / 账号找回 | 登录 → 选恢复方式 → 解锁 secret storage | `login` → `recovery` |
| F | 创建 / 加入 Space | 工作台 → 创建表单 / 邀请页 → Space 概览 | `home` → `space` 或 `directory` |
| G | 创建 Flow 并协作（synthesis ↔ discussion） | board → flow-detail → discussion | `board` → `flow-detail` → `discussion` |
| H | 在 board 上拖卡 / 改 list | board 内部 | `board` |
| I | 受控跨组织协作 Space 建立 + 外部成员接入 | 管理员 → 外部用户 | `space-admin` → `directory` → `inbox` |
| J | 申请加入 Space（application_form） | 用户 → 审核员 | `directory` → `inbox` → `space-admin/applications` |
| K | 设备撤销 / 全账号登出 / 账号停用 | 设置 → 二次校验 → 完成 | `settings` |
| L | 启用 / 撤销 Applet & Agent session | space-admin → applets | `applets` → `space-admin` |
| M | 发起 WebRTC 会议 + 录制授权 | flow → call | `flow-detail` → `call` |
| N | 内容审核：举报 → quarantine → 决议 | 任意 → moderation | `discussion` → `moderation` |
| O | 渐进式身份披露（claim presentation） | 关系入口 → 同意 → 披露 | `settings` → 任意请求方 |
| P | 切换默认 track（synthesis ↔ discussion） | flow-detail 入口设置 | `flow-detail` |
| Q | 多设备并发写入 + 离线收敛 | 任意页面 → audit | `audit` |

每个流程下边都列出：**意图 / 起点页面 / step 分解 / 每 step 的 UI 元素清单 / 错误状态 / 写入的 Event**。

---

## A. 新用户首次注册（Onboarding）

> **意图**：从空设备到拥有可签名 DID + 已配对设备 + 已设置恢复策略 + 落地工作台。
>
> **耗时目标**：≤ 90 秒（不含密码学计算）。
>
> **协议要点**（`crypto-media/device-lifecycle.md` §1）：登录、设备授权、设备密钥验证是三件独立事情，必须按顺序完成。

### A.0 入口：`desktop/login.html`

- **页面状态**：默认状态、未选方法。
- **UI 元素**：左侧品牌侧栏；右侧登录卡，含两段标题（"登录到你的协作工作台" / "首次使用？创建账号"）；4 个登录方法按钮（Passkey / OIDC / 设备扫码 / 开发者本地登录）。
- **底部链接**：「创建新账号」→ 跳转到 `onboarding/step-1-method.html`。

### A.1 选择 DID method — `onboarding/step-1-method.html`

| 元素 | 内容 / 行为 |
| --- | --- |
| 步骤指示器 | `1 of 5 · 选择身份方法` |
| 标题 | 「为你的账号选择身份方法」 |
| 副标题 | 「DID 是身份根。Handle 是入口。它们可以分别迁移。」 |
| 选项列表 | <ul><li>**Webvh（推荐）** — `did:webvh`，需提供 host。带 `did.jsonl` 历史链与 SCID。</li><li>**Web** — `did:web`，仅个人节点。次选；不能升级 small_team 以上。</li><li>**Key（设备本地）** — `did:key`，仅供测试 / bootstrap。无法获得多设备同步、邀请、外部信任。</li></ul> |
| 进阶折叠区 | 「我希望连接 AT Protocol（`did:plc`）」「我希望绑定钱包（`did:pkh`）」→ extension profile，需 admin 在配置里启用。 |
| 主按钮 | 「下一步：填写 host / 信任根」 → 进入 `step-2-host.html`。 |
| 取消 | 「我已经有账号」→ 回 `login.html`。 |

**错误**：若用户选 `did:web` 且当前 deployment profile 是 `small_team`，主按钮禁用，下方红色提示「当前部署 profile 要求 `did:webvh`，请联系管理员或选 webvh」。错误码 `policy_combination_invalid`。

### A.2 配置 host & inception key — `onboarding/step-2-host.html`

| 元素 | 内容 |
| --- | --- |
| 步骤指示器 | `2 of 5 · 创建 DID` |
| Host 输入 | `handle.example.com`（仅 `did:webvh`/`did:web`），inline 实时校验：DNS 可达 + HTTPS 证书有效。 |
| 信任根选择 | 「使用我的组织发布的 trust root」「使用公共 well-known」「自建（高级）」，对应 `trust_roots[]` 字段。 |
| 设备密钥概览 | 当前浏览器将本地生成 `device_private_key`（不发到服务端）。 |
| Inception 流程 | 实时进度条：①生成 inception keypair ②写入 `did.jsonl` 第 0 条目 ③创建 `principal_control_space`（`purpose=principal_control`, `schema_refs` 含 `cx.profile.principal_control_space.v1`）④发出首个 `cx.device.authorized` 把当前设备加进去 ⑤可选：旋转 inception key 后销毁，或入保险箱作恢复。 |
| 主按钮 | 「创建账号」（生成期间禁用）→ 成功后进入 `step-3-handle.html`。 |

**错误**：
- Host 不可达：`webvh_unreachable` → 红色 inline error，提示「请检查 DNS / 防火墙；若仍失败可继续，但只能离线读」（链接 `did:webvh` fallback 规则）。
- inception 写入冲突（host 已被占用）：`policy_violation`（reason: `host_collision`）→ 让用户改 host。
- 浏览器不支持 Ed25519 / Web Crypto：禁用主按钮，提示用其他浏览器。

### A.3 绑定 Handle — `onboarding/step-3-handle.html`

| 元素 | 内容 |
| --- | --- |
| 步骤指示器 | `3 of 5 · 绑定 handle（可跳过）` |
| Handle 输入 | `@alice` 或 `alice.example.com`。下方解释：「Handle 是可迁移的人类可读入口；和 DID 不是同一个东西。」 |
| 校验进度 | 双通道验证：① DNS TXT `_contrix.<handle>`；② HTTPS `/.well-known/contrix-did`。每完成一条打勾。 |
| Display Name | 仅本地 UI 用，不上链。 |
| 高级折叠 | 「以 connection identifier 起步（不公开）」→ 不立刻写 `alsoKnownAs`，仅与个别 contact 双向私下绑定。 |
| 主按钮 | 「确认 handle」 → `step-4-recovery.html`。次按钮：「先跳过，稍后在设置里添加」。 |

**错误**：
- DNSSEC 失败：warn 而不阻断，提示「未启用 DNSSEC，建议补 well-known 签名以提升安全」。
- 仅一个通道通过：UI 仍允许下一步，但在设置页常驻一个「Handle 未完全验证」的 banner。
- handle 已被占用：error `policy_violation` reason `handle_taken`，让用户换。

### A.4 设置恢复策略 — `onboarding/step-4-recovery.html`

| 元素 | 内容 |
| --- | --- |
| 步骤指示器 | `4 of 5 · 设置恢复` |
| 警告 callout | 「以下任何一种丢失都会导致永久失去身份与历史，至少选一种」。 |
| 选项 1：Recovery key | 生成 24 词 BIP39。要求用户在确认页输入其中 3 个验证。落到 `did_recovery` 类。 |
| 选项 2：加密保险箱口令 | 输入 Argon2id 口令。默认 KDF：`argon2id (m=64MiB, t=3, p=1)`，xchacha20poly1305。落到 `secret_storage`。 |
| 选项 3：社交恢复 / 门限 | 让用户挑 N 个联系人 / 设备，threshold M。生成 `recovery_policy`（`threshold`, `shares[]`），每个 share 通过 to-device 安全送达。 |
| 选项 4：受信恢复服务 | 进阶。要求 service DID 在 `did:webvh` 文档里声明。 |
| 「混合保管」开关 | 默认 OFF。仅 `personal_node` profile 可开启。开启时 UI 必须显示「⚠ 一次口令泄露会同时影响身份与 E2EE 历史」。 |
| 主按钮 | 「完成设置」→ `step-5-finish.html`。 |

**错误**：
- 口令熵不足：实时 strength meter，<60 bit 不允许提交。
- 选社交恢复但 threshold > shares：禁用提交。
- 用户没选任何策略：主按钮禁用，下面 `inline-warn`「v1 协议要求至少一种恢复方式」。

### A.5 完成 — `onboarding/step-5-finish.html`

| 元素 | 内容 |
| --- | --- |
| 步骤指示器 | `5 of 5 · 完成` |
| 摘要卡片 | DID、handle、设备指纹、恢复策略（部分遮蔽）。 |
| 「下载备份摘要 PDF」 | 仅本地生成，含 DID / handle / recovery hint（不含密钥本体）。 |
| 主按钮 | 「进入工作台」→ 跳到 `home.html`，并初始化 sync bootstrap。 |

**写入事件**：`cx.device.authorized`（自签）、`cx.account.profile.set`、`cx.account_data.set(cx.client.ui_state)`（写入 `language`、`recent_spaces=[]`）、`cx.recovery_policy.set`。

---

## B. 已有用户登录

> 协议要点：Auth Service 输出 ≥1 个 `cx.session.grant` 或 `cx.device.authorized`；session_key 必须在浏览器本地生成；登录因子验证 ≠ 设备授权。

### B.1 Passkey 登录 — `login.html?method=passkey`

1. 用户输入 handle（可选 — 浏览器 passkey 列表会自动列）。
2. 点 "用 Passkey 登录" → 浏览器调起 WebAuthn `navigator.credentials.get`。
3. 后端拼装 `cx.did.proof` challenge（`audience`, `origin`, `expires_at`）。
4. 浏览器签 → 提交 → Auth Service 验证 → 颁发 `cx.session.grant`（短 TTL，绑 origin + audience）。
5. 客户端做完 RYW 校验（`X-Contrix-Wait-For`）后跳 `home.html`。

**错误**：
- 用户取消 WebAuthn → 静默回到登录卡，不显示错误。
- challenge 过期 → toast「请求超时，请重试」，错误码 `auth_expired`。
- origin / audience 不匹配（人为篡改） → 红色 modal「拒绝登录：session 绑定不匹配」，错误码 `policy_violation` reason `origin_mismatch`。
- DID 解析失败（`did:webvh` host 暂时不可达） → callout「身份服务不可达；进入只读模式（24h 内不签新事件）」。

### B.2 OIDC / SSO 登录 — `login.html?method=oidc`

1. 用户选 IdP（页面预填多个：Google / Microsoft / Okta / GitHub / 自建）。
2. 跳 IdP 完成认证。
3. 回到 `login.html?cb=oidc&state=...`。
4. Auth Gateway 颁发 `cx.session.grant`，绑 `session_key_pub`。
5. 显示「正在初始化 sync...」加载条 → 进入 `home`。

**显示规则**：
- session TTL = IdP token 寿命 vs Gateway policy 中较短者，UI 在用户头像下展示 `expires_in 23m`。
- SSO 不会自动给设备授权 — 若新浏览器，提示「这是一次性 session，要长期使用请到设备 → 添加此浏览器」。

**错误**：
- IdP 拒绝 → 跳回登录页，红色 callout「SSO 提供方拒绝你的登录请求」，附 trace_id。
- Gateway policy 拒绝 → callout reason: `auth_threat` / `session_token_risk` → 提示「风险评估过高，请用 passkey 重试或联系管理员」。

### B.3 已授权设备扫码登录 — `login.html?method=devicepair`

1. 当前浏览器（新设备）展示 QR：内嵌 `device_public_key` + `transaction_id` + `expires_at(≤10 min)`。
2. 主设备扫码 → 跳到主设备的 `verify-device.html`，参考流程 D。
3. 主设备完成 SAS 后写 `cx.device.authorized` → 新设备本地通过 sync 收到 → UI 状态从 "等待主设备" → "已授权" → 进 `home.html`。

**错误**：
- 扫码超时（10 min）：QR 灰显，覆盖 "二维码已过期" + "重新生成"。
- 主设备拒绝：错误 `policy_denied` → 红色 toast，并显示理由。
- transaction_id 已被消费：`duplicate_conflict` → 自动刷新 QR。

### B.4 开发者本地登录 — `login.html?method=devlogin`

只在 `deployment.mode=dev` 时可见。展示警告 callout「未签名 session，仅供开发用」，并把按钮变成 danger 色。

### B.5 恢复登录 — `login.html?method=recovery`

进入流程 E。

---

## C. 二次校验（高风险动作）

> 协议要点（`identity/account-lifecycle.md` §10）：账号停用、撤销 session、改恢复策略、撤销设备、改 history visibility、改 federation policy、capability grant/revoke 等动作必须重新走 high-risk auth。

### C.1 触发

任意页面下用户点了高风险按钮（例：在 `settings` 点「停用账号」、`space-admin` 点「关闭联邦」、`devices` 点「移除该设备」）。

### C.2 modal：`confirm-high-risk`

| 元素 | 内容 |
| --- | --- |
| 标题 | 「请重新验证身份」 |
| 描述 | 「你即将执行：撤销设备 `cx:device:1f4a…`，这一动作不可撤销。」（动态填充） |
| 验证方式（按用户配置） | Passkey / Recovery key / 管理员多方签名（仅企业 profile）。 |
| 主按钮 | 「确认验证」 — 调起 WebAuthn 或粘贴 recovery share。 |
| 次按钮 | 「取消」。 |
| 协议事实 callout（dev 模式可见） | `requires_claim=high_risk`, `claim_max_age=120s`。 |

**错误**：
- WebAuthn 拒签 / 取消 → 关闭 modal，不执行原动作。
- claim 过期 → 自动重 challenge 一次；若还失败则 `unauthenticated` toast。
- 风险评估升级（Policy Server reason `auth_threat`） → modal 转 danger 红框「检测到异常登录，已锁定 15 分钟」。

---

## D. 新设备配对 + 验证（首次跨设备）

> 协议要点：device key 必在新设备本地生成；主设备签 `cx.device.authorized`；SAS / QR 是「设备密钥真伪验证」，不是「登录」也不是「授权」。

### D.1 新设备：`verify-device.html?role=new`

1. 本地生成 `(device_priv, device_pub)`，存 platform secure enclave / IndexedDB（按平台）。
2. 展示 QR `cx.qr.v1` payload，含 `transaction_id`、`device_public_key`、`expires_at`。
3. 显示文案：「在主设备打开『设置 → 设备 → 添加新设备』并扫描此二维码。」

### D.2 主设备：扫码 → `verify-device.html?role=primary&tx=...`

1. 摄像头/复制粘贴扫到二维码，进入 `request → ready → start`。
2. 主设备显示「正在与新设备建立会话…」。
3. 进入 SAS 阶段：

### D.3 SAS 比对（两台同时展示同一组 emoji + 数字）

| 元素 | 内容 |
| --- | --- |
| Emoji 行 | 7 个 emoji，每个底部标 label，例：`🐶 dog · 🚲 bicycle · ...` |
| 数字行 | 三组 4 位数字 |
| 主按钮 | 「两边一致」（success 色） |
| 次按钮 | 「不一致，取消」（danger 色） |
| 取消选项展开 | `user_cancelled` / `mismatched_mac` / `untrusted_device` 等 |

### D.4 完成

- 主设备签 `cx.device.authorized` 并发布到 `principal_control_space`。
- 主设备发送 secret storage bootstrap + MLS Welcome 到新设备 to-device 队列。
- 新设备页面状态从「等待主设备确认」→「✅ 已添加，正在拉取数据」→ 进入 `home`。

**错误状态**（参考 `cancel_code` 集合）：
- `timeout`（超过 10 分钟）：QR 失效页，重新生成。
- `mismatched_commitment` / `mismatched_mac`：danger banner「校验失败，可能是中间人攻击」，强制取消。
- `policy_denied`：例如该 principal 已达设备上限，提示先在「设置 → 设备」移除一个旧设备。
- `unsupported_method`：fallback 到手动输入设备指纹流程。

---

## E. 恢复 / 找回账号

> 协议要点（`identity/key-management.md` §7.3）：恢复后必须新生成 device key 并发 `cx.device.authorized` 或 `recover` 事件；E2EE Space 还要拉 MLS state 并补 epoch gap。

### E.1 入口：`login.html?method=recovery` 或 设备遗失提示链接

### E.2 选择恢复方式 — `recovery.html?step=method`

按用户的 `recovery_policy.shares[]` 决定可见选项：
- 恢复短语（24 词 BIP39）— `did_recovery`
- 保险箱口令（Argon2id）— `secret_storage`
- 社交恢复（联系 N 个 share 持有人收 share）— threshold
- 受信恢复服务（如果 DID document 里有 attest 过）

### E.3 收集材料 — `recovery.html?step=collect`

| 模式 | UI |
| --- | --- |
| 短语 | 24 个输入框 + auto-paste；不完整时按钮禁用。 |
| 口令 | 单输入 + strength meter；KDF 计算进度条。 |
| 社交 | 列出每个 share 持有人 + 状态（「已收到 / 等待 / 拒绝」），收到 ≥ threshold 后允许下一步。 |
| 服务 | 显示 service DID 的认证摘要 + challenge 状态。 |

### E.4 解密保险箱 — `recovery.html?step=unlock`

进度条：① 解 KDF ② 验 commitment ③ 派生 keys ④ 重组 self_signing_key / user_signing_key。

### E.5 设备授权 — `recovery.html?step=device`

- 当前设备本地生成新 device keypair。
- 用恢复出的 principal signing key 签 `cx.device.authorized`，scopes 含 `recovery_origin=true`。
- 发布并立刻订阅 sync。

### E.6 完成 + 历史回填

- 进 `home.html`，banner「我们正在回填你的历史（约 X 分钟）」。
- 后台对所有 E2EE Space 拉 MLS group state，处理 epoch gap：若仍有 `decryption_pending`，在 `audit.html` 显示。

**错误**：
- 口令错：`invalid_signature`（client-side commitment check），重试计数器。三次失败 → 警告 + 30 秒冷却。
- share 数量不足：禁用提交。
- 持有 share 但 share 已失效（`expires_at` 过期）：错误码 `claim_required` reason `share_expired`。

---

## F. 创建 / 加入 Space

### F.1 创建 — `home.html` 右上「+ 新 Space」按钮 → modal

| 步骤 | 内容 |
| --- | --- |
| 1. 起名 | `display_name`、`kind` 通过 `schema_refs` 暗示（个人 / 团队 / 项目 / 看板）。 |
| 2. 安全等级 | `security_class`: standard / high_assurance。后者锁 federation_policy。 |
| 3. 加密 profile | `encryption_profile`: none / mls_rfc9420 / external。**创建后不可改**。 |
| 4. 历史可见性 | `history_visibility`: world_readable / shared / invited / joined / restricted。 |
| 5. discoverability + join_rule（独立两个 dropdown） | 参考 `space-admin` 三轴部分。 |
| 6. anchor profile | single_did / threshold / open_set / mixed。 |

成功后写 `cx.space.create` Event → 跳 `space.html?id=...`。

**错误**：
- 组合非法（如 high_assurance + open federation）：`policy_combination_invalid` → 在对应行高亮 + 提示。
- 命名冲突：`duplicate_conflict`。

### F.2 加入 — `directory.html` 找到目标 → 点 Tile

按 `join_rule` 分支：
- `public`：直接生成 `cx.member.state=join` → 立即进入。
- `invite`：显示「需要邀请」，按钮禁用，附带「申请」入口（流程 J）。
- `knock`：弹「请输入加入理由」短文本，写 `knock` event → 显示「等待审核」。
- `restricted` + claim_required：先做流程 O（披露 claim），claim 通过后自动 join。
- `closed`：按钮替换为「该 Space 不接受新成员」。

---

## G. 创建 Flow 并协作

### G.1 在 board 里创建 — `board.html` 列底 `+ 添加卡片`

行内编辑：标题输入 → enter → 后台发 `cx.flow.create`（field=title, container_ref=该 list）→ 卡片乐观渲染（带 `pending` 虚框）→ 收到 Event Batch Receipt 后转实线。

### G.2 进入 flow — `flow-detail.html`

默认显示 `track.synthesis`。

### G.3 编辑字段

任意字段（assignee / due / status / labels / 描述）就地编辑 → 写 `cx.flow.update` + 必要时 `cx.relation.create`（如 `assigned_to`）。

### G.4 切换到 discussion track — 点 `Discussion` tab

如果 `track.discussion.enabled=false` 且当前用户有 `cx.flow.track.admin`，显示「Discussion track 未启用 → 启用」按钮，写 `cx.flow.track.enable`。

启用后页面切到 `discussion.html`：聊天界面 + 成员侧栏 + E2EE banner（如果父 Space 加密）。

### G.5 把 discussion 提升为 child Space（独立成员 / 独立 E2EE）

`flow-detail.html` 「Discussion 设置」按钮（仅 admin） → modal「升级为独立讨论 Space」：
- 写 `cx.space.create` 新 child Space（含 `space_hierarchy` parent ref）。
- 写 `flow_detail.discussion_space_ref` 指向新 space。
- 把现有 discussion 成员迁过去（透过 invite + `cx.member.state=join`）。

迁移期间 banner「正在迁移 discussion（约 N 秒）」。

---

## H. 看板拖卡 / 列内重排 / 跨列移动

### H.1 拖卡：UX

按下卡片 → 半透明跟随；展示 placeholder；进入目标列时该列高亮；松手后乐观渲染。

### H.2 写入语义

- 同列拖：`cx.flow.reorder`（更新 rank 字段）。
- 跨列拖：`cx.flow.move`（更新 container ref + rank）。
- View 投影变更不写 `cx.view.update`（**绝不只动 view 不动 flow**）。

### H.3 错误 / 冲突

- WIP 上限超：`policy_violation` reason `wip_limit_exceeded` → 卡片回弹原位 + toast「该列已达 WIP 上限 X」（按 `wip_limit_enforcement=warn` 时改为只警告允许）。
- 并发冲突：`cas_conflict` → 客户端按 reducer 重排，UI 上短暂闪烁 1 秒提示「冲突已合并」。
- `epoch_mismatch`（MLS）：卡片暂留 `decryption_pending`，等密钥到。

---

## I. 受控跨组织协作 Space（cross-org）

### I.1 创建 Controlled Collaboration Space — `space-admin.html?new&controlled=1`

预填：`security_class=high_assurance`, `discoverability=invite_only`, `join_rule=restricted`, `history_visibility=joined`, `encryption_profile=mls_rfc9420`, `federation_policy=closed`, `anchor_profile=single_did`。所有字段允许微调，但 UI 拒绝把 federation 设为 open。

### I.2 邀请外部组织

`space-admin.html` → Members → `+ 邀请外部` → modal：
1. 输入外部组织 DID（必填）+ 个人 DID（可选）。
2. UI 后台调 directory 查 DID 合法性、handle binding、org authority chain，逐项打勾。
3. 选 `roles[]`（capability bundle）、`max_members`、`valid_until`。
4. 提交 → 写 `cx.invite.create.third_party`，并签发 `external_org_authorization` claim。

### I.3 外部用户接受 — `inbox.html`

外部用户的 inbox 收到 invite item：
- 显示 issuer 的 trust bundle 摘要。
- 让外部用户披露所需 claim（流程 O）。
- 一切通过后写 `cx.member.state=join` → MLS Welcome 仅发到已 verified 设备。

### I.4 双方在 `audit.html` 都能看见全部 federation event 链

---

## J. 申请加入 Space（application_form）

### J.1 申请者：`directory.html` 选目标 Space → 点 `申请加入`

弹申请表 modal（由 Space admin 在 `space-admin` 配置）：
- 字段 `application_form.questions[]` 按 `answer_kind` 渲染（text / single_choice / multi_choice / boolean）。
- 提交后写 `cx.space.application.submit`，进入「等待审核」（`pending`）。

### J.2 审核员：`space-admin.html?tab=applications`

- 看 pending 列表，按 `applicant_visibility=reviewer_only` 控制是否显示申请人 DID。
- 决议按钮：`accept` / `reject` / `request_changes`。每次决议写 `cx.space.application.decide` + reason_code。
- 进度受 `reviewer_quorum`（any/majority/all/{threshold,of}）限制。

### J.3 申请者：状态变更通过 inbox 推送

- `accepted_pending_invite` 时显示「请等待 invite 完成」。
- `recently_decided` rejected 时显示 cooldown 剩余时间（默认 72h）。

**错误**：
- `claim_invalid`：写在 reason_code，UI 红色 callout。
- 反复申请超过 `max_open_applications_per_actor`（默认 1）：按钮禁用。

---

## K. 设备撤销 / 全账号登出 / 账号停用

### K.1 单设备撤销 — `settings.html → 设备` 列表的每一行「移除」

1. 触发流程 C 二次校验。
2. 写 `cx.device.revoked` + 发 `cx.device.list_update`。
3. 对所有该设备所在 MLS group 发 `Remove` + 推 `Epoch update`。
4. UI 显示进度条「正在将设备从 12 个 MLS group 中移除…」。

### K.2 撤销所有 session — `settings.html → 安全 → 一键登出所有设备`

写一组 `cx.session.revoke`（多个 access_token / refresh_token）。

### K.3 账号停用 — `settings.html → 账号 → 停用账号`

进入分步 wizard：
1. 警告页：「停用后 7 天内可撤销，7 天后进入 `erasure_pending`，正文将按 redaction-only 规则处理」。
2. 输入 handle 确认。
3. 流程 C 二次校验。
4. 写 `cx.account.status` (`status=deactivated`, `reason_code=user_request`, `effective_at=now+7d`)，附 `appeal_uri`。
5. 跳到 `goodbye.html` 倒计时页。

**错误**：
- 用户已有挂起的 admin 责任（如组织 admin 唯一签名权）：`policy_violation`，要求先委派 controller。

---

## L. 启用 / 撤销 Applet & Agent

### L.1 Applet 注册 — `applets.html → +注册 Applet`

输入：`applet_id`、`service_did`、`controller_did`、`base_url`、`namespaces`、`requested_scopes[]`。
后台校验 service_did 是 `did:web` + service DID Document 中声明 `ContrixApplet`。

### L.2 在 Space 内授权 — `space-admin.html?tab=applets`

为某 applet 创建 capability grant，受 `via_applet_id`, `allowed_actor_namespace`, `space_ids`, `actions`, `expires_at` 约束。

### L.3 Agent session 启动 — `applets.html?tab=agents`

用户点「执行」→ 选 protocol(`a2a`/`acp`) + endpoint + `capability_grant`(必填) + `allowed_artifact_types` + `max_duration_seconds` + `audit_mode`。

session 状态机：`negotiating → accepted → working → (input_required|blocked)? → completed|failed|cancelled|expired`。

agent 输出落地为 signed Event（`cx.message.create` / `cx.flow.create` / `cx.relation.create`），归属 ghost actor，可在 `audit.html` 追溯。

---

## M. WebRTC 会议 + 录制

### M.1 在 Flow 上发起 — `flow-detail.html → Call 按钮`

modal：模式（p2p / sfu / mcu）+ 是否允许录制 + 是否允许屏幕共享。提交后：
1. 写 Call Morph（`morph_type=call`, `state=ringing`）。
2. 客户端通过 `cx.call.configure_media_service` 获取 ICE config（TTL ≤ 1h）。
3. 跳到 `call.html`。

### M.2 通话期间

- 信令走 Ephemeral 通道（不写 Event）。
- 状态变化 `ringing → connecting → active`。
- 录制：操作前再次弹「确认开始录制」modal（capability `call.record`），同意后写 Event。
- 录制结束后产生 artifact Event（`cx.relation.create kind=derived_from`，attach 到本 Flow）。

### M.3 结束

`call.end_for_all` 或所有人离开后写 Call Morph `state=ended`、`ended_at`、`recording_artifacts[]`。

**错误**：
- TURN 不可达：`temporarily_unavailable` reason `media_unavailable` → 让用户尝试 p2p。
- 录制 capability 缺失：录制按钮禁用，hover 提示「未授权 `cx.message.create` + `call.record`」。

---

## N. 内容审核

### N.1 用户举报 — `discussion.html` 消息右键「举报」

modal：选 `reason`（spam / harassment / hate_speech / nsfw / illegal / misinformation / other）+ 可选附注。提交后写 `cx.report.submit`（事件落 moderation Space）。

### N.2 审核员视角 — `moderation.html`

队列：每条带消息原文（在 E2EE Space 中通过 franking key 临时解封）、报告者、关联 Space、风险评分。

决议按钮（按 capability `cx.moderation.decision`）：
- `quarantine_message`（隐藏正文，保留占位）
- `redact_on_accept`
- `require_review`（拉回 review_hold 队列）
- `deny_join` / `deny_invite`（拉黑用户）
- 维持原状

每决议写 `cx.moderation.anchor`，被审核消息附 `moderated_hidden` / `moderation_pending_anchor` flag。

### N.3 用户视角 — quarantine 消息

`discussion.html` 中显示为虚线灰底「该内容已被审核团队隐藏 · 申诉」。点击申诉跳 `moderation.html?my_appeals`。

---

## O. 渐进式身份披露

### O.1 触发：任意请求方发送 `presentation_request`

例：外部组织邀请页弹「该组织希望验证你的 `employee_at=acme.com` claim」。

### O.2 modal：`disclosure-consent`

| 元素 | 内容 |
| --- | --- |
| 请求方 | service_did + handle + verified badge |
| 用途 | `purpose` 字段（自然语言） |
| 要披露的 claims | 每个一行：claim_type + issuer + 选择字段 + `disclosure` 选项 |
| 自动隐藏 | 任何在 `forbidden_fields[]` 中的字段不出现 |
| 主按钮 | 「同意并发送」 — 二次校验若 `requires_user_consent=true` |
| 次按钮 | 「全部拒绝」 |

### O.3 历史 — `settings.html → 隐私 → 披露记录`

按 audience / claim_type 展开，可撤销未来披露（不删既往）。

**错误**：
- `verifier_not_authorized`：直接拒绝展示 modal。
- `overbroad_request`：UI 显示「该请求范围过大，已限制为最小集合」并自动剔字段。
- `policy_denied`：modal 不可点，红色 callout。

---

## P. 切换默认 track（synthesis ↔ discussion）

`flow-detail.html` 右上 "..." 菜单 → 「切换默认入口」。

modal 提示：
- 「这只是切换默认入口，不会迁移历史，也不会改变 access。」
- 选项：synthesis / discussion（仅显示已 enabled 的 track）。
- 二次校验：要求 `cx.flow.track.set_primary` capability。

写 `cx.flow.track.set_primary`。UI 立即按新 primary 重渲染 tab 顺序。

---

## Q. 多设备并发写入 + 离线收敛

### Q.1 离线写入

用户在没有网络的情况下编辑 Flow 字段、发消息。客户端把 Event 暂存到本地 `outbox`：
- UI 左下角持续显示「⏸ 离线 · 3 条待发送」。
- 卡片 / 消息标记为 `pending`。

### Q.2 重连

`home.html` / 任意页面立刻同步：
- 上传所有 outbox Event（按 actor_seq 顺序），收到 receipt 后转 normal。
- 拉取 frontier 差异。

### Q.3 冲突

- `cas_conflict`：reducer 自动收敛（last-write-wins / 字段级 merge / Move-Anchor-Lattice 投票）。UI 在 `audit.html` 显示 `conflict_records[]`。
- `causal_conflict`：自动 backfill 缺失的 prev_refs。
- `dependency_missing`：UI banner「等待缺失依赖事件」。

### Q.4 audit 页面查看

`audit.html` 显示：
- per-actor event chain（每行 `actor_id / actor_seq / event_id / kind / ts`）。
- frontier 摘要 + snapshot manifest（`snapshot_ref`, `state_hash`, `covered_event_count`）。
- 离线写入回放 + reducer 决议。
- 任何 `decryption_pending` / `state_mismatch` / `quarantined` 项显眼 badge。

---

## X. 英文摘要 / Quick reference (English)

Each workflow above maps to a numbered set of pages. The HTML mockups in this directory each implement one step or stable state of a workflow. Implementation rule: every user-visible state listed here MUST have an HTML page (or modal) that matches it pixel-by-pixel; every error code listed here MUST surface using one of the patterns in [`errors.md`](errors.md).

Implementers should treat the step decomposition as **a contract between design and code**:

1. **No protocol fact is implicit** — every action that writes a `cx.*` event must show its event kind to the user (in dev mode or under `?debug` flag).
2. **No screen lacks an error state** — if a step can fail, that page must include the failure variant.
3. **Three concerns stay separate** — login / device-authorization / device-key-verification are three distinct UI flows, never merged.
4. **Discoverability × join_rule × history_visibility are three independent controls** in every Space-creation or admin surface.

---

## 索引：错误码 ↔ 流程

每个错误码出现在哪些流程的具体位置，参见 [`errors.md` §错误码索引](errors.md#错误码索引)。

