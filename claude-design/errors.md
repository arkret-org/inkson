# 错误显示规范 / Error Display Guide

> 描述协议错误码如何回显到 UI。每种错误码绑定一种「显示模式」（toast / inline-error / banner / modal / 占位状态）、一种文案策略（中 / 英）、一种用户可执行的次动作（重试 / 联系管理员 / 取消 / 学习）。
>
> 配套文件：[`workflows.md`](workflows.md)（每个错误何时触发）。

---

## 1. 显示模式总览

| 模式 | 适用 | 何时用 | 样式 class |
| --- | --- | --- | --- |
| **inline-error** | 表单字段附近 | 字段级校验失败、提交因单字段失败 | `.inline-error` |
| **inline-warn** | 表单或卡片附近 | 不阻断的退化提醒（DNSSEC 缺失、降级保险箱） | `.inline-warn` |
| **callout（danger）** | 页面顶部 / 区域 | 多步骤流程被阻断；当前页要展示错误背景 | `.callout.danger` |
| **callout（warn）** | 页面顶部 / 区域 | 同上但可继续 | `.callout.warn` |
| **toast** | 全局浮层 | 后台动作失败（CRUD、拖拽冲突），不阻断当前视图 | `.toast.danger` |
| **modal（block）** | 全屏遮罩 | 严重错误，必须用户确认或重做（如登录被风控） | `.modal-backdrop > .modal` |
| **empty-state（占位）** | 列表 / 区块 | 数据无法加载或解密失败 | `.empty-state` |
| **chat banner** | 聊天顶部 | E2EE 状态变化、密钥不在场 | `.chat-banner.callout.warn` |
| **占位卡（locked / pending）** | 看板卡片 / 关系 | lazy_link、locked、parent_ref_dangling | `.kcard-locked` / `.kcard.lazy-link` / `.kcard-pending` |
| **风险锁定页** | 全屏接管 | account `suspended` / `locked` | 见 §6.3 |

---

## 2. 通用展示原则

1. **永远展示错误码**：错误码是机器可读契约（`capability_denied`, `epoch_mismatch` …），UI 至少在「展开详情」里给出。dev 模式下默认可见。
2. **永远附 `request_id`**：让用户能 copy 给客服 / 在 issue tracker 上引用。格式 `cx:req:0123…`，shorten 到前 12 字符并点击可展开。
3. **永远给一个动作**：重试 / 取消 / 联系管理员 / 阅读文档 / 切换网络。不要单纯丢一条文案让用户卡死。
4. **不要把 `details.*` 字段当文案**：那里是 hint，文案要 i18n 化。
5. **二次失败时升级显示**：第一次 toast，第二次 inline-error，第三次 modal block。
6. **风险锁定不可被关闭**：`suspended` / `locked` 状态用户无法 dismiss。
7. **DEV 模式**：`html[data-dev=true]` 下显示协议错误码 + reason_code + 原始 details JSON；正式环境只展示翻译过的描述。

---

## 3. 文案与 i18n

所有错误描述使用 `data-i18n-zh` / `data-i18n-en` 双属性，或显式 `<span class="zh">...</span><span class="en">...</span>`。文案应：

- **以用户视角动作描述**，不是协议描述。
  - ❌「`epoch_mismatch`：客户端的 MLS epoch 落后于服务端」
  - ✅「这条消息正在等待密钥分发（约 1 分钟），稍后会自动显示。」
- **保留 1 个动作短语**：「重试」「取消」「联系管理员」「了解更多」「重新登录」。
- **避免缩写**：DID, MLS, E2EE 用全称 + 注释（首次出现）。
- **不要责怪用户**：「你输错了」→「请检查输入是否正确」。

---

## 4. 错误码 → 显示模式映射

> 参考来源：`contrix-spec/spec/v1/artifacts/registry/error-code-registry.json` + `sync/api-conventions.md`。

### 4.1 4xx 客户端

| 状态 | code | 显示模式 | 文案（zh） | 文案（en） | 推荐动作 |
| --- | --- | --- | --- | --- | --- |
| 400 | `bad_json` | toast danger | 「请求格式错误，请刷新页面后重试。」 | "Request was malformed. Please refresh and retry." | 重试 |
| 400 | `bad_query` | inline-error 在搜索框 | 「查询语法不正确。」 | "The query is invalid." | 提示语法 link |
| 400 | `missing_param` | inline-error 在表单 | 「{字段} 不能为空。」 | "{field} is required." | 自动 focus |
| 400 | `invalid_param` | inline-error 在表单 | 「{字段} 的值不合法。」 | "{field} is invalid." | 显示允许范围 |
| 401 | `unauthenticated` | modal block + 跳登录 | 「请重新登录。」 | "Please sign in again." | 跳 `login.html` |
| 401 | `auth_expired` | modal block + 自动续期 | 「会话已过期，正在为你续期…」 | "Session expired. Refreshing…" | 自动 retry |
| 401 | `soft_logged_out` | modal block + 跳登录（保留本地密钥） | 「为了安全已为你登出，密钥仍在本地。」 | "Signed out for security. Keys remain on device." | 重新登录 |
| 401 | `invalid_signature` | toast danger（重发） | 「签名校验失败。」 | "Signature check failed." | 重试 / 检查时钟 |
| 403 | `capability_denied` | modal info | 「你没有执行此操作的权限。需要 capability: {actions}。」 | "You don't have permission. Required capability: {actions}." | 申请 / 联系 admin |
| 403 | `space_frozen` | banner warn 顶部 | 「该 Space 已被冻结，暂不接受写入。」 | "This Space is frozen and currently read-only." | 阅读 reason |
| 403 | `claim_required` | modal flow O | 「该操作需要披露 {claim_type} claim。」 | "This action requires presenting a {claim_type} claim." | 进入披露流程 |
| 403 | `policy_violation` | inline-error 或 modal | 「策略拒绝：{reason_code}。」 | "Policy denied: {reason_code}." | 展示 obligation |
| 403 | `quota_exceeded` | toast warn | 「已达到 {资源} 配额上限。」 | "Quota exceeded for {resource}." | 升级 / 等 reset |
| 404 | `not_found` | empty-state | 「找不到这个对象。」 | "We can't find this object." | 返回 |
| 404 | `unrecognized_endpoint` | modal block | 「服务端不支持此操作（请升级客户端）。」 | "Endpoint not recognized; please upgrade client." | 检查更新 |
| 405 | `method_not_allowed` | toast danger | 「不允许的方法。」 | "Method not allowed." | 检查代理 |
| 409 | `conflict` | toast warn | 「检测到冲突，正在合并…」 | "Conflict detected; merging…" | 自动合并 |
| 409 | `cas_conflict` | toast warn + 闪烁 | 「与他人同时修改，已为你保留最新版本。」 | "Conflicting edit detected; latest version kept." | undo |
| 409 | `causal_conflict` | banner warn | 「正在回填缺失事件…」 | "Backfilling missing events…" | 等进度 |
| 409 | `dependency_missing` | banner warn | 「依赖事件未到达，稍后会自动重试。」 | "Dependency missing; will retry shortly." | 等 |
| 409 | `discussion_track_disabled` | empty-state in flow | 「该 Flow 未启用讨论。」 + 启用按钮（视权限） | "Discussion is not enabled for this Flow." | 启用 / 离开 |
| 409 | `epoch_mismatch` | 消息占位 `decryption_pending` | 「正在等待密钥分发（MLS epoch 同步中）。」 | "Waiting for key delivery (MLS epoch sync)." | 自动等待 |
| 409 | `duplicate_conflict` | inline-error | 「这个值已存在。」 | "This value already exists." | 改 |
| 409 | `rank_exhausted` | toast warn | 「重排序冲突，正在重新分配排序值…」 | "Rank exhausted; reassigning…" | 自动 |
| 409 | `key_unavailable` | 消息占位 `decryption_failed` | 「密钥不可用，无法解密。」 | "Key unavailable; cannot decrypt." | 拉密钥 / 申诉 |
| 409 | `state_mismatch` | banner warn | 「服务端状态与本地不一致，正在重同步…」 | "State mismatch; resyncing…" | 等 |
| 409 | `audit_receipt_invalidated` | callout danger | 「审计回执已失效，请检查最近活动。」 | "Audit receipt was invalidated." | 跳 audit |
| 409 | `stale_frontier` | banner warn | 「客户端 frontier 已陈旧，正在升级…」 | "Frontier stale; updating…" | 自动 |
| 410 | `cursor_expired` | toast warn + 自动 reset | 「列表游标过期，已为你重新加载。」 | "Cursor expired; list reloaded." | 自动 |
| 413 | `payload_too_large` | inline-error 在上传 | 「文件超出 {max} 上限。」 | "File exceeds {max} limit." | 压缩 / 拆分 |
| 422 | `schema_violation` | inline-error 在表单 | 「{字段} 不符合 schema 要求。」 | "{field} violates schema." | 修正 |
| 422 | `digest_mismatch` | toast danger | 「内容摘要不匹配，可能传输损坏。」 | "Content digest mismatch." | 重试 |
| 422 | `aad_digest_mismatch` | toast danger | 「关联数据校验失败。」 | "Associated data check failed." | 重试 |
| 422 | `payload_digest_mismatch` | toast danger | 「数据摘要校验失败。」 | "Payload digest mismatch." | 重试 |
| 422 | `unknown_did` | modal block | 「无法解析这个 DID：{did}。」 | "Unable to resolve DID: {did}." | 检查 host |
| 422 | `policy_combination_invalid` | inline-error 在 Space 设置 | 「这组设置不兼容：{细节}。」 | "These settings are incompatible: {detail}." | 显示矛盾点 |
| 422 | `anchorer_recovery_missing` | callout danger | 「Anchor 恢复方案缺失，请联系 admin。」 | "Anchorer recovery missing; contact admin." | 跳 admin |
| 422 | `unsupported_lattice_type` | toast danger | 「不支持的 lattice 类型。」 | "Lattice type not supported." | 升级 client |
| 429 | `rate_limited` | toast warn + 倒计时 | 「请求过于频繁，请在 {retry_after}s 后再试。」 | "Too many requests; retry in {retry_after}s." | 等 |

### 4.2 5xx 服务端

| 状态 | code | 显示模式 | 文案（zh） | 文案（en） |
| --- | --- | --- | --- | --- |
| 500 | `internal_error` | toast danger | 「服务端异常，请稍后再试（{request_id}）。」 | "Internal error; please retry ({request_id})." |
| 501 | `unsupported_feature` | callout warn | 「此功能在当前部署不可用。」 | "This feature is not enabled in your deployment." |
| 501 | `unsupported_event_kind` | toast danger | 「未识别的事件类型，请升级客户端。」 | "Unknown event kind; please upgrade." |
| 503 | `temporarily_unavailable` | banner warn 顶部 | 「服务暂时不可用，正在自动重试…」 | "Service unavailable; retrying…" |
| 503 | `hlc_logical_overflow` | toast danger | 「时间戳计数溢出，请稍后再试。」 | "Logical clock overflow." |
| 504 | `timeout` | toast warn + 重试 | 「请求超时。」 | "Request timed out." |

### 4.3 Reason code（batch / auth / state，附在 envelope.details.reason_code）

UI 把 reason_code 拼到对应错误的 detail 行。常用例：

| reason_code | 触发位置 | UI 处理 |
| --- | --- | --- |
| `approval_required` | capability grant / 高风险动作 | modal「该动作需要 {n} 位审批者批准」+ 显示审批进度 |
| `no_flow_track_message_grant` | 在 discussion 中发消息 | inline-error「你没有在该 track 发言的权限」 |
| `grant_revoked_before_event_frontier` | 写入历史事件 | banner danger「该 grant 已撤销；新写入被拒」 |
| `revoke_order_unknown_requires_backfill_or_review` | 撤销链断裂 | callout warn「需要回填 revoke 链，请联系 admin」 |
| `service_not_plaintext_visible` | 在 minimal-metadata Space 中尝试 server-side rule | inline-warn「服务端无法看明文，规则将客户端执行」 |
| `audit_receipt_invalidated` | snapshot 校验失败 | callout danger，跳 audit 详情 |
| `duplicate_conflict` | 幂等冲突 | toast warn |
| `state_mismatch` | reducer 状态不一致 | banner warn |
| `quarantined` | moderation | 占位卡 + 「申诉」按钮 |
| `partial_auth_state` | 部分授权事件缺失 | banner warn「正在补全授权链…」 |
| `auth_incomplete` | 同上 | 同 |
| `projection_incomplete` | 客户端投影未完成 | progress bar |
| `decryption_pending` | MLS 等待 epoch | 消息占位 `.msg-content.decryption-pending` |
| `decryption_failed` | 超时仍不可解密 | 消息占位 `.msg-content.decryption-failed`，附 reason |
| `unsupported_feature` | 同 §4.2 | callout warn |
| `unsupported_event_kind` | 客户端遇到未识别事件 | banner warn + 升级提示 |
| `unknown_event_kind` | reducer 失败 | banner warn |
| `invalid_canonical_json` | 编码错 | toast danger |
| `invalid_encoding` | 同 | 同 |
| `invalid_cursor` | 列表 cursor 错 | 自动 reset |
| `cursor_unrecognized` | 同 | 同 |
| `cursor_expired` | 同 | 同 |

### 4.4 Moderation reason_code

| reason_code | 显示 |
| --- | --- |
| `spam` | 红色 quarantined 占位 + 「申诉」 |
| `harassment` | 同 + 「举报反馈给我」 |
| `abuse_cluster` / `abuse_network` | 仅 admin 可见 |
| `abuse_review` | 同 + 「查看待审清单」 |
| `policy_recall` | inline-warn 历史项「此前内容被回调」 |

### 4.5 Snapshot verify reason_code

| reason_code | 显示 |
| --- | --- |
| `inclusion_proof_failed` | callout danger 顶部 + 强制 fallback 到 event-replay |
| `snapshot_issuer_revoked` | callout danger，拒绝接受 |
| `reducer_profile_mismatch` | callout danger，提示升级或下载新 profile |
| `selector_too_complex` | inline-warn 在查询页 |

### 4.6 Disclosure failure (`identity-handles.md` §16.8)

modal 内显示：

| code | 文案 zh |
| --- | --- |
| `verifier_not_authorized` | 「请求方未被信任，已自动拒绝。」 |
| `policy_denied` | 「你的披露策略禁止向该请求方披露。」 |
| `consent_required` | 「需要你明确同意才能披露。」 |
| `unsupported_proof_profile` | 「请求方不支持当前 proof profile。」 |
| `transport_privacy_required` | 「该披露必须经由保密通道（TSP / JWE）发送。」 |
| `credential_not_found` | 「你没有可用于此请求的 claim。」 |
| `credential_expired` | 「相关 claim 已过期，请刷新。」 |
| `status_unavailable` | 「无法核验 claim 状态，请稍后再试。」 |
| `overbroad_request` | 「请求范围过大，已限制为最小集合。」 |

### 4.7 SAS / device verification cancel codes

modal 内 detail 行：

| cancel_code | 文案 zh |
| --- | --- |
| `user_cancelled` | 「已取消验证。」 |
| `timeout` | 「等待超时，二维码已失效。」 |
| `unknown_transaction` | 「会话不存在或已结束。」 |
| `unexpected_message` | 「协议时序异常，已取消。」 |
| `unsupported_method` | 「双方设备无法用同一种验证方式，请换设备。」 |
| `unsupported_algorithm` | 「双方设备算法不兼容，请升级。」 |
| `mismatched_commitment` | 「⚠ 校验码不匹配，可能存在中间人攻击，请勿继续。」 |
| `mismatched_mac` | 「⚠ MAC 校验失败，可能存在中间人攻击。」 |
| `device_revoked` | 「该设备已撤销。」 |
| `untrusted_device` | 「该设备尚未通过信任检查。」 |
| `policy_denied` | 「策略拒绝（已达设备上限或被风控）。」 |
| `accepted_by_other_device` | 「已由你的其他设备完成验证。」 |

### 4.8 Policy Server decisions

| decision | UI |
| --- | --- |
| `allow` | 无 |
| `soft_deny` | toast warn「该请求被风险评估拒绝（可重试）」 |
| `hard_deny` | modal danger「拒绝执行：{reason_code}」 |
| `quarantine` | 进入 quarantine 流（消息隐藏 + 待审） |
| `require_review` | banner info「等待审核中（{n} 位审批者）」 |

每个 decision 后端附 `obligation`（`rate_limit` / `challenge` / `review_hold` / `drop_attachment`）。UI 按 obligation 显示：

- `rate_limit` → toast 倒计时。
- `challenge` 含 `captcha`/`pow`/`attested_human`/`idp_oidc` → 弹对应 challenge modal。
- `review_hold` → 提交进入 pending 队列。
- `drop_attachment` → 上传完成后 inline-warn「附件被拒，仅消息已发送」。

---

## 5. 退化状态（不是错误，但要在 UI 显示）

| 状态 | 显示位置 | 文案 / 元素 |
| --- | --- | --- |
| `decryption_pending` | 消息内 / 卡片内 | `.msg-content.decryption-pending`，配 ⌛ icon |
| `decryption_failed` | 同上 | `.msg-content.decryption-failed`，配 ✕ icon + 「重试拉取密钥」 |
| `webvh_unreachable` | 顶部 banner | callout warn「身份服务暂时不可达；功能受限（剩余 {cached_evidence_age_ms}）」 |
| `lazy_link` | 看板卡 / 关系项 | `.kcard.lazy-link`「跨 Space 引用，受限可见」 |
| `locked` | 看板卡 / 关系项 | `.kcard-locked`「目标 Space 拒绝披露细节」 |
| `accessible` | 关系项右上 | `.pill.success` 小标记，无文案 |
| `parent_ref_dangling` | 列表行 | `.inline-warn`「父对象不可达，仅元数据」 |
| `moderated_hidden` | 消息 / 卡 | `.msg-content.quarantined`「该内容已被隐藏 · 申诉」 |
| `moderation_pending_anchor` | 同 | `.pill.warning`「审核 anchor 待确认」 |
| `degraded` | 顶部 banner | callout warn「快照校验失败，已回退到事件回放（较慢）」 |

---

## 6. 风险锁定 / 账号状态

### 6.1 `active`

正常，不显示。

### 6.2 `soft_logged_out`

`modal block`：

- 标题：「已为你登出」
- 描述：「为了保护你的账号，我们临时登出了此设备。设备密钥与本地数据仍然保留。」
- 主按钮：「重新登录」 → `login.html`
- 次按钮：「清除本地数据并退出」

### 6.3 `locked` / `suspended` / `deactivated` / `erasure_pending`

接管全屏（不可关闭的 `account-status.html` 风格页）：

- 顶部品牌行
- 大标题 + 状态 pill（danger）
- `reason_code` 翻译文案
- `effective_at` 倒计时（如果是 deactivated 7 天可撤销）
- 按钮：
  - 「查看详情 / 申诉」 → `appeal_uri`
  - 「下载数据导出」（按状态可用）
  - 「联系支持」
- 不暴露任何工作台数据
- 协议字段（dev）：完整 `cx.account.status` payload 折叠展示。

---

## 7. DEV 模式

按 `html[data-dev="true"]` 切换；通常 query string `?dev=1` 或 `localStorage.cx.design.dev=true`。

DEV 模式下，每个错误展示新增：

```
+——————————————————————————————+
| code:        capability_denied             |
| reason_code: no_flow_track_message_grant   |
| http:        403                           |
| request_id:  cx:req:0123abcdef…            |
| details: { ... }                           |
+——————————————————————————————+
```

折叠式，默认收起，点 "+" 展开。

---

## 8. 错误码索引（按流程）

| 流程 | 错误码可能出现位置 |
| --- | --- |
| A. Onboarding | `policy_combination_invalid` (A.1), `webvh_unreachable` (A.2), `policy_violation:host_collision` (A.2), `policy_violation:handle_taken` (A.3) |
| B. 登录 | `auth_expired`, `policy_violation:origin_mismatch`, `auth_threat`, `session_token_risk`, `duplicate_conflict` (B.3), `webvh_unreachable` |
| C. 二次校验 | `unauthenticated`, `auth_expired`, `auth_threat` |
| D. 设备验证 | 所有 cancel codes（§4.7） |
| E. 恢复 | `invalid_signature`（口令错），`claim_required:share_expired` |
| F. 创建 Space | `policy_combination_invalid`, `duplicate_conflict` |
| G. Flow 协作 | `capability_denied`, `state_mismatch`, `epoch_mismatch` |
| H. 看板拖拽 | `policy_violation:wip_limit_exceeded`, `cas_conflict`, `epoch_mismatch` |
| I. 受控跨组织 | `claim_required`, `policy_violation`, `verifier_not_authorized` |
| J. 申请加入 | `claim_invalid`, `incomplete_answers`, `cooldown_after_reject` |
| K. 设备 / 账号停用 | 所有 lifecycle reason，`policy_violation:admin_responsibility_pending` |
| L. Applet / Agent | `capability_denied`, `unsupported_feature` |
| M. 通话 | `temporarily_unavailable:media_unavailable`, `capability_denied:call.record` |
| N. 审核 | quarantined reason_code |
| O. 披露 | 所有 disclosure failure codes（§4.6） |
| P. 切换 track | `capability_denied` |
| Q. 离线收敛 | `cas_conflict`, `causal_conflict`, `dependency_missing`, `state_mismatch` |

---

## 9. 英文摘要 (English summary)

This document maps every protocol error/reason code to an explicit UI pattern. Implementation rules:

1. Always render an error code (visible in dev, behind expand in prod) and a `request_id` (clickable to copy).
2. Always offer at least one user action — retry, cancel, escalate, learn.
3. Severity is bound to layout: field-level → `.inline-error`; flow-level → `.callout`; non-blocking background → `.toast`; blocking → `.modal-backdrop`; account-level → full-screen takeover.
4. Degraded states (decryption_pending, lazy_link, webvh_unreachable, etc.) are **not errors** — they are first-class states with their own pill / placeholder.
5. Dev mode (`data-dev=true`) reveals raw payloads for engineering work without changing prod copy.

