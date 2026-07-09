# Design: 恢复密钥"先登记后显示"流程反转 + 恢复页分层

- 状态：已评审 + 已实现（2026-07-03；安全评审裁决见 §5，spec 依据 `key-management.md §7.6`）
- 来源：`_ux_review/README.md` P0 项 3 + 对比图 `08-recovery-verify.html`（2026-07-03 全站 UX 审计）
- 影响面：`views/recovery/panel.rs`、`components/recovery_key_setup_prompt.rs`、密钥备份上传链路

## 1. 背景与证据（`views/recovery/panel.rs`）

现状时序：**生成 → 立即在屏幕上显示 24 词 → 异步上传服务器备份 → 若服务器打回（如 `device_not_authorized`）则丢弃密钥**。

三个问题：
1. **用户可能抄写了一个作废的密钥**。状态文案自己都在赌时序："Recovery Key generated. Setting it up on the server — copy the words now; they are only displayed once."——用户抄完，上传失败，密钥被丢弃，抄写作废且用户未必意识到。
2. **复核死胡同**：确认输入不匹配时只给"Check your saved copy, or regenerate a new key"两条路，无轻量重试，也不提示错在哪个词。
3. **页面无主次**：24 词主流程、Passkey 快捷解锁、社交恢复（SSS）、备份历史、writeback 说明五块平铺一长页；Passkey 卡还依赖主流程状态（"Using the Recovery Key currently displayed above…"），信息架构互相缠绕。

## 2. 目标与非目标

**目标**
- 屏幕上出现的 24 词**保证有效**（服务器已接受对应备份），杜绝"抄了个废密钥"。
- 复核失败有轻量出路（重试 + 错词定位）。
- 恢复页分层：顶部状态卡 + 主流程；Passkey/SSS/备份历史折叠为高级。

**非目标**
- 不改变密钥派生、备份加密格式与服务器 API 契约（如需新端点见 §5）。
- 不动 MLS recovery（settings/mls_recovery.rs）——它已有独立的生成+确认闭环，仅在文案上与本页对齐。

## 3. 方案

### 3.1 时序反转（核心）

新状态机（UI 三步 + 顶部状态卡）：

```
[1 登记] 本地生成 key（仅内存）→ 立即加密上传备份 → 等服务器 accept
   ├─ accepted → 进入 [2 抄写]
   └─ rejected（device_not_authorized / backup_frontier_stale / 网络）
        → 丢弃内存 key，显示人话原因 + 行动按钮（去授权设备 / 重试）
        → 屏幕从未出现过词，用户零沉没成本
[2 抄写] 显示 24 词 + 复制按钮（就地变 "✓ 已复制"）+ 红色警示横幅（保留现有）
[3 复核] 逐词比对：失败时指出首个不匹配的词序号（"第 7 个词不匹配"），
        给 [再试一次]（清空输入重来）；[重新生成] 降为次选链接
        成功 → 清除内存明文 → 状态卡转绿
```

**安全评审点**：反转后存在一个窗口——服务器已持有密文备份、但用户尚未抄写。若用户在 [2] 关页面/断电，服务器上有一份"无人持有明文口令"的备份。处置：
- 备份记录本身无害（密文，无 key 解不开），但会占据"最新备份"语义。
- 方案：为 enrollment 加 pending 语义——[3] 复核成功后才把本地元数据（fingerprint、rotated_at）落库并宣告生效；未复核的旧 enrollment 在下次 Generate 时被新备份自然覆盖。**不需要服务器新增撤销端点**（评审确认这一点即可）。
- 备选（若安全评审要求强一致）：服务器备份接口若支持"draft→confirm"两段（需查 spec `keys.backups` 契约），则复核成功后 confirm；此路径涉及 spec 变更，成本高，默认不选。

### 3.2 复核体验

- 逐词 diff：确认输入按空白切分后与原词逐位比对，报首个不匹配位置（只报位置不报正确词，避免屏幕泄露）。
- "再试一次"清空输入框保留 24 词展示；三次失败后建议重新生成。
- 复制按钮点击后就地变 "✓ 已复制！"（2 秒还原），移除对 status 字符串的依赖（对齐统一反馈体系设计）。

### 3.3 页面分层

```
[状态卡] 恢复密钥：已备份 ✓ / 未设置 ⚠ · 上次轮换 N 天前 · 主按钮（生成/重新生成）
[主流程区] 仅在生成流程进行中展开（§3.1 三步）
[高级选项 ▸ 折叠] Passkey 快捷解锁 / 社交恢复（SSS，含 2/3 门限进度）/ 备份历史 / 恢复原理说明
```

- Passkey 卡文案解耦主流程（不再引用"上面正显示的词"），独立说明"粘贴已有 24 词或在生成流程中一键包装"。
- SSS 卡补门限进度（"已添加 2/3 位监护人"），差额写进按钮禁用 title。

## 4. 验收标准

- 服务器打回时屏幕从未显示过 24 词，且给出可行动的原因提示。
- 复核输错能定位词序号并轻量重试；不重新生成即可完成确认。
- 恢复页首屏只有状态卡（+ 进行中的流程）；高级块默认折叠。
- 既有 e2e（`recovery-key-hero`、`restore-section` 等 testid）梳理后保活或有替代断言。

## 5. 未决问题（已裁决，2026-07-03）

1. **§3.1 pending 语义 vs 服务器 draft→confirm** → **采用本地 pending 语义，零 spec 变更**。依据 `arkret-spec key-management.md §7.6`：备份契约是单段 `PUT`（`ck.self.keys.backups.resource.replace`，响应 `accepted`/`duplicate`），无 draft/pending 字段，也不需要——同一 `(actor, backup_class)` 走 series 链（`series_seq` 递增 + `supersedes`/`supersedes_digest`），恢复流程 MUST 取链尾解密，所以"未复核的 enrollment"就是链尾一条普通密文，下次 Generate 以 `series_seq+1` 自然取代，无孤儿、无需撤销端点（撤销端点其实存在但要高风险 proof，不走）。实现落点：`upload.rs` 在 accept 时只落服务器事实标记（sync badge），`save_generated_recovery_key_metadata`（fingerprint/公钥/rotated_at）推迟到复核成功（panel 的 Confirm and clear / prompt 的 Confirm saved key）。
2. **网络慢旁路** → **不允许**。accept 即服务端持久化（§7.6），"先看词、后台补备份"重新引入了本设计要消灭的时序；Registering 阶段屏幕给明确进度文案，失败回 Idle 可重试。
3. **Passkey 推荐下一步** → **采纳轻量版**：复核成功的状态文案推荐前往"高级选项 · Passkey 快捷解锁"；Passkey 卡文案已解耦主流程（不再引用"上面正显示的词"），生成流程进行中自动使用内存中的 key。

## 6. 实现记录（2026-07-03）

- `views/recovery/panel.rs`：`EnrollPhase`（Idle/Registering/Transcribe）状态机；Generate 反转为先上传、`Established` 才显示；`device_not_authorized` 给"Open device settings"行动按钮；复制按钮就地 "✓ Copied!"（2s 还原）；复核逐词 diff（报首个不匹配词序号，只报位置不报词）+ "Clear and retry" + 三次失败建议重新生成；状态卡（含"服务器有备份但本设备未确认"态）；Passkey/备份历史/恢复原理折叠为 "Advanced ·"；SSS 补门限进度与差额 title。
- `views/recovery/upload.rs`：accept 时不再落本地 recovery 元数据（改由复核成功时 finalize），sync badge 标记保留在 accept（服务器事实）。
- `components/recovery_key_setup_prompt.rs`：Confirm saved key 时 finalize 元数据 + 逐词 diff 反馈（此弹窗本就是 server-first，时序不变）。
- `recovery_crypto.rs`：新增 `recovery_key_confirmation_diff`（`Match`/`WordCount`/`MismatchAt`，1-based）+ 单测。
- e2e 兼容：`recovery-key-regenerate`/`recovery-key-current`/`recovery-key-status`/`recovery-key-sync-badge`/`recovery-key-live-warning` 及 upload 成功状态串保留；cotest 相关断言均为 poll 等待，与反转时序兼容。既有 lib 测残留失败（`mls::account_recovery` 3 例）经基线 stash 对照确认与本改动无关。
