# Design: 设置页信息架构重组（分组精简 / 术语人话化 / 保存语义可见 / 开发者面收纳）

- 状态：提案（待评审）
- 来源：`_ux_review/README.md` H10 后续 + 对比图 `06-settings.html`（2026-07-03 全站 UX 审计）
- 前置：Audit/Developer 独立分区已落地（8b655d7），本设计是其后的全量重组。
- 影响面：`views/settings/*`、`app` 侧设置导航、cotest settings 用例

## 1. 背景与证据

1. **信息过载**：4 个导航组、16 个一级分区，另有多层嵌套卡片/折叠面板。通知相关设置横跨 Notifications（按类型）与 per-realm 覆盖（按频率）两处，页面无解释二者关系。
2. **协议术语当分区名**（`settings/sections.rs` label）：`TSP connections`、`Capabilities`、`Blocked actors`、`Consent`——普通用户无法建立预期。
3. **开发者/测试面暴露在正常设置**：MIMI interop 测试面板（硬编码测试 payload + 5 个测试按钮，`settings/mod.rs` MIMI 区块）、Storage 诊断（"IndexedDB / Encryption at Rest" 实现细节）、Session diagnostics（Proof mode / Active signer）。
4. **保存语义不可见**：主题/语言/黑名单即时保存（本地或 account_data），通知/在线状态要点 Save，Realm 策略要点 Apply——哪些跨设备同步用户完全无从判断。
5. **危险操作确认不一**：删备注/清空通知覆盖零确认 vs 撤销设备输 24 词（审计 H2；本设计只定规范，逐处落地随迁移做）。

## 2. 目标与非目标

**目标**
- 一级分区收敛到 6 组，命名全部用户语言（i18n 化，分区 label 现为硬编码英文）。
- 每个分区标注保存语义（跨设备同步·自动保存 / 仅本机）。
- 开发者/测试面全部收进"开发者工具"（或 dev 构建限定）。
- 设置内搜索（分区+条目级过滤）。
- 危险操作三级确认规范成文。

**非目标**
- 不改任何设置项的存储后端与 API。
- 不动 Realm 管理后台（另属 realm_admin，见审计 07 号对比图，未立项）。

## 3. 方案

### 3.1 新分组结构（16 节 → 6 组）

| 新分组 | 收纳的现有分区 | 备注 |
|---|---|---|
| 账号 | Account information、My Agents、Server information | Agents 若日均使用低可再降级进"高级" |
| 设备与安全 | Devices、Recovery、Capabilities（改名"应用授权"） | Encryption/MLS recovery 归此 |
| 隐私 | Privacy & sharing、Blocked actors（改名"屏蔽名单"）、Who can invite me、Consent（改名"邀请与同意"） | 四节合并导航相邻，保留各自页面 |
| 通知 | Notifications | 页首加一行说明："此处选**类型**；各空间的**频率**在空间设置覆盖" |
| 外观与语言 | Appearance & locale | 不变 |
| 高级 | Data & sync、Diagnostics(Release)、Audit log、Developer tools、TSP connections（改名"外部连接"） | Audit/Developer 已独立（前置 PR 落地） |

术语映射（label 全部转 i18n key；slug 不变，URL 保持稳定）：
`TSP connections→外部连接 / Capabilities→应用授权 / Blocked actors→屏蔽名单 / Consent→邀请与同意 / Diagnostics→发布状态`。

### 3.2 保存语义标注

- 分区头部统一 pill：`跨设备同步 · 自动保存`（account_data 后端）/ `仅本机`（localStorage/文件后端）/ `需应用`（Realm 策略类，点 Apply 生效）。
- 数据来源：为每个分区在 sections.rs 声明 `persistence: SyncScope` 枚举，渲染层读取——单一真相源，避免文案漂移。
- 逐步取消散落的 Save 按钮：改动即存 + "✓ 已保存" 瞬时反馈（依赖统一反馈体系设计的 toast/inline；该 PR 未合前先保留 Save 按钮，只加 pill）。

### 3.3 开发者面收纳

移动到 Developer tools 分区（已独立）：MIMI interop checks（整块）、Storage diagnostics 详情（Data & sync 只留一行摘要）、Session diagnostics（Proof mode / Active signer）。
可选：`#[cfg(debug_assertions)]` 门控 MIMI 面板（评审定：运维是否需要在 release 构建可达）。

### 3.4 设置内搜索

- 导航顶部搜索框：按分区 label + 分区内条目标题（各分区提供静态 `searchable_terms()` 清单，i18n 后匹配）过滤导航树；命中条目跳转分区并滚动定位。
- 复用命令面板的 `palette_filter()` 多词匹配逻辑。

### 3.5 危险操作确认规范（成文，逐处落地随迁移）

| 级别 | 适用 | 形式 |
|---|---|---|
| L1 可逆 | 删备注、清空覆盖、移除 passkey 包装 | 确认框（或统一反馈体系落地后的 Undo toast） |
| L2 不可逆 | 清空黑名单、注销会话 | 确认框 + 后果一句话 |
| L3 毁灭性 | 撤销设备、销毁 Realm | 保持现状（恢复密钥 / 输入名称验证） |

### 3.6 落地拆分

- slug 全部保留：`sections.rs` 的 `from_slug` 已是多对一映射，新分组扩展它即可。
- 分四个 PR 落地：①分组+label i18n ②保存语义 pill ③开发者面搬迁 ④搜索。互相独立可乱序。
- cotest：settings 导航用例按 grep 清单同步（label 断言改 testid 断言）。

## 4. 验收标准

- 一级导航 ≤ 6 组；所有分区 label 走 i18n（en+zh）。
- 任一分区头部可见保存语义 pill，且与实际存储后端一致（单元测试断言 SyncScope 声明覆盖全部分区）。
- 正常设置页 grep 不到 MIMI/mimi 测试按钮 testid。
- 设置搜索能命中"屏蔽名单"并定位到对应分区。

## 5. 未决问题（评审时定）

1. My Agents 放"账号"还是降级"高级"？
2. MIMI 面板 release 构建是否保留（运维需求）？
3. "需应用"类（Realm 策略在 Realm 管理侧）是否也纳入本规范，还是留给 realm_admin 重组时统一？
