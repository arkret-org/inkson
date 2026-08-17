# Design: 看板行业基线补齐（改名 / 标签库 / 搜索 / 卡面升级 / 批量 / 模板）

- 状态：提案（待评审；标签库涉及数据落点，需协议侧确认）
- 来源：`_ux_review/README.md` P3 + 对比图 `05-kanban.html`（2026-07-03 全站 UX 审计）
- 前置：归档确认框已落地（8b655d7）。
- 影响面：`views/kanban/*`、可能的 spec/SDK 数据面（标签库落点）

## 1. 背景与证据（对照 Trello / Linear / Jira 基线）

| 缺口 | 现状证据 | 严重度 |
|---|---|---|
| 列表/看板不能改名 | 列头只渲染 `kanban-column-title` 文本，无编辑入口；改名只能归档重建 | 中 |
| 无标签库 | 卡片 Labels 是自由文本逗号分隔输入（`card-detail-labels-input`，placeholder "release, ops"），无预定义、无颜色、易拼错 | 中 |
| 无板内搜索 | 找卡片只能逐列扫视 | 中 |
| 卡面信息贫瘠 | 列表视图只有标题 + 文本 assignee/due badge；负责人显示 DID 缩写；无标签色条 | 中 |
| 拖拽无视觉反馈 | 被拖卡不变灰、drop 目标（`column-drop-target-before` 空 div）无高亮 | 中 |
| Composer 逐卡关闭 | 保存后 `adding_card_to.set(None)`，连续建卡每张重新点"+ Add Card" | 低 |
| 无批量操作 | 无多选，批量归档/指派/贴标签不可能 | 中 |
| 无模板 / 无收藏 | 新板从零建列；板列表无"常用/最近" | 低 |

## 2. 目标与非目标

**目标**：把看板拉到主流工具的基线可用性；分期交付，每期独立可发布。
**非目标**：不做泳道（swimlane）、自动化规则、跨板视图等超基线能力；不动 rank/移动的 CRDT 语义。

## 3. 方案（三期）

### M1 快赢（纯前端，1 个 PR）

1. **列/看板改名**：双击标题进入行内编辑（Enter 提交 / Esc 取消），列头 kebab 菜单加"重命名"；提交走既有 `ak.space.update`（title 字段已支持）。testid：`column-rename-input` / `board-rename-input`。
2. **Composer 连续建卡**：保存后保持打开并清空、焦点回输入框；✕ 主动关闭（对齐 Trello）。
3. **新建列输入自动聚焦** + Enter 提交。
4. **拖拽视觉反馈**：ondragstart 给原卡加 `.is-dragging`（opacity .5）；dragover 时 drop 目标加 `.is-drop-target`（accent 边框）；纯 CSS + 现有事件钩子。

### M2 标签库 + 卡面升级（1-2 个 PR，含数据落点决策）

1. **板级标签库**：`{ id, name, color }` 列表。**数据落点需协议确认**，两个候选：
   - **方案 A（推荐）**：作为 board Space 的 component（如 `ak.component.board.labels.v1`）随 `ak.space.update` 写——板内共享、随板归档、联邦语义与现有 component 一致；需在 spec 注册 schema（走 contract-registry 流程）。
   - **方案 B**：account_data（`ak.board_labels.v1:<board_id>`）——零 spec 变更但**仅本人可见**，违背"团队共享标签"目标，仅作 fallback。
2. **卡片标签结构化**：卡 component 的 labels 是 label id 数组，只读写这一种形状；详情侧栏 Labels 提升到与负责人/截止同层，改多选下拉（选库内 + 就地新建）。
3. **卡面升级**：标签色条（顶部 3 条上限 +N）、负责人头像（复用聊天侧 DID 哈希色 + 备注名优先级）、due pill（逾期红）、同步状态 pill 沿用现有 write-state。

### M3 搜索 / 批量 / 模板 / 收藏（1-2 个 PR）

1. **板内搜索**：工具栏常驻输入框，客户端过滤当前板卡片（标题+描述+标签名），命中卡片高亮、其余降透明；Esc 清除。复用全局搜索的本地索引接口（无服务端依赖）。
2. **批量操作**：进入"选择模式"（工具栏按钮或长按卡片）→ 卡片显复选框 → 底部操作条（归档 / 移动到列 / 贴标签 / 指派）；实现为对选中集循环发既有单卡操作（无需新事件 kind），队列语义沿用 write_records。
3. **模板**：新建看板对话框加模板选择（空白 / Kanban三列 / Scrum五列）——模板即"建板后自动追加 N 个 `ak.space.create` 列"，纯客户端预设。
4. **收藏/最近**：板选择器加"★ 收藏"（存 account_data realm remark 同族的 board remark）与"最近打开"（本地 local_state）分组。

## 4. 验收标准（按期）

- M1：双击可改列名；连续输入 3 张卡不需重新点按钮；拖拽中原卡半透明、落点高亮。
- M2：两名成员看到同一份标签库（方案 A）；卡面可见标签色 + 头像 + 逾期红；旧自由文本标签仍能显示。
- M3：搜索能过滤当前板；一次操作 5 张卡归档；新板可从模板生成三列。
- 各期 cargo check/test 无新增失败；cotest 看板用例（sprint-planning、kanban-week）保活。

## 5. 未决问题（评审时定）

1. **标签库落点方案 A 是否立项 spec 注册**（`ak.component.board.labels.v1` schema + contract-registry）？这是 M2 的硬前置。
2. 批量操作的权限边界：选择集内含无权操作的卡时，跳过并 toast 汇总，还是整体拒绝？（倾向跳过+汇总。）
3. 模板是否需要服务端概念（团队自定义模板）？首期仅客户端预设。
4. M2 卡面头像依赖"显示名优先级（备注>handle>DID）"公共函数——与聊天侧共用，落点建议 `views/helpers.rs`（与审计 H5 的 DID 显示治理共线）。
