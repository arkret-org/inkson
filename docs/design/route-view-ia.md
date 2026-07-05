# Design: 路由与视图信息架构对齐（Realm 落地页 / Call·Applets 独立视图 / 消息深链）

- 状态：提案（待评审，含 URL 语义变更，需产品裁决）
- 来源：`_ux_review/README.md` H11（2026-07-03 全站 UX 审计，高危）
- 影响面：`routes.rs`、`app/mod.rs` 视图分发、`app/realm_surface.rs`、全局搜索、cotest 深链用例

## 1. 背景与证据（`src/routes.rs`）

```rust
Route::RealmsManage | Route::Realm { .. } => AppView::Kanban,   // 点 "Realm" 进的是看板
Route::Call { .. } | Route::Applets => AppView::Dashboard,      // 无自己的视图枚举，面板硬编码渲染
```

1. **`/realms/:realm_id` 落地到看板**：URL 语义是"Realm 页"，实际渲染 KanbanPanel。侧栏点同一个 Realm，会依 `RealmSurface` 偏好导向 `/realms/:id` 或 `/kanban/:id` 两个不同 URL，同一目的地两条路径。
2. **Call / Applets 是"寄生视图"**：路由存在，但 `to_view()` 映射到 Dashboard，面板在 `app/mod.rs` 里以特判硬编码渲染；roundtrip 测试注释自认不闭环（"would not roundtrip"）。
3. **消息无法深链**：全局搜索命中消息后只能跳 `Route::Chat { realm_id }` 整页（`global_search.rs` 的 `SearchDestination.seal` 带着 message id 却无处可用），用户要自己滚动找消息。task 深链是能用的（`/kanban/:realm/task/:id`），双标准。
4. **`RealmsManage` 语义漂移**：管理列表路由也映射到 Kanban 视图。

## 2. 目标与非目标

**目标**
- Route ↔ AppView 一一对应；消灭寄生视图与特判渲染。
- `/realms/:realm_id` 的落地行为有明确定义且可预期。
- 消息支持深链 + 定位高亮，与 task 深链对齐。

**非目标**
- 不改侧栏结构与 RealmSurface 概念本身（Board/Chat 面切换保留）。
- 不动 kanban 既有的 board/task 深链方案（已闭环）。

## 3. 方案

### 3.1 Route ↔ AppView 对齐

| 路由 | 现状 | 提案 |
|---|---|---|
| `/call?...` | AppView::Dashboard + 特判 | 新增 `AppView::Call` |
| `/applets` | AppView::Dashboard + 特判 | 新增 `AppView::Applets` |
| `/realms/manage` | AppView::Kanban | 新增 `AppView::RealmsManage`（管理列表视图，manage_pages.rs 已有内容） |
| `/realms/:id` | AppView::Kanban | **方案 A（推荐）**：按 `RealmSurface` 偏好 302 式重定向到 `/kanban/:id` 或 `/chat/:id`，即 `/realms/:id` 只做入口不做落地；**方案 B**：独立 Realm 概览页（成员/最近活动/入口卡）。A 零新面板成本、语义即"上次用的面"；B 信息价值更高但属新功能。 |

`to_view()` roundtrip 测试恢复全量闭环（删除"intentionally omitted"豁免）。

### 3.2 消息深链

- 路由扩为 `#[route("/chat/:realm_id?:message")]`（可选 query 参数，不破坏既有链接）。
- ChatPanel 挂载后若带 `message`：滚动至目标消息 + 2 秒高亮（新增 `data-testid="chat-highlighted-message"`）；目标不在已加载窗口时先按现有分页机制回溯加载。
- `global_search.rs::result_destination` 把 `seal` 写进 `message` 参数；搜索结果按钮文案区分 "打开消息" / "打开任务"（已有 label 字段，接上即可）。
- 分享入口：聊天消息 hover "更多" 菜单加"复制消息链接"（与看板卡片"复制链接"同模式）。

### 3.3 兼容与迁移

- 旧 URL 全部保活：`/realms/:id` 重定向（方案 A）或渲染新页（方案 B）；`/chat/:id` 无参数行为不变。
- cotest：grep 深链用例（kanban board persistence 一族），新增消息深链正反用例；`Route::from(AppView)` 的默认参数路径需要同步。
- `app/mod.rs` 删除 Call/Applets 特判块，改走统一 match——这是纯机械迁移，风险点只在信号传参。

## 4. 验收标准

- `test_route_to_view_roundtrip` 覆盖全部 Route 变体，无豁免注释。
- 搜索命中消息 → 点击 → 聊天页定位到该消息并高亮。
- 侧栏点击 Realm 在两种 surface 偏好下 URL 均可预期（书签可复现）。
- `app/mod.rs` 无 `Route::Call | Route::Applets` 特判渲染。

## 5. 未决问题（评审时定）

1. `/realms/:id` 采用方案 A（重定向到偏好 surface）还是方案 B（概览页）？——建议 A 先行，B 若立项则替换 A 的落地。
2. 消息深链参数用 query（`?message=`）还是路径段（`/message/:id`）？query 兼容成本最低（Dioxus router 既有可选 query 支持，Call 路由已用）。
3. 高亮消息的滚动定位在长历史（需多次回溯分页）时的加载上限与失败降级文案。
