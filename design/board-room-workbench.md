# Board + Room Workbench 页面规格

## 目标

把 yougen 的核心工作页面设计为 Trello 式看板工作台，同时严格遵守 Contrix 协议的对象边界：

- `board` 是工作台容器。
- `list` 是 Board 内的有序列。
- `card` 是可执行、可跟踪、可沉淀的工作对象。
- `room` 是讨论容器，拥有独立 membership、history visibility、notification policy 和可选 E2EE。
- `message` 是 Room 时间线单元。
- `view` 只定义如何投影对象，不保存 Card 所属 List、Room 消息或权限事实。

## 页面结构

### 1. 全局顶栏

位置参考 Trello 顶部栏，但字段按 Contrix 调整。

| 区域 | 内容 | 协议含义 |
| --- | --- | --- |
| 左侧 | App switch、yougen 标识、当前 Space | Space 是权限与同步边界 |
| 中间 | 全局搜索 | Query / Index surface，结果需要按权限裁剪 |
| 右侧 | Create、Sync、Notifications、Device、Profile | Create 进入 board/list/card/room 快捷创建；Sync 显示 cursor/frontier |

设计要求：

- 搜索结果分组展示 Card、Room、Message、Board、Actor。
- 不可见 Room 只显示 locked lazy link，不泄露标题、成员、消息摘要或精确计数。
- 网络断开时顶栏显示 local queue 数量和最后同步 cursor。

### 2. Board 标题栏

| 控件 | 行为 | 写入 |
| --- | --- | --- |
| Board title | 内联改名 | `cx.board.update` |
| Star / pin | 个人偏好 | actor-private account data |
| View tabs | Board、Timeline、Rooms、Table、Calendar、Audit | 切换 renderer 或 projection；保存共享视图才写 `cx.view.update` |
| Share | Space / Board 授权入口 | capability / invite flow |
| Board Room | 打开 Board 关联 Room | `board --links_room--> room` |

标题栏下方保留 View 状态提示：

- `frontier` / `cursor`
- `read-your-writes` 状态
- 离线队列数量
- 当前 View 是 shared 还是 personal

### 3. 横向 List 画布

布局直接参考 Trello：横向滚动、列宽固定、卡片垂直堆叠、末尾 `Add another list`。

List 卡槽：

- Header：List title、Card count、WIP limit、List menu、可选 list room 图标。
- Body：Card 列表，按 active `list --contains--> card` relation rank 排序。
- Footer：`Add a card`，创建 Card 后立即进入该 List 的 position edge。

Card 卡片：

- 标题、摘要、labels、priority、due_at、assignee avatars。
- Checklist / attachment / dependency / blocked 状态。
- Room badge：primary Room unread、linked Rooms 数量、locked Room 标识。
- E2EE / external / review Room 小图标只表示 Room 属性，不表示 Card 权限。
- Optimistic move 时显示 pending 状态；CAS 冲突时显示需要刷新/重放。

### 4. Card 详情抽屉

点击 Card 从右侧打开抽屉，保持 Board 画布可见。

推荐分区：

| 分区 | 内容 | 写入 |
| --- | --- | --- |
| Header | title、status、priority、archive、copy link | `cx.flow.update` / `cx.flow.archive` |
| Fields | body、acceptance criteria、labels、due_at、assignees | `cx.flow.update` / `assigned_to` relation |
| Work graph | depends_on、blocks、references | relation events |
| Rooms | primary Room、linked Rooms、create/link/unlink/set primary | `discussion track enablement` / `discussion track disablement` / `primary discussion track state` |
| Chat | 当前 Room message timeline、composer、reply、reaction、redact | `cx.message.create` / `cx.message.revise` / `cx.message.redact` / `cx.reaction.*` |
| Activity | Card update events、move/reorder history、visible Room summaries | derived timeline projection |
| Audit | Event IDs、frontier、authz decision、conflict records | read-only |

Card 抽屉的默认焦点：

1. 若存在可见 `primary_room`，右侧 Chat tab 默认打开。
2. 若 primary Room 不可见，显示 locked link 和 `Request access`，不得显示 Room 标题或消息摘要。
3. 若无 Room，显示 `Create discussion room` 和 `Link existing room`。

### 5. Room 聊天面板

Room 面板可从 Card 抽屉、Board 标题栏或全局 Rooms tab 打开。

| 区域 | 内容 |
| --- | --- |
| Room header | title、room_kind、history_visibility、membership、E2EE profile、linked object |
| Timeline | messages、revisions、tombstones、reactions、read markers |
| Composer | Markdown / structured content、mention picker、attachments、E2EE disclosure |
| Members | current members、external indicator、invite/request access |
| Context rail | linked Card / Board / Run / Document lazy links |

Room 类型视觉规则：

- `discussion`：普通讨论。
- `announcement`：只允许特定成员发送，composer 默认只读。
- `support`：突出 external participant 和 SLA 字段。
- `activity`：机器事件和 agent runs，composer 可隐藏。
- `review`：强调决策、审批、decision summary。
- `external`：强提示外部成员与历史可见性。

## 典型业务流程

### 流程 A：创建 Board、List、Card，并进入工作

1. 用户点击全局 `Create`，选择 `Board`。
2. 客户端提交 `cx.board.create`，可选提交默认 `cx.view.create`。
3. 用户在 Board 内添加 `Todo / Doing / Review / Done`。
4. 每个 List 使用 `cx.list.create`，并用 `board --contains--> list` relation 表达归属与 rank。
5. 用户在 Todo 下添加 Card。
6. 客户端提交 `cx.flow.create`，再建立 `list --contains--> card` active position edge。
7. Board projection 重新拉取或本地归约后显示 Card。

通过标准：新 Card 只出现在目标 List；不依赖 Card canonical 字段里的 `board_id/list_id` 作为唯一真相。

### 流程 B：拖拽 Card 并处理并发

1. 用户把 Card 从 Doing 拖到 Review。
2. UI 立即做 optimistic move，Card 显示 pending。
3. 客户端提交 `cx.flow.move`，携带 `expected_position.relation_id` 和旧 rank。
4. 若服务器接受，projection frontier 前进，pending 消失。
5. 若并发导致 `expected_position` 过期，返回 `cas_conflict` 或 stale projection。
6. UI 显示冲突状态：`Refresh position`、`Replay my move`、`Open audit`。
7. 用户重放时基于最新 projection 重新生成 `cx.flow.move`。

并发规则：

- reducer 不使用到达顺序。
- 同一 `(list_id, flow_id)` 只能有一个 active position edge。
- tie-break 按授权权重、HLC、Actor ID、Event ID。

### 流程 C：Card 上创建 primary Room 并讨论

1. 用户打开 Card 抽屉，点击 `Create discussion room`。
2. 客户端提交 `cx.flow.create`，默认 `room_kind=discussion`，私密/E2EE 场景默认 `history_visibility=joined`。
3. 客户端提交 `discussion track enablement`，`purpose=implementation`。
4. 若设为默认讨论入口，再提交 `primary discussion track state` 或 `discussion track enablement` 中 `primary=true`。
5. Chat tab 展示 Room timeline，用户发送消息。
6. 消息写入 `cx.message.create`，mention 从结构化正文或 relation 派生 notification。

通过标准：Card 可见用户如果没有 Room membership，只能看到 locked Room link；link 不自动拉取消息。

### 流程 D：链接一个已有私密 Room

1. 用户在 Card 抽屉点击 `Link existing room`。
2. 搜索结果只展示当前 actor 可发现的 Room；不可读但可发现的结果用 locked lazy link。
3. 用户选择 Room 并设置 purpose：design / implementation / review / external_partner / private。
4. 客户端提交 `discussion track enablement`。
5. Card room badge 更新 linked count。
6. 其他成员打开 Card 时分别按 Room policy 裁剪。

通过标准：Room membership 不因链接 Card 自动变化；Card assignment 不因 Room membership 自动变化。

### 流程 E：外部协作 Room

1. Card 需要供应商协作，用户创建 `room_kind=external` 的 Room。
2. Space policy 验证是否允许 room-scoped external admission。
3. 邀请外部参与者加入 Room，只授予该 Room 的读取/发送能力。
4. 外部成员发送 Message，可 mention Card，但不能读取 Board 其他内容。
5. 内部成员可把结论写入 Card `decision_summary`。

通过标准：外部成员不获得 Space directory、Board、其他 Card 或其他 Room 可见性。

### 流程 F：编辑、撤回和审计消息

1. 用户编辑消息，客户端提交 `cx.message.revise`。
2. 默认 timeline 显示最新可见 revision，审计 tab 保留 revision chain。
3. 用户撤回消息，客户端提交 `cx.message.redact`。
4. 默认 timeline 显示 tombstone，不显示正文。
5. 后到达的 reaction 仍可保留最小审计事实，但默认 timeline 不展示。

通过标准：撤回不重写历史 hash；普通视图不会恢复已撤回正文。

### 流程 G：离线新增 Card 和消息

1. 客户端离线，顶栏显示 `offline` 和 local queue。
2. 用户新增 Card、移动 Card、发送 Room 消息。
3. UI 本地生成待签名/已签名 Event Envelope，进入 local queue。
4. 重连后按 actor chain 提交。
5. accepted event 前进 cursor；rejected event 留在 queue 并显示原因。
6. 若 move/reorder 冲突，进入流程 B 的冲突处理；message create 作为 append-only 通常直接并存。

通过标准：本地队列不伪装成已同步事实；projection 标出 pending frontier。

### 流程 H：从通知进入 Card Room

1. Actor 被 message mention 或 Card assignment 触发 notification。
2. 用户在 Notifications 打开通知。
3. 若 notification 指向 Message，客户端先验证 Room 可见性，再打开 Card 抽屉和目标 Room。
4. 若用户只能看 Card 不能看 Room，落到 Card 抽屉 locked Room 状态。
5. 用户 mark read：公开 receipt 和个人 read marker 按各自协议写入。

通过标准：notification 是派生投影，不成为 canonical truth。

## 交互到协议事件映射

| 用户动作 | 协议写入 |
| --- | --- |
| 新建 Board | `cx.board.create` |
| 更新 Board title / summary | `cx.board.update` |
| 新建 / 更新 / 归档 List | `cx.list.create` / `cx.list.update` / `cx.list.archive` |
| List 排序 | `cx.list.reorder` |
| 新建 / 更新 / 归档 / 恢复 Card | `cx.flow.create` / `cx.flow.update` / `cx.flow.archive` / `cx.flow.restore` |
| Card 跨 List 移动 | `cx.flow.move` |
| Card 同 List 排序 | `cx.flow.reorder` |
| 为 Card 关联 Room | `discussion track enablement` |
| 移除 Card Room 关联 | `discussion track disablement` |
| 设置默认讨论 Room | `primary discussion track state` |
| 新建 / 更新 / 归档 Room | `cx.flow.create` / `cx.flow.update` / `cx.flow.archive` |
<!-- C18 (spec 2026-05-09): event deleted; track-scoped membership replaced by Flow.discussion_space_ref child Space -->
| Room 成员变化 | `cx.flow.branch.member` |
| 发送 / 编辑 / 撤回消息 | `cx.message.create` / `cx.message.revise` / `cx.message.redact` |
| Reaction | `cx.reaction.add` / `cx.reaction.remove` |
| 保存共享 View 配置 | `cx.view.update` |
| 折叠列、密度、临时 filter | actor-private account data |

## 页面验收点

- Board 首屏必须是可操作工作台，不是说明页或营销页。
- 横向 List 画布在桌面端可快速扫视，在移动端切换为 Board / Card / Chat 三段式。
- Card 上必须能直接看出是否存在 primary Room、unread、locked Room、E2EE/external 状态。
- Card 抽屉必须能完成：编辑 Card、移动状态、关联 Room、发送消息、查看活动和审计。
- Room Chat 必须显示 history visibility、membership、E2EE profile，避免用户误判权限边界。
- 所有拖拽和排序都要有 optimistic、pending、accepted、conflict 四种状态。
- 不可见 Room 不泄露标题、成员、消息摘要或精确 unread 数。
- View 保存动作必须区分 shared View 和 personal preference。
- 当前实现中的 `cx:flow` 概念应迁移为 `cx:room` / `cx.message.*`。
