# yougen Board + Room 页面设计

本目录记录 yougen 作为 Contrix 协议实现的页面设计基线。当前优先级是把 Trello 式看板体验映射到 Contrix 标准对象模型，同时补上 Trello 没有的一等能力：`Room` / `Message` 聊天容器，以及 Card 与 Room 的独立权限边界。

## 设计产物

- `board-room-workbench.md`：页面信息架构、关键组件、协议事件映射、典型业务流程和验收点。
- `index.html`：完整页面地图。
- `app.html` / `app.css` / `app.js`：高保真可点击静态应用原型，推荐作为产品评审入口。
- `login.html`：登录页，覆盖 server、DID/handle、设备会话和登录方式。
- `register.html`：注册页，覆盖 DID、handle、profile、设备 proof、恢复策略。
- `dashboard.html`：应用首页，覆盖 Space、Inbox、最近 Board、同步和设备状态。
- `space.html`：Space 概览页。
- `board-room-workbench.html`：Trello 式 Board + Room 工作台。
- `card-detail.html`：点击 Card 后的详情抽屉状态。
- `room.html`：Room 聊天页。
- `notifications.html`：Inbox / Notifications 页。
- `directory.html`：目录发现页。
- `contacts.html`：联系人与 Actor 关系页。
- `space-admin.html`：Space 管理页。
- `devices.html`：设备与密钥页。
- `verify-device.html`：设备验证页。
- `audit.html`：同步与审计页。
- `settings.html`：设置与发布健康页。
- `_nav.html`：静态页面导航参考。
- `implementation-audit.md`：新设计与当前 Dioxus 实现的差距清单。
- `styles.css`：静态原型样式。

## 产品方向

默认工作台采用 Trello 近似结构：

- 顶部全局栏：Space / Board 标识、搜索、创建入口、同步状态、通知、设备和账号入口。
- Board 标题栏：Board 名称、视图切换、成员、分享、Room 菜单、更多操作。
- 横向 List 画布：List 作为有序列，Card 作为主要工作对象，支持添加、拖拽、排序和 WIP 提示。
- Card 详情抽屉：Card 字段、负责人、标签、截止时间、依赖、附件、活动、审计。
- Room 聊天面板：Card 的 primary Room 作为默认讨论入口，可切换 linked Rooms；Room 权限、历史可见性和 E2EE 独立展示。

完整应用页面入口：

- 登录/注册先完成 actor 和 device bootstrap。
- 首页聚合 Space、最近 Board、Inbox、同步和设备健康。
- Board 页面是主要工作台。
- Card 点击后显示详情抽屉，而不是跳到单独孤立页面。
- Room 页面提供独立聊天视角，支持从 Card、Board、Inbox 进入。
- Admin、Devices、Audit、Settings 用于协议级治理、密钥、安全、诊断和发布健康。

`app.html` 使用 hash route 模拟真实客户端页面流：

- `#login` 登录。
- `#register` 注册。
- `#dashboard` 应用首页。
- `#board` Trello 式看板。
- `#card/legal` Card 点击后的详情抽屉。
- `#room/review` Room 聊天。
- `#inbox` 通知。
- `#directory` 目录。
- `#admin` Space 管理。
- `#devices` 设备。
- `#audit` 审计。
- `#settings` 设置。

与 Trello 的关键差异：

- Card 可关联 `0..N` 个 Room，且最多一个 `primary_room` 作为 UI 默认入口。
- Card 可见不代表 Room 可见，Room 可见不代表 Card 可见。
- Card 归档、删除或移动不会自动删除 Room。
- 发送、编辑、撤回聊天消息必须落到 `cx.message.*`，不是 Card comment 字段。
- 拖拽和排序必须落到 `cx.card.move` / `cx.card.reorder`，View projection 只负责展示。

## 协议依据

主要依据 `E:\Works\contrix-dev\contrix-spec`：

- `zh/models/object-model-standard.md`
- `zh/models/conversation-model.md`
- `zh/models/views.md`
- `zh/sync/operations-sync.md`
- `artifacts/schemas/board.schema.json`
- `artifacts/schemas/list.schema.json`
- `artifacts/schemas/card.schema.json`
- `artifacts/schemas/room.schema.json`
- `artifacts/schemas/message.schema.json`

## 后续实现影响

当前 `src/views/kanban.rs` 仍是本地示例状态，`src/views/chat.rs` 仍使用旧的 `cx:channel` / `cx.channel.create` 概念。后续实现应按本设计迁移为：

- Board projection：`View{kind=collection, renderer=board}` + `board/list/card/contains relation`。
- Chat surface：`room/message` 标准对象，而不是 channel entity。
- Card detail：通过 `cx.card.link_room`、`cx.card.unlink_room`、`cx.card.set_primary_room` 管理 Room 关联。
- 同步/并发：所有拖拽、排序、消息和 Room membership 写入都生成 signed Event Envelope，UI 只做 optimistic projection。
