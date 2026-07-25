# Inkson 统一键盘快捷键设计

状态：已接受（Accepted）
文档类型：产品交互与客户端架构设计
适用范围：Inkson Web 与桌面端
最后核验：2026-07-25

## 1. 摘要

Inkson 采用“命令注册表 + 唯一分发器 + 上下文作用域”的快捷键架构。注册表是绑定、帮助、命令面板提示、按钮提示、冲突检查和测试的唯一真相源；分发器只执行当前最内层、可用且有权限的一个命令。

核心产品决策如下：

- `?` 和 `Mod+/` 打开同一个快捷键帮助。
- `Mod+K` 打开命令面板或快速跳转；自由文本编辑器优先拥有该组合。
- 目标态中 `Mod+F` 搜索当前上下文，`Mod+Shift+F` 搜索全部可访问内容。
- 在上下文搜索完成前，现有 `Mod+F` 继续打开全局消息搜索，不能提前修改帮助文案造成行为漂移。
- 聊天使用 `Enter` 发送、`Shift+Enter` 换行，保留 `Mod+Enter` 作为兼容发送键。
- 无修饰单键只在非编辑状态生效，并可单独关闭。
- 输入法合成期间不执行发送、提交、导航或写操作。
- `Escape` 每次只退出最内层状态，并恢复到合理焦点。
- Web 端不接管 `Mod+L`、`Mod+T`、`Mod+W`、`Mod+R` 等浏览器高价值键位。
- 归档、删除、退出 Realm 等危险操作不设置容易误触的无修饰单键。

本文不定义协议字段或 Event。第一阶段偏好是设备本地 UI 状态；若将来需要跨设备同步，必须先在 `arkret-spec` 的 v1 account-data 中定义，再由 `arkret-rust-sdk` 提供强类型。

## 2. 目标与非目标

### 2.1 目标

统一覆盖以下表面：

- 全局导航、命令面板和搜索；
- Board、列与 Card；
- 聊天编辑器、消息浏览和消息操作；
- 通用表单和富文本编辑器；
- Dialog、Drawer、菜单、popover 和自动补全；
- 通话控制；
- Windows/Linux、macOS、Web 与桌面端差异。

最终应满足：

1. 同一动作在不同页面使用同一命令身份和一致键位。
2. 帮助、命令面板和实际执行不会漂移。
3. 普通输入、中文输入法和屏幕阅读器导航不会被全局快捷键误伤。
4. 权限不足或功能关闭时，命令既不执行，也不谎报为当前可用。
5. 用户可以整体关闭应用快捷键，或仅关闭无修饰单键。

### 2.2 非目标

- 第一阶段不提供任意键位录制或完整自定义映射。
- 快捷键不替代可见按钮、菜单、焦点顺序和无障碍名称。
- 本文不改变服务端协议、数据库或网络 API。
- 本文不授权系统级全局热键；桌面端若需要，必须单独设计并默认关闭或显式启用。

## 3. 当前实现基线

截至 2026-07-25，Inkson 已有以下用户可见行为：

| 绑定 | 当前行为 | 所在表面 |
| --- | --- | --- |
| `?`、`Mod+/` | 打开快捷键帮助 | 应用壳层 |
| `Escape` | 关闭当前壳层浮层；局部组件可先消费 | 壳层与局部组件 |
| `Mod+K` | 打开顶部命令面板 | 应用壳层 |
| `Mod+F` | 打开全局本地消息搜索 | 应用壳层 |
| `Enter` | 发送消息 | Chat composer |
| `Shift+Enter` | 原生换行 | Chat composer |
| `Mod+Enter` | 兼容发送键 | Chat composer |
| `Enter` / `Escape` | 提交/取消列重命名 | Kanban |
| `Enter` | 提交目录搜索 | Directory |
| `Escape` | 关闭消息局部菜单或编辑态 | Chat timeline |

Phase 0 已将原先并存的 JavaScript listener 与 Dioxus 壳层 `onkeydown` 收敛为一个窗口 JavaScript 全局 owner。该 owner 统一处理 editable、IME composition 和自动重复；更细粒度的编辑器策略仍属于 Phase 1。

- `input`、`textarea`、`select`；
- `contenteditable` 与 `role="textbox"`；
- `event.isComposing`；
- `event.repeat`；

这只是现状纠偏，并不等于本设计的 `ShortcutRegistry` 已全部实现。注册表、编辑器适配、动态帮助、设置开关、完整 `Escape` 栈和页面级命令仍属于 Phase 1 及后续工作。

## 4. 业内依据

调研仅使用产品官方帮助资料，核验日期为 2026-07-25。

### 4.1 Trello

资料：

- [Keyboard shortcuts in Trello](https://support.atlassian.com/trello/docs/keyboard-shortcuts-in-trello/)
- [Format text in Trello](https://support.atlassian.com/trello/docs/how-to-format-your-text-in-trello/)

可采用：

- `Shift+?` 打开帮助；
- `J/K` 或上下方向键导航 Card；
- `F` 打开过滤、`X` 清除过滤；
- `Z` 撤销、`Shift+Z` 重做；
- 可以在无障碍设置中关闭快捷键。

不采用 Trello 的 `C` 归档语义。Inkson 将 `C` 留给上下文内“创建”，归档通过菜单或命令面板执行。

### 4.2 Jira

资料：

- [Navigate Jira with your keyboard](https://support.atlassian.com/jira-software-cloud/docs/navigate-jira-with-your-keyboard/)
- [What is the command palette?](https://support.atlassian.com/jira-software-cloud/docs/what-is-the-command-palette/)

可采用：

- `Mod+K` 打开命令面板；
- 在自由文本字段中不接管 `Mod+K`，让编辑器插入链接；
- 命令面板展示已有键位；
- 页面、选择状态和权限共同决定命令是否可用。

### 4.3 Slack

资料：

- [Slack keyboard shortcuts](https://slack.com/help/articles/201374536-Slack-keyboard-shortcuts-and-commands)
- [Navigate Slack with your keyboard](https://slack.com/help/articles/115003340723-Navigate-Slack-with-your-keyboard)

可采用：

- `Mod+/` 打开快捷键参考；
- `Mod+K` 快速跳转会话；
- `F6` 家族用于主要区域导航，但桌面端与浏览器组合并不完全相同；
- 聚焦消息后提供上下文单键；
- `Escape` 的效果由当前焦点和局部状态决定。

### 4.4 Discord

资料：

- [Discord Commands, Shortcuts, and Navigation Guide](https://support.discord.com/hc/en-us/articles/31232432266647-Discord-Commands-Shortcuts-and-Navigation-Guide)
- [Keyboard Navigation FAQ](https://support.discord.com/hc/en-us/articles/1500000056121-Keyboard-Navigation-FAQ)
- [Quick Switcher](https://support.discord.com/hc/en-us/articles/115000070311-Quick-Switcher)

可采用：

- `Mod+/` 打开帮助，`Mod+K` 打开 Quick Switcher；
- `Mod+F` 搜索当前频道，`Mod+Shift+F` 搜索全部频道；
- `Tab` 进入键盘导航，列表使用方向键，`Enter`/`Space` 激活；
- 聚焦消息后使用 `R`、`E`、`+` 等上下文单键；
- `F6` / `Shift+F6` 在主要区域间移动。

### 4.5 Google Chat

资料：

- [Use Google Chat keyboard shortcuts](https://support.google.com/chat/answer/7649271)

可采用：

- `?` 只在非文本输入状态打开帮助；
- `/` 聚焦搜索；
- 部分单键和两段式导航需要用户显式启用；
- 回复框使用 `Enter` 发送、`Shift+Enter` 换行；
- 消息浏览通过方向键和分层焦点模型完成。

### 4.6 Microsoft Teams

资料：

- [Keyboard shortcuts for Microsoft Teams](https://support.microsoft.com/en-US/accessibility/teams/keyboard-shortcuts-for-microsoft-teams)
- [Navigate conversations with the keyboard in Microsoft Teams](https://support.microsoft.com/en-US/teams/teams-channels/navigate-conversations-with-the-keyboard-in-microsoft-teams)

可采用：

- 明确区分桌面、Web、Windows 和 macOS；
- 文档提示键位基于美式布局，其他布局可能不同；
- 扩展编辑器使用 `Mod+Enter` 发送、`Shift+Enter` 换行；
- 通话控制使用带修饰键组合；
- 焦点区导航在 Web 与桌面端可能使用不同组合，必须实机验证。

## 5. 统一架构

### 5.1 命令注册表

每个快捷键动作都注册为稳定命令，不允许用显示文案作为身份：

```text
ShortcutCommand
  id
  category
  description_i18n_key
  bindings_by_platform
  scope
  editable_policy
  repeat_policy
  composition_policy
  availability
  permissions
  priority
  prevent_default
  stop_propagation
  action
  discoverability
```

注册表必须同时驱动：

- 事件匹配；
- 快捷键帮助；
- 命令面板键位提示；
- 按钮 tooltip 和菜单键位；
- 平台化显示；
- 冲突检查；
- 单元测试。

`availability` 是运行时函数，输入至少包括当前路由、焦点作用域、浮层栈、选择对象、权限、功能开关、会话类型和平台。

### 5.2 归一化事件

`NormalizedKeyEvent` 至少包含：

```text
key
code
ctrl
meta
alt
shift
mod
is_composing
repeat
editable_kind
focus_scope
active_overlay
platform
```

字符型单键按 `event.key` 的语义字符匹配，不假设固定物理键位。只有确实依赖物理位置的命令才允许使用 `event.code`。

### 5.3 唯一分发器

每次按键按以下顺序处理：

1. 局部原生/编辑器处理器先执行；已停止冒泡则结束。
2. 输入法合成事件直接放行。
3. 生成归一化事件和活动作用域栈。
4. 从最内层作用域向全局收集候选命令。
5. 过滤当前平台不支持、不可用、无权限、被设置关闭或不允许 repeat 的命令。
6. 编辑表面过滤所有不被显式允许的全局命令。
7. 若最高优先级存在多个候选，视为注册错误；开发模式报警且不执行。
8. 执行唯一命令。
9. 只有执行成功后才 `preventDefault()` 或 `stopPropagation()`。

执行日志只能记录命令 ID、作用域和结果，不能记录按键附近的用户输入内容。

### 5.4 作用域优先级

从高到低：

1. 输入法和操作系统保留行为；
2. 自动补全、菜单、popover、命令面板；
3. 当前编辑器或输入组件；
4. 聚焦的消息、Card、列表项或面板；
5. 当前页面；
6. 应用全局；
7. 浏览器或操作系统默认行为。

同一次按键最多执行一个命令。

## 6. 编辑表面与输入法规则

编辑表面包括：

- `input`、`textarea`、`select`；
- 任意 `contenteditable`；
- `role="textbox"`；
- 代码编辑器、富文本编辑器及其子节点；
- 输入法正在合成的目标。

强制规则：

- 无修饰字母、数字、`?`、`/` 不触发全局命令。
- `isComposing == true` 时不发送、提交、导航、创建、归档或删除。
- `repeat == true` 只允许声明为连续导航的命令。
- 编辑器标准组合优先，例如 `Mod+K` 插入链接。
- `Escape` 先退出编辑器内部的补全、emoji、mention 或编辑态；未消费时再到外层。
- 未命中或不可用的命令不得吞键。

Chat composer 的发送前置条件为：

```text
key == Enter
and not Shift
and not Alt
and not isComposing
and not repeat
and send action is enabled
```

`Ctrl+Enter` 与 `Cmd+Enter` 满足同一发送条件，但只是兼容别名。

## 7. `Escape` 与浮层栈

应用维护显式的可关闭层级栈，而不是在不同组件中猜测谁先关闭：

1. mention、emoji、slash quick insert 等自动补全；
2. 菜单和 popover；
3. 内嵌编辑态；
4. Dialog；
5. Drawer；
6. 全局搜索或命令面板；
7. 页面级选择态。

一次 `Escape` 只关闭栈顶一项。关闭后将焦点恢复到打开该层的触发元素；触发元素已卸载时，恢复到所属语义区域的稳定焦点入口。

## 8. 目标默认键位

`Mod` 在 Windows/Linux 显示为 `Ctrl`，在 macOS 显示为 `⌘`。

### 8.1 全局与导航

| 命令 | 默认绑定 | 说明 | 阶段 |
| --- | --- | --- | --- |
| 快捷键帮助 | `?`、`Mod+/` | 非编辑状态；始终保留可见按钮 | P0 |
| 命令面板 | `Mod+K` | 编辑器内让给插入链接 | P0 |
| 当前上下文搜索 | `Mod+F` | Chat 搜当前会话，Board 搜当前 Board | P0 / Phase 2 |
| 全局搜索 | `Mod+Shift+F` | 跨 Realm、Space、消息和 Card | P0 / Phase 2 |
| 页面搜索/过滤 | `/` | 非编辑状态且单键设置开启 | P1 |
| 退出最内层状态 | `Escape` | LIFO | P0 |
| 下一/上一主要区域 | `F6` / `Shift+F6` | 需按平台和 Web/桌面实测 | P1 |

迁移规则：当前 `Mod+F` 仍打开全局搜索。只有当前上下文搜索可用、帮助和测试同步更新后，才把全局搜索迁移到 `Mod+Shift+F`。迁移版本应在发行说明中明确。

### 8.2 Chat

| 命令 | 默认绑定 | 前置条件 |
| --- | --- | --- |
| 发送 | `Enter`、`Mod+Enter` | 非 IME、非 repeat；`Mod+Enter` 为兼容键 |
| 换行 | `Shift+Enter` | 编辑器原生行为 |
| 编辑最近消息 | `↑` | 草稿为空且光标位于起始位置 |
| 回复聚焦消息 | `R` | 消息浏览焦点 |
| 编辑聚焦消息 | `E` | 自己的消息且有权限 |
| 添加反应 | `+` | 消息浏览焦点 |
| 前/后一条消息 | `↑` / `↓` | 消息浏览模式 |
| 进入线程/详情 | `Enter` / `→` | 聚焦消息 |

私聊禁用 mention 时，mention 命令不得出现在帮助、补全或命令面板中。

### 8.3 Board 与 Card

| 命令 | 默认绑定 | 约束 |
| --- | --- | --- |
| 下一/上一 Card | `J` / `K`、`↓` / `↑` | Board 焦点模型 |
| 下一/上一列 | `N` / `P`、`→` / `←` | Board 焦点模型 |
| 打开 Card | `Enter` / `O` | 已选择 Card |
| 新建 Card | `C` | 非编辑状态 |
| 编辑 Card | `E` | 已选择且有权限 |
| 添加评论 | `M` | 已选择且可评论 |
| 分配成员/自己 | `A` / `I` | 有权限 |
| 打开/清除过滤 | `F` / `X` | 当前 Board；`X` 仅有活动过滤时 |
| 撤销/重做 | `Mod+Z` / `Mod+Shift+Z` | 标准组合 |
| 归档/删除 | 无单键 | 菜单或命令面板；保留确认 |

### 8.4 表单与富文本

| 表面 | `Enter` | `Shift+Enter` | `Mod+Enter` | `Escape` |
| --- | --- | --- | --- | --- |
| 单行表单 | 提交 | 不适用 | 提交别名 | 取消/关闭 |
| Chat composer | 发送 | 换行 | 发送兼容键 | 退出内层状态 |
| 多行普通文本 | 换行 | 换行 | 有明确主动作时提交 | 取消编辑 |
| 富文本/长文档 | 段落 | 硬换行 | 页面声明后保存/提交 | 退出内层状态 |
| 重命名 | 保存 | 不适用 | 保存别名 | 放弃 |

富文本保留 `Mod+B/I/U/K/Z`、`Mod+Shift+Z` 和 `Mod+Shift+V` 等平台标准组合。

### 8.5 通话

| 命令 | Windows/Linux | macOS | 约束 |
| --- | --- | --- | --- |
| 静音/取消静音 | `Ctrl+Shift+M` | `⌘+Shift+M` | 仅通话上下文 |
| 开关视频 | `Ctrl+Shift+O` | `⌘+Shift+O` | Web 能力需验证 |
| 举手/放下 | `Ctrl+Shift+K` | `⌘+Shift+K` | 仅通话上下文 |
| 结束通话 | `Ctrl+Shift+H` | `⌘+Shift+H` | 需明确焦点和冲突策略 |

通话键必须在 Windows、macOS、Web 和桌面端完成实机冲突验证后才能默认启用。

## 9. 设置与可发现性

第一阶段提供：

- “启用应用快捷键”：默认开启；
- “启用无修饰单键快捷键”：默认开启，可单独关闭。

帮助面板必须：

- 从注册表动态生成；
- 按全局、导航、Board、Chat、编辑器、通话分组；
- 默认显示当前上下文，允许切换“全部”；
- 按平台显示 `Ctrl` 或 `⌘`；
- 标记桌面专用、当前不可用和已关闭；
- 支持搜索动作；
- 说明单键在输入框中不生效；
- 可由键盘和可见按钮打开。

设置默认存储为客户端设备偏好，存储键只能使用 v1。第一阶段不写入 Arkret 协议 account-data。

## 10. 分阶段实施

### Phase 0：纠正现状漂移

- [x] 帮助显示 `Enter` 发送，并标记 `Mod+Enter` 为兼容键。
- [x] 明确当前 `Mod+F` 是全局消息搜索。
- [x] 合并重复的全局快捷键监听 owner。
- [x] 添加 editable、IME 和 repeat 的全局保护。
- [x] `?` 与 `Mod+/` 打开同一帮助。

### Phase 1：统一基础设施

- [ ] 实现 `ShortcutRegistry`、平台 binding 和作用域模型。
- [ ] 让唯一分发器从注册表匹配，而不是维护手写键位分支。
- [ ] 实现覆盖 input、textarea、select、contenteditable、textbox 和编辑器的统一 editable guard。
- [ ] 实现显式可关闭层级栈和焦点恢复。
- [ ] 帮助、tooltip 与命令面板从注册表生成。
- [ ] 实现应用快捷键和无修饰单键两个设置。
- [ ] 迁移现有全局、Chat 和表单命令。
- [ ] 添加绑定冲突、平台显示、IME、repeat、editable 和 availability 单元测试。

### Phase 2：Chat

- [ ] 消息列表 roving focus。
- [ ] 实现 `↑` 编辑最近消息的严格条件。
- [ ] 实现聚焦消息的 `R`、`E`、`+`、`Enter` / `→`。
- [ ] 完成当前会话 `Mod+F` 和全局 `Mod+Shift+F` 迁移。
- [ ] mention、emoji、slash command 统一接入局部作用域与 `Escape` 栈。

### Phase 3：Board 与 Card

- [ ] Card/列键盘选择模型、可见焦点环和读屏描述。
- [ ] 实现导航、打开、创建、编辑、评论和分配命令。
- [ ] 命令面板暴露移动、归档和删除等非单键动作。
- [ ] 为拖拽提供等价键盘移动方式。

### Phase 4：编辑器与通话

- [ ] 统一富文本标准组合和 slash quick insert。
- [ ] 统一多行表单的 `Mod+Enter` 提交约定。
- [ ] 完成通话快捷键四环境验证。
- [ ] 单独评估桌面端有限自定义键位。

## 11. 验收与测试

### 11.1 总体验收

- 快捷键执行、帮助、tooltip 和命令面板只有一个绑定数据源。
- 任一按键最多执行一个命令。
- 无修饰单键在所有编辑表面和输入法合成期间不生效。
- 发送、创建、归档和删除不响应自动重复事件。
- `Escape` 每次只关闭最内层状态并恢复合理焦点。
- Windows/Linux 与 macOS 显示正确修饰键。
- Web 不接管保留的浏览器快捷键。
- 快捷键可整体关闭，单键可单独关闭。
- 不可用或无权限命令不执行，帮助不谎报。
- 私聊不展示 mention 命令。
- 所有鼠标动作仍有键盘可达路径。

### 11.2 单元测试

- binding 归一化与平台显示；
- 作用域优先级；
- 同优先级冲突；
- editable、composition、repeat 策略；
- `Escape` 栈与焦点恢复目标；
- availability、权限与会话类型过滤；
- 帮助条目等于当前可发现注册项。

### 11.3 Playwright

- `?` / `Mod+/` 打开帮助；
- 输入框输入 `?`、`/`、`C` 不触发全局命令；
- composition 事件不发送；
- Chat 的 `Enter`、`Shift+Enter`、`Mod+Enter`；
- 当前搜索与全局搜索；
- Dialog、popover、mention picker 的 `Escape` 顺序；
- Board 键盘选择、打开、创建和编辑；
- 关闭设置后的行为；
- macOS/Windows 标签快照；
- 页面切换后不存在重复全局监听器。

### 11.4 实机

- Web 与桌面 WebView 分发一致；
- 权限或 feature profile 改变后帮助即时更新；
- 写命令只提交一次真实 Event；
- Windows、macOS 和国际键盘布局；
- 屏幕阅读器与主要区域导航。

## 12. 风险与约束

- `Mod+F` 迁移会改变现有习惯，必须与上下文搜索、帮助和发行说明同批交付。
- editable 识别失败会破坏普通输入；编辑器适配必须作为注册表迁移门槛。
- capture 阶段的全局 listener 会抢在局部组件前执行；统一分发器必须使用允许局部先消费的事件顺序，或通过明确的作用域桥接实现等价行为。
- 自定义键位会引入冲突解析、同步和无障碍复杂度，不进入 Phase 1。
- 国际键盘上 `?`、`+`、`/` 的产生方式不同，字符命令不得绑定固定物理位置。
- 快捷键写操作必须复用现有动作、权限检查和确认流程，不能建立旁路。

## 13. 完成定义

本文作为统一键盘快捷键的已接受设计记录。Phase 0 的现状纠偏完成不代表完整功能完成；Phase 1–4 必须按本文的验收条件分别交付。任何新增快捷键在合入前都必须：

1. 具有稳定命令 ID 和明确作用域；
2. 注册到唯一数据源；
3. 定义 editable、composition、repeat 和权限策略；
4. 在帮助和命令面板中自动反映；
5. 通过冲突测试和对应端到端测试。
