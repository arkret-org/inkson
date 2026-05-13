# 界面整改任务清单

来源：`_report.md`  
目标：把当前 UI 从“演示页 / 协议工具页拼盘”收敛到符合 `contrix-spec` 的 Space / View / Place / Flow 信息架构。

## P0

### [x] T01 重构全局导航模型
对应报告：R01、R02、R03  
优先级：P0  
目标文件：`src/app.rs`、`src/routes.rs`、必要时新增空间壳层组件文件  
整改要求：将当前把 `Timeline`、`Kanban`、`Chat`、`Files` 当作并列产品模块的导航方式，改为“Space 为一级上下文，View/renderer 为二级切换”。桌面侧边栏和移动端菜单都必须遵守同一模型。  
验收标准：
1. 顶级主导航不再把 `Kanban`、`Chat`、`Files` 作为与 `Space` 并列的一线入口。
2. 空间入口进入的是“该 Space 的默认视图”或“最近使用视图”，而不是硬编码进入 Timeline。
3. 同一 Space 内切换 board/list/chat/document 时不丢失当前 Space 上下文。
4. 桌面导航与移动导航的一级信息架构一致，只允许密度不同，不允许语义不同。

### [x] T02 引入 Space 内 View 切换壳层
对应报告：R01、R02  
优先级：P0  
目标文件：`src/app.rs`、`src/routes.rs`、`src/views/timeline.rs`、`src/views/kanban.rs`、`src/views/chat.rs`、`src/views/document.rs`  
整改要求：为 Space 页面增加统一的 view shell。Timeline、board、chat、document 都应成为同一 Space 下的不同 projection / renderer，而不是四套平行页面心智。  
验收标准：
1. 每个 Space 至少有一个明确的默认视图来源。
2. 视图切换器显示的是 View/renderer，而不是“切换到另一个产品”。
3. Space breadcrumb、标题、返回路径始终以 Space 为主，而不是以 renderer 名称为主。
4. `/timeline/:space_id`、`/kanban/:space_id`、`/chat/:space_id`、`/document/:space_id` 的语义被统一，避免继续强化错误心智。

### [x] T03 清理错误的 Track / Discussion 文案
对应报告：R09  
优先级：P0  
目标文件：`src/views/chat.rs`  
整改要求：删除或改写所有把 Track 说成独立 membership / access 域的内容，尤其是 `cx.flow.track.member` 一类已过时表述。Discussion 独立访问域只能通过 `discussion_space_ref` 解释。  
验收标准：
1. 页面内不再出现 `cx.flow.track.member`、`locked discussions fail closed` 这类过时模型文案。
2. Track 统一被描述为展示 / 时间线分段标识。
3. 需要独立访问域时，页面只使用 child Space / `discussion_space_ref` 说明。
4. 同页所有说明文案彼此一致，不再出现“上半页正确、下半页过时”的冲突。

### [x] T04 补齐或收束所有保留路由的入口策略
对应报告：R03  
优先级：P0  
目标文件：`src/app.rs`、`src/routes.rs`  
整改要求：对 `Recovery`、`Applets`、`Onboarding`、`Quarantine`、`VerifyDevice`、`Call` 等保留路由，逐一决定其入口位置。要么纳入合理菜单/上下文入口，要么明确降为仅深链入口并在代码上避免误导性主路由暴露。  
验收标准：
1. 每个保留 route 都有明确的入口策略文档化。
2. 不再存在“已注册主路由但在 UI 中几乎不可达”的灰色页面。
3. 主导航只保留高频、稳定、用户可理解的入口。
4. 管理型、恢复型、安装型、一次性流程型入口与常用协作入口分层展示。

## P1

### [x] T05 拆分并重命名遗留 `Product` 页面
对应报告：R04  
优先级：P1  
目标文件：`src/routes.rs`、`src/app.rs`、`src/views/setup.rs`  
整改要求：当前遗留 `Product` 页面同时包含 Account、Contacts、Space lifecycle、Message persistence，且导航标题叫 `Create Space`。必须拆成单一职责页面，并让路由名、菜单名、页面名一致。  
验收标准：
1. “Create Space” 只负责建空间，或改名为更准确的聚合入口。
2. Account / login 流程回到登录、Onboarding 或 Settings。
3. Contacts / handle / actor 相关能力回到 Directory 或独立 People 页面。
4. Message persistence / commit / sync token 之类开发运维内容移出普通业务页。

### [x] T06 重新划分 Settings
对应报告：R05  
优先级：P1  
目标文件：`src/views/settings.rs`、`src/app.rs`  
整改要求：Settings 应主要承载 actor-private 偏好、账号上下文、设备与通知配置；`Release gates` / build diagnostics / 审计类内容应迁出到 `Readiness` 或独立 diagnostics 面。  
验收标准：
1. Settings 目录树只保留“用户会持续回访的配置项”。
2. `Diagnostics` 不再与 Theme、Privacy、Push 并列。
3. actor-private 偏好分组清晰，例如 UI state、语言、私有过滤、本地显示偏好。
4. 与 Space 共享事实无关的个人偏好不再和管理/调试面混在一起。

### [x] T07 重新定义 Dashboard 的职责
对应报告：R06  
优先级：P1  
目标文件：`src/views/dashboard.rs`  
整改要求：Dashboard 应回答“现在我该去哪里、该处理什么”，而不是把 Workspace diagnostics、Protocol health、Inbox、Recent Spaces、Recent Flows 全部并排堆在首页。  
验收标准：
1. 首页首屏以最近空间、待办、未读、继续工作入口为主。
2. `Workspace State`、`Protocol Health` 迁到次级运维面或折叠在非主路径。
3. 首页 CTA 与主导航模型一致，不再继续强化遗留 `Product` 这个过载入口。
4. 用户第一次进入首页时可以直接理解“协作入口”与“协议诊断入口”的差异。

### [x] T08 拆分 Space Admin
对应报告：R08  
优先级：P1  
目标文件：`src/views/space_admin.rs`、`src/routes.rs`、`src/app.rs`  
整改要求：把当前单页上的成员管理、Invite、Join Policy、History Visibility、Discovery、MLS、Capability grant/revoke、Moderation、Federation、Conflict repair、Danger Zone 拆成明确子页或分组。  
验收标准：
1. 日常管理员任务与低频危险运维任务分开。
2. Space 级配置、Organization 级治理、Federation 信任、协议修复工具不再混在同一滚动页面。
3. 支持通过 `/space/:space_id/admin/:section` 或等价方式进入具体管理子面。
4. 任一子页的标题都能明确说明其责任边界。

### [x] T09 收敛 Directory 的职责边界
对应报告：R07  
优先级：P1  
目标文件：`src/views/directory.rs`、`src/views/applets.rs`、必要时新增独立页面  
整改要求：Directory 保留“目录发现 / 实体查找”职责；`Applets`、`Protocol Objects`、可能的调试型对象浏览器从统一检索页拆出。  
验收标准：
1. `Spaces`、`Organizations`、`Actors`、`Handles` 仍可共存，但语义说明清楚。
2. `Applets` 不再只是 Directory 的一个普通 tab，而是有自己明确的产品/工具定位。
3. `Objects` 若保留，必须改为开发者/诊断语义，不与普通目录查询混淆。
4. 页面文案继续坚持 discoverability、join_rule、history_visibility 三轴独立。

## P2

### [x] T10 清理导航中的空分组和重复入口
对应报告：R03、R10  
优先级：P2  
目标文件：`src/app.rs`  
整改要求：去掉长期为空的 `Cross-organization`、`Personal Spaces` 占位，或改为真正可工作的懒加载分组；同时清理 `Search / Directory` 与 `Directory` 的重复表达。  
验收标准：
1. 主导航不再长期展示“空壳分组”。
2. 相同功能不再用两套名称并列出现。
3. 占位分组若必须存在，必须带明确触发条件和进入路径。

### [x] T11 统一标签、标题和 breadcrumb 词汇
对应报告：R01、R04、R10  
优先级：P2  
目标文件：`src/app.rs`、`src/routes.rs`、相关 view 文件  
整改要求：统一使用 spec 认可的对象词汇，如 Space、View、Place、Discussion、Document；避免把 renderer 名称包装成独立产品名。  
验收标准：
1. `route_label()` 与页面主标题不再制造错误对象边界。
2. `Kanban`、`Chat`、`Files` 这类名称若继续存在，必须明确是 view/renderer，而不是一级产品。
3. 用户从标题和 breadcrumb 就能理解自己处于“哪个 Space 的哪个视图”。

### [x] T12 建立一轮 IA 回归检查
对应报告：全量  
优先级：P2  
目标文件：`_report.md`、`_todos.md`、必要时新增内部检查文档  
整改要求：在本轮重构完成后，按 contrix-spec 再做一次专门的 IA 审查，确认没有把 renderer、track、Place、Organization、Federation 等边界重新混淆。  
验收标准：
1. 所有 P0 / P1 项完成后有一次书面复查。
2. 复查结论明确标注“仍不符 / 基本符合 / 符合”。
3. 后续新增页面进入主导航前，必须先过同一检查清单。
