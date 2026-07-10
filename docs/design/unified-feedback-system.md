# Design: 统一反馈体系（废除全局 status 字符串）

- 状态：提案（待评审）
- 来源：`_ux_review/README.md` H3（2026-07-03 全站 UX 审计，高危）
- 影响面：inkson 全站（app shell、所有 views）

## 1. 背景与证据

当前 inkson 的用户反馈至少有 **5 套并行机制**，语义边界不清：

| 机制 | 位置 | 用途现状 |
|---|---|---|
| 全局 `status: Signal<String>` | `app/mod.rs` 数十处、`app/sidebar.rs:85/115`、`realm_admin/*` 40+ 处 | 错误、成功、进度、导航提示全塞一行字符串，大多硬编码英文 |
| `PolicyDenyBanner` | `components/policy_deny_banner.rs` | 仅 HTTP 403 policy/capability denied，8 秒自动消失 |
| `CircleErrorToast` | `components/circle_error_toast.rs` | 仅 AKP-0007 Circle 错误，单条覆盖不堆叠 |
| `.event.error-banner` / `.badge.red|amber` | 各 view 内散落 | 持久告警（notary_paused、covered_seals 等） |
| `.form-hint-warn` / `.field .err` | 表单 | 字段级内联错误 |

核心问题：
1. **全局 status 无优先级、无生命周期**——成功提示会覆盖未读的错误；显示位置在页面底部一行，用户几乎注意不到。
2. **同类事件走不同通道**——403 走 toast、Circle 错误走另一个 toast、其余错误走 status 字符串，风格与位置都不同。
3. **文案绕过 i18n**——status.set 的拼接字符串是硬编码重灾区（审计 H12）。

## 2. 目标与非目标

**目标**
- 三层反馈模型：**toast（瞬态操作结果）/ banner（持久状态）/ inline（字段错误）**，全站唯一入口。
- 废除全局 `status: Signal<String>`。
- 收编 PolicyDenyBanner、CircleErrorToast 为统一 toast host 的两种来源。
- 所有反馈文案强制走 i18n key。

**非目标**
- 不做视觉重设计（沿用现有 design token 与 toast/banner 样式类）。
- 不在本设计内完成全量 i18n 收口（属 H12 单独任务，此设计只保证新 API 不接受裸字符串以外的 escape hatch）。

## 3. 方案

### 3.1 新组件与 API（`src/components/feedback.rs`）

```rust
pub enum FeedbackSeverity { Success, Info, Warning, Error }

pub struct Toast {
    pub severity: FeedbackSeverity,
    /// i18n key; substitutions applied at render time.
    pub key: &'static str,
    pub args: Vec<(&'static str, String)>,
    /// Optional action button (e.g. Retry / Undo), i18n key + callback id.
    pub action: Option<ToastAction>,
}

// Context-provided handle, mirrors the existing I18nSignal pattern.
pub fn use_feedback() -> FeedbackHandle;   // handle.toast(...), handle.banner(...)
```

要点：
- **Toast host**：右上角堆叠（最多 3 条 + "还有 N 条"折叠），Success/Info 5 秒自动消失，Warning/Error 手动关闭或 10 秒；`aria-live="polite"`（Error 用 `assertive`）。testid：`toast-host` / `toast-item` / `toast-action`。
- **Banner slot**：app shell 顶部单槽位，按优先级抢占（离线 > 策略拒绝 > 会话过期 > 其他），持久显示直到条件解除。testid：`app-banner`。
- **参数化 i18n**：复用 T4 修复中验证过的 FormError 模式（key + args，渲染时 localize），杜绝调用侧拼接。注意 **`tr()` 不能在 Dioxus 运行时外调用**——所有 localize 都发生在 host 组件渲染时，业务层只传 key+args，这同时解决了单测 panic 问题。

### 3.2 收编既有机制

- `PolicyDenyBanner`（403）→ toast host 的 Warning 来源，保留其"从 API 层拦截"的产生方式。
- `CircleErrorToast`（AKP-0007）→ toast host 的 Error 来源；其"新错误覆盖旧错误"语义改为正常堆叠。
- `.event.error-banner` 类持久告警（notary_paused 等）→ 保留在各 view 内（它们是**内容**而非**反馈**），不收编，但文案 i18n 化归 H4/H12。
- 字段级 `.form-hint-warn` → 保持现状，即第三层。

### 3.3 迁移计划（四波，可分 PR）

1. **Wave 0**：落地 `feedback.rs` + toast host/banner slot 挂进 app shell；提供过渡适配器 `status_compat(status_signal)`——把旧 status 写入渲染成 Info toast，保证迁移期间无回归。
2. **Wave 1**：`app/mod.rs` + `app/sidebar.rs`（数十处 status.set → handle.toast，同时补 i18n key）。
3. **Wave 2**：`realm_admin/*`（40+ 处，与 H12 的 i18n 收口合并做）。
4. **Wave 3**：其余 views（settings/chat/kanban/contacts/…）；删除全局 status Signal 与适配器；CI 加 lint（grep `status.set(format!` 归零守门）。

### 3.4 cotest 影响

现有 e2e 少量断言 status 区文本（需 grep 确认清单）。迁移波次内同步改为断言 `toast-item` 文本或专用 testid。

## 4. 验收标准

- 全仓无 `status.set(` 面向用户字符串调用（grep 守门）。
- 一次操作失败 + 一次操作成功并发发生时，两条反馈都可见（不互相覆盖）。
- 离线 banner 与 toast 可同时存在、互不抢占。
- 所有 toast/banner 文案有 en+zh key；`cargo test --lib` 无新增失败。

## 5. 未决问题（评审时定）

1. Error toast 是否需要"复制详情"入口（把原始错误码/trace 放剪贴板）？（倾向：要，替代现在把协议错误拼进文案的做法。）
2. 撤销式 toast（Undo）是否纳入首期？它是"删除类操作免确认框"的前提（见 H2 三级确认规范），倾向首期只留接口不实现。
3. toast 队列溢出策略：折叠 vs 丢弃最旧。
