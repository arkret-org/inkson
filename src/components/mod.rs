use dioxus::prelude::*;

pub mod permission_pill;
pub mod right_panel;
pub mod write_state;

pub use permission_pill::{
    Discoverability, HistoryVisibility, JoinRule, PermissionPill, PermissionPillRow,
};
pub use right_panel::RightPanel;
pub use write_state::{WriteState, WriteStateExplainer, WriteStatePill};

// LazyLinkBadge is declared below.

#[component]
pub fn Metric(label: String, value: String) -> Element {
    rsx! {
        div { class: "metric",
            strong { "{label}" }
            span { "{value}" }
        }
    }
}

#[component]
pub fn StatusBadge(status: String, kind: Option<String>) -> Element {
    let cls = match kind.as_deref().unwrap_or("info") {
        "success" => "badge badge-success",
        "error" => "badge badge-error",
        "warning" => "badge badge-warning",
        _ => "badge badge-info",
    };
    rsx! {
        span { class: "{cls}", "{status}" }
    }
}

#[component]
pub fn EmptyState(message: String) -> Element {
    rsx! {
        div { class: "event",
            div { class: "event-head", span { "Empty" } span { "" } }
            div { class: "muted", "{message}" }
        }
    }
}

#[component]
pub fn ErrorBanner(message: String) -> Element {
    rsx! {
        div { class: "event error-banner",
            div { class: "event-head", span { "Error" } span { "" } }
            div { "{message}" }
        }
    }
}

#[component]
pub fn LoadingSpinner(label: Option<String>) -> Element {
    let text = label.unwrap_or_else(|| "Loading...".to_owned());
    rsx! {
        div { class: "event loading",
            div { class: "muted", "{text}" }
        }
    }
}

/// Cross-Space lazy_link badge.
///
/// 协议规则（`models/object-model-core.md` §2.4.1）：跨 Space Relation 的 `from_ref` / `to_ref`
/// 可指向其它 Space 的对象，但只发布引用事实，不复制内容、不授予读取权限。Sync / projection
/// 层不得因为源 Space 可见就 backfill 目标 Space 数据。本组件是 UI 上一致的提示。
#[component]
pub fn LazyLinkBadge(
    /// 目标 Space 的 opaque ref（可以是 sha256 摘要、cx:space:… ID 或省略）。
    target_ref: Option<String>,
    /// 简短理由：locked / external / restricted / quarantined。
    reason: Option<String>,
) -> Element {
    let reason_text = reason.unwrap_or_else(|| "locked".to_owned());
    let target_text = target_ref.unwrap_or_else(|| "opaque".to_owned());
    rsx! {
        span {
            class: "badge amber",
            "data-testid": "lazy-link-badge",
            "title": "object-model-core.md §2.4.1 — cross-Space lazy link",
            "🔒 lazy_link · {reason_text} · {target_text}"
        }
    }
}

#[component]
pub fn ActionButton(
    label: String,
    class_name: Option<String>,
    test_id: Option<String>,
    disabled: Option<bool>,
    onclick: EventHandler<MouseEvent>,
) -> Element {
    let cls = class_name.unwrap_or_else(|| "secondary".to_owned());
    let tid = test_id.unwrap_or_default();
    let dis = disabled.unwrap_or(false);
    rsx! {
        button {
            class: "{cls}",
            "data-testid": "{tid}",
            disabled: dis,
            onclick: move |evt| onclick.call(evt),
            "{label}"
        }
    }
}
