use dioxus::prelude::*;

pub mod right_panel;

pub use right_panel::RightPanel;

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
