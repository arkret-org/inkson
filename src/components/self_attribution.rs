use dioxus::prelude::*;

#[component]
pub fn SelfAttributionBadge(class: Option<String>, test_id: Option<String>) -> Element {
    let class_name = match class {
        Some(extra) if !extra.trim().is_empty() => {
            format!("badge self-attribution-badge {}", extra.trim())
        }
        _ => "badge self-attribution-badge".to_owned(),
    };
    let test_id = test_id.unwrap_or_else(|| "self-attribution-badge".to_owned());

    rsx! {
        span {
            class: "{class_name}",
            "data-testid": "{test_id}",
            title: "This is your account",
            "ME"
        }
    }
}
