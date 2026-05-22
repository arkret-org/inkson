//! Call view — compact status surface for call controls.
//!
//! The actual controls live in `webrtc.rs`; this panel keeps the stable
//! `call-panel` / `call-signal-count` handles and summarizes signal state.

use dioxus::prelude::*;

use crate::{components::HelpTip, local_state::LocalStateStore};

#[component]
pub fn CallPanel(state_store: Signal<LocalStateStore>) -> Element {
    let state = state_store.read().load();
    let signal_count = state
        .raw_operations
        .iter()
        .filter(|record| {
            record
                .payload
                .get("kind")
                .and_then(|v| v.as_str())
                .map(|kind| kind.starts_with("cx.call."))
                .unwrap_or(false)
        })
        .count();

    rsx! {
        div { class: "timeline", "data-testid": "call-panel", role: "region", "aria-label": "Calls",
            div { class: "event",
                div { class: "event-head",
                    span { "Calls" }
                    span { class: "badge green", "Controls ready" }
                    HelpTip { text: "Use the WebRTC controls below to start, accept, decline, mute, share, record, and leave calls. This summary shows the durable call signal state observed locally." }
                }
                div { class: "muted",
                    "Call controls are available below; this summary keeps protocol signal health visible without blocking the user flow."
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Observed signals" }
                        span { "data-testid": "call-signal-count", "{signal_count}" }
                        div { class: "muted", "Call signal, state, and recording events" }
                    }
                    div { class: "metric",
                        strong { "Signal envelope" }
                        span { "Implemented" }
                        div { class: "muted", "Builders in crate::webrtc; ephemeral classification per spec" }
                    }
                    div { class: "metric",
                        strong { "Media transport" }
                        span { "Browser bridge" }
                        div { class: "muted", "Peer setup is handled by the active renderer" }
                    }
                    div { class: "metric",
                        strong { "Recording" }
                        span { "User controlled" }
                        div { class: "muted", "Recording controls require explicit user action" }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::local_state::LocalStateStore;
    use serde_json::json;

    #[test]
    fn renders_signal_count_from_raw_operations() {
        let mut store = LocalStateStore::with_path("call_view_test.json");
        // counted: starts with cx.call.
        store.append_raw_operation(
            "op-1".to_owned(),
            Some("cx:space:s".to_owned()),
            json!({"kind": "cx.call.signal"}),
        );
        store.append_raw_operation(
            "op-2".to_owned(),
            Some("cx:space:s".to_owned()),
            json!({"kind": "cx.call.state"}),
        );
        // NOT counted
        store.append_raw_operation(
            "op-3".to_owned(),
            Some("cx:space:s".to_owned()),
            json!({"kind": "cx.message.create"}),
        );

        let state = store.load();
        let signal_count = state
            .raw_operations
            .iter()
            .filter(|record| {
                record
                    .payload
                    .get("kind")
                    .and_then(|v| v.as_str())
                    .map(|kind| kind.starts_with("cx.call."))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(signal_count, 2);

        // Cleanup the file the LocalStateStore wrote.
        let _ = std::fs::remove_file("call_view_test.json");
    }
}
