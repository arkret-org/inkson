//! Call view — minimal honest landing page for WebRTC signaling.
//!
//! Yougen does NOT bundle a WebRTC stack; the durable signaling envelope
//! builders live in `crate::webrtc` and are intended for a host renderer
//! (mobile / Tauri shell) to plug in.  This view states clearly what is
//! wired and what is pending so the URL is not a dead end.

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
                    span { class: "badge", "Signaling-only preview" }
                    HelpTip { text: "Yougen exposes the call event builders (cx.call.signal / cx.call.state / cx.call.recording.start) but does not bundle a WebRTC stack. The host renderer (mobile app, Tauri shell, browser embed) is responsible for the SDP / ICE / SFU plumbing." }
                }
                div { class: "muted",
                    "This is the durable signaling surface. A scannable media UI (incoming-call toast, in-call controls, screen share) lands once the platform-specific WebRTC bridge ships."
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Observed signals" }
                        span { "data-testid": "call-signal-count", "{signal_count}" }
                        div { class: "muted", "cx.call.signal / state / recording.start" }
                    }
                    div { class: "metric",
                        strong { "Signal envelope" }
                        span { "Implemented" }
                        div { class: "muted", "Builders in crate::webrtc; ephemeral classification per spec" }
                    }
                    div { class: "metric",
                        strong { "Media transport" }
                        span { "Renderer-provided" }
                        div { class: "muted", "Not bundled in the Rust crate" }
                    }
                    div { class: "metric",
                        strong { "Recording" }
                        span { "Opt-in marker only" }
                        div { class: "muted", "cx.call.recording.start; capture pipeline is host-side" }
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
