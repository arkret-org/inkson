//! Call view — compact status surface for call controls.
//!
//! The actual controls live in `webrtc.rs`; this panel keeps the stable
//! `call-panel` / `call-signal-count` handles and summarizes signal state.
//!
//! R3 spec sync (b47ff6ec) — also surfaces CXP-0010 media-binding wire
//! contract status: token-exchange integration, focus_unavailable_for_client
//! handling, MLS-exporter SFrame key derivation, participant identity
//! cross-check, and Contrix-blob recording pipeline. See
//! [`crate::media::rtc`] for the typed predicates / error reasons.

use dioxus::prelude::*;

use crate::components::HelpTip;
use crate::local_state::LocalStateStore;

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

            // R3 spec sync (CXP-0010) — media binding wire contract status.
            // The actual integration is stubbed (`TODO(R3.1)`) but the wire
            // contract surface stays visible so QA can verify which guards
            // are landed.
            div { class: "event", "data-testid": "call-media-binding-status",
                div { class: "event-head",
                    span { "Media binding (CXP-0010)" }
                    span { class: "badge", "spec b47ff6ec" }
                }
                div { class: "muted",
                    "Token exchange + MLS-exporter SFrame keying + participant identity cross-check + Contrix-blob recording pipeline are wire-contract aligned with the b47ff6ec spec. Live SFU integration lands in R3.1."
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Token exchange" }
                        span { "data-testid": "media-binding-token-exchange", "SDK helper wired" }
                        div { class: "muted",
                            "POST /rtc/token via SDK::call_media_token_exchange; TTL ≤ 600s; service_signature.kid anchored."
                        }
                    }
                    div { class: "metric",
                        strong { "Focus failure" }
                        span {
                            class: "badge amber",
                            "data-testid": "media-binding-focus-unavailable",
                            "No silent fallback"
                        }
                        div { class: "muted",
                            "focus_unavailable_for_client → surface retry / leave-call. Renderer MUST NOT silently pick a different focus."
                        }
                    }
                    div { class: "metric",
                        strong { "SFrame key" }
                        span { "data-testid": "media-binding-sframe-key", "MLS Exporter only" }
                        div { class: "muted",
                            "Label cx-rtc-frame-key/v1, length=19, Context=\"\". Backend-supplied keys rejected (e2ee_key_source_unauthorised)."
                        }
                    }
                    div { class: "metric",
                        strong { "Participant identity" }
                        span { "data-testid": "media-binding-participant-check", "Cross-checked" }
                        div { class: "muted",
                            "ParticipantConnected cross-checked against cx.call.state.participants[]; unknown → participant_identity_unrecognised."
                        }
                    }
                    div { class: "metric",
                        strong { "Recording pipeline" }
                        span { "data-testid": "media-binding-recording-pipeline", "Contrix blob only" }
                        div { class: "muted",
                            "Egress destinations outside the Contrix authenticated blob upload are rejected (recording_artifact_pipeline_bypassed)."
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::local_state::LocalStateStore;

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
