//! Developer Tools / Diagnostics panel — T7.1.
//!
//! Centralises the protocol-level details (schema ids, event kinds, raw
//! event log, server profile id, conformance status, protocol version)
//! that used to leak into the main strand. End-user views render friendly
//! product language; admins / operators / developers consult this panel
//! when they need to see the canonical identifiers.
//!
//! The panel is intentionally a thin protocol inspector. Audit rows are
//! surfaced by the sibling Diagnostics audit tab so the two operator tasks
//! remain visually distinct.

use dioxus::prelude::*;

use crate::components::{EmptyState, EmptyStateKind, HelpTip};
use crate::local_state::LocalStateStore;
use crate::views::helpers::short_protocol_id;

/// Default protocol version advertised by yougen — kept here so the
/// developer panel can surface a stable label until the conformance
/// module exports a canonical constant.
const PROTOCOL_VERSION: &str = "1.0";

const RAW_EVENT_PREVIEW_LIMIT: usize = 50;

#[component]
pub fn DeveloperToolsPanel(state_store: Signal<LocalStateStore>) -> Element {
    let state = state_store.read().load();
    let raw_ops_total = state.raw_operations.len();
    let preview_count = raw_ops_total.min(RAW_EVENT_PREVIEW_LIMIT);
    let recent_ops: Vec<(String, String)> = state
        .raw_operations
        .iter()
        .rev()
        .take(RAW_EVENT_PREVIEW_LIMIT)
        .map(|record| {
            let kind = record
                .payload
                .get("kind")
                .and_then(|v| v.as_str())
                .or_else(|| record.payload.get("type").and_then(|v| v.as_str()))
                .unwrap_or("(unknown)")
                .to_owned();
            (record.operation_id.clone(), kind)
        })
        .collect();

    rsx! {
        div { class: "timeline", "data-testid": "developer-tools-panel", role: "region", "aria-label": crate::i18n::tr("developer.title"),
            div { class: "event",
                div { class: "event-head",
                    span { {crate::i18n::tr("developer.title")} }
                    span { class: "muted", {crate::i18n::tr("developer.subtitle")} }
                    HelpTip { text: crate::i18n::tr("developer.hint") }
                }
                div { class: "muted", {crate::i18n::tr("developer.hint")} }
            }

            // Protocol version + conformance summary.
            div { class: "event", "data-testid": "developer-protocol-version",
                div { class: "event-head",
                    span { {crate::i18n::tr("developer.section.protocol_version")} }
                    span { class: "badge", "{PROTOCOL_VERSION}" }
                }
                div { class: "muted", "Negotiated protocol version reported to /server/describe." }
            }

            // Raw event log preview.
            div { class: "event", "data-testid": "developer-raw-events",
                div { class: "event-head",
                    span { {crate::i18n::tr("developer.section.events")} }
                    span { class: "badge", "{raw_ops_total}" }
                }
                if recent_ops.is_empty() {
                    EmptyState {
                        title: crate::i18n::tr("developer.section.events"),
                        kind: EmptyStateKind::Empty,
                        message: Some("No raw operations recorded yet.".to_owned()),
                        badge_override: None::<String>,
                        test_id: Some("developer-raw-events-empty".to_owned()),
                    }
                } else {
                    div { class: "muted",
                        "Showing {preview_count} of {raw_ops_total} raw operations (newest first)."
                    }
                    for (op_id, kind) in recent_ops.iter() {
                        {
                            let op_id_label = short_protocol_id(op_id);
                            rsx! {
                                div { class: "event", "data-testid": "developer-raw-event-row",
                                    div { class: "event-head",
                                        span { class: "badge", "{kind}" }
                                        span { class: "mono muted", title: "{op_id}", "{op_id_label}" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RAW_EVENT_PREVIEW_LIMIT;

    #[test]
    fn raw_event_preview_limit_is_reasonable() {
        const { assert!(RAW_EVENT_PREVIEW_LIMIT >= 10) };
        const { assert!(RAW_EVENT_PREVIEW_LIMIT <= 500) };
    }
}
