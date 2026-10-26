//! Developer Tools / Diagnostics panel — T7.1.
//!
//! Centralises the protocol-level details (schema ids, event kinds, raw
//! event log, server profile id, conformance status, protocol version)
//! that used to leak into the main flow. End-user views render friendly
//! product language; admins / operators / developers consult this panel
//! when they need to see the canonical identifiers.
//!
//! The panel is intentionally a thin protocol inspector. Audit rows are
//! surfaced by the dedicated "Audit log" settings section so the two
//! operator tasks remain visually distinct.

use std::rc::Rc;

use glory::Scope;

use crate::presentation::{InksonContext, View};
use crate::views::helpers::short_protocol_id;
use crate::views::settings::widgets::*;

/// Default protocol version advertised by inkson — kept here so the
/// developer panel can surface a stable label until the conformance
/// module exports a canonical constant.
const PROTOCOL_VERSION: &str = "1.0";

const RAW_EVENT_PREVIEW_LIMIT: usize = 50;

pub fn page(scope: &Scope, context: Rc<InksonContext>, _route: crate::routes::Route) -> View {
    let revision = context.state_revision;
    let locale = context.locale;
    let source = scope.bond(move || (revision.get(), locale.get()));
    let render = context.clone();
    reactive(source, move |scope, _| {
        let context = render.clone();
        let state = context.snapshot();
        let total = state.raw_operations.len();
        let count = total.min(RAW_EVENT_PREVIEW_LIMIT);
        let mut rows = Vec::new();
        for record in state
            .raw_operations
            .iter()
            .rev()
            .take(RAW_EVENT_PREVIEW_LIMIT)
        {
            let kind = record
                .payload
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .or_else(|| {
                    record
                        .payload
                        .get("type")
                        .and_then(serde_json::Value::as_str)
                })
                .unwrap_or("(unknown)");
            rows.push(stack(
                "event developer-raw-event-row",
                vec![line(
                    "event-head",
                    vec![
                        paragraph("badge", kind.to_owned()),
                        paragraph("mono muted", short_protocol_id(&record.operation_id)),
                    ],
                )],
            ));
        }
        let mut event_children = vec![line(
            "event-head",
            vec![
                plain(context.translated(scope, "developer.section.events")),
                paragraph("badge", total.to_string()),
            ],
        )];
        if rows.is_empty() {
            event_children.push(crate::components::empty_state(
                scope,
                context.clone(),
                crate::components::EmptyStateProps {
                    title: context.tr("developer.section.events"),
                    kind: crate::components::EmptyStateKind::Empty,
                    message: Some("No raw operations recorded yet.".to_owned()),
                    badge_override: None,
                    test_id: Some("developer-raw-events-empty".to_owned()),
                },
            ));
        } else {
            event_children.push(paragraph(
                "muted",
                format!("Showing {count} of {total} raw operations (newest first)."),
            ));
            event_children.extend(rows);
        }
        stack(
            "timeline developer-tools-panel",
            vec![
                stack(
                    "event",
                    vec![
                        line(
                            "event-head",
                            vec![
                                plain(context.translated(scope, "developer.title")),
                                paragraph("muted", context.translated(scope, "developer.subtitle")),
                                crate::components::help_tip(
                                    scope,
                                    context.clone(),
                                    crate::components::HelpTipProps {
                                        text: context.tr("developer.hint"),
                                    },
                                ),
                            ],
                        ),
                        paragraph("muted", context.translated(scope, "developer.hint")),
                    ],
                ),
                stack(
                    "event developer-protocol-version",
                    vec![
                        line(
                            "event-head",
                            vec![
                                plain(
                                    context.translated(scope, "developer.section.protocol_version"),
                                ),
                                paragraph("badge", PROTOCOL_VERSION),
                            ],
                        ),
                        paragraph(
                            "muted",
                            "Negotiated protocol version reported to /server/describe.",
                        ),
                    ],
                ),
                stack("event developer-raw-events", event_children),
            ],
        )
    })
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
