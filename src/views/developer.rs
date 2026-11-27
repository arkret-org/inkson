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
    let diagnostics = reactive(source, move |scope, _| {
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
            event_children.push(paragraph(
                "muted developer-raw-events-empty",
                context.translated(scope, "developer.events.empty"),
            ));
        } else {
            event_children.push(paragraph(
                "muted",
                context.translated_args(scope, "developer.events.preview", move || {
                    vec![("count", count.to_string()), ("total", total.to_string())]
                }),
            ));
            event_children.extend(rows);
        }
        Box::new(glory::ui::fragment(vec![
            paragraph(
                "muted developer-diagnostics-intro",
                context.translated(scope, "developer.diagnostics_intro"),
            ),
            stack(
                "event developer-protocol-version",
                vec![
                    line(
                        "event-head",
                        vec![
                            plain(context.translated(scope, "developer.section.protocol_version")),
                            paragraph("badge", PROTOCOL_VERSION),
                        ],
                    ),
                    paragraph(
                        "muted",
                        context.translated(scope, "developer.protocol_version.description"),
                    ),
                ],
            ),
            stack("event developer-raw-events", event_children),
            session_diagnostics(scope, &context),
        ])) as View
    });
    stack(
        "timeline developer-tools-panel",
        vec![diagnostics, super::dashboard::client_status(scope, context)],
    )
}

fn session_diagnostics(scope: &Scope, context: &InksonContext) -> View {
    let signer = crate::event_signer::signer_status()
        .map(|status| status.signer_did)
        .unwrap_or_else(|| "—".into());
    stack(
        "event settings-session-diagnostics",
        vec![
            line(
                "event-head",
                vec![plain(
                    context.translated(scope, "settings.session_diagnostics.title"),
                )],
            ),
            stack(
                "metric-grid",
                vec![
                    stack(
                        "metric settings-proof-mode",
                        vec![
                            plain(context.translated(scope, "settings.proof_mode.label")),
                            plain(crate::operation::current_proof_mode().label_en()),
                        ],
                    ),
                    stack(
                        "metric settings-signer-info",
                        vec![
                            plain(context.translated(scope, "settings.signer.label")),
                            paragraph("settings-signer-did", short_protocol_id(&signer)),
                            paragraph("sr-only settings-signer-identity", signer),
                        ],
                    ),
                ],
            ),
        ],
    )
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
