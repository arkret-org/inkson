//! Audit view — read-only inspector for audited E2EE events.
//!
//! Surfaces `ak.audit.accessed` from the local raw-operation log, so
//! administrators / users can verify the audit channel is firing under the
//! active policy.
//!
//! Writing new audit events is owned by the SDK / reducer path; this view
//! does not emit anything.

use std::rc::Rc;

use arkret_wire::event_kind_str;
use glory::Scope;
use serde_json::Value;

use crate::presentation::{InksonContext, View};
use crate::views::helpers::short_protocol_id;
use crate::views::settings::widgets::*;

#[derive(Clone, Debug, PartialEq)]
struct AuditRow {
    kind: String,
    realm_id: Option<String>,
    target_event_id: Option<String>,
    reader_device: Option<String>,
    operation_id: String,
}

fn extract_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned())
}

fn classify_audit_row(operation_id: &str, body: &Value) -> Option<AuditRow> {
    let kind = extract_string(body, "kind")?;
    if kind.as_str() != event_kind_str::AUDIT_ACCESSED {
        return None;
    }
    Some(AuditRow {
        kind,
        realm_id: extract_string(body, "realm_id"),
        target_event_id: extract_string(body, "target_event_id")
            .or_else(|| extract_string(body, "source_event_id")),
        reader_device: extract_string(body, "reader_device"),
        operation_id: operation_id.to_owned(),
    })
}

pub fn page(scope: &Scope, context: Rc<InksonContext>, _route: crate::routes::Route) -> View {
    let revision = context.state_revision;
    let locale = context.locale;
    let source = scope.bond(move || (revision.get(), locale.get()));
    let render = context.clone();
    reactive(source, move |scope, _| {
        let context = render.clone();
        let state = context.snapshot();
        let rows: Vec<_> = state
            .raw_operations
            .iter()
            .filter_map(|record| classify_audit_row(&record.operation_id, &record.payload))
            .collect();
        let attested = rows
            .iter()
            .filter(|row| row.kind == event_kind_str::AUDIT_ACCESSED)
            .count();
        let metric = |title: &str, count: String, key: &str, hint: &str| {
            stack(
                "metric",
                vec![
                    paragraph("audit-metric-label", context.translated(scope, title)),
                    paragraph(key, count),
                    paragraph("muted", context.translated(scope, hint)),
                ],
            )
        };
        let mut children = vec![stack(
            "event",
            vec![
                line(
                    "event-head",
                    vec![
                        plain(context.translated(scope, "audit.title")),
                        crate::components::help_tip(
                            scope,
                            context.clone(),
                            crate::components::HelpTipProps {
                                text: context.tr("audit.help"),
                            },
                        ),
                    ],
                ),
                line(
                    "metric-grid",
                    vec![
                        metric(
                            "audit.access_events",
                            attested.to_string(),
                            "audit-accessed-count",
                            "audit.access_events_hint",
                        ),
                        metric(
                            "audit.total_observed",
                            rows.len().to_string(),
                            "audit-total-count",
                            "audit.total_observed_hint",
                        ),
                    ],
                ),
            ],
        )];
        if rows.is_empty() {
            children.push(crate::components::empty_state(
                scope,
                context.clone(),
                crate::components::EmptyStateProps {
                    title: context.tr("audit.empty_title"),
                    kind: crate::components::EmptyStateKind::Empty,
                    message: Some(context.tr("audit.empty_message")),
                    badge_override: None,
                    test_id: Some("audit-empty".to_owned()),
                },
            ));
        }
        for row in rows {
            let mut header = vec![paragraph("badge", row.kind)];
            if let Some(realm) = row.realm_id {
                header.push(paragraph("mono audit-row-realm", short_protocol_id(&realm)));
            }
            let mut details = vec![line("event-head", header)];
            if let Some(target) = row.target_event_id {
                details.push(paragraph(
                    "muted",
                    format!("target {}", short_protocol_id(&target)),
                ));
            }
            if let Some(reader) = row.reader_device {
                details.push(paragraph(
                    "muted",
                    format!("reader {}", short_protocol_id(&reader)),
                ));
            }
            details.push(paragraph(
                "muted mono audit-row-op",
                format!("op {}", short_protocol_id(&row.operation_id)),
            ));
            children.push(stack("event audit-row", details));
        }
        stack("timeline audit-panel", children)
    })
}
#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{AuditRow, classify_audit_row};

    #[test]
    fn classifies_audit_accessed() {
        let row = classify_audit_row(
            "op-1",
            &json!({
                "kind": "ak.audit.accessed",
                "realm_id": "ak:realm:Af1zqB3_Jrboro34y4gO5sGw_9WdcaJpJ0RFj0J3Czok",
                "target_event_id": "ak:event:ANOufzo30HjlW4S8eBowzzay9mI2anxKRM5l1AUQ1pDE",
                "reader_device": "did:key:zDevice",
            }),
        )
        .expect("should classify");
        assert_eq!(row.kind, "ak.audit.accessed");
        assert_eq!(
            row.realm_id.as_deref(),
            Some("ak:realm:Af1zqB3_Jrboro34y4gO5sGw_9WdcaJpJ0RFj0J3Czok")
        );
        assert_eq!(
            row.target_event_id.as_deref(),
            Some("ak:event:ANOufzo30HjlW4S8eBowzzay9mI2anxKRM5l1AUQ1pDE")
        );
    }

    #[test]
    fn ignores_non_audit_kinds() {
        let none = classify_audit_row(
            "op-3",
            &json!({
                "kind": "ak.message.create",
                "realm_id": "ak:realm:Af1zqB3_Jrboro34y4gO5sGw_9WdcaJpJ0RFj0J3Czok",
            }),
        );
        assert!(none.is_none());
    }

    #[test]
    fn returns_none_when_kind_missing() {
        let none: Option<AuditRow> = classify_audit_row("op-4", &json!({"foo": "bar"}));
        assert!(none.is_none());
    }
}
