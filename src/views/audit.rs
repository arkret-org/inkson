//! Audit view — read-only inspector for audited E2EE events.
//!
//! Surfaces `cx.audit.accessed` (attested-audit reads) and
//! `cx.audit.ryw_receipt` (disclosed-audit write receipts) from the local
//! raw-operation log, so administrators / users can verify the audit
//! channel is firing under the active policy.
//!
//! Writing new audit events is owned by the SDK / reducer path; this view
//! does not emit anything.

use dioxus::prelude::*;
use serde_json::Value;

use crate::components::{EmptyState, EmptyStateKind, HelpTip};
use crate::local_state::LocalStateStore;
use crate::views::helpers::short_protocol_id;

#[derive(Clone, Debug, PartialEq)]
struct AuditRow {
    kind: String,
    space_id: Option<String>,
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
    if !matches!(kind.as_str(), "cx.audit.accessed" | "cx.audit.ryw_receipt") {
        return None;
    }
    Some(AuditRow {
        kind,
        space_id: extract_string(body, "space_id"),
        target_event_id: extract_string(body, "target_event_id")
            .or_else(|| extract_string(body, "source_event_id")),
        reader_device: extract_string(body, "reader_device"),
        operation_id: operation_id.to_owned(),
    })
}

#[component]
pub fn AuditPanel(state_store: Signal<LocalStateStore>) -> Element {
    let state = state_store.read().load();
    let rows: Vec<AuditRow> = state
        .raw_operations
        .iter()
        .filter_map(|record| classify_audit_row(&record.operation_id, &record.payload))
        .collect();
    let attested_count = rows
        .iter()
        .filter(|row| row.kind == "cx.audit.accessed")
        .count();
    let receipt_count = rows
        .iter()
        .filter(|row| row.kind == "cx.audit.ryw_receipt")
        .count();

    rsx! {
        div { class: "timeline", "data-testid": "audit-panel", role: "region", "aria-label": "Audit log",
            div { class: "event",
                div { class: "event-head",
                    span { "Audit log" }
                    HelpTip { text: "Attested-audit Spaces require every successful decrypt to emit a cx.audit.accessed event. Disclosed-audit Spaces require every write to emit a cx.audit.ryw_receipt. This view is read-only — it reflects what the local raw-operation log has observed." }
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Access events" }
                        span { "data-testid": "audit-accessed-count", "{attested_count}" }
                        div { class: "muted", "cx.audit.accessed (attested policy)" }
                    }
                    div { class: "metric",
                        strong { "Write receipts" }
                        span { "data-testid": "audit-receipt-count", "{receipt_count}" }
                        div { class: "muted", "cx.audit.ryw_receipt (disclosed policy)" }
                    }
                    div { class: "metric",
                        strong { "Total observed" }
                        span { "data-testid": "audit-total-count", "{rows.len()}" }
                        div { class: "muted", "Local raw-operation projection only" }
                    }
                }
            }
            if rows.is_empty() {
                EmptyState {
                    title: "Audit".to_owned(),
                    kind: EmptyStateKind::Empty,
                    message: Some(
                        "No audit events recorded yet. Audit emission depends on the active Space policy; if no Space you are in is under an attested or disclosed audit profile, nothing will show up here."
                            .to_owned(),
                    ),
                    test_id: Some("audit-empty".to_owned()),
                }
            } else {
                for row in rows.iter() {
                    {
                        let operation_id_label = short_protocol_id(&row.operation_id);
                        rsx! {
                            div { class: "event", "data-testid": "audit-row",
                                div { class: "event-head",
                                    span { class: "badge", "{row.kind}" }
                                    if let Some(space) = &row.space_id {
                                        {
                                            let space_label = short_protocol_id(space);
                                            rsx! {
                                                span {
                                                    class: "mono",
                                                    "data-testid": "audit-row-space",
                                                    title: "{space}",
                                                    "{space_label}"
                                                }
                                            }
                                        }
                                    }
                                }
                                if let Some(target) = &row.target_event_id {
                                    {
                                        let target_label = short_protocol_id(target);
                                        rsx! { div { class: "muted", title: "{target}", "target {target_label}" } }
                                    }
                                }
                                if let Some(reader) = &row.reader_device {
                                    {
                                        let reader_label = short_protocol_id(reader);
                                        rsx! { div { class: "muted", title: "{reader}", "reader {reader_label}" } }
                                    }
                                }
                                div { class: "muted mono", "data-testid": "audit-row-op", title: "{row.operation_id}", "op {operation_id_label}" }
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
    use serde_json::json;

    use super::{AuditRow, classify_audit_row};

    #[test]
    fn classifies_audit_accessed() {
        let row = classify_audit_row(
            "op-1",
            &json!({
                "kind": "cx.audit.accessed",
                "space_id": "cx:space:s1",
                "target_event_id": "cx:event:abc",
                "reader_device": "did:key:zDevice",
            }),
        )
        .expect("should classify");
        assert_eq!(row.kind, "cx.audit.accessed");
        assert_eq!(row.space_id.as_deref(), Some("cx:space:s1"));
        assert_eq!(row.target_event_id.as_deref(), Some("cx:event:abc"));
    }

    #[test]
    fn classifies_ryw_receipt_with_source_event_id() {
        let row = classify_audit_row(
            "op-2",
            &json!({
                "kind": "cx.audit.ryw_receipt",
                "source_event_id": "cx:event:xyz",
            }),
        )
        .expect("should classify");
        assert_eq!(row.kind, "cx.audit.ryw_receipt");
        assert_eq!(row.target_event_id.as_deref(), Some("cx:event:xyz"));
    }

    #[test]
    fn ignores_non_audit_kinds() {
        let none = classify_audit_row(
            "op-3",
            &json!({
                "kind": "cx.message.create",
                "space_id": "cx:space:s1",
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
