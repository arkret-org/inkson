//! Audit view — read-only inspector for audited E2EE events.
//!
//! Surfaces `ak.audit.accessed` (attested-audit reads) and
//! `ak.audit.ryw_receipt` (disclosed-audit write receipts) from the local
//! raw-operation log, so administrators / users can verify the audit
//! channel is firing under the active policy.
//!
//! Writing new audit events is owned by the SDK / reducer path; this view
//! does not emit anything.

use arkret_wire::event_kind_str;
use dioxus::prelude::*;
use serde_json::Value;

use crate::components::{EmptyState, EmptyStateKind, HelpTip};
use crate::i18n::tr;
use crate::views::helpers::short_protocol_id;

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

#[component]
pub fn AuditPanel() -> Element {
    let state_store = crate::app::SessionContext::get().state_store;
    let state = state_store.read().load();
    let rows: Vec<AuditRow> = state
        .raw_operations
        .iter()
        .filter_map(|record| classify_audit_row(&record.operation_id, &record.payload))
        .collect();
    let attested_count = rows
        .iter()
        .filter(|row| row.kind == event_kind_str::AUDIT_ACCESSED)
        .count();
    rsx! {
        div { class: "timeline", "data-testid": "audit-panel", role: "region", "aria-label": tr("audit.title"),
                div { class: "event",
                    div { class: "event-head",
                        span { {tr("audit.title")} }
                    HelpTip { text: tr("audit.help") }
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { {tr("audit.access_events")} }
                        span { "data-testid": "audit-accessed-count", "{attested_count}" }
                        div { class: "muted", {tr("audit.access_events_hint")} }
                    }
                    div { class: "metric",
                        strong { {tr("audit.total_observed")} }
                        span { "data-testid": "audit-total-count", "{rows.len()}" }
                        div { class: "muted", {tr("audit.total_observed_hint")} }
                    }
                }
            }
            if rows.is_empty() {
                EmptyState {
                    title: tr("audit.empty_title"),
                    kind: EmptyStateKind::Empty,
                    message: Some(tr("audit.empty_message")),
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
                                    if let Some(realm) = &row.realm_id {
                                        {
                                            let realm_label = short_protocol_id(realm);
                                            rsx! {
                                                span {
                                                    class: "mono",
                                                    "data-testid": "audit-row-realm",
                                                    title: "{realm}",
                                                    "{realm_label}"
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
    fn classifies_ryw_receipt_with_source_event_id() {
        let row = classify_audit_row(
            "op-2",
            &json!({
                "kind": "ak.audit.ryw_receipt",
                "source_event_id": "ak:event:AT0vreMDT0LOX4VqBw6oTfJXIygWfJREjoMZQIWL7Wm0",
            }),
        )
        .expect("should classify");
        assert_eq!(row.kind, "ak.audit.ryw_receipt");
        assert_eq!(
            row.target_event_id.as_deref(),
            Some("ak:event:AT0vreMDT0LOX4VqBw6oTfJXIygWfJREjoMZQIWL7Wm0")
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
