//! G3.Y3 — Capability delegation viewer (`/settings/capabilities`).
//!
//! Read-only-ish UI for inspecting `ck.capability.*` rows attached to
//! the current actor: capabilities held (subject), capabilities granted
//! out (issuer), and the full delegation chain for each row. The cotest
//! `authz/capability-chain` scenario is already live; this view focuses
//! on inspection until revoke/delegation endpoints are available.
//!
//! Spec anchors:
//! - `authz/capabilities.md` §3 — capability schema.
//! - `authz/capabilities.md` §3.2 — delegation.
//! - `authz/capabilities.md` §3.3 — revoke + cascade.
//! - `authz/capabilities.md` §3.4 — audit trail.

use dioxus::prelude::*;
use serde_json::Value;

use crate::api::CokretApi;
use crate::components::{EmptyState, EmptyStateKind};
use crate::local_state::LocalStateStore;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::dialog::Dialog;
use crate::views::helpers::{short_protocol_id, with_authed_api};

/// One row in the user's capability list. Backed by either the user
/// being the subject (capability held) or the issuer (capability
/// delegated to someone else). Decoded leniently because the soland
/// projection schema is still in flux (spec §3 — fields can be empty
/// when the originating event omits an optional attenuation step).
#[derive(Clone, Debug, PartialEq)]
struct CapabilityRow {
    capability_id: String,
    action: String,
    scope: String,
    issuer_did: String,
    subject_did: String,
    expires_at: String,
    /// Per `authz/capabilities.md` §3.2 — each delegation hop carries
    /// its own attenuation. Rendered as `capability-chain-step`
    /// entries in the detail modal.
    chain: Vec<DelegationStep>,
}

#[derive(Clone, Debug, PartialEq)]
struct DelegationStep {
    issuer_did: String,
    subject_did: String,
    constraints: String,
}

/// Best-effort decoder for one capability projection row. Soland's
/// `effective-grants` response carries `Vec<Value>`; until the schema
/// stabilises we pull strings out individually so unknown shapes
/// degrade to an empty cell rather than a parse error.
fn decode_capability_row(value: &Value) -> Option<CapabilityRow> {
    let capability_id = value
        .get("capability_id")
        .or_else(|| value.get("grant_id"))
        .and_then(|v| v.as_str())?
        .to_owned();
    let action = value
        .get("action")
        .or_else(|| value.get("actions").and_then(|a| a.get(0)))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    let scope = value
        .get("scope")
        .or_else(|| value.get("resource"))
        .map(|v| v.to_string())
        .unwrap_or_default();
    let issuer_did = value
        .get("issuer")
        .or_else(|| value.get("grantor"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    let subject_did = value
        .get("subject")
        .or_else(|| value.get("grantee"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    let expires_at = value
        .get("expires_at")
        .or_else(|| value.get("constraints").and_then(|c| c.get("expires_at")))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    let chain = value
        .get("chain")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|step| DelegationStep {
                    issuer_did: step
                        .get("issuer")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    subject_did: step
                        .get("subject")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    constraints: step
                        .get("constraints")
                        .map(|v| v.to_string())
                        .unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default();
    Some(CapabilityRow {
        capability_id,
        action,
        scope,
        issuer_did,
        subject_did,
        expires_at,
        chain,
    })
}

#[component]
pub fn CapabilitiesSettingsCard(
    base_url: Signal<String>,
    account_did: Signal<String>,
    token: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let _ = state_store;

    let mut rows = use_signal(Vec::<CapabilityRow>::new);
    let mut status = use_signal(String::new);
    let mut detail_for = use_signal(|| Option::<String>::None);

    // Fire a single effective-grants probe per token change.
    use_effect(move || {
        let base = base_url();
        let tok = token();
        let did = account_did();
        if tok.trim().is_empty() || did.trim().is_empty() {
            return;
        }
        spawn(async move {
            match with_authed_api(&base, tok, |api: CokretApi| async move {
                api.effective_grants(&did).await
            })
            .await
            {
                Ok(resp) => {
                    let decoded: Vec<CapabilityRow> = resp
                        .grants
                        .iter()
                        .filter_map(decode_capability_row)
                        .collect();
                    if decoded.is_empty() && !resp.grants.is_empty() {
                        status.set(format!(
                            "Received {} grants but none matched the expected schema",
                            resp.grants.len()
                        ));
                    } else {
                        status.set(format!("Loaded {} capabilities", decoded.len()));
                    }
                    rows.set(decoded);
                }
                Err(err) => {
                    // TODO(G3.Y3-followup): when soland adds the per-actor
                    // `GET /_cokret/self/authz/capabilities/{actor}` endpoint with
                    // the full delegation chain (spec §3.2), prefer that
                    // over effective-grants — the latter projects only the
                    // resolved leaf, not the hop history needed for the
                    // `capability-chain-step` detail modal.
                    status.set(format!("Failed to load capabilities: {}", err.display()));
                }
            }
        });
    });

    rsx! {
        div { class: "event", "data-testid": "capability-list-panel",
            div { class: "event-head",
                span { "Capabilities" }
            }
            if !status.read().is_empty() {
                div { class: "muted", "{status}" }
            }
            if rows.read().is_empty() {
                EmptyState {
                    title: "No capabilities".to_owned(),
                    kind: EmptyStateKind::Empty,
                    message: Some(
                        "No grants found for this actor. Either the projection is still warming up, or no grants have been issued yet."
                            .to_owned(),
                    ),
                    test_id: Some("capability-empty".to_owned()),
                }
            } else {
                ul { class: "settings-list",
                    for row in rows.read().iter().cloned() {
                        {
                            let issuer_did_label = short_protocol_id(&row.issuer_did);
                            let subject_did_label = short_protocol_id(&row.subject_did);
                            rsx! {
                                li {
                                    class: "event",
                                    "data-testid": "capability-row",
                                    "data-capability-id": "{row.capability_id}",
                                    "data-action": "{row.action}",
                                    "data-scope": "{row.scope}",
                                    "data-issuer-did": "{row.issuer_did}",
                                    "data-subject-did": "{row.subject_did}",
                                    "data-expires-at": "{row.expires_at}",
                                    div { class: "event-head",
                                        span { "{row.action}" }
                                        span { class: "muted", "expires {row.expires_at}" }
                                    }
                                    div {
                                        class: "muted",
                                        title: "{row.issuer_did} → {row.subject_did}",
                                        "issued by {issuer_did_label} → {subject_did_label}"
                                    }
                                    div { class: "muted mono", "scope {row.scope}" }
                                    div { class: "actions",
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "capability-detail-button",
                                            "data-capability-id": "{row.capability_id}",
                                            onclick: {
                                                let id = row.capability_id.clone();
                                                move |_| detail_for.set(Some(id.clone()))
                                            },
                                            "Detail"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if let Some(capability_id) = detail_for.read().clone() {
                if let Some(row) = rows.read().iter().find(|r| r.capability_id == capability_id).cloned() {
                    {
                        let capability_id_label = short_protocol_id(&row.capability_id);
                        rsx! {
                            Dialog {
                                open: true,
                                on_open_change: move |open: bool| {
                                    if !open {
                                        detail_for.set(None);
                                    }
                                },
                                "data-testid": "capability-detail-modal",
                                "data-capability-id": "{row.capability_id}",
                                div {
                                    class: "event modal",
                                    div { class: "event-head",
                                        span { "Delegation chain" }
                                        Button {
                                            variant: ButtonVariant::Ghost,
                                            size: ButtonSize::Icon,
                                            class: "btn",
                                            "data-testid": "capability-detail-close",
                                            "aria-label": "Close capability detail",
                                            onclick: move |_| detail_for.set(None),
                                            "×"
                                        }
                                    }
                                    div { class: "muted", title: "{row.capability_id}", "{capability_id_label}" }
                                    if row.chain.is_empty() {
                                        div {
                                            class: "muted",
                                            "data-testid": "capability-chain-empty",
                                            "No attenuation chain — capability is held directly from the root issuer."
                                        }
                                    } else {
                                        ol { class: "settings-list",
                                            for (idx, step) in row.chain.iter().enumerate() {
                                                {
                                                    let issuer_did_label = short_protocol_id(&step.issuer_did);
                                                    let subject_did_label = short_protocol_id(&step.subject_did);
                                                    rsx! {
                                                        li {
                                                            class: "event",
                                                            "data-testid": "capability-chain-step",
                                                            "data-step-index": "{idx}",
                                                            div { class: "event-head",
                                                                span { "Step {idx + 1}" }
                                                                span {
                                                                    class: "mono",
                                                                    title: "{step.issuer_did} → {step.subject_did}",
                                                                    "{issuer_did_label} → {subject_did_label}"
                                                                }
                                                            }
                                                            div { class: "muted mono", "constraints {step.constraints}" }
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
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn decodes_minimal_capability_row() {
        let value = json!({
            "capability_id": "cap-1",
            "action": "ck.space.write_message",
            "issuer": "did:web:alice.example",
            "subject": "did:web:bob.example",
            "expires_at": "2026-12-31T00:00:00Z",
        });
        let row = decode_capability_row(&value).expect("should decode");
        assert_eq!(row.capability_id, "cap-1");
        assert_eq!(row.action, "ck.space.write_message");
        assert_eq!(row.issuer_did, "did:web:alice.example");
        assert_eq!(row.subject_did, "did:web:bob.example");
        assert!(row.chain.is_empty());
    }

    #[test]
    fn decodes_delegation_chain() {
        let value = json!({
            "capability_id": "cap-2",
            "action": "ck.space.write_message",
            "grantor": "did:web:bob.example",
            "grantee": "did:web:carol.example",
            "chain": [
                {"issuer": "did:web:alice.example", "subject": "did:web:bob.example", "constraints": {"expires_at": "+1h"}},
                {"issuer": "did:web:bob.example", "subject": "did:web:carol.example", "constraints": {"expires_at": "+30m"}},
            ],
        });
        let row = decode_capability_row(&value).expect("should decode");
        assert_eq!(row.chain.len(), 2);
        assert_eq!(row.chain[0].issuer_did, "did:web:alice.example");
        assert_eq!(row.chain[1].subject_did, "did:web:carol.example");
    }

    #[test]
    fn returns_none_when_capability_id_missing() {
        let value = json!({"action": "ck.space.read"});
        assert!(decode_capability_row(&value).is_none());
    }

    #[test]
    fn fallbacks_handle_grant_id_alias() {
        let value = json!({"grant_id": "cap-3"});
        let row = decode_capability_row(&value).expect("should decode");
        assert_eq!(row.capability_id, "cap-3");
        assert!(row.action.is_empty());
    }
}
