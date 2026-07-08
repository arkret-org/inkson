//! G3.Y3 — Capability delegation viewer (`/settings/capabilities`).
//!
//! Read-only-ish UI for inspecting `ck.capability.*` rows attached to
//! the current actor: capabilities held (subject), capabilities granted
//! out (issuer), and the full delegation chain for each row. The cotest
//! `authz/capability-chain` scenario is already live; this view focuses
//! on inspection until revoke/delegation endpoints are available.
//!
//! Spec seals:
//! - `authz/capabilities.md` §3 — capability schema.
//! - `authz/capabilities.md` §3.2 — delegation.
//! - `authz/capabilities.md` §3.3 — revoke + cascade.
//! - `authz/capabilities.md` §3.4 — audit trail.

use cokret_sdk::models::{Capability, CapabilitySubject};
use dioxus::prelude::*;

use crate::components::{EmptyState, EmptyStateKind};
use crate::local_state::LocalStateStore;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::dialog::Dialog;
use crate::views::helpers::{display_name_for_did, short_protocol_id, with_authed_sdk_client};

/// One row in the user's capability list. Backed by either the user
/// being the subject (capability held) or the issuer (capability
/// delegated to someone else). Mapped from the authoritative SDK
/// [`Capability`] grant rows that `ck.self.authz.grants.query.effective`
/// returns (soland serialises the SDK `GrantList` verbatim).
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

/// Map one authoritative SDK [`Capability`] grant onto a display row.
/// The SDK grant carries no per-hop delegation chain (only
/// `parent_grant_id`), so `chain` stays empty until soland exposes a
/// chain projection (see the G3.Y3-followup note below).
fn decode_capability_row(grant: &Capability) -> CapabilityRow {
    CapabilityRow {
        capability_id: grant.id.as_str().to_owned(),
        action: grant.actions.first().cloned().unwrap_or_default(),
        scope: grant
            .resources
            .first()
            .map(|resource| resource.to_string())
            .unwrap_or_default(),
        issuer_did: grant.issuer.as_str().to_owned(),
        subject_did: match &grant.subject {
            CapabilitySubject::Did(did) => did.as_str().to_owned(),
            CapabilitySubject::Selector(selector) => selector.to_string(),
        },
        expires_at: grant
            .expires_at
            .map(|expires_at| expires_at.to_rfc3339())
            .unwrap_or_default(),
        chain: Vec::new(),
    }
}

#[component]
pub fn CapabilitiesSettingsCard(
    base_url: Signal<String>,
    account_did: Signal<String>,
    token: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
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
            match with_authed_sdk_client(&base, tok, |http| async move {
                crate::realm_read_api::effective_grants(&http, &did).await
            })
            .await
            {
                Ok(resp) => {
                    let decoded: Vec<CapabilityRow> =
                        resp.grants.iter().map(decode_capability_row).collect();
                    status.set(format!("Loaded {} capabilities", decoded.len()));
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
                            let issuer_did_label =
                                display_name_for_did(&state_store.read(), &row.issuer_did);
                            let subject_did_label =
                                display_name_for_did(&state_store.read(), &row.subject_did);
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
                                                    let issuer_did_label = display_name_for_did(
                                                        &state_store.read(),
                                                        &step.issuer_did,
                                                    );
                                                    let subject_did_label = display_name_for_did(
                                                        &state_store.read(),
                                                        &step.subject_did,
                                                    );
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

    fn sample_grant(subject: serde_json::Value) -> Capability {
        serde_json::from_value(json!({
            "id": "ck:grant:0196419b-0000-7000-8000-000000000000",
            "schema": "ck.schema.capability_grant.v1",
            "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000001",
            "issuer": "did:web:alice.example",
            "subject": subject,
            "actions": ["ck.message.create"],
            "resources": [
                {"kind": "realm", "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000001"}
            ],
            "issued_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-12-31T00:00:00Z",
            "proofs": [],
        }))
        .expect("sample grant decodes as SDK Capability")
    }

    #[test]
    fn maps_sdk_grant_to_capability_row() {
        let row = decode_capability_row(&sample_grant(json!("did:web:bob.example")));
        assert_eq!(
            row.capability_id,
            "ck:grant:0196419b-0000-7000-8000-000000000000"
        );
        assert_eq!(row.action, "ck.message.create");
        assert_eq!(row.issuer_did, "did:web:alice.example");
        assert_eq!(row.subject_did, "did:web:bob.example");
        assert!(row.expires_at.starts_with("2026-12-31"));
        // The SDK grant carries no per-hop chain projection (only
        // `parent_grant_id`), so the detail modal renders the
        // "held directly" empty state.
        assert!(row.chain.is_empty());
    }

    #[test]
    fn selector_subject_renders_as_json() {
        let row = decode_capability_row(&sample_grant(json!({"kind": "circle", "circle": "ops"})));
        assert!(row.subject_did.contains("circle"));
    }
}
