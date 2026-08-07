//! G3.Y3 — Capability authority viewer (`/settings/capabilities`).
//!
//! Read-only-ish UI for inspecting `ak.capability.*` rows attached to
//! the current actor: capabilities held (subject), capabilities granted
//! out (issuer), plus the reducer-derived authority audit for each row. The cotest
//! `authz/capability-chain` scenario is already live; this view focuses
//! on inspection until revoke and relinquish controls are available.
//!
//! Spec seals:
//! - `authz/capabilities.md` §3 — capability schema.
//! - `authz/capabilities.md` §3.2 — issuer authority.
//! - `authz/capabilities.md` §3.3 — revoke + cascade.
//! - `authz/capabilities.md` §3.4 — audit trail.

use arkret_models_collaboration::governance::grant_constraint::{
    CapabilityGrant, CapabilitySubject, IssuerAuthorityRef,
};
use dioxus::prelude::*;

use crate::components::{EmptyState, EmptyStateKind};
use crate::transport::auth::with_authed_sdk_client;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::dialog::Dialog;
use crate::views::helpers::{actor_display_label, short_protocol_id};

/// One row in the user's capability list. Backed by either the user
/// being the subject (capability held) or the issuer (capability
/// granted to someone else). Mapped from the authoritative SDK
/// [`CapabilityGrant`] rows that `ak.self.authz.grants.read.effective`
/// returns (soland serialises the SDK `GrantList` verbatim).
#[derive(Clone, Debug, PartialEq)]
struct CapabilityRow {
    capability_id: String,
    action: String,
    scope: String,
    issuer_did: String,
    subject_did: String,
    expires_at: String,
    issuer_authority_refs: Vec<String>,
}

/// Map one authoritative SDK [`CapabilityGrant`] onto a display row.
fn decode_capability_row(grant: &CapabilityGrant) -> CapabilityRow {
    CapabilityRow {
        capability_id: grant.id.as_str().to_owned(),
        action: grant.actions.first().cloned().unwrap_or_default(),
        scope: grant
            .resources
            .first()
            .and_then(|resource| serde_json::to_string(resource).ok())
            .unwrap_or_default(),
        issuer_did: grant.issuer.as_str().to_owned(),
        subject_did: match &grant.subject {
            CapabilitySubject::Did(did) => did.as_str().to_owned(),
            CapabilitySubject::Selector(selector) => selector.to_string(),
        },
        expires_at: grant
            .expires_at
            .map(arkret_sdk::canonical::format_timestamp_canonical)
            .unwrap_or_default(),
        issuer_authority_refs: grant
            .issuer_authority_refs
            .iter()
            .map(|authority| match authority {
                IssuerAuthorityRef::Grant { grant_id } => {
                    format!("grant {}", grant_id.as_str())
                }
                IssuerAuthorityRef::RealmRoot {
                    realm_id,
                    authority_generation,
                    ..
                } => format!(
                    "realm root {} generation {}",
                    realm_id.as_str(),
                    authority_generation
                ),
            })
            .collect(),
    }
}

#[component]
pub fn CapabilitiesSettingsCard(account_did: Signal<String>, token: Signal<String>) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::get().base_url;
    let state_store = crate::app::SessionContext::get().state_store;
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
                crate::transport::realm_read::effective_grants(&http, &did).await
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
                                actor_display_label(&state_store.read(), &row.issuer_did);
                            let subject_did_label =
                                actor_display_label(&state_store.read(), &row.subject_did);
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
                                        span { "Authority audit" }
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
                                    if row.issuer_authority_refs.is_empty() {
                                        div {
                                            class: "muted",
                                            "data-testid": "capability-authority-empty",
                                            "Issuer authority is not available in this projection."
                                        }
                                    } else {
                                        ol { class: "settings-list",
                                            for (idx, authority) in row.issuer_authority_refs.iter().enumerate() {
                                                li {
                                                    class: "event",
                                                    "data-testid": "capability-authority-ref",
                                                    "data-ref-index": "{idx}",
                                                    div { class: "mono", "{authority}" }
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

    fn sample_grant(subject: serde_json::Value) -> CapabilityGrant {
        serde_json::from_value(json!({
            "id": "ak:grant:0196419b-0000-7000-8000-000000000000",
            "schema": "ak.schema.capability.v1",
            "realm_id": "ak:realm:0196419b-0000-8000-8000-000000000001",
            "issuer": "did:web:alice.example",
            "subject": subject,
            "actions": ["ak.message.create"],
            "resources": [
                {"kind": "realm", "realm_id": "ak:realm:0196419b-0000-8000-8000-000000000001"}
            ],
            "issued_at": "2026-01-01T00:00:00.000Z",
            "expires_at": "2026-12-31T00:00:00.000Z",
            "issuer_authority_refs": [{
                "kind": "realm_root",
                "realm_id": "ak:realm:0196419b-0000-8000-8000-000000000001",
                "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                "controller_epoch_at_issuance": 0,
                "authority_generation": 0
            }]
        }))
        .expect("sample grant decodes as SDK CapabilityGrant")
    }

    #[test]
    fn maps_sdk_grant_to_capability_row() {
        let row = decode_capability_row(&sample_grant(json!("did:web:bob.example")));
        assert_eq!(
            row.capability_id,
            "ak:grant:0196419b-0000-7000-8000-000000000000"
        );
        assert_eq!(row.action, "ak.message.create");
        assert_eq!(row.issuer_did, "did:web:alice.example");
        assert_eq!(row.subject_did, "did:web:bob.example");
        assert!(row.expires_at.starts_with("2026-12-31"));
        assert_eq!(row.issuer_authority_refs.len(), 1);
    }

    #[test]
    fn selector_subject_renders_as_json() {
        let row = decode_capability_row(&sample_grant(json!({"kind": "circle", "circle": "ops"})));
        assert!(row.subject_did.contains("circle"));
    }
}
