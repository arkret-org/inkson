//! G3.Y3 — Capability authority viewer (`/settings/capabilities`).
//!
//! UI for inspecting `ak.capability.*` rows attached to the current
//! actor — capabilities held (subject), capabilities granted out
//! (issuer), plus the reducer-derived authority audit for each row —
//! and for the one self-service write this surface owns:
//! `ak.capability.relinquish` on grants where the current actor is the
//! subject. Relinquish is subject-only (`authz/capabilities.md` §10.4):
//! it MUST NOT require the actor to hold `ak.capability.revoke`, and the
//! reducer rejects any non-subject attempt with
//! `grant_relinquish_not_subject`. Issuer-side revoke stays on the
//! Realm-admin surface.
//!
//! Spec seals:
//! - `authz/capabilities.md` §3 — capability schema.
//! - `authz/capabilities.md` §3.2 — issuer authority.
//! - `authz/capabilities.md` §3.3 — revoke + cascade.
//! - `authz/capabilities.md` §3.4 — audit trail.
//! - `authz/capabilities.md` §10.4 — subject-only relinquish.

use arkret_models_collaboration::governance::grant_constraint::{
    CapabilityGrant, CapabilitySubject, GrantConstraintKind, IssuerAuthorityRef,
};
use dioxus::prelude::*;

use crate::components::{EmptyState, EmptyStateKind};
use crate::transport::auth::with_authed_sdk_client;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::dialog::Dialog;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::views::helpers::{actor_display_label, short_protocol_id};

/// One row in the user's capability list. Backed by either the user
/// being the subject (capability held) or the issuer (capability
/// granted to someone else). Mapped from the authoritative SDK
/// [`CapabilityGrant`] rows that `ak.self.authz.grants.read.effective.v1`
/// returns (soland serialises the SDK `GrantList` verbatim).
#[derive(Clone, Debug, PartialEq)]
struct CapabilityRow {
    capability_id: String,
    /// Realm the grant governs — the scope the relinquish control event is
    /// submitted into. Falls back to the Realm the row was queried from when
    /// the grant itself carries no `realm_id`.
    realm_id: String,
    action: String,
    scope: String,
    issuer_id: String,
    subject: String,
    subject_actor: Option<arkret_sdk::ActorId>,
    expires_at: String,
    issuer_authority_refs: Vec<String>,
}

impl CapabilityRow {
    fn can_relinquish(&self, actor: Option<&arkret_sdk::ActorId>) -> bool {
        actor.is_some() && self.subject_actor.as_ref() == actor
    }
}

/// Map one authoritative SDK [`CapabilityGrant`] onto a display row.
fn decode_capability_row(grant: &CapabilityGrant, queried_realm_id: &str) -> CapabilityRow {
    CapabilityRow {
        capability_id: grant.id.as_str().to_owned(),
        realm_id: grant
            .realm_id
            .as_ref()
            .map(|realm_id| realm_id.as_str().to_owned())
            .unwrap_or_else(|| queried_realm_id.to_owned()),
        action: grant.actions.first().cloned().unwrap_or_default(),
        scope: grant
            .resources
            .first()
            .and_then(|resource| serde_json::to_string(resource).ok())
            .unwrap_or_default(),
        issuer_id: grant.issuer_id.signing_principal_id().as_str().to_owned(),
        subject: match &grant.subject {
            CapabilitySubject::Actor(actor) => actor.signing_principal_id().to_string(),
            CapabilitySubject::Condition(selector) => {
                serde_json::to_string(selector).unwrap_or_else(|_| "condition".to_owned())
            }
        },
        subject_actor: match &grant.subject {
            CapabilitySubject::Actor(actor) => Some(actor.clone()),
            CapabilitySubject::Condition(_) => None,
        },
        expires_at: grant
            .constraints
            .iter()
            .filter(|constraint| constraint.constraint_kind == GrantConstraintKind::Temporal)
            .filter_map(|constraint| constraint.expires_at)
            .min()
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
pub fn CapabilitiesSettingsCard(principal_id: Signal<String>, token: Signal<String>) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let active_account = crate::app::SessionContext::get().active_account;
    let base_url = use_signal(move || {
        active_account()
            .map(|account| account.server_url.to_string())
            .unwrap_or_default()
    });
    let state_store = crate::app::SessionContext::get().state_store;
    let mut rows = use_signal(Vec::<CapabilityRow>::new);
    let mut status = use_signal(String::new);
    let mut detail_for = use_signal(|| Option::<String>::None);
    // Subject-only relinquish confirmation: capability_id of the pending row
    // plus an optional audit-trail reason (`capabilities.md` §10.4 — no
    // revoke authority is required or attached).
    let mut relinquish_for = use_signal(|| Option::<String>::None);
    let mut relinquish_reason = use_signal(String::new);
    // Relinquish belongs to the complete account, not just its signing principal.
    let my_actor = active_account().map(|account| arkret_sdk::ActorId::account(account.authority));

    // Fire a single effective-grants probe per token change.
    use_effect(move || {
        let base = base_url();
        let tok = token();
        let did = principal_id();
        if tok.trim().is_empty() || did.trim().is_empty() {
            return;
        }
        let Some(subject) =
            active_account().map(|account| arkret_sdk::ActorId::account(account.authority))
        else {
            status.set("Failed to load capabilities: no authenticated account".to_owned());
            return;
        };
        let realm_ids = state_store.read().known_realm_ids();
        spawn(async move {
            match with_authed_sdk_client(&base, tok, |http| async move {
                let mut grants = Vec::new();
                for realm_id in realm_ids {
                    let response =
                        crate::transport::realm_read::effective_grants(&http, &realm_id, &subject)
                            .await?;
                    grants.extend(
                        response
                            .grants
                            .into_iter()
                            .map(|grant| (realm_id.clone(), grant)),
                    );
                }
                Ok::<_, anyhow::Error>(grants)
            })
            .await
            {
                Ok(grants) => {
                    let decoded: Vec<CapabilityRow> = grants
                        .iter()
                        .map(|(realm_id, grant)| decode_capability_row(grant, realm_id.as_str()))
                        .collect();
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
                                actor_display_label(&state_store.read(), &row.issuer_id);
                            let subject_did_label =
                                actor_display_label(&state_store.read(), &row.subject);
                            rsx! {
                                li {
                                    class: "event",
                                    "data-testid": "capability-row",
                                    "data-capability-id": "{row.capability_id}",
                                    "data-action": "{row.action}",
                                    "data-scope": "{row.scope}",
                                    "data-issuer-id": "{row.issuer_id}",
                                    "data-subject": "{row.subject}",
                                    "data-expires-at": "{row.expires_at}",
                                    div { class: "event-head",
                                        span { "{row.action}" }
                                        span { class: "muted", "expires {row.expires_at}" }
                                    }
                                    div {
                                        class: "muted",
                                        title: "{row.issuer_id} → {row.subject}",
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
                                        // Subject-only self-service: any member
                                        // may drop a grant they hold, with no
                                        // revoke authority involved.
                                        if row.can_relinquish(my_actor.as_ref()) {
                                            Button {
                                                variant: ButtonVariant::Destructive,
                                                "data-testid": "capability-relinquish-button",
                                                "data-capability-id": "{row.capability_id}",
                                                onclick: {
                                                    let id = row.capability_id.clone();
                                                    move |_| {
                                                        relinquish_reason.set(String::new());
                                                        relinquish_for.set(Some(id.clone()));
                                                    }
                                                },
                                                "Relinquish"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if let Some(capability_id) = relinquish_for.read().clone() {
                if let Some(row) = rows.read().iter().find(|r| r.capability_id == capability_id).cloned() {
                    {
                        let capability_id_label = short_protocol_id(&row.capability_id);
                        rsx! {
                            Dialog {
                                open: true,
                                on_open_change: move |open: bool| {
                                    if !open {
                                        relinquish_for.set(None);
                                    }
                                },
                                "data-testid": "capability-relinquish-modal",
                                "data-capability-id": "{row.capability_id}",
                                div {
                                    class: "event modal",
                                    div { class: "event-head",
                                        span { "Relinquish capability" }
                                        Button {
                                            variant: ButtonVariant::Ghost,
                                            size: ButtonSize::Icon,
                                            class: "btn",
                                            "data-testid": "capability-relinquish-close",
                                            "aria-label": "Close relinquish confirmation",
                                            onclick: move |_| relinquish_for.set(None),
                                            "×"
                                        }
                                    }
                                    div { class: "muted", title: "{row.capability_id}",
                                        "{capability_id_label} · {row.action}"
                                    }
                                    div { class: "muted", "data-testid": "capability-relinquish-impact",
                                        "This permanently gives up the grant for yourself via "
                                        "`ak.capability.relinquish`. It is subject-only: no revoke "
                                        "authority is required or attached, and nobody else can use this "
                                        "path on your behalf. The issuer can re-grant later if needed."
                                    }
                                    Label {
                                        html_for: "capability-relinquish-reason-input",
                                        "Reason (optional, audit trail)"
                                    }
                                    Input {
                                        id: "capability-relinquish-reason-input",
                                        "data-testid": "capability-relinquish-reason-input",
                                        value: "{relinquish_reason}",
                                        placeholder: "no longer needed",
                                        oninput: move |event: FormEvent| relinquish_reason.set(event.value()),
                                    }
                                    div { class: "actions",
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "capability-relinquish-cancel",
                                            onclick: move |_| relinquish_for.set(None),
                                            "Cancel"
                                        }
                                        Button {
                                            variant: ButtonVariant::Destructive,
                                            "data-testid": "capability-relinquish-confirm",
                                            onclick: {
                                                let row = row.clone();
                                                move |_| {
                                                    let base = base_url();
                                                    let api_token = token();
                                                    let actor = principal_id().trim().to_owned();
                                                    if actor.is_empty() {
                                                        status.set("relinquish failed: account is not connected".to_owned());
                                                        return;
                                                    }
                                                    let realm_id = match arkret_sdk::RealmId::new(row.realm_id.clone()) {
                                                        Ok(realm_id) => realm_id,
                                                        Err(err) => {
                                                            status.set(format!(
                                                                "relinquish build failed: invalid realm id: {err}"
                                                            ));
                                                            return;
                                                        }
                                                    };
                                                    let grant_id = match arkret_sdk::GrantId::new(row.capability_id.clone()) {
                                                        Ok(grant_id) => grant_id,
                                                        Err(err) => {
                                                            status.set(format!(
                                                                "relinquish build failed: invalid grant id: {err}"
                                                            ));
                                                            return;
                                                        }
                                                    };
                                                    let reason_val = relinquish_reason().trim().to_owned();
                                                    let payload = arkret_sdk::CapabilityRelinquishPayload {
                                                        grant_id,
                                                        reason: (!reason_val.is_empty()).then_some(reason_val),
                                                    };
                                                    relinquish_for.set(None);
                                                    let capability_for_msg = row.capability_id.clone();
                                                    spawn(async move {
                                                        match crate::transport::auth::with_event_submitter(
                                                            &base,
                                                            api_token,
                                                            |sub| async move {
                                                                crate::transport::realm_write::relinquish_capability(
                                                                    &sub, realm_id, &actor, payload,
                                                                )
                                                                .await
                                                            },
                                                        )
                                                        .await
                                                        {
                                                            Ok(resp) => status.set(format!(
                                                                "relinquish submitted for {}: event_id={} — the grant is void once the control move seals",
                                                                short_protocol_id(&capability_for_msg),
                                                                short_protocol_id(&resp.event_id),
                                                            )),
                                                            Err(err) => {
                                                                let text = err.display();
                                                                let hint = relinquish_failure_hint(&text)
                                                                    .map(|hint| format!(" — {hint}"))
                                                                    .unwrap_or_default();
                                                                status.set(format!("relinquish failed: {text}{hint}"));
                                                            }
                                                        }
                                                    });
                                                }
                                            },
                                            "Relinquish grant"
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

/// Operator guidance for the known relinquish rejection reasons, appended to
/// the raw error text in the status line.
fn relinquish_failure_hint(error_text: &str) -> Option<&'static str> {
    if error_text.contains("grant_relinquish_not_subject") {
        Some(
            "the server rejected this because the signer is not the grant's subject — only the \
             subject may relinquish a grant; ask the issuer (or Realm owner) to revoke it instead",
        )
    } else if error_text.contains("capability_target_unresolved")
        || error_text.contains("dependency_pending")
    {
        Some(
            "the grant is not yet resolved in the server projection — the relinquish stays \
             pending until the grant row lands; retry after sync if it does not settle",
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn sample_grant(subject: serde_json::Value) -> CapabilityGrant {
        let value = json!({
            "id": "ak:grant:AfpU2UOijpNUdGOoAgQdaqV0xwreLXwLE3yXXHvB6n7X",
            "schema": "ak.schema.capability.v1",
            "realm_id": "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
            "issuer_id": {"kind": "account", "account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": "ak:did_core:web:principal.example"
            }},
            "subject": subject,
            "actions": ["ak.message.create"],
            "resources": [
                {"kind": "realm", "realm_id": "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"}
            ],
            "constraints": [{
                "constraint_kind": "temporal",
                "effect": "allow",
                "expires_at": "2026-12-31T00:00:00.000Z"
            }],
            "issued_at": "2026-01-01T00:00:00.000Z",
            "issuer_authority_refs": [{
                "kind": "realm_root",
                "realm_id": "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                "controller_epoch_at_issuance": 0,
                "authority_generation": 0
            }]
        });
        serde_json::from_value(value).expect("sample grant decodes as SDK CapabilityGrant")
    }

    #[test]
    fn maps_sdk_grant_to_capability_row() {
        let row = decode_capability_row(
            &sample_grant(json!({"kind": "account", "account_id": {
                "principal_id": "ak:did_core:web:bob.example",
                "station_id": "ak:did_core:web:principal.example"
            }})),
            "ak:realm:Afallback0000000000000000000000000000000000000",
        );
        assert_eq!(
            row.capability_id,
            "ak:grant:AfpU2UOijpNUdGOoAgQdaqV0xwreLXwLE3yXXHvB6n7X"
        );
        // The grant's own realm_id wins over the queried-realm fallback.
        assert_eq!(
            row.realm_id,
            "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
        );
        assert_eq!(row.action, "ak.message.create");
        assert_eq!(row.issuer_id, "ak:did_core:web:alice.example");
        assert_eq!(row.subject, "ak:did_core:web:bob.example");
        assert!(row.expires_at.starts_with("2026-12-31"));
        assert_eq!(row.issuer_authority_refs.len(), 1);
    }

    #[test]
    fn selector_subject_renders_as_json() {
        let row = decode_capability_row(
            &sample_grant(json!({
                "kind": "condition",
                "required_claims": []
            })),
            "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        );
        assert!(row.subject.contains("condition"));
    }

    #[test]
    fn relinquish_requires_same_actor_kind_and_station() {
        let principal = arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap();
        let station = arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap();
        let subject = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            principal.clone(),
            station.clone(),
        ));
        let row = decode_capability_row(
            &sample_grant(serde_json::to_value(&subject).unwrap()),
            "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        );
        assert!(row.can_relinquish(Some(&subject)));
        assert!(!row.can_relinquish(None));
        let foreign = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            principal.clone(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        ));
        assert!(!row.can_relinquish(Some(&foreign)));
        assert!(
            !row.can_relinquish(Some(&arkret_sdk::ActorId::hosted_principal(
                principal, station
            )))
        );
    }

    #[test]
    fn relinquish_failure_hint_covers_the_subject_guard() {
        assert!(relinquish_failure_hint("rejected: grant_relinquish_not_subject").is_some());
        assert!(relinquish_failure_hint("capability_target_unresolved").is_some());
        assert_eq!(relinquish_failure_hint("network timeout"), None);
    }
}
