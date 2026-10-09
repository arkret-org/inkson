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

use arkret_models_collaboration::governance::authorization::EffectiveCapabilityGrantRow;
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilitySubject, GrantConstraintKind, IssuerAuthorityRef,
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
/// [`EffectiveCapabilityGrantRow`] values that
/// `ak.self.authz.grants.read.effective.v1` returns. The row revision is the
/// only valid authoring basis for a subject-signed relinquish.
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
    issuer_authority_refs: Vec<IssuerAuthorityRef>,
    revision: arkret_wire::CurrentRevision,
}

impl CapabilityRow {
    fn can_relinquish(&self, actor: Option<&arkret_sdk::ActorId>) -> bool {
        actor.is_some() && self.subject_actor.as_ref() == actor
    }
}

#[derive(Clone, Debug, PartialEq)]
struct RelinquishConfirmation {
    capability_id: String,
    revision: arkret_wire::CurrentRevision,
}

const CONFIRMED_ROW_CHANGED: &str = "capability row changed; reload and confirm relinquish again";

/// Map one authoritative SDK row onto a display row without separating its
/// grant value from the exact current-result revision read atomically with it.
fn decode_capability_row(
    effective: &EffectiveCapabilityGrantRow,
    queried_realm_id: &str,
) -> CapabilityRow {
    let grant = &effective.grant;
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
        issuer_authority_refs: grant.issuer_authority_refs.clone(),
        revision: effective.revision.clone(),
    }
}

fn authority_label(authority: &IssuerAuthorityRef) -> String {
    match authority {
        IssuerAuthorityRef::OwnedAgent {
            controller_account_id,
            ..
        } => crate::i18n::tr_args(
            "settings.capabilities.authority_agent",
            &[("account", controller_account_id.to_string())],
        ),
        IssuerAuthorityRef::Grant { grant_id } => crate::i18n::tr_args(
            "settings.capabilities.authority_grant",
            &[("grant", grant_id.to_string())],
        ),
        IssuerAuthorityRef::RealmRoot {
            realm_id,
            authority_generation,
            ..
        } => crate::i18n::tr_args(
            "settings.capabilities.authority_root",
            &[
                ("realm", realm_id.to_string()),
                ("generation", authority_generation.to_string()),
            ],
        ),
    }
}

/// Build only from the revision the user explicitly confirmed. A refresh can
/// replace a row with the same grant id but a new revision, so matching merely
/// on id would silently sign against a basis the user never confirmed.
fn build_confirmed_relinquish_payload(
    row: &CapabilityRow,
    confirmation: &RelinquishConfirmation,
    reason: &str,
) -> anyhow::Result<arkret_sdk::CapabilityRelinquishPayload> {
    anyhow::ensure!(
        confirmation.capability_id == row.capability_id && confirmation.revision == row.revision,
        CONFIRMED_ROW_CHANGED
    );
    Ok(arkret_sdk::CapabilityRelinquishPayload {
        grant_id: arkret_sdk::GrantId::new(row.capability_id.clone())?,
        expected_revision: row.revision.clone(),
        reason: (!reason.is_empty()).then(|| reason.to_owned()),
    })
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
    let mut status = use_signal(|| ("", Vec::<(&'static str, String)>::new()));
    let mut detail_for = use_signal(|| Option::<String>::None);
    // Subject-only relinquish confirmation binds the selected capability id
    // and exact current-result revision. Any list refresh invalidates it.
    let mut relinquish_for = use_signal(|| Option::<RelinquishConfirmation>::None);
    let mut relinquish_reason = use_signal(String::new);
    let mut refresh_nonce = use_signal(|| 0_u64);
    // Relinquish belongs to the complete account, not just its signing principal.
    let my_actor = active_account().map(|account| arkret_sdk::ActorId::account(account.authority));

    // Fire a single effective-grants probe per token change.
    use_effect(move || {
        let _ = refresh_nonce();
        let base = base_url();
        let tok = token();
        let did = principal_id();
        // A refresh (including the mandatory refresh after cas_conflict) makes
        // every prior user confirmation stale even if the grant id survives.
        relinquish_for.set(None);
        relinquish_reason.set(String::new());
        rows.set(Vec::new());
        if tok.trim().is_empty() || did.trim().is_empty() {
            return;
        }
        let Some(subject) =
            active_account().map(|account| arkret_sdk::ActorId::account(account.authority))
        else {
            status.set(("settings.capabilities.no_account", vec![]));
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
                            .map(|row| (realm_id.clone(), row)),
                    );
                }
                Ok::<_, anyhow::Error>(grants)
            })
            .await
            {
                Ok(grants) => {
                    let decoded: Vec<CapabilityRow> = grants
                        .iter()
                        .map(|(realm_id, row)| decode_capability_row(row, realm_id.as_str()))
                        .collect();
                    status.set((
                        "settings.capabilities.loaded",
                        vec![("count", decoded.len().to_string())],
                    ));
                    rows.set(decoded);
                }
                Err(err) => {
                    rows.set(Vec::new());
                    status.set((
                        "settings.capabilities.load_failed",
                        api_error_feedback_args(&err),
                    ));
                }
            }
        });
    });

    rsx! {
        div { class: "event", "data-testid": "capability-list-panel",
            div { class: "event-head",
                span { {crate::i18n::tr("settings.capabilities.title")} }
            }
            if !status.read().0.is_empty() {
                div { class: "muted", {capability_feedback_text(&status.read())} }
            }
            if rows.read().is_empty() {
                EmptyState {
                    title: crate::i18n::tr("settings.capabilities.empty_title"),
                    kind: EmptyStateKind::Empty,
                    message: Some(
                        crate::i18n::tr("settings.capabilities.empty_hint"),
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
                                        span { class: "muted", {crate::i18n::tr_args("settings.capabilities.expires", &[("time", row.expires_at.clone())])} }
                                    }
                                    div {
                                        class: "muted",
                                        title: "{row.issuer_id} → {row.subject}",
                                        {crate::i18n::tr_args("settings.capabilities.issued", &[("issuer", issuer_did_label.clone()), ("subject", subject_did_label.clone())])}
                                    }
                                    div { class: "muted mono", {crate::i18n::tr_args("settings.capabilities.scope", &[("scope", row.scope.clone())])} }
                                    div { class: "actions",
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "capability-detail-button",
                                            "data-capability-id": "{row.capability_id}",
                                            onclick: {
                                                let id = row.capability_id.clone();
                                                move |_| detail_for.set(Some(id.clone()))
                                            },
                                            {crate::i18n::tr("settings.capabilities.detail")}
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
                                                    let confirmation = RelinquishConfirmation {
                                                        capability_id: row.capability_id.clone(),
                                                        revision: row.revision.clone(),
                                                    };
                                                    move |_| {
                                                        relinquish_reason.set(String::new());
                                                        relinquish_for.set(Some(confirmation.clone()));
                                                    }
                                                },
                                                {crate::i18n::tr("settings.capabilities.relinquish")}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if let Some(confirmation) = relinquish_for.read().clone() {
                if let Some(row) = rows
                    .read()
                    .iter()
                    .find(|row| row.capability_id == confirmation.capability_id)
                    .cloned()
                {
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
                                        span { {crate::i18n::tr("settings.capabilities.relinquish_title")} }
                                        Button {
                                            variant: ButtonVariant::Ghost,
                                            size: ButtonSize::Icon,
                                            class: "btn",
                                            "data-testid": "capability-relinquish-close",
                                            "aria-label": crate::i18n::tr("settings.capabilities.close_relinquish"),
                                            onclick: move |_| relinquish_for.set(None),
                                            "×"
                                        }
                                    }
                                    div { class: "muted", title: "{row.capability_id}",
                                        "{capability_id_label} · {row.action}"
                                    }
                                    div { class: "muted", "data-testid": "capability-relinquish-impact",
                                        {crate::i18n::tr("settings.capabilities.impact")}
                                    }
                                    Label {
                                        html_for: "capability-relinquish-reason-input",
                                        {crate::i18n::tr("settings.capabilities.reason")}
                                    }
                                    Input {
                                        id: "capability-relinquish-reason-input",
                                        "data-testid": "capability-relinquish-reason-input",
                                        value: "{relinquish_reason}",
                                        placeholder: crate::i18n::tr("settings.capabilities.reason_placeholder"),
                                        oninput: move |event: FormEvent| relinquish_reason.set(event.value()),
                                    }
                                    div { class: "actions",
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "capability-relinquish-cancel",
                                            onclick: move |_| relinquish_for.set(None),
                                            {crate::i18n::tr("common.cancel")}
                                        }
                                        Button {
                                            variant: ButtonVariant::Destructive,
                                            "data-testid": "capability-relinquish-confirm",
                                            onclick: {
                                                let row = row.clone();
                                                let confirmation = confirmation.clone();
                                                move |_| {
                                                    let base = base_url();
                                                    let api_token = token();
                                                    let actor = principal_id().trim().to_owned();
                                                    if actor.is_empty() {
                                                        status.set(("settings.capabilities.disconnected", vec![]));
                                                        return;
                                                    }
                                                    let realm_id = match arkret_sdk::RealmId::new(row.realm_id.clone()) {
                                                        Ok(realm_id) => realm_id,
                                                        Err(err) => {
                                                            status.set(("settings.capabilities.invalid_realm", vec![("error", err.to_string())]));
                                                            return;
                                                        }
                                                    };
                                                    let reason_val = relinquish_reason().trim().to_owned();
                                                    let payload = match build_confirmed_relinquish_payload(
                                                        &row,
                                                        &confirmation,
                                                        &reason_val,
                                                    ) {
                                                        Ok(payload) => payload,
                                                        Err(err) => {
                                                            status.set(if err.to_string() == CONFIRMED_ROW_CHANGED {
                                                                ("settings.capabilities.row_changed", vec![])
                                                            } else {
                                                                ("settings.capabilities.build_failed", vec![("error", err.to_string())])
                                                            });
                                                            return;
                                                        }
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
                                                            Ok(resp) => status.set(("settings.capabilities.submitted", vec![("grant", short_protocol_id(&capability_for_msg)), ("event", short_protocol_id(&resp.event_id))])),
                                                            Err(err) => {
                                                                let text = err.display();
                                                                if relinquish_failure_requires_refresh(&text) {
                                                                    rows.set(Vec::new());
                                                                    relinquish_for.set(None);
                                                                    let next_refresh = (*refresh_nonce.peek())
                                                                        .wrapping_add(1);
                                                                    refresh_nonce.set(next_refresh);
                                                                }
                                                                status.set(("settings.capabilities.failed", api_error_feedback_args(&err)));
                                                            }
                                                        }
                                                    });
                                                }
                                            },
                                            {crate::i18n::tr("settings.capabilities.confirm")}
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
                                        span { {crate::i18n::tr("settings.capabilities.audit")} }
                                        Button {
                                            variant: ButtonVariant::Ghost,
                                            size: ButtonSize::Icon,
                                            class: "btn",
                                            "data-testid": "capability-detail-close",
                                            "aria-label": crate::i18n::tr("settings.capabilities.close_detail"),
                                            onclick: move |_| detail_for.set(None),
                                            "×"
                                        }
                                    }
                                    div { class: "muted", title: "{row.capability_id}", "{capability_id_label}" }
                                    if row.issuer_authority_refs.is_empty() {
                                        div {
                                            class: "muted",
                                            "data-testid": "capability-authority-empty",
                                            {crate::i18n::tr("settings.capabilities.authority_empty")}
                                        }
                                    } else {
                                        ol { class: "settings-list",
                                            for (idx, authority) in row.issuer_authority_refs.iter().enumerate() {
                                                li {
                                                    class: "event",
                                                    "data-testid": "capability-authority-ref",
                                                    "data-ref-index": "{idx}",
                                                    div { class: "mono", "{authority_label(authority)}" }
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

// Keep the existing safe API-error classification, then translate at render time.
// Local errors have no server envelope and retain their opaque message.
pub(super) fn api_error_feedback_args(
    error: &crate::transport::auth::ApiCallError,
) -> Vec<(&'static str, String)> {
    use crate::transport::auth::ApiCallError;
    let key = match error {
        ApiCallError::Unavailable(inner) if crate::api_error::is_response_format_error(inner) => {
            crate::api_error::user_facing_error_key(inner)
        }
        ApiCallError::Unavailable(_) => Some("error.server_unavailable"),
        ApiCallError::AuthExpired(_) => Some("error.session_expired"),
        ApiCallError::Failed(inner) => crate::api_error::user_facing_error_key(inner),
    };
    match key {
        Some(key) => vec![("error_i18n_key", key.to_owned())],
        None => vec![("error", error.display())],
    }
}

pub(super) fn localized_feedback_args(
    args: &[(&'static str, String)],
) -> Vec<(&'static str, String)> {
    args.iter()
        .map(|(key, value)| {
            if *key == "error_i18n_key" {
                ("error", crate::i18n::tr(value))
            } else {
                (*key, value.clone())
            }
        })
        .collect()
}

fn capability_feedback_text(status: &(&str, Vec<(&'static str, String)>)) -> String {
    let mut args = localized_feedback_args(&status.1);
    if status.0 == "settings.capabilities.failed" {
        let hint = args
            .iter()
            .find(|(key, _)| *key == "error")
            .and_then(|(_, error)| relinquish_failure_hint(error))
            .map(|key| format!(" — {}", crate::i18n::tr(key)))
            .unwrap_or_default();
        args.push(("hint", hint));
    }
    // Insert opaque server detail last so its own braces remain untouched.
    args.sort_by_key(|(key, _)| *key == "error");
    crate::i18n::tr_args(status.0, &args)
}

/// Operator guidance for the known relinquish rejection reasons, appended to
/// the raw error text in the status line.
fn relinquish_failure_hint(error_text: &str) -> Option<&'static str> {
    if error_text.contains("grant_relinquish_not_subject") {
        Some("settings.capabilities.hint_subject")
    } else if error_text.contains("capability_target_unresolved")
        || error_text.contains("dependency_pending")
    {
        Some("settings.capabilities.hint_pending")
    } else {
        None
    }
}

fn relinquish_failure_requires_refresh(error_text: &str) -> bool {
    error_text.contains("cas_conflict")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn retained_authority_and_relinquish_error_follow_the_live_locale() {
        let effective = sample_effective_row(json!({"kind": "condition", "required_claims": []}));
        let row = decode_capability_row(&effective, "unused-fallback");
        let failure = (
            "settings.capabilities.failed",
            vec![(
                "error",
                "grant_relinquish_not_subject: raw {hint} / 原文".to_owned(),
            )],
        );
        let problem: arkret_sdk::Problem = serde_json::from_value(json!({
            "type": "https://arkret.org/problems/internal_error",
            "title": "Internal error", "status": 500,
            "detail": "private server detail / 原文", "code": "internal_error"
        }))
        .unwrap();
        let server_error = crate::transport::auth::ApiCallError::Failed(
            crate::api_error::TransportClientError {
                status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                error: problem,
            }
            .into(),
        );
        // Capture once, before either locale change, as an async completion does.
        let retained_safe_error = super::api_error_feedback_args(&server_error);
        let mut dom = dioxus::prelude::VirtualDom::new(|| dioxus::prelude::rsx! {});
        dom.rebuild_in_place();
        dom.in_scope(dioxus::prelude::ScopeId::ROOT, || {
            let mut locale = dioxus::prelude::provide_context(crate::i18n::init_i18n_with_locale(
                crate::i18n::UiLocale::En,
            ));
            for (language, authority, hint) in [
                (
                    crate::i18n::UiLocale::En,
                    "realm root",
                    "only the subject may relinquish",
                ),
                (
                    crate::i18n::UiLocale::Zh,
                    "Realm 根授权",
                    "仅持有人可放弃授权",
                ),
                (
                    crate::i18n::UiLocale::En,
                    "realm root",
                    "only the subject may relinquish",
                ),
            ] {
                crate::i18n::set_locale(&mut locale, language);
                let safe = super::localized_feedback_args(&retained_safe_error);
                assert_eq!(safe[0].0, "error");
                assert_eq!(safe[0].1, server_error.display());
                assert!(
                    safe[0]
                        .1
                        .contains(if language == crate::i18n::UiLocale::Zh {
                            "与服务器通信时出现问题"
                        } else {
                            "Something went wrong while talking to the server"
                        })
                );
                assert!(!safe[0].1.contains("private server detail"));
                let label = super::authority_label(&row.issuer_authority_refs[0]);
                assert!(label.contains(authority));
                assert!(label.contains(effective.grant.realm_id.as_ref().unwrap().as_str()));
                let text = super::capability_feedback_text(&failure);
                assert!(text.contains(&failure.1[0].1));
                assert!(text.contains(hint));
                assert_eq!(
                    row.issuer_authority_refs,
                    effective.grant.issuer_authority_refs
                );
                assert_eq!(row.revision, effective.revision);
            }
        });
    }

    use super::*;

    fn sample_effective_row(subject: serde_json::Value) -> EffectiveCapabilityGrantRow {
        let value = json!({
            "grant": {
                "id": "ak:grant:AfpU2UOijpNUdGOoAgQdaqV0xwreLXwLE3yXXHvB6n7X",
                "schema": "ak.schema.capability.v1",
                "realm_id": "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                "issuer_id": {"kind": "account", "account_id": {
                    "principal_id": "ak:did_core:web:alice.example",
                    "station_id": "ak:did_core:web:principal.example"
                }},
                "subject": subject,
                "actions": ["ak.message.create"],
                "status": "active",
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
                    "authority_generation": 0,
                    "authority_event_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
                }],
                "authority_depth": 0,
                "authority_root_refs": [{
                    "kind": "realm_root",
                    "realm_id": "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                    "authority_generation": 0,
                    "authority_event_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
                }]
            },
            "revision": {
                "commit_id": "ak:realm_commit:AT33EWBTXdTx5CjY-ogbIIF2T4vh-v7jCMCQ80Fss2Rq",
                "stream_position": 2
            }
        });
        serde_json::from_value(value)
            .expect("sample row decodes as SDK EffectiveCapabilityGrantRow")
    }

    #[test]
    fn maps_sdk_grant_to_capability_row() {
        let row = decode_capability_row(
            &sample_effective_row(json!({"kind": "account", "account_id": {
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
            &sample_effective_row(json!({
                "kind": "condition",
                "required_claims": []
            })),
            "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        );
        assert!(row.subject.contains("condition"));
    }

    #[test]
    fn relinquish_requires_same_actor_id_variant_and_station() {
        let principal = arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap();
        let station = arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap();
        let subject = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            principal.clone(),
            station.clone(),
        ));
        let row = decode_capability_row(
            &sample_effective_row(serde_json::to_value(&subject).unwrap()),
            "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        );
        assert!(row.can_relinquish(Some(&subject)));
        assert!(!row.can_relinquish(None));
        let foreign = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            principal.clone(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        ));
        assert!(!row.can_relinquish(Some(&foreign)));
        assert!(!row.can_relinquish(Some(&arkret_sdk::ActorId::service(principal))));
    }

    #[test]
    fn relinquish_failure_hint_covers_the_subject_guard() {
        assert!(relinquish_failure_hint("rejected: grant_relinquish_not_subject").is_some());
        assert!(relinquish_failure_hint("capability_target_unresolved").is_some());
        assert_eq!(relinquish_failure_hint("network timeout"), None);
    }

    #[test]
    fn relinquish_uses_only_the_exact_confirmed_row_revision() {
        let effective = sample_effective_row(json!({"kind": "account", "account_id": {
            "principal_id": "ak:did_core:web:bob.example",
            "station_id": "ak:did_core:web:principal.example"
        }}));
        let row = decode_capability_row(
            &effective,
            "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        );
        let confirmation = RelinquishConfirmation {
            capability_id: row.capability_id.clone(),
            revision: row.revision.clone(),
        };
        let payload = build_confirmed_relinquish_payload(&row, &confirmation, "no longer needed")
            .expect("exact confirmed row is authorable");
        assert_eq!(payload.expected_revision, effective.revision);

        let mut refreshed = row.clone();
        refreshed.revision.stream_position += 1;
        assert!(build_confirmed_relinquish_payload(&refreshed, &confirmation, "").is_err());
    }

    #[test]
    fn effective_row_without_revision_cannot_reach_authoring() {
        let mut value = serde_json::to_value(sample_effective_row(json!({
            "kind": "account",
            "account_id": {
                "principal_id": "ak:did_core:web:bob.example",
                "station_id": "ak:did_core:web:principal.example"
            }
        })))
        .unwrap();
        value.as_object_mut().unwrap().remove("revision");
        assert!(serde_json::from_value::<EffectiveCapabilityGrantRow>(value).is_err());
    }

    #[test]
    fn cas_conflict_requires_refresh_before_another_confirmation() {
        assert!(relinquish_failure_requires_refresh(
            "server rejected event: cas_conflict"
        ));
        assert!(!relinquish_failure_requires_refresh("dependency_pending"));
    }
}
