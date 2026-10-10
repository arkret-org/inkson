//! Applet Service installation, registry and accountability views.
//!
//! Installation submits the administrator-authored registration and grants after
//! a Station plan preview. Independent Bots are created by the installed Service;
//! this account client cannot impersonate its RFC9421 transport identity.
//! Registry rows retain actual Applet identifiers and registration epochs.

use std::collections::BTreeSet;

use arkret_models_integration::{
    AppletActorPolicy, AppletApprovalRequest, AppletGhostActorMode,
    AppletInstallAuthoringRequestBasis, AppletInstallPlan, AppletInstallPreviewOutcome,
    AppletInstallPreviewRequestBody, AppletInstallRequestBody, AppletManagedActorPurpose,
    AppletPackage, AppletRegistrationEpochEvidence, AppletRevokeRequestBody,
};
use arkret_wire::{AppletRevokeMode, DidCoreId, ScopeRef, event_kind_str};
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use serde_json::Value;

use crate::i18n::tr;
use crate::transport::auth::{with_authed_sdk_client, with_event_submitter};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::dialog::Dialog;
use crate::ui::textarea::Textarea;
use crate::views::helpers::short_protocol_id;

/// Parse the standard preview request and obtain epoch evidence exclusively
/// from its formal registration Event manifest.
pub fn applet_install_material_from_manifest(
    kind: &ManifestInputKind,
) -> Option<(AppletPackage, AppletRegistrationEpochEvidence)> {
    let ManifestInputKind::Json(raw) = kind else {
        return None;
    };
    let preview = serde_json::from_str::<AppletInstallPreviewRequestBody>(raw).ok()?;
    let registration_payload =
        serde_json::to_value(&preview.authoring_request_basis.registration_event.payload).ok()?;
    let registration: arkret_sdk::AppletRegistrationPayload =
        serde_json::from_value(registration_payload).ok()?;
    Some((
        preview.applet_package,
        registration.manifest.registration_epoch_evidence,
    ))
}

/// The effective-scope object an install/revoke targets. A blank `circle_id`
/// installs the applet Realm-wide; a `ak:circle:…` id scopes it to that Circle
/// only (spec §4b: a single install carries exactly one `effective_scope`, and a
/// Circle install MUST NOT widen to a Realm-wide grant). The Station checks
/// current management authority, operation policy and review at the exact scope.
pub fn applet_effective_scope(realm_id: &str, circle_id: Option<&str>) -> Result<ScopeRef, String> {
    let realm_id = crate::operation::trim_realm_id(realm_id);
    let realm = arkret_sdk::RealmId::new(realm_id.clone())
        .map_err(|err| format!("invalid Realm id {realm_id:?}: {err:?}"))?;
    match circle_id.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok(ScopeRef::Realm { realm_id: realm }),
        Some(circle) => arkret_sdk::CircleId::new(circle.to_owned())
            .map(|circle_id| ScopeRef::Circle {
                realm_id: realm,
                circle_id,
            })
            .map_err(|err| format!("invalid Circle id {circle:?}: {err:?}")),
    }
}

/// A conservative default approval request: no ghost / delegated-native actors,
/// no e2ee join, no widget — only the explicitly requested non-actor scopes.
/// The admin escalates these in the wizard's approval step before commit.
fn approval_request(
    approve_actions: Vec<String>,
    ghost_actor_mode: AppletGhostActorMode,
) -> AppletApprovalRequest {
    AppletApprovalRequest {
        approve_actions,
        ghost_actor_mode,
        delegated_native_actors_allowed: false,
        e2ee_join_allowed: false,
        widget_allowed: false,
    }
}

pub fn parse_applet_approval_actions(raw: &str) -> Vec<String> {
    raw.split(|ch: char| ch.is_ascii_whitespace() || ch == ',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter(|value| value.starts_with("ak."))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[derive(Clone)]
struct AppletInstallPreviewSnapshot {
    package: AppletPackage,
    basis: AppletInstallAuthoringRequestBasis,
    preview: AppletInstallPreviewOutcome,
}

fn approved_actions_from_plan(
    plan: &AppletInstallPlan,
    package: &AppletPackage,
) -> anyhow::Result<Vec<String>> {
    if plan.schema != AppletInstallPlan::SCHEMA {
        anyhow::bail!("preview returned unsupported schema {}", plan.schema);
    }
    if plan.compute_plan_digest()? != plan.plan_digest {
        anyhow::bail!("preview plan_digest does not cover the returned plan");
    }
    if plan.registration_epoch != package.registration_epoch {
        anyhow::bail!("preview registration_epoch does not match the Applet package");
    }
    let requested = package
        .requested_scopes
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut approved = BTreeSet::new();
    for scope in &plan.approved_scopes {
        for action in &scope.actions {
            if !requested.contains(action.as_str()) {
                anyhow::bail!("preview approved an action the Applet did not request: {action}");
            }
            if !approved.insert(action.clone()) {
                anyhow::bail!("preview approved the same action more than once: {action}");
            }
        }
    }
    if approved.is_empty() {
        anyhow::bail!("preview approved no Applet capability actions");
    }
    Ok(approved.into_iter().collect())
}

fn operation_builder_for_scope<K: arkret_sdk::EventSpec>(
    scope: &ScopeRef,
    actor_id: &str,
    payload: K::Payload,
) -> crate::operation::TypedOperationBuilder {
    match scope {
        ScopeRef::Realm { realm_id } => crate::operation::TypedOperationBuilder::new::<K>(
            realm_id.to_string(),
            actor_id,
            payload,
        ),
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } => crate::operation::TypedOperationBuilder::new::<K>(
            realm_id.to_string(),
            actor_id,
            payload,
        )
        .circle_id(circle_id.to_string()),
        _ => unreachable!("Applet install schema only permits Realm and Circle scopes"),
    }
}

fn applet_install_resource(scope: &ScopeRef) -> anyhow::Result<arkret_sdk::WireResourceSelector> {
    let selector = match scope {
        ScopeRef::Realm { realm_id } => arkret_sdk::WireResourceSelector::realm(realm_id.clone()),
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } => {
            let mut selector =
                arkret_sdk::WireResourceSelector::circle(realm_id.clone(), circle_id.clone());
            selector.match_scope = Some(arkret_sdk::ResourceMatchScope::Exact);
            selector
        }
        _ => anyhow::bail!("Applet install schema only permits Realm and Circle scopes"),
    };
    selector.validate()?;
    Ok(selector)
}

/// Convert only a previously verified governing-Station authority bundle into
/// the semantic Realm-root lineage carried by Applet capability grants.
/// Missing or cross-Realm cached state is not an authoring basis.
fn applet_capability_issuer_basis(
    basis: Option<crate::state::PersistedRealmAuthorityBasis>,
    realm_id: &arkret_sdk::RealmId,
) -> Option<crate::operation::ak_ops::IssuerRealmAuthorityBasis> {
    let basis = basis.filter(|basis| &basis.realm_id == realm_id)?;
    let authority_event_ref = basis
        .last_authority_change_ref
        .as_ref()
        .unwrap_or(&basis.genesis_ref)
        .event_id
        .clone();
    Some(crate::operation::ak_ops::IssuerRealmAuthorityBasis {
        authority_generation: basis.current_generation,
        authority_event_ref,
    })
}

fn build_formal_applet_install_events(
    package: &AppletPackage,
    registration_epoch_evidence: &AppletRegistrationEpochEvidence,
    effective_scope: &ScopeRef,
    approved_actions: &[String],
    actor_id: &str,
    target_station_id: &arkret_sdk::DidCoreId,
    issuer_authority_basis: &crate::operation::ak_ops::IssuerRealmAuthorityBasis,
    created_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<(
    crate::operation::LocalOperation,
    Vec<crate::operation::LocalOperation>,
)> {
    let actor = crate::mls_api_helpers::principal_core_id(actor_id)
        .map_err(|error| anyhow::anyhow!("invalid install actor DID: {error}"))?;
    package.validate_with_epoch_evidence(registration_epoch_evidence)?;
    let registration_payload: arkret_sdk::AppletRegistrationPayload =
        package.to_registration(registration_epoch_evidence)?;
    let registration = operation_builder_for_scope::<arkret_sdk::event_spec::AppletRegistration>(
        effective_scope,
        actor_id,
        registration_payload,
    )
    .created_at(created_at)
    .build_sdk_event("inkson")?;

    let requested = package
        .requested_scopes
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let actions = approved_actions
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if actions.is_empty() || !actions.iter().all(|action| requested.contains(action)) {
        anyhow::bail!("approved Applet actions must be a non-empty subset of requested_scopes");
    }
    let constraint = arkret_sdk::GrantConstraint::applet_authority(
        package.applet_id.clone(),
        arkret_sdk::ActorId::service(package.service_id.clone()),
        package.registration_epoch.clone(),
    );
    let resource = applet_install_resource(effective_scope)?;
    let realm_id = match effective_scope {
        ScopeRef::Realm { realm_id } | ScopeRef::Circle { realm_id, .. } => realm_id.clone(),
        _ => unreachable!("validated Applet effective scope"),
    };
    let mut grant_events = Vec::with_capacity(actions.len());
    for action in actions {
        let grant = arkret_sdk::CapabilityGrantCreateBody {
            schema: arkret_wire::SchemaId::CAPABILITY_V1.to_owned(),
            realm_id: Some(realm_id.clone()),
            issuer_id: arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                actor.clone(),
                target_station_id.clone(),
            )),
            subject: arkret_sdk::CapabilitySubject::Actor(arkret_sdk::ActorId::service(
                package.service_id.clone(),
            )),
            actions: vec![action.to_owned()],
            resources: vec![resource.clone()],
            constraints: vec![constraint.clone()],
            // The installing owner issues these under the Realm authority
            // root, which is what `issuer_authority_refs` now records.
            issuer_authority_refs: vec![arkret_sdk::IssuerAuthorityRef::RealmRoot {
                realm_id: realm_id.clone(),
                authority_event_ref: issuer_authority_basis.authority_event_ref.clone(),
                authority_generation: issuer_authority_basis.authority_generation,
            }],
            issued_at: created_at,
        };
        let payload = arkret_sdk::CapabilityGrantPayload { grant };
        grant_events.push(
            operation_builder_for_scope::<arkret_sdk::event_spec::CapabilityGrant>(
                effective_scope,
                actor_id,
                payload,
            )
            .created_at(created_at)
            .build_sdk_event("inkson")?,
        );
    }
    Ok((registration, grant_events))
}

/// Whether the local UI should expose applet install / registration panels.
pub fn applets_enabled() -> bool {
    cfg!(feature = "experimental-applets")
}

/// Render the namespace keys from the canonical registration payload. The
/// retired short form carried one `namespace` string; full registrations use
/// the closed `namespaces` object.
fn registration_namespace_label(body: Option<&Value>) -> String {
    body.and_then(|value| value.get("namespaces"))
        .and_then(Value::as_object)
        .map(|namespaces| namespaces.keys().cloned().collect::<Vec<_>>().join(", "))
        .filter(|label| !label.is_empty())
        .unwrap_or_else(|| "—".to_owned())
}

/// Parse a manifest input as either a URL (returns Url variant) or
/// inline JSON (returns Json variant). The cotest harness pastes a
/// `https://mock-applet-registry/.../manifest.json` URL OR a raw JSON
/// body in the same input; this helper disambiguates so the verifier
/// can take the right branch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestInputKind {
    Url(String),
    Json(String),
    Invalid,
}

pub fn classify_manifest_input(raw: &str) -> ManifestInputKind {
    let t = raw.trim();
    if t.is_empty() {
        return ManifestInputKind::Invalid;
    }
    if t.starts_with("http://") || t.starts_with("https://") {
        return ManifestInputKind::Url(t.to_owned());
    }
    if t.starts_with('{') && serde_json::from_str::<Value>(t).is_ok() {
        return ManifestInputKind::Json(t.to_owned());
    }
    ManifestInputKind::Invalid
}

/// Translate only the count label, keeping the observed registration count intact.
fn applet_registered_count(count: usize) -> String {
    crate::i18n::tr_args("applets.registered_count", &[("count", count.to_string())])
}

/// Substitute one presentation value once; raw identifiers are never dictionary keys.
fn applet_value_label(key: &'static str, value: &str) -> String {
    crate::i18n::tr_args(key, &[("value", value.to_owned())])
}

/// Transient presentation state; retained errors are rendered with the current locale.
/// This type is neither an installation authority nor a protocol/persistence model.
#[derive(Clone, Debug)]
enum AppletInstallFeedback {
    InvalidManifest,
    PreviewAccountUnavailable,
    InvalidRealm(String),
    AuthorityUnavailable,
    Previewing,
    InvalidScope(String),
    MissingPackageDigest,
    PlanReady {
        scopes: usize,
        actions: usize,
        digest: String,
    },
    ScopeMismatch,
    InvalidPreview(String),
    PreviewFailed(std::sync::Arc<crate::transport::auth::ApiCallError>),
    PreviewRequired,
    Installing,
    Installed(String),
    PartiallyInstalled {
        applet_id: String,
        rejected: usize,
    },
    InstallFailed(std::sync::Arc<crate::transport::auth::ApiCallError>),
    RevokeAccountUnavailable,
    Revoking,
    Revoked(usize),
    RevokeFailed(std::sync::Arc<crate::transport::auth::ApiCallError>),
}

impl AppletInstallFeedback {
    fn render(&self) -> String {
        use AppletInstallFeedback::*;

        use crate::i18n::tr_args;
        match self {
            InvalidManifest => tr("applets.feedback.invalid_manifest"),
            PreviewAccountUnavailable => tr("applets.feedback.preview_account_unavailable"),
            InvalidRealm(error) => tr_args(
                "applets.feedback.invalid_realm",
                &[("error", error.clone())],
            ),
            AuthorityUnavailable => tr("applets.feedback.authority_unavailable"),
            Previewing => tr("applets.feedback.previewing"),
            // Existing local validation diagnostics remain literal parameters.
            InvalidScope(error) => error.clone(),
            MissingPackageDigest => tr("applets.feedback.missing_package_digest"),
            PlanReady {
                scopes,
                actions,
                digest,
            } => tr_args(
                "applets.feedback.plan_ready",
                &[
                    ("scopes", scopes.to_string()),
                    ("actions", actions.to_string()),
                    ("digest", digest.clone()),
                ],
            ),
            ScopeMismatch => tr("applets.feedback.scope_mismatch"),
            InvalidPreview(error) => tr_args(
                "applets.feedback.invalid_preview",
                &[("error", error.clone())],
            ),
            PreviewFailed(error) => tr_args(
                "applets.feedback.preview_failed",
                &[("error", error.display())],
            ),
            PreviewRequired => tr("applets.feedback.preview_required"),
            Installing => tr("applets.feedback.installing"),
            Installed(applet_id) => tr_args(
                "applets.feedback.installed",
                &[("applet_id", applet_id.clone())],
            ),
            PartiallyInstalled {
                applet_id,
                rejected,
            } => tr_args(
                "applets.feedback.partially_installed",
                &[
                    ("rejected", rejected.to_string()),
                    ("applet_id", applet_id.clone()),
                ],
            ),
            InstallFailed(error) => tr_args(
                "applets.feedback.install_failed",
                &[("error", error.display())],
            ),
            RevokeAccountUnavailable => tr("applets.feedback.revoke_account_unavailable"),
            Revoking => tr("applets.feedback.revoking"),
            Revoked(count) => tr_args("applets.feedback.revoked", &[("count", count.to_string())]),
            RevokeFailed(error) => tr_args(
                "applets.feedback.revoke_failed",
                &[("error", error.display())],
            ),
        }
    }
}

fn applet_install_feedback(status: Option<&AppletInstallFeedback>) -> Element {
    let text = status
        .map(AppletInstallFeedback::render)
        .unwrap_or_default();
    rsx! {
        if !text.is_empty() {
            div { class: "muted", "data-testid": "applet-install-status", "{text}" }
        }
    }
}

#[component]
pub fn AppletsPanel(token: Signal<String>, selected_realm_id: String) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let session = crate::app::SessionContext::get();
    let base_url = crate::app::SessionContext::base_url_string();
    let state_store = session.state_store;
    let active_account = session.active_account;
    // ─────────────────────────────────────────────────────────────
    // G3.Y4 — install / uninstall / accountability state
    // ─────────────────────────────────────────────────────────────
    let mut install_open = use_signal(|| false);
    let mut install_manifest = use_signal(String::new);
    let mut install_status = use_signal(|| Option::<AppletInstallFeedback>::None);
    // The exact typed preview snapshot is the sole confirm-state authority.
    // Any input change discards it atomically.
    let mut install_preview = use_signal(|| Option::<AppletInstallPreviewSnapshot>::None);
    let mut install_approve_actions = use_signal(String::new);
    let mut install_ghost_actors_allowed = use_signal(|| false);
    // Optional Circle scope for the install. Blank = Realm-wide; a `ak:circle:…`
    // id scopes the install to that Circle only (spec §4b effective_scope).
    let mut install_circle_id = use_signal(String::new);
    let mut trace_open_for = use_signal(|| Option::<String>::None);

    // Pull registry rows from the local raw-operation
    // projection. The shape is keyed by op_type so a row's evidence is
    // the actual canonical event the projection observed; this view is
    // explicitly local-only — soland's projection_events feed will fan
    // out the same shape once the server-side applet broker ships.
    let raw_ops = state_store.read().load().raw_operations;
    let registrations: Vec<_> = raw_ops
        .iter()
        .filter_map(|r| {
            let is_registration = r
                .payload
                .get("kind")
                .and_then(Value::as_str)
                .map(|k| k == event_kind_str::APPLET_REGISTRATION)
                .unwrap_or(false);
            if !is_registration {
                return None;
            }
            let service_id = r
                .payload
                .get("body")
                .and_then(|body| body.get("service_id"))
                .and_then(Value::as_str)
                .and_then(|value| DidCoreId::new(value.to_owned()).ok())?;
            Some((r.clone(), service_id.into_string()))
        })
        .collect();
    let bridge_errors: Vec<_> = raw_ops
        .iter()
        .filter(|r| {
            r.payload
                .get("kind")
                .and_then(Value::as_str)
                .map(|k| k == event_kind_str::APPLET_BRIDGE_ERROR)
                .unwrap_or(false)
        })
        .cloned()
        .collect();

    // Render only actual registration coordinates and exact executable scopes.
    // Local projection rows never manufacture an Applet id or package digest.
    let applet_rows: Vec<_> = registrations
        .iter()
        .filter_map(|(r, service_id)| {
            let body = r.payload.get("body")?;
            let applet_id = arkret_sdk::AppletId::new(body.get("applet_id")?.as_str()?).ok()?;
            let registration_epoch =
                arkret_sdk::Hash::new(body.get("registration_epoch")?.as_str()?).ok()?;
            let scope: ScopeRef =
                serde_json::from_value(r.payload.get("scope_ref")?.clone()).ok()?;
            if !matches!(scope, ScopeRef::Realm { .. } | ScopeRef::Circle { .. })
                || scope.realm_id_opt()?.as_str()
                    != crate::operation::trim_realm_id(&selected_realm_id)
            {
                return None;
            }
            Some((
                applet_id.to_string(),
                service_id.clone(),
                registration_namespace_label(Some(body)),
                registration_epoch.to_string(),
                r.operation_id.clone(),
                scope,
            ))
        })
        .collect();

    // Audit trace for an applet: every raw op whose body
    // service_id matches the row's service_id. We materialize
    // once so the modal rendering doesn't re-filter on every paint.
    let trace_open_applet_id = trace_open_for();
    let trace_target_id = applet_rows
        .iter()
        .find(|(id, ..)| Some(id) == trace_open_applet_id.as_ref())
        .map(|(_, did, ..)| did.clone());
    let trace_events: Vec<_> = match &trace_target_id {
        Some(target) => raw_ops
            .iter()
            .filter(|r| {
                let kind_is_applet = r
                    .payload
                    .get("kind")
                    .and_then(Value::as_str)
                    .map(|k| k.starts_with("ak.applet."))
                    .unwrap_or(false);
                let matches_did = r
                    .payload
                    .get("body")
                    .and_then(|b| b.get("service_id"))
                    .and_then(Value::as_str)
                    .map(|d| d == target.as_str())
                    .unwrap_or(false);
                kind_is_applet && matches_did
            })
            .cloned()
            .collect(),
        None => Vec::new(),
    };

    rsx! {
           div { class: "timeline", "data-testid": "applets-panel", role: "region", "aria-label": tr("applets.region"),
               div { class: "event",
                   div { class: "event-head",
                       span { {tr("applets.registry")} }
                       span { class: "badge", {applet_registered_count(registrations.len())} }
                   }
                   div { class: "muted",
                       {tr("applets.registry_help")}
                   }
                   if registrations.is_empty() {
                       div { class: "muted", "data-testid": "applet-registry-empty",
                           {tr("applets.registry_empty")}
                       }
                   } else {
                       for (r, service_id) in registrations {
                           {
                               let namespace = registration_namespace_label(r.payload.get("body"));
                               let op_id = r.operation_id.clone();
                               let service_id_label = short_protocol_id(&service_id);
                               let op_id_label = short_protocol_id(&op_id);
                               rsx! {
                                   div { class: "event", "data-testid": "applet-registration-row",
                                       div { class: "event-head",
                                           span { class: "mono", title: "{service_id}", "{service_id_label}" }
                                           span { class: "badge", "{namespace}" }
                                       }
                                       div { class: "muted", title: "{op_id}", {applet_value_label("applets.operation_id", &op_id_label)} }
                                   }
                               }
                           }
                       }
                   }
               }
               div { class: "event", "data-testid": "applet-bridge-errors",
                   div { class: "event-head",
                       span { {tr("applets.bridge_errors")} }
                       span { class: "badge red", "{bridge_errors.len()}" }
                   }
                   if bridge_errors.is_empty() {
                       div { class: "muted", {tr("applets.bridge_errors_empty")} }
                   } else {
                       for e in bridge_errors {
                           {
                               let error_code = e.payload.get("body")
                                   .and_then(|b| b.get("error_code"))
                                   .and_then(Value::as_str)
                                   .unwrap_or("?")
                                   .to_owned();
                               let failed_transaction_ref = e.payload.get("body")
                                   .and_then(|b| b.get("failed_transaction_ref"))
                                   .and_then(Value::as_str)
                                   .unwrap_or("?")
                                   .to_owned();
                               let msg_opt = e.payload.get("body")
                                   .and_then(|b| b.get("message"))
                                   .and_then(Value::as_str)
                                   .map(ToOwned::to_owned);
                               let failed_transaction_ref_label = short_protocol_id(&failed_transaction_ref);
                               rsx! {
                                   div { class: "event", "data-testid": "applet-bridge-error-row",
                                       div { class: "event-head",
                                           span { class: "mono", "{error_code}" }
                                           span { class: "mono", title: "{failed_transaction_ref}", "{failed_transaction_ref_label}" }
                                       }
                                       if let Some(msg) = msg_opt {
                                           div { class: "muted", "{msg}" }
                                       }
                                   }
                               }
                           }
                       }
                   }
               }

               // ─────────────────────────────────────────────────────
               // G3.Y4 — install / list panel + accountability trace
               // ─────────────────────────────────────────────────────
               div { class: "event", "data-testid": "applet-list-panel",
                   div { class: "event-head",
                       span { {tr("applets.installed")} }
                       span { class: "badge", "{applet_rows.len()}" }
                       Button {
                           variant: ButtonVariant::Primary,
                           "data-testid": "applet-install-button",
                           onclick: move |_| install_open.set(!install_open()),
                           if install_open() { {tr("applets.close_install")} } else { {tr("applets.open_install")} }
                       }
                   }
                   if install_open() {
                       div { class: "workflow-form",
                           Textarea {
                               "data-testid": "applet-install-manifest-input",
                               placeholder: tr("applets.manifest_placeholder"),
                               value: "{install_manifest}",
                               oninput: move |event: FormEvent| {
                                   install_manifest.set(event.value());
                                   install_preview.set(None);
                               },
                               style: "width: 100%; min-height: 60px;",
                           }
                           // Optional Circle scope. Blank installs Realm-wide; a
                           // `ak:circle:…` id scopes the applet to that Circle only.
                           // Changing it invalidates the previewed plan (the digest
                           // is computed over effective_scope), so re-preview.
                           Textarea {
                               "data-testid": "applet-install-circle-input",
                               placeholder: tr("applets.circle_placeholder"),
                               value: "{install_circle_id}",
                               oninput: move |event: FormEvent| {
                                   install_circle_id.set(event.value());
                                   install_preview.set(None);
                               },
                               style: "width: 100%; min-height: 32px;",
                           }
                           Textarea {
                               "data-testid": "applet-install-approve-actions-input",
                               placeholder: tr("applets.actions_placeholder"),
                               value: "{install_approve_actions}",
                               oninput: move |event: FormEvent| {
                                   install_approve_actions.set(event.value());
                                   install_preview.set(None);
                               },
                               style: "width: 100%; min-height: 48px;",
                           }
                           label { class: "metric", "data-testid": "applet-install-ghost-row",
                               Checkbox {
                                   "data-testid": "applet-install-allow-ghost",
                                   checked: if install_ghost_actors_allowed() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                   on_checked_change: move |state: CheckboxState| {
                                       install_ghost_actors_allowed.set(bool::from(state));
                                       install_preview.set(None);
                                   },
                               }
                               span { {tr("applets.allow_ghost")} }
                           }
                           // Step 1 — author the administrator Events once, then ask
                           // the Station to sign the closed authoring request.
                           div { class: "actions",
                               Button {
                                   variant: ButtonVariant::Secondary,
                                   "data-testid": "applet-install-verify-button",
                                   onclick: {
                                       let base = base_url.clone();
                                       let realm = selected_realm_id.clone();
                                       move |_| {
                                           let raw = install_manifest();
                                           let kind = classify_manifest_input(&raw);
                                           let Some((package, registration_epoch_evidence)) =
                                               applet_install_material_from_manifest(&kind)
                                           else {
                                               install_preview.set(None);
                                               install_status.set(Some(AppletInstallFeedback::InvalidManifest));
                                               return;
                                           };
                                           let base = base.clone();
                                           let realm = realm.clone();
                                           let api_token = token();
                                           let Some(account) = active_account.peek().clone() else {
                                               install_status.set(Some(AppletInstallFeedback::PreviewAccountUnavailable));
                                               return;
                                           };
                                           let actor_id = account.principal_id().clone();
                                           let install_actor_id = arkret_sdk::ActorId::account(account.authority.clone());
                                           let target_station_id = account.authority.station_id.clone();
                                           let realm_typed = match arkret_sdk::RealmId::new(realm.clone()) {
                                               Ok(realm_id) => realm_id,
                                               Err(error) => {
                                                   install_status.set(Some(AppletInstallFeedback::InvalidRealm(error.to_string())));
                                                   return;
                                               }
                                           };
                                           let issuer_authority_basis = applet_capability_issuer_basis(
                                               state_store.read().realm_authority_basis(realm_typed.as_str()),
                                               &realm_typed,
                                           );
                                           let Some(issuer_authority_basis) = issuer_authority_basis else {
                                               install_status.set(Some(AppletInstallFeedback::AuthorityUnavailable));
                                               return;
                                           };
                                           let circle = install_circle_id();
                                           let approve_actions = parse_applet_approval_actions(
                                               &install_approve_actions(),
                                           );
                                           let ghost_actor_mode = if install_ghost_actors_allowed() {
                                               AppletGhostActorMode::PolicyDeclared
                                           } else {
                                               AppletGhostActorMode::Disallowed
                                           };
                                           install_status.set(Some(AppletInstallFeedback::Previewing));
                                           spawn(async move {
                                               let effective_scope = match applet_effective_scope(
                                                   &realm,
                                                   Some(circle.as_str()),
                                               ) {
                                                   Ok(scope) => scope,
                                                   Err(err) => {
                                                       install_status.set(Some(AppletInstallFeedback::InvalidScope(err)));
                                                       return;
                                                   }
                                               };
                                               let approval_request = approval_request(
                                                   approve_actions.clone(),
                                                   ghost_actor_mode,
                                               );
                                               let actor_policy = AppletActorPolicy {
                                                   ghost_actor_mode: Some(ghost_actor_mode),
                                               };
                                               let requested_at = crate::clock::now_utc_millis();
                                               let package_digest = match package.package_digest.clone() {
                                                   Some(value) => value,
                                                   None => {
                                                       install_status.set(Some(AppletInstallFeedback::MissingPackageDigest));
                                                       return;
                                                   }
                                               };
                                               let authored_package = package.clone();
                                               let authored_scope = effective_scope.clone();
                                               let result = with_event_submitter(&base, api_token, |submitter| async move {
                                                   let (registration, grants) =
                                                       build_formal_applet_install_events(
                                                           &authored_package,
                                                           &registration_epoch_evidence,
                                                           &authored_scope,
                                                           &approve_actions,
                                                           actor_id.as_str(),
                                                           &target_station_id,
                                                           &issuer_authority_basis,
                                                           requested_at,
                                                       )?;
                                                   let mut events = Vec::with_capacity(1 + grants.len());
                                                   events.push(registration.into_intent());
                                                   events.extend(grants.into_iter().map(
                                                       crate::operation::LocalOperation::into_intent,
                                                   ));
                                                   let mut events = submitter
                                                       .author_independent_events(events)
                                                       .await?
                                                       .into_iter()
                                                       .map(arkret_sdk::AuthoredEvent::into_event)
                                                       .collect::<Vec<_>>();
                                                   let registration_event = events.remove(0);
                                                   let body = AppletInstallPreviewRequestBody {
                                                       applet_package: authored_package.clone(),
                                                       authoring_request_basis:
                                                           AppletInstallAuthoringRequestBasis {
                                                               schema: AppletInstallAuthoringRequestBasis::SCHEMA.to_owned(),
                                                               purpose: AppletManagedActorPurpose::InstallService,
                                                               target_station_id,
                                                               install_actor_id,
                                                               applet_id: authored_package.applet_id.clone(),
                                                               service_id: authored_package.service_id.clone(),
                                                               package_digest,
                                                               effective_scope: authored_scope.clone(),
                                                               approval_request,
                                                               actor_policy: Some(actor_policy),
                                                               e2ee_policy: None,
                                                               widget_policy: None,
                                                               registration_event,
                                                               capability_grant_events: events,
                                                           },
                                                   };
                                                   let requested_basis = body.authoring_request_basis.clone();
                                                   let preview = submitter
                                                       .http()
                                                       .applet_install_preview(&body)
                                                       .await
                                                       .map_err(anyhow::Error::from)?;
                                                   Ok((preview, requested_basis))
                                               })
                                               .await;
                                               match result {
                                                   Ok((preview, requested_basis)) => match (|| {
                                                       approved_actions_from_plan(&preview.plan, &package)
                                                   })() {
                                                       Ok(actions)
                                                           if preview.plan.effective_scope == effective_scope
    =>
                                                       {
                                                           let scope_count = preview.plan.approved_scopes.len();
                                                           let digest = preview.plan.plan_digest.to_string();
                                                           install_preview.set(Some(AppletInstallPreviewSnapshot {
                                                               package,
                                                               basis: requested_basis,
                                                               preview,
                                                           }));
                                                           install_status.set(Some(AppletInstallFeedback::PlanReady {
                                                               scopes: scope_count,
                                                               actions: actions.len(),
                                                               digest: short_protocol_id(&digest),
                                                           }));
                                                       }
                                                       Ok(_) => {
                                                           install_preview.set(None);
                                                           install_status.set(Some(AppletInstallFeedback::ScopeMismatch));
                                                       }
                                                       Err(err) => {
                                                           install_preview.set(None);
                                                           install_status.set(Some(AppletInstallFeedback::InvalidPreview(err.to_string())));
                                                       }
                                                   },
                                                   Err(err) => {
                                                       install_preview.set(None);
                                                       install_status.set(Some(AppletInstallFeedback::PreviewFailed(std::sync::Arc::new(err))));
                                                   }
                                               }
                                           });
                                       }
                                   },
                                   {tr("applets.preview_plan")}
                               }
                               // Commit only the administrator-signed Service installation.
                               Button {
                                   variant: if install_preview().is_some() { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                                   disabled: install_preview().is_none(),
                                   "data-testid": "applet-install-confirm-button",
                                   onclick: {
                                       let base = base_url.clone();
                                       move |_| {
                                           let Some(snapshot) = install_preview() else {
                                               install_status.set(Some(AppletInstallFeedback::PreviewRequired));
                                               return;
                                           };
                                           let base = base.clone();
                                           let api_token = token();
                                           install_status.set(Some(AppletInstallFeedback::Installing));
                                           spawn(async move {
                                               let idem = snapshot.preview.plan.plan_digest.to_string();
                                               let result = with_authed_sdk_client(&base, api_token, |http| async move {
                                                   let body = AppletInstallRequestBody {
                                                       applet_package: snapshot.package,
                                                       authoring_request_basis: snapshot.basis,
                                                       plan_digest: snapshot.preview.plan.plan_digest,
                                                   };
                                                   http.applet_install(&idem, &body)
                                                       .await
                                                       .map_err(anyhow::Error::from)
                                               })
                                               .await;
                                               match result {
                                                   Ok(outcome) => {
                                                       use arkret_models_integration::AppletInstallEffectiveStatus as Status;
                                                       let aid = short_protocol_id(&outcome.applet_id);
                                                       let feedback = match outcome.effective_status {
                                                           Status::Installed => {
                                                               AppletInstallFeedback::Installed(aid)
                                                           }
                                                           Status::PartiallyInstalled => AppletInstallFeedback::PartiallyInstalled {
                                                               applet_id: aid,
                                                               rejected: outcome.rejections.len(),
                                                           },
                                                       };
                                                       let installed = matches!(outcome.effective_status, Status::Installed);
                                                       install_status.set(Some(feedback));
                                                       // Keep the form open on a partial outcome so the
                                                       // admin can adjust and retry denied scopes.
                                                       if installed {
                                                           install_open.set(false);
                                                           install_manifest.set(String::new());
                                                           install_circle_id.set(String::new());
                                                           install_approve_actions.set(String::new());
                                                           install_ghost_actors_allowed.set(false);
                                                           install_preview.set(None);
                                                       }
                                                   }
                                                   Err(err) => install_status.set(Some(AppletInstallFeedback::InstallFailed(std::sync::Arc::new(err)))),
                                               }
                                           });
                                       }
                                   },
                                   {tr("applets.install")}
                               }
                           }
                           {applet_install_feedback(install_status.read().as_ref())}
                       }
                   }

                   if applet_rows.is_empty() {
                       div { class: "muted", "data-testid": "applet-empty",
                           {tr("applets.installed_empty")}
                       }
                   } else {
                       for (applet_id, service_id, namespace, registration_epoch, registration_event_id, installed_scope) in applet_rows.iter().cloned() {
                           {
                               let service_id_label = short_protocol_id(&service_id);
                               let registration_epoch_label = short_protocol_id(&registration_epoch);
                               rsx! {
                                   div {
                                       class: "event",
                                       "data-testid": "applet-row",
                                       "data-applet-id": "{applet_id}",
                                       "data-applet-registration-epoch": "{registration_epoch}",
                                       "data-registration-event-id": "{registration_event_id}",
                                       div { class: "event-head",
                                           span { class: "mono", title: "{service_id}", "{service_id_label}" }
                                           span { class: "badge", "{namespace}" }
                                           span { class: "mono muted", title: "{registration_epoch}", "{registration_epoch_label}" }
                                       }
                                       div { class: "muted", "data-testid": "applet-bot-creation-status",
                                           {tr("applets.bot_creation_help")}
                                       }
                                       div { class: "actions",
                                           Button {
                                               variant: ButtonVariant::Secondary,
                                               "data-testid": "applet-accountability-trace-button",
                                               onclick: {
                                                   let aid = applet_id.clone();
                                                   move |_| trace_open_for.set(Some(aid.clone()))
                                               },
                                               {tr("applets.trace_events")}
                                           }
                                           Button {
                                               variant: ButtonVariant::Destructive,
                                               "data-testid": "applet-uninstall-button",
                                               onclick: {
                                                   let base = base_url.clone();
                                                   let effective_scope = installed_scope.clone();
                                                   let realm = effective_scope.realm_id_opt().unwrap().to_string();
                                                   let aid = applet_id.clone();
                                                   move |_| {
                                                       let base = base.clone();
                                                       let realm = realm.clone();
                                                       let effective_scope = effective_scope.clone();
                                                       let aid = aid.clone();
                                                       let api_token = token();
                                                       let Some(account) = active_account.peek().clone() else {
                                                           install_status.set(Some(AppletInstallFeedback::RevokeAccountUnavailable));
                                                           return;
                                                       };
                                                       let principal_id = account.authority.principal_id;
                                                       install_status.set(Some(AppletInstallFeedback::Revoking));
                                                       spawn(async move {
                                                           let reason_code = arkret_sdk::ReasonCode::PolicyRevoked;
                                                           let revoke_mode = AppletRevokeMode::RevokeRuntimeOnly;
                                                           let result = with_event_submitter(&base, api_token, |submitter| async move {
                                                               let preview = submitter.http().applet_revoke_preview(
                                                                   &aid,
                                                                   &arkret_sdk::AppletRevokePreviewRequestBody {
                                                                       effective_scope: effective_scope.clone(),
                                                                       reason_code: reason_code.clone(),
                                                                       revoke_mode,
                                                                   },
                                                               ).await.map_err(anyhow::Error::from)?;
                                                               if preview.revoke_plan.effective_scope != effective_scope {
                                                                   anyhow::bail!("revoke preview changed the installed scope");
                                                               }
                                                               if !preview.revoke_plan.membership_removals.is_empty() {
                                                                   anyhow::bail!("runtime revoke preview unexpectedly requires membership Events");
                                                               }
                                                               let mut revoke_events = Vec::with_capacity(
                                                                   preview.revoke_plan.capability_revocations.len(),
                                                               );
                                                               for intent in &preview.revoke_plan.capability_revocations {
                                                                   let builder = crate::operation::ak_ops::capability_revoke_from_applet_preview(
                                                                       &realm,
                                                                       principal_id.as_str(),
                                                                       intent,
                                                                   )?;
                                                                   let builder = match &effective_scope {
                                                                       ScopeRef::Circle { circle_id, .. } => builder.circle_id(circle_id.to_string()),
                                                                       _ => builder,
                                                                   };
                                                                   revoke_events.push(builder.build_sdk_event("inkson")?);
                                                               }
                                                               let authored_revokes = submitter
                                                                   .author_independent_events(
                                                                       revoke_events
                                                                           .into_iter()
                                                                           .map(crate::operation::LocalOperation::into_intent)
                                                                           .collect(),
                                                                   )
                                                                   .await?;
                                                               let capability_revoke_events = submitter
                                                                   .prepare_initial_submissions(&authored_revokes)
                                                                   .await?;
                                                               let revoke_plan_digest = arkret_sdk::Hash::new(
                                                                   arkret_sdk::canonical::canonical_sha256(&preview.revoke_plan)?,
                                                               )?;
                                                               let body = AppletRevokeRequestBody {
                                                                   revoke_plan_digest,
                                                                   effective_scope,
                                                                   reason_code,
                                                                   revoke_mode,
                                                                   capability_revoke_events,
                                                                   membership_state_events: Vec::new(),
                                                               };
                                                               let idempotency_key = crate::operation::uuid_v7();
                                                               submitter.http().applet_revoke(
                                                                   &aid,
                                                                   &idempotency_key,
                                                                   &body,
                                                               ).await.map_err(anyhow::Error::from)
                                                           })
                                                           .await;
                                                           match result {
                                                               Ok(outcome) => install_status.set(Some(AppletInstallFeedback::Revoked(outcome.revoked_refs.len()))),
                                                               Err(err) => install_status.set(Some(AppletInstallFeedback::RevokeFailed(std::sync::Arc::new(err)))),
                                                           }
                                                       });
                                                   }
                                               },
                                               {tr("applets.uninstall")}
                                           }
                                       }
                                   }
                               }
                           }
                       }
                   }
               }

               // Accountability trace modal — renders only when the
               // operator clicked the trace button on a row.
               if let Some(target) = trace_open_for() {
                   {
                       let target_label = short_protocol_id(&target);
                       rsx! {
                           Dialog {
                               open: true,
                               on_open_change: move |open: bool| {
                                   if !open {
                                       trace_open_for.set(None);
                                   }
                               },
                               "data-testid": "applet-accountability-modal",
                               div {
                                   class: "publish-to-source-modal",
                                   header {
                                       class: "publish-to-source-modal-header",
                                       h2 { title: "{target}", {applet_value_label("applets.trace_title", &target_label)} }
                                   }
                                   section {
                                       class: "publish-to-source-modal-body",
                                       if trace_events.is_empty() {
                                           p { class: "muted", {tr("applets.trace_empty")} }
                                       } else {
                                           for ev in trace_events.iter() {
                                               {
                                                   let event_id = ev.operation_id.clone();
                                                   let kind = ev
                                                       .payload
                                                       .get("kind")
                                                       .and_then(Value::as_str)
                                                       .unwrap_or("?")
                                                       .to_owned();
                                                   let emitted_at = ev
                                                       .payload
                                                       .get("timestamp")
                                                       .and_then(Value::as_str)
                                                       .unwrap_or("-")
                                                       .to_owned();
                                                   let event_id_label = short_protocol_id(&event_id);
                                                   rsx! {
                                                       div {
                                                           class: "event",
                                                           "data-testid": "applet-accountability-event",
                                                           "data-event-id": "{event_id}",
                                                           "data-emitted-at": "{emitted_at}",
                                                           div { class: "event-head",
                                                               span { class: "mono", "{kind}" }
                                                               span { class: "muted", "{emitted_at}" }
                                                           }
                                                           div { class: "muted", title: "{event_id}", {applet_value_label("applets.event_id", &event_id_label)} }
                                                       }
                                                   }
                                               }
                                           }
                                       }
                                   }
                                   footer {
                                       class: "publish-to-source-modal-footer",
                                       Button {
                                           variant: ButtonVariant::Secondary,
                                           onclick: move |_| trace_open_for.set(None),
                                           {tr("common.close")}
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

    use std::cell::RefCell;
    use std::rc::Rc;

    use dioxus::prelude::*;

    use crate::i18n::{I18nSignal, UiLocale};

    type LocaleHandle = Rc<RefCell<Option<I18nSignal>>>;

    type FeedbackHandle =
        Rc<RefCell<Option<(I18nSignal, Signal<Option<super::AppletInstallFeedback>>)>>>;

    fn retained_applet_feedback(handle: FeedbackHandle) -> Element {
        let locale = use_context_provider(|| crate::i18n::init_i18n_with_locale(UiLocale::En));
        let status = use_signal(|| Option::<super::AppletInstallFeedback>::None);
        *handle.borrow_mut() = Some((locale, status));
        // The production feedback surface retains values and typed API errors;
        // this test does not execute installation or the session-dependent panel.
        let status = status.read();
        super::applet_install_feedback(status.as_ref())
    }

    fn feedback_div_count(dom: &VirtualDom, node: &dioxus::core::VNode) -> usize {
        fn template_count(
            dom: &VirtualDom,
            node: &dioxus::core::VNode,
            template: &dioxus::core::TemplateNode,
        ) -> usize {
            use dioxus::core::{DynamicNode, TemplateAttribute, TemplateNode};
            match template {
                TemplateNode::Element {
                    tag,
                    attrs,
                    children,
                    ..
                } => {
                    let is_status = *tag == "div"
                        && attrs.iter().any(|attribute| {
                            matches!(
                                attribute,
                                TemplateAttribute::Static {
                                    name: "data-testid",
                                    value: "applet-install-status",
                                    ..
                                }
                            )
                        });
                    usize::from(is_status)
                        + children
                            .iter()
                            .map(|child| template_count(dom, node, child))
                            .sum::<usize>()
                }
                TemplateNode::Dynamic { id } => match &node.dynamic_nodes[*id] {
                    DynamicNode::Fragment(nodes) => nodes
                        .iter()
                        .map(|child| feedback_div_count(dom, child))
                        .sum(),
                    // Dioxus wraps the app in mounted Suspense/Error components.
                    // Follow the actual child scope rather than guessing a ScopeId.
                    DynamicNode::Component(component) => {
                        let scope = component
                            .mounted_scope(*id, node, dom)
                            .expect("rendered feedback component is mounted");
                        feedback_div_count(dom, scope.root_node())
                    }
                    _ => 0,
                },
                TemplateNode::Text { .. } => 0,
            }
        }

        node.template
            .roots
            .iter()
            .map(|root| template_count(dom, node, root))
            .sum()
    }

    #[test]
    fn retained_applet_feedback_rerenders_original_parameters_and_safe_api_errors() {
        use std::sync::Arc;

        use super::AppletInstallFeedback as Feedback;
        use crate::transport::auth::ApiCallError;

        let handle = Rc::new(RefCell::new(None));
        let mut dom = VirtualDom::new_with_props(retained_applet_feedback, handle.clone());
        assert!(text_edits(dom.rebuild_to_vec()).is_empty());
        assert_eq!(feedback_div_count(&dom, dom.base_scope().root_node()), 0);
        let (mut locale, mut status) = handle.borrow().expect("surface provides signals");
        dom.in_runtime(|| status.set(Some(Feedback::InvalidScope(String::new()))));
        assert!(text_edits(dom.render_immediate_to_vec()).is_empty());
        assert_eq!(feedback_div_count(&dom, dom.base_scope().root_node()), 0);
        for language in [UiLocale::Zh, UiLocale::En] {
            dom.in_runtime(|| crate::i18n::set_locale(&mut locale, language));
            assert!(text_edits(dom.render_immediate_to_vec()).is_empty());
            assert_eq!(feedback_div_count(&dom, dom.base_scope().root_node()), 0);
        }
        let original = "applets.registry {value} {scopes} {actions} {digest} {rejected} 原文";
        let server_detail = "applets.registry {error} private server detail";
        let diagnostic = "private diagnostic {error}";
        let problem = arkret_sdk::Problem::new("internal_error", 500, server_detail)
            .with_extension("reason_detail", serde_json::json!(diagnostic));
        let server_error = Arc::new(ApiCallError::Failed(anyhow::Error::new(
            crate::api_error::TransportClientError {
                status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                error: problem,
            },
        )));
        let local_error = Arc::new(ApiCallError::Failed(anyhow::anyhow!(original)));
        let cases = [
            (
                Feedback::PlanReady { scopes: 2, actions: 3, digest: original.to_owned() },
                format!("plan ready (2 scope(s), 3 action(s)); digest {original}"),
                format!("计划已就绪（2 个范围，3 项操作）；摘要 {original}"),
            ),
            (
                Feedback::PartiallyInstalled { applet_id: original.to_owned(), rejected: 4 },
                format!("⚠ partially installed: applet_id {original} — 4 scope(s) rejected"),
                format!("⚠ 部分安装成功：applet_id {original} — 4 个范围被拒绝"),
            ),
            (
                Feedback::Installed(String::new()),
                "✅ Service installed: applet_id . Bots are created separately by the Applet.".to_owned(),
                "✅ Service 已安装：applet_id 。Bot 由小程序另行创建。".to_owned(),
            ),
            (
                Feedback::InvalidRealm(original.to_owned()),
                format!("cannot preview install: invalid Realm id: {original}"),
                format!("无法预览安装：Realm 标识无效：{original}"),
            ),
            (
                Feedback::InvalidScope(original.to_owned()),
                original.to_owned(),
                original.to_owned(),
            ),
            (
                Feedback::InvalidPreview(original.to_owned()),
                format!("preview invalid: {original}"),
                format!("预览无效：{original}"),
            ),
            (
                Feedback::PreviewFailed(local_error.clone()),
                format!("preview failed: {original}"),
                format!("预览失败：{original}"),
            ),
            (
                Feedback::InstallFailed(server_error.clone()),
                "install failed: Something went wrong while talking to the server. Try again.".to_owned(),
                "安装失败：与服务器通信时出现问题。请重试。".to_owned(),
            ),
            (
                Feedback::RevokeFailed(server_error.clone()),
                "revoke failed: Something went wrong while talking to the server. Try again.".to_owned(),
                "撤销失败：与服务器通信时出现问题。请重试。".to_owned(),
            ),
            (
                Feedback::Revoked(0),
                "revoked: 0 ref(s)".to_owned(),
                "已撤销：0 个引用".to_owned(),
            ),
            (
                Feedback::PreviewFailed(Arc::new(ApiCallError::Unavailable(anyhow::anyhow!(server_detail)))),
                "preview failed: The server is unavailable right now. Check the server address, or wait a moment and try again.".to_owned(),
                "预览失败：服务器当前不可用。请检查服务器地址,或稍等片刻后重试。".to_owned(),
            ),
            (
                Feedback::PreviewFailed(Arc::new(ApiCallError::AuthExpired(anyhow::anyhow!(server_detail)))),
                "preview failed: Your session has expired. Sign in again to continue.".to_owned(),
                "预览失败：登录已过期。请重新登录以继续。".to_owned(),
            ),
        ];
        for (feedback, english, chinese) in cases {
            dom.in_runtime(|| status.set(Some(feedback.clone())));
            assert_eq!(
                text_edits(dom.render_immediate_to_vec()),
                vec![english.clone()]
            );
            assert_eq!(feedback_div_count(&dom, dom.base_scope().root_node()), 1);
            for (language, text) in [(UiLocale::Zh, chinese), (UiLocale::En, english)] {
                dom.in_runtime(|| crate::i18n::set_locale(&mut locale, language));
                let edits = text_edits(dom.render_immediate_to_vec());
                // An unchanged literal diagnostic has no text mutation.
                if matches!(feedback, Feedback::InvalidScope(_)) {
                    assert!(edits.is_empty());
                } else {
                    assert_eq!(edits, vec![text]);
                }
            }
            if let Feedback::InstallFailed(error) | Feedback::RevokeFailed(error) =
                status.read().as_ref().expect("feedback is retained")
            {
                assert!(Arc::ptr_eq(error, &server_error));
                let (_, envelope) = crate::api_error::api_error_status_and_envelope(error.inner())
                    .expect("original server envelope is retained");
                assert_eq!(envelope.detail, server_detail);
                assert_eq!(envelope.extensions["reason_detail"], diagnostic);
            }
            dom.in_runtime(|| status.set(None));
            assert!(text_edits(dom.render_immediate_to_vec()).is_empty());
            assert_eq!(feedback_div_count(&dom, dom.base_scope().root_node()), 0);
        }
    }

    fn retained_applet_labels(handle: LocaleHandle) -> Element {
        let locale = use_context_provider(|| crate::i18n::init_i18n_with_locale(UiLocale::En));
        *handle.borrow_mut() = Some(locale);
        // This surface exercises production presentation helpers, not the
        // session-dependent AppletsPanel lifecycle or registration authoring.
        let observed = use_signal(|| (7usize, "applets.registry {value} {count} 原文".to_owned()));
        let (count, original) = &*observed.read();
        let text = format!(
            "{} | {} | {} | {} | {}",
            super::applet_registered_count(*count),
            super::applet_value_label("applets.operation_id", original),
            super::applet_value_label("applets.trace_title", original),
            super::applet_value_label("applets.event_id", ""),
            original,
        );
        rsx! { p { "{text}" } }
    }

    fn text_edits(edits: dioxus::core::Mutations) -> Vec<String> {
        edits
            .edits
            .into_iter()
            .filter_map(|edit| match edit {
                dioxus::core::Mutation::CreateTextNode { value, .. }
                | dioxus::core::Mutation::SetText { value, .. } => Some(value),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn retained_applet_labels_rerender_without_interpreting_identifiers_or_empty_values() {
        let handle = Rc::new(RefCell::new(None));
        let mut dom = VirtualDom::new_with_props(retained_applet_labels, handle.clone());
        let original = "applets.registry {value} {count} 原文";
        let english = format!(
            "7 registered | operation_id {original} | Accountability trace — {original} | event_id  | {original}"
        );
        let chinese = format!(
            "已注册 7 个 | 操作标识 {original} | 问责事件追踪 — {original} | 事件标识  | {original}"
        );
        assert_eq!(text_edits(dom.rebuild_to_vec()), vec![english.clone()]);
        let mut locale = handle.borrow().expect("surface provides locale");
        for (language, text) in [(UiLocale::Zh, chinese), (UiLocale::En, english)] {
            dom.in_runtime(|| crate::i18n::set_locale(&mut locale, language));
            assert_eq!(text_edits(dom.render_immediate_to_vec()), vec![text]);
        }
    }

    // ── G3.Y4 — install helpers ─────────────────────────────────

    use super::{ManifestInputKind, classify_manifest_input};

    #[test]
    fn registration_namespace_label_reads_canonical_namespace_object() {
        let body = serde_json::json!({
            "namespaces": {
                "extensions": {"capabilities": ["read"]},
                "messaging": {"capabilities": ["write"]}
            }
        });
        assert_eq!(
            super::registration_namespace_label(Some(&body)),
            "extensions, messaging"
        );
        assert_eq!(super::registration_namespace_label(None), "—");
    }

    // ── P3 install wizard helpers ───────────────────────────────

    use super::{
        applet_effective_scope, applet_install_material_from_manifest, applet_install_resource,
        parse_applet_approval_actions,
    };

    #[test]
    fn applet_install_material_rejects_incomplete_json_and_url_kinds() {
        let json = super::ManifestInputKind::Json("{\"package_id\":\"package:demo\"}".to_owned());
        assert!(applet_install_material_from_manifest(&json).is_none());

        let url = super::ManifestInputKind::Url("https://x/manifest.json".to_owned());
        assert!(applet_install_material_from_manifest(&url).is_none());

        assert!(
            applet_install_material_from_manifest(&super::ManifestInputKind::Invalid).is_none()
        );
    }

    #[test]
    fn effective_scope_trims_realm_prefix_consistently() {
        let scope = applet_effective_scope(
            "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
            None,
        )
        .unwrap();
        assert!(matches!(
            scope,
            arkret_wire::ScopeRef::Realm { ref realm_id }
                if realm_id.as_str() == "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h"
        ));
    }

    #[test]
    fn effective_scope_circle_id_targets_circle() {
        let scope = applet_effective_scope(
            "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
            Some("ak:circle:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN"),
        )
        .unwrap();
        assert!(matches!(
            scope,
            arkret_wire::ScopeRef::Circle { ref realm_id, ref circle_id }
                if realm_id.as_str() == "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h"
                    && circle_id.as_str() == "ak:circle:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN"
        ));
        // Blank circle falls back to a Realm-wide install.
        assert!(matches!(
            applet_effective_scope(
                "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
                Some("  ")
            )
            .unwrap(),
            arkret_wire::ScopeRef::Realm { .. }
        ));
    }

    #[test]
    fn applet_grant_resource_is_the_exact_effective_scope() {
        let realm_scope = applet_effective_scope(
            "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
            None,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(applet_install_resource(&realm_scope).unwrap()).unwrap(),
            serde_json::json!({
                "kind": "realm",
                "realm_id": "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h"
            })
        );

        let circle_scope = applet_effective_scope(
            "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
            Some("ak:circle:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN"),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(applet_install_resource(&circle_scope).unwrap()).unwrap(),
            serde_json::json!({
                "kind": "circle",
                "realm_id": "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
                "circle_id": "ak:circle:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN",
                "match_scope": "exact"
            })
        );
    }

    #[test]
    fn applet_grant_basis_uses_verified_generation_anchor_and_rejects_other_realms() {
        let realm_id = arkret_sdk::RealmId::new(
            "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h".to_owned(),
        )
        .unwrap();
        let other_realm = arkret_sdk::RealmId::new(
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
        )
        .unwrap();
        let genesis =
            arkret_sdk::EventId::new("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap();
        let change =
            arkret_sdk::EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1")
                .unwrap();
        let committed = |event_id, position| arkret_wire::CommittedEventRef {
            event_id,
            commit_id: arkret_wire::RealmCommitId::from_digest(
                [u8::try_from(position).expect("fixture position fits a digest byte") + 1; 32],
            ),
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            stream_position: position,
        };
        let basis = crate::state::PersistedRealmAuthorityBasis {
            realm_id: realm_id.clone(),
            current_service_id: "ak:did_core:web:station.example".parse().unwrap(),
            current_generation: 4,
            genesis_ref: committed(genesis, 0),
            last_authority_change_ref: Some(committed(change.clone(), 4)),
            validated_at: chrono::Utc::now(),
        };

        let issuer = super::applet_capability_issuer_basis(Some(basis.clone()), &realm_id)
            .expect("verified matching Realm authority is usable");
        assert_eq!(issuer.authority_generation, 4);
        assert_eq!(issuer.authority_event_ref, change);
        assert!(super::applet_capability_issuer_basis(Some(basis), &other_realm).is_none());
        assert!(super::applet_capability_issuer_basis(None, &realm_id).is_none());
    }

    #[test]
    fn parse_applet_approval_actions_splits_and_dedupes() {
        assert_eq!(
            parse_applet_approval_actions(
                "ak.message.create, ak.applet.ghost.provision\nck.message.create"
            ),
            vec![
                "ak.applet.ghost.provision".to_owned(),
                "ak.message.create".to_owned()
            ]
        );
    }

    #[test]
    fn classify_manifest_input_detects_url_and_json_and_invalid() {
        assert_eq!(
            classify_manifest_input(
                "https://mock-applet-registry.local/_arkret/edge/applet/bridge.demo/manifest"
            ),
            ManifestInputKind::Url(
                "https://mock-applet-registry.local/_arkret/edge/applet/bridge.demo/manifest"
                    .to_owned(),
            )
        );
        let json = "{\"package_id\":\"package:demo\",\"namespace\":\"bridge.demo\"}";
        assert_eq!(
            classify_manifest_input(json),
            ManifestInputKind::Json(json.to_owned())
        );
        assert_eq!(classify_manifest_input("  "), ManifestInputKind::Invalid);
        // non-URL, non-{ prefix → invalid
        assert_eq!(
            classify_manifest_input("just a comment"),
            ManifestInputKind::Invalid
        );
        // looks like JSON but not parseable → invalid
        assert_eq!(
            classify_manifest_input("{not_json"),
            ManifestInputKind::Invalid
        );
    }
}
