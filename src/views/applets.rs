mod configuration;
use std::collections::BTreeSet;
use std::rc::Rc;

use arkret_models_integration::{
    AppletActorPolicy, AppletApprovalRequest, AppletGhostActorMode,
    AppletInstallAuthoringRequestBasis, AppletInstallPlan, AppletInstallPreviewRequestBody,
    AppletInstallPreviewResponseBody, AppletInstallRequestBody, AppletManagedActorPurpose,
    AppletPackage, AppletRegistrationEpochEvidence, AppletRevokeRequestBody,
};
use arkret_wire::{AppletRevokeMode, DidCoreId, ScopeRef, event_kind_str};
use glory::{Cage, Scope};
use serde_json::Value;

use crate::i18n::tr;
use crate::presentation::{InksonContext, View};
use crate::transport::auth::{with_authed_sdk_client, with_event_submitter};
use crate::views::helpers::short_protocol_id;
use crate::views::settings::widgets::*;

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
    preview: AppletInstallPreviewResponseBody,
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
    expected_revision: Option<arkret_sdk::CurrentRevision>,
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
        package.to_registration(registration_epoch_evidence, expected_revision)?;
    let registration = operation_builder_for_scope::<arkret_sdk::event_spec::AppletRegistration>(
        &ScopeRef::Realm {
            realm_id: effective_scope.realm_id().clone(),
        },
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

fn observed_applet_event(payload: &Value) -> &Value {
    payload.get("event").unwrap_or(payload)
}

fn observed_applet_body(payload: &Value) -> Option<&Value> {
    let event = observed_applet_event(payload);
    event.get("payload").or_else(|| event.get("body"))
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

fn applet_install_feedback(status: Option<&AppletInstallFeedback>) -> View {
    match status {
        Some(status) if !status.render().is_empty() => {
            paragraph("muted applet-install-status", status.render())
        }
        Some(_) => empty(),
        None => empty(),
    }
}

#[derive(Clone)]
struct AppletPage {
    context: Rc<InksonContext>,
    realm: String,
    install_open: Cage<bool>,
    install_manifest: Cage<String>,
    install_status: Cage<Option<AppletInstallFeedback>>,
    install_preview: Cage<Option<AppletInstallPreviewSnapshot>>,
    install_approve_actions: Cage<String>,
    install_ghost_actors_allowed: Cage<bool>,
    install_circle_id: Cage<String>,
    trace_open_for: Cage<Option<(String, String)>>,
    revoke_circle_id: Cage<String>,
}
impl AppletPage {
    fn preview(self) {
        let context = self.context.clone();
        let token = context.token;
        let active_account = context.active_account;
        let state_store = context.state_store.clone();
        let base_url = context.base_url.get_untracked();
        let selected_realm_id = self.realm.clone();
        let _install_open = self.install_open;
        let install_manifest = self.install_manifest;
        let install_status = self.install_status;
        let install_preview = self.install_preview;
        let install_approve_actions = self.install_approve_actions;
        let install_ghost_actors_allowed = self.install_ghost_actors_allowed;
        let install_circle_id = self.install_circle_id;
        let _trace_open_for = self.trace_open_for;
        let _revoke_circle_id = self.revoke_circle_id;
        let handler = {
            let base = base_url.clone();
            let realm = selected_realm_id.clone();
            move |_| {
                let raw = install_manifest.get();
                let kind = classify_manifest_input(&raw);
                let Some((package, registration_epoch_evidence)) =
                    applet_install_material_from_manifest(&kind)
                else {
                    install_preview.revise(|value| {
                        *value = None;
                    });
                    install_status.revise(|value| {
                        *value = Some(AppletInstallFeedback::InvalidManifest);
                    });
                    return;
                };
                let base = base.clone();
                let realm = realm.clone();
                let api_token = token.get();
                let Some(account) = active_account.get_untracked().clone() else {
                    install_status.revise(|value| {
                        *value = Some(AppletInstallFeedback::PreviewAccountUnavailable);
                    });
                    return;
                };
                let actor_id = account.principal_id().clone();
                let install_actor_id = arkret_sdk::ActorId::account(account.authority.clone());
                let target_station_id = account.authority.station_id.clone();
                let realm_typed = match arkret_sdk::RealmId::new(realm.clone()) {
                    Ok(realm_id) => realm_id,
                    Err(error) => {
                        install_status.revise(|value| {
                            *value = Some(AppletInstallFeedback::InvalidRealm(error.to_string()));
                        });
                        return;
                    }
                };
                let issuer_authority_basis = applet_capability_issuer_basis(
                    state_store.read(|store| store.realm_authority_basis(realm_typed.as_str())),
                    &realm_typed,
                );
                let Some(issuer_authority_basis) = issuer_authority_basis else {
                    install_status.revise(|value| {
                        *value = Some(AppletInstallFeedback::AuthorityUnavailable);
                    });
                    return;
                };
                let circle = install_circle_id.get();
                let approve_actions = parse_applet_approval_actions(&install_approve_actions.get());
                let ghost_actor_mode = if install_ghost_actors_allowed.get() {
                    AppletGhostActorMode::PolicyDeclared
                } else {
                    AppletGhostActorMode::Disallowed
                };
                install_status.revise(|value| {
                    *value = Some(AppletInstallFeedback::Previewing);
                });
                {
                    let task_owner = context.clone();
                    let _ = task_owner.spawn(async move {
                                               let effective_scope = match applet_effective_scope(
                                                   &realm,
                                                   Some(circle.as_str()),
                                               ) {
                                                   Ok(scope) => scope,
                                                   Err(err) => {
                                                       install_status.revise(|value|{*value=Some(AppletInstallFeedback::InvalidScope(err));});
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
                                                       install_status.revise(|value|{*value=Some(AppletInstallFeedback::MissingPackageDigest);});
                                                       return;
                                                   }
                                               };
                                               let authored_package = package.clone();
                                               let authored_scope = effective_scope.clone();
                                               let result = with_event_submitter(&base, api_token, |submitter| async move {
                                                   use arkret_sdk::exact_current_state::{
                                                       AppletRegistrationExactCurrentSelector, AppletRegistrationExactCurrentSelectorKind,
                                                       ExactCurrentStateSelector, ExactCurrentState, ExactCurrentStateReadRequestBody,
                                                       ExactCurrentStateReadResponseBody, NeverWrittenExactCurrentSelector,
                                                   };
                                                   let registration_current = submitter.http().exact_current_state(
                                                       &ExactCurrentStateReadRequestBody {
                                                           realm_id: authored_scope.realm_id().clone(),
                                                           selector: ExactCurrentStateSelector::AppletRegistration(AppletRegistrationExactCurrentSelector {
                                                               kind: AppletRegistrationExactCurrentSelectorKind::AppletRegistration,
                                                               applet_id: authored_package.applet_id.clone(), service_id: authored_package.service_id.clone(),
                                                           }),
                                                       }, issuer_authority_basis.authority_generation,
                                                   ).await?;
                                                   let expected_revision = match registration_current {
                                                       ExactCurrentStateReadResponseBody::Present { current_state: ExactCurrentState::AppletRegistration(row), .. } => Some(row.revision),
                                                       ExactCurrentStateReadResponseBody::NeverWritten { selector: NeverWrittenExactCurrentSelector::AppletRegistration(_), .. } => None,
                                                       _ => anyhow::bail!("registration current returned a different selector"),
                                                   };
                                                   let (registration, grants) =
                                                       build_formal_applet_install_events(
                                                           &authored_package,
                                                           &registration_epoch_evidence,
                                                           expected_revision,
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
                                                   Ok((preview, requested_basis)) => match approved_actions_from_plan(&preview.plan, &package) {
                                                       Ok(actions)
                                                           if preview.plan.effective_scope == effective_scope
    =>
                                                       {
                                                           let scope_count = preview.plan.approved_scopes.len();
                                                           let digest = preview.plan.plan_digest.to_string();
                                                           install_preview.revise(|value|{*value=Some(AppletInstallPreviewSnapshot {
                                                               package,
                                                               basis: requested_basis,
                                                               preview,
                                                           });});
                                                           install_status.revise(|value|{*value=Some(AppletInstallFeedback::PlanReady {
                                                               scopes: scope_count,
                                                               actions: actions.len(),
                                                               digest: short_protocol_id(&digest),
                                                           });});
                                                       }
                                                       Ok(_) => {
                                                           install_preview.revise(|value|{*value=None;});
                                                           install_status.revise(|value|{*value=Some(AppletInstallFeedback::ScopeMismatch);});
                                                       }
                                                       Err(err) => {
                                                           install_preview.revise(|value|{*value=None;});
                                                           install_status.revise(|value|{*value=Some(AppletInstallFeedback::InvalidPreview(err.to_string()));});
                                                       }
                                                   },
                                                   Err(err) => {
                                                       install_preview.revise(|value|{*value=None;});
                                                       install_status.revise(|value|{*value=Some(AppletInstallFeedback::PreviewFailed(std::sync::Arc::new(err)));});
                                                   }
                                               }
                                           });
                };
            }
        };
        handler(());
    }
    fn install(self) {
        let context = self.context.clone();
        let token = context.token;
        let _active_account = context.active_account;
        let _state_store = context.state_store.clone();
        let base_url = context.base_url.get_untracked();
        let _selected_realm_id = self.realm.clone();
        let install_open = self.install_open;
        let install_manifest = self.install_manifest;
        let install_status = self.install_status;
        let install_preview = self.install_preview;
        let install_approve_actions = self.install_approve_actions;
        let install_ghost_actors_allowed = self.install_ghost_actors_allowed;
        let install_circle_id = self.install_circle_id;
        let _trace_open_for = self.trace_open_for;
        let _revoke_circle_id = self.revoke_circle_id;
        let handler = {
            let base = base_url.clone();
            move |_| {
                let Some(snapshot) = install_preview.get() else {
                    install_status.revise(|value| {
                        *value = Some(AppletInstallFeedback::PreviewRequired);
                    });
                    return;
                };
                let base = base.clone();
                let api_token = token.get();
                install_status.revise(|value| {
                    *value = Some(AppletInstallFeedback::Installing);
                });
                {
                    let task_owner = context.clone();
                    let _ = task_owner.spawn(async move {
                                               let idem = snapshot.preview.plan.plan_digest.to_string();
                                               let result = with_authed_sdk_client(&base, api_token, |http| async move {
                                                   let body = AppletInstallRequestBody {
                                                       applet_package: snapshot.package,
                                                       authoring_request_basis: snapshot.basis,
                                                       plan_digest: snapshot.preview.plan.plan_digest,
                                                   };
                                                   http.applet_install(&idem, &crate::transport::own_station_results::verify_local_publication(&http, body).await?)
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
                                                       install_status.revise(|value|{*value=Some(feedback);});
                                                       // Keep the form open on a partial outcome so the
                                                       // admin can adjust and retry denied scopes.
                                                       if installed {
                                                           install_open.revise(|value|{*value=false;});
                                                           install_manifest.revise(|value|{*value=String::new();});
                                                           install_circle_id.revise(|value|{*value=String::new();});
                                                           install_approve_actions.revise(|value|{*value=String::new();});
                                                           install_ghost_actors_allowed.revise(|value|{*value=false;});
                                                           install_preview.revise(|value|{*value=None;});
                                                       }
                                                   }
                                                   Err(err) => install_status.revise(|value|{*value=Some(AppletInstallFeedback::InstallFailed(std::sync::Arc::new(err)));}),
                                               }
                                           });
                };
            }
        };
        handler(());
    }
    fn revoke(self, applet_id: String, service_id: String) {
        let context = self.context.clone();
        let token = context.token;
        let active_account = context.active_account;
        let _state_store = context.state_store.clone();
        let base_url = context.base_url.get_untracked();
        let selected_realm_id = self.realm.clone();
        let _install_open = self.install_open;
        let _install_manifest = self.install_manifest;
        let install_status = self.install_status;
        let _install_preview = self.install_preview;
        let _install_approve_actions = self.install_approve_actions;
        let _install_ghost_actors_allowed = self.install_ghost_actors_allowed;
        let _install_circle_id = self.install_circle_id;
        let _trace_open_for = self.trace_open_for;
        let revoke_circle_id = self.revoke_circle_id;
        let handler = {
            let base = base_url.clone();
            let realm = selected_realm_id.clone();
            let service_id = service_id.clone();
            let aid = applet_id.clone();
            move |_| {
                let base = base.clone();
                let realm = crate::operation::trim_realm_id(&realm);
                let effective_scope =
                    match applet_effective_scope(&realm, Some(&revoke_circle_id.get())) {
                        Ok(scope) => scope,
                        Err(error) => {
                            install_status.revise(|value| {
                                *value = Some(AppletInstallFeedback::InvalidScope(error));
                            });
                            return;
                        }
                    };
                let service_id = service_id.clone();
                let aid = aid.clone();
                let api_token = token.get();
                let Some(account) = active_account.get_untracked().clone() else {
                    install_status.revise(|value| {
                        *value = Some(AppletInstallFeedback::RevokeAccountUnavailable);
                    });
                    return;
                };
                let principal_id = account.authority.principal_id;
                install_status.revise(|value| {
                    *value = Some(AppletInstallFeedback::Revoking);
                });
                {
                    let task_owner = context.clone();
                    let _ = task_owner.spawn(async move {
                                                           let reason_code = arkret_sdk::ReasonCode::PolicyRevoked;
                                                           let revoke_mode = AppletRevokeMode::RevokeRuntimeOnly;
                                                           let result = with_event_submitter(&base, api_token, |submitter| async move {
                                                               let service_id: DidCoreId = service_id.parse()?;
                                                               let preview = submitter.http().applet_revoke_preview(
                                                                   &aid,
                                                                   &arkret_sdk::AppletRevokePreviewRequestBody {
                                                                       service_id: service_id.clone(),
                                                                       effective_scope: effective_scope.clone(),
                                                                       reason_code: reason_code.clone(),
                                                                       revoke_mode,
                                                                   },
                                                               ).await.map_err(anyhow::Error::from)?;
                                                               if preview.revoke_plan.effective_scope != effective_scope || preview.revoke_plan.service_id != service_id {
                                                                   anyhow::bail!("revoke preview changed the requested scope");
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
                                                                   service_id: preview.revoke_plan.service_id.clone(),
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
                                                                   &submitter.verify_publication(body)?,
                                                               ).await.map_err(anyhow::Error::from)
                                                           })
                                                           .await;
                                                           match result {
                                                               Ok(outcome) => install_status.revise(|value|{*value=Some(AppletInstallFeedback::Revoked(outcome.revoked_refs.len()));}),
                                                               Err(err) => install_status.revise(|value|{*value=Some(AppletInstallFeedback::RevokeFailed(std::sync::Arc::new(err)));}),
                                                           }
                                                       });
                };
            }
        };
        handler(());
    }
}
fn applet_inventory_surface(
    scope: &Scope,
    st: AppletPage,
    selected_realm_id: String,
    services: bool,
    installed_count: Cage<usize>,
) -> View {
    let _self_ref = st.clone();
    let state_store = st.context.state_store.clone();
    let trace_open_for = st.trace_open_for;
    let raw_ops = state_store.read(|store| store.load()).raw_operations;
    let registrations: Vec<_> = raw_ops
        .iter()
        .filter(|r| {
            r.realm_id.as_deref()
                == Some(crate::operation::trim_realm_id(&selected_realm_id).as_str())
        })
        .filter_map(|r| {
            let is_registration = observed_applet_event(&r.payload)
                .get("kind")
                .and_then(Value::as_str)
                .map(|k| k == event_kind_str::APPLET_REGISTRATION)
                .unwrap_or(false);
            if !is_registration {
                return None;
            }
            let service_id = observed_applet_body(&r.payload)
                .and_then(|body| body.get("service_id"))
                .and_then(Value::as_str)
                .and_then(|value| DidCoreId::new(value.to_owned()).ok())?;
            Some((r.clone(), service_id.into_string()))
        })
        .collect();
    let bridge_errors: Vec<_> = raw_ops
        .iter()
        .filter(|r| {
            r.realm_id.as_deref()
                == Some(crate::operation::trim_realm_id(&selected_realm_id).as_str())
        })
        .filter(|r| {
            observed_applet_event(&r.payload)
                .get("kind")
                .and_then(Value::as_str)
                .map(|k| k == event_kind_str::APPLET_BRIDGE_ERROR)
                .unwrap_or(false)
        })
        .cloned()
        .collect();

    // Observed registrations identify Services, not active installation scopes.
    // Revisions remain visible in the history panel; each Service has one action row.
    let mut applet_rows: BTreeSet<_> = registrations
        .iter()
        .filter_map(|(r, service_id)| {
            let body = observed_applet_body(&r.payload)?;
            let applet_id = arkret_sdk::AppletId::new(body.get("applet_id")?.as_str()?).ok()?;
            let scope: ScopeRef =
                serde_json::from_value(observed_applet_event(&r.payload).get("scope_ref")?.clone())
                    .ok()?;
            if !matches!(scope, ScopeRef::Realm { .. })
                || scope.realm_id_opt()?.as_str()
                    != crate::operation::trim_realm_id(&selected_realm_id)
            {
                return None;
            }
            Some((applet_id.to_string(), service_id.clone()))
        })
        .collect();

    if let Some(entries) = state_store.read(|store| {
        store.realm_current_view_entries(&crate::operation::trim_realm_id(&selected_realm_id))
    }) {
        for entry in entries {
            let arkret_wire::CurrentState::Value {
                selector, value, ..
            } = entry;
            if let arkret_wire::CurrentSelector::AppletRegistration {
                applet_id,
                service_id,
            } = selector
                && let Ok(registration) =
                    serde_json::from_value::<arkret_sdk::AppletRegistrationPayload>(value)
                && registration.applet_id == applet_id
                && registration.service_id == service_id
            {
                applet_rows.insert((applet_id.to_string(), service_id.to_string()));
            }
        }
    }

    let trace_target_id = trace_open_for.get();
    let _trace_events: Vec<_> = match &trace_target_id {
        Some((applet, target)) => raw_ops
            .iter()
            .filter(|r| {
                let kind_is_applet = observed_applet_event(&r.payload)
                    .get("kind")
                    .and_then(Value::as_str)
                    .map(|k| k.starts_with("ak.applet."))
                    .unwrap_or(false);
                let matches_did = observed_applet_body(&r.payload)
                    .and_then(|b| b.get("service_id"))
                    .and_then(Value::as_str)
                    .map(|d| d == target.as_str())
                    .unwrap_or(false);
                let matches_applet = observed_applet_body(&r.payload)
                    .and_then(|b| b.get("applet_id"))
                    .and_then(Value::as_str)
                    == Some(applet.as_str());
                let matches_realm = observed_applet_event(&r.payload)
                    .get("scope_ref")
                    .and_then(|value| serde_json::from_value::<ScopeRef>(value.clone()).ok())
                    .and_then(|scope| scope.realm_id_opt().map(ToString::to_string))
                    .is_some_and(|realm| {
                        realm == crate::operation::trim_realm_id(&selected_realm_id)
                    });
                kind_is_applet && matches_did && matches_applet && matches_realm
            })
            .cloned()
            .collect(),
        None => Vec::new(),
    };

    if !services {
        let registry = stack(
            "event",
            vec![
                line(
                    "event-head",
                    vec![
                        plain(tr("applets.registry")),
                        paragraph("badge", applet_registered_count(registrations.len())),
                    ],
                ),
                paragraph("muted", tr("applets.registry_help")),
                if registrations.is_empty() {
                    paragraph("muted applet-registry-empty", tr("applets.registry_empty"))
                } else {
                    stack(
                        "applet-registration-list",
                        registrations
                            .into_iter()
                            .map(|(record, service)| {
                                let namespace = registration_namespace_label(observed_applet_body(
                                    &record.payload,
                                ));
                                stack(
                                    "event applet-registration-row",
                                    vec![
                                        line(
                                            "event-head",
                                            vec![
                                                paragraph("mono", short_protocol_id(&service)),
                                                paragraph("badge", namespace),
                                            ],
                                        ),
                                        paragraph(
                                            "muted",
                                            applet_value_label(
                                                "applets.operation_id",
                                                &short_protocol_id(&record.operation_id),
                                            ),
                                        ),
                                    ],
                                )
                            })
                            .collect(),
                    )
                },
            ],
        );
        let errors = stack(
            "event applet-bridge-errors",
            vec![
                line(
                    "event-head",
                    vec![
                        plain(tr("applets.bridge_errors")),
                        paragraph("badge red", bridge_errors.len().to_string()),
                    ],
                ),
                if bridge_errors.is_empty() {
                    paragraph("muted", tr("applets.bridge_errors_empty"))
                } else {
                    stack(
                        "applet-error-list",
                        bridge_errors
                            .into_iter()
                            .map(|record| {
                                let body = observed_applet_body(&record.payload);
                                stack(
                                    "event applet-bridge-error-row",
                                    vec![
                                        line(
                                            "event-head",
                                            vec![
                                                paragraph(
                                                    "mono",
                                                    body.and_then(|b| b.get("error_code"))
                                                        .and_then(Value::as_str)
                                                        .unwrap_or("?")
                                                        .to_owned(),
                                                ),
                                                paragraph(
                                                    "mono",
                                                    short_protocol_id(
                                                        body.and_then(|b| {
                                                            b.get("failed_transaction_ref")
                                                        })
                                                        .and_then(Value::as_str)
                                                        .unwrap_or("?"),
                                                    ),
                                                ),
                                            ],
                                        ),
                                        paragraph(
                                            "muted",
                                            body.and_then(|b| b.get("message"))
                                                .and_then(Value::as_str)
                                                .unwrap_or_default()
                                                .to_owned(),
                                        ),
                                    ],
                                )
                            })
                            .collect(),
                    )
                },
            ],
        );
        return Box::new(glory::ui::group().fill(vec![registry, errors]));
    }
    let count = applet_rows.len();
    if installed_count.get_untracked() != count {
        installed_count.revise(|value| *value = count);
    }
    if applet_rows.is_empty() {
        paragraph("muted applet-empty", tr("applets.installed_empty"))
    } else {
        stack(
            "applet-service-list",
            applet_rows
                .into_iter()
                .map(|(applet, service)| {
                    let trace = st.trace_open_for;
                    let aid = applet.clone();
                    let sid = service.clone();
                    let revoke = st.clone();
                    let a = applet.clone();
                    let s = service.clone();
                    stack(
                        "event applet-row",
                        vec![
                            line(
                                "event-head",
                                vec![
                                    paragraph("mono", short_protocol_id(&service)),
                                    paragraph("mono muted", short_protocol_id(&applet)),
                                ],
                            ),
                            configuration::page(
                                scope,
                                st.context.clone(),
                                selected_realm_id.clone(),
                                applet,
                                service,
                            ),
                            line(
                                "actions",
                                vec![
                                    action(
                                        scope,
                                        st.context.clone(),
                                        "applet-accountability-trace-button",
                                        "applets.trace_events",
                                        "secondary",
                                        true,
                                        move || {
                                            trace.revise(|v| *v = Some((aid.clone(), sid.clone())))
                                        },
                                    ),
                                    action(
                                        scope,
                                        st.context.clone(),
                                        "applet-uninstall-button",
                                        "applets.uninstall",
                                        "destructive",
                                        true,
                                        move || revoke.clone().revoke(a.clone(), s.clone()),
                                    ),
                                ],
                            ),
                        ],
                    )
                })
                .collect(),
        )
    }
}

pub fn page(scope: &Scope, context: Rc<InksonContext>, _route: crate::routes::Route) -> View {
    let state = AppletPage {
        context: context.clone(),
        realm: context.selected_realm_id.get_untracked(),
        install_open: scope.cage(false),
        install_manifest: scope.cage(String::new()),
        install_status: scope.cage(None),
        install_preview: scope.cage(None),
        install_approve_actions: scope.cage(String::new()),
        install_ghost_actors_allowed: scope.cage(false),
        install_circle_id: scope.cage(String::new()),
        trace_open_for: scope.cage(None),
        revoke_circle_id: scope.cage(String::new()),
    };
    let open = state.install_open;
    let preview = state.install_preview;
    let form = {
        let state = state.clone();
        reactive(open, move |scope, open| {
            if !open {
                return empty();
            }
            let mut fields = vec![];
            for (key, label, value) in [
                (
                    "applet-install-manifest-input",
                    "applets.manifest_placeholder",
                    state.install_manifest,
                ),
                (
                    "applet-install-circle-input",
                    "applets.circle_placeholder",
                    state.install_circle_id,
                ),
                (
                    "applet-install-approve-actions-input",
                    "applets.actions_placeholder",
                    state.install_approve_actions,
                ),
            ] {
                let control: View = Box::new(
                    sapid::field(key)
                        .unstyled()
                        .class(format!("applet-install-field {key}"))
                        .label(state.context.translated(scope, label))
                        .control(move |field| {
                            sapid::text_field()
                                .unstyled()
                                .class("input")
                                .field(field)
                                .value(value)
                                .multiline(true)
                                .on_value_change(move |next| {
                                    value.revise(|v| *v = next);
                                    preview.revise(|v| *v = None);
                                })
                        }),
                );
                fields.push(stack(
                    format!("applet-install-prompt {key}-prompt"),
                    vec![input_prompt(
                        scope,
                        state.context.translated(scope, label).into(),
                        value,
                        control,
                    )],
                ));
            }
            let ghost = state.install_ghost_actors_allowed;
            fields.push(stack(
                "metric applet-install-ghost-row",
                vec![toggle(
                    scope,
                    state.context.clone(),
                    "applet-install-allow-ghost",
                    "applets.allow_ghost",
                    ghost,
                    true,
                    move |next| {
                        ghost.revise(|v| *v = next);
                        preview.revise(|v| *v = None);
                    },
                )],
            ));
            let st = state.clone();
            fields.push(action(
                scope,
                state.context.clone(),
                "applet-install-verify-button",
                "applets.preview_plan",
                "secondary",
                true,
                move || st.clone().preview(),
            ));
            let st = state.clone();
            fields.push(action(
                scope,
                state.context.clone(),
                "applet-install-confirm-button",
                "applets.install",
                "primary",
                scope.bond(move || preview.get().is_some()),
                move || st.clone().install(),
            ));
            fields.push(reactive(state.install_status, move |_, feedback| {
                applet_install_feedback(feedback.as_ref())
            }));
            stack("workflow-form", fields)
        })
    };
    let source = {
        let ctx = context.clone();
        scope.bond(move || {
            let _ = ctx.state_revision.get();
            let _ = ctx.locale.get();
            ctx.selected_realm_id.get()
        })
    };
    let installed_count = scope.cage(0usize);
    let inventory = reactive(source, {
        let state = state.clone();
        move |scope, selected_realm_id| {
            applet_inventory_surface(
                scope,
                state.clone(),
                selected_realm_id,
                false,
                installed_count,
            )
        }
    });
    let services = reactive(source, {
        let state = state.clone();
        move |scope, selected_realm_id| {
            applet_inventory_surface(
                scope,
                state.clone(),
                selected_realm_id,
                true,
                installed_count,
            )
        }
    });
    let trace = {
        let state = state.clone();
        reactive(state.trace_open_for, move |scope, target| {
            let Some((applet, service)) = target else {
                return empty();
            };
            let ctx = state.context.clone();
            let events = ctx
                .snapshot()
                .raw_operations
                .into_iter()
                .filter(|record| {
                    let event = observed_applet_event(&record.payload);
                    let body = observed_applet_body(&record.payload);
                    event
                        .get("kind")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| kind.starts_with("ak.applet."))
                        && body
                            .and_then(|b| b.get("applet_id"))
                            .and_then(Value::as_str)
                            == Some(applet.as_str())
                        && body
                            .and_then(|b| b.get("service_id"))
                            .and_then(Value::as_str)
                            == Some(service.as_str())
                        && event
                            .get("scope_ref")
                            .and_then(|scope| {
                                serde_json::from_value::<ScopeRef>(scope.clone()).ok()
                            })
                            .and_then(|scope| scope.realm_id_opt().map(ToString::to_string))
                            .as_deref()
                            == Some(state.realm.as_str())
                })
                .map(|record| {
                    stack(
                        "event applet-accountability-event",
                        vec![
                            paragraph("mono", record.operation_id),
                            paragraph(
                                "muted",
                                observed_applet_event(&record.payload)
                                    .get("kind")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                            ),
                        ],
                    )
                })
                .collect();
            confirmation(
                scope,
                ctx.clone(),
                "applet-accountability-modal",
                ctx.translated(scope, "applets.trace_events"),
                stack("applet-trace-events", events),
                move || state.trace_open_for.revise(|v| *v = None),
            )
        })
    };
    Box::new(
        glory::ui::view()
            .role(glory::render::Role::Section)
            .name(context.translated(scope, "applets.region"))
            .class("timeline applets-panel")
            .fill(vec![
                inventory,
                stack(
                    "event applet-list-panel",
                    vec![
                        line(
                            "event-head",
                            vec![
                                plain(context.translated(scope, "applets.installed")),
                                paragraph(
                                    "badge",
                                    scope.bond(move || installed_count.get().to_string()),
                                ),
                                Box::new(
                                    sapid::button()
                                        .unstyled()
                                        .class("primary applet-install-button")
                                        .label({
                                            let context = context.clone();
                                            scope.bond(move || {
                                                context.tr(if open.get() {
                                                    "applets.close_install"
                                                } else {
                                                    "applets.open_install"
                                                })
                                            })
                                        })
                                        .on_press(move || open.revise(|v| *v = !*v)),
                                ),
                            ],
                        ),
                        form,
                        services,
                        input(
                            scope,
                            context.clone(),
                            "applet-revoke-circle-input",
                            "applets.circle_placeholder",
                            state.revoke_circle_id,
                            true,
                        ),
                    ],
                ),
                trace,
            ]),
    )
}
#[cfg(test)]
mod tests {

    use crate::i18n::UiLocale;
    #[test]
    fn retained_applet_feedback_rerenders_original_parameters_and_safe_api_errors() {
        use std::sync::Arc;

        use super::AppletInstallFeedback as Feedback;
        use crate::transport::auth::ApiCallError;

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
            for (locale, expected) in [(UiLocale::En, english), (UiLocale::Zh, chinese)] {
                crate::i18n::with_test_locale(locale, || assert_eq!(feedback.render(), expected));
            }
            if let Feedback::InstallFailed(error) | Feedback::RevokeFailed(error) = &feedback {
                assert!(Arc::ptr_eq(error, &server_error));
                let (_, envelope) = crate::api_error::api_error_status_and_envelope(error.inner())
                    .expect("original server envelope is retained");
                assert_eq!(envelope.detail, server_detail);
                assert_eq!(envelope.extensions["reason_detail"], diagnostic);
            }
        }
        assert_eq!(Feedback::InvalidScope(String::new()).render(), "");
    }
    #[test]
    fn retained_applet_labels_rerender_without_interpreting_identifiers_or_empty_values() {
        let original = "applets.registry {value} {count} 原文";
        let english = format!(
            "7 registered | operation_id {original} | Accountability trace — {original} | event_id  | {original}"
        );
        let chinese = format!(
            "已注册 7 个 | 操作标识 {original} | 问责事件追踪 — {original} | 事件标识  | {original}"
        );
        for (locale, expected) in [(UiLocale::En, english), (UiLocale::Zh, chinese)] {
            crate::i18n::with_test_locale(locale, || {
                assert_eq!(
                    format!(
                        "{} | {} | {} | {} | {}",
                        super::applet_registered_count(7),
                        super::applet_value_label("applets.operation_id", original),
                        super::applet_value_label("applets.trace_title", original),
                        super::applet_value_label("applets.event_id", ""),
                        original
                    ),
                    expected
                )
            });
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
