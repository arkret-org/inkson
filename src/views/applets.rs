//! Applets — registry + interop_session controls.
//!
//! Spec: `arkret-spec/spec/v1/zh/extensions/applet-integration.md`.
//!
//! What the panel does today:
//!   * Reads `ak.applet.registration` / `ak.applet.discovery` events out of the local raw-operation
//!     projection and renders them as registry rows so users see which applets the Space already
//!     accepts.
//!   * Registration is derived from the signed manifest during the install preview/commit flow; the
//!     panel does not expose a short-form registration writer.
//!   * Per-session monitor lists active `interop_session.start/status` rows so an operator can see
//!     in-flight applet calls + their bridge errors.
//!
//! G3.Y4 additions:
//!   * `applet-list-panel` + per-applet `applet-row` carrying `data-applet-id` /
//!     `data-applet-manifest-hash` / `data-installed-at`.
//!   * `applet-install-button` opens an install form with manifest URL / JSON paste + signature
//!     verification (against `cotest/e2e/mocks/mock-applet-registry.mjs` for the verifier
//!     endpoint).
//!   * `applet-uninstall-button` per row.
//!   * `applet-accountability-trace-button` opens an audit modal listing every event the applet
//!     emitted (`applet-accountability-event` rows carrying `data-event-id` / `data-emitted-at`).
//!
//! Out of scope: applet capability gating at submit time (relies on
//! server-side soland validation), per-session cancellation. Those
//! follow once the bridge layer is implemented in a companion crate.

use std::collections::BTreeSet;

use arkret_models_collaboration::account_lifecycle::AppletRevokeRequestBody;
use arkret_models_integration::{
    AppletActorPolicy, AppletApprovalRequest, AppletGhostActorMode,
    AppletInstallAuthoringRequestBasis, AppletInstallCreateRequestBody, AppletInstallPlan,
    AppletInstallPreviewOutcome, AppletInstallPreviewRequestBody, AppletInstallRequestBody,
    AppletManagedActorAuthorRequestBody, AppletManagedActorPurpose, AppletPackage,
    AppletRegistrationEpochEvidence,
};
use arkret_wire::{AppletRevokeMode, DidCoreId, ScopeRef, event_kind_str};
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use serde_json::Value;

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
/// Circle install MUST NOT widen to a Realm-wide grant). soland gates the write
/// on `ak.realm.admin` over the resolved scope either way.
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

fn build_formal_applet_install_events(
    package: &AppletPackage,
    registration_epoch_evidence: &AppletRegistrationEpochEvidence,
    effective_scope: &ScopeRef,
    approved_actions: &[String],
    actor_id: &str,
    target_station_id: &arkret_sdk::DidCoreId,
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
                cell_ref: "ak:cell:ak.component.realm.authority_root.v1:null".to_owned(),
                controller_epoch_at_issuance: 0,
                authority_generation: 0,
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

/// Stable hash for a manifest body. `manifest_hash` is what soland's
/// applet registry will eventually pin per applet; the value is
/// rendered on `applet-row` via `data-applet-manifest-hash` so the
/// harness can assert it survives reload.
pub fn manifest_hash_for(manifest: &str) -> String {
    // Delegate to the SDK sha256-hex helper, then keep the leading 8 bytes
    // (16 hex chars) as the short manifest pin.
    let full = arkret_sdk::canonical::sha256_hex(manifest.as_bytes());
    format!("sha256:{}", &full[..16])
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
    let mut install_status = use_signal(String::new);
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

    // Build the canonical applet list (one entry per registration
    // operation, augmented with manifest_hash + installed_at).
    let applet_rows: Vec<_> = registrations
        .iter()
        .map(|(r, service_id)| {
            let namespace = registration_namespace_label(r.payload.get("body"));
            let applet_id = format!("{service_id}@{namespace}");
            let manifest_repr = format!("{}:{}", service_id, namespace);
            let manifest_hash = manifest_hash_for(&manifest_repr);
            let installed_at = r.operation_id.clone();
            (
                applet_id,
                service_id.clone(),
                namespace,
                manifest_hash,
                installed_at,
            )
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
        div { class: "timeline", "data-testid": "applets-panel", role: "region", "aria-label": "Applet registry and bridge errors",
            div { class: "event",
                div { class: "event-head",
                    span { "Applet registry" }
                    span { class: "badge", "{registrations.len()} registered" }
                }
                div { class: "muted",
                    "Spec extensions/applet-integration.md §2 — registrations are emitted from a verified, signed Applet Package. The registry lists every ak.applet.registration the local raw-operation log has observed."
                }
                if registrations.is_empty() {
                    div { class: "muted", "data-testid": "applet-registry-empty",
                        "No applets registered yet. Use the signed Applet Package install flow below; registration is derived during commit."
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
                                    div { class: "muted", title: "{op_id}", "operation_id {op_id_label}" }
                                }
                            }
                        }
                    }
                }
            }
            div { class: "event", "data-testid": "applet-bridge-errors",
                div { class: "event-head",
                    span { "Bridge errors" }
                    span { class: "badge red", "{bridge_errors.len()}" }
                }
                if bridge_errors.is_empty() {
                    div { class: "muted", "No bridge errors observed." }
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
                    span { "Installed applets" }
                    span { class: "badge", "{applet_rows.len()}" }
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "applet-install-button",
                        onclick: move |_| install_open.set(!install_open()),
                        if install_open() { "Close install" } else { "+ Install applet" }
                    }
                }
                if install_open() {
                    div { class: "workflow-form",
                        Textarea {
                            "data-testid": "applet-install-manifest-input",
                            placeholder: "manifest URL or JSON body",
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
                            placeholder: "optional Circle id (ak:circle:…) — blank = Realm-wide",
                            value: "{install_circle_id}",
                            oninput: move |event: FormEvent| {
                                install_circle_id.set(event.value());
                                install_preview.set(None);
                            },
                            style: "width: 100%; min-height: 32px;",
                        }
                        Textarea {
                            "data-testid": "applet-install-approve-actions-input",
                            placeholder: "approved actions, comma or newline separated",
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
                            span { "allow Applet-managed Ghost Actors" }
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
                                            install_status
                                                .set("input must be a closed AppletInstallPreviewRequestBody whose registration Event manifest carries registration_epoch_evidence".to_owned());
                                            return;
                                        };
                                        let base = base.clone();
                                        let realm = realm.clone();
                                        let api_token = token();
                                        let Some(account) = active_account.peek().clone() else {
                                            install_status.set(
                                                "cannot preview install: active account context is unavailable"
                                                    .to_owned(),
                                            );
                                            return;
                                        };
                                        let actor_id = account.principal_id().clone();
                                        let install_actor_id = arkret_sdk::ActorId::account(account.authority.clone());
                                        let target_station_id = account.authority.station_id.clone();
                                        let circle = install_circle_id();
                                        let approve_actions = parse_applet_approval_actions(
                                            &install_approve_actions(),
                                        );
                                        let ghost_actor_mode = if install_ghost_actors_allowed() {
                                            AppletGhostActorMode::PolicyDeclared
                                        } else {
                                            AppletGhostActorMode::Disallowed
                                        };
                                        install_status.set("previewing install plan…".to_owned());
                                        spawn(async move {
                                            let effective_scope = match applet_effective_scope(
                                                &realm,
                                                Some(circle.as_str()),
                                            ) {
                                                Ok(scope) => scope,
                                                Err(err) => {
                                                    install_status.set(err);
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
                                                    install_status.set(
                                                        "Applet package has no signed package_digest".to_owned(),
                                                    );
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
                                                            purpose: AppletManagedActorPurpose::InstallBot,
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
                                                    preview.authoring_request.validate_bindings()?;
                                                    let preview_basis = preview
                                                        .authoring_request
                                                        .basis
                                                        .install()
                                                        .ok_or_else(|| anyhow::anyhow!(
                                                            "preview returned a non-install authoring basis"
                                                        ))?;
                                                    if arkret_sdk::canonical::canonical_json_bytes(
                                                        preview_basis,
                                                    )? != arkret_sdk::canonical::canonical_json_bytes(
                                                        &requested_basis,
                                                    )? {
                                                        anyhow::bail!(
                                                            "preview changed the exact authoring request basis"
                                                        );
                                                    }
                                                    approved_actions_from_plan(&preview.plan, &package)
                                                })() {
                                                    Ok(actions)
                                                        if preview.plan.effective_scope == effective_scope
                                                            && preview.authoring_request.basis.install()
                                                                .is_some_and(|basis| {
                                                                    basis.effective_scope == effective_scope
                                                                }) =>
                                                    {
                                                        let scope_count = preview.plan.approved_scopes.len();
                                                        let digest = preview.plan.plan_digest.to_string();
                                                        install_preview.set(Some(AppletInstallPreviewSnapshot {
                                                            package,
                                                            preview,
                                                        }));
                                                        install_status.set(format!(
                                                            "plan ready ({} scope(s), {} action(s)); digest {}",
                                                            scope_count,
                                                            actions.len(),
                                                            short_protocol_id(&digest),
                                                        ));
                                                    }
                                                    Ok(_) => {
                                                        install_preview.set(None);
                                                        install_status.set(
                                                            "preview invalid: effective_scope does not match the request"
                                                                .to_owned(),
                                                        );
                                                    }
                                                    Err(err) => {
                                                        install_preview.set(None);
                                                        install_status.set(format!("preview invalid: {err}"));
                                                    }
                                                },
                                                Err(err) => {
                                                    install_preview.set(None);
                                                    install_status.set(format!(
                                                        "preview failed: {}", err.display()
                                                    ));
                                                }
                                            }
                                        });
                                    }
                                },
                                "Preview plan"
                            }
                            // Step 2 — relay the exact Station-signed
                            // request to the Applet service, then commit the
                            // returned co-signed managed-actor bundle unchanged.
                            Button {
                                variant: if install_preview().is_some() { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                                disabled: install_preview().is_none(),
                                "data-testid": "applet-install-confirm-button",
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
                                        let Some(snapshot) = install_preview() else {
                                            install_status.set("preview the plan before installing".to_owned());
                                            return;
                                        };
                                        let base = base.clone();
                                        let api_token = token();
                                        install_status.set("installing applet…".to_owned());
                                        spawn(async move {
                                            let applet_url = match url::Url::parse(
                                                &snapshot.package.base_url,
                                            ) {
                                                Ok(value) => value,
                                                Err(error) => {
                                                    install_status.set(format!(
                                                        "invalid Applet service base_url: {error}"
                                                    ));
                                                    return;
                                                }
                                            };
                                            let authoring_request =
                                                snapshot.preview.authoring_request;
                                            let idem = authoring_request
                                                .canonical_digest()
                                                .map(|digest| digest.to_string());
                                            let idem = match idem {
                                                Ok(value) => value,
                                                Err(error) => {
                                                    install_status.set(format!(
                                                        "cannot digest authoring request: {error}"
                                                    ));
                                                    return;
                                                }
                                            };
                                            let result = with_authed_sdk_client(&base, api_token, |http| async move {
                                                let author_outcome = http
                                                    .applet_managed_actor_author_at(
                                                        &applet_url,
                                                        &AppletManagedActorAuthorRequestBody {
                                                            authoring_request:
                                                                authoring_request.clone(),
                                                        },
                                                    )
                                                    .await
                                                    .map_err(anyhow::Error::from)?;
                                                author_outcome
                                                    .managed_actor_bundle
                                                    .validate_bindings(&authoring_request)?;
                                                let body = AppletInstallRequestBody::Create(Box::new(AppletInstallCreateRequestBody {
                                                    applet_package: snapshot.package,
                                                    authoring_request,
                                                    managed_actor_bundle:
                                                        author_outcome.managed_actor_bundle,
                                                }));
                                                http.applet_install(&idem, &body)
                                                    .await
                                                    .map_err(anyhow::Error::from)
                                            })
                                            .await;
                                            match result {
                                                Ok(outcome) => {
                                                    use arkret_models_integration::AppletInstallEffectiveStatus as Status;
                                                    let aid = short_protocol_id(&outcome.applet_id);
                                                    let line = match outcome.effective_status {
                                                        Status::Installed => {
                                                            format!("✅ installed: applet_id {aid}")
                                                        }
                                                        Status::PartiallyInstalled => format!(
                                                            "⚠ partially installed: applet_id {aid} — {} scope(s) rejected",
                                                            outcome.rejections.len(),
                                                        ),
                                                    };
                                                    let installed = matches!(outcome.effective_status, Status::Installed);
                                                    install_status.set(line);
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
                                                Err(err) => install_status.set(format!(
                                                    "install failed: {}", err.display()
                                                )),
                                            }
                                        });
                                    }
                                },
                                "Install applet"
                            }
                        }
                        if !install_status().is_empty() {
                            div { class: "muted", "data-testid": "applet-install-status", "{install_status}" }
                        }
                    }
                }

                if applet_rows.is_empty() {
                    div { class: "muted", "data-testid": "applet-empty",
                        "No applets installed."
                    }
                } else {
                    for (applet_id, service_id, namespace, manifest_hash, installed_at) in applet_rows.iter().cloned() {
                        {
                            let service_id_label = short_protocol_id(&service_id);
                            let manifest_hash_label = short_protocol_id(&manifest_hash);
                            rsx! {
                                div {
                                    class: "event",
                                    "data-testid": "applet-row",
                                    "data-applet-id": "{applet_id}",
                                    "data-applet-manifest-hash": "{manifest_hash}",
                                    "data-installed-at": "{installed_at}",
                                    div { class: "event-head",
                                        span { class: "mono", title: "{service_id}", "{service_id_label}" }
                                        span { class: "badge", "{namespace}" }
                                        span { class: "mono muted", title: "{manifest_hash}", "{manifest_hash_label}" }
                                    }
                                    div { class: "actions",
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "applet-accountability-trace-button",
                                            onclick: {
                                                let aid = applet_id.clone();
                                                move |_| trace_open_for.set(Some(aid.clone()))
                                            },
                                            "Trace events"
                                        }
                                        Button {
                                            variant: ButtonVariant::Destructive,
                                            "data-testid": "applet-uninstall-button",
                                            onclick: {
                                                let base = base_url.clone();
                                                let realm = selected_realm_id.clone();
                                                let aid = applet_id.clone();
                                                move |_| {
                                                    let base = base.clone();
                                                    let realm = realm.clone();
                                                    let aid = aid.clone();
                                                    let api_token = token();
                                                    let Some(account) = active_account.peek().clone() else {
                                                        install_status.set("revoke failed: active account context is unavailable".to_owned());
                                                        return;
                                                    };
                                                    let principal_id = account.authority.principal_id;
                                                    install_status.set("revoking applet…".to_owned());
                                                    spawn(async move {
                                                        // Revoke targets the Realm-wide install; a
                                                        // Circle-scoped revoke would need the row's
                                                        // installed scope (not surfaced here yet).
                                                        let effective_scope = match applet_effective_scope(&realm, None) {
                                                            Ok(scope) => scope,
                                                            Err(err) => {
                                                                install_status.set(err);
                                                                return;
                                                            }
                                                        };
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
                                                            if !preview.revoke_plan.membership_removals.is_empty() {
                                                                anyhow::bail!("runtime revoke preview unexpectedly requires membership Events");
                                                            }
                                                            let mut revoke_events = Vec::with_capacity(
                                                                preview.revoke_plan.capability_revocations.len(),
                                                            );
                                                            for intent in &preview.revoke_plan.capability_revocations {
                                                                revoke_events.push(
                                                                    crate::operation::ak_ops::capability_revoke(
                                                                        &realm,
                                                                        principal_id.as_str(),
                                                                        intent.grant_id.as_str(),
                                                                        Some(intent.reason_code.as_str()),
                                                                    )?
                                                                    .build_sdk_event("inkson")?,
                                                                );
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
                                                            let body = AppletRevokeRequestBody {
                                                                revoke_plan_digest: preview.revoke_plan_digest,
                                                                effective_scope,
                                                                reason_code,
                                                                revoke_mode,
                                                                capability_revoke_events,
                                                                membership_state_events: Vec::new(),
                                                                proof: None,
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
                                                            Ok(outcome) => install_status.set(format!(
                                                                "revoked: {} ref(s)", outcome.revoked_refs.len()
                                                            )),
                                                            Err(err) => install_status.set(format!(
                                                                "revoke failed: {}", err.display()
                                                            )),
                                                        }
                                                    });
                                                }
                                            },
                                            "Uninstall"
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
                                    h2 { title: "{target}", "Accountability trace — {target_label}" }
                                }
                                section {
                                    class: "publish-to-source-modal-body",
                                    if trace_events.is_empty() {
                                        p { class: "muted", "No events observed for this applet yet." }
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
                                                        div { class: "muted", title: "{event_id}", "event_id {event_id_label}" }
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
                                        "Close"
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

    // ── G3.Y4 — install helpers ─────────────────────────────────

    use super::{ManifestInputKind, classify_manifest_input, manifest_hash_for};

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

    #[test]
    fn manifest_hash_is_stable_and_prefixed() {
        let h1 = manifest_hash_for("did:web:applet.example:extensions");
        let h2 = manifest_hash_for("did:web:applet.example:extensions");
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
        // The short hash carries 8 bytes = 16 hex chars after the prefix.
        assert_eq!(h1.len(), "sha256:".len() + 16);
    }

    #[test]
    fn manifest_hash_differs_for_distinct_manifests() {
        let a = manifest_hash_for("did:web:applet.example:extensions");
        let b = manifest_hash_for("did:web:applet.example:messaging");
        assert_ne!(a, b);
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
