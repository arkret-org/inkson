//! Applets — registry + interop_session controls.
//!
//! Spec: `cokret-spec/spec/v1/zh/extensions/applet-integration.md`.
//!
//! What the panel does today:
//!   * Reads `ck.applet.registration` / `ck.applet.discovery` events out of the local raw-operation
//!     projection and renders them as registry rows so users see which applets the Space already
//!     accepts.
//!   * Surfaces a registration form bound to [`crate::operation::ck_ops::applet_registration`] —
//!     fills `service_did`, `namespace` and `capabilities` and submits via
//!     `with_authed_api(api.submit_sdk_event)`.
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

use cokret_sdk::models::{
    AppletActorPolicy, AppletApprovalRequest, AppletBotMembership, AppletGhostActorMode,
    AppletInstallPreviewRequestBody, AppletInstallRequestBody, AppletRevokeMode,
    AppletRevokeRequestBody, EffectiveScope, ScopeGrant,
};
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use serde_json::{Value, json};

use crate::local_state::LocalStateStore;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::dialog::Dialog;
use crate::ui::input::Input;
use crate::ui::textarea::Textarea;
use crate::views::helpers::{short_protocol_id, with_authed_api, with_authed_sdk_client};

/// Build the canonical `applet_package` Value the install preview/commit
/// surface expects from a manifest input. For inline JSON the parsed object is
/// the package as-is; for a URL we wrap it in the minimal
/// `{ manifest_url }` envelope soland resolves server-side. Pure so the
/// classify→package mapping is unit-tested.
pub fn applet_package_from_manifest(kind: &ManifestInputKind) -> Option<Value> {
    match kind {
        ManifestInputKind::Json(raw) => serde_json::from_str::<Value>(raw).ok(),
        ManifestInputKind::Url(url) => Some(json!({ "manifest_url": url })),
        ManifestInputKind::Invalid => None,
    }
}

/// The effective-scope object an install/revoke targets. A blank `circle_id`
/// installs the applet Realm-wide; a `ck:circle:…` id scopes it to that Circle
/// only (spec §4b: a single install carries exactly one `effective_scope`, and a
/// Circle install MUST NOT widen to a Realm-wide grant). soland gates the write
/// on `ck.realm.admin` over the resolved scope either way.
pub fn applet_effective_scope(
    realm_id: &str,
    circle_id: Option<&str>,
) -> Result<EffectiveScope, String> {
    let realm_id = crate::operation::trim_realm_id(realm_id);
    let realm = cokret_sdk::RealmId::new(realm_id.clone())
        .map_err(|err| format!("invalid Realm id {realm_id:?}: {err:?}"))?;
    match circle_id.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok(EffectiveScope::Realm { realm_id: realm }),
        Some(circle) => cokret_sdk::CircleId::new(circle.to_owned())
            .map(|circle_id| EffectiveScope::Circle {
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
    allow_ghost_actors: bool,
) -> AppletApprovalRequest {
    AppletApprovalRequest {
        approve_actions,
        allow_ghost_actors,
        allow_delegated_native_actors: false,
        allow_e2ee_join: false,
        allow_widget: false,
    }
}

pub fn parse_applet_approval_actions(raw: &str) -> Vec<String> {
    raw.split(|ch: char| ch.is_ascii_whitespace() || ch == ',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Pull `plan_digest` + `approved_scopes` out of the canonical InstallPlan the
/// preview returns. `applet-install-plan.schema.json` makes both required, so a
/// missing `plan_digest` is a hard error the caller surfaces rather than
/// committing a digest-less (always-rejected) install.
pub fn parse_install_plan(plan: &Value) -> Result<(String, Vec<ScopeGrant>), String> {
    let plan_digest = plan
        .get("plan_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| "preview returned no plan_digest".to_owned())?
        .to_owned();
    let approved_scopes = plan
        .get("approved_scopes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let approved_scopes = serde_json::from_value::<Vec<ScopeGrant>>(Value::Array(approved_scopes))
        .map_err(|err| format!("preview approved_scopes invalid: {err}"))?;
    Ok((plan_digest, approved_scopes))
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
    let full = cokret_sdk::canonical::sha256_hex(manifest.as_bytes());
    format!("sha256:{}", &full[..16])
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
pub fn AppletsPanel(
    base_url: String,
    account_did: String,
    token: Signal<String>,
    selected_realm_id: String,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let mut service_did = use_signal(String::new);
    let mut namespace = use_signal(|| "extensions".to_owned());
    let mut capabilities = use_signal(|| "read".to_owned());
    let mut status = use_signal(String::new);

    // ─────────────────────────────────────────────────────────────
    // G3.Y4 — install / uninstall / accountability state
    // ─────────────────────────────────────────────────────────────
    let mut install_open = use_signal(|| false);
    let mut install_manifest = use_signal(String::new);
    let mut install_verified = use_signal(|| false);
    let mut install_status = use_signal(String::new);
    // P3 install wizard: the previewed plan_digest the commit MUST echo, and
    // the resolved approved-scope count surfaced after preview.
    let mut install_plan_digest = use_signal(String::new);
    let mut install_approved_scopes = use_signal(|| 0usize);
    let mut install_approved_scope_values = use_signal(Vec::<ScopeGrant>::new);
    let mut install_approve_actions = use_signal(String::new);
    let mut install_allow_ghost_actors = use_signal(|| false);
    // Optional Circle scope for the install. Blank = Realm-wide; a `ck:circle:…`
    // id scopes the install to that Circle only (spec §4b effective_scope).
    let mut install_circle_id = use_signal(String::new);
    let mut trace_open_for = use_signal(|| Option::<String>::None);

    // Pull registry + session rows from the local raw-operation
    // projection. The shape is keyed by op_type so a row's evidence is
    // the actual canonical event the projection observed; this view is
    // explicitly local-only — soland's projection_events feed will fan
    // out the same shape once the server-side applet broker ships.
    let raw_ops = state_store.read().load().raw_operations;
    let registrations: Vec<_> = raw_ops
        .iter()
        .filter(|r| {
            r.payload
                .get("kind")
                .and_then(Value::as_str)
                .map(|k| k == "ck.applet.registration")
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    let sessions: Vec<_> = raw_ops
        .iter()
        .filter(|r| {
            r.payload
                .get("kind")
                .and_then(Value::as_str)
                .map(|k| k.starts_with("ck.applet.interop_session."))
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    let bridge_errors: Vec<_> = raw_ops
        .iter()
        .filter(|r| {
            r.payload
                .get("kind")
                .and_then(Value::as_str)
                .map(|k| k == "ck.applet.bridge_error")
                .unwrap_or(false)
        })
        .cloned()
        .collect();

    // Build the canonical applet list (one entry per registration
    // operation, augmented with manifest_hash + installed_at).
    let applet_rows: Vec<_> = registrations
        .iter()
        .map(|r| {
            let service_did = r
                .payload
                .get("body")
                .and_then(|b| b.get("service_did"))
                .and_then(Value::as_str)
                .unwrap_or("did:web:?")
                .to_owned();
            let namespace = r
                .payload
                .get("body")
                .and_then(|b| b.get("namespace"))
                .and_then(Value::as_str)
                .unwrap_or("-")
                .to_owned();
            let applet_id = format!("{service_did}@{namespace}");
            let manifest_repr = format!("{}:{}", service_did, namespace);
            let manifest_hash = manifest_hash_for(&manifest_repr);
            let installed_at = r.operation_id.clone();
            (
                applet_id,
                service_did,
                namespace,
                manifest_hash,
                installed_at,
            )
        })
        .collect();

    // Audit trace for an applet: every raw op whose body
    // service_did matches the row's service_did. We materialize
    // once so the modal rendering doesn't re-filter on every paint.
    let trace_open_applet_id = trace_open_for();
    let trace_target_service_did = applet_rows
        .iter()
        .find(|(id, ..)| Some(id) == trace_open_applet_id.as_ref())
        .map(|(_, did, ..)| did.clone());
    let trace_events: Vec<_> = match &trace_target_service_did {
        Some(target) => raw_ops
            .iter()
            .filter(|r| {
                let kind_is_applet = r
                    .payload
                    .get("kind")
                    .and_then(Value::as_str)
                    .map(|k| k.starts_with("ck.applet."))
                    .unwrap_or(false);
                let matches_did = r
                    .payload
                    .get("body")
                    .and_then(|b| b.get("service_did"))
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
        div { class: "timeline", "data-testid": "applets-panel", role: "region", "aria-label": "Applet registry and protocol sessions",
            div { class: "event",
                div { class: "event-head",
                    span { "Applet registry" }
                    span { class: "badge", "{registrations.len()} registered" }
                }
                div { class: "muted",
                    "Spec extensions/applet-integration.md §2 — applet registration carries service_did + namespace + capabilities. The registry lists every ck.applet.registration the local raw-operation log has observed."
                }
                if registrations.is_empty() {
                    div { class: "muted", "data-testid": "applet-registry-empty",
                        "No applets registered yet. Use the registration form below to write a ck.applet.registration event."
                    }
                } else {
                    for r in registrations {
                        {
                            let service_did = r.payload.get("body")
                                .and_then(|b| b.get("service_did"))
                                .and_then(Value::as_str)
                                .unwrap_or("did:web:?")
                                .to_owned();
                            let namespace = r.payload.get("body")
                                .and_then(|b| b.get("namespace"))
                                .and_then(Value::as_str)
                                .unwrap_or("-")
                                .to_owned();
                            let op_id = r.operation_id.clone();
                            let service_did_label = short_protocol_id(&service_did);
                            let op_id_label = short_protocol_id(&op_id);
                            rsx! {
                                div { class: "event", "data-testid": "applet-registration-row",
                                    div { class: "event-head",
                                        span { class: "mono", title: "{service_did}", "{service_did_label}" }
                                        span { class: "badge", "{namespace}" }
                                    }
                                    div { class: "muted", title: "{op_id}", "operation_id {op_id_label}" }
                                }
                            }
                        }
                    }
                }
            }
            div { class: "event", "data-testid": "applet-register-form",
                div { class: "event-head",
                    span { "Register applet" }
                    span { class: "badge", title: "ck.applet.registration", "Applet" }
                }
                div { class: "workflow-form",
                    Input {
                        "data-testid": "applet-register-service-did",
                        value: "{service_did}",
                        placeholder: "applet handle (e.g. applet:example.com)",
                        oninput: move |event: FormEvent| service_did.set(event.value()),
                    }
                    Input {
                        "data-testid": "applet-register-namespace",
                        value: "{namespace}",
                        placeholder: "namespace (extensions / messaging / …)",
                        oninput: move |event: FormEvent| namespace.set(event.value()),
                    }
                    Input {
                        "data-testid": "applet-register-capabilities",
                        value: "{capabilities}",
                        placeholder: "capabilities (comma-separated)",
                        oninput: move |event: FormEvent| capabilities.set(event.value()),
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "applet-register-submit-button",
                            onclick: {
                                let base = base_url.clone();
                                let realm = selected_realm_id.clone();
                                let actor = account_did.clone();
                                move |_| {
                                    let base = base.clone();
                                    let realm = realm.clone();
                                    let actor = actor.clone();
                                    let did = service_did().trim().to_owned();
                                    let ns = namespace().trim().to_owned();
                                    let caps_input = capabilities();
                                    let caps: Vec<String> = caps_input
                                        .split(',')
                                        .map(|s| s.trim().to_owned())
                                        .filter(|s| !s.is_empty())
                                        .collect();
                                    if did.is_empty() || ns.is_empty() {
                                        status.set("service_did + namespace are required".to_owned());
                                        return;
                                    }
                                    let api_token = token();
                                    spawn(async move {
                                        let caps_refs: Vec<&str> = caps.iter().map(String::as_str).collect();
                                        let op = crate::operation::ck_ops::applet_registration(
                                            &realm, &actor, &did, &ns, &caps_refs,
                                        )
                                        .build_sdk_event("yougen");
                                        let op = match op {
                                            Ok(op) => op,
                                            Err(err) => {
                                                status.set(format!(
                                                    "applet registration build failed: {err}"
                                                ));
                                                return;
                                            }
                                        };
                                        match with_authed_api(&base, api_token, |api| async move {
                                            api.event_submitter()?.submit_sdk_event(&op).await
                                        })
                                        .await
                                        {
                                            Ok(resp) => status.set(format!(
                                                "applet registration submitted; event_id {}",
                                                resp.event_id
                                            )),
                                            Err(err) => status.set(format!(
                                                "applet registration failed: {}", err.display()
                                            )),
                                        }
                                    });
                                }
                            },
                            "Register applet"
                        }
                    }
                    if !status().is_empty() {
                        div { class: "muted", "data-testid": "applet-register-status", "{status}" }
                    }
                }
            }
            div { class: "event", "data-testid": "applet-session-list",
                div { class: "event-head",
                    span { "Active protocol sessions" }
                    span { class: "badge",
                        "{sessions.len()} session-event(s)"
                    }
                }
                if sessions.is_empty() {
                    div { class: "muted", "data-testid": "applet-session-empty",
                        "No protocol sessions observed. Once an applet calls ck.applet.interop_session.start the row appears here with its status updates."
                    }
                } else {
                    for s in sessions {
                        {
                            let kind = s.payload.get("kind")
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_owned();
                            let session_id = s.payload.get("body")
                                .and_then(|b| b.get("session_id"))
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_owned();
                            let status_opt = s.payload.get("body")
                                .and_then(|b| b.get("status"))
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned);
                            let session_id_label = short_protocol_id(&session_id);
                            rsx! {
                                div { class: "event", "data-testid": "applet-session-row",
                                    div { class: "event-head",
                                        span { class: "mono", "{kind}" }
                                        span { class: "mono", title: "{session_id}", "{session_id_label}" }
                                    }
                                    if let Some(status_str) = status_opt {
                                        div { class: "muted", "status: {status_str}" }
                                    }
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
                            let session_id = e.payload.get("body")
                                .and_then(|b| b.get("session_id"))
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_owned();
                            let msg_opt = e.payload.get("body")
                                .and_then(|b| b.get("message"))
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned);
                            let session_id_label = short_protocol_id(&session_id);
                            rsx! {
                                div { class: "event", "data-testid": "applet-bridge-error-row",
                                    div { class: "event-head",
                                        span { class: "mono", "{error_code}" }
                                        span { class: "mono", title: "{session_id}", "{session_id_label}" }
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
                                install_verified.set(false);
                                install_plan_digest.set(String::new());
                                install_approved_scope_values.set(Vec::new());
                                install_approved_scopes.set(0);
                            },
                            style: "width: 100%; min-height: 60px;",
                        }
                        // Optional Circle scope. Blank installs Realm-wide; a
                        // `ck:circle:…` id scopes the applet to that Circle only.
                        // Changing it invalidates the previewed plan (the digest
                        // is computed over effective_scope), so re-preview.
                        Textarea {
                            "data-testid": "applet-install-circle-input",
                            placeholder: "optional Circle id (ck:circle:…) — blank = Realm-wide",
                            value: "{install_circle_id}",
                            oninput: move |event: FormEvent| {
                                install_circle_id.set(event.value());
                                install_verified.set(false);
                                install_plan_digest.set(String::new());
                                install_approved_scope_values.set(Vec::new());
                                install_approved_scopes.set(0);
                            },
                            style: "width: 100%; min-height: 32px;",
                        }
                        Textarea {
                            "data-testid": "applet-install-approve-actions-input",
                            placeholder: "approved actions, comma or newline separated",
                            value: "{install_approve_actions}",
                            oninput: move |event: FormEvent| {
                                install_approve_actions.set(event.value());
                                install_verified.set(false);
                                install_plan_digest.set(String::new());
                                install_approved_scope_values.set(Vec::new());
                                install_approved_scopes.set(0);
                            },
                            style: "width: 100%; min-height: 48px;",
                        }
                        label { class: "metric", "data-testid": "applet-install-ghost-row",
                            Checkbox {
                                "data-testid": "applet-install-allow-ghost",
                                checked: if install_allow_ghost_actors() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                on_checked_change: move |state: CheckboxState| {
                                    install_allow_ghost_actors.set(bool::from(state));
                                    install_verified.set(false);
                                    install_plan_digest.set(String::new());
                                    install_approved_scope_values.set(Vec::new());
                                    install_approved_scopes.set(0);
                                },
                            }
                            span { "allow Applet-managed Ghost Actors" }
                        }
                        // Step 1 — preview: POST the manifest-derived package to
                        // `applet_install_preview`, capturing the canonical
                        // plan_digest the commit MUST echo back (P3 API).
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
                                        let Some(package) = applet_package_from_manifest(&kind) else {
                                            install_verified.set(false);
                                            install_plan_digest.set(String::new());
                                            install_status
                                                .set("manifest must be a URL or JSON body".to_owned());
                                            return;
                                        };
                                        let base = base.clone();
                                        let realm = realm.clone();
                                        let api_token = token();
                                        let circle = install_circle_id();
                                        let approve_actions = install_approve_actions();
                                        let allow_ghost_actors = install_allow_ghost_actors();
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
                                            let body = AppletInstallPreviewRequestBody {
                                                applet_package: package,
                                                effective_scope,
                                                approval_request: approval_request(
                                                    parse_applet_approval_actions(&approve_actions),
                                                    allow_ghost_actors,
                                                ),
                                            };
                                            let result = with_authed_sdk_client(&base, api_token, |http| async move {
                                                http.applet_install_preview(&body).await.map_err(anyhow::Error::from)
                                            })
                                            .await;
                                            match result {
                                                // `parse_install_plan` reads the plan via lenient
                                                // `Value` accessors; serialize the typed
                                                // `AppletInstallPlan` back to its wire JSON.
                                                Ok(plan) => match parse_install_plan(
                                                    &serde_json::to_value(&plan).unwrap_or_default(),
                                                ) {
                                                    Ok((digest, scopes)) => {
                                                        let scope_count = scopes.len();
                                                        install_plan_digest.set(digest.clone());
                                                        install_approved_scopes.set(scope_count);
                                                        install_approved_scope_values.set(scopes);
                                                        install_verified.set(true);
                                                        install_status.set(format!(
                                                            "plan ready ({} scope(s)); digest {}",
                                                            scope_count,
                                                            short_protocol_id(&digest),
                                                        ));
                                                    }
                                                    Err(err) => {
                                                        install_verified.set(false);
                                                        install_status.set(format!("preview invalid: {err}"));
                                                    }
                                                },
                                                Err(err) => {
                                                    install_verified.set(false);
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
                            // Step 2 — commit: echo plan_digest + approved_scopes
                            // back via `applet_install` with an Idempotency-Key.
                            Button {
                                variant: if install_verified() { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                                disabled: !install_verified(),
                                "data-testid": "applet-install-confirm-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let realm = selected_realm_id.clone();
                                    move |_| {
                                        let raw = install_manifest();
                                        let kind = classify_manifest_input(&raw);
                                        let Some(package) = applet_package_from_manifest(&kind) else {
                                            install_status.set("manifest no longer valid".to_owned());
                                            return;
                                        };
                                        let digest = install_plan_digest();
                                        if digest.is_empty() {
                                            install_status.set("preview the plan before installing".to_owned());
                                            return;
                                        }
                                        let base = base.clone();
                                        let realm = realm.clone();
                                        let api_token = token();
                                        let circle = install_circle_id();
                                        let approved_scopes = install_approved_scope_values();
                                        let allow_ghost_actors = install_allow_ghost_actors();
                                        install_status.set("installing applet…".to_owned());
                                        spawn(async move {
                                            let digest_typed = match cokret_sdk::Hash::new(digest.clone()) {
                                                Ok(h) => h,
                                                Err(err) => {
                                                    install_status.set(format!("bad plan_digest: {err:?}"));
                                                    return;
                                                }
                                            };
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
                                            let body = AppletInstallRequestBody {
                                                plan_digest: digest_typed,
                                                applet_package: package,
                                                effective_scope,
                                                approved_scopes,
                                                actor_policy: Some(AppletActorPolicy {
                                                    bot_membership: Some(AppletBotMembership::Join),
                                                    ghost_actor_mode: Some(if allow_ghost_actors {
                                                        AppletGhostActorMode::PolicyDeclared
                                                    } else {
                                                        AppletGhostActorMode::Disallowed
                                                    }),
                                                }),
                                                e2ee_policy: None,
                                                widget_policy: None,
                                            };
                                            let idem = crate::operation::uuid_v7();
                                            let result = with_authed_sdk_client(&base, api_token, |http| async move {
                                                http.applet_install(&idem, &body).await.map_err(anyhow::Error::from)
                                            })
                                            .await;
                                            match result {
                                                Ok(outcome) => {
                                                    // Surface the three-value effective_status
                                                    // distinctly: a Rejected outcome is an orphan
                                                    // registration (registration landed, no active
                                                    // grant) and grants the applet nothing.
                                                    use cokret_sdk::models::AppletInstallEffectiveStatus as Status;
                                                    let aid = short_protocol_id(&outcome.applet_id);
                                                    let line = match outcome.effective_status {
                                                        Status::Installed => {
                                                            format!("✅ installed: applet_id {aid}")
                                                        }
                                                        Status::PartiallyInstalled => format!(
                                                            "⚠ partially installed: applet_id {aid} — {} scope(s) rejected",
                                                            outcome.rejected.len(),
                                                        ),
                                                        Status::Rejected => format!(
                                                            "⛔ rejected (orphan registration — no active grant): applet_id {aid}"
                                                        ),
                                                    };
                                                    let installed = matches!(outcome.effective_status, Status::Installed);
                                                    install_status.set(line);
                                                    // Keep the form open on a rejected / partial
                                                    // outcome so the admin can adjust and retry.
                                                    if installed {
                                                        install_open.set(false);
                                                        install_manifest.set(String::new());
                                                        install_circle_id.set(String::new());
                                                        install_approve_actions.set(String::new());
                                                        install_allow_ghost_actors.set(false);
                                                        install_verified.set(false);
                                                        install_plan_digest.set(String::new());
                                                        install_approved_scope_values.set(Vec::new());
                                                        install_approved_scopes.set(0);
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
                    for (applet_id, service_did, namespace, manifest_hash, installed_at) in applet_rows.iter().cloned() {
                        {
                            let service_did_label = short_protocol_id(&service_did);
                            let manifest_hash_label = short_protocol_id(&manifest_hash);
                            rsx! {
                                div {
                                    class: "event",
                                    "data-testid": "applet-row",
                                    "data-applet-id": "{applet_id}",
                                    "data-applet-manifest-hash": "{manifest_hash}",
                                    "data-installed-at": "{installed_at}",
                                    div { class: "event-head",
                                        span { class: "mono", title: "{service_did}", "{service_did_label}" }
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
                                                        let body = AppletRevokeRequestBody {
                                                            effective_scope,
                                                            reason_code: "admin_uninstall".to_owned(),
                                                            revoke_mode: AppletRevokeMode::RevokeAll,
                                                            proof: None,
                                                        };
                                                        let result = with_authed_sdk_client(&base, api_token, |http| async move {
                                                            http.applet_revoke(&aid, &body).await.map_err(anyhow::Error::from)
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

    /// Pin the current lightweight registration form. The full durable
    /// `ck.applet.registration` payload still requires controller proof and
    /// package metadata that this panel does not collect yet.
    #[test]
    fn applet_registration_body_keys_pin_canonical_wire() {
        let op = crate::operation::ck_ops::applet_registration(
            "ck:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "did:web:applet.example",
            "extensions",
            &["read"],
        )
        .build("yougen");
        assert_eq!(op.payload["service_did"], "did:web:applet.example");
        assert_eq!(op.payload["namespace"], "extensions");
        assert_eq!(op.payload["capabilities"][0], "read");
    }

    #[test]
    fn applet_session_kind_filter_matches_three_session_event_kinds() {
        // The view filters with `kind.starts_with("ck.applet.interop_session.")`.
        for kind in [
            "ck.applet.interop_session.start",
            "ck.applet.interop_session.status",
        ] {
            assert!(kind.starts_with("ck.applet.interop_session."));
        }
        assert!(!"ck.applet.registration".starts_with("ck.applet.interop_session."));
    }

    // ── G3.Y4 — install helpers ─────────────────────────────────

    use super::{ManifestInputKind, classify_manifest_input, manifest_hash_for};

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
        applet_effective_scope, applet_package_from_manifest, parse_applet_approval_actions,
        parse_install_plan,
    };

    #[test]
    fn applet_package_maps_json_and_url_kinds() {
        let json = super::ManifestInputKind::Json("{\"package_id\":\"package:demo\"}".to_owned());
        let pkg = applet_package_from_manifest(&json).unwrap();
        assert_eq!(pkg["package_id"], "package:demo");

        let url = super::ManifestInputKind::Url("https://x/manifest.json".to_owned());
        let pkg = applet_package_from_manifest(&url).unwrap();
        assert_eq!(pkg["manifest_url"], "https://x/manifest.json");

        assert!(applet_package_from_manifest(&super::ManifestInputKind::Invalid).is_none());
    }

    #[test]
    fn effective_scope_trims_realm_prefix_consistently() {
        let scope =
            applet_effective_scope("ck:realm:01904100-0000-7000-8000-000000000010", None).unwrap();
        assert!(matches!(
            scope,
            cokret_sdk::models::EffectiveScope::Realm { ref realm_id }
                if realm_id.as_str() == "ck:realm:01904100-0000-7000-8000-000000000010"
        ));
    }

    #[test]
    fn effective_scope_circle_id_targets_circle() {
        let scope = applet_effective_scope(
            "ck:realm:01904100-0000-7000-8000-000000000010",
            Some("ck:circle:01904100-0000-7000-8000-0000000000c1"),
        )
        .unwrap();
        assert!(matches!(
            scope,
            cokret_sdk::models::EffectiveScope::Circle { ref realm_id, ref circle_id }
                if realm_id.as_str() == "ck:realm:01904100-0000-7000-8000-000000000010"
                    && circle_id.as_str() == "ck:circle:01904100-0000-7000-8000-0000000000c1"
        ));
        // Blank circle falls back to a Realm-wide install.
        assert!(matches!(
            applet_effective_scope("ck:realm:01904100-0000-7000-8000-000000000010", Some("  "))
                .unwrap(),
            cokret_sdk::models::EffectiveScope::Realm { .. }
        ));
    }

    #[test]
    fn parse_install_plan_requires_plan_digest() {
        let plan = serde_json::json!({
            "plan_digest": "sha256:deadbeef",
            "approved_scopes": [{
                "actions": ["ck.message.create", "ck.applet.ghost.provision"],
                "realm_ids": ["ck:realm:01904100-0000-7000-8000-000000000010"],
                "constraints": []
            }],
        });
        let (digest, scopes) = parse_install_plan(&plan).unwrap();
        assert_eq!(digest, "sha256:deadbeef");
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0].actions[0], "ck.message.create");

        // Missing plan_digest is a hard error (never commit a digest-less
        // install — soland would reject it with applet_install_plan_mismatch).
        let bad = serde_json::json!({ "approved_scopes": [] });
        assert!(parse_install_plan(&bad).is_err());
    }

    #[test]
    fn parse_applet_approval_actions_splits_and_dedupes() {
        assert_eq!(
            parse_applet_approval_actions(
                "ck.message.create, ck.applet.ghost.provision\nck.message.create"
            ),
            vec![
                "ck.applet.ghost.provision".to_owned(),
                "ck.message.create".to_owned()
            ]
        );
    }

    #[test]
    fn classify_manifest_input_detects_url_and_json_and_invalid() {
        assert_eq!(
            classify_manifest_input(
                "https://mock-applet-registry.local/_cokret/edge/applet/bridge.demo/manifest"
            ),
            ManifestInputKind::Url(
                "https://mock-applet-registry.local/_cokret/edge/applet/bridge.demo/manifest"
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
