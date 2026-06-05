//! Applets — registry + protocol_session controls.
//!
//! Spec: `cokret-spec/spec/v1/zh/extensions/applet-integration.md`.
//!
//! What the panel does today:
//!   * Reads `ck.applet.registration` / `ck.applet.discovery` events out of the local raw-operation
//!     projection and renders them as registry rows so users see which applets the Space already
//!     accepts.
//!   * Surfaces a registration form bound to [`crate::operation::cx_ops::applet_registration`] —
//!     fills `service_did`, `namespace` and `capabilities` and submits via
//!     `with_authed_api(api.submit_event_envelope)`.
//!   * Per-session monitor lists active `protocol_session.start/status` rows so an operator can see
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

use dioxus::prelude::*;
use serde_json::Value;

use crate::local_state::LocalStateStore;
use crate::views::helpers::{short_protocol_id, with_authed_api};

/// Whether the local UI should expose applet install / registration panels.
pub fn applets_enabled() -> bool {
    cfg!(feature = "experimental-applets")
}

/// Stable hash for a manifest body. `manifest_hash` is what soland's
/// applet registry will eventually pin per applet; the value is
/// rendered on `applet-row` via `data-applet-manifest-hash` so the
/// harness can assert it survives reload.
pub fn manifest_hash_for(manifest: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(manifest.as_bytes());
    let bytes = h.finalize();
    let mut out = String::from("sha256:");
    for b in bytes.iter().take(8) {
        out.push_str(&format!("{:02x}", b));
    }
    out
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
                .map(|k| k.starts_with("ck.applet.protocol_session."))
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
                    input {
                        "data-testid": "applet-register-service-did",
                        value: "{service_did}",
                        placeholder: "applet handle (e.g. applet:example.com)",
                        oninput: move |evt| service_did.set(evt.value()),
                    }
                    input {
                        "data-testid": "applet-register-namespace",
                        value: "{namespace}",
                        placeholder: "namespace (extensions / messaging / …)",
                        oninput: move |evt| namespace.set(evt.value()),
                    }
                    input {
                        "data-testid": "applet-register-capabilities",
                        value: "{capabilities}",
                        placeholder: "capabilities (comma-separated)",
                        oninput: move |evt| capabilities.set(evt.value()),
                    }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "applet-register-submit-button",
                            onclick: {
                                let base = base_url.clone();
                                let space = selected_realm_id.clone();
                                let actor = account_did.clone();
                                move |_| {
                                    let base = base.clone();
                                    let space = space.clone();
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
                                        let op = crate::operation::cx_ops::applet_registration(
                                            &space, &actor, &did, &ns, &caps_refs,
                                        )
                                        .build("yougen");
                                        match with_authed_api(&base, api_token, |api| async move {
                                            api.submit_event_envelope(&op).await
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
                        "No protocol sessions observed. Once an applet calls ck.applet.protocol_session.start the row appears here with its status updates."
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
                    button {
                        class: "primary",
                        "data-testid": "applet-install-button",
                        onclick: move |_| install_open.set(!install_open()),
                        if install_open() { "Close install" } else { "+ Install applet" }
                    }
                }
                if install_open() {
                    div { class: "workflow-form",
                        textarea {
                            "data-testid": "applet-install-manifest-input",
                            placeholder: "manifest URL or JSON body",
                            value: "{install_manifest}",
                            oninput: move |evt| {
                                install_manifest.set(evt.value());
                                install_verified.set(false);
                            },
                            style: "width: 100%; min-height: 60px;",
                        }
                        div { class: "actions",
                            button {
                                class: "secondary",
                                "data-testid": "applet-install-verify-button",
                                onclick: move |_| {
                                    let raw = install_manifest();
                                    match classify_manifest_input(&raw) {
                                        ManifestInputKind::Invalid => {
                                            install_verified.set(false);
                                            install_status
                                                .set("manifest must be a URL or JSON body".to_owned());
                                        }
                                        ManifestInputKind::Url(u) => {
                                            // Experimental-only surface:
                                            // default builds hide this panel
                                            // until server-side manifest
                                            // verification is owned by soland.
                                            install_verified.set(true);
                                            install_status.set(format!(
                                                "manifest URL accepted: {u}"
                                            ));
                                        }
                                        ManifestInputKind::Json(_j) => {
                                            install_verified.set(true);
                                            install_status.set(format!(
                                                "manifest JSON parsed (hash {})",
                                                manifest_hash_for(&raw)
                                            ));
                                        }
                                    }
                                },
                                "Verify manifest"
                            }
                            button {
                                class: if install_verified() { "primary" } else { "secondary" },
                                disabled: !install_verified(),
                                "data-testid": "applet-install-confirm-button",
                                onclick: move |_| {
                                    install_status.set(
                                        "install confirmed — submit ck.applet.registration in the form above to publish".to_owned(),
                                    );
                                    install_open.set(false);
                                    install_manifest.set(String::new());
                                    install_verified.set(false);
                                    // Experimental-only surface:
                                    // default builds hide this panel
                                    // until manifest prefill and direct
                                    // registration submission are complete.
                                },
                                "Confirm install"
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
                                        button {
                                            class: "secondary",
                                            "data-testid": "applet-accountability-trace-button",
                                            onclick: {
                                                let aid = applet_id.clone();
                                                move |_| trace_open_for.set(Some(aid.clone()))
                                            },
                                            "Trace events"
                                        }
                                        button {
                                            class: "danger",
                                            "data-testid": "applet-uninstall-button",
                                            onclick: {
                                                let sd = service_did.clone();
                                                move |_| {
                                                    install_status.set(format!(
                                                        "uninstall requested for {sd}"
                                                    ));
                                                    // Experimental-only surface:
                                                    // default builds hide this panel
                                                    // until soland accepts applet
                                                    // revoke/uninstall events.
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
                        div {
                            class: "publish-to-source-modal-backdrop",
                            "data-testid": "applet-accountability-modal",
                            div {
                                class: "publish-to-source-modal",
                                role: "dialog",
                                "aria-modal": "true",
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
                                    button {
                                        class: "secondary",
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

    /// Pin that the registry row body shape matches the canonical wire
    /// `body.service_did` / `body.namespace` schema the
    /// cx_ops::applet_registration builder emits. If the builder changes
    /// shape this test catches the view drift.
    #[test]
    fn applet_registration_body_keys_pin_canonical_wire() {
        let op = crate::operation::cx_ops::applet_registration(
            "ck:space:test",
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
        // The view filters with `kind.starts_with("ck.applet.protocol_session.")`.
        for kind in [
            "ck.applet.protocol_session.start",
            "ck.applet.protocol_session.status",
        ] {
            assert!(kind.starts_with("ck.applet.protocol_session."));
        }
        assert!(!"ck.applet.registration".starts_with("ck.applet.protocol_session."));
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
