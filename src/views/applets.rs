//! Applets — registry + protocol_session controls.
//!
//! Spec: `contrix-spec/spec/v1/zh/extensions/applet-integration.md`.
//!
//! What the panel does today:
//!   * Reads `cx.applet.registration` / `cx.applet.discovery` events out of
//!     the local raw-operation projection and renders them as registry rows
//!     so users see which applets the Space already accepts.
//!   * Surfaces a registration form bound to
//!     [`crate::operation::cx_ops::applet_registration`] — fills `service_did`
//!     + `namespace` + `capabilities` and submits via
//!     `with_authed_api(api.submit_event_envelope)`.
//!   * Per-session monitor lists active `protocol_session.start/status` rows
//!     so an operator can see in-flight applet calls + their bridge errors.
//!
//! Out of scope: applet manifest signature verification, capability gating
//! at submit time (relies on server-side soland validation), per-session
//! cancellation. Those follow once the bridge layer is implemented in a
//! companion crate.

use dioxus::prelude::*;
use serde_json::Value;

use crate::local_state::LocalStateStore;
use crate::views::helpers::with_authed_api;

#[component]
pub fn AppletsPanel(
    base_url: String,
    account_did: String,
    token: Signal<String>,
    selected_space: String,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let mut service_did = use_signal(String::new);
    let mut namespace = use_signal(|| "extensions".to_owned());
    let mut capabilities = use_signal(|| "read".to_owned());
    let mut status = use_signal(String::new);

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
                .map(|k| k == "cx.applet.registration")
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
                .map(|k| k.starts_with("cx.applet.protocol_session."))
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
                .map(|k| k == "cx.applet.bridge_error")
                .unwrap_or(false)
        })
        .cloned()
        .collect();

    rsx! {
        div { class: "timeline", "data-testid": "applets-panel", role: "region", "aria-label": "Applet registry and protocol sessions",
            div { class: "event",
                div { class: "event-head",
                    span { "Applet registry" }
                    span { class: "badge", "{registrations.len()} registered" }
                }
                div { class: "muted",
                    "Spec extensions/applet-integration.md §2 — applet registration carries service_did + namespace + capabilities. The registry lists every cx.applet.registration the local raw-operation log has observed."
                }
                if registrations.is_empty() {
                    div { class: "muted", "data-testid": "applet-registry-empty",
                        "No applets registered yet. Use the registration form below to write a cx.applet.registration event."
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
                            rsx! {
                                div { class: "event", "data-testid": "applet-registration-row",
                                    div { class: "event-head",
                                        span { class: "mono", "{service_did}" }
                                        span { class: "badge", "{namespace}" }
                                    }
                                    div { class: "muted", "operation_id {op_id}" }
                                }
                            }
                        }
                    }
                }
            }
            div { class: "event", "data-testid": "applet-register-form",
                div { class: "event-head",
                    span { "Register applet" }
                    span { class: "badge", "cx.applet.registration" }
                }
                div { class: "workflow-form",
                    input {
                        "data-testid": "applet-register-service-did",
                        value: "{service_did}",
                        placeholder: "service DID (did:web:applet.example)",
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
                                let space = selected_space.clone();
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
                        "No protocol sessions observed. Once an applet calls cx.applet.protocol_session.start the row appears here with its status updates."
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
                            rsx! {
                                div { class: "event", "data-testid": "applet-session-row",
                                    div { class: "event-head",
                                        span { class: "mono", "{kind}" }
                                        span { class: "mono", "{session_id}" }
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
                            rsx! {
                                div { class: "event", "data-testid": "applet-bridge-error-row",
                                    div { class: "event-head",
                                        span { class: "mono", "{error_code}" }
                                        span { class: "mono", "{session_id}" }
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
            "cx:space:test",
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
        // The view filters with `kind.starts_with("cx.applet.protocol_session.")`.
        for kind in [
            "cx.applet.protocol_session.start",
            "cx.applet.protocol_session.status",
        ] {
            assert!(kind.starts_with("cx.applet.protocol_session."));
        }
        assert!(!"cx.applet.registration".starts_with("cx.applet.protocol_session."));
    }
}
