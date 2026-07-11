//! Global same-principal device-pairing approval prompt
//! (`crypto-media/device-lifecycle.md` §2.1 / §7).
//!
//! Mounted once near the app shell. When a new device asks to be authorized it
//! sends a `ak.key.verification.request` (`purpose =
//! "same_principal_device_authorization"`) to every already-authorized sibling;
//! `sync_engine` delivers it into `to_device_inbox`. This prompt surfaces the
//! first such pending request on ANY authorized device as a modal — the user
//! compares the `pairing_code` shown on both devices and approves or rejects,
//! instead of having to navigate to Settings → Devices → Pair and refresh.
//!
//! Approval finalizes through `POST /_arkret/gate/account/device-pair`
//! (`TransportClient::account_device_pair`); rejection dismisses locally. Both clear
//! the request from the inbox so the prompt does not nag again. The spec MUST
//! that the request alone never marks the new device trusted is honored: nothing
//! happens without the explicit Approve click.

use std::collections::HashSet;

use dioxus::prelude::*;

use crate::identity::device_pairing::{
    PendingPairingRequest, pairing_request_body, parse_pending_pairing_requests,
};
use crate::transport::auth::with_authed_api;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::dialog::Dialog;
use crate::views::helpers::short_protocol_id;

#[component]
pub fn DevicePairApprovalPrompt(token: Signal<String>, device_id: Signal<String>) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let session = crate::app::SessionContext::get();
    let base_url = session.base_url;
    let mut state_store = session.state_store;
    // Requests the user already acted on this session (approved, rejected, or
    // dismissed via escape). Keyed by `request_key`.
    let mut handled = use_signal(HashSet::<String>::new);
    let mut status = use_signal(String::new);

    if token().trim().is_empty() {
        return rsx! {};
    }

    let local_device = device_id();
    let handled_now = handled.read().clone();
    let inbox = state_store.read().to_device_inbox();
    let next_request = parse_pending_pairing_requests(&inbox)
        .into_iter()
        .find(|req| {
            req.requesting_device_id != local_device && !handled_now.contains(&req.request_key)
        });

    let Some(request) = next_request else {
        return rsx! {};
    };

    let PendingPairingRequest {
        request_key,
        requesting_device_id,
        pairing_code,
        display_name,
        platform,
        expires_at,
        request_payload,
    } = request;

    let device_label = if display_name.trim().is_empty() {
        short_protocol_id(&requesting_device_id)
    } else {
        display_name.clone()
    };
    let device_id_label = short_protocol_id(&requesting_device_id);
    let status_value = status();

    // Owned copies for each handler closure.
    let approve_key = request_key.clone();
    let approve_device = requesting_device_id.clone();
    let approve_code = pairing_code.clone();
    let approve_payload = request_payload.clone();

    let reject_key = request_key.clone();
    let reject_device = requesting_device_id.clone();
    let reject_code = pairing_code.clone();

    let dismiss_key = request_key.clone();

    rsx! {
        Dialog {
            open: true,
            on_open_change: move |open: bool| {
                if !open {
                    // Escape / backdrop = "later": hide for now without
                    // consuming the request, so it can resurface next session.
                    handled.write().insert(dismiss_key.clone());
                }
            },
            "data-testid": "device-pair-approval-modal",
            "aria-labelledby": "device-pair-approval-title",
            "aria-label": "A new device is requesting access to your account",
            div { class: "modal event",
                div { class: "modal-head event-head",
                    h3 { id: "device-pair-approval-title", "New device wants to join your account" }
                    span { class: "muted", "device pairing" }
                }
                div { class: "modal-body",
                    p { class: "muted",
                        "A device is asking to be added to your account. Approve it only if you started this — compare the code below on both devices first."
                    }
                    div {
                        class: "device-pair-approval-device",
                        "data-testid": "device-pair-approval-device",
                        "data-device-id": "{requesting_device_id}",
                        strong { "{device_label}" }
                        if device_label != device_id_label {
                            span { class: "muted mono", "{device_id_label}" }
                        }
                        if !platform.trim().is_empty() {
                            span { class: "muted", "Platform: {platform}" }
                        }
                        if !expires_at.trim().is_empty() {
                            span { class: "muted", "Request expires {expires_at}" }
                        }
                    }
                    div { class: "device-pair-approval-code-block",
                        span { class: "muted", "Compare this code on both devices" }
                        strong {
                            class: "device-pair-approval-code mono",
                            "data-testid": "device-pair-approval-code",
                            "{pairing_code}"
                        }
                    }
                    if !status_value.is_empty() {
                        div { class: "muted", "data-testid": "device-pair-approval-status", "{status_value}" }
                    }
                }
                div { class: "modal-foot actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "device-pair-approval-reject",
                        onclick: move |_| {
                            handled.write().insert(reject_key.clone());
                            state_store
                                .write()
                                .dismiss_pairing_to_device_message(&reject_device, &reject_code);
                            status.set(String::new());
                        },
                        "Reject"
                    }
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "device-pair-approval-approve",
                        onclick: move |_| {
                            let body = match pairing_request_body(&approve_payload) {
                                Ok(body) => body,
                                Err(err) => {
                                    status.set(format!("Cannot approve: {err}"));
                                    return;
                                }
                            };
                            let base = base_url();
                            let api_token = token();
                            let key = approve_key.clone();
                            let device = approve_device.clone();
                            let code = approve_code.clone();
                            status.set("Approving…".to_owned());
                            spawn(async move {
                                match crate::transport::auth::with_endpoint_clients(
                                    &base,
                                    api_token,
                                    None,
                                    |clients| async move {
                                        clients.keys().account_device_pair(&body).await
                                    },
                                )
                                .await
                                {
                                    Ok(_) => {
                                        state_store
                                            .write()
                                            .dismiss_pairing_to_device_message(&device, &code);
                                        handled.write().insert(key);
                                        status.set(String::new());
                                    }
                                    Err(err) => {
                                        status.set(format!("Approval failed: {}", err.display()));
                                    }
                                }
                            });
                        },
                        "Approve"
                    }
                }
            }
        }
    }
}
