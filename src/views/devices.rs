use dioxus::prelude::*;
use serde_json::Value;

use crate::{local_state::LocalStateStore, models::*, views::helpers::authed_api};

#[component]
pub fn DevicesPanel(
    base_url: String,
    token: Signal<String>,
    device_id: String,
    device_queue: usize,
    push_state: Signal<String>,
    state_store: Signal<LocalStateStore>,
    crypto_state: Signal<String>,
    push_ready: bool,
) -> Element {
    let mut one_time_keys = use_signal(|| Value::Null);
    let mut to_device_messages = use_signal(Vec::<Value>::new);
    let mut trust_devices = use_signal(Vec::<DeviceTrustEntry>::new);
    let mut mls_epoch = use_signal(|| Option::<MlsEpochResponse>::None);
    let mut upload_status = use_signal(|| String::new());
    let mut rotate_status = use_signal(|| String::new());
    let mut group_id = use_signal(|| "default".to_owned());

    // Clone String params for use in multiple closures
    let base_url_c = base_url.clone();
    let device_id_c = device_id.clone();

    rsx! {
        div { class: "timeline", "data-testid": "devices-panel",
            // Current device detail card
            div { class: "event", "data-testid": "device-summary",
                div { class: "event-head", span { "Current Device" } span { "{device_id}" } }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Device ID" }
                        span { "{device_id}" }
                    }
                    div { class: "metric",
                        strong { "Queue" }
                        span { "{device_queue}" }
                    }
                    div { class: "metric",
                        strong { "Push" }
                        span { "{push_state}" }
                    }
                    div { class: "metric",
                        strong { "Crypto" }
                        span { "{crypto_state}" }
                    }
                }
            }

            div { class: "event", "data-testid": "device-verification-workbench",
                div { class: "event-head", span { "Device verification" } span { "SAS / QR / KeyPackage" } }
                div { class: "muted",
                    "Verification is modeled as a device-scoped flow. Revocation explains MLS epoch impact before any destructive action."
                }
                div { class: "metric-grid",
                    div { class: "metric", strong { "SAS" } span { "473 918" } div { class: "muted", "compare on both devices" } }
                    div { class: "metric", strong { "QR" } span { "cx:verify:{device_id}" } div { class: "muted", "short-lived verification token" } }
                    div { class: "metric", strong { "KeyPackage" } span { "published" } div { class: "muted", "ready for MLS Welcome" } }
                    div { class: "metric", strong { "Epoch impact" } span { "proposal required" } div { class: "muted", "revoked device is removed at next commit" } }
                }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "sas-start-button",
                        onclick: move |_| crypto_state.set("SAS verification started for current device".to_owned()),
                        "Start SAS"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "qr-start-button",
                        onclick: move |_| crypto_state.set("QR verification token prepared".to_owned()),
                        "Show QR"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "revoke-impact-button",
                        onclick: move |_| crypto_state.set("Revocation will require MLS remove proposal and epoch advance".to_owned()),
                        "Preview revoke impact"
                    }
                }
            }

            // One-time keys
            div { class: "event", "data-testid": "otk-panel",
                div { class: "event-head", span { "One-Time Keys" } span { "management" } }
                div { class: "muted", "Upload one-time keys for forward secrecy." }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "upload-keys-button",
                        onclick: {
                            let base = base_url_c.clone();
                            let dev = device_id_c.clone();
                            move |_| {
                                let base = base.clone();
                                let api_token = token();
                                let dev = dev.clone();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.upload_keys(&dev).await {
                                            Ok(resp) => {
                                                one_time_keys.set(resp.one_time_key_counts.clone());
                                                upload_status.set(format!("uploaded; counts: {}", resp.one_time_key_counts));
                                            }
                                            Err(e) => upload_status.set(format!("upload failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Upload OTKs"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "rotate-keys-button",
                        onclick: {
                            let base = base_url_c.clone();
                            let dev = device_id_c.clone();
                            move |_| {
                                let base = base.clone();
                                let api_token = token();
                                let dev = dev.clone();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.rotate_keys(&dev).await {
                                            Ok(resp) => {
                                                one_time_keys.set(resp.one_time_key_counts.clone());
                                                rotate_status.set(format!("rotated; counts: {}", resp.one_time_key_counts));
                                            }
                                            Err(e) => rotate_status.set(format!("rotate failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Rotate Keys"
                    }
                }
                if !upload_status().is_empty() {
                    div { class: "muted", "data-testid": "upload-status", "{upload_status}" }
                }
                if !rotate_status().is_empty() {
                    div { class: "muted", "data-testid": "rotate-status", "{rotate_status}" }
                }
                if one_time_keys() != Value::Null {
                    div { class: "muted", "data-testid": "otk-counts", "Keys: {one_time_keys}" }
                }
            }

            // To-device message inbox
            div { class: "event", "data-testid": "to-device-inbox",
                div { class: "event-head", span { "To-Device Messages" } span { "{to_device_messages().len()} pending" } }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "fetch-device-messages",
                        onclick: {
                            let base = base_url_c.clone();
                            move |_| {
                                let base = base.clone();
                                let api_token = token();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.receive_device_messages().await {
                                            Ok(resp) => to_device_messages.set(resp.events),
                                            Err(e) => push_state.set(format!("fetch failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Fetch Messages"
                    }
                }
                for msg in to_device_messages() {
                    div { class: "muted", "data-testid": "device-message", "{msg}" }
                }
                if to_device_messages().is_empty() {
                    div { class: "muted", "No pending to-device messages." }
                }
            }

            // Push notification controls
            div { class: "event", "data-testid": "push-controls",
                div { class: "event-head", span { "Push Notifications" } span { "register / unregister" } }
                if push_ready {
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "push-register-button",
                            onclick: {
                                let base = base_url_c.clone();
                                let dev = device_id_c.clone();
                                move |_| {
                                    let base = base.clone();
                                    let api_token = token();
                                    let dev = dev.clone();
                                    spawn(async move {
                                        if let Ok(api) = authed_api(&base, api_token) {
                                            match crate::push::build_register_request(&dev) {
                                                Ok(request) => match api.register_push_device_with_request(&request).await {
                                                    Ok(push) => {
                                                        let local_push = chime::RegisterDeviceResponse {
                                                            ok: push.ok,
                                                            registration_id: push.registration_id.clone(),
                                                            expires_at: push.expires_at.clone(),
                                                            ..Default::default()
                                                        };
                                                        state_store.write().save_push_registration(
                                                            crate::push::registration_state_from_response(
                                                                &request,
                                                                &local_push,
                                                            ),
                                                        );
                                                        push_state.set(push.registration_id.unwrap_or_else(|| "registered".to_owned()));
                                                    }
                                                    Err(e) => push_state.set(format!("push failed: {e}")),
                                                },
                                                Err(e) => push_state.set(format!("push unavailable: {e}")),
                                            }
                                        }
                                    });
                                }
                            },
                            "Register Push"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "push-unregister-button",
                            onclick: {
                                let base = base_url_c.clone();
                                let dev = device_id_c.clone();
                                move |_| {
                                    let base = base.clone();
                                    let api_token = token();
                                    let dev = dev.clone();
                                    let existing = state_store.read().push_registration();
                                    spawn(async move {
                                        if let Ok(api) = authed_api(&base, api_token) {
                                            match crate::push::build_unregister_request(&dev, existing.as_ref()) {
                                                Ok(request) => match api.unregister_push_device_with_request(&request).await {
                                                    Ok(_) => {
                                                        state_store.write().clear_push_registration();
                                                        push_state.set("Not registered".to_owned());
                                                    }
                                                    Err(e) => push_state.set(format!("unregister failed: {e}")),
                                                },
                                                Err(e) => push_state.set(format!("unregister unavailable: {e}")),
                                            }
                                        }
                                    });
                                }
                            },
                            "Unregister Push"
                        }
                    }
                } else {
                    div { class: "muted", "Push registration controls are hidden until /server/describe advertises push.register_device." }
                }
                div { class: "muted", "Current: {push_state}" }
            }

            // Device trust table
            div { class: "event", "data-testid": "device-trust-table",
                div { class: "event-head", span { "Device Trust" } span { "{trust_devices().len()} devices" } }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "fetch-trust-button",
                        onclick: {
                            let base = base_url_c.clone();
                            move |_| {
                                let base = base.clone();
                                let api_token = token();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.get_device_trust().await {
                                            Ok(resp) => trust_devices.set(resp.devices),
                                            Err(e) => crypto_state.set(format!("trust fetch failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Refresh Trust"
                    }
                }
                for entry in trust_devices() {
                    div { class: "event", "data-testid": "trust-entry",
                        div { class: "event-head",
                            span { "{entry.device_id}" }
                            span { "{entry.trust_state}" }
                        }
                        if let Some(ref name) = entry.display_name {
                            div { class: "muted", "{name}" }
                        }
                        if let Some(ref verified) = entry.verified_at {
                            div { class: "muted", "Verified: {verified}" }
                        }
                        div { class: "actions",
                            button {
                                class: "secondary",
                                "data-testid": "verify-device-button",
                                onclick: {
                                    let base = base_url_c.clone();
                                    let dev_id = entry.device_id.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let dev_id = dev_id.clone();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                let _ = api.verify_device(&dev_id, "sas", serde_json::json!({})).await;
                                            }
                                        });
                                    }
                                },
                                "Verify"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "revoke-device-button",
                                onclick: {
                                    let base = base_url_c.clone();
                                    let dev_id = entry.device_id.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let dev_id = dev_id.clone();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                let _ = api.revoke_device(&dev_id).await;
                                            }
                                        });
                                    }
                                },
                                "Revoke"
                            }
                        }
                    }
                }
                if trust_devices().is_empty() {
                    div { class: "muted", "No device trust data. Click Refresh Trust to load." }
                }
            }

            // MLS epoch display
            div { class: "event", "data-testid": "mls-epoch-panel",
                div { class: "event-head", span { "MLS Epoch" } span { "group state" } }
                div { class: "workflow-form",
                    input {
                        "data-testid": "mls-group-id-input",
                        value: "{group_id}",
                        oninput: move |evt| group_id.set(evt.value()),
                    }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "get-epoch-button",
                            onclick: {
                                let base = base_url_c.clone();
                                move |_| {
                                    let base = base.clone();
                                    let gid = group_id();
                                    let api_token = token();
                                    spawn(async move {
                                        if let Ok(api) = authed_api(&base, api_token) {
                                            match api.get_mls_epoch(&gid).await {
                                                Ok(epoch) => mls_epoch.set(Some(epoch)),
                                                Err(e) => crypto_state.set(format!("epoch fetch failed: {e}")),
                                            }
                                        }
                                    });
                                }
                            },
                            "Get Epoch"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "rotate-epoch-button",
                            onclick: {
                                let base = base_url_c.clone();
                                move |_| {
                                    let base = base.clone();
                                    let gid = group_id();
                                    let api_token = token();
                                    spawn(async move {
                                        if let Ok(api) = authed_api(&base, api_token) {
                                            match api.rotate_mls_epoch(&gid).await {
                                                Ok(resp) => {
                                                    mls_epoch.set(Some(MlsEpochResponse {
                                                        epoch: resp.epoch,
                                                        group_id: resp.group_id,
                                                        member_count: 0,
                                                        last_rotation: None,
                                                    }));
                                                }
                                                Err(e) => crypto_state.set(format!("rotate failed: {e}")),
                                            }
                                        }
                                    });
                                }
                            },
                            "Rotate Epoch"
                        }
                    }
                    if let Some(ref epoch) = mls_epoch() {
                        div { class: "metric-grid",
                            div { class: "metric",
                                strong { "Epoch" }
                                span { "{epoch.epoch}" }
                            }
                            div { class: "metric",
                                strong { "Group" }
                                span { "{epoch.group_id}" }
                            }
                            div { class: "metric",
                                strong { "Members" }
                                span { "{epoch.member_count}" }
                            }
                            div { class: "metric",
                                strong { "Last Rotation" }
                                span { "{epoch.last_rotation.as_deref().unwrap_or(\"never\")}" }
                            }
                        }
                    }
                }
            }

            // Encryption summary
            div { class: "event",
                div { class: "event-head", span { "Encryption" } span { "dev mode" } }
                div { "MLS local compose/decrypt helpers are active. Missing group state keeps ciphertext pending." }
            }
        }
    }
}
