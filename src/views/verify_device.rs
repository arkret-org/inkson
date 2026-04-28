use dioxus::prelude::*;
use serde_json::json;

use crate::{
    models::*,
    views::helpers::authed_api,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerifyMethod {
    QrCode,
    Sas,
}

#[component]
pub fn VerifyDevicePanel(
    base_url: String,
    token: Signal<String>,
    device_id: String,
) -> Element {
    let mut verify_method = use_signal(|| VerifyMethod::QrCode);
    let mut target_device = use_signal(String::new);
    let mut verify_status = use_signal(|| String::new());
    let mut trust_devices = use_signal(Vec::<DeviceTrustEntry>::new);
    let mut cross_signing_state = use_signal(|| "Not configured".to_owned());
    let mut sas_code = use_signal(|| String::new());
    let mut qr_data = use_signal(|| String::new());

    rsx! {
        div { class: "timeline", "data-testid": "verify-device-panel",
            // Verification method selector
            div { class: "event", "data-testid": "verify-method",
                div { class: "event-head", span { "Device Verification" } span { "choose method" } }
                div { class: "actions",
                    button {
                        class: if verify_method() == VerifyMethod::QrCode { "primary" } else { "secondary" },
                        "data-testid": "qr-verify-button",
                        onclick: move |_| verify_method.set(VerifyMethod::QrCode),
                        "QR Code"
                    }
                    button {
                        class: if verify_method() == VerifyMethod::Sas { "primary" } else { "secondary" },
                        "data-testid": "sas-verify-button",
                        onclick: move |_| verify_method.set(VerifyMethod::Sas),
                        "SAS (Emoji)"
                    }
                }
            }

            // QR Code verification flow
            if verify_method() == VerifyMethod::QrCode {
                div { class: "event", "data-testid": "qr-verify-flow",
                    div { class: "event-head", span { "QR Verification" } span { "scan or display" } }
                    div { class: "workflow-form",
                        label { "Target Device ID" }
                        input {
                            "data-testid": "qr-target-device",
                            value: "{target_device}",
                            placeholder: "Device ID to verify",
                            oninput: move |evt| target_device.set(evt.value()),
                        }
                        div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "generate-qr-button",
                                onclick: move |_| {
                                    qr_data.set(format!("contrix:verify:{}:{}", device_id, target_device()));
                                },
                                "Generate QR Data"
                            }
                        }
                        if !qr_data().is_empty() {
                            div { class: "event", "data-testid": "qr-display",
                                div { class: "space-title", "QR Code Data" }
                                div { class: "muted", "data-testid": "qr-data", "{qr_data}" }
                                div { class: "muted", "Display this QR code for the other device to scan." }
                            }
                        }
                    }
                }
            }

            // SAS verification flow
            if verify_method() == VerifyMethod::Sas {
                div { class: "event", "data-testid": "sas-verify-flow",
                    div { class: "event-head", span { "SAS Verification" } span { "emoji comparison" } }
                    div { class: "workflow-form",
                        label { "Target Device ID" }
                        input {
                            "data-testid": "sas-target-device",
                            value: "{target_device}",
                            placeholder: "Device ID to verify",
                            oninput: move |evt| target_device.set(evt.value()),
                        }
                        div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "start-sas-button",
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let target = target_device();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                match api.verify_device(&target, "sas", json!({})).await {
                                                    Ok(resp) => {
                                                        sas_code.set(format!("verified: {}", resp.trust_state));
                                                        verify_status.set(format!("SAS started with {}", resp.device_id));
                                                    }
                                                    Err(e) => verify_status.set(format!("SAS failed: {e}")),
                                                }
                                            }
                                        });
                                    }
                                },
                                "Start SAS Verification"
                            }
                        }
                        if !sas_code().is_empty() {
                            div { class: "event", "data-testid": "sas-display",
                                div { class: "space-title", "Short Authentication String" }
                                div { class: "muted", "Compare these emojis with the other device:" }
                                div { class: "space-title", "emoji-sequence-placeholder" }
                                div { class: "muted", "{sas_code}" }
                                div { class: "actions",
                                    button {
                                        class: "primary",
                                        onclick: move |_| verify_status.set("SAS verified!".to_owned()),
                                        "They Match"
                                    }
                                    button {
                                        class: "secondary",
                                        onclick: move |_| verify_status.set("SAS mismatch - verification failed".to_owned()),
                                        "They Don't Match"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if !verify_status().is_empty() {
                div { class: "muted", "data-testid": "verify-status", "{verify_status}" }
            }

            // Device trust table
            div { class: "event", "data-testid": "trust-table",
                div { class: "event-head", span { "Device Trust" } span { "{trust_devices().len()} devices" } }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "refresh-trust-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let base = base.clone();
                                let api_token = token();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.get_device_trust().await {
                                            Ok(resp) => trust_devices.set(resp.devices),
                                            Err(e) => verify_status.set(format!("trust fetch failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Refresh"
                    }
                }
                for entry in trust_devices() {
                    div { class: "event", "data-testid": "trust-row",
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
                                "data-testid": "verify-action-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let dev_id = entry.device_id.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let dev_id = dev_id.clone();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                let _ = api.verify_device(&dev_id, "sas", json!({})).await;
                                            }
                                        });
                                    }
                                },
                                "Verify"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "revoke-action-button",
                                onclick: {
                                    let base = base_url.clone();
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
                    div { class: "muted", "No devices loaded. Click Refresh to load device trust." }
                }
            }

            // Cross-signing state
            div { class: "event", "data-testid": "cross-signing",
                div { class: "event-head", span { "Cross-Signing" } span { "state" } }
                div { class: "muted", "{cross_signing_state}" }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "setup-cross-signing",
                        onclick: move |_| cross_signing_state.set("Setup not yet available".to_owned()),
                        "Setup Cross-Signing"
                    }
                }
            }
        }
    }
}
