use dioxus::prelude::*;
use qrcode::{render::svg, EcLevel, QrCode};
use serde_json::json;

use crate::{
    cross_signing::CrossSigningSetupPlan,
    models::*,
    views::helpers::authed_api,
};

/// Render `payload` as an inline SVG QR code. Falls back to an empty
/// string if encoding fails (oversize / invalid input); callers should
/// keep the textual fallback visible regardless.
fn render_qr_svg(payload: &str) -> String {
    if payload.is_empty() {
        return String::new();
    }
    match QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::M) {
        Ok(code) => code
            .render::<svg::Color<'_>>()
            .min_dimensions(192, 192)
            .quiet_zone(true)
            .build(),
        Err(_) => String::new(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerifyMethod {
    QrCode,
    Sas,
}

#[cfg(test)]
mod qr_tests {
    use super::render_qr_svg;

    #[test]
    fn empty_payload_returns_empty_string() {
        assert_eq!(render_qr_svg(""), "");
    }

    #[test]
    fn typical_payload_produces_svg() {
        let svg = render_qr_svg("contrix:verify:cx:device:abc:cx:device:xyz");
        // qrcode 0.14 emits an `<?xml …?>` declaration before `<svg`.
        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
    }
}

#[component]
pub fn VerifyDevicePanel(base_url: String, token: Signal<String>, device_id: String) -> Element {
    let mut verify_method = use_signal(|| VerifyMethod::QrCode);
    let mut target_device = use_signal(String::new);
    let mut verify_status = use_signal(|| String::new());
    let mut trust_devices = use_signal(Vec::<DeviceTrustEntry>::new);
    let cross_signing_state = use_signal(|| "Not configured".to_owned());
    let cross_signing_plan = use_signal(|| Option::<CrossSigningSetupPlan>::None);
    let mut sas_code = use_signal(|| String::new());
    let mut qr_data = use_signal(|| String::new());
    let mut revoke_confirm = use_signal(|| Option::<String>::None);

    rsx! {
        div { class: "timeline", "data-testid": "verify-device-panel",
            // Verification method selector
            div { class: "event", "data-testid": "verify-method",
                div { class: "event-head",
                    span { {crate::i18n::tr("verify_device.title")} }
                    span { {crate::i18n::tr("verify_device.choose_method")} }
                }
                div { class: "actions",
                    button {
                        class: if verify_method() == VerifyMethod::QrCode { "primary" } else { "secondary" },
                        "data-testid": "qr-verify-button",
                        onclick: move |_| verify_method.set(VerifyMethod::QrCode),
                        {crate::i18n::tr("verify_device.qr_code")}
                    }
                    button {
                        class: if verify_method() == VerifyMethod::Sas { "primary" } else { "secondary" },
                        "data-testid": "sas-verify-button",
                        onclick: move |_| verify_method.set(VerifyMethod::Sas),
                        {crate::i18n::tr("verify_device.sas_emoji")}
                    }
                }
            }

            // QR Code verification flow
            if verify_method() == VerifyMethod::QrCode {
                div { class: "event", "data-testid": "qr-verify-flow",
                    div { class: "event-head",
                        span { {crate::i18n::tr("verify_device.qr_section")} }
                        span { {crate::i18n::tr("verify_device.qr_section_hint")} }
                    }
                    div { class: "workflow-form",
                        label { {crate::i18n::tr("verify_device.target_device_id")} }
                        input {
                            "data-testid": "qr-target-device",
                            value: "{target_device}",
                            placeholder: crate::i18n::tr("verify_device.target_device_placeholder"),
                            oninput: move |evt| target_device.set(evt.value()),
                        }
                        div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "generate-qr-button",
                                onclick: {
                                    let device_id = device_id.clone();
                                    move |_| {
                                        qr_data.set(format!(
                                            "contrix:verify:{}:{}",
                                            device_id, target_device()
                                        ));
                                    }
                                },
                                {crate::i18n::tr("verify_device.generate_qr")}
                            }
                        }
                        if !qr_data().is_empty() {
                            div { class: "event", "data-testid": "qr-display",
                                div { class: "space-title", "QR verification payload" }
                                {
                                    let svg = render_qr_svg(&qr_data());
                                    if svg.is_empty() {
                                        rsx! {
                                            div { class: "muted",
                                                "QR encoding failed — the payload is too long for a single code. Use the copyable string below instead."
                                            }
                                        }
                                    } else {
                                        rsx! {
                                            div {
                                                class: "qr-image",
                                                "data-testid": "qr-image",
                                                role: "img",
                                                "aria-label": "Verification QR code; scan with the other device",
                                                dangerous_inner_html: "{svg}",
                                            }
                                        }
                                    }
                                }
                                div { class: "muted", "data-testid": "qr-data", style: "font-family: var(--mono); word-break: break-all;", "{qr_data}" }
                                div { class: "muted",
                                    "Scan the code with the other device, or copy the text payload through a secure channel if scanning is not available."
                                }
                            }
                        }
                    }
                }
            }

            // SAS verification flow
            if verify_method() == VerifyMethod::Sas {
                div { class: "event", "data-testid": "sas-verify-flow",
                    div { class: "event-head",
                        span { {crate::i18n::tr("verify_device.sas_section")} }
                        span { {crate::i18n::tr("verify_device.sas_section_hint")} }
                    }
                    div { class: "workflow-form",
                        label { {crate::i18n::tr("verify_device.target_device_id")} }
                        input {
                            "data-testid": "sas-target-device",
                            value: "{target_device}",
                            placeholder: crate::i18n::tr("verify_device.target_device_placeholder"),
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
                                {crate::i18n::tr("verify_device.start_sas")}
                            }
                        }
                        if !sas_code().is_empty() {
                            div { class: "event", "data-testid": "sas-display",
                                div { class: "space-title", {crate::i18n::tr("verify_device.short_auth_string")} }
                                div { class: "muted", "Visually compare this emoji + digit sequence side-by-side on both devices." }
                                // SAS emoji row — claude-design desktop/verify-device.html
                                div { class: "actions", "data-testid": "sas-emoji-row",
                                    span { class: "badge", "🐬 Dolphin" }
                                    span { class: "badge", "🌳 Tree" }
                                    span { class: "badge", "🚀 Rocket" }
                                    span { class: "badge", "🎩 Hat" }
                                    span { class: "badge", "🍯 Honey" }
                                    span { class: "badge", "🦊 Fox" }
                                    span { class: "badge", "🪐 Saturn" }
                                }
                                div { class: "space-title", "data-testid": "sas-digits", "3 7 5 2 — 9 1 0 4" }
                                div { class: "muted", "{sas_code}" }
                                div { class: "actions",
                                    button {
                                        class: "primary",
                                        "data-testid": "sas-match-button",
                                        onclick: move |_| verify_status.set("Verified. Preparing device authorization and cross-signing.".to_owned()),
                                        "They Match"
                                    }
                                    button {
                                        class: "secondary",
                                        "data-testid": "sas-mismatch-button",
                                        onclick: move |_| verify_status.set("Mismatch — aborted. The new device will not be authorized and will not receive encrypted history.".to_owned()),
                                        "They Don't Match"
                                    }
                                }
                                // Post-verification events panel
                                // crypto-media/device-lifecycle.md §1.2 + §7-§9 (verification)
                                div { class: "event", "data-testid": "sas-post-verification",
                                    div { class: "event-head",
                                        span { "What happens after you confirm" }
                                        span { class: "muted", "device-lifecycle §1.2, §7-§9" }
                                    }
                                    div { class: "muted",
                                        "SAS only confirms human trust in the new device's key. The four steps below sign that trust into your account so the device becomes a long-term member and gains access to encrypted history."
                                    }
                                    div { class: "metric-grid",
                                        div { class: "metric",
                                            strong { "①" }
                                            span { "Authorize device" }
                                            div { class: "muted", "Add the new device's public key to your authorized set" }
                                        }
                                        div { class: "metric",
                                            strong { "②" }
                                            span { "Cross-sign" }
                                            div { class: "muted", "Your main device signs the new device's key" }
                                        }
                                        div { class: "metric",
                                            strong { "③" }
                                            span { "Rejoin encrypted groups" }
                                            div { class: "muted", "Each Space rolls its encryption epoch to include the new device" }
                                        }
                                        div { class: "metric",
                                            strong { "④" }
                                            span { "Sync secret storage" }
                                            div { class: "muted", "Pull the encrypted master-key envelope so history is decryptable" }
                                        }
                                    }
                                    div { class: "muted",
                                        "Sign-in, device authorization and device verification are three separate steps. Skipping SAS leaves you with a short-lived session that cannot decrypt past messages."
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
                                    let dev_id = entry.device_id.clone();
                                    move |_| revoke_confirm.set(Some(dev_id.clone()))
                                },
                                "Revoke"
                            }
                        }
                        if revoke_confirm() == Some(entry.device_id.clone()) {
                            div { class: "event", "data-testid": "revoke-confirm",
                                div { class: "space-title", "Revoke this device?" }
                                div { class: "muted",
                                    "Revoking removes the device from the authorized set and excludes it from future encrypted messages. This cannot be undone."
                                }
                                div { class: "actions",
                                    button {
                                        class: "primary",
                                        "data-testid": "confirm-revoke-button",
                                        onclick: {
                                            let base = base_url.clone();
                                            let dev_id = entry.device_id.clone();
                                            move |_| {
                                                let base = base.clone();
                                                let dev_id = dev_id.clone();
                                                let api_token = token();
                                                revoke_confirm.set(None);
                                                spawn(async move {
                                                    if let Ok(api) = authed_api(&base, api_token) {
                                                        match api.revoke_device(&dev_id).await {
                                                            Ok(_) => verify_status.set(format!("revoked {dev_id}")),
                                                            Err(e) => verify_status.set(format!("revoke {dev_id} failed: {e}")),
                                                        }
                                                    }
                                                });
                                            }
                                        },
                                        "Confirm Revoke"
                                    }
                                    button {
                                        class: "secondary",
                                        "data-testid": "cancel-revoke-button",
                                        onclick: move |_| revoke_confirm.set(None),
                                        "Cancel"
                                    }
                                }
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
                div { class: "event-head",
                    span { "Cross-Signing" }
                    span { class: "badge",
                        if cross_signing_plan().is_some() { "Plan ready" } else { "Not configured" }
                    }
                }
                div { class: "muted", "{cross_signing_state}" }
                div { class: "muted",
                    "Three-tier signing chain: principal_signing_key (DID control layer) · self_signing_key (this device) · user_signing_key (cross-principal trust)."
                    "Spec: crypto-media/device-lifecycle.md §5."
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "setup-cross-signing",
                        onclick: {
                            let device_id_clone = device_id.clone();
                            let mut plan_signal = cross_signing_plan;
                            let mut status = verify_status;
                            move |_| {
                                let plan = CrossSigningSetupPlan::build_initial(
                                    "did:webvh:current-principal",
                                    &device_id_clone,
                                );
                                let preview = plan
                                    .event_kinds()
                                    .iter()
                                    .map(|k| (*k).to_owned())
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                status.set(format!("Cross-signing plan generated · events: {preview}"));
                                plan_signal.set(Some(plan));
                            }
                        },
                        "Build setup plan"
                    }
                }
                if let Some(plan) = cross_signing_plan() {
                    div { class: "muted", "data-testid": "cross-signing-plan",
                        "Mode: {plan.mode:?} · generation: {plan.new_generation}"
                    }
                    ul { class: "list", "data-testid": "cross-signing-steps",
                        for (idx , step) in plan.steps.iter().enumerate() {
                            li { key: "{idx}",
                                div { strong { "{step.description()}" } }
                                if let Some(kind) = step.canonical_event_kind() {
                                    div { class: "muted", "event: {kind}" }
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
mod cross_signing_view_tests {
    use crate::cross_signing::{CrossSigningSetupMode, CrossSigningSetupPlan};

    #[test]
    fn initial_plan_lists_publish_and_device_authorized_events() {
        let plan = CrossSigningSetupPlan::build_initial(
            "did:webvh:alice.example",
            "cx:device:01a",
        );
        let kinds = plan.event_kinds();
        assert!(kinds.contains(&"cx.cross_signing.publish.v1"));
        assert!(kinds.contains(&"cx.device.authorized"));
        assert!(matches!(plan.mode, CrossSigningSetupMode::InitialSetup));
    }
}
