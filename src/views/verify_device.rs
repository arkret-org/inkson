use dioxus::prelude::*;
use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};

use crate::cross_signing::{CrossSigningExecutor, CrossSigningSetupPlan};
use crate::local_state::LocalStateStore;
use crate::models::*;
use crate::secure_key_store::default_secure_key_store;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::views::helpers::{short_protocol_id, with_authed_api};

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

/// Walk a `DeviceMessagesGetOutcome` JSON representation and
/// return the first non-empty `content.key` string carried by a
/// `ck.key.verification.key` typed envelope.
///
/// Per spec the receive endpoint returns `{ "messages": [...] }` where each
/// `DeviceMessageEnvelope` carries `kind` + `content`; the helper returns
/// `None` if no matching envelope is present so the poll loop can keep
/// retrying without surfacing noise.
fn extract_peer_verification_key(value: &serde_json::Value) -> Option<String> {
    fn key_from_entry(entry: &serde_json::Value) -> Option<String> {
        if entry.get("kind").and_then(|t| t.as_str()) != Some("ck.key.verification.key") {
            return None;
        }
        let content = entry.get("content").and_then(|v| v.as_object())?;
        let key = content.get("key").and_then(|v| v.as_str()).or_else(|| {
            content
                .get("device_envelope")
                .and_then(|v| v.get("local_public_key"))
                .and_then(|v| v.as_str())
        })?;
        if key.trim().is_empty() {
            return None;
        }
        Some(key.trim().to_owned())
    }
    if let Some(messages) = value.get("messages").and_then(|v| v.as_array()) {
        for entry in messages {
            if let Some(k) = key_from_entry(entry) {
                return Some(k);
            }
        }
    }
    None
}

#[cfg(test)]
mod verification_key_poll_tests {
    use serde_json::json;

    use super::extract_peer_verification_key;

    #[test]
    fn picks_key_out_of_flat_events_list() {
        let resp = json!({
            "messages": [
                {"kind": "ck.mls.welcome", "content": {"unrelated": true}},
                {
                    "kind": "ck.key.verification.key",
                    "content": {"key": "bob-pub-b64==", "from_device": "ck:device:abc"},
                },
            ]
        });
        assert_eq!(
            extract_peer_verification_key(&resp).as_deref(),
            Some("bob-pub-b64==")
        );
    }

    #[test]
    fn returns_none_when_no_verification_key_present() {
        let resp = json!({
            "messages": [
                {"kind": "ck.mls.welcome", "content": {"welcome_blob": "..."}},
            ]
        });
        assert!(extract_peer_verification_key(&resp).is_none());
    }

    #[test]
    fn ignores_envelope_with_blank_key() {
        let resp = json!({
            "messages": [
                {"kind": "ck.key.verification.key", "content": {"key": "   "}}
            ]
        });
        assert!(extract_peer_verification_key(&resp).is_none());
    }

    #[test]
    fn picks_key_out_of_signed_device_envelope() {
        let resp = json!({
            "messages": [
                {
                    "kind": "ck.key.verification.key",
                    "content": {
                        "device_envelope": {
                            "local_public_key": "signed-pub-b64=="
                        },
                        "signature": {"alg": "EdDSA", "jws": "a.b.c"}
                    }
                }
            ]
        });
        assert_eq!(
            extract_peer_verification_key(&resp).as_deref(),
            Some("signed-pub-b64==")
        );
    }
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
        let svg = render_qr_svg("cokret:verify:ck:device:abc:ck:device:xyz");
        // qrcode 0.14 emits an `<?xml …?>` declaration before `<svg`.
        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
    }
}

#[component]
pub fn VerifyDevicePanel(
    base_url: String,
    token: Signal<String>,
    device_id: String,
    account_did: String,
    selected_realm_id: String,
    state_store: Signal<LocalStateStore>,
) -> Element {
    // B2e wires `state_store` to persist the cross-signing publish content;
    // `selected_realm_id` is kept on the prop list so the route binding in
    // `app.rs` stays uniform with other panel signatures.
    let _ = (&selected_realm_id,);
    let mut verify_method = use_signal(|| VerifyMethod::QrCode);
    let mut target_device = use_signal(String::new);
    let mut verify_status = use_signal(String::new);
    let mut trust_devices = use_signal(Vec::<DeviceTrustEntry>::new);
    // Hydrate the latest persisted cross-signing publish (B2e) so the
    // panel reflects the device's cross-signed state across reloads.
    let persisted_publish_label = state_store
        .read()
        .load_private_data(&account_did, "cross_signing.publish.latest")
        .and_then(|json| serde_json::from_str::<cokret_sdk::CrossSigningPublishContent>(&json).ok())
        .map(|p| {
            format!(
                "Last cross-signing publish for {} (generation {})",
                p.principal_id.as_str(),
                p.generation,
            )
        })
        .unwrap_or_else(|| "Not configured".to_owned());
    let mut cross_signing_state = use_signal(move || persisted_publish_label);
    let mut cross_signing_plan = use_signal(|| Option::<CrossSigningSetupPlan>::None);
    let mut cross_signing_publish_id = use_signal(String::new);
    let mut sas_code = use_signal(String::new);
    let mut qr_data = use_signal(String::new);
    let mut revoke_confirm = use_signal(|| Option::<String>::None);
    let mut revoke_passphrase = use_signal(String::new);
    // SAS key-exchange state. The ephemeral keypair is generated
    // lazily on "Generate my key" click + held in an Arc so a
    // single getrandom call covers the lifetime of this SAS
    // session. Peer's public key is pasted (or auto-filled by the
    // device_message poll below) into `peer_public_b64`. When both
    // halves are present, the SAS display block recomputes the
    // emoji + decimal pair from the real X25519 shared secret
    // instead of the `target_device_did + sas_code` placeholder
    // info.
    let mut ephemeral_keypair = use_signal(|| {
        Option::<std::sync::Arc<cokret_sdk::key_verification::EphemeralX25519Keypair>>::None
    });
    let mut peer_public_b64 = use_signal(String::new);
    let mut sas_send_status = use_signal(String::new);

    {
        let state_store_for_inbox = state_store;
        use_effect(move || {
            if verify_method() != VerifyMethod::Sas
                || ephemeral_keypair().is_none()
                || !peer_public_b64().is_empty()
                || !verify_status().is_empty()
            {
                return;
            }
            let inbox = state_store_for_inbox.read().to_device_inbox();
            if inbox.is_empty() {
                return;
            }
            let messages_value = serde_json::json!({ "messages": inbox });
            if let Some(key) = extract_peer_verification_key(&messages_value) {
                peer_public_b64.set(key);
                sas_send_status
                    .set("peer X25519 public key auto-filled from account subscribe".to_owned());
            }
        });
    }

    // The main receive path is account.subscribe via the local to-device
    // dispatcher above. This foreground poll is a short recovery path for
    // cases where sync is not yet running or the dispatcher needs a catch-up.
    {
        let base = base_url.clone();
        let token_for_poll = token;
        let mut state_store_for_poll = state_store;
        use_future(move || {
            let base = base.clone();
            async move {
                let mut ticks: u32 = 0;
                loop {
                    ticks += 1;
                    if ticks > 120 {
                        break;
                    }
                    crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(3000)).await;
                    if verify_method() != VerifyMethod::Sas {
                        continue;
                    }
                    if ephemeral_keypair().is_none() {
                        continue;
                    }
                    if !peer_public_b64().is_empty() {
                        break;
                    }
                    if !verify_status().is_empty() {
                        break;
                    }
                    let inbox = state_store_for_poll.read().to_device_inbox();
                    if !inbox.is_empty() {
                        let messages_value = serde_json::json!({ "messages": inbox });
                        if let Some(key) = extract_peer_verification_key(&messages_value) {
                            peer_public_b64.set(key);
                            sas_send_status.set(
                                "peer X25519 public key auto-filled from account subscribe"
                                    .to_owned(),
                            );
                            break;
                        }
                    }
                    let api_token = token_for_poll();
                    if api_token.trim().is_empty() {
                        continue;
                    }
                    let messages = match crate::views::helpers::with_authed_api(
                        &base,
                        api_token.clone(),
                        |api| async move { api.receive_device_messages().await },
                    )
                    .await
                    {
                        Ok(resp) => resp,
                        Err(_) => continue,
                    };
                    let ack_token = messages.ack_token.clone();
                    let can_ack_batch = !messages.messages.is_empty()
                        && messages
                            .messages
                            .iter()
                            .all(|message| message.kind.starts_with("ck.key.verification."));
                    let messages_value = match serde_json::to_value(&messages) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if let Some(items) = messages_value
                        .get("messages")
                        .and_then(serde_json::Value::as_array)
                    {
                        state_store_for_poll
                            .write()
                            .ingest_to_device_messages(items);
                    }
                    if let Some(key) = extract_peer_verification_key(&messages_value) {
                        peer_public_b64.set(key);
                        sas_send_status.set(
                            "peer X25519 public key auto-filled from device_messages fallback"
                                .to_owned(),
                        );
                        if can_ack_batch && let Some(ack_token) = ack_token {
                            let _ = crate::views::helpers::with_authed_api(
                                &base,
                                api_token,
                                |api| async move { api.ack_device_messages(&ack_token).await },
                            )
                            .await;
                        }
                        break;
                    }
                }
            }
        });
    }

    rsx! {
        div { class: "timeline", "data-testid": "verify-device-panel",
            // Verification method selector
            div { class: "event", "data-testid": "verify-method",
                div { class: "event-head",
                    span { {crate::i18n::tr("verify_device.title")} }
                    span { {crate::i18n::tr("verify_device.choose_method")} }
                }
                div { class: "actions",
                    Button {
                        variant: if verify_method() == VerifyMethod::QrCode { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        "data-testid": "qr-verify-button",
                        onclick: move |_| verify_method.set(VerifyMethod::QrCode),
                        {crate::i18n::tr("verify_device.qr_code")}
                    }
                    Button {
                        variant: if verify_method() == VerifyMethod::Sas { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        "data-testid": "sas-verify-button",
                        onclick: move |_| verify_method.set(VerifyMethod::Sas),
                        {crate::i18n::tr("verify_device.sas_emoji")}
                    }
                }
            }

            // QR Code verification strand
            if verify_method() == VerifyMethod::QrCode {
                div { class: "event", "data-testid": "qr-verify-strand",
                    div { class: "event-head",
                        span { {crate::i18n::tr("verify_device.qr_section")} }
                        span { {crate::i18n::tr("verify_device.qr_section_hint")} }
                    }
                    div { class: "workflow-form",
                        Label { html_for: "qr-target-device-input", {crate::i18n::tr("verify_device.target_device_id")} }
                        Input {
                            id: "qr-target-device-input",
                            "data-testid": "qr-target-device",
                            value: "{target_device}",
                            placeholder: crate::i18n::tr("verify_device.target_device_placeholder"),
                            oninput: move |event: FormEvent| target_device.set(event.value()),
                        }
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "generate-qr-button",
                                onclick: {
                                    let device_id = device_id.clone();
                                    move |_| {
                                        qr_data.set(format!(
                                            "cokret:verify:{}:{}",
                                            device_id, target_device()
                                        ));
                                    }
                                },
                                {crate::i18n::tr("verify_device.generate_qr")}
                            }
                        }
                        if !qr_data().is_empty() {
                            div { class: "event", "data-testid": "qr-display",
                                div { class: "entity-title", "QR verification payload" }
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

            // SAS verification strand
            if verify_method() == VerifyMethod::Sas {
                div { class: "event", "data-testid": "sas-verify-strand",
                    div { class: "event-head",
                        span { {crate::i18n::tr("verify_device.sas_section")} }
                        span { {crate::i18n::tr("verify_device.sas_section_hint")} }
                    }
                    div { class: "workflow-form",
                        Label { html_for: "sas-target-device-input", {crate::i18n::tr("verify_device.target_device_id")} }
                        Input {
                            id: "sas-target-device-input",
                            "data-testid": "sas-target-device",
                            value: "{target_device}",
                            placeholder: crate::i18n::tr("verify_device.target_device_placeholder"),
                            oninput: move |event: FormEvent| target_device.set(event.value()),
                        }
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "start-sas-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor_for_sas_start = account_did.clone();
                                    let from_device_for_sas_start = device_id.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let target = target_device();
                                        let api_token = token();
                                        let actor = actor_for_sas_start.clone();
                                        let from_device = from_device_for_sas_start.clone();
                                        spawn(async move {
                                            let identity = match state_store.write().ensure_local_identity() {
                                                Ok(identity) => identity,
                                                Err(error) => {
                                                    verify_status.set(format!(
                                                        "SAS failed: secure device signing key unavailable: {error}"
                                                    ));
                                                    return;
                                                }
                                            };
                                            let proof = match crate::api::build_signed_device_verification_proof(
                                                &actor,
                                                &from_device,
                                                &target,
                                                "sas",
                                                None,
                                                None,
                                                None,
                                                &identity.signing_key,
                                            ) {
                                                Ok(proof) => proof,
                                                Err(error) => {
                                                    verify_status.set(format!("SAS failed: could not sign proof: {error}"));
                                                    return;
                                                }
                                            };
                                            match crate::views::helpers::with_authed_api(
                                                &base,
                                                api_token,
                                                |api| async move {
                                                    api.verify_device(&target, "sas", proof).await
                                                },
                                            )
                                            .await
                                            {
                                                Ok(resp) => {
                                                    sas_code.set(format!("verified: {}", resp.trust_state));
                                                    verify_status.set(format!("SAS started with {}", resp.device_id));
                                                }
                                                Err(err) => verify_status.set(format!("SAS failed: {}", err.display())),
                                            }
                                        });
                                    }
                                },
                                {crate::i18n::tr("verify_device.start_sas")}
                            }
                        }
                        // X25519 key exchange controls. Generate
                        // this side's ephemeral keypair, ship the
                        // public half via `/_cokret/self/device_messages`
                        // (type=`ck.key.verification.key`), and
                        // accept the peer's public key (either
                        // pasted manually or auto-filled by the
                        // device_message poll).
                        div { class: "event", "data-testid": "sas-x25519-exchange",
                            div { class: "event-head",
                                span { "Key exchange (X25519)" }
                                span { class: "badge",
                                    if ephemeral_keypair().is_some() { "keypair ready" }
                                    else { "not generated" }
                                }
                            }
                            div { class: "muted",
                                "Generate a fresh ephemeral X25519 keypair, send the public half to your other device, and paste its public key here. The SAS pair below recomputes from the real ECDH shared secret as soon as both halves are present."
                            }
                            div { class: "actions",
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "sas-generate-keypair-button",
                                    onclick: move |_| {
                                        match cokret_sdk::key_verification::EphemeralX25519Keypair::generate() {
                                            Ok(keypair) => {
                                                ephemeral_keypair.set(Some(std::sync::Arc::new(keypair)));
                                                sas_send_status.set(
                                                    "fresh X25519 keypair generated; click Send to push the public half to the peer".to_owned(),
                                                );
                                            }
                                            Err(error) => {
                                                sas_send_status.set(format!(
                                                    "could not generate ephemeral X25519 keypair: {error}"
                                                ));
                                            }
                                        }
                                    },
                                    "Generate my X25519 keypair"
                                }
                                Button {
                                    variant: ButtonVariant::Primary,
                                    "data-testid": "sas-send-public-button",
                                    disabled: ephemeral_keypair().is_none() || target_device().trim().is_empty(),
                                    onclick: {
                                        let base = base_url.clone();
                                        let account = account_did.clone();
                                        let from_device_for_send = device_id.clone();
                                        move |_| {
                                            let Some(pair) = ephemeral_keypair() else {
                                                sas_send_status.set("generate a keypair first".to_owned());
                                                return;
                                            };
                                            let target = target_device().trim().to_owned();
                                            if target.is_empty() {
                                                sas_send_status.set("target device id is required".to_owned());
                                                return;
                                            }
                                            let public_b64 = pair.public_base64();
                                            let base = base.clone();
                                            let account = account.clone();
                                            let from_device = from_device_for_send.clone();
                                            let api_token = token();
                                            spawn(async move {
                                                let identity = match state_store.write().ensure_local_identity() {
                                                    Ok(identity) => identity,
                                                    Err(error) => {
                                                        sas_send_status.set(format!(
                                                            "send failed: secure device signing key unavailable: {error}"
                                                        ));
                                                        return;
                                                    }
                                                };
                                                let signed_content = match crate::api::build_signed_device_verification_proof(
                                                    &account,
                                                    &from_device,
                                                    &target,
                                                    "sas_key",
                                                    None,
                                                    Some(&public_b64),
                                                    None,
                                                    &identity.signing_key,
                                                ) {
                                                    Ok(proof) => proof,
                                                    Err(error) => {
                                                        sas_send_status.set(format!("send failed: could not sign key envelope: {error}"));
                                                        return;
                                                    }
                                                };
                                                match crate::views::helpers::with_authed_api(
                                                    &base,
                                                    api_token,
                                                    |api| async move {
                                                        api.send_device_message_envelope(
                                                            "yougen-sas-key",
                                                            &account,
                                                            &target,
                                                            "ck.key.verification.key",
                                                            &crate::clock::rfc3339_secs_in(10),
                                                            signed_content,
                                                        )
                                                        .await
                                                    },
                                                )
                                                .await
                                                {
                                                    Ok(_) => sas_send_status.set(
                                                        "public key shipped via /device_messages; awaiting peer's key".to_owned(),
                                                    ),
                                                    Err(err) => sas_send_status.set(format!(
                                                        "send failed: {}", err.display()
                                                    )),
                                                }
                                            });
                                        }
                                    },
                                    "Send my public key to peer"
                                }
                            }
                            if let Some(pair) = ephemeral_keypair() {
                                {
                                    let pub_b64 = pair.public_base64();
                                    rsx! {
                                        div { class: "muted", "data-testid": "sas-local-public",
                                            "My X25519 public (base64): {pub_b64}"
                                        }
                                    }
                                }
                            }
                            Input {
                                "data-testid": "sas-peer-public-input",
                                value: "{peer_public_b64}",
                                placeholder: "Paste peer's X25519 public key (base64)",
                                oninput: move |event: FormEvent| peer_public_b64.set(event.value().trim().to_owned()),
                            }
                            if !sas_send_status().is_empty() {
                                div { class: "muted", "data-testid": "sas-send-status", "{sas_send_status}" }
                            }
                        }
                        if !sas_code().is_empty() {
                            {
                                // When this side's
                                // `EphemeralX25519Keypair` is
                                // generated AND the peer's public
                                // key has been pasted, compute the
                                // real X25519 shared secret and
                                // derive the SAS pair from it via
                                // the SDK helper. Two devices doing
                                // the same exchange produce
                                // identical emoji + digits - the
                                // contract verify-device relies on.
                                //
                                // Fallback: when peer key is not yet
                                // pasted (or ECDH fails on an invalid
                                // peer key), keep the demo
                                // `(target_device_did, sas_code)` info
                                // hash so the panel still renders
                                // something the user can see. That
                                // placeholder MUST NOT be confirmable:
                                // `sas_is_real` is false in both demo
                                // branches, which shows a warning
                                // callout and disables "They Match"
                                // until a real shared secret exists.
                                let target = target_device();
                                let info = format!("{target}|{}", sas_code());
                                let (sas, sas_source, sas_is_real) = match (
                                    ephemeral_keypair(),
                                    if peer_public_b64().is_empty() { None } else { Some(peer_public_b64()) },
                                ) {
                                    (Some(pair), Some(peer_pub)) => {
                                        match pair.compute_shared_secret(&peer_pub) {
                                            Ok(shared) => (
                                                cokret_sdk::key_verification::derive_sas_bytes(
                                                    shared.as_ref(),
                                                    info.as_bytes(),
                                                ),
                                                "real X25519 shared secret",
                                                true,
                                            ),
                                            Err(_) => (
                                                cokret_sdk::key_verification::derive_sas_bytes(
                                                    target.as_bytes(),
                                                    info.as_bytes(),
                                                ),
                                                "demo info (peer key invalid)",
                                                false,
                                            ),
                                        }
                                    }
                                    _ => (
                                        cokret_sdk::key_verification::derive_sas_bytes(
                                            target.as_bytes(),
                                            info.as_bytes(),
                                        ),
                                        "demo info (paste peer key for real ECDH)",
                                        false,
                                    ),
                                };
                                let emoji_pairs = sas.emoji_pairs();
                                let digits_text = format!(
                                    "{:04} {:04} — {:04}",
                                    sas.decimal_digits[0],
                                    sas.decimal_digits[1],
                                    sas.decimal_digits[2],
                                );
                                rsx! {
                            div { class: "event", "data-testid": "sas-display",
                                // Security gate: the placeholder SAS derived
                                // from public inputs must never be confirmed
                                // as a match — make that explicit up front.
                                if !sas_is_real {
                                    div { class: "callout warn", "data-testid": "sas-demo-warning",
                                        div { class: "body",
                                            {crate::i18n::tr("verify_device.sas_demo_warning")}
                                        }
                                    }
                                }
                                div { class: "entity-title", {crate::i18n::tr("verify_device.short_auth_string")} }
                                div { class: "muted", "Visually compare this emoji + digit sequence side-by-side on both devices." }
                                div { class: "muted", "data-testid": "sas-source", "Source: {sas_source}" }
                                // SAS emoji row — now computed via SDK HKDF.
                                div { class: "actions", "data-testid": "sas-emoji-row",
                                    for (codepoint, label) in emoji_pairs {
                                        span { class: "badge", "{codepoint} {label}" }
                                    }
                                }
                                div { class: "entity-title", "data-testid": "sas-digits", "{digits_text}" }
                                div { class: "muted", "{sas_code}" }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "sas-match-button",
                                        // Confirming a match is only meaningful when the
                                        // displayed SAS was derived from the real X25519
                                        // shared secret; the demo placeholder is derived
                                        // from public inputs and proves nothing.
                                        disabled: !sas_is_real,
                                        title: if sas_is_real {
                                            String::new()
                                        } else {
                                            crate::i18n::tr("verify_device.sas_match_disabled_hint")
                                        },
                                        onclick: {
                                            let base = base_url.clone();
                                            let actor = account_did.clone();
                                            let from_device = device_id.clone();
                                            let target = target_device();
                                            let local_public = ephemeral_keypair()
                                                .map(|pair| pair.public_base64())
                                                .unwrap_or_default();
                                            let peer_public = peer_public_b64();
                                            let sas_decimal = sas.decimal_digits;
                                            move |_| {
                                                if local_public.trim().is_empty() || peer_public.trim().is_empty() {
                                                    verify_status.set("SAS proof requires both signed X25519 public keys; generate/send your key and wait for the peer key first.".to_owned());
                                                    return;
                                                }
                                                let base = base.clone();
                                                let actor = actor.clone();
                                                let from_device = from_device.clone();
                                                let target = target.clone();
                                                let local_public = local_public.clone();
                                                let peer_public = peer_public.clone();
                                                let api_token = token();
                                                spawn(async move {
                                                    let identity = match state_store.write().ensure_local_identity() {
                                                        Ok(identity) => identity,
                                                        Err(error) => {
                                                            verify_status.set(format!(
                                                                "SAS failed: secure device signing key unavailable: {error}"
                                                            ));
                                                            return;
                                                        }
                                                    };
                                                    let proof = match crate::api::build_signed_device_verification_proof(
                                                        &actor,
                                                        &from_device,
                                                        &target,
                                                        "sas",
                                                        Some(sas_decimal),
                                                        Some(&local_public),
                                                        Some(&peer_public),
                                                        &identity.signing_key,
                                                    ) {
                                                        Ok(proof) => proof,
                                                        Err(error) => {
                                                            verify_status.set(format!("SAS failed: could not sign proof: {error}"));
                                                            return;
                                                        }
                                                    };
                                                    match crate::views::helpers::with_authed_api(
                                                        &base,
                                                        api_token,
                                                        |api| async move { api.verify_device(&target, "sas", proof).await },
                                                    )
                                                    .await
                                                    {
                                                        Ok(resp) => verify_status.set(format!(
                                                            "Verified {} with signed SAS proof ({})",
                                                            resp.device_id, resp.trust_state
                                                        )),
                                                        Err(err) => verify_status.set(format!("SAS proof rejected: {}", err.display())),
                                                    }
                                                });
                                            }
                                        },
                                        "They Match"
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
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
                            }  // close rsx!
                            }  // close outer let-block
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
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "refresh-trust-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let base = base.clone();
                                let api_token = token();
                                spawn(async move {
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move { api.get_device_trust().await },
                                    )
                                    .await
                                    {
                                        Ok(resp) => trust_devices.set(resp.devices),
                                        Err(err) => verify_status.set(format!("trust fetch failed: {}", err.display())),
                                    }
                                });
                            }
                        },
                        {crate::i18n::tr("verify_device.refresh_trust")}
                    }
                }
                for entry in trust_devices() {
                    {
                        let device_id_label = short_protocol_id(&entry.device_id);
                        rsx! {
                            div { class: "event", "data-testid": "trust-row",
                                div { class: "event-head",
                                    span { title: "{entry.device_id}", "{device_id_label}" }
                                    span { "{entry.trust_state}" }
                                }
                                if let Some(ref name) = entry.display_name {
                                    div { class: "muted", "{name}" }
                                }
                                if let Some(ref verified) = entry.verified_at {
                                    div { class: "muted", "Verified: {verified}" }
                                }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "verify-action-button",
                                        onclick: {
                                            let base = base_url.clone();
                                            let dev_id = entry.device_id.clone();
                                            let actor_for_verify = account_did.clone();
                                            let from_device_for_verify = device_id.clone();
                                            move |_| {
                                                let base = base.clone();
                                                let dev_id = dev_id.clone();
                                                let api_token = token();
                                                let actor = actor_for_verify.clone();
                                                let from_device = from_device_for_verify.clone();
                                                spawn(async move {
                                                    let identity = match state_store.write().ensure_local_identity() {
                                                        Ok(identity) => identity,
                                                        Err(error) => {
                                                            verify_status.set(format!(
                                                                "verify failed: secure device signing key unavailable: {error}"
                                                            ));
                                                            return;
                                                        }
                                                    };
                                                    let proof = match crate::api::build_signed_device_verification_proof(
                                                        &actor,
                                                        &from_device,
                                                        &dev_id,
                                                        "sas",
                                                        None,
                                                        None,
                                                        None,
                                                        &identity.signing_key,
                                                    ) {
                                                        Ok(proof) => proof,
                                                        Err(error) => {
                                                            verify_status.set(format!("verify failed: could not sign proof: {error}"));
                                                            return;
                                                        }
                                                    };
                                                    let _ = crate::views::helpers::with_authed_api(
                                                        &base,
                                                        api_token,
                                                        |api| async move {
                                                            api.verify_device(&dev_id, "sas", proof).await
                                                        },
                                                    )
                                                    .await;
                                                });
                                            }
                                        },
                                        {crate::i18n::tr("verify_device.verify_action")}
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "revoke-action-button",
                                        onclick: {
                                            let dev_id = entry.device_id.clone();
                                            move |_| revoke_confirm.set(Some(dev_id.clone()))
                                        },
                                        {crate::i18n::tr("verify_device.revoke_action")}
                                    }
                                }
                                if revoke_confirm() == Some(entry.device_id.clone()) {
                                    div { class: "event", "data-testid": "revoke-confirm",
                                        div { class: "entity-title", {crate::i18n::tr("verify_device.revoke_confirm_title")} }
                                        div { class: "muted",
                                            "Revoking removes the device from the authorized set, excludes it from future encrypted messages, and rotates the account MLS history secret. This cannot be undone."
                                        }
                                        Label { html_for: "verify-device-revoke-passphrase", "Recovery Key (24 words)" }
                                        Input {
                                            id: "verify-device-revoke-passphrase",
                                            "data-testid": "verify-device-revoke-passphrase-input",
                                            r#type: "password",
                                            value: "{revoke_passphrase}",
                                            autocomplete: "off",
                                            placeholder: "Your 24-word Recovery Key — required to rotate encrypted history backups",
                                            oninput: move |event: FormEvent| revoke_passphrase.set(event.value()),
                                        }
                                        div { class: "actions",
                                            Button {
                                                variant: ButtonVariant::Primary,
                                                "data-testid": "confirm-revoke-button",
                                                disabled: revoke_passphrase().trim().is_empty(),
                                                onclick: {
                                                    let base = base_url.clone();
                                                    let dev_id = entry.device_id.clone();
                                                    let actor = account_did.clone();
                                                    let current_device = device_id.clone();
                                                    move |_| {
                                                        let base = base.clone();
                                                        let dev_id = dev_id.clone();
                                                        let api_token = token();
                                                        // P1: pre-validate the Recovery Key BEFORE
                                                        // the irreversible revoke. The rotation
                                                        // re-wraps the new account secret under
                                                        // these bytes and the restore paths only
                                                        // accept the 24-word format, so reject
                                                        // anything else up front.
                                                        let Some(recovery_secret) =
                                                            crate::recovery_crypto::normalize_recovery_key_input(
                                                                &revoke_passphrase(),
                                                            )
                                                        else {
                                                            verify_status.set(
                                                                "Enter your 24-word Recovery Key before revoking — it is required to rotate the MLS history secret.".to_owned(),
                                                            );
                                                            return;
                                                        };
                                                        let passphrase_bytes = recovery_secret.into_bytes();
                                                        let snapshots = state_store.read().mls_snapshots();
                                                        let secure_store = default_secure_key_store("yougen");
                                                        let secure_store_for_rotation = secure_store.clone();
                                                        let actor_for_rotation = actor.clone();
                                                        let actor_for_commit = actor.clone();
                                                        let device_for_rotation = current_device.clone();
                                                        revoke_confirm.set(None);
                                                        spawn(async move {
                                                            let dev_id_for_err = dev_id.clone();
                                                            let actor_for_revoke = actor_for_rotation.clone();
                                                            let device_for_revoke = device_for_rotation.clone();
                                                            let revoke_result = crate::views::helpers::with_authed_api(
                                                                &base,
                                                                api_token.clone(),
                                                                |api| async move {
                                                                    api.revoke_device(
                                                                        &actor_for_revoke,
                                                                        &device_for_revoke,
                                                                        &dev_id,
                                                                    )
                                                                    .await
                                                                },
                                                            )
                                                            .await;
                                                            if let Err(err) = revoke_result {
                                                                verify_status.set(format!(
                                                                    "revoke {dev_id_for_err} failed: {}",
                                                                    err.display()
                                                                ));
                                                                return;
                                                            }
                                                            let rotation_result =
                                                                crate::views::helpers::with_authed_api(
                                                                    &base,
                                                                    api_token,
                                                                    move |api| async move {
                                                                        crate::mls::account_recovery::upload_mls_account_secret_rotation_after_device_revoke(
                                                                            &api,
                                                                            secure_store_for_rotation.as_ref(),
                                                                            &actor_for_rotation,
                                                                            &device_for_rotation,
                                                                            &passphrase_bytes,
                                                                            &snapshots,
                                                                        )
                                                                        .await
                                                                    },
                                                                )
                                                                .await;
                                                            match rotation_result {
                                                                Ok(rotation) => {
                                                                    let mut local_state = state_store.write();
                                                                    if let Err(err) = crate::mls::runtime::commit_account_mls_secret_rotation(
                                                                        &mut local_state,
                                                                        secure_store.as_ref(),
                                                                        &actor_for_commit,
                                                                        &rotation.rotation,
                                                                    ) {
                                                                        verify_status.set(format!(
                                                                            "revoked {dev_id_for_err}; MLS secret rotation uploaded but local commit failed: {err}"
                                                                        ));
                                                                        return;
                                                                    }
                                                                    revoke_passphrase.set(String::new());
                                                                    verify_status.set(format!(
                                                                        "revoked {dev_id_for_err}; rotated MLS history secret to v{}",
                                                                        rotation.rotation.new_version
                                                                    ));
                                                                }
                                                                Err(err) => verify_status.set(format!(
                                                                    "revoked {dev_id_for_err}; MLS secret rotation failed: {}",
                                                                    err.display()
                                                                )),
                                                            }
                                                        });
                                                    }
                                                },
                                                {crate::i18n::tr("verify_device.revoke_confirm_button")}
                                            }
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                "data-testid": "cancel-revoke-button",
                                                onclick: move |_| revoke_confirm.set(None),
                                                {crate::i18n::tr("common.cancel_button")}
                                            }
                                        }
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
                    Button {
                        variant: ButtonVariant::Primary,
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
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "run-cross-signing-setup",
                            disabled: account_did.trim().is_empty(),
                            onclick: {
                                let base = base_url.clone();
                                let actor = account_did.clone();
                                let plan = plan.clone();
                                move |_| {
                                    let base = base.clone();
                                    let actor = actor.clone();
                                    let plan = plan.clone();
                                    let api_token = token();
                                    // Construct the principal DID from the
                                    // current account DID — the plan was
                                    // built with a placeholder ("did:webvh:
                                    // current-principal") because the
                                    // build_initial caller had no actor
                                    // context; the executor uses this
                                    // canonical DID instead.
                                    let principal = match cokret_sdk::Did::new(actor.clone()) {
                                        Ok(d) => d,
                                        Err(err) => {
                                            cross_signing_state.set(format!(
                                                "Invalid actor DID: {err:?}"
                                            ));
                                            return;
                                        }
                                    };
                                    spawn(async move {
                                        // 1. Run the executor: generate
                                        //    PSK/SSK/USK + sign bindings +
                                        //    validate the publish content.
                                        //
                                        // Round 4 — `ck.cross_signing.publish`
                                        // requires `trust_domain` in the
                                        // canonical bind input. We thread the
                                        // active deployment's trust domain from
                                        // the local-state cache populated by
                                        // /server/describe. Until the cache is
                                        // populated we fall back to the public
                                        // sentinel so the local executor stays
                                        // testable without a live connect; the
                                        // submit path will be rejected by the
                                        // server if the value disagrees with
                                        // the deployment.
                                        // TODO(round4-cross-signing-trust-domain):
                                        // surface a clear "connect required"
                                        // error before the run begins instead
                                        // of relying on server-side rejection.
                                        let trust_domain = match state_store
                                            .read()
                                            .load()
                                            .server_trust_domain
                                            .clone()
                                            .and_then(|s| cokret_sdk::TypedTrustDomainId::new(s).ok())
                                        {
                                            Some(trust_domain) => trust_domain,
                                            None => match cokret_sdk::TypedTrustDomainId::new(
                                                "ck:trust_domain:unknown.local",
                                            ) {
                                                Ok(trust_domain) => trust_domain,
                                                Err(error) => {
                                                    cross_signing_state.set(format!(
                                                        "Invalid fallback trust domain: {error}"
                                                    ));
                                                    return;
                                                }
                                            },
                                        };
                                        let executor = CrossSigningExecutor::new(
                                            plan,
                                            principal.clone(),
                                            trust_domain,
                                        );
                                        let output = match executor.run() {
                                            Ok(out) => out,
                                            Err(err) => {
                                                cross_signing_state.set(format!(
                                                    "Setup failed during key generation: {err}"
                                                ));
                                                return;
                                            }
                                        };
                                        // 2. Persist the private keys to
                                        //    the OS keychain (or the in-
                                        //    memory fallback on wasm).
                                        let store = default_secure_key_store("yougen");
                                        if let Err(err) = output
                                            .persist_private_keys(
                                                store.as_ref(),
                                                principal.as_str(),
                                            )
                                        {
                                            cross_signing_state.set(format!(
                                                "Setup failed to persist keys: {err}"
                                            ));
                                            return;
                                        }
                                        // 3. Submit the publish event. Per
                                        //    spec key-management.md §4.1 +
                                        //    device-lifecycle.md §5.1,
                                        //    cross-signing publish + device
                                        //    authorization events MUST live
                                        //    in the principal control
                                        //    Realm. The SDK exposes the
                                        //    canonical derivation; we route
                                        //    through it so the server-side
                                        //    pinning check accepts the write.
                                        let control_realm =
                                            cokret_sdk::auth::principal_control_realm_id(
                                                &principal,
                                            );
                                        let envelope = match output
                                            .build_publish_envelope(&control_realm, &actor)
                                        {
                                            Ok(env) => env,
                                            Err(err) => {
                                                cross_signing_state.set(format!(
                                                    "Setup failed to build publish envelope: {err}"
                                                ));
                                                return;
                                            }
                                        };
                                        match with_authed_api(
                                            &base,
                                            api_token,
                                            |api| async move {
                                                api.submit_sdk_event(&envelope).await
                                            },
                                        )
                                        .await
                                        {
                                            Ok(resp) => {
                                                cross_signing_publish_id
                                                    .set(resp.event_id.clone());
                                                cross_signing_state.set(format!(
                                                    "Cross-signing publish accepted as {} (generation {})",
                                                    resp.event_id,
                                                    output.publish_content.generation,
                                                ));
                                                // B2e: persist the publish content into
                                                // LocalStateStore.private_data (XOR-
                                                // encrypted with the account DID) so a
                                                // subsequent mount, refresh, or device-
                                                // trust panel can re-read the cross-
                                                // signed state without rerunning the
                                                // executor. Failures here are non-
                                                // fatal — the server accepted the
                                                // publish, and the in-memory output
                                                // is still valid for this session.
                                                if let Ok(serialized) =
                                                    serde_json::to_string(&output.publish_content)
                                                {
                                                    state_store.write().save_private_data(
                                                        &actor,
                                                        "cross_signing.publish.latest",
                                                        serialized,
                                                    );
                                                }
                                                // Plan consumed — clear so
                                                // the UI does not invite a
                                                // duplicate submit.
                                                cross_signing_plan.set(None);
                                            }
                                            Err(err) => cross_signing_state.set(format!(
                                                "Setup submitted but server rejected publish: {}",
                                                err.display()
                                            )),
                                        }
                                    });
                                }
                            },
                            "Run setup"
                        }
                    }
                }
                if !cross_signing_publish_id().is_empty() {
                    {
                        let publish_id = cross_signing_publish_id();
                        let publish_id_label = short_protocol_id(&publish_id);
                        rsx! {
                            div { class: "muted", "data-testid": "cross-signing-publish-id",
                                title: "{publish_id}",
                                "Last publish event id: {publish_id_label}"
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
        let plan = CrossSigningSetupPlan::build_initial("did:webvh:alice.example", "ck:device:01a");
        let kinds = plan.event_kinds();
        assert!(kinds.contains(&"ck.cross_signing.publish"));
        assert!(kinds.contains(&"ck.device.authorize"));
        assert!(matches!(plan.mode, CrossSigningSetupMode::InitialSetup));
    }
}
