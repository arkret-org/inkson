use dioxus::prelude::*;
use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};

use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;

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
/// `ak.key.verification.key` typed envelope.
///
/// Per spec the receive endpoint returns `{ "messages": [...] }` where each
/// `DeviceMessageEnvelope` carries `kind` + `content`; the helper returns
/// `None` if no matching envelope is present so the poll loop can keep
/// retrying without surfacing noise.
fn extract_peer_verification_key(value: &serde_json::Value) -> Option<String> {
    fn key_from_entry(entry: &serde_json::Value) -> Option<String> {
        let envelope: arkret_sdk::DeviceMessageEnvelope =
            serde_json::from_value(entry.clone()).ok()?;
        if envelope.kind.as_str() != "ak.key.verification.key" {
            return None;
        }
        let arkret_sdk::DeviceMessageContent::KeyVerification(content) = envelope.content else {
            return None;
        };
        content
            .key
            .filter(|key| !key.as_str().trim().is_empty())
            .map(|key| key.as_str().to_owned())
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
    use serde_json::{Value, json};

    use super::extract_peer_verification_key;

    fn envelope(kind: &str, content: Value) -> Value {
        json!({
            "device_message_id": "ak:device_message:0196419b-0000-7000-8000-000000000003",
            "kind": kind,
            "sender_account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture:alice.example",
                "station_id": "ak:did_core:webvh:z6mkfixture:station.example"
            },
            "sender_device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
            "recipient_account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture:bob.example",
                "station_id": "ak:did_core:webvh:z6mkfixture:station.example"
            },
            "recipient_device_id": "ak:device:0196419b-0000-7000-8000-000000000002",
            "sent_at": "2026-07-15T00:00:00.000Z",
            "expires_at": "2026-07-15T00:10:00.000Z",
            "content": content
        })
    }

    fn key_content(key: &str) -> Value {
        json!({
            "transaction_id": "txn-key-poll",
            "from_device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
            "key": key
        })
    }

    #[test]
    fn picks_key_out_of_flat_events_list() {
        let resp = json!({
            "messages": [
                envelope("ak.mls.welcome", json!({"unrelated": true})),
                envelope(
                    "ak.key.verification.key",
                    key_content("bob-pub-b64=="),
                ),
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
                envelope("ak.mls.welcome", json!({"welcome_blob": "..."})),
            ]
        });
        assert!(extract_peer_verification_key(&resp).is_none());
    }

    #[test]
    fn ignores_envelope_with_blank_key() {
        let resp = json!({
            "messages": [
                envelope("ak.key.verification.key", key_content("   "))
            ]
        });
        assert!(extract_peer_verification_key(&resp).is_none());
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
        let svg = render_qr_svg("arkret:verify:ak:device:abc:ak:device:xyz");
        // qrcode 0.14 emits an `<?xml …?>` declaration before `<svg`.
        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
    }
}

#[component]
pub fn VerifyDevicePanel(
    token: Signal<String>,
    device_id: String,
    principal_id: String,
    selected_realm_id: String,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    // `selected_realm_id` is kept on the prop list so the route binding in
    // `app.rs` stays uniform with other panel signatures.
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state_store = crate::app::SessionContext::get().state_store;
    let _ = (&selected_realm_id,);
    let mut verify_method = use_signal(|| VerifyMethod::QrCode);
    let mut target_device = use_signal(String::new);
    let mut verify_status = use_signal(String::new);
    let mut sas_code = use_signal(String::new);
    let mut qr_data = use_signal(String::new);
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
        Option::<std::sync::Arc<arkret_crypto::key_verification::EphemeralX25519Keypair>>::None
    });
    let mut peer_public_b64 = use_signal(String::new);
    let mut sas_send_status = use_signal(String::new);

    // `tr()` reads the i18n signal out of Dioxus context, which is not
    // available inside spawned tasks / futures — the same constraint that
    // makes `setup::realms::BootstrapProgressStrings` pre-resolve
    // templates. Status strings set from async code below are resolved
    // here and cloned across the boundary; `{placeholder}`s go through
    // `crate::i18n::substitute_args`.
    let peer_key_autofilled = crate::i18n::tr("verify_device.peer_key_autofilled");
    let public_key_sent = crate::i18n::tr("verify_device.public_key_sent");
    let send_failed_signing_tpl = crate::i18n::tr("verify_device.send_failed_signing");
    let send_failed_sign_tpl = crate::i18n::tr("verify_device.send_failed_sign");
    let send_failed_tpl = crate::i18n::tr("verify_device.send_failed");
    let match_failed_signing_tpl = crate::i18n::tr("verify_device.match_failed_signing");
    let match_failed_sign_tpl = crate::i18n::tr("verify_device.match_failed_sign");
    let matched_tpl = crate::i18n::tr("verify_device.matched");

    {
        let state_store_for_inbox = state_store;
        let peer_key_autofilled = peer_key_autofilled.clone();
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
                sas_send_status.set(peer_key_autofilled.clone());
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
        let peer_key_autofilled = peer_key_autofilled.clone();
        use_future(move || {
            let base = base.clone();
            let peer_key_autofilled = peer_key_autofilled.clone();
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
                            sas_send_status.set(peer_key_autofilled.clone());
                            break;
                        }
                    }
                    let api_token = token_for_poll();
                    if api_token.trim().is_empty() {
                        continue;
                    }
                    let messages = match crate::transport::auth::with_endpoint_clients(
                        &base,
                        api_token.clone(),
                        None,
                        |clients| async move { clients.keys().receive_device_messages().await },
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
                            .all(|message| message.kind.starts_with("ak.key.verification."));
                    let messages_value = match serde_json::to_value(&messages) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    state_store_for_poll
                        .write()
                        .ingest_to_device_messages(&messages.messages);
                    if let Some(key) = extract_peer_verification_key(&messages_value) {
                        peer_public_b64.set(key);
                        sas_send_status.set(peer_key_autofilled.clone());
                        if can_ack_batch && let Some(ack_token) = ack_token {
                            let _ = crate::transport::auth::with_endpoint_clients(
                                &base,
                                api_token,
                                None,
                                |clients| async move {
                                    clients.keys().ack_device_messages(&ack_token).await
                                },
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

            // QR Code verification flow
            if verify_method() == VerifyMethod::QrCode {
                div { class: "event", "data-testid": "qr-verify-flow",
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
                                            "arkret:verify:{}:{}",
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

            // SAS verification flow
            if verify_method() == VerifyMethod::Sas {
                div { class: "event", "data-testid": "sas-verify-flow",
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
                                    move |_| {
                                        let target = target_device();
                                        if target.trim().is_empty() {
                                            verify_status.set(crate::i18n::tr("verify_device.target_required"));
                                            return;
                                        }
                                        sas_code.set(format!("sas-session:{target}"));
                                        verify_status.set(crate::i18n::tr("verify_device.session_started"));
                                    }
                                },
                                {crate::i18n::tr("verify_device.start_sas")}
                            }
                        }
                        // X25519 key exchange controls. Generate
                        // this side's ephemeral keypair, ship the
                        // public half via `/_arkret/self/device_messages`
                        // (type=`ak.key.verification.key`), and
                        // accept the peer's public key (either
                        // pasted manually or auto-filled by the
                        // device_message poll).
                        div { class: "event", "data-testid": "sas-x25519-exchange",
                            div { class: "event-head",
                                span { {crate::i18n::tr("verify_device.key_exchange_title")} }
                                span { class: "badge",
                                    if ephemeral_keypair().is_some() {
                                        {crate::i18n::tr("verify_device.keypair_ready")}
                                    } else {
                                        {crate::i18n::tr("verify_device.keypair_missing")}
                                    }
                                }
                            }
                            div { class: "muted",
                                {crate::i18n::tr("verify_device.key_exchange_hint")}
                            }
                            div { class: "actions",
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "sas-generate-keypair-button",
                                    onclick: move |_| {
                                        match arkret_crypto::key_verification::EphemeralX25519Keypair::generate() {
                                            Ok(keypair) => {
                                                ephemeral_keypair.set(Some(std::sync::Arc::new(keypair)));
                                                sas_send_status.set(crate::i18n::tr(
                                                    "verify_device.keypair_generated",
                                                ));
                                            }
                                            Err(error) => {
                                                sas_send_status.set(crate::i18n::tr_args(
                                                    "verify_device.keypair_generate_failed",
                                                    &[("error", error.to_string())],
                                                ));
                                            }
                                        }
                                    },
                                    {crate::i18n::tr("verify_device.generate_keypair")}
                                }
                                Button {
                                    variant: ButtonVariant::Primary,
                                    "data-testid": "sas-send-public-button",
                                    disabled: ephemeral_keypair().is_none() || target_device().trim().is_empty(),
                                    onclick: {
                                        let base = base_url.clone();
                                        let account = principal_id.clone();
                                        let from_device_for_send = device_id.clone();
                                        let send_failed_signing_tpl = send_failed_signing_tpl.clone();
                                        let send_failed_sign_tpl = send_failed_sign_tpl.clone();
                                        let send_failed_tpl = send_failed_tpl.clone();
                                        let public_key_sent = public_key_sent.clone();
                                        move |_| {
                                            let Some(pair) = ephemeral_keypair() else {
                                                sas_send_status.set(crate::i18n::tr("verify_device.generate_first"));
                                                return;
                                            };
                                            let target = target_device().trim().to_owned();
                                            if target.is_empty() {
                                                sas_send_status.set(crate::i18n::tr("verify_device.target_required"));
                                                return;
                                            }
                                            let public_b64 = pair.public_base64();
                                            let base = base.clone();
                                            let principal_id = account.clone();
                                            let from_device = from_device_for_send.clone();
                                            let api_token = token();
                                            // `tr()` context is unavailable inside the
                                            // spawned task; move the pre-resolved
                                            // templates across the boundary.
                                            let send_failed_signing = send_failed_signing_tpl.clone();
                                            let send_failed_sign = send_failed_sign_tpl.clone();
                                            let send_failed = send_failed_tpl.clone();
                                            let public_key_sent = public_key_sent.clone();
                                            spawn(async move {
                                                let identity = match state_store.write().ensure_local_identity() {
                                                    Ok(identity) => identity,
                                                    Err(error) => {
                                                        sas_send_status.set(crate::i18n::substitute_args(
                                                            send_failed_signing,
                                                            &[("error", error.to_string())],
                                                        ));
                                                        return;
                                                    }
                                                };
                                                let proof = match crate::event_builders::build_signed_device_verification_proof(
                                                    &principal_id,
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
                                                        sas_send_status.set(crate::i18n::substitute_args(
                                                            send_failed_sign,
                                                            &[("error", error.to_string())],
                                                        ));
                                                        return;
                                                    }
                                                };
                                                // device-message.schema.json requires transaction_id +
                                                // from_device on every ak.key.verification.* content and
                                                // `key` on this kind; the signed proof rides in the open
                                                // part of the same object.
                                                let signed_content = match crate::event_builders::build_sas_key_verification_content(
                                                    &crate::operation::uuid_v7(),
                                                    &public_b64,
                                                    proof,
                                                ) {
                                                    Ok(content) => content,
                                                    Err(error) => {
                                                        sas_send_status.set(crate::i18n::substitute_args(
                                                            send_failed.clone(),
                                                            &[("error", error.to_string())],
                                                        ));
                                                        return;
                                                    }
                                                };
                                                match crate::transport::auth::with_authed_sdk_client(
                                                    &base,
                                                    api_token,
                                                    |http| async move {
                                                        crate::transport::keys::send_device_message::<
                                                            arkret_sdk::device_message_spec::KeyVerificationKey,
                                                        >(
                                                            &http,
                                                            "inkson-sas-key",
                                                            &crate::mls_api_helpers::local_account_actor_id(&principal_id)?,
                                                            &target,
                                                            &crate::clock::timestamp_in(10),
                                                            signed_content,
                                                        )
                                                        .await
                                                    },
                                                )
                                                .await
                                                {
                                                    Ok(_) => sas_send_status.set(public_key_sent),
                                                    Err(err) => sas_send_status.set(crate::i18n::substitute_args(
                                                        send_failed,
                                                        &[("error", err.display().to_string())],
                                                    )),
                                                }
                                            });
                                        }
                                    },
                                    {crate::i18n::tr("verify_device.send_public_key")}
                                }
                            }
                            if let Some(pair) = ephemeral_keypair() {
                                {
                                    let pub_b64 = pair.public_base64();
                                    rsx! {
                                        div { class: "muted", "data-testid": "sas-local-public",
                                            {crate::i18n::tr_args("verify_device.my_public_key", &[("key", pub_b64.clone())])}
                                        }
                                    }
                                }
                            }
                            Input {
                                "data-testid": "sas-peer-public-input",
                                value: "{peer_public_b64}",
                                placeholder: crate::i18n::tr("verify_device.peer_key_placeholder"),
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
                                let target = target_device();
                                let info = format!("{target}|{}", sas_code());
                                let (secure_sas, unavailable_message) = match (
                                    ephemeral_keypair(),
                                    if peer_public_b64().is_empty() { None } else { Some(peer_public_b64()) },
                                ) {
                                    (Some(pair), Some(peer_pub)) => {
                                        match pair.compute_shared_secret(&peer_pub) {
                                            Ok(shared) => (
                                                Some((
                                                    arkret_crypto::key_verification::derive_sas_bytes(
                                                        shared.as_ref(),
                                                        info.as_bytes(),
                                                    ),
                                                    crate::i18n::tr("verify_device.source_secure"),
                                                )),
                                                String::new(),
                                            ),
                                            Err(_) => (
                                                None,
                                                crate::i18n::tr(
                                                    "verify_device.source_demo_invalid",
                                                ),
                                            ),
                                        }
                                    }
                                    _ => (
                                        None,
                                        crate::i18n::tr("verify_device.source_demo_waiting"),
                                    ),
                                };
                                if let Some((sas, sas_source)) = secure_sas {
                                    let emoji_pairs = sas.emoji_pairs();
                                    let digits_text = format!(
                                        "{:04} {:04} — {:04}",
                                        sas.decimal_digits[0],
                                        sas.decimal_digits[1],
                                        sas.decimal_digits[2],
                                    );
                                    rsx! {
                            div { class: "event", "data-testid": "sas-display",
                                div { class: "entity-title", {crate::i18n::tr("verify_device.short_auth_string")} }
                                div { class: "muted", {crate::i18n::tr("verify_device.compare_hint")} }
                                div { class: "muted", "data-testid": "sas-source", "{sas_source}" }
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
                                        onclick: {
                                            let actor = principal_id.clone();
                                            let from_device = device_id.clone();
                                            let target = target_device();
                                            let local_public = ephemeral_keypair()
                                                .map(|pair| pair.public_base64())
                                                .unwrap_or_default();
                                            let peer_public = peer_public_b64();
                                            let sas_decimal = sas.decimal_digits;
                                            let match_failed_signing_tpl = match_failed_signing_tpl.clone();
                                            let match_failed_sign_tpl = match_failed_sign_tpl.clone();
                                            let matched_tpl = matched_tpl.clone();
                                            move |_| {
                                                if local_public.trim().is_empty() || peer_public.trim().is_empty() {
                                                    verify_status.set(crate::i18n::tr("verify_device.match_requires_keys"));
                                                    return;
                                                }
                                                let actor = actor.clone();
                                                let from_device = from_device.clone();
                                                let target = target.clone();
                                                let local_public = local_public.clone();
                                                let peer_public = peer_public.clone();
                                                // `tr()` context is unavailable inside the
                                                // spawned task; move the pre-resolved
                                                // templates across the boundary.
                                                let match_failed_signing = match_failed_signing_tpl.clone();
                                                let match_failed_sign = match_failed_sign_tpl.clone();
                                                let matched = matched_tpl.clone();
                                                spawn(async move {
                                                    let identity = match state_store.write().ensure_local_identity() {
                                                        Ok(identity) => identity,
                                                        Err(error) => {
                                                            verify_status.set(crate::i18n::substitute_args(
                                                                match_failed_signing,
                                                                &[("error", error.to_string())],
                                                            ));
                                                            return;
                                                        }
                                                    };
                                                    let proof = match crate::event_builders::build_signed_device_verification_proof(
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
                                                            verify_status.set(crate::i18n::substitute_args(
                                                                match_failed_sign,
                                                                &[("error", error.to_string())],
                                                            ));
                                                            return;
                                                        }
                                                    };
                                                    let _ = proof;
                                                    verify_status.set(crate::i18n::substitute_args(
                                                        matched,
                                                        &[("target", target)],
                                                    ));
                                                });
                                            }
                                        },
                                        {crate::i18n::tr("verify_device.they_match")}
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "sas-mismatch-button",
                                        onclick: move |_| verify_status.set(crate::i18n::tr("verify_device.mismatch_aborted")),
                                        {crate::i18n::tr("verify_device.they_dont_match")}
                                    }
                                }
                                // Post-verification events panel
                                // crypto-media/device-lifecycle.md §1.2 + §7-§9 (verification)
                                div { class: "event", "data-testid": "sas-post-verification",
                                    div { class: "event-head",
                                        span { {crate::i18n::tr("verify_device.after_confirm_title")} }
                                        span { class: "muted", "device-lifecycle §1.2, §7-§9" }
                                    }
                                    div { class: "muted",
                                        {crate::i18n::tr("verify_device.after_confirm_body")}
                                    }
                                    div { class: "metric-grid",
                                        div { class: "metric",
                                            strong { "①" }
                                            span { {crate::i18n::tr("verify_device.step_authorize")} }
                                            div { class: "muted", {crate::i18n::tr("verify_device.step_authorize_hint")} }
                                        }
                                        div { class: "metric",
                                            strong { "②" }
                                            span { {crate::i18n::tr("verify_device.step_record")} }
                                            div { class: "muted", {crate::i18n::tr("verify_device.step_record_hint")} }
                                        }
                                        div { class: "metric",
                                            strong { "③" }
                                            span { {crate::i18n::tr("verify_device.step_rejoin")} }
                                            div { class: "muted", {crate::i18n::tr("verify_device.step_rejoin_hint")} }
                                        }
                                        div { class: "metric",
                                            strong { "④" }
                                            span { {crate::i18n::tr("verify_device.step_sync")} }
                                            div { class: "muted", {crate::i18n::tr("verify_device.step_sync_hint")} }
                                        }
                                    }
                                    div { class: "muted",
                                        {crate::i18n::tr("verify_device.after_confirm_note")}
                                    }
                                }
                            }
                                    }  // close secure SAS rsx!
                                } else {
                                    rsx! {
                                        div { class: "callout warn", "data-testid": "sas-unavailable",
                                            div { class: "body", "{unavailable_message}" }
                                        }
                                    }
                                }
                            }  // close outer let-block
                        }
                    }
                }
            }

            if !verify_status().is_empty() {
                div { class: "muted", "data-testid": "verify-status", "{verify_status}" }
            }
        }
    }
}
