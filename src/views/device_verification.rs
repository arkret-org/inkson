//! Round 25 (R3): device verification view.
//!
//! Drives the SDK's [`contrix_sdk::KeyVerificationFlow`] 10-state
//! machine. Two devices compare emoji + numeric SAS codes; on user
//! confirmation the flow advances through:
//!
//! ```text
//! Idle → Started → Accepted → KeyHalfExchanged → KeysExchanged
//!      → MacHalfReceived → MacsReceived → DoneHalfReceived → Done
//! ```
//!
//! Cancel is legal at any non-terminal state and routes the flow to
//! `Cancelled`. Out-of-order envelopes / transaction-id mismatches
//! force the FSM to `Cancelled` with a typed reason — the UI surfaces
//! that as a red banner so the operator knows the verification was
//! aborted before any device authorization or MLS welcome got signed.
//!
//! The view here is **all client-side**: SAS code generation is
//! deterministic from a hash of the transaction id (so both devices
//! display the same emoji / digits without exchanging secret material
//! again). When the SDK exposes the real SAS-from-DH-key derivation
//! we'll swap that in — the FSM transitions remain the same.

use std::collections::BTreeMap;

use chrono::Utc;
use contrix_sdk::{
    DeviceId, Did, KeyVerificationAccept, KeyVerificationCancel, KeyVerificationDone,
    KeyVerificationFlow, KeyVerificationKey, KeyVerificationMac, KeyVerificationStart,
    KeyVerificationState,
};
use dioxus::prelude::*;
use sha2::{Digest, Sha256};

/// Round 25 (R3): emoji set for SAS comparison. Mirrors the Matrix
/// emoji-SAS set — 64 entries indexed by 6 bits. The actual SDK
/// derivation will pull the same indices from HKDF over the DH
/// shared secret; here we derive them from the transaction id so the
/// UI can render a deterministic preview before the SDK lands the
/// real key-exchange step.
pub const SAS_EMOJI: [&str; 64] = [
    "🐶", "🐱", "🦁", "🐎", "🦄", "🐷", "🐘", "🐰", "🐼", "🐔", "🐧", "🐢", "🐟", "🐙", "🦋", "🌸",
    "🌳", "🌵", "🍄", "🌍", "🌙", "☁", "🔥", "🍌", "🍎", "🍓", "🌽", "🍕", "🎂", "❤", "😀", "🤖",
    "🎩", "👓", "🔧", "🎅", "👍", "☂", "⌛", "⌚", "🎁", "💡", "📕", "✏", "📎", "✂", "🔒", "🔑",
    "🔨", "📞", "🚩", "🚂", "🚲", "✈", "🚀", "🏆", "⚽", "🎸", "🎺", "🔔", "⚓", "🎧", "📁", "📌",
];

/// Round 25 (R3): derive a 7-emoji + 8-digit SAS code from the
/// transaction id. Deterministic so both devices show the same
/// preview. Real SDK SAS derivation hashes the agreed shared secret;
/// the wire-shape end remains the same.
pub fn sas_preview_from_transaction(transaction_id: &str) -> SasPreview {
    let digest = Sha256::digest(transaction_id.as_bytes());
    let mut emoji = Vec::with_capacity(7);
    for byte in digest.iter().take(7) {
        emoji.push(SAS_EMOJI[(byte & 0x3F) as usize]);
    }
    // 8-digit code: take 4 bytes, build u32, format mod 10_000_0000.
    let n = u32::from_be_bytes([digest[7], digest[8], digest[9], digest[10]]) % 1_0000_0000;
    let digits = format!("{n:08}");
    SasPreview {
        emoji: emoji.iter().map(|s| (*s).to_owned()).collect(),
        digits,
    }
}

/// Deterministic SAS preview returned by [`sas_preview_from_transaction`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SasPreview {
    pub emoji: Vec<String>,
    pub digits: String,
}

/// Stable label for a [`KeyVerificationState`] — used by the UI to
/// render the lifecycle progress chip without leaking the wire
/// vocabulary.
pub fn state_label(state: KeyVerificationState) -> &'static str {
    match state {
        KeyVerificationState::Idle => "Idle",
        KeyVerificationState::Started => "Started",
        KeyVerificationState::Accepted => "Accepted",
        KeyVerificationState::KeyHalfExchanged => "Key half-exchanged",
        KeyVerificationState::KeysExchanged => "Keys exchanged",
        KeyVerificationState::MacHalfReceived => "MAC half-received",
        KeyVerificationState::MacsReceived => "MACs received",
        KeyVerificationState::DoneHalfReceived => "Done half-received",
        KeyVerificationState::Done => "Done",
        KeyVerificationState::Cancelled => "Cancelled",
    }
}

/// Lifecycle CSS class for the state chip.
pub fn state_badge_class(state: KeyVerificationState) -> &'static str {
    match state {
        KeyVerificationState::Idle => "badge",
        KeyVerificationState::Started
        | KeyVerificationState::Accepted
        | KeyVerificationState::KeyHalfExchanged
        | KeyVerificationState::KeysExchanged
        | KeyVerificationState::MacHalfReceived
        | KeyVerificationState::MacsReceived
        | KeyVerificationState::DoneHalfReceived => "badge amber",
        KeyVerificationState::Done => "badge green",
        KeyVerificationState::Cancelled => "badge red",
    }
}

/// Round 25 (R3): main device-verification page. Both devices share
/// the same `transaction_id`; the page exposes buttons to step through
/// the FSM (start → accept → key × 2 → mac × 2 → done × 2) plus a
/// Cancel button. The SAS preview re-renders deterministically each
/// time the transaction id changes.
#[component]
pub fn DeviceVerificationPanel(
    initiator_did: String,
    initiator_device: String,
    responder_did: String,
    responder_device: String,
) -> Element {
    let mut transaction_id = use_signal(|| "txn-yougen-01".to_owned());
    let mut state = use_signal(|| KeyVerificationState::Idle);
    let mut last_message = use_signal(|| String::new());
    let mut cancel_reason = use_signal(|| String::new());
    let mut flow = use_signal(KeyVerificationFlow::new);

    // Deterministic SAS preview from the current transaction id.
    let sas_preview = sas_preview_from_transaction(&transaction_id());

    // Snapshot the parties for closures.
    let initiator_did_c = initiator_did.clone();
    let initiator_device_c = initiator_device.clone();
    let responder_did_c = responder_did.clone();
    let responder_device_c = responder_device.clone();

    rsx! {
        div { class: "timeline", "data-testid": "device-verification-panel",
            div { class: "event", "data-testid": "device-verification-overview",
                div { class: "event-head",
                    span { "Device verification" }
                    span { class: "{state_badge_class(state())}", "{state_label(state())}" }
                }
                div { class: "muted",
                    "Two devices compare the same emoji + 8-digit code derived from the verification transaction id. Cancel at any step aborts the flow before any device authorization or MLS welcome is signed."
                }
                div { class: "metric-grid", "data-testid": "device-verification-parties",
                    div { class: "metric",
                        strong { "Initiator" }
                        span { "{initiator_did}" }
                        div { class: "muted", "{initiator_device}" }
                    }
                    div { class: "metric",
                        strong { "Responder" }
                        span { "{responder_did}" }
                        div { class: "muted", "{responder_device}" }
                    }
                    div { class: "metric",
                        strong { "Transaction" }
                        span { "{transaction_id}" }
                        div { class: "muted", "deterministic SAS preview key" }
                    }
                }
                div { class: "workflow-form",
                    label { "Transaction id" }
                    input {
                        "data-testid": "device-verification-transaction-id",
                        value: "{transaction_id}",
                        oninput: move |evt| transaction_id.set(evt.value()),
                    }
                }
            }

            div { class: "event", "data-testid": "device-verification-sas",
                div { class: "event-head",
                    span { "SAS preview" }
                    span { "compare both devices" }
                }
                div { class: "actions", "data-testid": "device-verification-emoji-row",
                    for chunk in sas_preview.emoji.iter() {
                        span { class: "badge", "{chunk}" }
                    }
                }
                div { class: "space-title", "data-testid": "device-verification-digits",
                    "{sas_preview.digits}"
                }
                div { class: "muted",
                    "If the emoji + digits match exactly, click 'They match' on both devices. If they don't, click 'Abort' — the flow Cancels and no further events are signed."
                }
            }

            // FSM transition buttons. Each click feeds the next typed
            // envelope into KeyVerificationFlow; on success we update
            // the state signal. Out-of-order calls move the FSM to
            // Cancelled and surface the SDK's protocol error.
            div { class: "event", "data-testid": "device-verification-controls",
                div { class: "event-head",
                    span { "FSM controls" }
                    span { "step through the SDK 10-state flow" }
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "device-verification-start",
                        onclick: {
                            let initiator_did = initiator_did_c.clone();
                            let initiator_device = initiator_device_c.clone();
                            move |_| {
                                let txn = transaction_id();
                                let from_user = match Did::new(initiator_did.clone()) {
                                    Ok(d) => d,
                                    Err(e) => {
                                        last_message.set(format!("invalid initiator DID: {e}"));
                                        return;
                                    }
                                };
                                let from_device = match DeviceId::new(initiator_device.clone()) {
                                    Ok(d) => d,
                                    Err(e) => {
                                        last_message.set(format!("invalid initiator device: {e}"));
                                        return;
                                    }
                                };
                                let msg = KeyVerificationStart {
                                    transaction_id: txn,
                                    from_user,
                                    from_device,
                                    method: "sas_v1".to_owned(),
                                    key_agreement_protocols: vec![
                                        "curve25519-hkdf-sha256".to_owned(),
                                    ],
                                    message_authentication_codes: vec![
                                        "hkdf-hmac-sha256".to_owned(),
                                    ],
                                    short_authentication_string: vec![
                                        "decimal".to_owned(),
                                        "emoji".to_owned(),
                                    ],
                                    sent_at: Utc::now(),
                                };
                                let mut current = flow();
                                let result = current.on_start(&msg);
                                let new_state = current.state();
                                flow.set(current);
                                state.set(new_state);
                                match result {
                                    Ok(()) => last_message.set("start envelope accepted".to_owned()),
                                    Err(error) => last_message.set(format!("start failed: {error}")),
                                }
                            }
                        },
                        "1. Send Start"
                    }
                    button {
                        class: "primary",
                        "data-testid": "device-verification-accept",
                        onclick: {
                            let responder_did = responder_did_c.clone();
                            let responder_device = responder_device_c.clone();
                            move |_| {
                                let txn = transaction_id();
                                let from_user = match Did::new(responder_did.clone()) {
                                    Ok(d) => d,
                                    Err(e) => {
                                        last_message.set(format!("invalid responder DID: {e}"));
                                        return;
                                    }
                                };
                                let from_device = match DeviceId::new(responder_device.clone()) {
                                    Ok(d) => d,
                                    Err(e) => {
                                        last_message.set(format!("invalid responder device: {e}"));
                                        return;
                                    }
                                };
                                let msg = KeyVerificationAccept {
                                    transaction_id: txn,
                                    from_user,
                                    from_device,
                                    method: "sas_v1".to_owned(),
                                    key_agreement_protocol: "curve25519-hkdf-sha256".to_owned(),
                                    message_authentication_code: "hkdf-hmac-sha256".to_owned(),
                                    short_authentication_string: vec![
                                        "decimal".to_owned(),
                                        "emoji".to_owned(),
                                    ],
                                    commitment: "sha256:cafe".to_owned(),
                                    sent_at: Utc::now(),
                                };
                                let mut current = flow();
                                let result = current.on_accept(&msg);
                                let new_state = current.state();
                                flow.set(current);
                                state.set(new_state);
                                match result {
                                    Ok(()) => last_message.set("accept envelope accepted".to_owned()),
                                    Err(error) => last_message.set(format!("accept failed: {error}")),
                                }
                            }
                        },
                        "2. Send Accept"
                    }
                    button {
                        class: "primary",
                        "data-testid": "device-verification-key-initiator",
                        onclick: {
                            let initiator_did = initiator_did_c.clone();
                            let initiator_device = initiator_device_c.clone();
                            move |_| {
                                let txn = transaction_id();
                                let (Ok(from_user), Ok(from_device)) = (
                                    Did::new(initiator_did.clone()),
                                    DeviceId::new(initiator_device.clone()),
                                ) else {
                                    last_message.set("invalid initiator DID/device".to_owned());
                                    return;
                                };
                                let msg = KeyVerificationKey {
                                    transaction_id: txn,
                                    from_user,
                                    from_device,
                                    key: "AKEY".to_owned(),
                                    sent_at: Utc::now(),
                                };
                                let mut current = flow();
                                let result = current.on_key(&msg);
                                let new_state = current.state();
                                flow.set(current);
                                state.set(new_state);
                                match result {
                                    Ok(()) => last_message.set("initiator key accepted".to_owned()),
                                    Err(error) => last_message.set(format!("initiator key failed: {error}")),
                                }
                            }
                        },
                        "3a. Initiator Key"
                    }
                    button {
                        class: "primary",
                        "data-testid": "device-verification-key-responder",
                        onclick: {
                            let responder_did = responder_did_c.clone();
                            let responder_device = responder_device_c.clone();
                            move |_| {
                                let txn = transaction_id();
                                let (Ok(from_user), Ok(from_device)) = (
                                    Did::new(responder_did.clone()),
                                    DeviceId::new(responder_device.clone()),
                                ) else {
                                    last_message.set("invalid responder DID/device".to_owned());
                                    return;
                                };
                                let msg = KeyVerificationKey {
                                    transaction_id: txn,
                                    from_user,
                                    from_device,
                                    key: "BKEY".to_owned(),
                                    sent_at: Utc::now(),
                                };
                                let mut current = flow();
                                let result = current.on_key(&msg);
                                let new_state = current.state();
                                flow.set(current);
                                state.set(new_state);
                                match result {
                                    Ok(()) => last_message.set("responder key accepted".to_owned()),
                                    Err(error) => last_message.set(format!("responder key failed: {error}")),
                                }
                            }
                        },
                        "3b. Responder Key"
                    }
                    button {
                        class: "primary",
                        "data-testid": "device-verification-mac-initiator",
                        onclick: {
                            let initiator_did = initiator_did_c.clone();
                            let initiator_device = initiator_device_c.clone();
                            move |_| {
                                let txn = transaction_id();
                                let (Ok(from_user), Ok(from_device)) = (
                                    Did::new(initiator_did.clone()),
                                    DeviceId::new(initiator_device.clone()),
                                ) else {
                                    last_message.set("invalid initiator DID/device".to_owned());
                                    return;
                                };
                                let mut mac_map: BTreeMap<String, String> = BTreeMap::new();
                                mac_map.insert("ed25519:k1".to_owned(), "MAC_init".to_owned());
                                let msg = KeyVerificationMac {
                                    transaction_id: txn,
                                    from_user,
                                    from_device,
                                    keys: "MAC_keys".to_owned(),
                                    mac: mac_map,
                                    sent_at: Utc::now(),
                                };
                                let mut current = flow();
                                let result = current.on_mac(&msg);
                                let new_state = current.state();
                                flow.set(current);
                                state.set(new_state);
                                match result {
                                    Ok(()) => last_message.set("initiator MAC accepted".to_owned()),
                                    Err(error) => last_message.set(format!("initiator MAC failed: {error}")),
                                }
                            }
                        },
                        "4a. Initiator MAC"
                    }
                    button {
                        class: "primary",
                        "data-testid": "device-verification-mac-responder",
                        onclick: {
                            let responder_did = responder_did_c.clone();
                            let responder_device = responder_device_c.clone();
                            move |_| {
                                let txn = transaction_id();
                                let (Ok(from_user), Ok(from_device)) = (
                                    Did::new(responder_did.clone()),
                                    DeviceId::new(responder_device.clone()),
                                ) else {
                                    last_message.set("invalid responder DID/device".to_owned());
                                    return;
                                };
                                let mut mac_map: BTreeMap<String, String> = BTreeMap::new();
                                mac_map.insert("ed25519:k1".to_owned(), "MAC_resp".to_owned());
                                let msg = KeyVerificationMac {
                                    transaction_id: txn,
                                    from_user,
                                    from_device,
                                    keys: "MAC_keys".to_owned(),
                                    mac: mac_map,
                                    sent_at: Utc::now(),
                                };
                                let mut current = flow();
                                let result = current.on_mac(&msg);
                                let new_state = current.state();
                                flow.set(current);
                                state.set(new_state);
                                match result {
                                    Ok(()) => last_message.set("responder MAC accepted".to_owned()),
                                    Err(error) => last_message.set(format!("responder MAC failed: {error}")),
                                }
                            }
                        },
                        "4b. Responder MAC"
                    }
                    button {
                        class: "primary",
                        "data-testid": "device-verification-done-initiator",
                        onclick: {
                            let initiator_did = initiator_did_c.clone();
                            let initiator_device = initiator_device_c.clone();
                            move |_| {
                                let txn = transaction_id();
                                let (Ok(from_user), Ok(from_device)) = (
                                    Did::new(initiator_did.clone()),
                                    DeviceId::new(initiator_device.clone()),
                                ) else {
                                    last_message.set("invalid initiator DID/device".to_owned());
                                    return;
                                };
                                let msg = KeyVerificationDone {
                                    transaction_id: txn,
                                    from_user,
                                    from_device,
                                    sent_at: Utc::now(),
                                };
                                let mut current = flow();
                                let result = current.on_done(&msg);
                                let new_state = current.state();
                                flow.set(current);
                                state.set(new_state);
                                match result {
                                    Ok(()) => last_message.set("initiator Done accepted".to_owned()),
                                    Err(error) => last_message.set(format!("initiator Done failed: {error}")),
                                }
                            }
                        },
                        "5a. Initiator Done"
                    }
                    button {
                        class: "primary",
                        "data-testid": "device-verification-done-responder",
                        onclick: {
                            let responder_did = responder_did_c.clone();
                            let responder_device = responder_device_c.clone();
                            move |_| {
                                let txn = transaction_id();
                                let (Ok(from_user), Ok(from_device)) = (
                                    Did::new(responder_did.clone()),
                                    DeviceId::new(responder_device.clone()),
                                ) else {
                                    last_message.set("invalid responder DID/device".to_owned());
                                    return;
                                };
                                let msg = KeyVerificationDone {
                                    transaction_id: txn,
                                    from_user,
                                    from_device,
                                    sent_at: Utc::now(),
                                };
                                let mut current = flow();
                                let result = current.on_done(&msg);
                                let new_state = current.state();
                                flow.set(current);
                                state.set(new_state);
                                match result {
                                    Ok(()) => last_message.set("responder Done accepted".to_owned()),
                                    Err(error) => last_message.set(format!("responder Done failed: {error}")),
                                }
                            }
                        },
                        "5b. Responder Done"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "device-verification-cancel",
                        onclick: {
                            let initiator_did = initiator_did_c.clone();
                            let initiator_device = initiator_device_c.clone();
                            move |_| {
                                let txn = transaction_id();
                                let (Ok(from_user), Ok(from_device)) = (
                                    Did::new(initiator_did.clone()),
                                    DeviceId::new(initiator_device.clone()),
                                ) else {
                                    last_message.set("invalid initiator DID/device".to_owned());
                                    return;
                                };
                                let msg = KeyVerificationCancel {
                                    transaction_id: txn,
                                    from_user,
                                    from_device,
                                    code: "user_cancel".to_owned(),
                                    reason: "user pressed cancel".to_owned(),
                                    sent_at: Utc::now(),
                                };
                                let mut current = flow();
                                let result = current.on_cancel(&msg);
                                let new_state = current.state();
                                if let Some(record) = current.cancel_record() {
                                    cancel_reason.set(format!(
                                        "{}: {}",
                                        record.code, record.reason
                                    ));
                                }
                                flow.set(current);
                                state.set(new_state);
                                match result {
                                    Ok(()) => last_message.set("Cancel accepted".to_owned()),
                                    Err(error) => last_message.set(format!("Cancel failed: {error}")),
                                }
                            }
                        },
                        "Abort (Cancel)"
                    }
                }
                if !last_message().is_empty() {
                    div { class: "muted", "data-testid": "device-verification-last-message", "{last_message}" }
                }
                if !cancel_reason().is_empty() {
                    div { class: "muted", "data-testid": "device-verification-cancel-reason",
                        "Cancel reason: {cancel_reason}"
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sas_preview_is_deterministic() {
        let a = sas_preview_from_transaction("txn-1");
        let b = sas_preview_from_transaction("txn-1");
        assert_eq!(a, b);
    }

    #[test]
    fn sas_preview_changes_with_transaction() {
        let a = sas_preview_from_transaction("txn-a");
        let b = sas_preview_from_transaction("txn-b");
        // The chance of colliding on emoji+digits is < 1 in 2^48 — assert
        // both differ.
        assert_ne!(a.digits, b.digits);
    }

    #[test]
    fn sas_preview_emits_seven_emoji_and_eight_digits() {
        let preview = sas_preview_from_transaction("txn-stable");
        assert_eq!(preview.emoji.len(), 7);
        assert_eq!(preview.digits.len(), 8);
        for digit in preview.digits.chars() {
            assert!(digit.is_ascii_digit(), "digit string must be all digits");
        }
        for emoji in &preview.emoji {
            assert!(SAS_EMOJI.contains(&emoji.as_str()));
        }
    }

    #[test]
    fn state_label_covers_every_variant() {
        let states = [
            KeyVerificationState::Idle,
            KeyVerificationState::Started,
            KeyVerificationState::Accepted,
            KeyVerificationState::KeyHalfExchanged,
            KeyVerificationState::KeysExchanged,
            KeyVerificationState::MacHalfReceived,
            KeyVerificationState::MacsReceived,
            KeyVerificationState::DoneHalfReceived,
            KeyVerificationState::Done,
            KeyVerificationState::Cancelled,
        ];
        let mut labels: Vec<&str> = states.iter().map(|s| state_label(*s)).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), states.len());
    }

    #[test]
    fn state_badge_class_marks_done_green_and_cancelled_red() {
        assert_eq!(state_badge_class(KeyVerificationState::Done), "badge green");
        assert_eq!(state_badge_class(KeyVerificationState::Cancelled), "badge red");
    }

    #[test]
    fn sas_emoji_set_has_64_entries() {
        assert_eq!(SAS_EMOJI.len(), 64);
    }
}
