//! Encrypted-payload crypto state on projected messages.

use super::*;

#[test]
fn message_crypto_state_pending_detects_grey_states() {
    assert!(!MessageCryptoState::Plaintext.is_pending());
    assert!(MessageCryptoState::Decrypting.is_pending());
    assert!(MessageCryptoState::KeyMissing.is_pending());
    assert!(!MessageCryptoState::NeedsVerification.is_pending());
}

#[test]
fn secure_content_block_round_trips_back_to_text() {
    // P1: the secure send path encrypts the canonical Content Block JSON
    // (not raw body bytes), and the decrypt-on-read path extracts the text
    // back out via `text_body_from_value`. This locks that symmetry without
    // standing up a full MLS group.
    let body = "secret hello with spaces";
    let content_value = arkret_sdk::ContentBlock::markdown_text(body)
        .to_value()
        .expect("content block serializes");
    let bytes = serde_json::to_vec(&content_value).expect("content block bytes");
    let parsed: Value = serde_json::from_slice(&bytes).expect("content block parses");
    assert_eq!(text_body_from_value(&parsed), Some(body));
    assert_eq!(
        content_format_from_value(&parsed),
        Some(arkret_sdk::TextFormat::Markdown)
    );
}

#[test]
fn chat_message_from_event_flags_encrypted_payload_as_decrypting() {
    let event = signed_chat_event(
        "ak.message.create",
        "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI",
        json!({"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}}),
        "2026-05-14T01:23:45.000Z",
        json!({
            "strand_id": "ak:strand:AI5OKPo7cL4WAh-kQD_G9aUudPNU0xGaEiCVn1F1nFGA",
            "content": {"body": "[encrypted]", "encrypted_content": {"ciphertext": "blob"}}
        }),
    );
    let msg = chat_message_from_event(
        "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI",
        &event,
    )
    .expect("message");
    assert_eq!(msg.crypto_state, MessageCryptoState::Decrypting);
}

#[test]
fn circle_scoped_message_does_not_require_forbidden_payload_scope_field() {
    let event = signed_chat_event_in_scope(
        "ak.message.create",
        json!({
            "kind": "circle",
            "realm_id": "ak:realm:AZ50TDWNf7-ZvnbVpb3-bD97v_NiKs0krmIiZeXokdCg",
            "circle_id": "ak:circle:Ad3sAE8SdL97yMaxfdHCkPiyKsWulMWC1Eisx0zigFOe"
        }),
        json!({"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}}),
        "2026-05-14T01:23:45.000Z",
        json!({
            "strand_id": "ak:strand:AegcXfEz2IA1aMoPIHXpIIKiqHdDUdO6mYsEziNN-gnj",
            "track_name": "discussion",
            "content": { "body": "private" }
        }),
    );

    let message = chat_message_from_event(
        "ak:realm:AZ50TDWNf7-ZvnbVpb3-bD97v_NiKs0krmIiZeXokdCg",
        &event,
    )
    .unwrap();
    assert_eq!(message.crypto_state, MessageCryptoState::Plaintext);
    assert_eq!(message.body, "private");
}

#[test]
fn chat_message_from_event_keeps_bodyless_encrypted_payload_visible() {
    let event = signed_chat_event(
        "ak.message.create",
        "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI",
        json!({"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}}),
        "2026-05-14T01:23:45.000Z",
        json!({
            "strand_id": "ak:strand:AI5OKPo7cL4WAh-kQD_G9aUudPNU0xGaEiCVn1F1nFGA",
            "content": {
                "encrypted_content": {
                    "scheme": "mls_rfc9420",
                    "version": "1.0",
                    "group_id": "ak:mls:test",
                    "epoch": 1,
                    "content_type": "application/vnd.arkret.message+json",
                    "ciphertext": "AAAA",
                    "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                },
            }
        }),
    );

    let msg = chat_message_from_event(
        "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI",
        &event,
    )
    .expect("message");

    assert_eq!(msg.body, "");
    assert_eq!(
        msg.strand_id,
        "ak:strand:AI5OKPo7cL4WAh-kQD_G9aUudPNU0xGaEiCVn1F1nFGA"
    );
    assert_eq!(msg.crypto_state, MessageCryptoState::Decrypting);
}

#[test]
fn chat_message_from_event_marks_failed_local_decrypt_as_key_missing() {
    let temp = std::env::temp_dir().join(format!(
        "inkson-chat-key-missing-{}.json",
        crate::operation::uuid_v7()
    ));
    let store = LocalStateStore::with_path(temp);
    let event = signed_chat_event(
        "ak.message.create",
        "ak:realm:AacL7ZYuTtiI1Wvq5aTmbQo8CihIcuFhJ4WKAZZMxlxY",
        json!({"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}}),
        "2026-05-14T01:23:45.000Z",
        json!({
            "strand_id": "ak:strand:AI5OKPo7cL4WAh-kQD_G9aUudPNU0xGaEiCVn1F1nFGA",
            "content": {
                "encrypted_content": {
                    "scheme": "mls_rfc9420",
                    "version": "1.0",
                    "group_id": "ak:mls:test",
                    "epoch": 1,
                    "content_type": "application/vnd.arkret.message+json",
                    "ciphertext": "AAAA",
                    "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                },
            }
        }),
    );
    let authority = fixture::authority("ak:did_core:web:bob.example");
    let device_id = fixture::device_id("ak:device:01964137-0000-7000-8000-000000000001");

    let msg = chat_message_from_event_with_sidecar(
        "ak:realm:AacL7ZYuTtiI1Wvq5aTmbQo8CihIcuFhJ4WKAZZMxlxY",
        &event,
        Some(&store),
        Some((&authority, "ak:did_core:web:bob.example", &device_id)),
    )
    .expect("message");

    assert_eq!(msg.body, "");
    assert_eq!(msg.crypto_state, MessageCryptoState::KeyMissing);
}
