use serde_json::Value;

use super::decrypt::try_local_mls_decrypt_core;
use super::model::TimelineEvent;
use crate::local_state::ReadMarkerRecord;
use crate::views::helpers::short_protocol_id;

/// Read the sender identity from a timeline event envelope.
///
/// Canonical envelopes expose `actor_id` / `sender_actor_id` only;
/// forbidden `sender` fields are not accepted.
fn timeline_actor_id(event: &Value) -> Option<&str> {
    ["actor_id", "sender_actor_id"]
        .into_iter()
        .find_map(|key| event.get(key).and_then(Value::as_str))
}

/// Extract the display text from a decrypted canonical Content Block JSON.
///
/// The secure send path encodes the body via `ContentBlock::text(..).to_value()`,
/// whose canonical shape is `{ "text": .. }`; older / multi-block shapes carry it
/// at `blocks[0].text`. Mirrors chat's `text_body_from_value` for the subset the
/// timeline read path needs.
fn timeline_text_from_content_value(value: &Value) -> Option<&str> {
    value.get("text").and_then(Value::as_str).or_else(|| {
        value
            .get("blocks")
            .and_then(Value::as_array)
            .and_then(|blocks| blocks.first())
            .and_then(|block| block.get("text"))
            .and_then(Value::as_str)
    })
}

/// Project the `realms[*].timeline.events` of an account-subscribe response
/// into [`TimelineEvent`]s. YOU-06-003 / YOU-01-013: this is the single
/// owner of timeline wire parsing — the former Matrix-shaped `app.rs` copy
/// (read `sender`/`content` only) was deleted and both the sync engine and
/// the timeline view now call this canonical version, which reads the spec
/// envelope (`actor_id` / `sender_actor_id`, `payload`/`content` body) and
/// carries `encrypted_content` forward for local MLS decrypt.
pub fn timeline_events_from_sync_realms(
    realms: &std::collections::BTreeMap<String, Value>,
    store: Option<&crate::local_state::LocalStateStore>,
    decrypt_identity: Option<(&str, &str)>,
) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    for (realm_id, body) in realms {
        let realm_id_label = short_protocol_id(realm_id);
        let mut summary_event = TimelineEvent::system_notice(
            format!("summary-{realm_id}"),
            "server",
            format!(
                "{realm_id_label}: {}",
                body["summary"]["summary"]
                    .as_str()
                    .unwrap_or("No summary available")
            ),
        );
        summary_event.realm_id = Some(realm_id.clone());
        events.push(summary_event);

        let Some(timeline_events) = body
            .get("timeline")
            .and_then(|timeline| timeline.get("events"))
            .and_then(Value::as_array)
        else {
            continue;
        };

        for event in timeline_events {
            if event.get("kind").and_then(Value::as_str) != Some("ck.message.create") {
                continue;
            }
            let event_id = event
                .get("event_id")
                .and_then(Value::as_str)
                .unwrap_or("event:unknown")
                .to_owned();
            let message_id = event
                .get("message_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let content = event.get("content").unwrap_or(&Value::Null);
            let mut body = content
                .get("body")
                .and_then(Value::as_str)
                .or_else(|| event.get("body").and_then(Value::as_str))
                .or_else(|| {
                    content
                        .get("blocks")
                        .and_then(Value::as_array)
                        .and_then(|blocks| blocks.first())
                        .and_then(|block| block.get("text"))
                        .and_then(Value::as_str)
                })
                .unwrap_or("[message]")
                .to_owned();
            let is_expiry_stub = crate::disappearing::message_event_is_expiry_stub(event);
            if is_expiry_stub {
                body = crate::disappearing::message_expiry_stub_body(event);
            }
            // B7: carry the raw `encrypted_content` block forward so the
            // audit-accessed emitter (later in this component) can try a
            // local MLS decrypt against it and fire `ck.audit.accessed`
            // on every successful decrypt.
            let encrypted_payload = content.get("encrypted_content").cloned();
            // Parity with the chat read path: for encrypted messages the wire
            // body is just `[message]`. Recover plaintext, preferring the
            // author's own local sidecar (OpenMLS forbids an author from
            // decrypting their OWN ciphertext) and otherwise a remote-member
            // decrypt-on-read. Leave the `[message]` fallback untouched when
            // neither store nor identity is available, or recovery soft-fails.
            if !is_expiry_stub && let Some(encrypted_content) = encrypted_payload.as_ref() {
                let message_realm = content
                    .get("realm_id")
                    .and_then(Value::as_str)
                    .unwrap_or(realm_id);
                let sidecar_message_id = message_id.as_deref();
                let strand_id = content
                    .get("strand_id")
                    .and_then(Value::as_str)
                    .or_else(|| event.get("thread_id").and_then(Value::as_str));
                // a. Author sidecar — the plaintext the author stored on send.
                let sidecar_body = store.and_then(|store| {
                    let message_id = sidecar_message_id?;
                    let strand_id = strand_id?;
                    store.private_plaintext_for(
                        message_realm,
                        strand_id,
                        &format!("message:{message_id}"),
                    )
                });
                // b. Remote decrypt-on-read — envelope → payload → MLS core →
                // canonical Content Block JSON → display text.
                let decrypted_body = if sidecar_body.is_none() {
                    if let (Some((actor_id, device_id)), Some(store)) = (decrypt_identity, store) {
                        serde_json::from_value::<cokret_sdk::EncryptedEnvelopeV1>(
                            encrypted_content.clone(),
                        )
                        .ok()
                        .and_then(|env| env.to_payload().ok())
                        .and_then(|payload| serde_json::to_value(payload).ok())
                        .and_then(|payload_value| {
                            try_local_mls_decrypt_core(
                                store,
                                message_realm,
                                actor_id,
                                device_id,
                                &payload_value,
                            )
                        })
                        .and_then(|plaintext| serde_json::from_slice::<Value>(&plaintext).ok())
                        .and_then(|value| {
                            timeline_text_from_content_value(&value).map(ToOwned::to_owned)
                        })
                    } else {
                        None
                    }
                } else {
                    None
                };
                if let Some(plaintext) = sidecar_body.or(decrypted_body) {
                    body = plaintext;
                }
            }
            events.push(TimelineEvent {
                realm_id: Some(realm_id.clone()),
                id: event_id.clone(),
                message_id,
                // The canonical envelope subject is `actor_id`; sender display
                // fields use the role-explicit `sender_actor_*` schema names.
                // Prefer actor_id / sender_actor_id; `sender` is deprecated and
                // kept only for backward compatibility.
                sender: timeline_actor_id(event)
                    .unwrap_or("did:web:unknown")
                    .to_owned(),
                sender_display: timeline_actor_id(event)
                    .map(short_protocol_id)
                    .unwrap_or_else(|| "server".to_owned()),
                body,
                timestamp: event
                    .get("created_at")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                thread_id: event
                    .get("thread_id")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                reply_to: event
                    .get("reply_to")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                event_id: Some(event_id),
                encrypted_payload,
                ..TimelineEvent::default()
            });
        }
    }
    events
}

pub(super) fn timeline_reply_quote_preview(
    events: &[TimelineEvent],
    reply_id: &str,
) -> Option<(String, String)> {
    let quoted = events
        .iter()
        .find(|event| event.message_reply_ref() == Some(reply_id) || event.id == reply_id)?;
    let body = if quoted.redacted {
        "[Message redacted]".to_owned()
    } else {
        quoted.body.clone()
    };
    Some((quoted.sender_display.clone(), body))
}

pub(super) fn timeline_event_has_moderation_decision(event: &TimelineEvent) -> bool {
    let body = event.body.to_ascii_lowercase();
    let tombstone = event
        .tombstone_reason
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    body.contains("moderation decision")
        || body.contains("moderation blocked")
        || tombstone.contains("moderation")
}

pub(super) fn read_cursor_status_label(marker: &ReadMarkerRecord) -> String {
    let scope = match (
        marker.body.read_scope.kind.as_str(),
        marker.body.read_scope.object_ref.as_deref(),
        marker.body.read_scope.track_name.as_deref(),
    ) {
        ("thread", Some(object_ref), _) => format!("thread {}", short_protocol_id(object_ref)),
        ("strand", Some(object_ref), Some(track)) => {
            format!("{track} {}", short_protocol_id(object_ref))
        }
        ("strand", Some(object_ref), None) => format!("strand {}", short_protocol_id(object_ref)),
        (kind, ..) => kind.to_owned(),
    };
    format!(
        "Read marker: {} ({scope}) at {}",
        short_protocol_id(&marker.body.position.event_id),
        marker.updated_at.format("%Y-%m-%d %H:%M")
    )
}
