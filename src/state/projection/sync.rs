use arkret_wire::event_kind_str;
use serde_json::Value;
use yoface::utils::text::short_protocol_id;

use super::decrypt::try_local_mls_decrypt_core_for_scope_from_verified_sender;
use super::model::ProjectionEvent;

/// Read the sender identity from an account event projection envelope.
///
/// Canonical envelopes expose `actor_id` / `sender_actor_id` only;
/// forbidden `sender` fields are not accepted.
fn projection_actor_id(event: &Value) -> Option<&str> {
    ["actor_id", "sender_actor_id"]
        .into_iter()
        .find_map(|key| event.get(key).and_then(Value::as_str))
}

/// Extract the display text from a decrypted canonical Content Block JSON.
///
/// The secure send path encodes the body as a canonical Content Block with
/// `body` plus its declared format; composite content carries
/// ordered blocks under `parts[]`.
fn projection_text_from_content_value(value: &Value) -> Option<&str> {
    value
        .get("body")
        .or_else(|| value.get("text"))
        .and_then(Value::as_str)
        .or_else(|| {
            value
                .get("parts")
                .and_then(Value::as_array)
                .and_then(|parts| parts.first())
                .and_then(projection_text_from_content_value)
        })
}

fn projection_text_from_private_sidecar(value: String) -> String {
    serde_json::from_str::<Value>(&value)
        .ok()
        .filter(|content| {
            content
                .get("kind")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind.starts_with("ak.content."))
        })
        .and_then(|content| projection_text_from_content_value(&content).map(ToOwned::to_owned))
        .unwrap_or(value)
}

/// Project the `realms[*].timeline.events` of an account-subscribe response
/// into [`ProjectionEvent`]s. YOU-06-003 / YOU-01-013: this is the single
/// owner of account event projection parsing — the former Matrix-shaped `app.rs` copy
/// (read `sender`/`content` only) was deleted. The sync engine and local
/// search now call this canonical version, which reads the spec envelope
/// (`actor_id` / `sender_actor_id`, `payload`/`content` body) and carries
/// `encrypted_content` forward for local MLS decrypt.
pub fn projection_events_from_sync_realms(
    realms: &std::collections::BTreeMap<String, Value>,
    store: Option<&crate::state::LocalStateStore>,
    decrypt_identity: Option<(&arkret_sdk::PrincipalAuthorityKey, &arkret_sdk::DeviceId)>,
) -> Vec<ProjectionEvent> {
    let mut events = Vec::new();
    for (realm_id, body) in realms {
        let realm_id_label = short_protocol_id(realm_id);
        let mut summary_event = ProjectionEvent::system_notice(
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

        let Some(wire_events) = body
            .get("timeline")
            .and_then(|projection| projection.get("events"))
            .and_then(Value::as_array)
        else {
            continue;
        };

        for event in wire_events {
            if event.get("kind").and_then(Value::as_str)
                == Some(arkret_wire::event_kind_str::AUDIT_ACCESSED)
            {
                match crate::late_recovery::late_recovered_event_from_audit_policy_access_event(
                    event, false,
                ) {
                    crate::late_recovery::LateRecoveryAuditAccessConversion::LateRecovered(
                        recovered,
                    ) => {
                        let mut marker = ProjectionEvent::system_notice(
                            format!("late-recovery-{}", recovered.event_id),
                            "audit",
                            recovered.banner_text(),
                        );
                        marker.realm_id = Some(realm_id.clone());
                        marker.event_id = Some(recovered.event_id);
                        events.push(marker);
                        continue;
                    }
                    crate::late_recovery::LateRecoveryAuditAccessConversion::Reject(reason) => {
                        let mut rejected = ProjectionEvent::system_notice(
                            format!(
                                "late-recovery-rejected-{}",
                                event
                                    .get("event_id")
                                    .and_then(Value::as_str)
                                    .unwrap_or("event:unknown")
                            ),
                            "audit",
                            reason.reason_code(),
                        );
                        rejected.realm_id = Some(realm_id.clone());
                        rejected.failed = true;
                        rejected.error = Some(reason.reason_code().to_owned());
                        events.push(rejected);
                        continue;
                    }
                    crate::late_recovery::LateRecoveryAuditAccessConversion::NotLateRecovery => {}
                }
            }
            if event.get("kind").and_then(Value::as_str) != Some(event_kind_str::MESSAGE_CREATE) {
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
                .or_else(|| projection_text_from_content_value(content))
                .unwrap_or("[message]")
                .to_owned();
            let late_recovery_transition =
                crate::late_recovery::evaluate_late_recovery_transition_event(event);
            let late_recovery_rejection = late_recovery_transition
                .rejection_reason_code()
                .map(ToOwned::to_owned);
            // B7: carry the raw `encrypted_content` block forward so local
            // consumers can try an MLS decrypt against it.
            let encrypted_payload = content.get("encrypted_content").cloned();
            // Parity with the chat read path: for encrypted messages the wire
            // body is just `[message]`. Recover plaintext, preferring the
            // author's own local sidecar (OpenMLS forbids an author from
            // decrypting their OWN ciphertext) and otherwise a remote-member
            // decrypt-on-read. Leave the `[message]` fallback untouched when
            // neither store nor identity is available, or recovery soft-fails.
            if late_recovery_transition.allows_plaintext()
                && let Some(encrypted_content) = encrypted_payload.as_ref()
            {
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
                    if let (Some((authority, device_id)), Some(store)) = (decrypt_identity, store) {
                        let actor_id = authority.principal_id.as_str();
                        event
                            .get("scope_ref")
                            .or_else(|| event.get("effective_scope"))
                            .cloned()
                            .and_then(|scope| {
                                serde_json::from_value::<arkret_sdk::ScopeRef>(scope).ok()
                            })
                            .and_then(|effective_scope| {
                                let sender_domain =
                                    crate::views::chat::verified_chat_sender_domain_for_realm(
                                        message_realm,
                                        event,
                                        Some(store),
                                        Some((authority, actor_id, device_id)),
                                    );
                                try_local_mls_decrypt_core_for_scope_from_verified_sender(
                                    store,
                                    message_realm,
                                    authority,
                                    device_id,
                                    encrypted_content,
                                    &effective_scope,
                                    event_kind_str::MESSAGE_CREATE,
                                    sender_domain.as_deref()?,
                                    None,
                                )
                            })
                            .and_then(|plaintext| serde_json::from_slice::<Value>(&plaintext).ok())
                            .and_then(|value| {
                                projection_text_from_content_value(&value).map(ToOwned::to_owned)
                            })
                    } else {
                        None
                    }
                } else {
                    None
                };
                if let Some(plaintext) = sidecar_body.or(decrypted_body) {
                    body = projection_text_from_private_sidecar(plaintext);
                }
            }
            if late_recovery_rejection.is_some() {
                body.clear();
            }
            events.push(ProjectionEvent {
                realm_id: Some(realm_id.clone()),
                strand_id: content
                    .get("strand_id")
                    .and_then(Value::as_str)
                    .or_else(|| event.get("thread_id").and_then(Value::as_str))
                    .map(ToOwned::to_owned),
                id: event_id.clone(),
                message_id,
                // The canonical envelope subject is `actor_id`; sender display
                // fields use the role-explicit `sender_actor_*` schema names.
                // Envelope attribution uses `actor_id`; derived notification
                // projections use the role-explicit `sender_actor_id`.
                sender: projection_actor_id(event)
                    .unwrap_or("did:web:unknown")
                    .to_owned(),
                sender_display: projection_actor_id(event)
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
                failed: late_recovery_rejection.is_some(),
                error: late_recovery_rejection,
                encrypted_payload,
                ..ProjectionEvent::default()
            });
        }
    }
    events
}
