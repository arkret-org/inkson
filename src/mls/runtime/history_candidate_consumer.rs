use dioxus::prelude::{ReadableExt, SyncSignal, WritableExt};

struct ExternalHistoryDecryptTask {
    realm_id: String,
    payload: arkret_sdk::EncryptedPayload,
    effective_scope: arkret_sdk::ScopeRef,
    binding_key: arkret_sdk::EventCandidateBindingKey,
}

/// Open accepted exporter-AEAD Events with bounded external candidates and
/// durably bind every candidate outcome before publishing plaintext to reads.
pub(crate) fn converge_external_history_candidate_decryptions(
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<usize, String> {
    let tasks = {
        let store = state_store.read();
        let state = store.load();
        let mut tasks = Vec::new();
        for projection in state.realm_tree_projections.values() {
            let Some(events) = projection
                .get("state")
                .and_then(|state| state.get("events"))
                .and_then(serde_json::Value::as_array)
            else {
                continue;
            };
            for event in events {
                let Some(event_id) = event
                    .get("event_id")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|value| arkret_sdk::EventId::new(value.to_owned()).ok())
                else {
                    continue;
                };
                let Some(effective_scope) = event
                    .get("scope_ref")
                    .or_else(|| event.get("effective_scope"))
                    .cloned()
                    .and_then(|value| serde_json::from_value::<arkret_sdk::ScopeRef>(value).ok())
                else {
                    continue;
                };
                let Some(realm_id) = effective_scope
                    .realm_id_opt()
                    .map(|realm_id| realm_id.as_str().to_owned())
                else {
                    continue;
                };
                let encrypted = event
                    .pointer("/payload/content/encrypted_content")
                    .or_else(|| event.pointer("/payload/encrypted_content"))
                    .or_else(|| event.pointer("/content/encrypted_content"))
                    .or_else(|| event.get("encrypted_content"));
                let Some(envelope) = encrypted.cloned().and_then(|value| {
                    serde_json::from_value::<arkret_sdk::EncryptedEnvelope>(value).ok()
                }) else {
                    continue;
                };
                let Some(sender_domain) = crate::views::chat::verified_chat_sender_domain_for_realm(
                    &realm_id,
                    event,
                    Some(&store),
                    Some((authority, actor_id, device_id)),
                ) else {
                    continue;
                };
                let Some(event_kind) = event.get("kind").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                let reaction_routing_window = if matches!(
                    event_kind,
                    arkret_wire::event_kind_str::REACTION_ADD
                        | arkret_wire::event_kind_str::REACTION_REMOVE
                ) {
                    let Some(created_at) = event
                        .get("created_at")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|value| value.parse::<chrono::DateTime<chrono::Utc>>().ok())
                    else {
                        continue;
                    };
                    Some(created_at.timestamp_millis().div_euclid(3_600_000) as u64)
                } else {
                    None
                };
                let Some(payload) = super::message::encrypted_payload_from_verified_event_context(
                    &store,
                    &envelope,
                    &effective_scope,
                    event_kind,
                    &sender_domain,
                    reaction_routing_window,
                ) else {
                    continue;
                };
                tasks.push(ExternalHistoryDecryptTask {
                    realm_id,
                    payload: payload.clone(),
                    effective_scope: effective_scope.clone(),
                    binding_key: arkret_sdk::EventCandidateBindingKey {
                        effective_scope: match effective_scope {
                            arkret_sdk::ScopeRef::Realm { realm_id } => {
                                arkret_sdk::HistoryEffectiveScope::Realm { realm_id }
                            }
                            arkret_sdk::ScopeRef::Circle {
                                realm_id,
                                circle_id,
                            } => arkret_sdk::HistoryEffectiveScope::Circle {
                                realm_id,
                                circle_id,
                            },
                            _ => continue,
                        },
                        mls_group_id: payload.group_id.clone(),
                        epoch: payload.epoch,
                        event_id,
                        verified_sender_domain: String::from_utf8(sender_domain)
                            .map_err(|_| "verified sender domain is not UTF-8".to_owned())?,
                    },
                });
            }
        }
        tasks
    };
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let mut opened = 0;
    for task in tasks {
        let plaintext = {
            let mut store = state_store.write();
            super::decrypt_external_history_candidates_for_event(
                &mut store,
                secure_store.as_ref(),
                &task.realm_id,
                &task.payload,
                &task.effective_scope,
                task.binding_key,
                now,
            )
            .map_err(|error| error.user_message())?
        };
        if let Some(plaintext) = plaintext {
            state_store.read().cache_external_history_plaintext(
                &task.realm_id,
                task.payload.payload_digest.as_str(),
                &plaintext,
            );
            opened += 1;
        }
    }
    Ok(opened)
}
