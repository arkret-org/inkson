use crate::runtime::input::StateStoreHandle;

struct ExternalHistoryDecryptTask {
    realm_id: String,
    payload: arkret_sdk::EncryptedPayload,
    effective_scope: arkret_sdk::ScopeRef,
    binding_key: arkret_sdk::EventCandidateBindingKey,
}

fn external_history_decrypt_tasks(
    state_store: &StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
) -> Result<Vec<ExternalHistoryDecryptTask>, String> {
    state_store.read(|store| {
        external_history_decrypt_tasks_in_store(store, authority, actor_id, device_id)
    })
}

fn external_history_decrypt_tasks_in_store(
    store: &crate::state::LocalStateStore,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
) -> Result<Vec<ExternalHistoryDecryptTask>, String> {
    let state = store.load();
    let mut tasks = Vec::new();
    // The Realm stream persists messages in raw_operations, which is also the
    // chat feed's source after reload. Account tree snapshots need not contain
    // those messages, especially ones delivered while this endpoint was offline.
    let projected_events = state.realm_tree_projections.values().filter_map(|projection| {
        projection.get("state").and_then(|state| state.get("events"))
            .and_then(serde_json::Value::as_array)
    }).flatten();
    let durable_events = state.raw_operations.iter().map(|record| &record.payload);
    let mut seen = std::collections::BTreeSet::new();
    for event in projected_events.chain(durable_events) {
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
                Some(store),
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
                store,
                &envelope,
                &effective_scope,
                event_kind,
                &sender_domain,
                reaction_routing_window,
            ) else {
                continue;
            };
            if !seen.insert(event_id.clone()) {
                continue;
            }
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
    Ok(tasks)
}

/// Return canonical missing exporter-history ranges from the same verified
/// Event contexts used by the candidate consumer. This prevents the recovery
/// driver from creating requests for unverified projection-shaped input.
pub(crate) fn missing_external_history_ranges(
    state_store: &StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
) -> Result<
    Vec<(
        arkret_sdk::HistoryEffectiveScope,
        Vec<arkret_sdk::EpochRange>,
    )>,
    String,
> {
    let tasks = external_history_decrypt_tasks(state_store, authority, actor_id, device_id)?;
    let mut missing = std::collections::BTreeMap::<
        String,
        (
            arkret_sdk::HistoryEffectiveScope,
            std::collections::BTreeSet<u64>,
        ),
    >::new();
    for task in tasks {
        if state_store.read(|store| {
            store
                .mls_decrypted_plaintext_for(&task.realm_id, task.payload.payload_digest.as_str())
                .is_some()
        }) {
            continue;
        }
        let scope = task.binding_key.effective_scope;
        let key = serde_json::to_string(&scope).map_err(|error| error.to_string())?;
        missing
            .entry(key)
            .or_insert_with(|| (scope, std::collections::BTreeSet::new()))
            .1
            .insert(task.payload.epoch);
    }
    Ok(missing
        .into_values()
        .map(|(scope, epochs)| {
            let mut ranges = Vec::<arkret_sdk::EpochRange>::new();
            for epoch in epochs {
                if let Some(last) = ranges.last_mut()
                    && last.to_epoch.checked_add(1) == Some(epoch)
                {
                    last.to_epoch = epoch;
                    continue;
                }
                ranges.push(arkret_sdk::EpochRange {
                    from_epoch: epoch,
                    to_epoch: epoch,
                });
            }
            (scope, ranges)
        })
        .collect())
}

/// Open accepted exporter-AEAD Events with bounded external candidates and
/// durably bind every candidate outcome before publishing plaintext to reads.
pub(crate) fn converge_external_history_candidate_decryptions(
    state_store: &StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<usize, String> {
    let tasks = external_history_decrypt_tasks(state_store, authority, actor_id, device_id)?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let mut opened = 0;
    for task in tasks {
        let plaintext = state_store
            .write(|store| {
                super::decrypt_external_history_candidates_for_event(
                    store,
                    secure_store.as_ref(),
                    &task.realm_id,
                    &task.payload,
                    &task.effective_scope,
                    task.binding_key,
                    now,
                )
            })
            .map_err(|error| error.user_message())?;
        if let Some(plaintext) = plaintext {
            state_store.read(|store| {
                store.cache_external_history_plaintext(
                    &task.realm_id,
                    task.payload.payload_digest.as_str(),
                    &plaintext,
                )
            });
            opened += 1;
        }
    }
    Ok(opened)
}
