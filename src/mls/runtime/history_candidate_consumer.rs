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
    let projected_events = state
        .realm_tree_projections
        .values()
        .filter_map(|projection| {
            projection
                .get("state")
                .and_then(|state| state.get("events"))
                .and_then(serde_json::Value::as_array)
        })
        .flatten();
    let durable_events = state.raw_operations.iter().map(|record| &record.payload);
    let mut seen = std::collections::BTreeSet::new();
    for event in projected_events.chain(durable_events) {
        // Only a canonical signed Event supplies scope, kind and encrypted
        // field bytes. Projection wrappers cannot author this context.
        let Ok(signed_event) = serde_json::from_value::<arkret_sdk::Event>(event.clone()) else {
            continue;
        };
        let event_id = signed_event.event_id.clone();
        let effective_scope = signed_event.scope_ref.clone();
        let realm_id = signed_event.realm_id.to_string();
        let envelopes = encrypted_event_fields(&signed_event);
        if envelopes.is_empty() {
            continue;
        }
        let Some(sender_domain) = crate::views::chat::verified_chat_sender_domain_for_realm(
            &realm_id,
            event,
            Some(store),
            Some((authority, actor_id, device_id)),
        ) else {
            continue;
        };
        let event_kind = signed_event.kind.as_str();
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
        for envelope in envelopes {
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
            if !seen.insert((event_id.clone(), payload.payload_digest.clone())) {
                continue;
            }
            tasks.push(ExternalHistoryDecryptTask {
                realm_id: realm_id.clone(),
                payload: payload.clone(),
                effective_scope: effective_scope.clone(),
                binding_key: arkret_sdk::EventCandidateBindingKey {
                    effective_scope: match effective_scope.clone() {
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
                    event_id: event_id.clone(),
                    verified_sender_domain: String::from_utf8(sender_domain.clone())
                        .map_err(|_| "verified sender domain is not UTF-8".to_owned())?,
                },
            });
        }
    }
    Ok(tasks)
}

/// Discover encrypted fields on the canonical Event payload, including typed
/// patch values. One Event can update several private fields with independent
/// counters, so callers deduplicate by Event and payload digest, not Event alone.
fn encrypted_event_fields(event: &arkret_sdk::Event) -> Vec<arkret_sdk::EncryptedEnvelope> {
    fn append(value: &serde_json::Value, out: &mut Vec<arkret_sdk::EncryptedEnvelope>) {
        if let Ok(envelope) = serde_json::from_value::<arkret_sdk::EncryptedEnvelope>(value.clone())
            && envelope.validate().is_ok()
        {
            out.push(envelope);
        }
    }
    fn object_fields(value: &serde_json::Value, out: &mut Vec<arkret_sdk::EncryptedEnvelope>) {
        for path in [
            "/encrypted_content",
            "/encrypted_metadata",
            "/tracks/synthesis/encrypted_content",
            "/metadata/fields/calendar/location",
        ] {
            if let Some(field) = value.pointer(path) {
                append(field, out);
            }
        }
    }
    let mut envelopes = Vec::new();
    for key in ["encrypted_content", "encrypted_metadata"] {
        if let Some(value) = event.payload.get(key) {
            append(value, &mut envelopes);
        }
    }
    for key in ["object", "content"] {
        if let Some(value) = event.payload.get(key) {
            object_fields(value, &mut envelopes);
        }
    }
    if let Some(patch) = event
        .payload
        .get("patch")
        .and_then(serde_json::Value::as_object)
    {
        for (path, value) in patch {
            let Ok(op) = serde_json::from_value::<arkret_wire::patch::PatchOp>(value.clone())
            else {
                continue;
            };
            if !matches!(
                op.op(),
                arkret_wire::patch::PatchOpKind::Set | arkret_wire::patch::PatchOpKind::Add
            ) {
                continue;
            }
            if let Some(value) = op.value() {
                append(value, &mut envelopes);
                object_fields(value, &mut envelopes);
                if path == "metadata.fields.calendar"
                    && let Some(location) = value.get("location")
                {
                    append(location, &mut envelopes);
                }
            }
        }
    }
    envelopes
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

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn envelope(counter: u64) -> Value {
        json!({
            "version": "1.0",
            "content_type": "application/json",
            "encryption_context": {
                "epoch": 0,
                "group_state_ref": "ak:event:AZc5yUQiAVSI3hquJ6vb24B9nBqhiONzxJK6xPKc-IQ9",
                "counter": counter,
            },
            "ciphertext": "AAAA",
        })
    }

    fn event(kind: &str, payload: Value) -> arkret_sdk::Event {
        arkret_wire::test_support::raw_event(
            kind,
            arkret_sdk::ScopeRef::Realm {
                realm_id: arkret_sdk::RealmId::new(
                    "ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN",
                )
                .unwrap(),
            },
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            1,
            arkret_sdk::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            payload,
        )
        .unwrap()
    }

    #[test]
    fn strand_patch_recovers_every_authored_encrypted_field() {
        let event = event(
            arkret_wire::event_kind_str::STRAND_UPDATE,
            json!({
                "target_ref": "ak:strand:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN",
                "patch": {
                    "encrypted_content": {"$op": "set", "value": envelope(1)},
                    "tracks.synthesis.encrypted_content": envelope(2),
                    "metadata.fields.calendar": {"$op": "set", "value": {"location": envelope(3)}},
                    "metadata.summary": {"$op": "unset"},
                    "metadata.fields.removed": {"$op": "remove", "value": envelope(4)},
                }
            }),
        );
        let mut counters = encrypted_event_fields(&event)
            .iter()
            .map(|value| value.encryption_context.counter().unwrap())
            .collect::<Vec<_>>();
        counters.sort();
        assert_eq!(counters, [1, 2, 3]);
    }

    #[test]
    fn canonical_create_and_message_carriers_are_discovered() {
        let create = event(
            arkret_wire::event_kind_str::STRAND_CREATE,
            json!({"object": {
                "encrypted_content": envelope(1),
                "tracks": {"synthesis": {"encrypted_content": envelope(2)}},
            }}),
        );
        assert_eq!(encrypted_event_fields(&create).len(), 2);
        let message = event(
            arkret_wire::event_kind_str::MESSAGE_CREATE,
            json!({
                "content": {"encrypted_content": envelope(3)}
            }),
        );
        assert_eq!(encrypted_event_fields(&message).len(), 1);
    }

    #[test]
    fn unrelated_business_data_and_malformed_envelopes_are_not_history_work() {
        let mut malformed = envelope(1);
        malformed["unregistered"] = json!(true);
        let event = event(
            arkret_wire::event_kind_str::STRAND_UPDATE,
            json!({"patch": {
                "encrypted_content": {"$op": "set", "value": malformed},
                "metadata.fields.example": {"$op": "set", "value": {"example": envelope(2)}},
            }}),
        );
        assert!(encrypted_event_fields(&event).is_empty());
    }
}
