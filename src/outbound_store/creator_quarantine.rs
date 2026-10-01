//! Quarantine authenticated creator inconsistencies before a queue mutation.

use arkret_models_collaboration::mls_creator_bootstrap::{
    MlsCreatorBootstrapInvariant, MlsCreatorBootstrapKnownGenesis,
};
use serde_json::Value;

use super::*;

fn original_attempt(mut raw: &Value) -> &Value {
    while let Some(inner) = raw
        .get("rejected_record")
        .or_else(|| raw.get("loser_record"))
    {
        raw = inner;
    }
    raw
}

pub(super) fn belongs_to_attempt(
    item: &Value,
    intent: &MlsCreatorBootstrapIntent,
    raw: &Value,
) -> bool {
    let id = item.pointer("/submission/event_id").and_then(Value::as_str);
    if id == Some(intent.scope_create_event_id().as_str())
        || id.is_some_and(|id| {
            original_attempt(raw)
                .pointer("/queued_genesis/outbound_queue_item_id")
                .and_then(Value::as_str)
                == Some(id)
        })
    {
        return true;
    }
    let matches = |event: &Value| {
        let scope = event
            .get("scope_ref")
            .cloned()
            .and_then(|value| serde_json::from_value::<arkret_sdk::ScopeRef>(value).ok());
        let actor = event
            .get("actor_id")
            .cloned()
            .and_then(|value| serde_json::from_value::<arkret_sdk::ActorId>(value).ok());
        scope.as_ref() == Some(intent.effective_scope())
            && actor.as_ref() == Some(intent.owner_actor_id())
    };
    let Some(request) = item.pointer("/submission/request") else {
        return false;
    };
    request.get("event").is_some_and(&matches)
        || request.get("commit_event").is_some_and(&matches)
        || request
            .pointer("/event_submission/event")
            .is_some_and(&matches)
        || request
            .get("events")
            .and_then(Value::as_array)
            .is_some_and(|events| {
                events
                    .iter()
                    .filter_map(|submission| submission.get("event"))
                    .any(matches)
            })
}

fn scope_matches(value: &Value, intent: &MlsCreatorBootstrapIntent) -> bool {
    value
        .get("effective_scope")
        .cloned()
        .and_then(|scope| serde_json::from_value::<arkret_sdk::ScopeRef>(scope).ok())
        .as_ref()
        == Some(intent.effective_scope())
}

fn known_original(record: &MlsCreatorBootstrapRecord) -> Option<MlsCreatorBootstrapKnownGenesis> {
    let accepted = record.accepted_genesis()?;
    let queued = record.queued_genesis()?;
    accepted.validate_binding(record.intent(), queued).ok()?;
    Some(MlsCreatorBootstrapKnownGenesis::Original {
        acceptance: Box::new(accepted.clone()),
    })
}

fn known_original_raw(raw: &Value) -> Option<MlsCreatorBootstrapKnownGenesis> {
    use arkret_models_collaboration::mls_creator_bootstrap::{
        MlsCreatorBootstrapAcceptedGenesis, MlsCreatorBootstrapQueuedGenesis,
    };
    let intent: MlsCreatorBootstrapIntent =
        serde_json::from_value(raw.get("intent")?.clone()).ok()?;
    let original = original_attempt(raw);
    let queued: MlsCreatorBootstrapQueuedGenesis =
        serde_json::from_value(original.get("queued_genesis")?.clone()).ok()?;
    let acceptance: MlsCreatorBootstrapAcceptedGenesis =
        serde_json::from_value(original.get("accepted_genesis")?.clone()).ok()?;
    acceptance.validate_binding(&intent, &queued).ok()?;
    Some(MlsCreatorBootstrapKnownGenesis::Original {
        acceptance: Box::new(acceptance),
    })
}

fn quarantine_raw(
    raw: Value,
    items: &mut Vec<Value>,
    index: &mut Vec<Value>,
    invariant: MlsCreatorBootstrapInvariant,
    detail: String,
    known: Option<MlsCreatorBootstrapKnownGenesis>,
) -> garth::Result<Value> {
    quarantine_records(vec![raw], items, index, invariant, detail, known)
}

fn quarantine_records(
    records: Vec<Value>,
    items: &mut Vec<Value>,
    index: &mut Vec<Value>,
    invariant: MlsCreatorBootstrapInvariant,
    detail: String,
    known: Option<MlsCreatorBootstrapKnownGenesis>,
) -> garth::Result<Value> {
    let raw = &records[0];
    let intent: MlsCreatorBootstrapIntent =
        serde_json::from_value(raw.get("intent").cloned().ok_or_else(|| {
            garth::Error::Storage("creator inconsistency has no authenticated intent".into())
        })?)?;
    intent.validate()?;
    let recovery = items
        .iter()
        .filter(|item| {
            records
                .iter()
                .any(|raw| belongs_to_attempt(item, &intent, raw))
        })
        .cloned()
        .collect();
    let quarantined = MlsCreatorBootstrapRecord::quarantine_authenticated_records(
        records.clone(),
        recovery,
        invariant,
        detail,
        known,
        crate::clock::now_utc_canonical(),
    )?;
    let mut stopped = Vec::with_capacity(items.len());
    for item in std::mem::take(items) {
        if !records
            .iter()
            .any(|raw| belongs_to_attempt(&item, &intent, raw))
        {
            stopped.push(item);
            continue;
        }
        // Keep valid frozen requests, including scheduled bindings, stopped.
        // An undecodable request survives only in the opaque diagnostic.
        if let Ok(mut typed) = serde_json::from_value::<garth::SendQueueItem>(item) {
            if !typed.status.is_terminal() {
                typed.status = garth::SendQueueStatus::Cancelled;
                typed.settled_at = Some(crate::clock::now_utc_canonical());
            }
            stopped.push(serde_json::to_value(typed)?);
        }
    }
    *items = stopped;
    index.retain(|entry| !scope_matches(entry, &intent));
    serde_json::to_value(quarantined).map_err(|error| garth::Error::Storage(error.to_string()))
}

pub(super) fn stop_creator(
    state: &mut DurableOutboundState,
    position: usize,
    invariant: MlsCreatorBootstrapInvariant,
    detail: String,
    known: Option<MlsCreatorBootstrapKnownGenesis>,
) -> garth::Result<()> {
    let raw = serde_json::to_value(&state.creator_bootstrap_records[position])?;
    let mut items = serde_json::to_value(&state.items)?
        .as_array()
        .expect("serialized queue array")
        .clone();
    let mut index = serde_json::to_value(&state.creator_ready_index)?
        .as_array()
        .expect("serialized index array")
        .clone();
    let diagnostic = quarantine_raw(raw, &mut items, &mut index, invariant, detail, known)?;
    state.creator_bootstrap_records[position] = serde_json::from_value(diagnostic)?;
    state.items = serde_json::from_value(Value::Array(items))?;
    state.creator_ready_index = serde_json::from_value(Value::Array(index))?;
    Ok(())
}

/// Decode only an already-authenticated local vault. Unknown coordinates or
/// unrelated corruption stay opaque and are never replaced by an empty store.
/// A true result requires the caller to commit the quarantine before returning
/// an error; it must not execute the requested queue mutation in that cut.
pub(super) fn decode_for_recovery(
    raw: Option<&str>,
    authority: Option<&arkret_sdk::AccountId>,
) -> garth::Result<(DurableOutboundState, bool, bool)> {
    let Some(raw) = raw else {
        return Ok((DurableOutboundState::default(), false, false));
    };
    let mut value: Value = serde_json::from_str(raw).map_err(|error| {
        garth::Error::Storage(format!("decode authenticated outbound vault: {error}"))
    })?;
    let root = value
        .as_object_mut()
        .ok_or_else(|| garth::Error::Storage("outbound vault is not an object".into()))?;
    // The old SendQueueSnapshot also kept a top-level sequence counter, even
    // for empty queues. Archive it without giving it any current queue meaning.
    // Tagged old snapshots have one known schema marker too. Do not accept a
    // different schema or an incomplete tagged snapshot as an old queue.
    if let Some(schema) = root.get("schema").cloned() {
        if schema.as_str() != Some("org.arkret.garth.send_queue.v1")
            || !root.contains_key("next_sequence")
        {
            return Err(garth::Error::Storage(
                "unknown or incomplete retired ingress snapshot schema".into(),
            ));
        }
        if let Some(archived) = root.get("retired_ingress_schema") {
            if archived != &schema {
                return Err(garth::Error::Storage(
                    "retired ingress schema diagnostics conflict".into(),
                ));
            }
        } else {
            root.insert("retired_ingress_schema".into(), schema);
        }
        root.remove("schema");
    }
    // Only the known u64 counter is retired; other unknown fields still fail.
    let retired_sequence = if let Some(sequence) = root.remove("next_sequence") {
        if sequence.as_u64().is_none() {
            return Err(garth::Error::Storage(
                "retired ingress next_sequence is not a u64".into(),
            ));
        }
        if let Some(archived) = root.get("retired_ingress_next_sequence") {
            if archived != &sequence {
                return Err(garth::Error::Storage(
                    "retired ingress sequence diagnostics conflict".into(),
                ));
            }
        } else {
            root.insert("retired_ingress_next_sequence".into(), sequence);
        }
        true
    } else {
        false
    };
    let records_value = root
        .remove("creator_bootstrap_records")
        .unwrap_or_else(|| Value::Array(vec![]));
    let mut records: Vec<Value> = serde_json::from_value(records_value)?;
    let mut items: Vec<Value> = serde_json::from_value(
        root.remove("items")
            .ok_or_else(|| garth::Error::Storage("outbound vault lost its queue".into()))?,
    )?;
    let mut index: Vec<Value> = serde_json::from_value(
        root.remove("creator_ready_index")
            .unwrap_or_else(|| Value::Array(vec![])),
    )?;
    // The removed ingress queue stored records and leases, not frozen
    // authority submissions. Preserve its bytes as diagnostics, without
    // interpreting its status or upgrading ingress receipts into acceptance.
    // Unknown damage to the current queue must still fail closed below.
    let mut retired_items: Vec<Value> = serde_json::from_value(
        root.remove("retired_ingress_items")
            .unwrap_or_else(|| Value::Array(vec![])),
    )?;
    let original_retired_count = retired_items.len();
    items.retain(|item| {
        let is_ingress_record = item.get("submission").is_none()
            && item.get("record").is_some_and(Value::is_object)
            && item.get("transaction_id").is_some_and(Value::is_string)
            && item
                .get("canonical_payload_bytes")
                .is_some_and(Value::is_array);
        if is_ingress_record {
            retired_items.push(item.clone());
        }
        !is_ingress_record
    });
    let retired = retired_items.len() != original_retired_count || retired_sequence;
    root.insert(
        "retired_ingress_items".into(),
        serde_json::to_value(retired_items)?,
    );
    let mut quarantined = false;
    let intents: Vec<MlsCreatorBootstrapIntent> = records
        .iter()
        .map(|record| {
            let intent: MlsCreatorBootstrapIntent =
                serde_json::from_value(record.get("intent").cloned().ok_or_else(|| {
                    garth::Error::Storage("creator vault has unknown logical coordinates".into())
                })?)?;
            intent.validate()?;
            if authority
                .is_some_and(|authority| intent.owner_actor_id().as_account_id() != Some(authority))
            {
                return Err(garth::Error::Storage(
                    "creator record belongs to another account vault".into(),
                ));
            }
            Ok(intent)
        })
        .collect::<garth::Result<_>>()?;
    let mut grouped = Vec::new();
    let mut used = vec![false; records.len()];
    for position in 0..records.len() {
        if used[position] {
            continue;
        }
        let mut originals = vec![];
        for candidate in position..records.len() {
            if intents[candidate].effective_scope() == intents[position].effective_scope() {
                used[candidate] = true;
                originals.push(records[candidate].clone());
            }
        }
        if originals.len() > 1 {
            let known = known_original_raw(&originals[0]);
            grouped.push(quarantine_records(
                originals,
                &mut items,
                &mut index,
                MlsCreatorBootstrapInvariant::RecordBinding,
                "multiple authenticated creator records disagree on the unique logical key".into(),
                known,
            )?);
            quarantined = true;
        } else {
            grouped.extend(originals);
        }
    }
    records = grouped;
    for raw_record in &mut records {
        let intent: MlsCreatorBootstrapIntent =
            serde_json::from_value(raw_record.get("intent").cloned().ok_or_else(|| {
                garth::Error::Storage("creator vault has unknown logical coordinates".into())
            })?)?;
        intent.validate()?;
        if authority
            .is_some_and(|authority| intent.owner_actor_id().as_account_id() != Some(authority))
        {
            return Err(garth::Error::Storage(
                "creator record belongs to another account vault".into(),
            ));
        }
        let typed = serde_json::from_value::<MlsCreatorBootstrapRecord>(raw_record.clone());
        let (failure, known) = match typed {
            Ok(record) => (
                record.validate().err().map(|error| error.to_string()),
                known_original(&record),
            ),
            Err(error) => (
                Some(format!("decode creator recovery unit: {error}")),
                known_original_raw(raw_record),
            ),
        };
        if let Some(detail) = failure {
            *raw_record = quarantine_raw(
                raw_record.clone(),
                &mut items,
                &mut index,
                MlsCreatorBootstrapInvariant::RecordBinding,
                detail,
                known,
            )?;
            quarantined = true;
        }
    }
    root.insert("items".into(), serde_json::to_value(items)?);
    root.insert(
        "creator_bootstrap_records".into(),
        serde_json::to_value(records)?,
    );
    root.insert("creator_ready_index".into(), serde_json::to_value(index)?);
    let mut state: DurableOutboundState = serde_json::from_value(value)?;
    if state.validate().is_err() {
        for position in 0..state.creator_bootstrap_records.len() {
            let record = &state.creator_bootstrap_records[position];
            if record.quarantine_diagnostic().is_some() {
                continue;
            }
            // On a failed read only, isolate each logical record against its
            // actual queue and index. Healthy scopes never lose their entries.
            let isolated = DurableOutboundState {
                items: state.items.clone(),
                creator_bootstrap_records: vec![record.clone()],
                creator_realm_discussions: state
                    .creator_realm_discussions
                    .iter()
                    .filter(|(realm, _)| {
                        record.intent().effective_scope()
                            == &arkret_sdk::ScopeRef::Realm {
                                realm_id: (*realm).clone(),
                            }
                    })
                    .map(|(realm, plan)| {
                        (
                            realm.clone(),
                            creator_discussion::CreatorRealmDiscussion::clone(plan),
                        )
                    })
                    .collect(),
                creator_ready_index: state
                    .creator_ready_index
                    .iter()
                    .filter(|receipt| {
                        receipt.effective_scope() == record.intent().effective_scope()
                    })
                    .cloned()
                    .collect(),
                commit_position: state.commit_position,
                ..Default::default()
            };
            let Err(error) = isolated.validate() else {
                continue;
            };
            let invariant = if record.ready_receipt().is_some_and(|receipt| {
                isolated.creator_ready_index != vec![receipt.clone()]
                    || receipt.ready_commit_position() > state.commit_position
            }) {
                MlsCreatorBootstrapInvariant::ReadyIndex
            } else {
                MlsCreatorBootstrapInvariant::QueueBinding
            };
            let raw = serde_json::to_value(record)?;
            let known = known_original(record);
            let mut items = serde_json::to_value(&state.items)?
                .as_array()
                .expect("serialized queue array")
                .clone();
            let mut index = serde_json::to_value(&state.creator_ready_index)?
                .as_array()
                .expect("serialized index array")
                .clone();
            let diagnostic = quarantine_raw(
                raw,
                &mut items,
                &mut index,
                invariant,
                error.to_string(),
                known,
            )?;
            state.creator_bootstrap_records[position] = serde_json::from_value(diagnostic)?;
            state.items = serde_json::from_value(Value::Array(items))?;
            state.creator_ready_index = serde_json::from_value(Value::Array(index))?;
            quarantined = true;
        }
    }
    // Unrelated malformed queue data still fails closed. No partial repair is
    // persisted unless the entire replacement vault is valid.
    state.validate()?;
    Ok((state, quarantined, retired))
}
