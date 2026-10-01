//! Account-local quarantine for retired producer Event records.
//!
//! Never rewrite a signed legacy Event into the current wire contract. Only
//! known local containers are separated; unrelated decode errors remain fatal.

use serde_json::Value;

use super::ClientLocalState;

fn retired_event(event: &Value) -> bool {
    event.get("actor_seq").and_then(Value::as_u64).is_some()
        && event.get("event_id").and_then(Value::as_str).is_some()
        && event.get("kind").and_then(Value::as_str).is_some()
}

fn retired_genesis(record: &Value) -> bool {
    record
        .pointer("/pcr_genesis_unit/events")
        .and_then(Value::as_array)
        .is_some_and(|events| events.iter().any(retired_event))
}

pub(super) fn decode_account_state(bytes: &[u8]) -> serde_json::Result<ClientLocalState> {
    let original_error = match serde_json::from_slice(bytes) {
        Ok(state) => return Ok(state),
        Err(error) => error,
    };
    let mut value: Value = serde_json::from_slice(bytes)?;
    let Some(object) = value.as_object_mut() else {
        return Err(original_error);
    };
    let mut retired = serde_json::Map::new();
    for field in ["verified_poll_inputs", "verified_reaction_assertions"] {
        if let Some(records) = object.get_mut(field).and_then(Value::as_array_mut) {
            let old = records
                .iter()
                .filter(|record| record.get("event").is_some_and(retired_event))
                .cloned()
                .collect::<Vec<_>>();
            if !old.is_empty() {
                records.retain(|record| !record.get("event").is_some_and(retired_event));
                retired.insert(field.to_owned(), Value::Array(old));
            }
        }
    }
    if let Some(records) = object
        .get_mut("historical_agent_event_candidates")
        .and_then(Value::as_object_mut)
    {
        let old = records
            .iter()
            .filter(|(_, record)| record.get("accepted_event").is_some_and(retired_event))
            .map(|(key, record)| (key.clone(), record.clone()))
            .collect::<serde_json::Map<_, _>>();
        for key in old.keys() {
            records.remove(key);
        }
        if !old.is_empty() {
            retired.insert(
                "historical_agent_event_candidates".to_owned(),
                Value::Object(old),
            );
        }
    }
    for field in [
        "pending_principal_registration",
        "recovery_material_evidence",
    ] {
        if object.get(field).is_some_and(retired_genesis) {
            // Preserve the complete checkpoint, including accepted stage and
            // receipts. It cannot authorize setup or be retried on the wire.
            let old = object.insert(field.to_owned(), Value::Null).unwrap();
            retired.insert(field.to_owned(), old);
        }
    }
    if retired.is_empty() {
        return Err(original_error);
    }
    if retired.contains_key("verified_poll_inputs") {
        // A retained prefix must not attest completeness after its original
        // inputs have been separated. A fresh verified scan rebuilds it.
        if let Some(prefixes) = object.insert(
            "verified_poll_prefixes".to_owned(),
            Value::Object(Default::default()),
        ) {
            retired.insert("verified_poll_prefixes".to_owned(), prefixes);
        }
    }
    let archive = object
        .entry("retired_event_records")
        .or_insert_with(|| Value::Object(Default::default()));
    let Some(archive) = archive.as_object_mut() else {
        return Err(original_error);
    };
    for (key, record) in retired {
        // A conflicting archive must not overwrite the only original copy.
        if archive.get(&key).is_some_and(|stored| stored != &record) {
            return Err(original_error);
        }
        archive.insert(key, record);
    }
    let state: ClientLocalState = serde_json::from_value(value)?;
    tracing::warn!(
        fields = ?state.retired_event_records.keys().collect::<Vec<_>>(),
        "retired local Event records preserved outside current account evidence"
    );
    Ok(state)
}

#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
pub(crate) async fn run_browser_retired_account_contract() -> anyhow::Result<()> {
    use super::LocalStateStore;
    use crate::secure_key_store::SecureKeyStore;
    crate::secure_key_store::ensure_wasm_secure_key_store_ready("inkson").await?;
    let namespace = format!("retired-account-test-{}", js_sys::Date::now());
    let key = super::account_state_key(&namespace);
    let mut original = serde_json::to_value(ClientLocalState::default())?;
    original["primary_handle"] = serde_json::json!("alice");
    original["verified_poll_inputs"] = serde_json::json!([{
        "accepted_ref": {"original": "receipt"},
        "event": {"event_id": "original-event", "kind": "ak.message.create", "actor_seq": 7,
            "producer_proof": {"original": "signed-bytes"}}
    }]);
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    secure
        .store_secret_durable(&key, &original.to_string())
        .await?;
    let store = LocalStateStore::default();
    let state = store
        .read_account_state(&namespace)
        .ok_or_else(|| anyhow::anyhow!("browser account read failed"))?;
    anyhow::ensure!(state.primary_handle == "alice" && store.persist_error().is_none());
    anyhow::ensure!(state.verified_poll_inputs.is_empty());
    anyhow::ensure!(
        state.retired_event_records["verified_poll_inputs"] == original["verified_poll_inputs"]
    );
    super::account_persist::enqueue_account_state_persist_barrier(
        key.clone(),
        serde_json::to_string(&state)?,
    )?
    .wait()
    .await?;
    let reopened = crate::secure_key_store::IndexedDbSecureKeyStore::new_async("inkson").await?;
    let stored = reopened
        .read_secret_bytes_durable(&key)
        .await?
        .ok_or_else(|| anyhow::anyhow!("durable migrated account missing"))?;
    anyhow::ensure!(decode_account_state(&stored)? == state);
    anyhow::ensure!(
        web_sys::window()
            .unwrap()
            .local_storage()
            .unwrap()
            .unwrap()
            .get_item(&key)
            .unwrap()
            .is_none()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{LocalStateStore, VerifiedPollInput};
    use super::*;

    fn current_record() -> Value {
        let realm_id = arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [31; 32],
        ));
        let event = arkret_sdk::Event {
            event_id: arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [32; 32]),
            kind: arkret_sdk::EventKind::MessageCreate,
            realm_id: realm_id.clone(),
            scope_ref: arkret_sdk::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            actor_id: arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            )),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            created_at: "2026-10-01T00:00:00Z".parse().unwrap(),
            semantic_refs: Vec::new(),
            payload: Default::default(),
            producer_proof: None,
        };
        serde_json::to_value(VerifiedPollInput {
            accepted_ref: arkret_wire::CommittedEventRef {
                event_id: event.event_id.clone(),
                commit_id: arkret_sdk::RealmCommitId::from_digest([33; 32]),
                stream_ref: arkret_sdk::CommitStreamRef::Realm { realm_id },
                stream_position: 1,
            },
            event,
        })
        .unwrap()
    }

    fn legacy_record() -> Value {
        let mut record = current_record();
        record["event"]["actor_seq"] = serde_json::json!(7);
        record["event"]["prev_refs"] = serde_json::json!(["original-signed-reference"]);
        record["event"]["producer_proof"] = serde_json::json!({"original": "signed-bytes"});
        record
    }

    fn legacy_account() -> Value {
        let mut state = serde_json::to_value(ClientLocalState::default()).unwrap();
        state["primary_handle"] = serde_json::json!("alice");
        state["plain_local_data"] = serde_json::json!({"ui.preference": "retained"});
        state["verified_poll_inputs"] = serde_json::json!([legacy_record(), current_record()]);
        state
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn retired_account_events_are_archived_without_rewriting_or_losing_current_records() {
        let original = legacy_account();
        let decoded = decode_account_state(&serde_json::to_vec(&original).unwrap()).unwrap();
        assert_eq!(decoded.primary_handle, "alice");
        assert_eq!(decoded.plain_local_data["ui.preference"], "retained");
        assert_eq!(decoded.verified_poll_inputs.len(), 1);
        assert_eq!(
            serde_json::to_value(&decoded.verified_poll_inputs[0]).unwrap(),
            current_record()
        );
        assert_eq!(
            decoded.retired_event_records["verified_poll_inputs"],
            serde_json::json!([legacy_record()])
        );
        assert!(
            serde_json::from_value::<arkret_sdk::Event>(legacy_record()["event"].clone()).is_err()
        );
        let reloaded = decode_account_state(&serde_json::to_vec(&decoded).unwrap()).unwrap();
        assert_eq!(decoded, reloaded);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn retired_account_authoritative_checkpoints_remain_opaque_and_cannot_resume() {
        let mut original = legacy_account();
        for field in [
            "pending_principal_registration",
            "recovery_material_evidence",
        ] {
            original[field] = serde_json::json!({
                "stage": "accepted", "device_id": "original-device",
                "pcr_genesis_commits": ["exact-original-receipts"],
                "pcr_genesis_unit": {"events": [legacy_record()["event"], current_record()["event"]]}
            });
        }
        let decoded = decode_account_state(&serde_json::to_vec(&original).unwrap()).unwrap();
        assert!(decoded.pending_principal_registration.is_none());
        assert!(decoded.recovery_material_evidence.is_none());
        for field in [
            "pending_principal_registration",
            "recovery_material_evidence",
        ] {
            assert_eq!(decoded.retired_event_records[field], original[field]);
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn retired_account_quarantine_does_not_mask_other_corruption() {
        let mut original = legacy_account();
        original["sync_cursor"] = serde_json::json!(42);
        assert!(decode_account_state(&serde_json::to_vec(&original).unwrap()).is_err());
        assert!(decode_account_state(b"{truncated").is_err());
        original = legacy_account();
        original["verified_poll_inputs"] = serde_json::json!([current_record()]);
        original["verified_poll_inputs"][0]["event"]["unexpected_current_field"] =
            serde_json::json!(7);
        assert!(decode_account_state(&serde_json::to_vec(&original).unwrap()).is_err());
        original = legacy_account();
        original["retired_event_records"] =
            serde_json::json!({"verified_poll_inputs": ["different-original"]});
        assert!(decode_account_state(&serde_json::to_vec(&original).unwrap()).is_err());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn retired_account_native_read_recovers_prior_quarantine_and_keeps_archive_on_flush() {
        let root = std::env::temp_dir().join(format!(
            "inkson-retired-account-{}.json",
            crate::operation::uuid_v7()
        ));
        let mut store = LocalStateStore::with_path(root);
        let path = store.account_state_path(super::super::ANONYMOUS_ACCOUNT_NAMESPACE);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let bytes = serde_json::to_vec(&legacy_account()).unwrap();
        let original_path = path.with_extension("corrupt");
        std::fs::write(&original_path, &bytes).unwrap();
        let state = store.load();
        assert_eq!(state.primary_handle, "alice");
        assert!(store.persist_error().is_none());
        store.save(state.clone());
        assert!(store.persist_error().is_none());
        assert_eq!(std::fs::read(&original_path).unwrap(), bytes);
        let reopened = LocalStateStore::with_path(store.path.clone());
        assert_eq!(reopened.load(), state);
        let mut reset = reopened;
        reset.clear_account_scoped();
        assert_eq!(
            reset.load().retired_event_records,
            state.retired_event_records
        );
    }
}
