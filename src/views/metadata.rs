//! Personal display of authenticated standard Space and Strand metadata.

use serde_json::Value;

use crate::state::LocalStateStore;

pub(crate) fn open_metadata(
    store: &LocalStateStore,
    realm: &str,
    id: &str,
    envelope: &arkret_sdk::EncryptedEnvelope,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
) -> Option<Value> {
    let digest = envelope.payload_digest().ok()?;
    let path = format!("encrypted_metadata:{digest}");
    let local = store
        .private_plaintext_for(realm, id, &path)
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .or_else(|| {
            store
                .mls_decrypted_plaintext_for(realm, digest.as_str())
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        });
    let opened = local.or_else(|| {
        let cipher = serde_json::to_value(envelope).ok()?;
        let snapshot = store.load();
        let event = snapshot.raw_operations.iter().find_map(|record| {
            let event = record.payload.get("event").unwrap_or(&record.payload);
            let body = event.get("payload")?;
            let target = body.get("target_ref").or_else(|| body.get("space_id"));
            let creation = event
                .get("event_id")
                .and_then(Value::as_str)
                .and_then(|id| arkret_sdk::EventId::new(id).ok())
                .is_some_and(|event_id| match event.get("kind").and_then(Value::as_str) {
                    Some("ak.space.create") => {
                        arkret_sdk::SpaceId::from_event_id(&event_id).as_str() == id
                    }
                    Some("ak.strand.create") => {
                        arkret_sdk::StrandId::from_event_id(&event_id).as_str() == id
                    }
                    _ => false,
                });
            let candidate = body
                .pointer("/object/encrypted_metadata")
                .or_else(|| body.pointer("/patch/encrypted_metadata/value"));
            ((creation || target.and_then(Value::as_str) == Some(id)) && candidate == Some(&cipher))
                .then_some(event)
        })?;
        let signed: arkret_sdk::Event = serde_json::from_value(event.clone()).ok()?;
        if signed.realm_id.as_str() != realm {
            return None;
        }
        let sender = crate::views::chat::verified_chat_sender_domain_for_realm(
            realm,
            event,
            Some(store),
            Some((account, account.principal_id.as_str(), device)),
        )?;
        let payload = crate::mls::runtime::encrypted_payload_from_verified_event_context(
            store,
            envelope,
            &signed.scope_ref,
            signed.kind.as_str(),
            &sender,
            None,
        )?;
        let secure = crate::secure_key_store::default_secure_key_store("inkson");
        let bytes =
            crate::mls::runtime::decrypt_application_payload_for_scope_from_verified_sender(
                store,
                secure.as_ref(),
                realm,
                account,
                device,
                &payload,
                &signed.scope_ref,
                &sender,
            )?;
        serde_json::from_slice(&bytes).ok()
    })?;
    if id.starts_with("ak:space:") {
        let metadata: arkret_sdk::SpaceMetadata = serde_json::from_value(opened).ok()?;
        metadata.validate().ok()?;
        serde_json::to_value(metadata).ok()
    } else {
        let metadata: arkret_sdk::StrandMetadata = serde_json::from_value(opened).ok()?;
        arkret_models_collaboration::objects::productivity::validate_calendar_event_metadata_fields(&metadata.fields).ok()?;
        serde_json::to_value(metadata).ok()
    }
}

pub(crate) fn current_metadata(
    store: &LocalStateStore,
    realm: &str,
    id: &str,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
) -> Option<Value> {
    let entries = store.realm_current_state_entries(realm);
    let mut values = entries.iter().filter_map(|entry| {
        let arkret_sdk::TypedCurrentResult::Value {
            selector, value, ..
        } = entry;
        let target = match selector {
            arkret_sdk::CurrentSelector::Space { space_id } => space_id.as_str(),
            arkret_sdk::CurrentSelector::Strand { strand_id } => strand_id.as_str(),
            _ => return None,
        };
        (target == id).then_some(value)
    });
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let envelope = serde_json::from_value(value.get("encrypted_metadata")?.clone()).ok()?;
    let opened = open_metadata(store, realm, id, &envelope, account, device)?;
    if id.starts_with("ak:strand:") {
        let mut strand: arkret_sdk::Strand = serde_json::from_value(value.clone()).ok()?;
        strand.encrypted_metadata = None;
        strand.metadata = Some(serde_json::from_value(opened.clone()).ok()?);
        strand.validate_profile_activation().ok()?;
    }
    Some(opened)
}

pub(crate) fn current_title(
    store: &LocalStateStore,
    realm: &str,
    id: &str,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
) -> Option<String> {
    current_metadata(store, realm, id, account, device)?
        .get("title")?
        .as_str()
        .map(str::to_owned)
}
