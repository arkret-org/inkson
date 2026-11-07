//! Host decryption and sender evidence for standard Space and Strand metadata.

use serde_json::Value;

use crate::state::LocalStateStore;

/// Run only after the accepted projection transaction and its durability
/// barrier. A refused installation must not consume an MLS receive key.
pub(crate) fn retain_accepted_page_metadata(
    store: &LocalStateStore,
    page: &impl crate::transport::own_station_results::AcceptedPageRows,
) -> Result<(), String> {
    let Some(endpoint) = crate::secure_key_store::active_device_seed_scope() else {
        return Ok(());
    };
    if store.active_authority().as_ref() != Some(&endpoint.authority)
        || page
            .accepted_account()
            .is_some_and(|account| account != &endpoint.authority)
    {
        return Err("metadata page belongs to another active account".into());
    }
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    for row in page.accepted_rows()? {
        if let arkret_sdk::CommittedEventView::Full(full) = row {
            retain_accepted_metadata(
                store,
                &full.event,
                &endpoint.authority,
                &endpoint.device_id,
                secure.as_ref(),
            );
        }
    }
    Ok(())
}

/// Consume metadata while its accepted Event is received, before later
/// application messages can evict its skipped MLS generation. Rendering must
/// not decide which application keys survive in the durable receive chain.
pub(crate) fn retain_accepted_metadata(
    store: &LocalStateStore,
    event: &arkret_sdk::Event,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    secure: &dyn crate::secure_key_store::SecureKeyStore,
) {
    if !matches!(
        event.kind,
        arkret_sdk::EventKind::SpaceCreate
            | arkret_sdk::EventKind::SpaceUpdate
            | arkret_sdk::EventKind::StrandCreate
            | arkret_sdk::EventKind::StrandUpdate
    ) {
        return;
    }
    let Ok(original) = serde_json::to_value(event) else {
        return;
    };
    let Some(body) = original.get("payload") else {
        return;
    };
    let Some(value) = body
        .pointer("/object/encrypted_metadata")
        .or_else(|| body.pointer("/patch/encrypted_metadata/value"))
    else {
        return;
    };
    let Ok(envelope) = serde_json::from_value::<arkret_sdk::EncryptedEnvelope>(value.clone())
    else {
        return;
    };
    let Some(sender) = crate::identity::committed_sender::verified_chat_sender_domain_for_realm(
        event.realm_id.as_str(),
        &original,
        Some(store),
        Some((account, account.principal_id.as_str(), device)),
    ) else {
        return;
    };
    let Some(payload) = crate::mls::runtime::encrypted_payload_from_verified_event_context(
        store,
        &envelope,
        &event.scope_ref,
        event.kind.as_str(),
        &sender,
        None,
    ) else {
        return;
    };
    // The runtime atomically retains the advanced chain and the exact digest's
    // plaintext. Failure leaves metadata pending and never installs structure.
    let _ = crate::mls::runtime::decrypt_application_payload_for_scope_from_verified_sender(
        store,
        secure,
        event.realm_id.as_str(),
        account,
        device,
        &payload,
        &event.scope_ref,
        &sender,
    );
}

fn observe_open_gate(digest: &arkret_sdk::Hash, gate: &'static str, passed: bool) {
    #[cfg(any(
        feature = "spec-conformance",
        all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test")
    ))]
    tracing::warn!(phase = "metadata_open_gate", payload_digest = %digest, gate, passed,
        "encrypted metadata admission boundary");
    #[cfg(not(any(
        feature = "spec-conformance",
        all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test")
    )))]
    let _ = (digest, gate, passed);
}

fn current_metadata_context(
    store: &LocalStateStore,
    realm: &str,
    id: &str,
    envelope: &arkret_sdk::EncryptedEnvelope,
) -> Option<(arkret_sdk::ScopeRef, arkret_wire::CalendarMetadataContext)> {
    let realm_id: arkret_sdk::RealmId = realm.parse().ok()?;
    let strand_id: arkret_sdk::StrandId = id.parse().ok()?;
    let entries = store.realm_current_state_entries(realm);
    let mut strands = entries.iter().filter_map(|entry| {
        let arkret_wire::CurrentState::Value { selector, source_stream_ref, revision, value } = entry;
        matches!(selector, arkret_wire::CurrentSelector::Strand { strand_id: target } if target == &strand_id).then_some((source_stream_ref, revision, value))
    });
    let (stream, revision, strand) = strands.next()?;
    if strands.next().is_some()
        || strand.get("encrypted_metadata")? != &serde_json::to_value(envelope).ok()?
    {
        return None;
    }
    let mut sources = entries.iter().filter_map(|entry| {
        let arkret_wire::CurrentState::Value { selector, source_stream_ref, revision, value } = entry;
        matches!(selector, arkret_wire::CurrentSelector::CalendarScheduleSource { strand_id: target } if target == &strand_id).then_some((source_stream_ref, revision, value))
    });
    let (source_stream, source_revision, value) = sources.next()?;
    if sources.next().is_some() || source_stream != stream || source_revision != revision {
        return None;
    }
    let source: arkret_wire::CalendarScheduleSourceValue =
        serde_json::from_value(value.clone()).ok()?;
    source
        .validate_for_current(&realm_id, stream, revision)
        .ok()?;
    let context = source.metadata_context?;
    if context.payload_digest != envelope.payload_digest().ok()? {
        return None;
    }
    Some((source.effective_scope, context))
}

pub(crate) fn open_metadata(
    store: &LocalStateStore,
    realm: &str,
    id: &str,
    envelope: &arkret_sdk::EncryptedEnvelope,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
) -> Option<Value> {
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    open_metadata_with_secure_store(store, realm, id, envelope, account, device, secure.as_ref())
}

pub(crate) fn open_metadata_with_secure_store(
    store: &LocalStateStore,
    realm: &str,
    id: &str,
    envelope: &arkret_sdk::EncryptedEnvelope,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    secure: &dyn crate::secure_key_store::SecureKeyStore,
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
    observe_open_gate(&digest, "cache", local.is_some());
    let opened = local.or_else(|| {
        if let Some((scope, context)) = current_metadata_context(store, realm, id, envelope) {
            let sender =
                arkret_models_crypto::mls_basic_credential_identity(&context.signer_id).ok()?;
            let payload = crate::mls::runtime::encrypted_payload_from_verified_event_context(
                store,
                envelope,
                &scope,
                context.event_kind.as_str(),
                &sender,
                None,
            )?;
            let bytes =
                crate::mls::runtime::decrypt_application_payload_for_scope_from_verified_sender(
                    store, secure, realm, account, device, &payload, &scope, &sender,
                )?;
            return serde_json::from_slice(&bytes).ok();
        }
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
                    Some(arkret_wire::CapabilityActionId::SPACE_CREATE) => {
                        arkret_sdk::SpaceId::from_event_id(&event_id).as_str() == id
                    }
                    Some(arkret_wire::CapabilityActionId::STRAND_CREATE) => {
                        arkret_sdk::StrandId::from_event_id(&event_id).as_str() == id
                    }
                    _ => false,
                });
            let candidate = body
                .pointer("/object/encrypted_metadata")
                .or_else(|| body.pointer("/patch/encrypted_metadata/value"));
            ((creation || target.and_then(Value::as_str) == Some(id)) && candidate == Some(&cipher))
                .then_some(event)
        });
        observe_open_gate(&digest, "original", event.is_some());
        let event = event?;
        let signed: arkret_sdk::Event = serde_json::from_value(event.clone()).ok()?;
        if signed.realm_id.as_str() != realm {
            return None;
        }
        let sender = crate::identity::committed_sender::verified_chat_sender_domain_for_realm(
            realm,
            event,
            Some(store),
            Some((account, account.principal_id.as_str(), device)),
        );
        observe_open_gate(&digest, "sender", sender.is_some());
        let sender = sender?;
        let payload = crate::mls::runtime::encrypted_payload_from_verified_event_context(
            store,
            envelope,
            &signed.scope_ref,
            signed.kind.as_str(),
            &sender,
            None,
        );
        observe_open_gate(&digest, "context", payload.is_some());
        let payload = payload?;
        let bytes = crate::mls::runtime::decrypt_application_payload_for_scope_from_verified_sender(
            store,
            secure,
            realm,
            account,
            device,
            &payload,
            &signed.scope_ref,
            &sender,
        );
        observe_open_gate(&digest, "decrypt", bytes.is_some());
        let bytes = bytes?;
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
