//! Accepted originals and host decryption for encrypted UI projections.

use arkret_event_draft::EventContentEnvelopesExt as _;
use arkret_sdk::EventPayloadExt as _;
use serde_json::Value;

use crate::state::LocalStateStore;

/// Run only after the accepted projection transaction and its durability
/// barrier. A refused installation must not install decrypted presentation data.
pub(crate) fn retain_accepted_page_encrypted_originals(
    store: &LocalStateStore,
    page: &impl crate::transport::own_station_results::AcceptedPageRows,
) -> Result<(), String> {
    let originals = page
        .accepted_rows()?
        .iter()
        .filter_map(|row| {
            let arkret_sdk::CommittedEventView::Full(full) = row else {
                return None;
            };
            full.event
                .event_content_envelopes()
                .ok()
                .filter(|slots| !slots.is_empty())
                .map(|_| &full.event)
        })
        .collect::<Vec<_>>();
    if originals.is_empty() {
        return Ok(());
    }
    let Some(endpoint) = crate::secure_key_store::active_device_seed_scope() else {
        return Ok(());
    };
    if store.active_authority().as_ref() != Some(&endpoint.authority)
        || page
            .accepted_account()
            .is_some_and(|account| account != &endpoint.authority)
    {
        return Err("encrypted original page belongs to another active account".into());
    }
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    for event in originals {
        retain_accepted_encrypted_original(
            store,
            event,
            &endpoint.authority,
            &endpoint.device_id,
            secure.as_ref(),
        );
    }
    Ok(())
}

/// Retain presentation content from its accepted original and exact frozen encryption
/// header. Reading content never consumes an MLS application message key.
fn retain_accepted_encrypted_original(
    store: &LocalStateStore,
    event: &arkret_sdk::Event,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    secure: &dyn crate::secure_key_store::SecureKeyStore,
) {
    let Ok(carriers) = event.event_content_envelopes() else {
        return;
    };
    if carriers.is_empty() {
        return;
    }
    let Ok(original) = serde_json::to_value(event) else {
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
    store.retain_encrypted_original(event);
    for carrier in carriers {
        let Some(payload) = crate::mls::runtime::encrypted_payload_from_verified_original(
            store,
            secure,
            account,
            device,
            event,
            &carrier.envelope,
            &sender,
        ) else {
            continue;
        };
        // Missing root material keeps the original pending for a later read.
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
}

/// A fixture models the already verified sealed-page boundary separately
/// from Root/AEAD behavior. Production callers cannot inject a raw Event here.
#[cfg(test)]
pub(crate) fn retain_accepted_encrypted_original_for_test(
    store: &LocalStateStore,
    event: &arkret_sdk::Event,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    secure: &dyn crate::secure_key_store::SecureKeyStore,
) {
    retain_accepted_encrypted_original(store, event, account, device, secure);
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
    let expected = current_metadata_context(store, realm, id, envelope);
    let cipher = serde_json::to_value(envelope).ok()?;
    let snapshot = store.load();
    let mut retained = store.encrypted_originals_for(realm);
    retained.extend(snapshot.raw_operations.iter().filter_map(|record| {
        let value = record.payload.get("event").unwrap_or(&record.payload);
        serde_json::from_value::<arkret_sdk::Event>(value.clone()).ok()
    }));
    let mut originals = std::collections::BTreeMap::new();
    for original in retained {
        let value = serde_json::to_value(&original).ok()?;
        if original.realm_id.as_str() != realm {
            continue;
        }
        let target = match original.kind {
            arkret_sdk::EventKind::SpaceCreate => {
                Some(arkret_sdk::SpaceId::from_event_id(&original.event_id).to_string())
            }
            arkret_sdk::EventKind::StrandCreate => {
                Some(arkret_sdk::StrandId::from_event_id(&original.event_id).to_string())
            }
            arkret_sdk::EventKind::SpaceUpdate => original
                .payload
                .get("space_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            arkret_sdk::EventKind::StrandUpdate => original
                .as_strand_update()
                .ok()
                .map(|payload| payload.strand_id.to_string()),
            _ => continue,
        };
        let Some(target) = target else {
            continue;
        };
        let body = value.get("payload")?;
        let candidate = body
            .pointer("/object/encrypted_metadata")
            .or_else(|| body.pointer("/patch/encrypted_metadata/value"));
        if target != id || candidate != Some(&cipher) {
            continue;
        }
        if let Some((scope, context)) = &expected
            && (original.event_id != context.source.event_id
                || original.scope_ref != *scope
                || original.kind != context.event_kind
                || original.actual_signer() != &context.signer_id)
        {
            continue;
        }
        originals.insert(original.event_id.clone(), (original, value));
    }
    // A cipher digest excludes E. Neither a plaintext cache hit nor the first
    // matching ciphertext may choose which accepted original to authenticate.
    observe_open_gate(&digest, "original", originals.len() == 1);
    if originals.len() != 1 {
        return None;
    }
    let (original, value) = originals.into_values().next()?;
    let sender = crate::identity::committed_sender::verified_chat_sender_domain_for_realm(
        realm,
        &value,
        Some(store),
        Some((account, account.principal_id.as_str(), device)),
    );
    observe_open_gate(&digest, "sender", sender.is_some());
    let sender = sender?;
    let payload = crate::mls::runtime::encrypted_payload_from_verified_original(
        store, secure, account, device, &original, envelope, &sender,
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
        &original.scope_ref,
        &sender,
    );
    observe_open_gate(&digest, "decrypt", bytes.is_some());
    let opened = serde_json::from_slice(&bytes?).ok()?;
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
