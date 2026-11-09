//! Content coordinates come from accepted originals, never ambient defaults.

use arkret_event_draft::EventContentEnvelopesExt as _;
use arkret_sdk::EventPayloadExt as _;

pub(crate) async fn prepare_material(
    api: &crate::transport::TransportClient,
    state: &crate::runtime::input::StateStoreHandle,
    intent: &arkret_sdk::EventIntent,
    path: &str,
    content_type: &str,
    plaintext: &[u8],
) -> anyhow::Result<arkret_models_crypto::EventContentMaterial> {
    let fence = crate::transport::auth::AuthoringSessionFence::capture()?;
    let active = crate::secure_key_store::active_device_seed_scope()
        .ok_or_else(|| anyhow::anyhow!("content requires an active Device"))?;
    let actor = arkret_sdk::ActorId::account(active.authority.clone());
    anyhow::ensure!(
        intent.executed_by().unwrap_or_else(|| intent.actor_id()) == &actor,
        "content actual signer differs from the active Account"
    );
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    let (group, current, producer) = state.read(|state| -> anyhow::Result<_> {
        let current = state
            .current_mls_group_for_scope(intent.scope_ref())
            .ok_or_else(|| anyhow::anyhow!("content group current is pending"))?;
        let producer = crate::mls::runtime::current_local_content_endpoint(
            state,
            secure.as_ref(),
            &active.authority,
            &active.device_id,
            intent.scope_ref(),
        )
        .map_err(|e| anyhow::anyhow!(e.user_message()))?;
        let snapshot = state
            .mls_checkpoint_for_scope(intent.scope_ref())
            .ok_or_else(|| anyhow::anyhow!("content checkpoint is missing"))?;
        let secret = crate::mls::runtime::load_device_checkpoint_secret(
            secure.as_ref(),
            &active.authority,
            &active.device_id,
        )?;
        Ok((
            crate::mls::persistence::restore_envelope(&snapshot, &secret, current.epoch)?,
            current,
            producer,
        ))
    })?;
    let context = resolve_root_context(
        &api.sdk_http_client()?,
        &group,
        &current.genesis_event_ref,
        &current.current_mls_commit_event_ref,
    )
    .await?;
    let entry = export_epoch_root(&group, &context)?;
    let root = entry.root_base64url.clone();
    let root_ref = entry.root_ref.clone();
    let backups = crate::mls::account_recovery::ensure_content_root_backup(
        api,
        secure.as_ref(),
        &active.authority,
        &active.device_id,
        &entry,
    )
    .await?;
    fence.check()?;
    let unchanged = state.read(|state| {
        state
            .current_mls_group_for_scope(intent.scope_ref())
            .as_ref()
            == Some(&current)
    });
    anyhow::ensure!(
        unchanged,
        "content current changed while making its root durable"
    );
    let blob_refs: Vec<arkret_sdk::BlobRef> = intent
        .payload()
        .get("blob_refs")
        .cloned()
        .map(serde_json::from_value)
        .transpose()?
        .unwrap_or_default();
    let protection = arkret_models_crypto::ContentProtection {
        root_refs: vec![root_ref.clone()],
        blob_refs,
        backup_refs: backups,
    };
    let endpoint = arkret_sdk::MlsWelcomeRecipientEndpoint::Device {
        device_id: active.device_id,
    };
    let vault =
        garth::mls::content_roots::ContentRootVault::new(secure.as_ref(), &actor, &endpoint);
    let operation = arkret_sdk::canonical::canonical_sha256(&intent.pre_encryption_outer_event()?)?;
    let salt = vault
        .reserve_salt(
            &operation,
            path,
            &garth::mls::content_roots::ContentSaltBinding {
                intent,
                root_context: &context,
                root_ref: &root_ref,
                producer: &producer,
                content_type,
                protection: &protection,
                plaintext,
            },
        )
        .await?;
    fence.check()?;
    let content_context = arkret_models_crypto::ContentContext {
        root_context: context,
        root_ref,
        purpose: arkret_models_crypto::ContentPurpose::EventBody,
        encryption_scheme: arkret_sdk::EncryptedPayloadScheme::EpochContentAead,
        encryption_algorithm: arkret_models_crypto::ContentEncryptionAlgorithm::Aes128Gcm,
        producer,
        content_key_salt: salt,
    };
    let key = arkret_crypto::content_history::derive_content_key(&root, &content_context)?;
    Ok(arkret_models_crypto::EventContentMaterial {
        key_commitment: arkret_crypto::content_history::content_key_commitment(
            &content_context,
            &key,
        )?,
        content_context,
        outer_event: intent.pre_encryption_outer_event()?,
        protection,
    })
}

fn export_epoch_root(
    group: &arkret_sdk::ArkretMlsGroup,
    context: &arkret_models_crypto::ContentRootContext,
) -> anyhow::Result<arkret_models_crypto::ContentRootBackupEntry> {
    context.validate()?;
    anyhow::ensure!(
        group.scope() == &context.effective_scope
            && group.epoch() == context.epoch
            && group.group_ciphersuite_canonical_id()? == context.cipher_suite,
        "content root context differs from the installed RFC epoch"
    );
    let root = group.export_content_root(context)?;
    let root_ref = arkret_crypto::content_history::content_root_ref(&root, context)?;
    Ok(arkret_models_crypto::ContentRootBackupEntry {
        item_kind: arkret_models_crypto::ContentRootItemKind::ContentEpochRoot,
        secret_id: format!("root_{}", root_ref.as_str().trim_start_matches("sha256:")),
        root_context: context.clone(),
        root_ref,
        root_base64url: root,
    })
}

/// The caller first verifies the exact accepted context and complete roster.
/// Retain R before installing the next checkpoint; this is a local read key,
/// never an upload receipt, private-state backup or history authorization.
pub(crate) async fn retain_received_epoch_root(
    secure: &dyn crate::secure_key_store::SecureKeyStore,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    group: &arkret_sdk::ArkretMlsGroup,
    context: &arkret_models_crypto::ContentRootContext,
) -> anyhow::Result<()> {
    let actor = arkret_sdk::ActorId::account(account.clone());
    let endpoint = arkret_sdk::MlsWelcomeRecipientEndpoint::Device {
        device_id: device.clone(),
    };
    let producer = group.local_content_endpoint()?;
    anyhow::ensure!(
        group.is_active() && producer.actor_id == actor && producer.endpoint == endpoint,
        "received content root belongs to another local endpoint"
    );
    let root = export_epoch_root(group, context)?;
    garth::mls::content_roots::ContentRootVault::new(secure, &actor, &endpoint)
        .retain_root(&root)
        .await?;
    Ok(())
}

pub(crate) fn retained_original_material(
    state: &crate::state::LocalStateStore,
    envelope: &arkret_sdk::EncryptedEnvelope,
    scope: &arkret_sdk::ScopeRef,
    kind: &str,
    sender: &[u8],
) -> Option<arkret_models_crypto::EventContentMaterial> {
    let active = crate::secure_key_store::active_device_seed_scope()?;
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    let actor = arkret_sdk::ActorId::account(active.authority.clone());
    let endpoint = arkret_sdk::MlsWelcomeRecipientEndpoint::Device {
        device_id: active.device_id.clone(),
    };
    let vault =
        garth::mls::content_roots::ContentRootVault::new(secure.as_ref(), &actor, &endpoint);
    let arkret_models_crypto::EncryptedEnvelopeEncryptionContext::EpochContent { root_ref, .. } =
        &envelope.encryption_context;
    let root = vault.cached_root(root_ref).ok()??;
    let snapshot = state.mls_checkpoint_for_scope(scope)?;
    let secret = crate::mls::runtime::load_device_checkpoint_secret(
        secure.as_ref(),
        &active.authority,
        &active.device_id,
    )
    .ok()?;
    let group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0).ok()?;
    let local = state.load();
    let mut originals = std::collections::BTreeMap::new();
    for record in &local.raw_operations {
        let value = record.payload.get("event").unwrap_or(&record.payload);
        let Ok(event) = serde_json::from_value::<arkret_sdk::Event>(value.clone()) else {
            continue;
        };
        if event.scope_ref != *scope || event.kind.as_str() != kind {
            continue;
        }
        if !event
            .event_content_envelopes()
            .ok()?
            .iter()
            .any(|slot| &slot.envelope == envelope)
        {
            continue;
        }
        let verified = crate::identity::committed_sender::verified_chat_sender_domain_for_realm(
            event.realm_id.as_str(),
            value,
            Some(state),
            Some((
                &active.authority,
                active.authority.principal_id.as_str(),
                &active.device_id,
            )),
        )?;
        if verified != sender {
            continue;
        }
        originals.insert(event.event_id.clone(), event);
    }
    if originals.len() != 1 {
        return None;
    }
    let event = originals.into_values().next()?;
    let producer = group.original_content_endpoint(&event).ok()?;
    arkret_models_crypto::EventContentMaterial::from_original(
        &event,
        envelope,
        root.root_context,
        producer,
    )
    .ok()
}

pub(crate) async fn resolve_root_context(
    http: &arkret_sdk::http_client::Client,
    group: &arkret_sdk::ArkretMlsGroup,
    genesis: &arkret_sdk::EventId,
    reference: &arkret_sdk::EventId,
) -> anyhow::Result<arkret_models_crypto::ContentRootContext> {
    let source = crate::transport::own_station_results::client_for_http(http).await?;
    let original = source.committed_event_get(reference).await?;
    let arkret_sdk::CommittedEventView::Full(accepted) = original.value()? else {
        anyhow::bail!("content group original is withheld");
    };
    group.verify_installed_historical_base(accepted, reference)?;
    let strategy =
        crate::transport::own_station_results::genesis_response(&source, group.scope().realm_id())
            .await?;
    let arkret_sdk::CommittedEventView::Full(strategy) = strategy.value()? else {
        anyhow::bail!("content strategy original is withheld");
    };
    let payload = strategy.event.as_realm_create()?;
    let context = arkret_models_crypto::ContentRootContext {
        effective_scope: group.scope().clone(),
        genesis_event_ref: genesis.clone(),
        epoch: group.epoch(),
        group_state_ref: reference.clone(),
        cipher_suite: group.group_ciphersuite_canonical_id()?.to_owned(),
        encryption_backup_strategy: payload.object.initial_encryption_backup_strategy,
        backup_strategy_ref: strategy.event.event_id.clone(),
    };
    context.validate()?;
    source.check_session()?;
    Ok(context)
}

#[cfg(test)]
mod tests {
    use garth::mls::content_roots::ContentRootVault;

    use super::*;

    fn fixture() -> (
        arkret_sdk::ArkretMlsGroup,
        arkret_models_crypto::EventContentMaterial,
        arkret_sdk::AccountId,
        arkret_sdk::DeviceId,
    ) {
        // Cryptographic fixtures do not establish Native or history authority.
        let account = crate::test_support::authority("did:web:alice.example");
        let device =
            arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000a1").unwrap();
        let identity = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
            arkret_sdk::ActorId::account(account.clone()),
            device.clone(),
        )
        .unwrap();
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            )
            .unwrap(),
        };
        let group = identity.create_group(&scope).unwrap();
        let reference =
            arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [0x51; 32]);
        let material =
            crate::test_support::content::material(&group, "ak.message.create", &reference);
        (group, material, account, device)
    }

    #[tokio::test]
    async fn retained_epoch_root_opens_content_after_private_group_is_gone() {
        let (mut group, material, account, device) = fixture();
        let context = material.content_context.root_context.clone();
        let reference = material.content_context.root_ref.clone();
        let header = arkret_models_crypto::EventContentPreEncryptionHeader::reconstruct(
            "1.0",
            "application/json",
            arkret_sdk::EncryptedPayloadScheme::EpochContentAead,
            group.scope().clone(),
            "ak.message.create",
            group.epoch(),
            context.group_state_ref.clone(),
            group.local_content_sender_domain().unwrap(),
            arkret_models_crypto::EventContentRoutingContext::None,
            material,
        )
        .unwrap();
        let payload = group
            .encrypt_payload(header, b"retained original body")
            .unwrap();
        let secure = crate::secure_key_store::MemorySecureKeyStore::new();
        retain_received_epoch_root(&secure, &account, &device, &group, &context)
            .await
            .unwrap();
        drop(group);
        let actor = arkret_sdk::ActorId::account(account);
        let endpoint = arkret_sdk::MlsWelcomeRecipientEndpoint::Device { device_id: device };
        let reopened = ContentRootVault::new(&secure, &actor, &endpoint);
        let root = reopened.root(&reference).await.unwrap().unwrap();
        assert_eq!(root.root_context, context);
        assert_eq!(
            arkret_crypto::content_history::open_content(
                &root.root_base64url,
                &payload.pre_encryption_header,
                &payload.ciphertext,
            )
            .unwrap(),
            b"retained original body"
        );
        let wrong_endpoint = arkret_sdk::MlsWelcomeRecipientEndpoint::Device {
            device_id: arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000b1")
                .unwrap(),
        };
        assert!(
            ContentRootVault::new(&secure, &actor, &wrong_endpoint)
                .root(&reference)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn received_root_rejects_another_endpoint_and_an_uninstalled_epoch() {
        let (group, material, account, device) = fixture();
        let secure = crate::secure_key_store::MemorySecureKeyStore::new();
        let context = &material.content_context.root_context;
        let wrong_device =
            arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000b1").unwrap();
        assert!(
            retain_received_epoch_root(&secure, &account, &wrong_device, &group, context)
                .await
                .is_err()
        );
        let foreign = crate::test_support::authority("did:web:bob.example");
        assert!(
            retain_received_epoch_root(&secure, &foreign, &device, &group, context)
                .await
                .is_err()
        );
        let mut future = context.clone();
        future.epoch += 1;
        assert!(
            retain_received_epoch_root(&secure, &account, &device, &group, &future)
                .await
                .is_err()
        );
        let actor = arkret_sdk::ActorId::account(account);
        let endpoint = arkret_sdk::MlsWelcomeRecipientEndpoint::Device { device_id: device };
        assert!(
            ContentRootVault::new(&secure, &actor, &endpoint)
                .root(&material.content_context.root_ref)
                .await
                .unwrap()
                .is_none()
        );
    }
}
