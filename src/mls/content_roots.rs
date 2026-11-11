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
    let mut protection = arkret_models_crypto::ContentProtection {
        root_refs: vec![root_ref.clone()],
        blob_refs,
        backup_refs: backups,
    };
    let endpoint = arkret_sdk::MlsWelcomeRecipientEndpoint::Device {
        device_id: active.device_id.clone(),
    };
    let vault =
        garth::mls::content_roots::ContentRootVault::new(secure.as_ref(), &actor, &endpoint);
    if let Some(content) =
        arkret_event_draft::content_block_plaintext(intent.kind(), path, plaintext)?
    {
        let source =
            crate::transport::own_station_results::client_for_http(&api.sdk_http_client()?).await?;
        for reference in content.referenced_blobs()? {
            protection
                .blob_refs
                .push(arkret_sdk::BlobRef::new(reference)?);
        }
        for descriptor in content.encrypted_attachments()? {
            let reference = descriptor.key_ref().group_state_ref.event_id()?;
            let root = vault
                .root_for_group_state(intent.scope_ref(), &reference)
                .await?
                .ok_or_else(|| anyhow::anyhow!("attachment content root is pending"))?;
            anyhow::ensure!(
                root.root_context.genesis_event_ref == context.genesis_event_ref,
                "attachment belongs to another immutable group"
            );
            let roster = crate::mls::historical_content::read_public_epoch(
                &source,
                state,
                &root.root_context,
            )
            .await?;
            roster
                .validate_content_endpoint_for_device(
                    &actor,
                    &active.device_id,
                    descriptor.producer(),
                )
                .map_err(anyhow::Error::msg)?;
            validate_attachment_root(&root, &descriptor)?;
            let references = crate::mls::account_recovery::ensure_content_root_backup(
                api,
                secure.as_ref(),
                &active.authority,
                &active.device_id,
                &root,
            )
            .await?;
            protection.root_refs.push(root.root_ref);
            protection.backup_refs.extend(references);
            fence.check()?;
        }
        source.check_session()?;
    }
    protection.root_refs.sort();
    protection.root_refs.dedup();
    protection.blob_refs.sort();
    protection.blob_refs.dedup();
    protection.backup_refs.sort();
    protection.backup_refs.dedup();
    protection.validate()?;
    anyhow::ensure!(
        state.read(|state| state
            .current_mls_group_for_scope(intent.scope_ref())
            .as_ref()
            == Some(&current)),
        "content current changed while making its attachment roots durable"
    );
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

// The caller independently verifies the native author and original public leaf.
// Publishing a root dependency also requires its actual blob-key commitment.
fn validate_attachment_root(
    root: &arkret_models_crypto::ContentRootBackupEntry,
    descriptor: &arkret_models_crypto::EncryptedAttachment,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        descriptor.key_ref().group_state_ref.event_id()? == root.root_context.group_state_ref,
        "attachment root differs from its original group-state reference"
    );
    let context = descriptor.content_key_context(
        root.root_context.effective_scope.clone(),
        root.root_context.genesis_event_ref.clone(),
        root.root_context.epoch,
    );
    let key = arkret_crypto::content_history::derive_attachment_content_key(
        &root.root_base64url,
        &context,
    )?;
    let expected =
        arkret_crypto::key_commitment::content_key_commitment_sha256(&context, key.as_ref())?;
    anyhow::ensure!(
        &expected == descriptor.key_commitment(),
        "attachment key commitment differs from its retained content root"
    );
    Ok(())
}

pub(crate) fn export_epoch_root(
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

fn observe_material_gate(root: &arkret_sdk::Hash, gate: &'static str, passed: bool) {
    #[cfg(any(
        feature = "spec-conformance",
        all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test")
    ))]
    {
        use std::collections::BTreeSet;
        use std::sync::{Mutex, OnceLock};
        static SEEN: OnceLock<Mutex<BTreeSet<(String, &'static str, bool)>>> = OnceLock::new();
        let mut seen = SEEN
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if !seen.insert((root.to_string(), gate, passed)) {
            return;
        }
        if seen.len() > 4096 {
            seen.pop_first();
        }
        tracing::warn!(
            phase = "original_content_material",
            gate,
            passed,
            "public original content material boundary"
        );
    }
    #[cfg(not(any(
        feature = "spec-conformance",
        all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test")
    )))]
    let _ = (root, gate, passed);
}

/// The caller supplies an original already accepted through its own Station.
/// Prefer a public exact-epoch proof prepared from a sealed accepted page.
/// An unrelated current roster must not manufacture old producer provenance.
pub(crate) fn material_from_accepted_original(
    state: &crate::state::LocalStateStore,
    secure: &dyn crate::secure_key_store::SecureKeyStore,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    event: &arkret_sdk::Event,
    envelope: &arkret_sdk::EncryptedEnvelope,
) -> Option<arkret_models_crypto::EventContentMaterial> {
    let actor = arkret_sdk::ActorId::account(account.clone());
    let endpoint = arkret_sdk::MlsWelcomeRecipientEndpoint::Device {
        device_id: device.clone(),
    };
    let vault = garth::mls::content_roots::ContentRootVault::new(secure, &actor, &endpoint);
    let arkret_models_crypto::EncryptedEnvelopeEncryptionContext::EpochContent { root_ref, .. } =
        &envelope.encryption_context;
    let root = vault.cached_root(root_ref).ok().flatten();
    observe_material_gate(root_ref, "retained_root", root.is_some());
    let root = root?;
    let public_material =
        state
            .historical_content_rosters
            .material(account, event, envelope, &root.root_context);
    observe_material_gate(root_ref, "public_epoch", public_material.is_some());
    if let Some(material) = public_material {
        return Some(material);
    }
    // Only the installed-group fallback needs the current projection's epoch
    // index. A verified public historical epoch requires no private snapshot.
    let group_id = event.scope_ref.canonical_mls_group_id().ok()?;
    if state
        .mls_group_state_ref_for_scope(
            &event.scope_ref,
            &group_id,
            envelope.encryption_context.epoch(),
        )
        .ok()?
        != *envelope.encryption_context.group_state_ref()
    {
        return None;
    }
    let snapshot = state.mls_checkpoint_for_scope(&event.scope_ref)?;
    let secret =
        crate::mls::runtime::load_device_checkpoint_secret(secure, account, device).ok()?;
    let group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0).ok()?;
    observe_material_gate(
        root_ref,
        "installed_epoch",
        group.scope() == &event.scope_ref && group.epoch() == root.root_context.epoch,
    );
    if group.scope() != &event.scope_ref || group.epoch() != root.root_context.epoch {
        return None;
    }
    if !event
        .event_content_envelopes()
        .ok()?
        .iter()
        .any(|slot| &slot.envelope == envelope)
    {
        return None;
    }
    let producer = group.original_content_endpoint(event).ok()?;
    let suite = event.realm_id.digest_suite_code().digest_suite();
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .ok()?;
    event.verify_producer_proof_self_consistency(suite).ok()?;
    // The accepted-source boundary verifies the Event proof with its exact
    // native historical key. This independent roster binds the MLS leaf key;
    // the protocol permits these two keys to differ for the same endpoint.
    arkret_models_crypto::EventContentMaterial::from_original(
        event,
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
    let principal_request = arkret_sdk::CurrentPrincipalRequestBody {
        request_id: arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms()),
        account_id: source.session()?.account_id().clone(),
    };
    let principal = source.current_principal(&principal_request).await?;
    let (strategy, strategy_ref) =
        if principal.value()?.principal_control_realm_id == *group.scope().realm_id() {
            let pcr =
                garth::own_station_results::read_own_station_human_pcr_genesis(&source, principal)
                    .await?;
            let original = pcr.genesis()?;
            (
                original
                    .event
                    .as_realm_create()?
                    .object
                    .initial_encryption_backup_strategy,
                original.event.event_id.clone(),
            )
        } else {
            let strategy = crate::transport::own_station_results::genesis_response(
                &source,
                group.scope().realm_id(),
            )
            .await?;
            let arkret_sdk::CommittedEventView::Full(strategy) = strategy.value()? else {
                anyhow::bail!("content strategy original is withheld");
            };
            (
                strategy
                    .event
                    .as_realm_create()?
                    .object
                    .initial_encryption_backup_strategy,
                strategy.event.event_id.clone(),
            )
        };
    let context = arkret_models_crypto::ContentRootContext {
        effective_scope: group.scope().clone(),
        genesis_event_ref: genesis.clone(),
        epoch: group.epoch(),
        group_state_ref: reference.clone(),
        cipher_suite: group.group_ciphersuite_canonical_id()?.to_owned(),
        encryption_backup_strategy: strategy,
        backup_strategy_ref: strategy_ref,
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

    #[test]
    fn attachment_dependency_rejects_a_root_salt_commitment_or_state_substitution() {
        use arkret_models_crypto::{
            AttachmentContentKeySalt, EncryptedAttachment, EncryptedAttachmentGroupStateRef,
        };
        let (group, material, ..) = fixture();
        let root = export_epoch_root(&group, &material.content_context.root_context).unwrap();
        let context = arkret_models_crypto::AttachmentContentKeyContext {
            effective_scope: root.root_context.effective_scope.clone(),
            genesis_event_ref: root.root_context.genesis_event_ref.clone(),
            epoch: root.root_context.epoch,
            scheme: arkret_crypto::blob_aead::SCHEME_STREAM.into(),
            encryption_algorithm: arkret_crypto::blob_aead::ALG_STREAM_XCHACHA.into(),
            content_key_salt: AttachmentContentKeySalt::from_bytes([81; 32]),
            producer: material.content_context.producer,
        };
        let key = arkret_crypto::content_history::derive_attachment_content_key(
            &root.root_base64url,
            &context,
        )
        .unwrap();
        let resolver = |reference: &EncryptedAttachmentGroupStateRef| {
            (reference.event_id().ok().as_ref() == Some(&root.root_context.group_state_ref)).then(
                || arkret_crypto::blob_aead::ResolvedAttachmentGroupState {
                    effective_scope: root.root_context.effective_scope.clone(),
                    genesis_event_ref: root.root_context.genesis_event_ref.clone(),
                    epoch: root.root_context.epoch,
                },
            )
        };
        let parameters = arkret_crypto::blob_aead::StreamEncryptParams {
            key_ref: arkret_models_crypto::EncryptedAttachmentKeyRef {
                algorithm: arkret_models_crypto::EncryptedAttachmentKeyAlgorithm::Mls,
                group_state_ref: EncryptedAttachmentGroupStateRef::Event(
                    root.root_context.group_state_ref.clone(),
                ),
            },
            content_context: context,
            digest_suite: arkret_sdk::DigestSuite::Sha256,
            media_type: "application/octet-stream".into(),
            segment_bytes: 262144,
        };
        let (_, descriptor) = arkret_crypto::blob_aead::encrypt_stream(
            b"original attachment",
            &key,
            &parameters,
            &resolver,
        )
        .unwrap();
        validate_attachment_root(&root, &descriptor).unwrap();
        let mut changed = descriptor.clone();
        let EncryptedAttachment::Stream(stream) = &mut changed else {
            unreachable!()
        };
        stream.key_commitment =
            arkret_sdk::Hash::new(format!("sha256:{}", "82".repeat(32))).unwrap();
        assert!(validate_attachment_root(&root, &changed).is_err());
        let mut changed = descriptor.clone();
        let EncryptedAttachment::Stream(stream) = &mut changed else {
            unreachable!()
        };
        stream.content_key_salt = AttachmentContentKeySalt::from_bytes([83; 32]);
        assert!(validate_attachment_root(&root, &changed).is_err());
        let mut changed = descriptor.clone();
        let EncryptedAttachment::Stream(stream) = &mut changed else {
            unreachable!()
        };
        stream.key_ref.group_state_ref = EncryptedAttachmentGroupStateRef::Digest(
            arkret_sdk::Hash::new(root.root_context.group_state_ref.event_digest().to_string())
                .unwrap(),
        );
        validate_attachment_root(&root, &changed).unwrap();
        let EncryptedAttachment::Stream(stream) = &mut changed else {
            unreachable!()
        };
        stream.key_ref.group_state_ref = EncryptedAttachmentGroupStateRef::Event(
            arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [85; 32]),
        );
        assert!(validate_attachment_root(&root, &changed).is_err());
        let mut changed_root = root;
        changed_root.root_base64url = arkret_models_crypto::ContentRootSecret::new([84; 32]);
        assert!(validate_attachment_root(&changed_root, &descriptor).is_err());
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
        let state = crate::state::LocalStateStore::default();
        let opened =
            crate::mls::runtime::decrypt_application_payload_for_scope_from_verified_sender(
                &state,
                &secure,
                context.effective_scope.realm_id().as_str(),
                actor.as_account_id().unwrap(),
                match &endpoint {
                    arkret_sdk::MlsWelcomeRecipientEndpoint::Device { device_id } => device_id,
                    _ => unreachable!(),
                },
                &payload,
                &context.effective_scope,
                payload.pre_encryption_header.sender_domain.as_bytes(),
            );
        assert_eq!(
            opened.as_deref(),
            Some(b"retained original body".as_slice())
        );
        assert!(
            state
                .mls_checkpoint_for_scope(&context.effective_scope)
                .is_none()
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
