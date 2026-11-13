//! Original-bound DEKs. A retained secret is usable only with independently
//! reverified native original and exact public historical epoch material.

use arkret_models_crypto::{ContentRootContext, EncryptedEnvelope, EventContentMaterial};
use garth::mls::content_history::{RetainedHistoryContentKey, RetainedHistoryKeyContext};
use garth::mls::content_roots::ContentRootVault;

use super::*;

pub(crate) async fn read_attachment_key(
    source: &OwnStationStateClient,
    state: &StateStoreHandle,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    full: &CommittedEventFullView,
    expected: &arkret_sdk::ContentBlock,
    descriptor: &arkret_models_crypto::EncryptedAttachment,
) -> anyhow::Result<(
    arkret_models_crypto::AttachmentContentKeyContext,
    zeroize::Zeroizing<[u8; 32]>,
)> {
    let active = require_reader(source, state)?;
    anyhow::ensure!(
        &active.authority == account && &active.device_id == device,
        "attachment endpoint changed"
    );
    let actor = ActorId::account(account.clone());
    let endpoint = arkret_sdk::MlsWelcomeRecipientEndpoint::Device {
        device_id: device.clone(),
    };
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    let vault = HistoryExchangeVault::new(secure.as_ref(), &actor, &endpoint);
    let mut blocks = arkret_event_draft::event_plain_content_blocks(&full.event)?;
    for slot in full.event.event_content_envelopes()? {
        if slot.envelope.content_type
            == <arkret_sdk::ContentBlock as arkret_models_crypto::MlsPayloadType>::MLS_CONTENT_TYPE
        {
            let (_, plaintext) = body(
                source,
                state,
                &vault,
                account,
                device,
                full,
                &slot.content_path,
                None,
            )
            .await?;
            blocks.push((slot.content_path, serde_json::from_slice(&plaintext)?));
        }
    }
    let mut selected_path = None;
    for (base, block) in blocks {
        if crate::attachments::history::require_original_descriptor(&block, expected, descriptor)
            .is_err()
        {
            continue;
        }
        for (path, found) in arkret_event_draft::history_attachment_slots(&block, &base)? {
            if found == *descriptor {
                anyhow::ensure!(
                    selected_path.is_none(),
                    "attachment original selector is ambiguous"
                );
                selected_path = Some(path);
            }
        }
    }
    let path = selected_path.ok_or_else(|| {
        anyhow::anyhow!("attachment descriptor differs from authenticated original")
    })?;
    let retained = held(source, state, &vault, account, device, full, &path).await?;
    let RetainedHistoryKeyContext::Attachment { context, .. } = &retained.context else {
        anyhow::bail!("attachment selected key type differs");
    };
    let key = retained.key()?;
    Ok((
        context.clone(),
        zeroize::Zeroizing::new(key.as_slice().try_into()?),
    ))
}

fn header(
    event: &Event,
    envelope: &EncryptedEnvelope,
    material: EventContentMaterial,
) -> anyhow::Result<arkret_models_crypto::EventContentPreEncryptionHeader> {
    let sender = arkret_sdk::mls_basic_credential_identity(event.actual_signer())?;
    Ok(envelope.reconstruct_pre_encryption_header(
        arkret_sdk::EncryptedPayloadScheme::EpochContentAead,
        event.scope_ref.clone(),
        event.kind.as_str(),
        std::str::from_utf8(&sender)?,
        None,
        material,
    )?)
}

async fn body(
    source: &OwnStationStateClient,
    state: &StateStoreHandle,
    vault: &HistoryExchangeVault<'_>,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    full: &CommittedEventFullView,
    path: &str,
    received: Option<&[u8]>,
) -> anyhow::Result<(RetainedHistoryContentKey, Vec<u8>)> {
    let event = &full.event;
    let slot = event
        .event_content_envelopes()?
        .into_iter()
        .find(|slot| slot.content_path == path)
        .ok_or_else(|| anyhow::anyhow!("history body is not a registered original slot"))?;
    let envelope = &slot.envelope;
    let cache = state.read(|store| store.historical_content_rosters.clone());
    let material = if let Some(material) = cache.material_for_original(account, event, envelope) {
        material
    } else {
        let context = context_for(
            source,
            state,
            &event.scope_ref,
            envelope.encryption_context.epoch(),
            envelope.encryption_context.group_state_ref(),
        )
        .await?;
        let roster =
            crate::mls::historical_content::read_public_epoch(source, state, &context).await?;
        let material = roster
            .content_material_for_verified_original(event, envelope)
            .map_err(anyhow::Error::msg)?;
        let arkret_models_crypto::EncryptedEnvelopeEncryptionContext::EpochContent {
            root_ref, ..
        } = &envelope.encryption_context;
        cache.install(root_ref.clone(), source, roster)?;
        material
    };
    let context = material.content_context.root_context.clone();
    let key = if let Some(key) = received {
        zeroize::Zeroizing::new(key.to_vec())
    } else {
        let actor = ActorId::account(account.clone());
        let endpoint = arkret_sdk::MlsWelcomeRecipientEndpoint::Device {
            device_id: device.clone(),
        };
        let secure = crate::secure_key_store::default_secure_key_store("inkson");
        let roots = ContentRootVault::new(secure.as_ref(), &actor, &endpoint);
        if let Some(root) = roots.root(&material.content_context.root_ref).await? {
            anyhow::ensure!(
                root.root_context == context,
                "history body root coordinates differ"
            );
            zeroize::Zeroizing::new(
                arkret_crypto::content_history::derive_content_key(
                    &root.root_base64url,
                    &material.content_context,
                )?
                .to_vec(),
            )
        } else {
            let retained = vault
                .read_key(&event.event_id, path)
                .await?
                .ok_or_else(|| anyhow::anyhow!("history body key pending"))?;
            anyhow::ensure!(
                retained.source == reference(full)
                    && retained.context
                        == RetainedHistoryKeyContext::Body {
                            material: material.clone()
                        },
                "history body key differs from original"
            );
            retained.key()?
        }
    };
    let retained = RetainedHistoryContentKey::new(
        reference(full),
        path.into(),
        RetainedHistoryKeyContext::Body {
            material: material.clone(),
        },
        material.key_commitment.clone(),
        &key,
    )?;
    let key16: &[u8; 16] = key.as_slice().try_into()?;
    let plaintext = arkret_crypto::content_history::open_content_from_granted_key(
        key16,
        &header(event, envelope, material)?,
        &envelope.ciphertext,
    )?;
    require_reader(source, state)?;
    Ok((retained, plaintext))
}

async fn descriptor_context(
    source: &OwnStationStateClient,
    state: &StateStoreHandle,
    event: &Event,
    descriptor: &arkret_models_crypto::EncryptedAttachment,
) -> anyhow::Result<ContentRootContext> {
    let reference = descriptor.key_ref().group_state_ref.event_id()?;
    let current = crate::mls::send_gate::read_durable_mls_current(
        &crate::mls::send_gate::MlsSendGateInput::capture(state, &event.scope_ref),
        &event.scope_ref,
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("attachment MLS current pending"))?;
    let epoch = if reference == current.genesis_event_ref {
        0
    } else {
        let original =
            garth::own_station_results::read_window_dependency_by_event_id(source, &reference)
                .await?;
        let original = original.full()?;
        anyhow::ensure!(
            original.event.scope_ref == event.scope_ref,
            "attachment group state belongs to another scope"
        );
        original.event.as_mls_commit()?.next_epoch()
    };
    context_for(source, state, &event.scope_ref, epoch, &reference).await
}

pub(super) async fn paths(
    source: &OwnStationStateClient,
    state: &StateStoreHandle,
    vault: &HistoryExchangeVault<'_>,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    full: &CommittedEventFullView,
) -> anyhow::Result<Vec<String>> {
    let mut paths = Vec::new();
    for slot in full.event.event_content_envelopes()? {
        paths.push(slot.content_path.clone());
        if slot.envelope.content_type
            == <arkret_sdk::ContentBlock as arkret_models_crypto::MlsPayloadType>::MLS_CONTENT_TYPE
            && let Ok((_, plaintext)) = body(
                source,
                state,
                vault,
                account,
                device,
                full,
                &slot.content_path,
                None,
            )
            .await
        {
            let block: arkret_sdk::ContentBlock = serde_json::from_slice(&plaintext)?;
            paths.extend(
                arkret_event_draft::history_attachment_slots(&block, &slot.content_path)?
                    .into_iter()
                    .map(|(path, _)| path),
            );
        }
    }
    for (path, block) in arkret_event_draft::event_plain_content_blocks(&full.event)? {
        paths.extend(
            arkret_event_draft::history_attachment_slots(&block, &path)?
                .into_iter()
                .map(|(path, _)| path),
        );
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

pub(super) async fn held(
    source: &OwnStationStateClient,
    state: &StateStoreHandle,
    vault: &HistoryExchangeVault<'_>,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    full: &CommittedEventFullView,
    path: &str,
) -> anyhow::Result<RetainedHistoryContentKey> {
    select(source, state, vault, account, device, full, path, None).await
}

pub(super) async fn verify(
    source: &OwnStationStateClient,
    state: &StateStoreHandle,
    vault: &HistoryExchangeVault<'_>,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    full: &CommittedEventFullView,
    path: &str,
    received: &[u8],
) -> anyhow::Result<RetainedHistoryContentKey> {
    select(
        source,
        state,
        vault,
        account,
        device,
        full,
        path,
        Some(received),
    )
    .await
}

async fn select(
    source: &OwnStationStateClient,
    state: &StateStoreHandle,
    vault: &HistoryExchangeVault<'_>,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    full: &CommittedEventFullView,
    path: &str,
    received: Option<&[u8]>,
) -> anyhow::Result<RetainedHistoryContentKey> {
    if full
        .event
        .event_content_envelopes()?
        .iter()
        .any(|slot| slot.content_path == path)
    {
        return Ok(
            body(source, state, vault, account, device, full, path, received)
                .await?
                .0,
        );
    }
    let mut parents = std::collections::BTreeMap::new();
    for slot in full.event.event_content_envelopes()? {
        if path.starts_with(&(slot.content_path.clone() + "/")) {
            parents.insert(
                slot.content_path.clone(),
                body(
                    source,
                    state,
                    vault,
                    account,
                    device,
                    full,
                    &slot.content_path,
                    None,
                )
                .await?
                .1,
            );
        }
    }
    let selection = arkret_event_draft::select_history_content(&full.event, path, |slot| {
        parents.get(&slot.content_path).cloned().ok_or_else(|| {
            arkret_wire::WireError::Protocol("independently authorized parent key pending".into())
        })
    })?;
    let arkret_event_draft::HistoryContentSelection::Attachment { descriptor, .. } = selection
    else {
        anyhow::bail!("history selected target differs");
    };
    let context = descriptor_context(source, state, &full.event, &descriptor).await?;
    let roster = crate::mls::historical_content::read_public_epoch(source, state, &context).await?;
    roster
        .validate_content_endpoint_for_original(&full.event, descriptor.producer())
        .map_err(anyhow::Error::msg)?;
    let attachment = descriptor.content_key_context(
        context.effective_scope.clone(),
        context.genesis_event_ref.clone(),
        context.epoch,
    );
    let key = if let Some(key) = received {
        zeroize::Zeroizing::new(key.to_vec())
    } else {
        let actor = ActorId::account(account.clone());
        let endpoint = arkret_sdk::MlsWelcomeRecipientEndpoint::Device {
            device_id: device.clone(),
        };
        let secure = crate::secure_key_store::default_secure_key_store("inkson");
        if let Some(root) = ContentRootVault::new(secure.as_ref(), &actor, &endpoint)
            .root_for_group_state(&full.event.scope_ref, &context.group_state_ref)
            .await?
        {
            anyhow::ensure!(
                root.root_context == context,
                "attachment root coordinates differ"
            );
            zeroize::Zeroizing::new(
                arkret_crypto::content_history::derive_attachment_content_key(
                    &root.root_base64url,
                    &attachment,
                )?
                .to_vec(),
            )
        } else {
            let retained = vault
                .read_key(&full.event.event_id, path)
                .await?
                .ok_or_else(|| anyhow::anyhow!("history attachment key pending"))?;
            anyhow::ensure!(
                retained.source == reference(full)
                    && retained.context
                        == RetainedHistoryKeyContext::Attachment {
                            root_context: context.clone(),
                            context: attachment.clone()
                        },
                "history attachment key differs from original"
            );
            retained.key()?
        }
    };
    let retained = RetainedHistoryContentKey::new(
        reference(full),
        path.into(),
        RetainedHistoryKeyContext::Attachment {
            root_context: context.clone(),
            context: attachment.clone(),
        },
        descriptor.key_commitment().clone(),
        &key,
    )?;
    if received.is_some() {
        let arkret_models_crypto::EncryptedAttachment::Stream(stream) = &descriptor else {
            anyhow::bail!("unsupported_attachment_scheme");
        };
        anyhow::ensure!(
            stream.size_bytes <= 64 * 1024 * 1024,
            "attachment exceeds client limit"
        );
        let ciphertext = source
            .http_client()?
            .blob_download(descriptor.blob_ref(), None)
            .await?;
        let key32: &[u8; 32] = key.as_slice().try_into()?;
        let resolver = |reference: &arkret_models_crypto::EncryptedAttachmentGroupStateRef| {
            (reference.event_id().ok().as_ref() == Some(&context.group_state_ref)).then(|| {
                arkret_crypto::blob_aead::ResolvedAttachmentGroupState {
                    effective_scope: context.effective_scope.clone(),
                    genesis_event_ref: context.genesis_event_ref.clone(),
                    epoch: context.epoch,
                }
            })
        };
        match &descriptor {
            arkret_models_crypto::EncryptedAttachment::Stream(_) => {
                let _ = arkret_crypto::blob_aead::decrypt_stream(
                    &ciphertext,
                    &descriptor,
                    key32,
                    &resolver,
                )?;
            }
            _ => anyhow::bail!("unsupported_attachment_scheme"),
        }
    }
    require_reader(source, state)?;
    Ok(retained)
}
