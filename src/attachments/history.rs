//! Original-authenticated attachment reads using history-only content roots.

use arkret_models_crypto::{AttachmentContentKeyContext, EncryptedAttachment};
use arkret_sdk::http_client::own_station_results::OwnStationStateClient;
use garth::mls::content_roots::ContentRootVault;

/// Both sources stay bound to the live own-Station session. Local key
/// possession and a rendered descriptor are never original-read authority.
pub(crate) async fn read_attachment_key(
    source: &OwnStationStateClient,
    state: &crate::runtime::input::StateStoreHandle,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    original: &garth::own_station_results::OwnStationWindowDependency,
    expected: &arkret_sdk::ContentBlock,
    descriptor: &EncryptedAttachment,
) -> anyhow::Result<(AttachmentContentKeyContext, zeroize::Zeroizing<[u8; 32]>)> {
    anyhow::ensure!(
        source.session()?.account_id() == account
            && original.session()?.account_id() == account
            && source.session()? == original.session()?,
        "attachment original belongs to another reader session"
    );
    ensure_reader(state, account)?;
    let event = &original.full()?.event;
    anyhow::ensure!(
        matches!(
            event.kind,
            arkret_sdk::EventKind::MessageCreate | arkret_sdk::EventKind::MessageRevise
        ),
        "attachment source is not a message original"
    );
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    let actor = arkret_sdk::ActorId::account(account.clone());
    let endpoint = arkret_sdk::MlsWelcomeRecipientEndpoint::Device {
        device_id: device.clone(),
    };
    let vault = ContentRootVault::new(secure.as_ref(), &actor, &endpoint);
    let content = match (
        event.payload.get("content"),
        event.payload.get("encrypted_content"),
    ) {
        (Some(content), None) => {
            serde_json::from_value::<arkret_sdk::ContentBlock>(content.clone())?
        }
        (None, Some(encrypted)) => {
            let envelope: arkret_sdk::EncryptedEnvelope =
                serde_json::from_value(encrypted.clone())?;
            anyhow::ensure!(envelope.content_type == <arkret_sdk::ContentBlock as arkret_models_crypto::MlsPayloadType>::MLS_CONTENT_TYPE,
                "attachment source is not a message ContentBlock");
            let arkret_models_crypto::EncryptedEnvelopeEncryptionContext::EpochContent {
                root_ref,
                ..
            } = &envelope.encryption_context;
            let root = vault
                .root(root_ref)
                .await?
                .ok_or_else(|| anyhow::anyhow!("attachment source content root is pending"))?;
            let roster = crate::mls::historical_content::read_public_epoch(
                source,
                state,
                &root.root_context,
            )
            .await?;
            let material = roster
                .content_material_for_verified_original(event, &envelope)
                .map_err(anyhow::Error::msg)?;
            let sender = arkret_sdk::mls_basic_credential_identity(event.actual_signer())?;
            let header = envelope.reconstruct_pre_encryption_header(
                arkret_sdk::EncryptedPayloadScheme::EpochContentAead,
                event.scope_ref.clone(),
                event.kind.as_str(),
                std::str::from_utf8(&sender)?,
                None,
                material,
            )?;
            let plaintext = zeroize::Zeroizing::new(arkret_crypto::content_history::open_content(
                &root.root_base64url,
                &header,
                &envelope.ciphertext,
            )?);
            serde_json::from_slice::<arkret_sdk::ContentBlock>(&plaintext)?
        }
        _ => anyhow::bail!("attachment source content choice is invalid"),
    };
    require_original_descriptor(&content, expected, descriptor)?;
    original.full()?;
    source.check_session()?;
    ensure_reader(state, account)?;
    let reference = descriptor.key_ref().group_state_ref.event_id()?;
    let root = vault
        .root_for_group_state(&event.scope_ref, &reference)
        .await?
        .ok_or_else(|| anyhow::anyhow!("attachment original content root is pending"))?;
    let roster =
        crate::mls::historical_content::read_public_epoch(source, state, &root.root_context)
            .await?;
    roster
        .validate_content_endpoint_for_original(event, descriptor.producer())
        .map_err(anyhow::Error::msg)?;
    let context = descriptor.content_key_context(
        root.root_context.effective_scope.clone(),
        root.root_context.genesis_event_ref.clone(),
        root.root_context.epoch,
    );
    let key = arkret_crypto::content_history::derive_attachment_content_key(
        &root.root_base64url,
        &context,
    )?;
    original.full()?;
    source.check_session()?;
    ensure_reader(state, account)?;
    Ok((context, key))
}

fn ensure_reader(
    state: &crate::runtime::input::StateStoreHandle,
    account: &arkret_sdk::AccountId,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        state.read(|store| store.active_authority().as_ref() == Some(account)
            && !store.current_reset_required()),
        "attachment reader changed"
    );
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn descriptor_and_rendered_content_must_both_match_the_original() {
        // This isolates original-content selection, not Native authorization.
        let fixture =
            arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json")
                .unwrap();
        let source: arkret_models_crypto::ContentContext =
            serde_json::from_value(fixture["kat"]["content_context"].clone()).unwrap();
        let context = AttachmentContentKeyContext {
            effective_scope: source.root_context.effective_scope.clone(),
            genesis_event_ref: source.root_context.genesis_event_ref.clone(),
            epoch: source.root_context.epoch,
            scheme: arkret_crypto::blob_aead::SCHEME_STREAM.into(),
            encryption_algorithm: arkret_crypto::blob_aead::ALG_STREAM_XCHACHA.into(),
            content_key_salt: arkret_models_crypto::AttachmentContentKeySalt::from_bytes([81; 32]),
            producer: source.producer,
        };
        let reference = source.root_context.group_state_ref;
        let parameters = arkret_crypto::blob_aead::StreamEncryptParams {
            key_ref: arkret_models_crypto::EncryptedAttachmentKeyRef {
                algorithm: arkret_models_crypto::EncryptedAttachmentKeyAlgorithm::Mls,
                group_state_ref: arkret_models_crypto::EncryptedAttachmentGroupStateRef::Event(
                    reference.clone(),
                ),
            },
            content_context: context.clone(),
            digest_suite: arkret_sdk::DigestSuite::Sha256,
            media_type: "application/octet-stream".into(),
            segment_bytes: 262144,
        };
        let (_, descriptor) = arkret_crypto::blob_aead::encrypt_stream(
            b"original",
            &[82; 32],
            &parameters,
            &|candidate: &arkret_models_crypto::EncryptedAttachmentGroupStateRef| {
                (candidate.event_id().ok().as_ref() == Some(&reference)).then(|| {
                    arkret_crypto::blob_aead::ResolvedAttachmentGroupState {
                        effective_scope: context.effective_scope.clone(),
                        genesis_event_ref: context.genesis_event_ref.clone(),
                        epoch: context.epoch,
                    }
                })
            },
        )
        .unwrap();
        let expected = crate::attachments::content_for_attachment(
            "original.bin",
            "application/octet-stream",
            8,
            descriptor.blob_ref(),
            Some(&descriptor),
        )
        .unwrap();
        let original = arkret_sdk::ContentBlock::new(arkret_sdk::ContentBlockKind::Composite, "")
            .with_part(arkret_sdk::ContentBlock::markdown_text("original caption"))
            .with_part(expected.clone());
        require_original_descriptor(&original, &expected, &descriptor).unwrap();
        let mut substituted = expected.clone();
        substituted.body = "a different rendered attachment".into();
        assert!(require_original_descriptor(&original, &substituted, &descriptor).is_err());
        let mut substituted = descriptor.clone();
        let EncryptedAttachment::Stream(stream) = &mut substituted else {
            unreachable!()
        };
        stream.media_type = "text/plain".into();
        assert!(require_original_descriptor(&original, &expected, &substituted).is_err());
        assert!(
            require_original_descriptor(
                &arkret_sdk::ContentBlock::markdown_text("unrelated original"),
                &expected,
                &descriptor
            )
            .is_err()
        );
    }
}

fn require_original_descriptor(
    original: &arkret_sdk::ContentBlock,
    expected: &arkret_sdk::ContentBlock,
    descriptor: &EncryptedAttachment,
) -> anyhow::Result<()> {
    fn contains(original: &arkret_sdk::ContentBlock, expected: &arkret_sdk::ContentBlock) -> bool {
        original == expected || original.parts.iter().any(|part| contains(part, expected))
    }
    anyhow::ensure!(
        contains(original, expected)
            && expected.rendered_encrypted_attachment()?.as_ref() == Some(descriptor),
        "attachment descriptor differs from its authenticated original"
    );
    Ok(())
}
