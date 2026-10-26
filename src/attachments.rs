//! Private attachment preparation shared by compose and authenticated rendering.
pub(crate) mod artifact;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

use arkret_models_crypto::{
    AttachmentContentKeyContext, AttachmentContentKeySalt, EncryptedAttachment,
    EncryptedAttachmentGroupStateRef, EncryptedAttachmentKeyAlgorithm, EncryptedAttachmentKeyRef,
};
use arkret_sdk::{AccountId, DeviceId, EventId, ScopeRef, StrandId};

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DraftAttachment {
    pub id: String,
    pub scope: ScopeRef,
    pub content: arkret_sdk::ContentBlock,
    pub pending: bool,
}

/// Holder-local intent stored inside the existing authenticated outbound vault.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AttachmentObject {
    pub id: String,
    pub authority: AccountId,
    pub device_id: DeviceId,
    pub scope: ScopeRef,
    pub strand_id: StrandId,
    pub filename: String,
    pub long_text: bool,
    pub input_size: u64,
    pub input_digest: Option<arkret_sdk::Hash>,
    pub text_prefix: Option<String>,
    pub line_count: Option<u64>,
    pub media_type: String,
    pub salt: AttachmentContentKeySalt,
    pub digest_suite: arkret_sdk::DigestSuite,
    pub context: Option<AttachmentContentKeyContext>,
    pub checkpoint: Option<garth::mls::checkpoint::MlsLocalCheckpointEnvelope>,
    pub state_tree_ref: Option<arkret_sdk::BlobRef>,
    pub nonce_prefix: Option<arkret_sdk::Base64UrlString>,
    pub prepared: Option<PreparedAttachment>,
    pub uploaded: bool,
    pub submitted_operation: Option<String>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedAttachment {
    pub content: arkret_sdk::ContentBlock,
    pub ciphertext_size: u64,
    pub part_count: u32,
    pub descriptor: Option<EncryptedAttachment>,
    pub blob_ref: arkret_sdk::BlobRef,
}

pub(crate) const SEGMENT_BYTES: u32 = 262_144;
pub(crate) const MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) async fn with_target_fence<T>(
    operation: impl std::future::Future<Output = anyhow::Result<T>>,
    active: impl Fn() -> bool,
) -> anyhow::Result<T> {
    tokio::pin!(operation);
    loop {
        anyhow::ensure!(active(), "attachment session or target changed");
        tokio::select! {
            result = &mut operation => {
                anyhow::ensure!(active(), "attachment session or target changed");
                return result;
            }
            _ = crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(50)) => {}
        }
    }
}

/// Cold recovery waits for typed readiness at the same live target. Each attempt
/// retains the gate's authorization and private-state checks; no body is authored
/// and an incomplete baseline never implies plaintext.
pub(crate) async fn await_attachment_send_gate(
    store: &crate::runtime::input::StateStoreHandle,
    scope: &ScopeRef,
    device: &DeviceId,
    active: impl Fn() -> bool,
) -> anyhow::Result<crate::mls::send_gate::MlsSendGate> {
    use crate::mls::send_gate::{
        MlsSendGateBlocked, MlsSendGateInput, resolve_restorable_mls_send_gate,
    };
    for attempt in 0..240 {
        anyhow::ensure!(active(), "attachment session or target changed");
        let result = resolve_restorable_mls_send_gate(
            &MlsSendGateInput::capture(store, scope),
            scope,
            device,
        )
        .await;
        match result {
            Ok(gate) => return Ok(gate),
            Err(error)
                if attempt < 239
                    && matches!(
                        error.downcast_ref::<MlsSendGateBlocked>(),
                        Some(
                            MlsSendGateBlocked::DetailBaselinePending
                                | MlsSendGateBlocked::NotReady(_)
                        )
                    ) =>
            {
                crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(500)).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("bounded attachment readiness loop always returns")
}

pub(crate) async fn input_bytes_to_parts(
    chunks: &crate::state::current_index::AttachmentChunkStore,
    bytes: &[u8],
    suite: arkret_sdk::DigestSuite,
) -> anyhow::Result<arkret_sdk::Hash> {
    let mut hasher = arkret_sdk::canonical::ContentHasher::new(suite);
    let count = arkret_models_crypto::stream_segment_count(bytes.len() as u64, SEGMENT_BYTES)?;
    for index in 0..count {
        let start = index as usize * SEGMENT_BYTES as usize;
        let end = start
            .saturating_add(SEGMENT_BYTES as usize)
            .min(bytes.len());
        let part = &bytes[start..end];
        chunks.write_part("input", index, part).await?;
        hasher.update(part);
    }
    Ok(arkret_sdk::Hash::new(hasher.finish())?)
}

/// A selected host resource with a stable snapshot, never an ambient file path.
/// Native implementations retain one open handle and reject length/mtime changes.
/// Browser implementations retain the selected token and its owning file controller.
pub trait AttachmentSource {
    fn size(&self) -> u64;
    fn read_range(
        &self,
        offset: u64,
        length: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Vec<u8>>> + '_>>;
    fn verify_snapshot(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + '_>>;
}

/// Freeze the same protocol-sized parts with bounded host reads and target fences.
pub(crate) async fn file_to_parts(
    chunks: &crate::state::current_index::AttachmentChunkStore,
    file: &dyn AttachmentSource,
    suite: arkret_sdk::DigestSuite,
    active: impl Fn() -> bool,
) -> anyhow::Result<arkret_sdk::Hash> {
    let size = file.size();
    anyhow::ensure!(
        size <= MAX_OBJECT_BYTES,
        "attachment exceeds the client limit"
    );
    with_target_fence(file.verify_snapshot(), &active).await?;
    let mut hasher = arkret_sdk::canonical::ContentHasher::new(suite);
    let count = arkret_models_crypto::stream_segment_count(size, SEGMENT_BYTES)?;
    for index in 0..count {
        anyhow::ensure!(
            active() && file.size() == size,
            "attachment target or selected file changed"
        );
        let start = u64::from(index) * u64::from(SEGMENT_BYTES);
        let length = size.saturating_sub(start).min(u64::from(SEGMENT_BYTES));
        let mut part = zeroize::Zeroizing::new(Vec::with_capacity(usize::try_from(length)?));
        while (part.len() as u64) < length {
            let remaining = length - part.len() as u64;
            let read_length = usize::try_from(remaining.min(65536))?;
            let offset = start + part.len() as u64;
            let bytes = zeroize::Zeroizing::new(
                with_target_fence(file.read_range(offset, read_length), &active).await?,
            );
            anyhow::ensure!(
                bytes.len() == read_length,
                "selected attachment part differs or is truncated"
            );
            part.extend_from_slice(&bytes);
        }
        anyhow::ensure!(active(), "attachment target changed");
        hasher.update(&part);
        with_target_fence(chunks.write_part("input", index, &part), &active).await?;
    }
    with_target_fence(file.verify_snapshot(), &active).await?;
    anyhow::ensure!(
        file.size() == size && active(),
        "selected file changed while reading"
    );
    Ok(arkret_sdk::Hash::new(hasher.finish())?)
}

pub(crate) fn restore_attachment_group(
    snapshot: &garth::mls::checkpoint::MlsLocalCheckpointEnvelope,
    authority: &AccountId,
    device: &DeviceId,
    context: &AttachmentContentKeyContext,
) -> anyhow::Result<arkret_sdk::ArkretMlsGroup> {
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    restore_attachment_group_from_store(snapshot, authority, device, context, secure.as_ref())
}

fn restore_attachment_group_from_store(
    snapshot: &garth::mls::checkpoint::MlsLocalCheckpointEnvelope,
    authority: &AccountId,
    device: &DeviceId,
    context: &AttachmentContentKeyContext,
    secure: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<arkret_sdk::ArkretMlsGroup> {
    let secret = crate::mls::runtime::load_device_checkpoint_secret(secure, authority, device)?;
    let group = crate::mls::persistence::restore_envelope(snapshot, &secret, 0)?;
    anyhow::ensure!(
        group.scope() == &context.effective_scope
            && group.epoch() == context.epoch
            && group.group_id() == context.effective_scope.canonical_mls_group_id()?,
        "attachment_group_state_unresolved: private scope or epoch differs"
    );
    anyhow::ensure!(
        group.local_actor_id() == &arkret_sdk::ActorId::account(authority.clone())
            && group.local_endpoint_identity()
                == arkret_sdk::MlsEndpointIdentity::HumanDevice {
                    principal_id: authority.principal_id.clone(),
                    device_id: device.clone()
                },
        "attachment checkpoint belongs to another endpoint"
    );
    Ok(group)
}

pub(crate) fn content_for_attachment(
    filename: &str,
    media_type: &str,
    size: u64,
    blob_ref: &arkret_sdk::BlobRef,
    descriptor: Option<&EncryptedAttachment>,
) -> anyhow::Result<arkret_sdk::ContentBlock> {
    use arkret_sdk::ContentBlockKind;
    let kind = if media_type.starts_with("image/") {
        ContentBlockKind::Image
    } else if media_type.starts_with("audio/") {
        ContentBlockKind::Audio
    } else if media_type.starts_with("video/") {
        ContentBlockKind::Video
    } else {
        ContentBlockKind::File
    };
    let mut content = arkret_sdk::ContentBlock::new(kind, filename)
        .with_field("blob_ref", serde_json::to_value(blob_ref)?)
        .with_field(
            "mime_type",
            serde_json::Value::String(media_type.to_owned()),
        )
        .with_field("filename", serde_json::Value::String(filename.to_owned()))
        .with_field("size_bytes", serde_json::Value::from(size));
    if let Some(descriptor) = descriptor {
        content = content.with_field("attachments", serde_json::to_value([descriptor])?);
    }
    content.referenced_blobs()?;
    Ok(content)
}

impl AttachmentObject {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.input_size <= MAX_OBJECT_BYTES,
            "attachment exceeds client limit"
        );
        let encrypted = self.context.is_some();
        anyhow::ensure!(
            encrypted == self.checkpoint.is_some()
                && encrypted == self.state_tree_ref.is_some()
                && encrypted == self.nonce_prefix.is_some(),
            "attachment frozen state is incomplete"
        );
        if let Some(context) = &self.context {
            context.validate()?;
            let checkpoint = self
                .checkpoint
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing checkpoint"))?;
            anyhow::ensure!(
                context.effective_scope == self.scope
                    && context.content_key_salt == self.salt
                    && context.epoch == checkpoint.epoch
                    && checkpoint.group_state_event_id.is_some()
                    && checkpoint.group_id == self.scope.canonical_mls_group_id()?.as_str()
                    && context.scheme == arkret_crypto::blob_aead::SCHEME_STREAM
                    && context.encryption_algorithm == arkret_crypto::blob_aead::ALG_STREAM_XCHACHA,
                "attachment intent binding differs"
            );
            let prefix = arkret_sdk::canonical::base64url_decode(
                self.nonce_prefix
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("missing nonce prefix"))?
                    .as_str(),
            )?;
            anyhow::ensure!(prefix.len() == 19, "attachment nonce prefix differs");
        }
        anyhow::ensure!(
            self.long_text == self.text_prefix.is_some()
                && self.long_text == self.line_count.is_some(),
            "attachment text summary differs"
        );
        if let Some(prepared) = &self.prepared {
            let count = arkret_models_crypto::stream_segment_count(self.input_size, SEGMENT_BYTES)?;
            anyhow::ensure!(
                self.input_digest.is_some()
                    && prepared.part_count == count
                    && prepared.ciphertext_size
                        == self.input_size + if encrypted { 16 * u64::from(count) } else { 0 }
                    && prepared.descriptor.is_some() == encrypted
                    && prepared.content.referenced_blobs()? == [prepared.blob_ref.as_str()],
                "prepared attachment differs from its frozen commitment"
            );
            let suite = prepared
                .blob_ref
                .as_str()
                .strip_prefix("ak:blob:")
                .and_then(|r| r.split_once(':'))
                .map(|(s, _)| s);
            anyhow::ensure!(
                suite == Some(self.digest_suite.as_str()),
                "attachment digest suite differs"
            );
            if let (Some(descriptor), Some(context)) = (&prepared.descriptor, &self.context) {
                let EncryptedAttachment::Stream(stream) = descriptor else {
                    anyhow::bail!("unsupported_attachment_scheme");
                };
                anyhow::ensure!(
                    stream.size_bytes == self.input_size
                        && stream.media_type == self.media_type
                        && stream.segment_bytes == u64::from(SEGMENT_BYTES)
                        && Some(&stream.nonce_prefix) == self.nonce_prefix.as_ref()
                        && descriptor.blob_ref() == &prepared.blob_ref
                        && descriptor.content_key_context(
                            self.scope.clone(),
                            context.genesis_event_ref.clone(),
                            context.epoch
                        ) == *context
                        && self
                            .checkpoint
                            .as_ref()
                            .and_then(|c| c.group_state_event_id.as_ref())
                            == Some(&descriptor.key_ref().group_state_ref.event_id()?),
                    "attachment descriptor differs from intent"
                );
            }
        } else {
            anyhow::ensure!(
                !self.uploaded && self.submitted_operation.is_none(),
                "attachment is not prepared"
            );
        }
        Ok(())
    }

    pub(crate) async fn prepare(
        &self,
        chunks: &crate::state::current_index::AttachmentChunkStore,
    ) -> anyhow::Result<PreparedAttachment> {
        self.validate()?;
        if let Some(prepared) = &self.prepared {
            return Ok(prepared.clone());
        }
        let count = arkret_models_crypto::stream_segment_count(self.input_size, SEGMENT_BYTES)?;
        let expected = self.input_digest.as_ref().ok_or_else(||anyhow::anyhow!("attachment source is incomplete; select the file again or remove the interrupted object"))?;
        // Verify the durable source before restoring a secret or encrypting.
        let mut input_hasher = arkret_sdk::canonical::ContentHasher::new(self.digest_suite);
        for index in 0..count {
            let input = chunks.read_part("input", index).await?;
            let length = self
                .input_size
                .saturating_sub(u64::from(index) * u64::from(SEGMENT_BYTES))
                .min(u64::from(SEGMENT_BYTES));
            anyhow::ensure!(
                input.len() as u64 == length,
                "frozen attachment source geometry differs"
            );
            input_hasher.update(&input);
        }
        anyhow::ensure!(
            input_hasher.finish() == expected.as_str(),
            "frozen attachment source digest differs"
        );
        let descriptor = if let Some(context) = &self.context {
            let snapshot = self
                .checkpoint
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing frozen checkpoint"))?;
            let reference = snapshot
                .group_state_event_id
                .clone()
                .ok_or_else(|| anyhow::anyhow!("missing accepted reference"))?;
            let group =
                restore_attachment_group(snapshot, &self.authority, &self.device_id, context)?;
            let (_, tree) = group.public_group_state_bytes()?;
            let tree_ref = self
                .state_tree_ref
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing winning tree"))?;
            let tree_suite =
                arkret_models_collaboration::mls_group_state_material::material_digest_from_ref(
                    tree_ref,
                )?
                .digest_suite()?;
            anyhow::ensure!(
                tree_ref.as_str()
                    == format!(
                        "ak:blob:{}",
                        arkret_sdk::canonical::digest(tree_suite, &tree)
                    ),
                "attachment checkpoint is not the winning tree"
            );
            let key = arkret_sdk::mls::derive_attachment_content_key(&group, context)?;
            let parameters = arkret_crypto::blob_aead::StreamEncryptParams {
                key_ref: EncryptedAttachmentKeyRef {
                    algorithm: EncryptedAttachmentKeyAlgorithm::Mls,
                    group_state_ref: EncryptedAttachmentGroupStateRef::Event(reference.clone()),
                },
                content_key_salt: self.salt.clone(),
                digest_suite: self.digest_suite,
                media_type: self.media_type.clone(),
                segment_bytes: SEGMENT_BYTES,
            };
            let prefix: [u8; 19] = arkret_sdk::canonical::base64url_decode(
                self.nonce_prefix
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("missing prefix"))?
                    .as_str(),
            )?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid prefix"))?;
            let resolver = |r: &EncryptedAttachmentGroupStateRef| {
                r.event_id()
                    .ok()
                    .filter(|id| id == &reference)
                    .map(|_| context.epoch)
            };
            let mut encoder = arkret_crypto::blob_aead::StreamEncryptor::new(
                self.input_size,
                &key,
                &parameters,
                prefix,
                &resolver,
            )?;
            for index in 0..count {
                let input = chunks.read_part("input", index).await?;
                let ciphertext = encoder.push_segment(&input)?;
                chunks.write_part("ciphertext", index, &ciphertext).await?;
            }
            Some(encoder.finish()?)
        } else {
            for index in 0..count {
                let input = chunks.read_part("input", index).await?;
                chunks.write_part("ciphertext", index, &input).await?;
            }
            None
        };
        let blob_ref = match &descriptor {
            Some(d) => d.blob_ref().clone(),
            None => arkret_sdk::BlobRef::new(format!("ak:blob:{expected}"))?,
        };
        let content = if self.long_text {
            let descriptor = descriptor
                .clone()
                .ok_or_else(|| anyhow::anyhow!("private long text requires stream AEAD"))?;
            arkret_sdk::ContentBlock::encrypted_long_text_summary(
                self.text_prefix
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("missing text prefix"))?,
                self.line_count
                    .ok_or_else(|| anyhow::anyhow!("missing line count"))?,
                descriptor,
            )?
        } else {
            content_for_attachment(
                &self.filename,
                &self.media_type,
                self.input_size,
                &blob_ref,
                descriptor.as_ref(),
            )?
        };
        Ok(PreparedAttachment {
            content,
            ciphertext_size: self.input_size
                + if descriptor.is_some() {
                    16 * u64::from(count)
                } else {
                    0
                },
            part_count: count,
            descriptor,
            blob_ref,
        })
    }
}

/// Oversized private text follows the same frozen, segmented upload pipeline.
pub(crate) async fn private_message_body(
    api: &crate::transport::TransportClient,
    store: crate::runtime::input::StateStoreHandle,
    authority: &AccountId,
    device: &DeviceId,
    scope: &ScopeRef,
    strand: &str,
    operation: &str,
    body: &str,
) -> anyhow::Result<arkret_sdk::ContentBlock> {
    let body = arkret_sdk::normalize_long_text(body)?;
    if body.len() <= arkret_sdk::CONTENT_TEXT_INLINE_MAX_BYTES {
        return Ok(arkret_sdk::ContentBlock::markdown_text(body));
    }
    anyhow::ensure!(
        body.len() as u64 <= MAX_OBJECT_BYTES,
        "long text exceeds client limit"
    );
    let fence = crate::transport::auth::AuthoringSessionFence::capture()?;
    let vault = crate::outbound_store::InksonOutboundStore::open(
        authority,
        crate::outbound_store::OutboundLane::Standard,
    )?;
    let id = format!("long-text:{operation}");
    let suite = arkret_sdk::DigestSuite::Sha256;
    let digest = arkret_sdk::Hash::new(arkret_sdk::canonical::digest(suite, body.as_bytes()))?;
    let chunks = crate::state::current_index::AttachmentChunkStore::open(
        store.read(|s| s.current_index_location()),
        authority,
        device,
        &id,
    )
    .await?;
    let mut object = match vault.attachment_object(&id).await? {
        Some(object) => {
            anyhow::ensure!(
                &object.authority == authority
                    && &object.device_id == device
                    && &object.scope == scope
                    && object.input_size == body.len() as u64
                    && object.input_digest.as_ref().is_none_or(|d| d == &digest),
                "long-text intent changed"
            );
            object
        }
        None => {
            let gate = crate::mls::send_gate::resolve_restorable_mls_send_gate(
                &crate::mls::send_gate::MlsSendGateInput::capture(&store, scope),
                scope,
                device,
            )
            .await?;
            let crate::mls::send_gate::MlsSendGate::Encrypted(current) = gate else {
                anyhow::bail!("private text requires MLS");
            };
            let checkpoint = store
                .read(|s| s.durable_mls_checkpoint_for_scope(scope))?
                .ok_or_else(|| anyhow::anyhow!("missing checkpoint"))?;
            anyhow::ensure!(
                checkpoint.epoch == current.epoch
                    && checkpoint.group_state_event_id.as_ref()
                        == Some(&current.current_mls_commit_event_ref),
                "long-text state changed"
            );
            let salt = arkret_crypto::blob_aead::fresh_content_key_salt()?;
            let context = AttachmentContentKeyContext {
                effective_scope: scope.clone(),
                genesis_event_ref: current.genesis_event_ref,
                epoch: current.epoch,
                scheme: arkret_crypto::blob_aead::SCHEME_STREAM.into(),
                encryption_algorithm: arkret_crypto::blob_aead::ALG_STREAM_XCHACHA.into(),
                content_key_salt: salt.clone(),
            };
            fence.check_session_identity()?;
            vault
                .freeze_attachment(AttachmentObject {
                    id,
                    authority: authority.clone(),
                    device_id: device.clone(),
                    scope: scope.clone(),
                    strand_id: StrandId::new(strand.to_owned())?,
                    filename: "message.md".into(),
                    long_text: true,
                    input_size: body.len() as u64,
                    input_digest: None,
                    text_prefix: Some(
                        arkret_models_collaboration::events_payloads::message::long_text_prefix(
                            &body,
                        )
                        .to_owned(),
                    ),
                    line_count: Some(
                        arkret_models_collaboration::events_payloads::message::long_text_line_count(
                            &body,
                        ),
                    ),
                    media_type: "text/markdown".into(),
                    salt,
                    digest_suite: suite,
                    context: Some(context),
                    checkpoint: Some(checkpoint),
                    state_tree_ref: Some(current.public_tree_ref),
                    nonce_prefix: Some(
                        arkret_sdk::Base64UrlString::new(arkret_sdk::canonical::base64url_encode(
                            arkret_crypto::blob_aead::fresh_stream_nonce_prefix()?,
                        ))
                        .map_err(anyhow::Error::msg)?,
                    ),
                    prepared: None,
                    uploaded: false,
                    submitted_operation: None,
                })
                .await?
        }
    };
    if object.input_digest.is_none() {
        let digest = input_bytes_to_parts(&chunks, body.as_bytes(), suite).await?;
        object = vault.freeze_attachment_input(&object.id, digest).await?;
    }
    if object.prepared.is_none() {
        let prepared = object.prepare(&chunks).await?;
        object = vault
            .freeze_prepared_attachment(&object.id, prepared)
            .await?;
        chunks.clear("input").await?;
    }
    fence.check_session_identity()?;
    if !object.uploaded {
        let endpoint = crate::transport::BlobEndpoints::new(api);
        with_target_fence(endpoint.upload_attachment_object(&object, chunks), || {
            fence.check_session_identity().is_ok()
        })
        .await?;
        fence.check_session_identity()?;
        vault.mark_attachment_uploaded(&object.id).await?;
    }
    fence.check_session_identity()?;
    Ok(object
        .prepared
        .ok_or_else(|| anyhow::anyhow!("missing long-text descriptor"))?
        .content)
}

/// The raw reference is kept for segment AAD; normalized EventId is resolution only.
pub(crate) fn attachment_receive_context(
    state: &crate::state::LocalStateStore,
    authority: &AccountId,
    scope: &ScopeRef,
    current: &arkret_wire::MlsGroupValue,
    descriptor: &EncryptedAttachment,
) -> anyhow::Result<(
    AttachmentContentKeyContext,
    garth::mls::checkpoint::MlsLocalCheckpointEnvelope,
    EventId,
)> {
    anyhow::ensure!(
        state.active_authority().as_ref() == Some(authority) && !state.current_reset_required(),
        "attachment account is not ready"
    );
    // The caller supplies the actor-authorized complete durable cut. Product
    // views can be temporarily uninstalled during reconciliation or navigation;
    // rereading that ephemeral cache would discard this already verified input.
    anyhow::ensure!(
        &current.effective_scope == scope,
        "attachment scope differs"
    );
    let reference = descriptor.key_ref().group_state_ref.event_id()?;
    let snapshot = state.attachment_checkpoint_for_ref(scope, &reference)?;
    anyhow::ensure!(
        snapshot.epoch <= current.epoch,
        "attachment state is beyond the authorized cut"
    );
    let context = descriptor.content_key_context(
        scope.clone(),
        current.genesis_event_ref.clone(),
        snapshot.epoch,
    );
    context.validate()?;
    Ok((context, snapshot, reference))
}

pub(crate) fn compose_attachments(
    mut content: arkret_sdk::ContentBlock,
    attachments: &[arkret_sdk::ContentBlock],
) -> anyhow::Result<arkret_sdk::ContentBlock> {
    if !attachments.is_empty() {
        let mut composite =
            arkret_sdk::ContentBlock::new(arkret_sdk::ContentBlockKind::Composite, "");
        if !content.body.is_empty() || !content.extra.is_empty() {
            composite = composite.with_part(content);
        }
        for attachment in attachments {
            composite = composite.with_part(attachment.clone());
        }
        content = composite;
    }
    content.referenced_blobs()?;
    Ok(content)
}

pub(crate) fn compose_draft_attachments(
    content: arkret_sdk::ContentBlock,
    drafts: &[DraftAttachment],
    scope: &ScopeRef,
) -> anyhow::Result<arkret_sdk::ContentBlock> {
    anyhow::ensure!(
        drafts.iter().all(|a| !a.pending),
        "Wait for attachment upload to finish or remove the pending file."
    );
    anyhow::ensure!(
        drafts.iter().all(|a| &a.scope == scope),
        "Attachments belong to a different public/private conversation. Remove them before changing the target."
    );
    compose_attachments(
        content,
        &drafts.iter().map(|a| a.content.clone()).collect::<Vec<_>>(),
    )
}
