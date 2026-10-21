//! Native access to the ordinary product message path, with no alternate author.
use garth::OutboundQueueStore as _;

pub use crate::event_submit::conformance_transport::MessageResponseLoss;

/// Run the real MLS ratchet and durability barrier, then the same local author,
/// signing, queue and submit entry used by the composer. The host must already
/// own its accepted group and authenticated device session.
pub async fn send_native_ordinary_mls_message(
    host: &crate::sync_engine::NativeAccountHost,
    realm: &arkret_sdk::RealmId,
    strand: &arkret_sdk::StrandId,
    body: &str,
) -> anyhow::Result<crate::models::SubmitEventResult> {
    let account = host.active_account_context();
    let scope = arkret_sdk::ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let store = host.state_store_handle();
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    let plain = arkret_sdk::canonical::canonical_json_bytes(&arkret_sdk::ContentBlock::text(body))?;
    let (encrypted, barrier) = store.write(|state| -> anyhow::Result<_> {
        let checkpoint = state.mls_checkpoint_for_scope(&scope).ok_or_else(|| {
            anyhow::anyhow!("ordinary message lacks its accepted private checkpoint")
        })?;
        let reference = state
            .mls_group_state_ref_for_scope(&scope, &checkpoint.group_id, checkpoint.epoch)
            .map_err(anyhow::Error::msg)?;
        let encrypted = crate::mls::runtime::encrypt_message_with_device_snapshot(
            state,
            secure.as_ref(),
            realm.as_str(),
            &account.authority,
            &account.device_id,
            "application/vnd.arkret.message+json",
            arkret_sdk::EventKind::MessageCreate.as_str(),
            reference,
            &plain,
            None,
            None,
            None,
            None,
            None,
        )
        .map_err(|error| anyhow::anyhow!("ordinary native MLS encryption: {error:?}"))?;
        Ok((encrypted.content, state.begin_durable_flush()?))
    })?;
    barrier.wait().await?;
    super::persist_native_private_cache(&host.state_store()).await?;
    let encryption_context = arkret_sdk::MessageEncryptionContext {
        scheme: encrypted.pre_encryption_header.scheme.clone(),
        effective_scope: encrypted.pre_encryption_header.effective_scope.clone(),
        sender_domain: encrypted.pre_encryption_header.sender_domain.clone(),
    };
    let api = crate::transport::TransportClient::from_http(
        host.call_http_client(),
        crate::transport::RequestContext::new(""),
    );
    crate::views::chat::model::send_ordinary_chat_message(
        &api,
        store,
        realm.as_str(),
        scope,
        strand.as_str(),
        arkret_sdk::MessageAuthoringContent::Mls {
            encrypted_content: arkret_sdk::mls::encrypted_envelope_from_payload(&encrypted)?,
            encrypted_metadata: None,
            encryption_context,
        },
        None,
        format!("native-message:{}", crate::operation::uuid_v7()),
    )
    .await
    .map_err(anyhow::Error::from)
}

/// Inspect the ordinary protected durable queue without replacing its store.
pub async fn native_ordinary_outbound_snapshot(
    host: &crate::sync_engine::NativeAccountHost,
) -> anyhow::Result<garth::SendQueueSnapshot> {
    let account = host.active_account_context();
    Ok(crate::outbound_store::InksonOutboundStore::open(
        &account.authority,
        crate::outbound_store::OutboundLane::Standard,
    )?
    .mutate_outbound(|queue| Ok(queue.snapshot()))
    .await?)
}

/// Resume the product drain. This does not encrypt, author or sign an Event.
pub async fn drain_native_ordinary_messages(
    host: &crate::sync_engine::NativeAccountHost,
) -> anyhow::Result<usize> {
    crate::event_submit::EventSubmitter::new(host.call_http_client())
        .with_authority(host.active_account_context().authority)
        .with_state_store(host.state_store_handle())
        .drain_outbound()
        .await
}

/// Return actual private provider bytes only to the native conformance caller.
pub fn native_private_mls_record(
    host: &crate::sync_engine::NativeAccountHost,
    scope: &arkret_sdk::ScopeRef,
) -> anyhow::Result<arkret_sdk::MlsGroupStateRecord> {
    let account = host.active_account_context();
    let checkpoint = host
        .state_store()
        .mls_checkpoint_for_scope(scope)
        .ok_or_else(|| anyhow::anyhow!("private checkpoint absent"))?;
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    let secret = crate::mls::runtime::load_device_checkpoint_secret(
        secure.as_ref(),
        &account.authority,
        &account.device_id,
    )?;
    let group = crate::mls::persistence::restore_envelope(&checkpoint, &secret, checkpoint.epoch)?;
    Ok(group.export_state_record()?)
}
