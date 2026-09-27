use super::*;
use crate::payload::strand_id_value;

pub(crate) const CHAT_PRIVATE_SAVED_COLLECTION_TITLE: &str = "Saved";

pub(crate) fn fail_optimistic_chat_send(
    mut messages: Signal<Vec<ChatMessage>>,
    mut chat_draft: Signal<String>,
    mut status_msg: Signal<String>,
    message_id: &str,
    body_for_restore: &str,
    message: String,
) {
    if let Some(found) = messages
        .write()
        .iter_mut()
        .find(|candidate| candidate.matches_id_or_protocol(message_id))
    {
        found.pending = false;
        found.failed = true;
        found.error = Some(message.clone());
    }
    if chat_draft().trim().is_empty() {
        chat_draft.set(body_for_restore.to_owned());
    }
    status_msg.set(message);
}

// The MLS encrypt + commit/envelope/payload build + commit→message submission
// orchestration for the encrypted "Send Secure" path now lives in the shared
// `crate::views::secure_send` module so chat drives ONE MLS core +
// persist-on-accept pipeline. The Chat composer calls
// `secure_send::build_secure_send` / `secure_send::submit_secure_send`
// directly; the former local `run_local_mls_encrypt` / `chat_mls_*` helpers
// moved there verbatim.

pub(crate) fn next_shared_pin_rank() -> String {
    format!("r{}", chrono::Utc::now().timestamp_millis())
}

pub(crate) fn shared_pin_scope_for_message(_realm_id: &str, strand_id: &str) -> SharedPinScope {
    let strand_id = strand_id.trim();
    // Default-Strand identity is not derivable from the Realm token. The
    // caller's exact selected Strand is therefore the only authoritative
    // scope available here.
    SharedPinScope::strand(strand_id.to_owned())
}

fn sdk_pin_scope(pin_scope: &SharedPinScope) -> anyhow::Result<arkret_sdk::PinScope> {
    match pin_scope.kind {
        SharedPinScopeKind::Realm => Ok(arkret_sdk::PinScope::Realm {
            id: arkret_sdk::RealmId::new(pin_scope.id.clone())
                .map_err(|error| anyhow::anyhow!("invalid pin realm scope: {error:?}"))?,
        }),
        SharedPinScopeKind::Strand => Ok(arkret_sdk::PinScope::Strand {
            id: arkret_sdk::StrandId::new(pin_scope.id.clone())
                .map_err(|error| anyhow::anyhow!("invalid pin strand scope: {error:?}"))?,
        }),
    }
}

pub(crate) fn shared_message_pin_add_operation(
    realm_id: &str,
    actor: &str,
    pin_scope: &SharedPinScope,
    target_ref: &str,
    rank: &str,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let payload = arkret_sdk::PinAddPayload {
        pin_scope: sdk_pin_scope(pin_scope)?,
        target_ref: target_ref.to_owned(),
        rank: rank.to_owned(),
        note: None,
    };
    crate::operation::TypedOperationBuilder::new::<arkret_sdk::event_spec::PinAdd>(
        realm_id, actor, payload,
    )
    .target_ref(target_ref)
    .build_sdk_event("inkson")
}

pub(crate) fn shared_message_pin_remove_operation(
    realm_id: &str,
    actor: &str,
    pin_scope: &SharedPinScope,
    target_ref: &str,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let payload = arkret_sdk::PinRemovePayload {
        pin_scope: sdk_pin_scope(pin_scope)?,
        target_ref: target_ref.to_owned(),
        expected_rank: None,
    };
    crate::operation::TypedOperationBuilder::new::<arkret_sdk::event_spec::PinRemove>(
        realm_id, actor, payload,
    )
    .target_ref(target_ref)
    .build_sdk_event("inkson")
}

pub(crate) fn load_chat_productivity_namespace_key(
    authority: &arkret_sdk::AccountId,
) -> anyhow::Result<[u8; crate::account_data::PRODUCTIVITY_ACCOUNT_DATA_NAMESPACE_KEY_LEN]> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let account_secret =
        crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), authority)
            .map_err(|error| anyhow::anyhow!("account MLS secret unavailable: {error}"))?
            .ok_or_else(|| anyhow::anyhow!("account MLS secret recovery is required"))?;
    crate::account_data::productivity_account_data_namespace_key(&account_secret.secret)
}

pub(crate) fn chat_saved_account_data_item(
    namespace_key: &[u8],
    target_ref: &str,
    updated_hlc: &str,
) -> anyhow::Result<crate::account_data::SavedAccountDataItem> {
    crate::account_data::saved_account_data_item(
        namespace_key,
        arkret_sdk::SavedItemValue {
            collection_title: CHAT_PRIVATE_SAVED_COLLECTION_TITLE.to_owned(),
            target_ref: target_ref.to_owned(),
            note: None,
            updated_hlc: updated_hlc.to_owned(),
        },
    )
}

pub(crate) fn private_saved_targets_from_account_data(
    entries: &std::collections::BTreeMap<String, Value>,
    collection_title: &str,
) -> std::collections::BTreeSet<String> {
    entries
        .values()
        .filter_map(|value| crate::account_data::saved_item_value_from_account_data(value).ok())
        .filter(|value| value.collection_title == collection_title)
        .map(|value| value.target_ref)
        .collect()
}

#[cfg(test)]
pub(crate) fn chat_message_revise_operation(
    realm_id: &str,
    actor: &str,
    event_id: &str,
    body: &str,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let content = chat_content_block_for_body(body)?;
    chat_message_revise_operation_with_content(realm_id, actor, event_id, content)
}

pub(crate) fn chat_message_revise_operation_with_content(
    realm_id: &str,
    actor: &str,
    event_id: &str,
    content: arkret_sdk::ContentBlock,
) -> anyhow::Result<crate::operation::LocalOperation> {
    // Route through the SDK-typed `message_revise_payload` builder rather than a
    // hand-rolled `json!` body: it validates ids at build time and addresses a
    // `ak:message:` target via the payload's `message_id` field (falling back to
    // `target_ref` for event/local refs), matching the schema's anyOf.
    crate::operation::ak_ops::message_revise_content(realm_id, actor, event_id, content)?
        .build_sdk_event("inkson")
}

pub(crate) fn chat_message_redact_operation(
    realm_id: &str,
    actor: &str,
    target_id: &str,
    reason: &str,
) -> anyhow::Result<crate::operation::LocalOperation> {
    // `message_id` is the single registered target carrier; an `ak:event:`
    // create token is retyped to `ak:message:` (`common-fields.md` §6.0).
    let target_id = target_id.trim();
    let candidate = match target_id.strip_prefix("ak:event:") {
        Some(token) => format!("ak:message:{token}"),
        None => target_id.to_owned(),
    };
    let message_id = arkret_sdk::MessageId::new(candidate)
        .map_err(|err| anyhow::anyhow!("invalid redaction message target: {err}"))?;
    let payload = arkret_sdk::MessageRedactPayload {
        message_id: message_id.clone(),
        track_name: None,
        reason: Some(reason.to_owned()),
        preserve: None,
        mimi_provenance: None,
    };
    crate::operation::TypedOperationBuilder::new::<arkret_sdk::event_spec::MessageRedact>(
        realm_id, actor, payload,
    )
    .target_ref(message_id.as_str())
    .build_sdk_event("inkson")
}

pub(crate) fn chat_reaction_add_operation(
    realm_id: &str,
    actor: &str,
    event_id: &str,
    key: &str,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let payload = arkret_sdk::ReactionPayload {
        target_ref: event_id.into(),
        key: key.to_owned(),
        annotation: None,
        encrypted_payload: None,
    };
    crate::operation::TypedOperationBuilder::new::<arkret_sdk::event_spec::ReactionAdd>(
        realm_id, actor, payload,
    )
    .target_ref(event_id)
    .build_sdk_event("inkson")
}

/// E2EE reaction (encryption-and-audit.md §2.9): the plaintext `key` carries
/// the v1 keyed-HMAC routing tag (43-character base64url) so the server can still
/// OR-Set dedup / rate-limit without learning the emoji; the real emoji
/// travels inside `encrypted_payload`.
pub(crate) fn chat_reaction_add_operation_encrypted(
    realm_id: &str,
    actor: &str,
    event_id: &str,
    routing_tag: &str,
    encrypted_payload: &arkret_sdk::EncryptedEnvelope,
    created_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let payload = arkret_sdk::ReactionPayload {
        target_ref: event_id.into(),
        key: routing_tag.to_owned(),
        annotation: None,
        encrypted_payload: Some(encrypted_payload.clone()),
    };
    crate::operation::TypedOperationBuilder::new::<arkret_sdk::event_spec::ReactionAdd>(
        realm_id, actor, payload,
    )
    .target_ref(event_id)
    .created_at(created_at)
    .build_sdk_event("inkson")
}

/// Build the `ak.reaction.add` operation for a tapped emoji, choosing the
/// plaintext or E2EE (§2.9 routing-tag) shape based on whether the channel
/// is encrypted. On any MLS failure in an encrypted channel the reaction is
/// dropped (returns `None`) rather than leaking the emoji in plaintext.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_chat_reaction_add_operation(
    mut state_store: SyncSignal<LocalStateStore>,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    actor: &str,
    device_id: &arkret_sdk::DeviceId,
    event_id: &str,
    emoji: &str,
    channel_encrypted: bool,
) -> anyhow::Result<Option<crate::operation::LocalOperation>> {
    if !channel_encrypted {
        return chat_reaction_add_operation(realm_id, actor, event_id, emoji).map(Some);
    }
    let realm_id = trim_realm_id(realm_id);
    let target_ref = arkret_sdk::EventId::new(event_id.to_owned())
        .map_err(|error| anyhow::anyhow!("invalid reaction target Event id: {error}"))?;
    let created_at = crate::clock::now_utc();
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let sealed = match crate::mls::runtime::encrypt_reaction_with_device_snapshot(
        &mut state_store.write(),
        secure_store.as_ref(),
        &realm_id,
        authority,
        device_id,
        &target_ref,
        created_at,
        emoji,
    ) {
        Ok(sealed) => sealed,
        Err(_) => return Ok(None),
    };
    let encrypted_payload = arkret_sdk::mls::encrypted_envelope_from_payload(
        &sealed.encrypted_payload,
    )
    .map_err(|error| anyhow::anyhow!("reaction encrypted envelope build failed: {error}"))?;
    chat_reaction_add_operation_encrypted(
        &realm_id,
        actor,
        event_id,
        &sealed.routing_tag,
        &encrypted_payload,
        created_at,
    )
    .map(Some)
}

pub(crate) fn is_schema_message_id(value: &str) -> bool {
    arkret_sdk::MessageId::new(value.trim().to_owned()).is_ok()
}

pub(crate) fn new_chat_local_id() -> String {
    format!("local-message:{}", uuid_v7())
}

pub(crate) fn message_id_or_new_local_id(value: &str) -> String {
    if is_schema_message_id(value) {
        value.trim().to_owned()
    } else {
        new_chat_local_id()
    }
}

fn public_update_policy_error(body: &str) -> Option<&'static str> {
    let lower = body.to_ascii_lowercase();
    if !lower.contains("public update") {
        return None;
    }
    let sensitive = [
        "root cause",
        "leaked",
        "token",
        "secret",
        "credential",
        "password",
        "private key",
        "api key",
    ];
    sensitive
        .iter()
        .any(|term| lower.contains(term))
        .then_some("public_update_blocked: remove internal root-cause or credential details")
}

pub(crate) fn chat_content_block_for_body(body: &str) -> anyhow::Result<arkret_sdk::ContentBlock> {
    if let Some(error) = public_update_policy_error(body) {
        anyhow::bail!(error);
    }
    let normalized = arkret_sdk::normalize_long_text(body)
        .map_err(|error| anyhow::anyhow!("normalize message body: {error}"))?;
    let content = arkret_sdk::ContentBlock::markdown_text(normalized);
    content
        .validate_inline_text()
        .map_err(|error| anyhow::anyhow!("build inline message content: {error}"))?;
    Ok(content)
}

pub(crate) async fn chat_content_block_for_body_with_upload(
    base_url: &str,
    session_credential: String,
    wait_for_sync_token: Option<String>,
    realm_id: &str,
    body: &str,
) -> anyhow::Result<arkret_sdk::ContentBlock> {
    if let Some(error) = public_update_policy_error(body) {
        anyhow::bail!(error);
    }
    let normalized = arkret_sdk::normalize_long_text(body)
        .map_err(|error| anyhow::anyhow!("normalize message body: {error}"))?;
    if normalized.len() <= arkret_sdk::CONTENT_TEXT_INLINE_MAX_BYTES {
        return chat_content_block_for_body(&normalized);
    }
    let api = crate::transport::auth::authed_api_with_sync(
        base_url,
        session_credential,
        wait_for_sync_token,
    )?;
    let clients = crate::transport::EndpointClients::from_http(api.sdk_http_client()?);
    clients
        .blob()
        .upload_plaintext_long_text(
            &normalized,
            arkret_sdk::LongTextMediaType::Markdown,
            realm_id,
        )
        .await
}

pub(crate) fn chat_message_create_operation_with_content(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    message_id: &str,
    body: &str,
    content: arkret_sdk::ContentBlock,
    mentions: &[MentionNode],
    reply_to: Option<&str>,
) -> anyhow::Result<crate::operation::LocalOperation> {
    chat_message_create_operation_with_content_inner(
        realm_id, actor, strand_id, message_id, body, content, mentions, reply_to,
    )
}

/// Build the only shared Event shape accepted by explicit Sidecar publish.
/// The caller must present the final body to the controller and pass
/// `controller_confirmed=true` only after confirmation. No private Event
/// envelope or metadata map is accepted by this API, so retries cannot widen
/// the allowlist beyond a normal shared message body.
pub(crate) fn confirmed_sidecar_publish_message_operation(
    privacy_gate: &crate::sidecar::SidecarPrivacyGate,
    controller_confirmed: bool,
    realm_id: &str,
    actor: &str,
    target_shared_strand_id: &str,
    message_id: &str,
    allowlisted_body: &str,
) -> anyhow::Result<crate::operation::LocalOperation> {
    privacy_gate.validate_shared_publish(
        controller_confirmed,
        target_shared_strand_id,
        allowlisted_body,
    )?;
    let content = chat_content_block_for_body(allowlisted_body)?;
    let event = chat_message_create_operation_with_content(
        realm_id,
        actor,
        target_shared_strand_id,
        message_id,
        allowlisted_body,
        content,
        &[],
        None,
    )?;
    // A shared publish is also the only Sidecar-derived value eligible for a
    // later public export. Validate the complete ordinary write rather than
    // assuming the allowlisted body alone makes its envelope safe.
    privacy_gate.validate_public_export(event.intent())?;
    Ok(event)
}

/// Fold explicit mention intent into the Content Block the user authored.
///
/// Mentions are Content Block nodes, not a second durable write: the caller
/// gets one block back and nothing else is emitted on its behalf.
pub(crate) fn chat_content_with_mentions(
    body: &str,
    mut content: arkret_sdk::ContentBlock,
    mentions: &[MentionNode],
) -> anyhow::Result<arkret_sdk::ContentBlock> {
    if let Some(error) = public_update_policy_error(body) {
        anyhow::bail!(error);
    }
    let actor_mentions = mentions
        .iter()
        .filter_map(|mention| mention.as_mention().cloned())
        .collect::<Vec<_>>();
    let audience_mentions = mentions
        .iter()
        .filter_map(|mention| mention.as_audience_mention().cloned())
        .collect::<Vec<_>>();
    if content.kind == arkret_sdk::ContentBlockKind::LongText
        && (!actor_mentions.is_empty() || !audience_mentions.is_empty())
    {
        let fallback = content.body.clone();
        content = arkret_sdk::ContentBlock::new(arkret_sdk::ContentBlockKind::Composite, fallback)
            .with_part(content);
    }
    if !actor_mentions.is_empty() {
        content = content
            .with_mentions(actor_mentions)
            .map_err(|err| anyhow::anyhow!("chat message mentions serialize: {err}"))?;
    }
    if !audience_mentions.is_empty() {
        content = content
            .with_audience_mentions(audience_mentions)
            .map_err(|err| anyhow::anyhow!("chat message audience_mentions serialize: {err}"))?;
    }
    Ok(content)
}

/// The closed typed intent for one ordinary message.
///
/// This is the only thing a chat send hands to the shared authoring engine.
/// There is deliberately no way to reach an Event envelope from here: the
/// actor chain position, authority closure and CBS basis are the Station's
/// answers, and this client checks them rather than inventing them.
pub(crate) fn chat_message_authoring_intent(
    strand_id: &str,
    content: arkret_sdk::MessageAuthoringContent,
    reply_to: Option<&str>,
) -> anyhow::Result<arkret_sdk::MessageAuthoringIntent> {
    let reply_to_id = match reply_to.map(str::trim).filter(|value| !value.is_empty()) {
        Some(reply_to) => {
            if !is_schema_message_id(reply_to) {
                anyhow::bail!("reply_to must be a ak:message id");
            }
            Some(reply_to.to_owned())
        }
        None => None,
    };
    let intent = arkret_sdk::MessageAuthoringIntent {
        strand_id: strand_id_value(strand_id)?,
        track_name: arkret_sdk::MessageTrackName::Discussion,
        content,
        blob_refs: vec![],
        reply_to_id,
    };
    // The closed SDK intent has no independent validator. Its payload is
    // authored through the typed MessageCreate builder, then the governing
    // Station validates the committed Event against the registered schema.
    Ok(intent)
}

fn chat_message_create_operation_with_content_inner(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    _local_message_id: &str,
    body: &str,
    content: arkret_sdk::ContentBlock,
    mentions: &[MentionNode],
    reply_to: Option<&str>,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let content = chat_content_with_mentions(body, content, mentions)?;
    // T2.3: v1 wire uses `track_name` — a display-only message segment
    // identifier — instead of the removed `branch` top-level field.
    let mut payload = arkret_sdk::MessageCreatePayload::with_content(
        strand_id_value(strand_id)?,
        "discussion",
        content,
    );
    if let Some(reply_to) = reply_to.map(str::trim).filter(|value| !value.is_empty()) {
        if !is_schema_message_id(reply_to) {
            anyhow::bail!("reply_to must be a ak:message id");
        }
        payload = payload.with_reply_to_id(reply_to);
    }
    crate::operation::TypedOperationBuilder::new::<arkret_sdk::event_spec::MessageCreate>(
        realm_id, actor, payload,
    )
    .target_ref(strand_id)
    .build_sdk_event("inkson")
}

/// The exact reason one ordinary message did not land, in the user's words.
///
/// Every branch names a different situation and a different thing to do about
/// it. A send that is waiting on its own authorization to be sealed is not the
/// same event as a Station returning a message the user did not author, and
/// collapsing both into "send failed" tells the user nothing they can act on.
pub(crate) fn chat_authoring_failure_message(
    failure: &garth::MessageAuthoringFailure,
) -> &'static str {
    match failure {
        garth::MessageAuthoringFailure::AuthorizationPending { .. } => {
            "chat.send.not_ready.authorization"
        }
        garth::MessageAuthoringFailure::DependencyUnavailable { .. } => {
            "chat.send.not_ready.dependency"
        }
        garth::MessageAuthoringFailure::PlaintextRefused { .. } => "chat.send.failed.e2ee_required",
        garth::MessageAuthoringFailure::EncryptionContextChanged { .. } => {
            "chat.send.failed.encryption_context"
        }
        garth::MessageAuthoringFailure::EpochCommitPending { .. } => {
            "chat.send.not_ready.epoch_commit"
        }
        garth::MessageAuthoringFailure::DuplicateConflict { .. } => "chat.send.failed.duplicate",
        garth::MessageAuthoringFailure::SubmissionOutcomeUnknown { .. } => {
            "chat.send.pending.unknown"
        }
        garth::MessageAuthoringFailure::RevisionConflict { .. } => "chat.send.failed.revision",
        garth::MessageAuthoringFailure::PermissionRevoked { .. } => "chat.send.failed.permission",
        garth::MessageAuthoringFailure::PreconditionFailed { .. } => {
            "chat.send.failed.precondition"
        }
        garth::MessageAuthoringFailure::Refused { .. } => "chat.send.failed.refused",
    }
}

/// Send one ordinary message through the shared typed authoring engine.
///
/// The `content` is already final: plaintext the target still permits, or the
/// envelope this device's MLS engine produced. Nothing below this call can
/// change it, so a retry inside the engine never re-encrypts and never consumes
/// another sender counter.
pub(crate) async fn send_ordinary_chat_message(
    api: &TransportClient,
    realm_id: &str,
    scope: arkret_sdk::ScopeRef,
    strand_id: &str,
    content: arkret_sdk::MessageAuthoringContent,
    reply_to: Option<&str>,
    local_operation_id: String,
) -> std::result::Result<SubmitEventResult, garth::MessageAuthoringFailure> {
    let refused = |error: anyhow::Error| garth::MessageAuthoringFailure::Refused {
        code: "failed_precondition".to_owned(),
        detail: format!("{error:#}"),
    };
    let submitter = api.event_submitter().map_err(refused)?;
    let intent = chat_message_authoring_intent(strand_id, content, reply_to).map_err(refused)?;
    let session = submitter.message_authoring_session(
        realm_id,
        scope,
        intent,
        crate::clock::now_utc_millis(),
    )?;
    crate::event_submit::drive_message_send(
        &submitter,
        crate::event_submit::MessageSendAttempt {
            session,
            local_operation_id,
        },
    )
    .await
}
