use super::*;
use crate::api_error::{
    is_auth_expired_error, is_plaintext_visibility_policy_error, is_space_membership_denied_error,
};
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
) -> anyhow::Result<arkret_sdk::Event> {
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
) -> anyhow::Result<arkret_sdk::Event> {
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
    actor_id: &str,
    device_id: &str,
) -> anyhow::Result<[u8; crate::account_data::PRODUCTIVITY_ACCOUNT_DATA_NAMESPACE_KEY_LEN]> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let account_secret = crate::mls::runtime::load_or_create_account_mls_secret(
        secure_store.as_ref(),
        actor_id,
        device_id,
    )
    .map_err(|error| anyhow::anyhow!("account MLS secret unavailable: {error}"))?;
    crate::account_data::productivity_account_data_namespace_key(&account_secret)
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

pub(crate) fn chat_message_revise_operation(
    realm_id: &str,
    actor: &str,
    event_id: &str,
    body: &str,
) -> anyhow::Result<arkret_sdk::Event> {
    // Route through the SDK-typed `message_revise_payload` builder rather than a
    // hand-rolled `json!` body: it validates ids at build time and addresses a
    // `ak:message:` target via the payload's `message_id` field (falling back to
    // `target_ref` for event/local refs), matching the schema's anyOf.
    crate::operation::ak_ops::message_revise_content(
        realm_id,
        actor,
        event_id,
        arkret_sdk::ContentBlock::text(body),
    )?
    .build_sdk_event("inkson")
}

pub(crate) fn chat_message_redact_operation(
    realm_id: &str,
    actor: &str,
    target_id: &str,
    reason: &str,
) -> anyhow::Result<arkret_sdk::Event> {
    let target_id = target_id.trim();
    let mut payload = arkret_sdk::MessageRedactPayload {
        message_id: None,
        target_ref: None,
        event_id: None,
        target_event_id: None,
        track_name: None,
        reason: Some(reason.to_owned()),
        preserve: None,
    };
    if target_id.starts_with("ak:event:") {
        payload.target_event_id = Some(
            arkret_sdk::EventId::new(target_id.to_owned())
                .map_err(|err| anyhow::anyhow!("invalid redaction event target: {err}"))?,
        );
    } else if target_id.starts_with("ak:message:") {
        payload.message_id = Some(
            arkret_sdk::MessageId::new(target_id.to_owned())
                .map_err(|err| anyhow::anyhow!("invalid redaction message target: {err}"))?,
        );
    } else {
        payload.target_ref = Some(target_id.to_owned());
    }
    crate::operation::TypedOperationBuilder::new::<arkret_sdk::event_spec::MessageRedact>(
        realm_id, actor, payload,
    )
    .target_ref(target_id)
    .build_sdk_event("inkson")
}

pub(crate) fn chat_reaction_add_operation(
    realm_id: &str,
    actor: &str,
    event_id: &str,
    key: &str,
) -> anyhow::Result<arkret_sdk::Event> {
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
/// the v1 keyed-HMAC routing tag (`sha256:<hex>`) so the server can still
/// OR-Set dedup / rate-limit without learning the emoji; the real emoji
/// travels inside `encrypted_payload`.
pub(crate) fn chat_reaction_add_operation_encrypted(
    realm_id: &str,
    actor: &str,
    event_id: &str,
    routing_tag: &str,
    encrypted_payload: &arkret_sdk::EncryptedEnvelope,
) -> anyhow::Result<arkret_sdk::Event> {
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
    .build_sdk_event("inkson")
}

fn reaction_encrypted_envelope(
    state_store: &LocalStateStore,
    realm_id: &str,
    payload: &arkret_sdk::EncryptedPayload,
) -> anyhow::Result<arkret_sdk::EncryptedEnvelope> {
    let aad = payload
        .aad
        .clone()
        .ok_or_else(|| anyhow::anyhow!("reaction encryption omitted its bound AAD"))?;
    let group_state_ref = crate::mls::group_events::mls_base_epoch_ref_for_scope(
        state_store,
        realm_id,
        None,
        payload.group_id.as_str(),
        payload.epoch,
    )
    .map_err(anyhow::Error::msg)?;
    arkret_sdk::mls::encrypted_envelope_from_payload(
        payload,
        aad,
        arkret_sdk::EncryptedEnvelopeAadVisibility::Hidden,
        arkret_sdk::AadVisibilityCeiling::from_declared(None),
        group_state_ref,
    )
    .map_err(|error| anyhow::anyhow!("reaction encrypted envelope build failed: {error}"))
}

/// Build the `ak.reaction.add` operation for a tapped emoji, choosing the
/// plaintext or E2EE (§2.9 routing-tag) shape based on whether the channel
/// is encrypted. On any MLS failure in an encrypted channel the reaction is
/// dropped (returns `None`) rather than leaking the emoji in plaintext.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_chat_reaction_add_operation(
    mut state_store: SyncSignal<LocalStateStore>,
    realm_id: &str,
    actor: &str,
    device_id: &str,
    event_id: &str,
    emoji: &str,
    channel_encrypted: bool,
) -> anyhow::Result<Option<arkret_sdk::Event>> {
    if !channel_encrypted {
        return chat_reaction_add_operation(realm_id, actor, event_id, emoji).map(Some);
    }
    let realm_id = trim_realm_id(realm_id);
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let sealed = match crate::mls::runtime::encrypt_reaction_with_device_snapshot(
        &mut state_store.write(),
        secure_store.as_ref(),
        &realm_id,
        actor,
        device_id,
        emoji,
    ) {
        Ok(sealed) => sealed,
        Err(_) => return Ok(None),
    };
    // A forced epoch advance needs the commit Event to be submitted and
    // accepted before its EventId can become this reaction's group-state ref.
    // This single-event UI path cannot perform that two-event transaction, so
    // fail closed and let the next action retry after normal MLS rotation.
    if sealed.forced_commit.is_some() {
        return Ok(None);
    }
    let encrypted_payload =
        reaction_encrypted_envelope(&state_store.read(), &realm_id, &sealed.encrypted_payload)?;
    chat_reaction_add_operation_encrypted(
        &realm_id,
        actor,
        event_id,
        &sealed.routing_tag,
        &encrypted_payload,
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

#[cfg(test)]
pub(crate) fn chat_message_create_operation(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    _channel_kind: &str,
    local_message_id: &str,
    body: &str,
    mentions: &[MentionNode],
    reply_to: Option<&str>,
) -> anyhow::Result<arkret_sdk::Event> {
    chat_message_create_operation_with_expiry(
        realm_id,
        actor,
        strand_id,
        _channel_kind,
        local_message_id,
        body,
        mentions,
        reply_to,
        None,
    )
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
    Ok(arkret_sdk::ContentBlock::text(body))
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
        return Ok(arkret_sdk::ContentBlock::text(body));
    }
    let api = crate::transport::auth::authed_api_with_sync(
        base_url,
        session_credential,
        wait_for_sync_token,
    )?;
    let clients = crate::transport::EndpointClients::from_http(api.sdk_http_client()?);
    clients
        .blob()
        .upload_plaintext_long_text(&normalized, arkret_sdk::LongTextFormat::Markdown, realm_id)
        .await
}

#[cfg(test)]
pub(crate) fn chat_message_create_operation_with_expiry(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    _channel_kind: &str,
    message_id: &str,
    body: &str,
    mentions: &[MentionNode],
    reply_to: Option<&str>,
    expiry: Option<arkret_sdk::DisappearingMessageExpiry>,
) -> anyhow::Result<arkret_sdk::Event> {
    let content = chat_content_block_for_body(body)?;
    chat_message_create_operation_with_content_and_expiry(
        realm_id, actor, strand_id, message_id, body, content, mentions, reply_to, expiry,
    )
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
) -> anyhow::Result<arkret_sdk::Event> {
    chat_message_create_operation_with_content_and_expiry(
        realm_id, actor, strand_id, message_id, body, content, mentions, reply_to, None,
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
) -> anyhow::Result<arkret_sdk::Event> {
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
    // later public export. Validate the complete ordinary Event rather than
    // assuming the allowlisted body alone makes its envelope safe.
    privacy_gate.validate_public_export(&event)?;
    Ok(event)
}

fn chat_message_create_operation_with_content_and_expiry(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    _local_message_id: &str,
    body: &str,
    mut content: arkret_sdk::ContentBlock,
    mentions: &[MentionNode],
    reply_to: Option<&str>,
    expiry: Option<arkret_sdk::DisappearingMessageExpiry>,
) -> anyhow::Result<arkret_sdk::Event> {
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
        payload = payload.with_reply_to(reply_to);
    }
    if let Some(expiry) = expiry {
        payload = payload.with_expiry(expiry);
    }
    crate::operation::TypedOperationBuilder::new::<arkret_sdk::event_spec::MessageCreate>(
        realm_id, actor, payload,
    )
    .target_ref(strand_id)
    .build_sdk_event("inkson")
}

pub(crate) fn chat_send_error_message(error: &anyhow::Error) -> String {
    if is_auth_expired_error(error) {
        "Session expired while sending. Refresh the session or sign in again, then retry."
            .to_owned()
    } else if is_plaintext_visibility_policy_error(error) {
        "Plaintext is not enabled for this Realm on the current service. Send Secure or update Realm plaintext visibility."
            .to_owned()
    } else if is_space_membership_denied_error(error) {
        "This account is not a member of this Realm. Join the Realm or switch to an account that is a member before sending."
            .to_owned()
    } else {
        error.to_string()
    }
}

pub(crate) async fn submit_chat_operation_with_plaintext_retry(
    api: &TransportClient,
    realm_id: &str,
    actor_id: &str,
    plaintext_visible_services: &[String],
    operation: &arkret_sdk::Event,
) -> anyhow::Result<SubmitEventResult> {
    match api.event_submitter()?.submit_sdk_event(operation).await {
        Ok(response) => Ok(response),
        Err(error) if is_plaintext_visibility_policy_error(&error) => {
            let mut services = plaintext_visible_services.to_vec();
            if let Ok(description) = api.describe().await {
                let service_id = description.service_id.as_str().trim();
                if !service_id.is_empty() && !services.iter().any(|existing| existing == service_id)
                {
                    services.push(service_id.to_owned());
                }
            }
            if services.is_empty() {
                return Err(error);
            }
            let policy_update =
                crate::transport::realm_write::update_realm_plaintext_visible_services(
                    &api.event_submitter()?,
                    realm_id,
                    actor_id,
                    services,
                )
                .await;
            let mut retry_operation = operation.clone();
            retry_operation.event_id = retry_operation.derive_event_id()?;
            retry_operation.unsigned.insert(
                "local_operation_idempotency_alias".to_owned(),
                serde_json::Value::String(format!("ak:operation:{}", crate::operation::uuid_v7())),
            );
            let retry = api
                .event_submitter()?
                .submit_sdk_event(&retry_operation)
                .await;
            match (policy_update, retry) {
                (_, Ok(response)) => Ok(response),
                (Ok(_), Err(retry_error)) => Err(retry_error),
                (Err(update_error), Err(retry_error)) => Err(anyhow::anyhow!(
                    "plaintext policy update failed: {update_error}; retry after policy convergence failed: {retry_error}; original send failed: {error}"
                )),
            }
        }
        Err(error) => Err(error),
    }
}

/// Submit a chat operation using the current typed transport. Session refresh
/// is owned by `RuntimeServices`; this lower layer returns auth failures to the
/// caller instead of reaching through a global callback.
pub(crate) async fn submit_chat_operation_with_auth_refresh(
    base_url: &str,
    actor_id: &str,
    realm_id: &str,
    session_credential: String,
    wait_for_sync_token: Option<String>,
    plaintext_visible_services: &[String],
    operation: &arkret_sdk::Event,
) -> anyhow::Result<SubmitEventResult> {
    let api = authed_api_with_sync(base_url, session_credential, wait_for_sync_token.clone())?;
    submit_chat_operation_with_plaintext_retry(
        &api,
        realm_id,
        actor_id,
        plaintext_visible_services,
        operation,
    )
    .await
}
