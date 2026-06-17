use super::*;

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
        .find(|candidate| candidate.id == message_id)
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
// `crate::views::secure_send` module so the Chat and Timeline views drive ONE
// MLS core + persist-on-accept pipeline. The Chat composer calls
// `secure_send::build_secure_send` / `secure_send::submit_secure_send`
// directly; the former local `run_local_mls_encrypt` / `chat_mls_*` helpers
// moved there verbatim.

pub(crate) fn chat_message_revise_operation(
    realm_id: &str,
    actor: &str,
    event_id: &str,
    body: &str,
) -> crate::operation::EventEnvelope {
    OperationBuilder::new(realm_id, actor, "ck.message.revise")
        .target_ref(event_id)
        .body(json!({
            "content": {
                "kind": "ck.content.text",
                "body": body,
            },
            "target_ref": event_id,
        }))
        .build("yougen")
}

pub(crate) fn chat_message_redact_operation(
    realm_id: &str,
    actor: &str,
    event_id: &str,
    reason: &str,
) -> crate::operation::EventEnvelope {
    OperationBuilder::new(realm_id, actor, "ck.message.redact")
        .target_ref(event_id)
        .body(json!({
            "reason": reason,
            "target_event_id": event_id,
        }))
        .build("yougen")
}

pub(crate) fn chat_reaction_add_operation(
    realm_id: &str,
    actor: &str,
    event_id: &str,
    key: &str,
) -> crate::operation::EventEnvelope {
    OperationBuilder::new(realm_id, actor, "ck.reaction.add")
        .target_ref(event_id)
        .body(json!({
            "target_ref": event_id,
            "key": key,
        }))
        .build("yougen")
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
    encrypted_payload: &cokret_sdk::EncryptedPayload,
) -> crate::operation::EventEnvelope {
    let encrypted_payload_json =
        serde_json::to_value(encrypted_payload).unwrap_or(serde_json::Value::Null);
    OperationBuilder::new(realm_id, actor, "ck.reaction.add")
        .target_ref(event_id)
        .body(json!({
            "target_ref": event_id,
            "key": routing_tag,
            "encrypted_payload": encrypted_payload_json,
        }))
        .build("yougen")
}

/// Build the `ck.reaction.add` operation for a tapped emoji, choosing the
/// plaintext or E2EE (§2.9 routing-tag) shape based on whether the channel
/// is encrypted. On any MLS failure in an encrypted channel the reaction is
/// dropped (returns `None`) rather than leaking the emoji in plaintext.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_chat_reaction_add_operation(
    mut state_store: Signal<LocalStateStore>,
    realm_id: &str,
    actor: &str,
    device_id: &str,
    event_id: &str,
    emoji: &str,
    channel_encrypted: bool,
) -> Option<crate::operation::EventEnvelope> {
    if !channel_encrypted {
        return Some(chat_reaction_add_operation(
            realm_id, actor, event_id, emoji,
        ));
    }
    let realm_id = trim_realm_id(realm_id);
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    match crate::mls::runtime::encrypt_reaction_with_device_snapshot(
        &mut state_store.write(),
        secure_store.as_ref(),
        &realm_id,
        actor,
        device_id,
        emoji,
    ) {
        Ok(sealed) => Some(chat_reaction_add_operation_encrypted(
            &realm_id,
            actor,
            event_id,
            &sealed.routing_tag,
            &sealed.encrypted_payload,
        )),
        Err(_) => None,
    }
}

pub(crate) fn is_schema_message_id(value: &str) -> bool {
    let Some(suffix) = value.trim().strip_prefix("ck:message:") else {
        return false;
    };
    !suffix.is_empty()
        && suffix
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
}

pub(crate) fn new_chat_message_id() -> String {
    format!("ck:message:{}", uuid_v7())
}

pub(crate) fn schema_message_id_or_new(value: &str) -> String {
    if is_schema_message_id(value) {
        value.trim().to_owned()
    } else {
        new_chat_message_id()
    }
}

// YOU-02-001: these helpers return `Result` instead of panicking — the
// realm/strand ids they parse come from server-synced UI state, and a
// non-canonical id must not abort the client (wasm panic = blank page).
pub(crate) fn sdk_payload_value(
    result: cokret_sdk::Result<Value>,
    context: &str,
) -> anyhow::Result<Value> {
    result.map_err(|err| anyhow::anyhow!("{context}: {err}"))
}

pub(crate) fn strand_id_value(value: &str) -> anyhow::Result<cokret_sdk::StrandId> {
    cokret_sdk::StrandId::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid strand id {value:?}: {err:?}"))
}

pub(crate) fn chat_message_create_operation(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    _channel_kind: &str,
    message_id: &str,
    body: &str,
    mentions: &[MentionNode],
    reply_to: Option<&str>,
) -> anyhow::Result<crate::operation::EventEnvelope> {
    let actor_mentions = mentions
        .iter()
        .filter_map(|mention| mention.as_mention().cloned())
        .collect::<Vec<_>>();
    let audience_mentions = mentions
        .iter()
        .filter_map(|mention| mention.as_audience_mention().cloned())
        .collect::<Vec<_>>();
    let mut content = cokret_sdk::ContentBlock::text(body);
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
    // T2.3: v1 wire uses `track_name` — a display-only timeline segment
    // identifier — instead of the removed `branch` top-level field.
    let mut payload = cokret_sdk::MessageCreatePayload::with_content(
        strand_id_value(strand_id)?,
        "discussion",
        sdk_payload_value(content.to_value(), "chat message content serialize")?,
    )
    .with_message_id(message_id);
    if let Some(reply_to) = reply_to.filter(|value| !value.trim().is_empty()) {
        payload = payload.with_reply_to(reply_to);
    }
    Ok(OperationBuilder::new(realm_id, actor, "ck.message.create")
        .target_ref(strand_id)
        .body(sdk_payload_value(
            payload.to_value(),
            "chat ck.message.create payload serialize",
        )?)
        .build("yougen"))
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
    api: &CokretApi,
    realm_id: &str,
    actor_id: &str,
    plaintext_visible_services: &[String],
    operation: &EventEnvelope,
) -> anyhow::Result<SubmitEventResult> {
    match api.submit_event_envelope(operation).await {
        Ok(response) => Ok(response),
        Err(error) if is_plaintext_visibility_policy_error(&error) => {
            let mut services = plaintext_visible_services.to_vec();
            if let Ok(description) = api.describe().await {
                let service_did = description.service_did.as_str().trim();
                if !service_did.is_empty()
                    && !services.iter().any(|existing| existing == service_did)
                {
                    services.push(service_did.to_owned());
                }
            }
            if services.is_empty() {
                return Err(error);
            }
            api.update_realm_metadata(
                realm_id,
                actor_id,
                json!({"plaintext_visible_services": services}),
            )
            .await
            .map_err(|update_error| {
                anyhow::anyhow!(
                    "plaintext policy update failed: {update_error}; original send failed: {error}"
                )
            })?;
            api.submit_event_envelope(operation).await
        }
        Err(error) => Err(error),
    }
}

/// Submit a chat operation and, if the first attempt fails with a
/// definitive `auth_expired` (the short-lived principal bearer died
/// between background refresh ticks), silently re-mint the bearer through
/// the shared refresher and retry once before surfacing the error.
///
/// The send paths used to bounce straight to `/login` on the first
/// `auth_expired` — the "it randomly asks me to sign in mid-conversation"
/// report. Routing through [`crate::session::refresh_current_bearer`]
/// keeps the user signed in across a routine token rollover; only a
/// genuinely dead session (refresh material exhausted) still returns an
/// `auth_expired` for the caller to route to login.
pub(crate) async fn submit_chat_operation_with_auth_refresh(
    base_url: &str,
    actor_id: &str,
    realm_id: &str,
    access_token: String,
    wait_for_sync_token: Option<String>,
    plaintext_visible_services: &[String],
    operation: &EventEnvelope,
) -> anyhow::Result<SubmitEventResult> {
    let api = authed_api_with_sync(base_url, access_token, wait_for_sync_token.clone())?;
    let first = submit_chat_operation_with_plaintext_retry(
        &api,
        realm_id,
        actor_id,
        plaintext_visible_services,
        operation,
    )
    .await;
    match first {
        Ok(response) => Ok(response),
        Err(error) if is_auth_expired_error(&error) => {
            match crate::session::refresh_current_bearer().await {
                Some(fresh_token) => {
                    let retry_api =
                        authed_api_with_sync(base_url, fresh_token, wait_for_sync_token)?;
                    submit_chat_operation_with_plaintext_retry(
                        &retry_api,
                        realm_id,
                        actor_id,
                        plaintext_visible_services,
                        operation,
                    )
                    .await
                }
                // Refresh material is exhausted — the session is really
                // dead. Hand the original auth_expired back so the caller
                // routes to login.
                None => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}
