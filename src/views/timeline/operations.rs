use serde_json::{Value, json};

use crate::local_state::default_strand_id_for_realm;
use crate::operation::OperationBuilder;

// YOU-02-001: these helpers return `Result` instead of panicking — the
// realm/strand ids they parse come from server-synced UI state, and a
// non-canonical id must not abort the client (wasm panic = blank page).
pub(super) fn sdk_payload_value(
    result: cokret_sdk::Result<Value>,
    context: &str,
) -> anyhow::Result<Value> {
    result.map_err(|err| anyhow::anyhow!("{context}: {err}"))
}

fn strand_id_value(value: &str) -> anyhow::Result<cokret_sdk::StrandId> {
    cokret_sdk::StrandId::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid strand id {value:?}: {err:?}"))
}

pub(super) fn sdk_event_local_operation_id(event: &cokret_sdk::Event) -> &str {
    event
        .unsigned
        .get("local_operation_idempotency_alias")
        .and_then(Value::as_str)
        .unwrap_or_else(|| event.event_id.as_str())
}

fn text_content(body: &str) -> anyhow::Result<Value> {
    // Spec `event-payload.schema.json` `content_block` requires `kind` (a
    // `content_kind` string matching `^cx\.content\.[a-z0-9_]+...` or a
    // reverse-domain id) and `body` (string). Plain timeline text uses
    // `ck.content.text`. `blocks[]` is optional and, when present, MUST
    // be an array of `content_block` items — the older yougen shape
    // (`[{kind: "text", text: ...}]`) failed both the `content_kind`
    // pattern (`text` has no dot) and the `body` requirement, so it is
    // dropped here; downstream renderers should read `body` directly.
    sdk_payload_value(
        cokret_sdk::ContentBlock::text(body).to_value(),
        "timeline text content serialize",
    )
}

fn incident_priority_wire_value(priority: &str) -> Option<&'static str> {
    match priority {
        "sev1" => Some("critical"),
        "sev2" => Some("high"),
        "sev3" => Some("urgent"),
        _ => None,
    }
}

pub(super) fn public_update_requires_sanitization(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    [
        "root cause",
        "secret",
        "token",
        "credential",
        "private key",
        "customer data",
        "exploit",
        "internal only",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

pub(crate) fn message_create_operation(
    realm_id: &str,
    actor: &str,
    thread_id: Option<&str>,
    body: &str,
    incident_priority: Option<&str>,
) -> anyhow::Result<cokret_sdk::Event> {
    message_create_operation_with_expiry(realm_id, actor, thread_id, body, incident_priority, None)
}

pub(crate) fn message_create_operation_with_expiry(
    realm_id: &str,
    actor: &str,
    thread_id: Option<&str>,
    body: &str,
    incident_priority: Option<&str>,
    expiry: Option<cokret_sdk::DisappearingMessageExpiry>,
) -> anyhow::Result<cokret_sdk::Event> {
    // Spec `event-payload.schema.json` `message_create_payload` requires
    // `strand_id` and `track_name` (`strand-and-message.md` §2). The default Strand
    // for a Realm is `ck:strand:<uuid>` (typed-id re-tag, matching
    // soland's `strand_id_from_realm_id`); the default track is "discussion".
    let strand_id = default_strand_id_for_realm(realm_id);
    let mut content = cokret_sdk::ContentBlock::text(body);
    if let Some(priority) = incident_priority.and_then(incident_priority_wire_value) {
        content = content.with_field("priority", json!(priority)).with_field(
            "notification",
            json!({
                "priority": priority,
                "priority_override": true,
            }),
        );
    }
    let mut payload = cokret_sdk::MessageCreatePayload::with_content(
        strand_id_value(&strand_id)?,
        "discussion",
        sdk_payload_value(content.to_value(), "timeline message content serialize")?,
    );
    if let Some(thread_id) = thread_id {
        payload = payload.with_reply_to(thread_id);
    }
    if let Some(expiry) = expiry {
        payload = payload.with_expiry(expiry);
    }
    OperationBuilder::new(realm_id, actor, "ck.message.create")
        .body(sdk_payload_value(
            payload.to_value(),
            "timeline ck.message.create payload serialize",
        )?)
        .build("yougen")
        .to_sdk_event_for_submit()
}

pub(super) fn message_revise_operation(
    realm_id: &str,
    actor: &str,
    event_id: &str,
    body: &str,
) -> anyhow::Result<cokret_sdk::Event> {
    OperationBuilder::new(realm_id, actor, "ck.message.revise")
        .target_ref(event_id)
        .body(json!({
            "content": text_content(body)?,
            "target_ref": event_id,
        }))
        .build("yougen")
        .to_sdk_event_for_submit()
}

pub(super) fn pending_send_error_is_permanent(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("capability_denied")
        || lower.contains("actor is not a member")
        || lower.contains("not a joined member")
        || lower.contains("banned")
        || lower.contains("forbidden")
        || lower.contains("403")
        || lower.contains("401")
}

pub(super) async fn submit_timeline_message_with_plaintext_retry(
    api: &crate::api::CokretApi,
    realm_id: &str,
    actor_id: &str,
    operation: &cokret_sdk::Event,
) -> anyhow::Result<crate::models::SubmitEventResult> {
    match api.submit_sdk_event(operation).await {
        Ok(response) => Ok(response),
        Err(error) if crate::api::is_plaintext_visibility_policy_error(&error) => {
            let description = api.describe().await?;
            let service_did = description.service_did.as_str().trim();
            if service_did.is_empty() {
                return Err(error);
            }
            api.update_realm_metadata(
                realm_id,
                actor_id,
                json!({"plaintext_visible_services": [service_did]}),
            )
            .await
            .map_err(|update_error| {
                anyhow::anyhow!(
                    "plaintext policy update failed: {update_error}; original send failed: {error}"
                )
            })?;
            api.submit_sdk_event(operation).await
        }
        Err(error) => Err(error),
    }
}

pub(super) fn message_redact_operation(
    realm_id: &str,
    actor: &str,
    event_id: &str,
    reason: Option<&str>,
) -> anyhow::Result<cokret_sdk::Event> {
    OperationBuilder::new(realm_id, actor, "ck.message.redact")
        .target_ref(event_id)
        .body(json!({
            "reason": reason,
            "target_event_id": event_id,
        }))
        .build("yougen")
        .to_sdk_event_for_submit()
}

pub(super) fn reaction_add_operation(
    realm_id: &str,
    actor: &str,
    event_id: &str,
    key: &str,
) -> anyhow::Result<cokret_sdk::Event> {
    OperationBuilder::new(realm_id, actor, "ck.reaction.add")
        .target_ref(event_id)
        .body(json!({
            "target_ref": event_id,
            "key": key,
        }))
        .build("yougen")
        .to_sdk_event_for_submit()
}
