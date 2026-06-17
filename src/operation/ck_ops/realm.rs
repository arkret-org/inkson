//! Realm lifecycle / update / organization / message-revise builders.

use serde_json::json;

use super::{OperationBuilder, object_patch_payload_value, patch_from_value};

/// Build a `ck.space.archive` operation against a container Space. The
/// Space transitions from `Active` to `Archived`; reversible via
/// `space_restore`. Spec: `models/realm-and-space.md` §4.4. The wire
/// payload uses canonical `space_id`.
pub fn realm_archive(realm_id: &str, actor: &str, container_space_id: &str) -> OperationBuilder {
    OperationBuilder::new(realm_id, actor, "ck.space.archive")
        .target_ref(container_space_id)
        .body(json!({ "space_id": container_space_id }))
}

/// Build a `ck.message.revise` patch operation. Spec: revise is
/// supposed to carry `payload.patch` like the other `*.update`
/// events. New clients emit patches; full-content revise payloads are
/// outside the client write contract.
pub fn message_revise_patch(
    realm_id: &str,
    actor: &str,
    message_id: &str,
    patch: serde_json::Value,
) -> OperationBuilder {
    OperationBuilder::new(realm_id, actor, "ck.message.revise")
        .target_ref(message_id)
        .body(json!({
            "message_id": message_id,
            "patch": patch,
        }))
}

/// Build a `ck.realm.update` patch operation. The reducer accepts
/// both flat fields (action/owner/title/security_class) and
/// `payload.patch`; the patch shape is preferred for non-lifecycle
/// edits (title / description).
pub fn realm_update_patch(
    envelope_realm_id: &str,
    actor: &str,
    realm_id: &str,
    patch: serde_json::Value,
) -> anyhow::Result<OperationBuilder> {
    let patch = patch_from_value(patch)?;
    Ok(
        OperationBuilder::new(envelope_realm_id, actor, "ck.realm.update")
            .target_ref(realm_id)
            .body(object_patch_payload_value(realm_id, patch)?),
    )
}

/// `ck.realm.update` patch event on the organization cell. Mirrors the
/// Realm organization update Move shape (name /
/// topic / description / etc.). Pass the merge patch as `value`.
pub fn realm_organization_update(
    realm_id: &str,
    actor: &str,
    value: serde_json::Value,
) -> anyhow::Result<OperationBuilder> {
    let patch = patch_from_value(value)?;
    Ok(OperationBuilder::new(realm_id, actor, "ck.realm.update")
        .target_ref(realm_id)
        .body(object_patch_payload_value(realm_id, patch)?))
}
