//! Document Morph / comment / relation builders.

use serde_json::json;

use super::{
    OperationBuilder, did_id, morph_id_value, object_patch_payload_value, patch_from_value,
    realm_id_value, relation_create_payload_value, sdk_payload_value, strand_id_value,
    trim_realm_id,
};

/// Build a `ck.morph.create` for a document Morph.
pub fn document_morph_create(
    realm_id: &str,
    actor: &str,
    morph_id: &str,
    title: &str,
    document_body: serde_json::Value,
) -> anyhow::Result<OperationBuilder> {
    let realm_id = trim_realm_id(realm_id);
    let object = cokret_sdk::MorphCreateObject::new(
        morph_id_value(morph_id)?,
        realm_id_value(&realm_id)?,
        "document",
        did_id(actor)?,
    )
    .with_title(title)
    .with_facet("documentable", json!({}))
    .with_field("document", document_body);
    Ok(OperationBuilder::new(
        &realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::MorphCreate,
    )
    .target_ref(morph_id)
    .body(sdk_payload_value(
        object.to_create_payload_value(),
        "ck.morph.create document payload serialize",
    )?))
}

/// Build a `ck.morph.update` carrying a new document body.
pub fn document_morph_update(
    realm_id: &str,
    actor: &str,
    morph_id: &str,
    document_body: serde_json::Value,
) -> anyhow::Result<OperationBuilder> {
    morph_update_patch(
        realm_id,
        actor,
        morph_id,
        json!({
            "fields": {
                "$op": "set",
                "value": {
                    "document": document_body
                }
            }
        }),
    )
}

/// Build a range-sealed document comment as `ck.message.create`.
pub fn document_comment_create(
    realm_id: &str,
    actor: &str,
    morph_id: &str,
    start: u32,
    end: u32,
    body: &str,
    reply_to: Option<&str>,
) -> anyhow::Result<OperationBuilder> {
    let realm_id = trim_realm_id(realm_id);
    let discussion_strand_id = realm_id
        .strip_prefix("ck:realm:")
        .map(|suffix| format!("ck:strand:{suffix}"))
        .unwrap_or_else(|| morph_id.to_owned());
    let content = cokret_sdk::ContentBlock::text(body)
        .with_field(
            "anchor_range",
            json!({
                "end": end,
                "start": start,
                "target_ref": morph_id
            }),
        )
        .with_field("morph_id", json!(morph_id));
    let mut payload = cokret_sdk::MessageCreatePayload::with_content(
        strand_id_value(&discussion_strand_id)?,
        "discussion",
        sdk_payload_value(content.to_value(), "document comment content serialize")?,
    );
    if let Some(parent) = reply_to.map(str::trim).filter(|value| !value.is_empty()) {
        payload = payload.with_reply_to(parent);
    }
    Ok(OperationBuilder::new(
        &realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::MessageCreate,
    )
    .target_ref(morph_id)
    .body(sdk_payload_value(
        payload.to_value(),
        "ck.message.create document comment payload serialize",
    )?))
}

/// Build a Relation linking a document Morph to another object.
pub fn document_relation_create(
    realm_id: &str,
    actor: &str,
    morph_id: &str,
    target_ref: &str,
) -> anyhow::Result<OperationBuilder> {
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::RelationCreate,
    )
    .target_ref(morph_id)
    .body(relation_create_payload_value(
        "references",
        morph_id,
        target_ref,
    )?))
}

/// Build a `ck.morph.update` patch operation. Mirrors
/// [`strand_update_patch`](super::strand_update_patch) for Morph objects;
/// soland's `apply_morph_update` reducer accepts `payload.patch` with the
/// standard `ck.schema.patch.v1` shape.
pub fn morph_update_patch(
    realm_id: &str,
    actor: &str,
    morph_id: &str,
    patch: serde_json::Value,
) -> anyhow::Result<OperationBuilder> {
    let patch = patch_from_value(patch)?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::MorphUpdate,
    )
    .target_ref(morph_id)
    .body(object_patch_payload_value(morph_id, patch)?))
}
