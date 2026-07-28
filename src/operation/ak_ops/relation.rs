//! Generic Relation create / tombstone builders.

use serde_json::json;

use super::{OperationBuilder, relation_create_payload_value};

/// Build a schema-legal `ak.relation.create` event.
pub fn relation_create(
    realm_id: &str,
    actor: &str,
    kind: &str,
    from_ref: &str,
    to_ref: &str,
) -> anyhow::Result<OperationBuilder> {
    let relation_id = format!("ak:relation:{}", crate::operation::uuid_v7());
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::RelationCreate,
    )
    .target_ref(&relation_id)
    .body(relation_create_payload_value(
        realm_id,
        actor,
        &relation_id,
        kind,
        from_ref,
        to_ref,
        None,
    )?))
}

/// Build a `ak.relation.tombstone` event targeting an existing Relation.
pub fn relation_tombstone(realm_id: &str, actor: &str, relation_id: &str) -> OperationBuilder {
    OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::RelationTombstone,
    )
    .target_ref(relation_id)
    .body(json!({ "relation_id": relation_id }))
}
