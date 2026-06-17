//! Generic Relation create / tombstone builders.

use serde_json::json;

use super::{OperationBuilder, relation_create_payload_value};

/// Build a schema-legal `ck.relation.create` event. The Relation id is
/// server-normalized from the accepted event id; payload keeps only the
/// v1 `kind` / `from_ref` / `to_ref` endpoints.
pub fn relation_create(
    realm_id: &str,
    actor: &str,
    kind: &str,
    from_ref: &str,
    to_ref: &str,
) -> anyhow::Result<OperationBuilder> {
    Ok(OperationBuilder::new(realm_id, actor, "ck.relation.create")
        .target_ref(from_ref)
        .body(relation_create_payload_value(kind, from_ref, to_ref)?))
}

/// Build a `ck.relation.tombstone` event targeting an existing Relation.
pub fn relation_tombstone(realm_id: &str, actor: &str, relation_id: &str) -> OperationBuilder {
    OperationBuilder::new(realm_id, actor, "ck.relation.tombstone")
        .target_ref(relation_id)
        .body(json!({ "relation_id": relation_id }))
}
