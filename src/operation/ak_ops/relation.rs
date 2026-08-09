//! Generic Relation create / tombstone builders.

use super::TypedOperationBuilder;

/// Build a schema-legal `ak.relation.create` event.
pub fn relation_create(
    realm_id: &str,
    actor: &str,
    kind: &str,
    from_ref: &str,
    to_ref: &str,
) -> anyhow::Result<TypedOperationBuilder> {
    // No relation id is minted here: `TypedOperationBuilder` stamps the derived one
    // as `unsigned.local_target_ref` once the envelope exists.
    Ok(TypedOperationBuilder::new::<
        arkret_sdk::event_spec::RelationCreate,
    >(
        realm_id,
        actor,
        arkret_sdk::RelationCreatePayload::new(kind, from_ref, to_ref),
    ))
}

/// Build a `ak.relation.tombstone` event targeting an existing Relation.
pub fn relation_tombstone(
    realm_id: &str,
    actor: &str,
    relation_id: &str,
) -> anyhow::Result<TypedOperationBuilder> {
    let payload = arkret_sdk::RelationTombstonePayload {
        relation_id: arkret_sdk::RelationId::new(relation_id.to_owned())?,
        reason: None,
    };
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::RelationTombstone>(
            realm_id, actor, payload,
        )
        .target_ref(relation_id),
    )
}
