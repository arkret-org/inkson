//! Generic Relation create / tombstone builders.

use super::TypedOperationBuilder;

/// Build the `ak.relation.create` payload.
///
/// `#/$defs/relation_create_object` is `allOf [relation.schema.json, not
/// required id/type/effective_scope]`, so the payload carries the whole
/// Relation object: the registered projection is `set value = payload.relation`
/// and a partial object has no derivable cell value. The id stays unset — it is
/// derived from the create Event — and `effective_scope` stays unset because it
/// is reducer-managed.
pub(crate) fn relation_create_payload(
    realm_id: &str,
    actor: &str,
    kind: &str,
    from_ref: &str,
    to_ref: &str,
) -> anyhow::Result<arkret_sdk::RelationCreatePayload> {
    Ok(arkret_sdk::RelationCreatePayload::new(
        arkret_sdk::Relation {
            schema: arkret_sdk::SchemaId::RELATION_V1.to_owned(),
            id: None,
            realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())
                .map_err(|err| anyhow::anyhow!("invalid realm id {realm_id:?}: {err:?}"))?,
            scope_circle_id: None,
            effective_scope: None,
            relation_kind: arkret_sdk::RelationKind::from_wire(kind),
            from_ref: from_ref.to_owned(),
            to_ref: to_ref.to_owned(),
            rank: None,
            fields: Default::default(),
            state: None,
            state_changed_at: None,
            created_by: crate::mls_api_helpers::local_account_actor_id(actor)?,
            created_at: chrono::Utc::now(),
            updated_by: None,
            updated_at: None,
        },
    ))
}

/// `created_by` carries a `did_core_id` (`zh/models/common-fields.md` §4.1).
/// Callers hand this module whichever spelling they hold, so a `did:` URI
/// is projected through the registered adapter rather than rejected.
fn actor_core_id(actor: &str) -> anyhow::Result<arkret_sdk::DidCoreId> {
    if let Ok(core) = arkret_sdk::DidCoreId::new(actor.to_owned()) {
        return Ok(core);
    }
    let did = arkret_sdk::Did::new(actor.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid actor id {actor:?}: {err:?}"))?;
    arkret_sdk::project_did_to_core_id(&did)
        .map_err(|err| anyhow::anyhow!("invalid actor id {actor:?}: {err:?}"))
}

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
        relation_create_payload(realm_id, actor, kind, from_ref, to_ref)?,
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
