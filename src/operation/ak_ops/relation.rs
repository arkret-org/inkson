//! Generic Relation create / tombstone builders.

use super::TypedOperationBuilder;

fn relation_definition(
    kind: &str,
    from_ref: arkret_sdk::RelationEndpoint,
    to_ref: arkret_sdk::RelationEndpoint,
) -> anyhow::Result<arkret_sdk::RelationDefinition> {
    let definition = arkret_sdk::RelationDefinition {
        scope_circle_id: None,
        relation_kind: arkret_sdk::RelationKind::from_wire(kind),
        from_ref,
        to_ref,
        rank: None,
        fields: Default::default(),
    };
    definition.validate()?;
    Ok(definition)
}

fn relation_domain(
    domain_kind: arkret_sdk::RelationPrimaryConflictDomainKind,
    definition: &arkret_sdk::RelationDefinition,
) -> anyhow::Result<arkret_sdk::RelationPrimaryConflictDomain> {
    arkret_sdk::RelationPrimaryConflictDomain::try_new(
        domain_kind,
        definition.relation_kind.clone(),
        definition.from_ref.clone(),
        matches!(
            domain_kind,
            arkret_sdk::RelationPrimaryConflictDomainKind::Tuple
        )
        .then(|| definition.to_ref.clone()),
    )
    .map_err(anyhow::Error::from)
}

pub(crate) fn relation_actor_domain(
    kind: &str,
    from_ref: &str,
    target_actor: &arkret_sdk::ActorId,
) -> anyhow::Result<arkret_sdk::RelationPrimaryConflictDomain> {
    let definition = relation_definition(kind, from_ref.into(), target_actor.clone().into())?;
    relation_domain(
        arkret_sdk::RelationPrimaryConflictDomainKind::Tuple,
        &definition,
    )
}

/// Build an `ak.relation.create` payload only from a Station-verified exact
/// current result. `None` is therefore reachable only through the formal
/// Relation `never_written` outcome, never through a local default.
pub(crate) fn relation_create_payload(
    kind: &str,
    from_ref: arkret_sdk::RelationEndpoint,
    to_ref: arkret_sdk::RelationEndpoint,
    domain_kind: arkret_sdk::RelationPrimaryConflictDomainKind,
    current: &crate::event_submit::VerifiedRelationCurrent,
) -> anyhow::Result<arkret_sdk::RelationCreatePayload> {
    let definition = relation_definition(kind, from_ref, to_ref)?;
    let domain = relation_domain(domain_kind, &definition)?;
    arkret_sdk::RelationCreatePayload::try_new(
        domain.clone(),
        current.expected_revision_for_create(&domain)?,
        definition,
    )
    .map_err(anyhow::Error::from)
}

/// Build a schema-legal `ak.relation.create` event whose `to_ref` is an actor.
pub(crate) fn relation_create_for_actor(
    realm_id: &str,
    actor: &str,
    kind: &str,
    from_ref: &str,
    target_actor: &arkret_sdk::ActorId,
    current: &crate::event_submit::VerifiedRelationCurrent,
) -> anyhow::Result<TypedOperationBuilder> {
    Ok(TypedOperationBuilder::new::<
        arkret_sdk::event_spec::RelationCreate,
    >(
        realm_id,
        actor,
        relation_create_payload(
            kind,
            from_ref.into(),
            target_actor.clone().into(),
            arkret_sdk::RelationPrimaryConflictDomainKind::Tuple,
            current,
        )?,
    ))
}

/// Build an `ak.relation.tombstone` from the exact present Relation returned
/// for the assignment tuple. The local projection's RelationId is never used
/// as authority.
pub(crate) fn relation_tombstone_for_actor(
    realm_id: &str,
    actor: &str,
    kind: &str,
    from_ref: &str,
    target_actor: &arkret_sdk::ActorId,
    current: &crate::event_submit::VerifiedRelationCurrent,
) -> anyhow::Result<TypedOperationBuilder> {
    let domain = relation_actor_domain(kind, from_ref, target_actor)?;
    let (revision, relation) = current.present(&domain)?;
    let relation_id = relation.id.clone().ok_or_else(|| {
        anyhow::anyhow!("exact present Relation current result lacks its materialized id")
    })?;
    let payload = arkret_sdk::RelationTombstonePayload {
        primary_conflict_domain: domain,
        expected_revision: revision.clone(),
        relation_id: relation_id.clone(),
        reason: None,
    };
    payload.validate()?;
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::RelationTombstone>(
            realm_id, actor, payload,
        )
        .target_ref(relation_id.as_str()),
    )
}
