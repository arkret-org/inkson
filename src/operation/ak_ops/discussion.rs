//! Discussion Strand / Circle builders.

use super::{
    TypedOperationBuilder, circle_id_value, did_id, realm_id_value, strand_create_payload,
    trim_realm_id,
};

/// Build a canonical `ak.strand.create` discussion operation with the full
/// typed Strand payload expected by the current reducers.
///
/// The full Strand lives under the spec-canonical `object` key —
/// see soland `routing/events/operations.rs::STRAND_CREATE_REQUIREMENTS`
/// and SDK `crates/core/src/schema/payloads.rs` which both gate
/// `ak.strand.create` on `payload.object`.
/// Build a canonical `ak.strand.create` for a discussion Strand.
///
/// Every caller-chosen facet is a typed member of the create object: `rank`,
/// `category` and `has_synthesis` live in `metadata.fields` (the same place the
/// kanban card builder puts them) and `summary` in `metadata.summary`. The Strand
/// object schema is closed, so writing them onto the serialized payload instead
/// would put non-spec members on the wire.
#[allow(clippy::too_many_arguments)]
pub fn discussion_strand_create(
    realm_id: &str,
    actor: &str,
    title: &str,
    category: &str,
    summary: Option<&str>,
    rank: &str,
    scope_circle_id: Option<&str>,
    with_synthesis: bool,
) -> anyhow::Result<TypedOperationBuilder> {
    let typed_realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|e| anyhow::anyhow!("invalid realm_id: {e:?}"))?;
    let actor_id = crate::mls_api_helpers::principal_core_id(actor)
        .map_err(|e| anyhow::anyhow!("invalid actor DID: {e:?}"))?;
    // No caller-supplied Strand id: the object is derived from this create
    // Event, so the payload omits it and the projection keys the optimistic row
    // by the holder-local operation id until the accepted id arrives.
    let mut strand = arkret_sdk::StrandCreateObject::new(typed_realm_id, actor_id)
        .with_metadata_title(title)
        .with_metadata_field("category", serde_json::json!(category))
        .with_metadata_field("has_synthesis", serde_json::json!(with_synthesis))
        .with_metadata_field("rank", serde_json::json!(rank))
        .with_track("discussion", arkret_sdk::StrandTrack::discussion_primary());
    if with_synthesis {
        strand = strand.with_track(
            "synthesis",
            arkret_sdk::StrandTrack::new()
                .primary()
                .with_profile("kanban_card"),
        );
    }
    if let Some(summary) = summary.map(str::trim).filter(|value| !value.is_empty()) {
        strand = strand.with_metadata_summary(summary);
    }
    if let Some(circle_id) = scope_circle_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        strand = strand.with_scope_circle_id(
            arkret_sdk::CircleId::new(circle_id.to_owned())
                .map_err(|e| anyhow::anyhow!("invalid scope circle_id: {e:?}"))?,
        );
    }
    Ok(TypedOperationBuilder::new::<
        arkret_sdk::event_spec::StrandCreate,
    >(realm_id, actor, strand_create_payload(strand)?))
}

/// Build the metadata-free discussion Strand used as a newly-created Realm's
/// default entry point. Omitting plaintext metadata keeps this valid when the
/// Realm's metadata encryption floor is already `e2ee_required`.
pub fn initial_default_discussion_strand_create(
    realm_id: &str,
    actor: &str,
) -> anyhow::Result<TypedOperationBuilder> {
    let typed_realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|e| anyhow::anyhow!("invalid realm_id: {e:?}"))?;
    let actor_id = crate::mls_api_helpers::principal_core_id(actor)
        .map_err(|e| anyhow::anyhow!("invalid actor DID: {e:?}"))?;
    let strand = arkret_sdk::StrandCreateObject::new(typed_realm_id, actor_id)
        .with_track("discussion", arkret_sdk::StrandTrack::discussion_primary());
    Ok(TypedOperationBuilder::new::<
        arkret_sdk::event_spec::StrandCreate,
    >(realm_id, actor, strand_create_payload(strand)?))
}

pub fn realm_set_default_strand(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
) -> anyhow::Result<TypedOperationBuilder> {
    let realm_id_value = arkret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|e| anyhow::anyhow!("invalid realm_id: {e:?}"))?;
    let strand_id_value = arkret_sdk::StrandId::new(strand_id.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid strand_id: {e:?}"))?;
    Ok(TypedOperationBuilder::new::<
        arkret_sdk::event_spec::RealmSetDefaultStrand,
    >(
        realm_id,
        actor,
        arkret_sdk::RealmSetDefaultStrandPayload::new(realm_id_value, strand_id_value),
    ))
}

/// Build a canonical `ak.circle.create` operation for a private
/// discussion scope inside `realm_id`.
pub fn discussion_circle_create(
    realm_id: &str,
    actor: &str,
    title: &str,
) -> anyhow::Result<TypedOperationBuilder> {
    let display = arkret_sdk::CircleDisplay {
        short_name: title.trim().chars().take(16).collect::<String>(),
        color_token: arkret_sdk::CircleColorToken::Indigo,
        symbol: arkret_sdk::CircleSymbol::Glyph {
            glyph: arkret_sdk::CircleGlyph::Lock,
        },
    };
    let circle = arkret_sdk::Circle::create_object(
        realm_id_value(&trim_realm_id(realm_id))?,
        title.trim(),
        display,
        did_id(actor)?,
    );
    Ok(TypedOperationBuilder::new::<
        arkret_sdk::event_spec::CircleCreate,
    >(
        realm_id,
        actor,
        arkret_sdk::CircleCreatePayload { object: circle },
    ))
}

/// Build a `ak.strand.create` operation whose full Strand scope is a
/// private discussion Circle.
pub fn scoped_discussion_strand_create(
    realm_id: &str,
    actor: &str,
    circle_id: &str,
    title: &str,
) -> anyhow::Result<TypedOperationBuilder> {
    let typed_realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|e| anyhow::anyhow!("invalid realm_id: {e:?}"))?;
    let actor_id = crate::mls_api_helpers::principal_core_id(actor)
        .map_err(|e| anyhow::anyhow!("invalid actor DID: {e:?}"))?;
    let mut strand = arkret_sdk::StrandCreateObject::new(typed_realm_id, actor_id)
        .with_metadata_title(title)
        .with_track("discussion", arkret_sdk::StrandTrack::discussion_primary());
    strand.scope_circle_id = Some(circle_id_value(circle_id)?);
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::StrandCreate>(
            realm_id,
            actor,
            strand_create_payload(strand)?,
        )
        .circle_id(circle_id),
    )
}

/// Build the private-side relation from a Circle-scoped discussion Strand
/// back to the public seal Strand/message.
pub fn confidential_discussion_relation_create(
    realm_id: &str,
    actor: &str,
    private_strand_id: &str,
    public_seal_ref: &str,
    circle_id: &str,
) -> anyhow::Result<TypedOperationBuilder> {
    // No relation id is minted here: `TypedOperationBuilder` stamps the derived one
    // as `unsigned.local_target_ref` once the envelope exists.
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::RelationCreate>(
            realm_id,
            actor,
            super::relation::relation_create_payload(
                realm_id,
                actor,
                "confidential_discussion_of",
                private_strand_id,
                public_seal_ref,
            )?,
        )
        .circle_id(circle_id),
    )
}
