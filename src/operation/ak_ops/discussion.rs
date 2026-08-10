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
pub fn discussion_strand_create(
    realm_id: &str,
    actor: &str,
    title: &str,
) -> anyhow::Result<TypedOperationBuilder> {
    let typed_realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|e| anyhow::anyhow!("invalid realm_id: {e:?}"))?;
    let did = crate::mls_api_helpers::principal_core_id(actor)
        .map_err(|e| anyhow::anyhow!("invalid actor DID: {e:?}"))?;
    // No caller-supplied Strand id: the object is derived from this create
    // Event, and `TypedOperationBuilder` stamps that derived id as the client-local
    // handle in `unsigned.local_target_ref`.
    let strand = arkret_sdk::StrandCreateObject::new(typed_realm_id, did)
        .with_metadata_title(title)
        .with_track(
            "discussion",
            arkret_sdk::StrandTrackConfig::discussion_primary(),
        );
    Ok(TypedOperationBuilder::new::<
        arkret_sdk::event_spec::StrandCreate,
    >(realm_id, actor, strand_create_payload(strand)?))
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
    let did = crate::mls_api_helpers::principal_core_id(actor)
        .map_err(|e| anyhow::anyhow!("invalid actor DID: {e:?}"))?;
    let mut strand = arkret_sdk::StrandCreateObject::new(typed_realm_id, did)
        .with_metadata_title(title)
        .with_track(
            "discussion",
            arkret_sdk::StrandTrackConfig::discussion_primary(),
        );
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
            arkret_sdk::RelationCreatePayload::new(
                "confidential_discussion_of",
                private_strand_id,
                public_seal_ref,
            ),
        )
        .circle_id(circle_id),
    )
}
