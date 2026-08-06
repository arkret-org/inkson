//! Discussion Strand / Circle builders.

use super::{
    OperationBuilder, circle_id_value, did_id, object_create_payload_value, realm_id_value,
    relation_create_payload_value, trim_realm_id,
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
    strand_id: &str,
    title: &str,
) -> anyhow::Result<OperationBuilder> {
    let typed_realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|e| anyhow::anyhow!("invalid realm_id: {e:?}"))?;
    let did = arkret_sdk::Did::new(actor.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid actor DID: {e:?}"))?;
    // `strand_id` is no longer the object id — that is derived from this
    // create Event. It survives only as the client-local correlation handle in
    // `unsigned.local_target_ref`, so validate its shape and drop the value.
    arkret_sdk::StrandId::new(strand_id.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid strand_id: {e:?}"))?;
    let strand = arkret_sdk::StrandCreateObject::new(typed_realm_id, did)
        .with_metadata_title(title)
        .with_track(
            "discussion",
            arkret_sdk::StrandTrackConfig::discussion_primary(),
        );
    let payload = arkret_sdk::ObjectCreatePayload::new(strand)
        .to_value()
        .map_err(|e| anyhow::anyhow!("ak.strand.create payload serialize: {e}"))?;
    Ok(
        OperationBuilder::new(realm_id, actor, arkret_sdk::EventKind::StrandCreate)
            .target_ref(strand_id)
            .body(payload),
    )
}

/// Build a canonical `ak.circle.create` operation for a private
/// discussion scope inside `realm_id`.
pub fn discussion_circle_create(
    realm_id: &str,
    actor: &str,
    title: &str,
) -> anyhow::Result<OperationBuilder> {
    let display = arkret_sdk::CircleDisplay {
        short_name: title.trim().chars().take(16).collect::<String>(),
        color_token: arkret_sdk::CircleColorToken::Indigo,
        symbol: arkret_sdk::CircleSymbol::Glyph {
            glyph: arkret_sdk::CircleGlyph::Lock,
        },
    };
    let mut circle = arkret_sdk::Circle::new(
        // Placeholder: cleared below, since a create payload carries no id.
        circle_id_value("ak:circle:00000000-0000-8000-8000-000000000000")?,
        realm_id_value(&trim_realm_id(realm_id))?,
        title.trim(),
        display,
        did_id(actor)?,
    );
    circle.id = None;
    let body = object_create_payload_value(circle, "ak.circle.create payload serialize")?;
    Ok(OperationBuilder::new(realm_id, actor, arkret_sdk::EventKind::CircleCreate).body(body))
}

/// Build a `ak.strand.create` operation whose full Strand scope is a
/// private discussion Circle.
pub fn scoped_discussion_strand_create(
    realm_id: &str,
    actor: &str,
    circle_id: &str,
    title: &str,
) -> anyhow::Result<OperationBuilder> {
    let typed_realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|e| anyhow::anyhow!("invalid realm_id: {e:?}"))?;
    let did = arkret_sdk::Did::new(actor.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid actor DID: {e:?}"))?;
    let mut strand = arkret_sdk::StrandCreateObject::new(typed_realm_id, did)
        .with_metadata_title(title)
        .with_track(
            "discussion",
            arkret_sdk::StrandTrackConfig::discussion_primary(),
        );
    strand.scope_circle_id = Some(circle_id_value(circle_id)?);
    let payload = arkret_sdk::ObjectCreatePayload::new(strand)
        .to_value()
        .map_err(|e| anyhow::anyhow!("ak.strand.create payload serialize: {e}"))?;
    Ok(OperationBuilder::new(realm_id, actor, arkret_sdk::EventKind::StrandCreate).body(payload))
}

/// Build the private-side relation from a Circle-scoped discussion Strand
/// back to the public seal Strand/message.
pub fn confidential_discussion_relation_create(
    realm_id: &str,
    actor: &str,
    private_strand_id: &str,
    public_seal_ref: &str,
    circle_id: &str,
) -> anyhow::Result<OperationBuilder> {
    // No relation id is minted here: `OperationBuilder` stamps the derived one
    // as `unsigned.local_target_ref` once the envelope exists.
    Ok(
        OperationBuilder::new(realm_id, actor, arkret_sdk::EventKind::RelationCreate).body(
            relation_create_payload_value(
                realm_id,
                actor,
                "confidential_discussion_of",
                private_strand_id,
                public_seal_ref,
                // The object branch carries the private side's Circle scope, which the
                // flat branch had nowhere to put.
                Some(circle_id),
            )?,
        ),
    )
}
