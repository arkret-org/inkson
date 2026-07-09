//! Discussion Strand / Circle builders.

use super::{
    OperationBuilder, circle_id_value, did_id, object_create_payload_value, realm_id_value,
    relation_create_payload_value, trim_realm_id,
};

/// Build a canonical `ck.strand.create` discussion operation with the full
/// typed Strand payload expected by the current reducers.
///
/// The full Strand lives under the spec-canonical `object` key —
/// see soland `routing/events/operations.rs::STRAND_CREATE_REQUIREMENTS`
/// and SDK `crates/core/src/schema/payloads.rs` which both gate
/// `ck.strand.create` on `payload.object`.
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
    let typed_strand_id = arkret_sdk::StrandId::new(strand_id.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid strand_id: {e:?}"))?;
    let strand = arkret_sdk::StrandCreateObject::new(typed_strand_id, typed_realm_id, did)
        .with_metadata_title(title)
        .with_track(
            "discussion",
            arkret_sdk::StrandTrackConfig::discussion_primary(),
        );
    let payload = arkret_sdk::ObjectCreatePayload::new(strand)
        .to_value()
        .map_err(|e| anyhow::anyhow!("ak.strand.create payload serialize: {e}"))?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::StrandCreate,
    )
    .target_ref(strand_id)
    .body(payload))
}

/// Build a canonical `ck.circle.create` operation for a private
/// discussion scope inside `realm_id`.
pub fn discussion_circle_create(
    realm_id: &str,
    actor: &str,
    circle_id: &str,
    title: &str,
) -> anyhow::Result<OperationBuilder> {
    let display = arkret_sdk::CircleDisplay {
        short_name: title.trim().chars().take(16).collect::<String>(),
        color_token: arkret_sdk::CircleColorToken::Indigo,
        symbol: arkret_sdk::CircleSymbol::Glyph {
            glyph: arkret_sdk::CircleGlyph::Lock,
        },
    };
    let circle = arkret_sdk::Circle::new(
        circle_id_value(circle_id)?,
        realm_id_value(&trim_realm_id(realm_id))?,
        title.trim(),
        display,
        did_id(actor)?,
    );
    let body = object_create_payload_value(circle, "ak.circle.create payload serialize")?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::CircleCreate,
    )
    .target_ref(circle_id)
    .body(body))
}

/// Build a `ck.strand.create` operation whose full Strand scope is a
/// private discussion Circle.
pub fn scoped_discussion_strand_create(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    circle_id: &str,
    title: &str,
) -> anyhow::Result<OperationBuilder> {
    let typed_realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|e| anyhow::anyhow!("invalid realm_id: {e:?}"))?;
    let did = arkret_sdk::Did::new(actor.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid actor DID: {e:?}"))?;
    let typed_strand_id = arkret_sdk::StrandId::new(strand_id.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid strand_id: {e:?}"))?;
    let mut strand = arkret_sdk::StrandCreateObject::new(typed_strand_id, typed_realm_id, did)
        .with_metadata_title(title)
        .with_track(
            "discussion",
            arkret_sdk::StrandTrackConfig::discussion_primary(),
        );
    strand.scope_circle_id = Some(circle_id_value(circle_id)?);
    let payload = arkret_sdk::ObjectCreatePayload::new(strand)
        .to_value()
        .map_err(|e| anyhow::anyhow!("ak.strand.create payload serialize: {e}"))?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::StrandCreate,
    )
    .target_ref(strand_id)
    .body(payload))
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
    // `circle_id` is unused on the wire: relation_create_payload is
    // additionalProperties:false and the private-side scope is already
    // carried by the Circle-scoped Strand itself.
    let _ = circle_id;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::RelationCreate,
    )
    .target_ref(private_strand_id)
    .body(relation_create_payload_value(
        "confidential_discussion_of",
        private_strand_id,
        public_seal_ref,
    )?))
}
