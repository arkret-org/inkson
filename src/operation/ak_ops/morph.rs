//! Generic Morph object builders.
//!
//! `ak.morph.*` is a generic object family in the protocol; the Document
//! surface that used to drive these builders was removed, but the
//! `ak.morph.update` patch builder is retained for the Morph patch payload
//! family.

#[cfg(test)]
use super::{TypedOperationBuilder, morph_id_value, patch_from_value};

#[cfg(test)]
/// Build a `ak.morph.update` patch operation. Mirrors
/// [`strand_update_patch`](super::strand_update_patch) for Morph objects;
/// soland's `apply_morph_update` reducer accepts `payload.patch` with the
/// standard `ak.schema.patch.v1` shape.
pub fn morph_update_patch(
    realm_id: &str,
    actor: &str,
    morph_id: &str,
    patch: serde_json::Value,
) -> anyhow::Result<TypedOperationBuilder> {
    let patch = patch_from_value(morph_id, patch)?;
    let payload = arkret_sdk::MorphUpdatePayload::for_morph(morph_id_value(morph_id)?, patch)?;
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::MorphUpdate>(realm_id, actor, payload)
            .target_ref(morph_id),
    )
}
