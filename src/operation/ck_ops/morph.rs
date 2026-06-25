//! Generic Morph object builders.
//!
//! `ck.morph.*` is a generic object family in the protocol; the Document
//! surface that used to drive these builders was removed, but the generic
//! `ck.morph.update` patch builder is retained for the object-patch family
//! (it mirrors [`strand_update_patch`](super::strand_update_patch) /
//! [`space_update_patch`](super::space_update_patch)).

use super::{OperationBuilder, object_patch_payload_value, patch_from_value};

/// Build a `ck.morph.update` patch operation. Mirrors
/// [`strand_update_patch`](super::strand_update_patch) for Morph objects;
/// soland's `apply_morph_update` reducer accepts `payload.patch` with the
/// standard `ck.schema.patch.v1` shape.
pub fn morph_update_patch(
    realm_id: &str,
    actor: &str,
    morph_id: &str,
    patch: serde_json::Value,
) -> anyhow::Result<OperationBuilder> {
    let patch = patch_from_value(patch)?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::MorphUpdate,
    )
    .target_ref(morph_id)
    .body(object_patch_payload_value(morph_id, patch)?))
}
