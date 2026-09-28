//! Canonical helper constructors used by the current UI.
//!
//! This module is split by topic across the sibling files (`discussion`,
//! `strand`, `space`, ...). Each `pub fn` builder is re-exported here so the
//! external path stays `crate::operation::ak_ops::<fn>`. The shared private
//! helpers below are `pub(super)` so the topic files can reuse them while
//! remaining invisible outside `ak_ops`.

use serde_json::Value;

// Structural split: the topic files (`discussion`, `strand`, ...) reach the
// envelope builder and realm-id normalizer through `super::*` (= this module).
// Re-export them from the parent `operation` module so topic modules share the
// same typed envelope boundary and Realm-id normalizer.
pub(super) use super::{TypedOperationBuilder, trim_realm_id};
pub(super) use crate::payload::strand_id_value;

// Every fallible helper below returns `anyhow::Result`
// instead of panicking. The ids these helpers parse ultimately come from
// server sync data (bare `String` fields in `models.rs` strand into local
// UI state), so a non-canonical id from a buggy or malicious server must
// surface as a recoverable error — on wasm a panic kills the whole page.

mod account_profile;
mod calendar;
mod capability;
mod circle;
mod consent;
mod device_mls;
mod discussion;
mod incident_kanban;
mod invite;
mod moderation;
mod morph;
mod realm;
mod relation;
mod space;
mod strand;

pub use account_profile::*;
pub use calendar::*;
pub use capability::*;
pub use circle::*;
pub use consent::*;
pub use device_mls::*;
pub use discussion::*;
pub use incident_kanban::*;
pub use invite::*;
pub use moderation::*;
#[cfg(test)]
pub use morph::*;
pub use realm::*;
pub(crate) use relation::*;
pub use space::*;
pub use strand::*;

pub(super) fn did_id(value: &str) -> anyhow::Result<arkret_sdk::DidCoreId> {
    crate::mls_api_helpers::principal_core_id(value)
        .map_err(|err| anyhow::anyhow!("invalid DID {value:?}: {err:?}"))
}

pub(super) fn actor_id(value: &str) -> anyhow::Result<arkret_sdk::ActorId> {
    crate::mls_api_helpers::local_account_actor_id(value)
        .map_err(|err| anyhow::anyhow!("invalid actor core_id {value:?}: {err:?}"))
}

pub(super) fn realm_id_value(value: &str) -> anyhow::Result<arkret_sdk::RealmId> {
    arkret_sdk::RealmId::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid realm id {value:?}: {err:?}"))
}

pub(super) fn space_id_value(value: &str) -> anyhow::Result<arkret_sdk::SpaceId> {
    arkret_sdk::SpaceId::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid space id {value:?}: {err:?}"))
}

pub(super) fn circle_id_value(value: &str) -> anyhow::Result<arkret_sdk::CircleId> {
    arkret_sdk::CircleId::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid circle id {value:?}: {err:?}"))
}

#[cfg(test)]
pub(super) fn morph_id_value(value: &str) -> anyhow::Result<arkret_sdk::MorphId> {
    arkret_sdk::MorphId::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid morph id {value:?}: {err:?}"))
}

pub(crate) fn strand_create_payload(
    object: arkret_sdk::StrandCreateObject,
) -> anyhow::Result<arkret_sdk::StrandCreatePayload> {
    Ok(arkret_sdk::StrandCreatePayload {
        object: arkret_sdk::Strand {
            id: object.id,
            schema: object.schema,
            realm_id: object.realm_id,
            scope_circle_id: object.scope_circle_id,
            schema_refs: None,
            agent_participation: object.agent_participation,
            metadata: object.metadata,
            encrypted_metadata: object.encrypted_metadata,
            content: object.content,
            encrypted_content: object.encrypted_content,
            tracks: object.tracks,
            state: object.state,
            state_changed_at: None,
            // The create schema forbids stage; only ak.strand.stage.set may
            // initialize the optional business progression axis.
            stage: None,
            stage_changed_at: None,
            created_by: object.created_by,
            created_at: object.created_at,
            updated_by: object.updated_by,
            updated_at: object.updated_at,
        },
    })
}

pub(super) fn strand_create_operation(
    realm_id: &str,
    actor: &str,
    object: arkret_sdk::StrandCreateObject,
) -> anyhow::Result<TypedOperationBuilder> {
    // The service derives the initial Strand from the authored Event. Its
    // created_at must be the exact same canonical instant as the Event clock.
    let created_at = object.created_at;
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::StrandCreate>(
            realm_id,
            actor,
            strand_create_payload(object)?,
        )
        .created_at(created_at),
    )
}

pub(super) fn strand_object_patch_payload(
    strand_id: &str,
    patch: arkret_sdk::Patch,
) -> anyhow::Result<arkret_sdk::StrandPatchPayload> {
    arkret_sdk::StrandPatchPayload::for_strand(strand_id_value(strand_id)?, patch)
        .map_err(anyhow::Error::from)
}

/// `ak.strand.tracks.update` body.
///
/// The registered contract derives the `ak.component.strand.tracks.v1` cell
/// subject from `payload.target_ref` and applies `payload.patch`, so this is
/// the `object_patch_payload` shape, not the SDK
/// `StrandTracksUpdatePayload`'s `{strand_id, patch}` — a `strand_id`-keyed
/// body has no derivable cell write and would be rejected at admission.
pub(super) fn strand_tracks_update_payload(
    strand_id: &str,
    patch: arkret_sdk::Patch,
) -> anyhow::Result<arkret_sdk::StrandPatchPayload> {
    strand_object_patch_payload(strand_id, patch)
}

/// Build the canonical `strand_move_payload` body via the SDK strong type.
/// `additionalProperties:false` — the destination is single-sourced by
/// `target_space_id`; the optional `from_space_id` / `expected_position`
/// carry the complete observed current value and request an explicit CAS.
/// Omission leaves concurrent writes serialized by the Station without a CAS.
pub(super) fn strand_move_payload(
    board_space_id: &str,
    strand_id: &str,
    target_space_id: &str,
    rank: &str,
    from_space_id: Option<&str>,
    expected: Option<(&str, &str)>,
) -> anyhow::Result<arkret_sdk::StrandMovePayload> {
    let mut payload = arkret_sdk::StrandMovePayload::new(
        space_id_value(board_space_id)?,
        strand_id_value(strand_id)?,
        space_id_value(target_space_id)?,
        rank.to_owned(),
    );
    if let Some(from) = from_space_id {
        payload = payload.with_from_space_id(space_id_value(from)?);
    }
    if let Some((expected_space, expected_rank)) = expected {
        payload = payload.with_expected_position(arkret_sdk::StrandPositionCurrent {
            list_space_id: space_id_value(expected_space)?,
            rank: expected_rank.to_owned(),
        });
    }
    Ok(payload)
}

/// Build the canonical `strand_reorder_payload` body via the SDK strong
/// type. Re-ranks within a single List Space (`space_id`); the optional
/// `expected_position` carries the complete observed position current value.
pub(super) fn strand_reorder_payload(
    board_space_id: &str,
    strand_id: &str,
    space_id: &str,
    rank: &str,
    expected: Option<(&str, &str)>,
) -> anyhow::Result<arkret_sdk::StrandReorderPayload> {
    let mut payload = arkret_sdk::StrandReorderPayload::new(
        space_id_value(board_space_id)?,
        strand_id_value(strand_id)?,
        space_id_value(space_id)?,
        rank.to_owned(),
    );
    if let Some((expected_space, expected_rank)) = expected {
        payload = payload.with_expected_position(arkret_sdk::StrandPositionCurrent {
            list_space_id: space_id_value(expected_space)?,
            rank: expected_rank.to_owned(),
        });
    }
    Ok(payload)
}

/// Decode and fully validate an outbound `ak.schema.patch.v1` map.
///
/// Every Strand / Space / Morph patch this client authors goes through here, so
/// this is where the cross-object patch safety rules of
/// `event-and-patch.md` §4.2.4 (no `unset` / `remove` on redactable content
/// fields) and §4.2.5 (no reducer-managed paths) are enforced. The SDK owns
/// both path lists; failing here keeps a patch a compliant reducer would reject
/// with `patch_unset_redactable_field` / `patch_path_reducer_managed` off the
/// wire in the first place.
pub(super) fn patch_from_value(
    target_ref: &str,
    patch: Value,
) -> anyhow::Result<arkret_sdk::Patch> {
    let patch: arkret_sdk::Patch = serde_json::from_value(patch)
        .map_err(|err| anyhow::anyhow!("patch must match ak.patch.v1: {err}"))?;
    arkret_sdk::validate_patch_semantic_safety(&patch)
        .map_err(|err| anyhow::anyhow!("patch must match ak.patch.v1: {err}"))?;
    Ok(patch)
}
