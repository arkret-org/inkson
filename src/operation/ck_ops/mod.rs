//! Canonical helper constructors used by the current UI.
//!
//! This module is split by topic across the sibling files (`discussion`,
//! `strand`, `space`, ...). Each `pub fn` builder is re-exported here so the
//! external path stays `crate::operation::ck_ops::<fn>`. The shared private
//! helpers below are `pub(super)` so the topic files can reuse them while
//! remaining invisible outside `ck_ops`.

use serde_json::Value;

// Structural split: the topic files (`discussion`, `strand`, ...) reach the
// envelope builder and realm-id normalizer through `super::*` (= this module).
// Re-export them from the parent `operation` module so those `use
// super::OperationBuilder` / `super::trim_realm_id` paths resolve unchanged.
pub(super) use super::{OperationBuilder, trim_realm_id};
pub(super) use crate::payload::{payload_value, sdk_payload_value, strand_id_value};

// YOU-02-001: every fallible helper below returns `anyhow::Result`
// instead of panicking. The ids these helpers parse ultimately come from
// server sync data (bare `String` fields in `models.rs` strand into local
// UI state), so a non-canonical id from a buggy or malicious server must
// surface as a recoverable error — on wasm a panic kills the whole page.

mod agent;
mod applet;
mod calendar;
mod capability;
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

pub use agent::*;
pub use applet::*;
pub use calendar::*;
pub use capability::*;
pub use device_mls::*;
pub use discussion::*;
pub use incident_kanban::*;
pub use invite::*;
pub use moderation::*;
pub use morph::*;
pub use realm::*;
pub use relation::*;
pub use space::*;
pub use strand::*;

pub(super) fn did_id(value: &str) -> anyhow::Result<cokret_sdk::Did> {
    cokret_sdk::Did::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid DID {value:?}: {err:?}"))
}

/// Build a spec `invite_payload` (invite_id-ref anyOf branch) value for
/// `ck.invite.accept` / `ck.invite.cancel` via the SDK strong type.
pub(super) fn invite_ref_payload_value(
    invite_id: &str,
    reason: Option<&str>,
) -> anyhow::Result<Value> {
    let invite_id_typed = cokret_sdk::InviteId::new(invite_id.to_owned())
        .map_err(|err| anyhow::anyhow!("invite_id not canonical {invite_id:?}: {err}"))?;
    let mut payload = cokret_sdk::models::InviteRefPayload::new(invite_id_typed);
    if let Some(reason) = reason {
        payload = payload.with_reason(reason);
    }
    payload
        .to_value()
        .map_err(|err| anyhow::anyhow!("invite ref payload: {err}"))
}

pub(super) fn realm_id_value(value: &str) -> anyhow::Result<cokret_sdk::RealmId> {
    cokret_sdk::RealmId::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid realm id {value:?}: {err:?}"))
}

pub(super) fn space_id_value(value: &str) -> anyhow::Result<cokret_sdk::SpaceId> {
    cokret_sdk::SpaceId::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid space id {value:?}: {err:?}"))
}

pub(super) fn circle_id_value(value: &str) -> anyhow::Result<cokret_sdk::CircleId> {
    cokret_sdk::CircleId::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid circle id {value:?}: {err:?}"))
}

pub(super) fn morph_id_value(value: &str) -> anyhow::Result<cokret_sdk::MorphId> {
    cokret_sdk::MorphId::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid morph id {value:?}: {err:?}"))
}

pub(super) fn object_create_payload_value<T: serde::Serialize>(
    object: T,
    context: &str,
) -> anyhow::Result<Value> {
    sdk_payload_value(
        cokret_sdk::ObjectCreatePayload::new(object).to_value(),
        context,
    )
}

pub(super) fn object_patch_payload_value(
    object_ref: &str,
    patch: cokret_sdk::Patch,
) -> anyhow::Result<Value> {
    cokret_sdk::ObjectPatchPayload::for_target(object_ref, patch)
        .and_then(|payload| payload.to_value())
        .map_err(|err| anyhow::anyhow!("invalid object_patch_payload for {object_ref}: {err}"))
}

pub(super) fn morph_update_payload_value(
    morph_id: &str,
    patch: cokret_sdk::Patch,
) -> anyhow::Result<Value> {
    cokret_sdk::ObjectPatchPayload::for_target(morph_id_value(morph_id)?.as_str(), patch)
        .and_then(|payload| payload.to_value())
        .map_err(|err| anyhow::anyhow!("invalid morph_update_payload for {morph_id}: {err}"))
}

pub(super) fn space_patch_payload_value(
    space_id: &str,
    patch: cokret_sdk::Patch,
) -> anyhow::Result<Value> {
    let payload = cokret_sdk::SpacePatchPayload {
        space_id: space_id_value(space_id)?,
        patch,
        expected_state_digest: None,
    };
    payload_value(
        &payload,
        &format!("invalid space_patch_payload for {space_id}"),
    )
}

pub(super) fn space_state_transition_payload_value(
    space_id: &str,
    new_state: cokret_sdk::ObjectState,
) -> anyhow::Result<Value> {
    let payload = cokret_sdk::SpaceStateTransitionPayload {
        space_id: space_id_value(space_id)?,
        new_state,
        reason: None,
    };
    payload_value(
        &payload,
        &format!("invalid space_state_transition_payload for {space_id}"),
    )
}

pub(super) fn strand_object_patch_payload_value(
    strand_id: &str,
    patch: cokret_sdk::Patch,
) -> anyhow::Result<Value> {
    object_patch_payload_value(strand_id, patch)
}

pub(super) fn strand_tracks_update_payload_value(
    strand_id: &str,
    patch: cokret_sdk::Patch,
) -> anyhow::Result<Value> {
    cokret_sdk::StrandTracksUpdatePayload::with_patch(strand_id_value(strand_id)?, patch)
        .and_then(|payload| payload.to_value())
        .map_err(|err| {
            anyhow::anyhow!("invalid ck.strand.tracks.update payload for {strand_id}: {err}")
        })
}

pub(super) fn strand_watch_level_value(
    level: &str,
) -> anyhow::Result<cokret_sdk::StrandWatchLevel> {
    match level {
        "mentions_only" => Ok(cokret_sdk::StrandWatchLevel::MentionsOnly),
        "participating" => Ok(cokret_sdk::StrandWatchLevel::Participating),
        "all" => Ok(cokret_sdk::StrandWatchLevel::All),
        "muted" => Ok(cokret_sdk::StrandWatchLevel::Muted),
        other => Err(anyhow::anyhow!(
            "unknown ck.strand.watch.set level {other:?}"
        )),
    }
}

/// Build the canonical `strand_watch_set_payload` body via the SDK strong
/// type. `level=None` clears the cell (`level:null`); per the schema
/// `allOf`, the typed constructor forces `level_public` off on that path.
pub(super) fn strand_watch_set_payload_value(
    strand_id: &str,
    watcher_actor_id: &str,
    level: Option<&str>,
    level_public: Option<bool>,
) -> anyhow::Result<Value> {
    let payload = match level {
        Some(level) => cokret_sdk::StrandWatchSetPayload::set(
            strand_id_value(strand_id)?,
            did_id(watcher_actor_id)?,
            strand_watch_level_value(level)?,
            level_public,
        ),
        None => cokret_sdk::StrandWatchSetPayload::clear(
            strand_id_value(strand_id)?,
            did_id(watcher_actor_id)?,
        ),
    };
    payload
        .to_value()
        .map_err(|err| anyhow::anyhow!("invalid strand_watch_set_payload for {strand_id}: {err}"))
}

/// Build the canonical `strand_move_payload` body via the SDK strong type.
/// `additionalProperties:false` — the destination is single-sourced by
/// `target_space_id`; the optional `from_space_id` / `expected_position`
/// (space_id + rank) are CAS hints.
pub(super) fn strand_move_payload_value(
    board_space_id: &str,
    strand_id: &str,
    target_space_id: &str,
    rank: &str,
    from_space_id: Option<&str>,
    expected: Option<(Option<&str>, Option<&str>)>,
) -> anyhow::Result<Value> {
    let mut payload = cokret_sdk::StrandMovePayload::new(
        space_id_value(board_space_id)?,
        strand_id_value(strand_id)?,
        space_id_value(target_space_id)?,
        rank.to_owned(),
    );
    if let Some(from) = from_space_id {
        payload = payload.with_from_space_id(space_id_value(from)?);
    }
    if let Some((expected_space, expected_rank)) = expected {
        payload = payload.with_expected_position(cokret_sdk::StrandMoveExpectedPosition {
            space_id: expected_space.map(space_id_value).transpose()?,
            rank: expected_rank.map(ToOwned::to_owned),
            relation_id: None,
        });
    }
    payload
        .to_value()
        .map_err(|err| anyhow::anyhow!("invalid strand_move_payload for {strand_id}: {err}"))
}

/// Build the canonical `strand_reorder_payload` body via the SDK strong
/// type. Re-ranks within a single List Space (`space_id`); the optional
/// `expected_position` carries only a rank (no space_id field).
pub(super) fn strand_reorder_payload_value(
    board_space_id: &str,
    strand_id: &str,
    space_id: &str,
    rank: &str,
    expected_rank: Option<&str>,
) -> anyhow::Result<Value> {
    let mut payload = cokret_sdk::StrandReorderPayload::new(
        space_id_value(board_space_id)?,
        strand_id_value(strand_id)?,
        space_id_value(space_id)?,
        rank.to_owned(),
    );
    if let Some(expected_rank) = expected_rank {
        payload = payload.with_expected_position(cokret_sdk::StrandReorderExpectedPosition {
            rank: Some(expected_rank.to_owned()),
            relation_id: None,
        });
    }
    payload
        .to_value()
        .map_err(|err| anyhow::anyhow!("invalid strand_reorder_payload for {strand_id}: {err}"))
}

/// Build the canonical `object_lifecycle_payload` body via the SDK strong
/// type. Single truth source `target_ref` (`additionalProperties:false`).
pub(super) fn object_lifecycle_payload_value(target_ref: &str) -> anyhow::Result<Value> {
    cokret_sdk::ObjectLifecyclePayload::new(target_ref.to_owned())
        .to_value()
        .map_err(|err| anyhow::anyhow!("invalid object_lifecycle_payload for {target_ref}: {err}"))
}

/// Build the canonical `relation_create_payload` body (flat
/// `{kind, from_ref, to_ref}` form) via the SDK strong type. The
/// schema is `additionalProperties:false`, so unsupported
/// `relation_id` / `scope_circle_id` / `fields` keys are dropped:
/// the relation id is routed via the operation `target_ref`, and the
/// extra annotation fields were never spec-legal (they tripped
/// `schema_violation`).
pub(super) fn relation_create_payload_value(
    kind: &str,
    from_ref: &str,
    to_ref: &str,
) -> anyhow::Result<Value> {
    cokret_sdk::RelationCreatePayload::new(kind, from_ref.to_owned(), to_ref.to_owned())
        .to_value()
        .map_err(|err| {
            anyhow::anyhow!("invalid relation_create_payload ({kind} {from_ref}->{to_ref}): {err}")
        })
}

pub(super) fn patch_from_value(patch: Value) -> anyhow::Result<cokret_sdk::Patch> {
    let patch: cokret_sdk::Patch = serde_json::from_value(patch)
        .map_err(|err| anyhow::anyhow!("ck.strand.update patch must match ck.patch.v1: {err}"))?;
    patch
        .validate()
        .map_err(|err| anyhow::anyhow!("ck.strand.update patch must match ck.patch.v1: {err}"))?;
    Ok(patch)
}
