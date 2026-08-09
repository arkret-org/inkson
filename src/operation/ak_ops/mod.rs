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

// YOU-02-001: every fallible helper below returns `anyhow::Result`
// instead of panicking. The ids these helpers parse ultimately come from
// server sync data (bare `String` fields in `models.rs` strand into local
// UI state), so a non-canonical id from a buggy or malicious server must
// surface as a recoverable error — on wasm a panic kills the whole page.

mod applet;
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

pub use applet::*;
pub use calendar::*;
pub use capability::*;
pub use circle::*;
pub use consent::*;
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

pub(super) fn did_id(value: &str) -> anyhow::Result<arkret_sdk::Did> {
    arkret_sdk::Did::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid DID {value:?}: {err:?}"))
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

pub(super) fn morph_id_value(value: &str) -> anyhow::Result<arkret_sdk::MorphId> {
    arkret_sdk::MorphId::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid morph id {value:?}: {err:?}"))
}

pub(crate) fn strand_create_payload(
    object: arkret_sdk::StrandCreateObject,
) -> arkret_sdk::StrandCreatePayload {
    arkret_sdk::StrandCreatePayload {
        object: arkret_sdk::Strand {
            id: object.id,
            schema: object.schema,
            realm_id: object.realm_id,
            scope_circle_id: object.scope_circle_id,
            schema_refs: None,
            agent_participation: object.agent_participation,
            metadata: object.metadata,
            encrypted_metadata: object.encrypted_metadata,
            body: object.content,
            encrypted_content: object.encrypted_content,
            tracks: object.tracks,
            state: object.state,
            state_changed_at: None,
            stage: Some(object.stage),
            stage_changed_at: None,
            created_by: object.created_by,
            created_at: object.created_at,
            updated_by: object.updated_by,
            updated_at: object.updated_at,
        },
        initial_relations: None,
    }
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

pub(super) fn strand_watch_level_value(
    level: &str,
) -> anyhow::Result<arkret_sdk::StrandWatchLevel> {
    match level {
        "mentions_only" => Ok(arkret_sdk::StrandWatchLevel::MentionsOnly),
        "participating" => Ok(arkret_sdk::StrandWatchLevel::Participating),
        "all" => Ok(arkret_sdk::StrandWatchLevel::All),
        "muted" => Ok(arkret_sdk::StrandWatchLevel::Muted),
        other => Err(anyhow::anyhow!(
            "unknown ak.strand.watch.set level {other:?}"
        )),
    }
}

/// Build the canonical `strand_watch_set_payload` body via the SDK strong
/// type. `level=None` clears the cell (`level:null`); per the schema
/// `allOf`, the typed constructor forces `level_public` off on that path.
pub(super) fn strand_watch_set_payload(
    strand_id: &str,
    watcher_actor_id: &str,
    level: Option<&str>,
    level_public: Option<bool>,
) -> anyhow::Result<arkret_sdk::StrandWatchSetPayload> {
    let payload = match level {
        Some(level) => arkret_sdk::StrandWatchSetPayload::set(
            strand_id_value(strand_id)?,
            did_id(watcher_actor_id)?,
            strand_watch_level_value(level)?,
            level_public,
        ),
        None => arkret_sdk::StrandWatchSetPayload::clear(
            strand_id_value(strand_id)?,
            did_id(watcher_actor_id)?,
        ),
    };
    Ok(payload)
}

/// Build the canonical `strand_move_payload` body via the SDK strong type.
/// `additionalProperties:false` — the destination is single-sourced by
/// `target_space_id`; the optional `from_space_id` / `expected_position`
/// (space_id + rank) are CAS hints.
pub(super) fn strand_move_payload(
    board_space_id: &str,
    strand_id: &str,
    target_space_id: &str,
    rank: &str,
    from_space_id: Option<&str>,
    expected: Option<(Option<&str>, Option<&str>)>,
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
        payload = payload.with_expected_position(arkret_sdk::StrandMoveExpectedPosition {
            space_id: expected_space.map(space_id_value).transpose()?,
            rank: expected_rank.map(ToOwned::to_owned),
            relation_id: None,
        });
    }
    Ok(payload)
}

/// Build the canonical `strand_reorder_payload` body via the SDK strong
/// type. Re-ranks within a single List Space (`space_id`); the optional
/// `expected_position` carries only a rank (no space_id field).
pub(super) fn strand_reorder_payload(
    board_space_id: &str,
    strand_id: &str,
    space_id: &str,
    rank: &str,
    expected_rank: Option<&str>,
) -> anyhow::Result<arkret_sdk::StrandReorderPayload> {
    let mut payload = arkret_sdk::StrandReorderPayload::new(
        space_id_value(board_space_id)?,
        strand_id_value(strand_id)?,
        space_id_value(space_id)?,
        rank.to_owned(),
    );
    if let Some(expected_rank) = expected_rank {
        payload = payload.with_expected_position(arkret_sdk::StrandReorderExpectedPosition {
            rank: Some(expected_rank.to_owned()),
            relation_id: None,
        });
    }
    Ok(payload)
}

pub(super) fn patch_from_value(patch: Value) -> anyhow::Result<arkret_sdk::Patch> {
    let patch: arkret_sdk::Patch = serde_json::from_value(patch)
        .map_err(|err| anyhow::anyhow!("ak.strand.update patch must match ak.patch.v1: {err}"))?;
    patch
        .validate()
        .map_err(|err| anyhow::anyhow!("ak.strand.update patch must match ak.patch.v1: {err}"))?;
    Ok(patch)
}
