//! Strand lifecycle / tracks / watch / position builders.

use arkret_wire::event_kind_str;
use serde_json::{Value, json};

use super::{
    TypedOperationBuilder, patch_from_value, strand_id_value, strand_move_payload,
    strand_object_patch_payload, strand_reorder_payload, strand_tracks_update_payload,
};

/// Build a `ak.strand.tracks.update` operation. Spec:
/// `arkret-spec/spec/v1/zh/models/strand-and-message.md §3` (post dc01ad7).
///
/// This is the single unified track-mutation event that replaces
/// `ak.strand.track.{enable,disable,update,set_primary}`.
/// `patch` is a `ak.patch.v1` JSON Patch object against the `Strand.tracks`
/// map (keys are track names like `synthesis` / `discussion`). For
/// example, enabling the `discussion` track is:
///
/// ```json
/// { "tracks.discussion.enabled": { "$op": "set", "value": true } }
/// ```
///
/// Disabling, renaming, or marking a track primary all flow through the
/// same patch shape. Callers that only know a track name should compose
/// the patch via the helpers below (`strand_tracks_update_enable`,
/// `strand_tracks_update_disable`, `strand_tracks_update_set_primary`).
pub fn strand_tracks_update(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    patch: serde_json::Value,
) -> anyhow::Result<TypedOperationBuilder> {
    let patch = patch_from_value(strand_id, patch)?;
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::StrandTracksUpdate>(
            realm_id,
            actor,
            strand_tracks_update_payload(strand_id, patch)?,
        )
        .target_ref(strand_id),
    )
}

/// Convenience wrapper: mark `track` as the Strand's primary track.
/// Carries a single set-op against `tracks.<name>.is_primary`. The reducer
/// is responsible for clearing the previous primary cell.
pub fn strand_tracks_update_set_primary(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    track: &str,
) -> anyhow::Result<TypedOperationBuilder> {
    let key = format!("tracks.{track}.is_primary");
    let patch = json!({ key: { "$op": "set", "value": true } });
    strand_tracks_update(realm_id, actor, strand_id, patch)
}

/// Build a `ak.strand.archive` operation. Spec: `strand-and-message.md §3`
/// and `common-fields.md §5.1`; payload shape is the
/// `object_lifecycle_payload` from
/// `artifacts/schemas/event-payload.schema.json`, which requires
/// `target_ref`. SDK reducer rejects with
/// `strand_not_active` when source state is not `active`.
pub fn strand_archive(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
) -> anyhow::Result<TypedOperationBuilder> {
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::StrandArchive>(
            realm_id,
            actor,
            arkret_sdk::ObjectLifecyclePayload::new(strand_id_value(strand_id)?.as_str()),
        )
        .target_ref(strand_id),
    )
}

/// Build a `ak.strand.restore` operation. Reverses [`strand_archive`]
/// (`archived -> active`). SDK reducer rejects with `strand_not_archived`
/// when source state is not `archived`. Payload shape mirrors the
/// archive op (spec `object_lifecycle_payload`).
pub fn strand_restore(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
) -> anyhow::Result<TypedOperationBuilder> {
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::StrandRestore>(
            realm_id,
            actor,
            arkret_sdk::ObjectLifecyclePayload::new(strand_id_value(strand_id)?.as_str()),
        )
        .target_ref(strand_id),
    )
}

/// Build a `ak.strand.update` delta operation using the canonical
/// `ak.patch.v1` payload shape. Non-create Strand updates should carry
/// only changed fields; callers are responsible for composing patch paths
/// that are valid for the Strand schema/profile.
pub fn strand_update_patch(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    patch: serde_json::Value,
) -> anyhow::Result<TypedOperationBuilder> {
    let patch = patch_from_value(strand_id, patch)?;
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::StrandUpdate>(
            realm_id,
            actor,
            strand_object_patch_payload(strand_id, patch)?,
        )
        .target_ref(strand_id),
    )
}

/// Strand position update. The payload retains the optional observed position;
/// the complete observed value is an explicit CAS guard, while omission
/// requests no concurrency guard. The Station determines accepted order.
pub fn strand_position_update(
    realm_id: &str,
    actor: &str,
    kind: &str,
    board_space_id: &str,
    strand_id: &str,
    expected_position: Value,
    effect_position: Value,
) -> anyhow::Result<TypedOperationBuilder> {
    let expected: Option<arkret_sdk::StrandPositionCurrent> =
        serde_json::from_value(expected_position)
            .map_err(|error| anyhow::anyhow!("invalid complete expected position: {error}"))?;
    let effect: arkret_sdk::StrandPositionCurrent = serde_json::from_value(effect_position)
        .map_err(|error| anyhow::anyhow!("requires complete effect_position: {error}"))?;
    let effect_space = effect.list_space_id.as_str();
    let effect_rank = effect.rank.as_str();
    let expected_space = expected
        .as_ref()
        .map(|position| position.list_space_id.as_str());
    let expected_pair = expected
        .as_ref()
        .map(|position| (position.list_space_id.as_str(), position.rank.as_str()));

    // Strong types: strand_reorder_payload / strand_move_payload
    // (additionalProperties:false). The reorder path stays within a
    // single List Space (effect_space == space_id); the move path treats
    // effect_space as the destination target_space_id and carries the
    // optional source hint and exact whole-value compare-and-set preimage.
    match kind {
        event_kind_str::STRAND_REORDER => {
            let payload = strand_reorder_payload(
                board_space_id,
                strand_id,
                effect_space,
                effect_rank,
                expected_pair,
            )?;
            Ok(
                TypedOperationBuilder::new::<arkret_sdk::event_spec::StrandReorder>(
                    realm_id, actor, payload,
                )
                .target_ref(strand_id),
            )
        }
        _ => {
            let payload = strand_move_payload(
                board_space_id,
                strand_id,
                effect_space,
                effect_rank,
                expected_space,
                expected_pair,
            )?;
            Ok(
                TypedOperationBuilder::new::<arkret_sdk::event_spec::StrandMove>(
                    realm_id, actor, payload,
                )
                .target_ref(strand_id),
            )
        }
    }
}
