//! Strand lifecycle / tracks / watch / position builders.

use arkret_wire::event_kind_str;
use serde_json::{Value, json};

use super::{
    TypedOperationBuilder, patch_from_value, strand_id_value, strand_move_payload,
    strand_object_patch_payload, strand_reorder_payload, strand_tracks_update_payload,
    strand_watch_set_payload,
};

/// Build a `ak.strand.watch.set` operation. Spec:
/// `arkret-spec/spec/v1/zh/models/strand-and-message.md §8.3` —
/// writes the causal-register cell `ak.component.strand.watch.v1` keyed by
/// `(strand_id, watcher_actor_id)`.
///
/// `level` is one of `mentions_only` / `participating` / `all` / `muted`,
/// or `None` to clear the cell (equivalent to `mentions_only` default).
/// `level_public` is the opt-in flag from §8.5 — when `true`, projection
/// to non-self viewers does not strip the level value (but `muted` still
/// stays invisible). Caller MUST omit `level_public` when `level` is None.
///
/// Default reducer invariant: `target_actor` MUST equal `sender_actor`
/// unless the sender holds `ak.strand.watch.set.others`. Callers
/// helping someone else subscribe (e.g. Strand creator seeding
/// watchers on create) need that capability.
pub fn strand_watch_set(
    realm_id: &str,
    sender_actor: &str,
    target_actor_id: &str,
    strand_id: &str,
    level: Option<&str>,
    level_public: Option<bool>,
) -> anyhow::Result<TypedOperationBuilder> {
    // Strong type: strand_watch_set_payload (additionalProperties:false +
    // allOf forbidding level_public when level is null). The typed
    // constructors keep the clear path (level:null) free of level_public.
    let payload = strand_watch_set_payload(strand_id, target_actor_id, level, level_public)?;
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::StrandWatchSet>(
            realm_id,
            sender_actor,
            payload,
        )
        .target_ref(strand_id),
    )
}

/// Return the exact causal-register selector used by a receiver's watch
/// preference. Keep this derived by the SDK payload type so product reads and
/// writes cannot disagree about the composite `(strand, actor)` subject.
pub fn strand_watch_cell_ref(
    strand_id: &str,
    watcher_actor_id: &str,
) -> anyhow::Result<arkret_sdk::CellRef> {
    strand_watch_set_payload(strand_id, watcher_actor_id, Some("mentions_only"), None)?
        .cell_ref()
        .map_err(Into::into)
}

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
/// Disabling, renaming, or marking a track primary all strand through the
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
/// callers must separately put the corresponding position-head digests in the
/// Event's `causal_refs` so offline concurrent Moves remain concurrent.
pub fn strand_position_update(
    realm_id: &str,
    actor: &str,
    kind: &str,
    board_space_id: &str,
    strand_id: &str,
    expected_position: Value,
    effect_position: Value,
) -> anyhow::Result<TypedOperationBuilder> {
    let position_field = |value: &Value, field: &str| {
        value
            .get(field)
            .or_else(|| match field {
                "space_id" => value.get("list_space_id"),
                _ => None,
            })
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    };
    let expected_space = position_field(&expected_position, "space_id");
    let expected_rank = position_field(&expected_position, "rank");
    let effect_space = position_field(&effect_position, "space_id");
    let effect_rank = position_field(&effect_position, "rank");

    let Some(effect_space) = effect_space else {
        anyhow::bail!("strand position update requires effect_position.space_id");
    };
    let Some(effect_rank) = effect_rank else {
        anyhow::bail!("strand position update requires effect_position.rank");
    };

    // Strong types: strand_reorder_payload / strand_move_payload
    // (additionalProperties:false). The reorder path stays within a
    // single List Space (effect_space == space_id); the move path treats
    // effect_space as the destination target_space_id and carries the
    // optional from_space_id / expected_position basis diagnostics.
    match kind {
        event_kind_str::STRAND_REORDER => {
            let payload = strand_reorder_payload(
                board_space_id,
                strand_id,
                &effect_space,
                &effect_rank,
                expected_rank.as_deref(),
            )?;
            Ok(
                TypedOperationBuilder::new::<arkret_sdk::event_spec::StrandReorder>(
                    realm_id, actor, payload,
                )
                .target_ref(strand_id),
            )
        }
        _ => {
            // expected_position is only emitted when BOTH a prior
            // space_id and rank are known.
            let expected = match (expected_space.as_deref(), expected_rank.as_deref()) {
                (Some(space), Some(rank)) => Some((Some(space), Some(rank))),
                _ => None,
            };
            let payload = strand_move_payload(
                board_space_id,
                strand_id,
                &effect_space,
                &effect_rank,
                expected_space.as_deref(),
                expected,
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
