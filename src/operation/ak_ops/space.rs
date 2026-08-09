//! Container Space (Board / List) builders.

use super::{
    TypedOperationBuilder, did_id, patch_from_value, realm_id_value, space_id_value, trim_realm_id,
};

/// Build a `ak.space.create` operation for Board/List container Spaces.
///
/// Board/List containers are Space objects and the security boundary is
/// Realm. The optional `parent_space_id` + `rank` fields carry the board/list
/// structural placement while the event kind stays canonical.
///
/// No Space id is taken or minted: `ak.space.create` is
/// `id_source: event_derived`, so the id is `retype(create.event_id)` and the
/// payload MUST omit it (spec `zh/models/common-fields.md` section 6.0).
/// [`TypedOperationBuilder`] stamps the derived id as `unsigned.local_target_ref`
/// once the envelope exists — callers that need to name the new Space read it
/// back from there.
pub fn space_create(
    realm_id: &str,
    actor: &str,
    kind: &str,
    title: &str,
    parent_space_id: Option<&str>,
    rank: Option<&str>,
) -> anyhow::Result<TypedOperationBuilder> {
    let mut object = arkret_sdk::Space::create_object(
        realm_id_value(&trim_realm_id(realm_id))?,
        kind,
        title,
        did_id(actor)?,
    );
    if let Some(parent_space_id) = parent_space_id {
        object.parent_space_id = Some(space_id_value(parent_space_id)?);
    }
    if let Some(rank) = rank {
        object.rank = Some(rank.to_owned());
    }
    Ok(TypedOperationBuilder::new::<
        arkret_sdk::event_spec::SpaceCreate,
    >(
        realm_id,
        actor,
        arkret_sdk::SpaceCreatePayload::new(object),
    ))
}

/// Build a `ak.space.restore` operation. Reverses `realm_archive`
/// (`archived -> active`). The SDK reducer enforces `state == archived`
/// at apply time; tombstoned container Spaces MUST NOT be restored. Spec:
/// `models/realm-and-space.md` §4.4, `common-fields.md §5`.
pub fn space_restore(
    realm_id: &str,
    actor: &str,
    container_space_id: &str,
) -> anyhow::Result<TypedOperationBuilder> {
    let payload = arkret_sdk::SpaceStateTransitionPayload {
        space_id: space_id_value(container_space_id)?,
        reason: None,
        effective_at: None,
    };
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::SpaceRestore>(
            realm_id, actor, payload,
        )
        .target_ref(container_space_id),
    )
}

/// Build a `ak.space.update` patch operation for structural Space
/// metadata (`title`, `summary`, `rank`, `fields`, ...). The event lives
/// in the Space's home Realm; `space_id` stays as the object target.
pub fn space_update_patch(
    realm_id: &str,
    actor: &str,
    space_id: &str,
    patch: serde_json::Value,
) -> anyhow::Result<TypedOperationBuilder> {
    let patch = patch_from_value(patch)?;
    let payload = arkret_sdk::SpacePatchPayload {
        space_id: space_id_value(space_id)?,
        patch,
        expected_state_digest: None,
    };
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::SpaceUpdate>(realm_id, actor, payload)
            .target_ref(space_id),
    )
}
