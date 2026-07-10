//! Container Space (Board / List) builders.

use super::{
    OperationBuilder, did_id, object_create_payload_value, patch_from_value, realm_id_value,
    space_id_value, space_patch_payload_value, space_state_transition_payload_value, trim_realm_id,
};

/// Build a `ak.space.create` operation for Board/List container Spaces.
///
/// Board/List containers are Space objects and the security boundary is
/// Realm. The optional
/// `parent_space_id` + `rank` fields carry the board/list structural
/// placement while the object id and event kind stay canonical.
pub fn space_create(
    realm_id: &str,
    actor: &str,
    container_space_id: &str,
    kind: &str,
    title: &str,
    parent_space_id: Option<&str>,
    rank: Option<&str>,
) -> anyhow::Result<OperationBuilder> {
    let mut object = arkret_sdk::SpaceCreateObject::new(
        space_id_value(container_space_id)?,
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
    let body = object_create_payload_value(object, "ak.space.create payload serialize")?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::SpaceCreate,
    )
    .target_ref(container_space_id)
    .body(body))
}

/// Build a `ak.space.restore` operation. Reverses `realm_archive`
/// (`archived -> active`). The SDK reducer enforces `state == archived`
/// at apply time; tombstoned container Spaces MUST NOT be restored. Spec:
/// `models/realm-and-space.md` §4.4, `common-fields.md §5`.
pub fn space_restore(
    realm_id: &str,
    actor: &str,
    container_space_id: &str,
) -> anyhow::Result<OperationBuilder> {
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::SpaceRestore,
    )
    .target_ref(container_space_id)
    .body(space_state_transition_payload_value(
        container_space_id,
        arkret_sdk::ObjectState::Active,
    )?))
}

/// Build a `ak.space.update` patch operation for structural Space
/// metadata (`title`, `summary`, `rank`, `fields`, ...). The event lives
/// in the Space's home Realm; `space_id` stays as the object target.
pub fn space_update_patch(
    realm_id: &str,
    actor: &str,
    space_id: &str,
    patch: serde_json::Value,
) -> anyhow::Result<OperationBuilder> {
    let patch = patch_from_value(patch)?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::SpaceUpdate,
    )
    .target_ref(space_id)
    .body(space_patch_payload_value(space_id, patch)?))
}
