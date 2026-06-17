//! Incident-response and Kanban card Strand builders.

use serde_json::json;

use super::{
    OperationBuilder, did_id, object_create_payload_value, realm_id_value, strand_id_value,
    strand_update_patch, trim_realm_id,
};

/// Build a `ck.strand.create` for an incident response Strand. The
/// common incident workflow status is carried in `fields.status` so
/// soland can enforce the profile FSM and emit
/// `incident.status.transition` audit rows on subsequent updates.
pub fn incident_strand_create(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    title: &str,
    status: &str,
    priority: &str,
) -> anyhow::Result<OperationBuilder> {
    let realm_id = trim_realm_id(realm_id);
    let object = cokret_sdk::StrandCreateObject::new(
        strand_id_value(strand_id)?,
        realm_id_value(&realm_id)?,
        did_id(actor)?,
    )
    .with_metadata_title(title)
    .with_metadata_field("strand_kind", json!("incident"))
    .with_metadata_field("status", json!(status))
    .with_metadata_field("incident_priority", json!(priority))
    .with_track(
        "synthesis",
        cokret_sdk::StrandTrackConfig::new()
            .primary()
            .with_profile("incident_response"),
    )
    .with_track(
        "discussion",
        cokret_sdk::StrandTrackConfig::new().with_profile("war_room"),
    );
    Ok(OperationBuilder::new(&realm_id, actor, "ck.strand.create")
        .target_ref(strand_id)
        .body(object_create_payload_value(
            object,
            "ck.strand.create incident payload serialize",
        )?))
}

/// Build a `ck.strand.update` for the incident `fields.status` FSM.
pub fn incident_status_update(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    status: &str,
) -> anyhow::Result<OperationBuilder> {
    strand_update_patch(
        realm_id,
        actor,
        strand_id,
        json!({ "fields": { "$op": "set", "value": { "status": status } } }),
    )
}

/// Build a `ck.strand.create` for a Kanban card Strand and include the
/// initial Board/List position component used by board projections.
pub fn kanban_card_strand_create(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    board_space_id: &str,
    list_space_id: &str,
    title: &str,
    rank: &str,
) -> anyhow::Result<OperationBuilder> {
    let realm_id = trim_realm_id(realm_id);
    let object = cokret_sdk::StrandCreateObject::new(
        strand_id_value(strand_id)?,
        realm_id_value(&realm_id)?,
        did_id(actor)?,
    )
    .with_metadata_title(title)
    .with_metadata_field("strand_kind", json!("card"))
    .with_metadata_field("board_space_id", json!(board_space_id))
    .with_metadata_field("list_space_id", json!(list_space_id))
    .with_metadata_field("rank", json!(rank))
    .with_track(
        "synthesis",
        cokret_sdk::StrandTrackConfig::new()
            .primary()
            .with_profile("kanban_card"),
    );
    Ok(OperationBuilder::new(&realm_id, actor, "ck.strand.create")
        .target_ref(strand_id)
        .body(object_create_payload_value(
            object,
            "ck.strand.create kanban card payload serialize",
        )?))
}
