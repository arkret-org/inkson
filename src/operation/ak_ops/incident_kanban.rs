//! Kanban card Strand builders.

use serde_json::json;

use super::{
    OperationBuilder, did_id, object_create_payload_value, realm_id_value, strand_id_value,
    trim_realm_id,
};

/// Build a `ak.strand.create` for a Kanban card Strand and include the
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
    let object = arkret_sdk::StrandCreateObject::new(
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
        arkret_sdk::StrandTrackConfig::new()
            .primary()
            .with_profile("kanban_card"),
    )
    .with_track("discussion", arkret_sdk::StrandTrackConfig::discussion());
    Ok(OperationBuilder::new(
        &realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::StrandCreate,
    )
    .target_ref(strand_id)
    .body(object_create_payload_value(
        object,
        "ak.strand.create kanban card payload serialize",
    )?))
}
