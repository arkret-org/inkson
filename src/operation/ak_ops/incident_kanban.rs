//! Kanban card Strand builders.

use serde_json::json;

use super::{TypedOperationBuilder, realm_id_value, strand_create_payload, trim_realm_id};

/// Build a `ak.strand.create` for a Kanban card Strand and include the
/// initial Board/List position component used by board projections.
///
/// No Strand id is taken: `ak.strand.create` is `id_source: event_derived`, so
/// the card is named `retype(create.event_id)` and [`TypedOperationBuilder`] stamps
/// that id as `unsigned.local_target_ref` once the envelope exists.
pub fn kanban_card_strand_create(
    realm_id: &str,
    actor: &str,
    board_space_id: &str,
    list_space_id: &str,
    title: &str,
    rank: &str,
) -> anyhow::Result<TypedOperationBuilder> {
    let realm_id = trim_realm_id(realm_id);
    let object = arkret_sdk::StrandCreateObject::new(
        realm_id_value(&realm_id)?,
        crate::mls_api_helpers::local_account_actor_id(actor)?,
    )
    .with_metadata_title(title)
    .with_metadata_field("strand_kind", json!("card"))
    .with_metadata_field("board_space_id", json!(board_space_id))
    .with_metadata_field("list_space_id", json!(list_space_id))
    .with_metadata_field("rank", json!(rank))
    .with_track(
        "synthesis",
        arkret_sdk::StrandTrack::new()
            .primary()
            .with_profile("kanban_card"),
    )
    .with_track("discussion", arkret_sdk::StrandTrack::discussion());
    Ok(TypedOperationBuilder::new::<
        arkret_sdk::event_spec::StrandCreate,
    >(&realm_id, actor, strand_create_payload(object)?))
}
