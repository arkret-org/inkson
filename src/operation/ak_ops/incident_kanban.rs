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
    // realm-and-space.md §3.6 types both placement references as `id:space`.
    // Reject a holder-local handle here, at the single point that produces the
    // wire bytes, so no call site can sign a fabricated Space reference.
    for (field, value) in [
        ("board_space_id", board_space_id),
        ("list_space_id", list_space_id),
    ] {
        arkret_sdk::SpaceId::new(value).map_err(|error| {
            anyhow::anyhow!("card placement {field} is not a Space id: {error}")
        })?;
    }
    if rank.is_empty() || rank.len() > 128 || !rank.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        anyhow::bail!("card placement rank must match ^[0-9A-Za-z]{{1,128}}$");
    }
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
