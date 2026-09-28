//! Kanban card Strand builders.

use serde_json::json;

use super::{TypedOperationBuilder, realm_id_value, strand_create_operation, trim_realm_id};

/// Build a `ak.strand.create` for a Kanban card Strand.
///
/// No Strand id is taken: `ak.strand.create` is `id_source: event_derived`, so
/// the card is named `retype(create.event_id)` and [`TypedOperationBuilder`] stamps
/// that id as `unsigned.local_target_ref` once the envelope exists.
pub fn kanban_card_strand_create(
    realm_id: &str,
    actor: &str,
    title: &str,
) -> anyhow::Result<TypedOperationBuilder> {
    let realm_id = trim_realm_id(realm_id);
    let object = arkret_sdk::StrandCreateObject::new(
        realm_id_value(&realm_id)?,
        crate::mls_api_helpers::local_account_actor_id(actor)?,
    )
    .with_metadata_title(title)
    .with_metadata_field("strand_kind", json!("card"))
    .with_track(
        "synthesis",
        arkret_sdk::StrandTrack::new()
            .primary()
            .with_profile("kanban_card"),
    )
    .with_track("discussion", arkret_sdk::StrandTrack::discussion());
    strand_create_operation(&realm_id, actor, object)
}
