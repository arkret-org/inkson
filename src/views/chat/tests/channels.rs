//! Discussion channels read the Station's deterministic current Strand value.
use super::*;
use crate::current_projection::RealmCurrentView;

const CHANNEL_REALM: &str = "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI";

fn current_strand(
    realm: &str,
    title: &str,
    alternate_revision: bool,
) -> arkret_wire::TypedCurrentResult {
    let event_id =
        arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [0x41; 32]);
    let strand_id = arkret_sdk::StrandId::from_event_id(&event_id);
    let mut strand = arkret_sdk::Strand::discussion(
        strand_id.clone(),
        arkret_sdk::RealmId::new(realm).unwrap(),
        title,
        crate::mls_api_helpers::local_account_actor_id("did:web:alice.example").unwrap(),
    );
    let metadata = strand.metadata.as_mut().unwrap();
    metadata.summary = Some("Operations support".to_owned());
    metadata
        .fields
        .insert("category".to_owned(), json!("support"));

    let revision_seed = if alternate_revision { 2 } else { 1 };
    arkret_wire::TypedCurrentResult::Value {
        selector: arkret_wire::CurrentSelector::Strand { strand_id },
        source_stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: arkret_sdk::RealmId::new(realm).unwrap(),
        },
        revision: arkret_wire::CurrentRevision {
            commit_id: arkret_sdk::RealmCommitId::from_digest([revision_seed; 32]),
            stream_position: 7,
        },
        value: serde_json::to_value(strand).unwrap(),
    }
}

fn view(realm: &str, entries: Vec<arkret_wire::TypedCurrentResult>) -> RealmCurrentView {
    RealmCurrentView::new(realm, entries, true).unwrap()
}

fn channel_from_current(current: arkret_wire::TypedCurrentResult) -> ChannelEntity {
    channels_from_current_view(Some(&view(CHANNEL_REALM, vec![current])), CHANNEL_REALM)
        .into_iter()
        .next()
        .unwrap()
}

#[test]
fn channel_reads_complete_current_metadata() {
    let channel = channel_from_current(current_strand(CHANNEL_REALM, "Ops discussion", false));
    assert_eq!(channel.name, "Ops discussion");
    assert_eq!(channel.category, "support");
    assert_eq!(channel.topic.as_deref(), Some("Operations support"));
    assert!(!channel.is_private_sidecar);
}

#[test]
fn deterministic_current_value_is_displayable() {
    let channel = channel_from_current(current_strand(CHANNEL_REALM, "Converged", true));
    assert_eq!(channel.name, "Converged");
}

#[test]
fn channel_restore_is_isolated_to_selected_realm() {
    let other = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI";
    for (realm, title) in [(CHANNEL_REALM, "Selected"), (other, "Other")] {
        let installed = view(realm, vec![current_strand(realm, title, false)]);
        let channels = channels_from_current_view(Some(&installed), realm);
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0].name, title);
        // The view of one Realm never answers for another.
        let foreign = if realm == other { CHANNEL_REALM } else { other };
        assert!(channels_from_current_view(Some(&installed), foreign).is_empty());
    }
    assert!(channels_from_current_view(None, CHANNEL_REALM).is_empty());
}
