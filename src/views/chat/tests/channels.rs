//! Discussion channels read the Station's deterministic current Strand value.
use super::*;
use crate::current_projection::RealmCurrentView;

const CHANNEL_REALM: &str = "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI";

fn current_strand(
    realm: &str,
    title: &str,
    alternate_revision: bool,
) -> arkret_wire::TypedCurrentRow {
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
    arkret_wire::TypedCurrentRow::Value {
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

fn view(realm: &str, entries: Vec<arkret_wire::TypedCurrentRow>) -> RealmCurrentView {
    RealmCurrentView::new(realm, entries, true).unwrap()
}

fn channel_from_current(current: arkret_wire::TypedCurrentRow) -> ChannelEntity {
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

#[test]
fn late_verified_circle_current_adds_channel_after_initial_empty_view() {
    let circle_event =
        arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [0x43; 32]);
    let circle_id = arkret_sdk::CircleId::from_event_id(&circle_event);
    let mut current = current_strand(CHANNEL_REALM, "Circle poll", false);
    let arkret_wire::TypedCurrentRow::Value {
        source_stream_ref,
        value,
        ..
    } = &mut current;
    *source_stream_ref = arkret_wire::CommitStreamRef::Circle {
        realm_id: arkret_sdk::RealmId::new(CHANNEL_REALM).unwrap(),
        circle_id: circle_id.clone(),
    };
    value["scope_circle_id"] = json!(circle_id);
    let mut channels = channels_from_current_view(None, CHANNEL_REALM);
    assert!(channels.is_empty());
    merge_channels(
        &mut channels,
        channels_from_current_view(Some(&view(CHANNEL_REALM, vec![current])), CHANNEL_REALM),
    );
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0].name, "Circle poll");
    assert_eq!(
        channels[0]
            .scope_circle
            .as_ref()
            .map(|scope| scope.circle_id.as_str()),
        Some(circle_id.as_str()),
    );
}

#[test]
fn hidden_synthesis_discussion_keeps_its_exact_circle_scope() {
    let circle_event =
        arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [0x53; 32]);
    let circle_id = arkret_sdk::CircleId::from_event_id(&circle_event);
    let mut current = current_strand(CHANNEL_REALM, "Private synthesis card", false);
    let arkret_wire::TypedCurrentRow::Value {
        source_stream_ref,
        value,
        ..
    } = &mut current;
    *source_stream_ref = arkret_sdk::CommitStreamRef::Circle {
        realm_id: arkret_sdk::RealmId::new(CHANNEL_REALM).unwrap(),
        circle_id: circle_id.clone(),
    };
    let mut strand: arkret_sdk::Strand = serde_json::from_value(value.clone()).unwrap();
    strand.scope_circle_id = Some(circle_id.clone());
    strand
        .tracks
        .insert("synthesis".to_owned(), arkret_sdk::StrandTrack::synthesis());
    *value = serde_json::to_value(strand).unwrap();
    let card = channel_from_current(current);
    assert_eq!(card.kind, "strand");
    let fallback_event =
        arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [0x54; 32]);
    let fallback_strand = arkret_sdk::StrandId::from_event_id(&fallback_event);
    let fallback = discussion_channel_for_strand(fallback_strand.as_str()).unwrap();
    let channels = vec![fallback.clone(), card.clone()];
    for filter in ["discussion_only", "with_discussion_track"] {
        let (visible, selected) =
            discussion_channels_for_surface(&channels, &card.strand_id, filter);
        assert_eq!(
            visible.len(),
            if filter == "discussion_only" { 1 } else { 2 }
        );
        let selected = selected.unwrap();
        assert_eq!(selected, card);
        assert_eq!(
            selected.effective_scope(CHANNEL_REALM),
            Some(arkret_sdk::ScopeRef::Circle {
                realm_id: arkret_sdk::RealmId::new(CHANNEL_REALM).unwrap(),
                circle_id: circle_id.clone(),
            }),
        );
    }
    let missing = arkret_sdk::StrandId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::canonical::DigestSuite::Sha256,
        [0x55; 32],
    ));
    let (visible, selected) =
        discussion_channels_for_surface(&channels, missing.as_str(), "discussion_only");
    assert_eq!(visible, vec![fallback]);
    assert!(
        selected.is_none(),
        "unknown targets cannot inherit another Strand's scope"
    );
}
