//! Discussion channels derived from canonical Strand creation Events.

use super::*;

const CHANNEL_REALM: &str = "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI";

fn canonical_strand_create(tracks: Value, metadata: Value) -> Value {
    canonical_strand_create_in_realm(CHANNEL_REALM, tracks, metadata)
}

fn canonical_strand_create_in_realm(realm_id: &str, tracks: Value, metadata: Value) -> Value {
    let event: arkret_sdk::Event = serde_json::from_value(json!({
        "event_id": arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [0x41;32]),
        "kind":"ak.strand.create", "realm_id":realm_id,
        "scope_ref":{"kind":"realm","realm_id":realm_id},
        "actor_id":{"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:station.example"}},
        "actor_seq":1,"created_at":"2026-09-07T00:00:00.000Z","hlc":"01970e589d21-0000-a13f9c2e",
        "prev_refs":[],"refs":[],"requirements":{"schema":["ak.schema.event_payload.v1"],"features":[],"critical_extensions":[]},
        "payload":{"object":{"schema":"ak.schema.strand.v1","realm_id":realm_id,"tracks":tracks,
            "metadata":metadata,"stage":"draft","created_at":"2026-09-07T00:00:00.000Z",
            "created_by":{"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:station.example"}}
        }},"proofs":[]
    })).unwrap();
    let event = arkret_sdk::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_sdk::canonical::DigestSuite::Sha256,
    )
    .unwrap()
    .into_event();
    serde_json::to_value(event).unwrap()
}

#[test]
fn channel_from_strand_event_derives_identity_and_reads_canonical_metadata() {
    let event = canonical_strand_create(
        json!({"discussion":{"profile":"discussion"}}),
        json!({"title":"Ops discussion","summary":"Operations support","fields":{"category":"support"}}),
    );
    let channel = channel_from_strand_event(CHANNEL_REALM, &event).unwrap();
    let event_id = arkret_sdk::EventId::new(event["event_id"].as_str().unwrap()).unwrap();
    assert_eq!(
        channel.strand_id,
        arkret_sdk::StrandId::from_event_id(&event_id).to_string()
    );
    assert_eq!(channel.name, "Ops discussion");
    assert_eq!(channel.category, "support");
    assert_eq!(channel.topic.as_deref(), Some("Operations support"));
    assert!(!channel.is_private_sidecar);
}

#[test]
fn channel_from_strand_event_accepts_metadata_free_default_creation() {
    let mut event = canonical_strand_create(
        json!({"discussion":{"is_primary":true}}),
        json!({"title":"Default"}),
    );
    event["payload"]["object"]
        .as_object_mut()
        .unwrap()
        .remove("metadata");
    let event = arkret_sdk::AuthoredEvent::finalize_with_digest_suite(
        serde_json::from_value(event).unwrap(),
        arkret_sdk::canonical::DigestSuite::Sha256,
    )
    .unwrap()
    .into_event();
    let channel =
        channel_from_strand_event(CHANNEL_REALM, &serde_json::to_value(event).unwrap()).unwrap();
    assert_eq!(channel.name, channel.strand_id);
    assert_eq!(channel.security_encrypted, None);
}

#[test]
fn channels_from_current_ingest_records_retain_canonical_event_identity() {
    let event: arkret_sdk::Event = serde_json::from_value(canonical_strand_create(
        json!({"discussion": {}}),
        json!({"title": "Synced discussion"}),
    ))
    .unwrap();
    let mut state = ClientLocalState::default();
    state.raw_operations = crate::state::projection::kanban_ops::kanban_operations_from_events(
        std::slice::from_ref(&event),
    );
    assert_eq!(state.raw_operations.len(), 1);
    let channels = channels_from_local_state(&state, CHANNEL_REALM);
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0].name, "Synced discussion");
    assert_eq!(
        channels[0].strand_id,
        arkret_sdk::StrandId::from_event_id(&event.event_id).to_string()
    );

    state.raw_operations[0].payload["local_target_ref"] = json!("obsolete-alias");
    assert_eq!(
        channels_from_local_state(&state, CHANNEL_REALM)[0].strand_id,
        channels[0].strand_id
    );
    state.raw_operations[0].payload["operation_id"] = json!("obsolete-event-id");
    assert!(channels_from_local_state(&state, CHANNEL_REALM).is_empty());
}

#[test]
fn channel_from_strand_event_rejects_legacy_identity_and_wrong_realm() {
    let event = canonical_strand_create(json!({"discussion":{}}), json!({"title":"Discussion"}));
    let mut legacy = event.clone();
    legacy["payload"]["object"]["id"] =
        json!("ak:strand:Ac19GaGmchhLqPeXsofsVdQCPnHo5URGMEFiQj6tRLz0");
    assert!(channel_from_strand_event(CHANNEL_REALM, &legacy).is_none());
    assert!(
        channel_from_strand_event(
            "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI",
            &event
        )
        .is_none()
    );
}

#[test]
fn channel_from_strand_event_never_infers_private_sidecar_identity() {
    let event = canonical_strand_create(
        json!({"discussion":{}}),
        json!({"title":"AI sidecar","fields":{"client_private_hint":true}}),
    );
    assert!(
        !channel_from_strand_event(CHANNEL_REALM, &event)
            .unwrap()
            .is_private_sidecar
    );
}

#[test]
fn channel_from_strand_event_ignores_non_discussion_strands() {
    let event = canonical_strand_create(json!({"synthesis":{}}), json!({"title":"Synthesis"}));
    assert!(channel_from_strand_event(CHANNEL_REALM, &event).is_none());
}

#[test]
fn default_discussion_channel_uses_realm_default_strand_projection() {
    let body = json!({
        "default_strand_id": "ak:strand:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL"
    });

    let channel = default_discussion_channel(Some(&body))
        .expect("accepted projection exposes its default Strand");

    assert_eq!(
        channel.strand_id,
        "ak:strand:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL"
    );
    assert_eq!(channel.name, "Discussion");
    assert_eq!(channel.kind, "discussion");
    assert_eq!(
        channel.topic.as_deref(),
        Some("Default Strand discussion track")
    );
    assert!(channel.is_default);
}

#[test]
fn default_discussion_channel_fails_closed_when_projection_is_absent() {
    assert!(default_discussion_channel(None).is_none());
}

#[test]
fn default_discussion_channel_rejects_obsolete_summary_strand() {
    let body = json!({"summary":{"strand":{
        "strand_id":"ak:strand:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL",
        "tracks":{"discussion":{}}
    }}});
    assert!(default_discussion_channel(Some(&body)).is_none());
}

#[test]
fn channel_restore_and_sync_are_isolated_to_the_selected_realm() {
    let other_realm = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI";
    let selected = canonical_strand_create(json!({"discussion": {}}), json!({"title": "Selected"}));
    let other = canonical_strand_create_in_realm(
        other_realm,
        json!({"discussion": {}}),
        json!({"title": "Other"}),
    );
    let events = [other.clone(), selected.clone()]
        .into_iter()
        .map(|event| serde_json::from_value(event).unwrap())
        .collect::<Vec<arkret_sdk::Event>>();
    let mut state = ClientLocalState::default();
    state.raw_operations =
        crate::state::projection::kanban_ops::kanban_operations_from_events(&events);
    let realms = std::collections::BTreeMap::from([
        (
            CHANNEL_REALM.to_owned(),
            json!({"timeline": {"events": [selected]}}),
        ),
        (
            other_realm.to_owned(),
            json!({"timeline": {"events": [other]}}),
        ),
    ]);
    for (realm_id, title) in [(CHANNEL_REALM, "Selected"), (other_realm, "Other")] {
        for channels in [
            channels_from_local_state(&state, realm_id),
            channels_from_sync_realms(&realms, realm_id),
        ] {
            assert_eq!(channels.len(), 1);
            assert_eq!(channels[0].name, title);
        }
    }
    assert!(channels_from_local_state(&state, "").is_empty());
    assert!(channels_from_sync_realms(&realms, "").is_empty());
}
