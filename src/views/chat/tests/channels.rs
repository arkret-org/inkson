//! Discussion channels read complete Station current Strand heads.
use super::*;

const CHANNEL_REALM: &str = "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI";

fn current_strand(realm: &str, title: &str, concurrent: bool) -> arkret_sdk::CurrentResultEntry {
    let event_id =
        arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [0x41; 32]);
    let strand_id = arkret_sdk::StrandId::from_event_id(&event_id);
    let object = json!({
        "schema":"ak.schema.strand.v1", "id":strand_id,"realm_id":realm,
        "tracks":{"discussion":{}},"metadata":{"title":title,"summary":"Operations support","fields":{"category":"support"}},
        "created_at":"2026-09-07T00:00:00.000Z",
        "created_by":{"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:station.example"}}
    });
    let mut heads = vec![json!({"event_id":event_id,"value":object})];
    if concurrent {
        heads.push(json!({"event_id":arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256,[0x42;32]),"value":object}));
    }
    serde_json::from_value(json!({
        "selector":{"scope_ref":{"kind":"realm","realm_id":realm},
            "cell_id":format!("ak:cell:ak.component.strand.object.v1:{strand_id}")},
        "target":{"kind":"strand","strand_id":strand_id},
        "revision":7,"result":{"status":"heads","heads":heads}
    }))
    .unwrap()
}

#[test]
fn channel_reads_complete_current_metadata() {
    let current = current_strand(CHANNEL_REALM, "Ops discussion", false);
    let channel = channel_from_current_strand(CHANNEL_REALM, &current).unwrap();
    assert_eq!(channel.name, "Ops discussion");
    assert_eq!(channel.category, "support");
    assert_eq!(channel.topic.as_deref(), Some("Operations support"));
    assert!(!channel.is_private_sidecar);
}

#[test]
fn concurrent_heads_are_not_collapsed_to_an_arbitrary_channel() {
    let current = current_strand(CHANNEL_REALM, "Conflicting", true);
    assert!(channel_from_current_strand(CHANNEL_REALM, &current).is_none());
    let arkret_sdk::CurrentOutcome::Heads { heads } = current.result() else {
        panic!("heads")
    };
    assert_eq!(heads.len(), 2);
}

#[test]
fn channel_restore_is_isolated_to_selected_realm() {
    let other = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI";
    let mut state = ClientLocalState::default();
    for (realm, title) in [(CHANNEL_REALM, "Selected"), (other, "Other")] {
        state.realm_tree_projections.insert(
            realm.to_owned(),
            json!({
                "current":{"entries":[current_strand(realm,title,false)]}
            }),
        );
    }
    for (realm, title) in [(CHANNEL_REALM, "Selected"), (other, "Other")] {
        let channels = channels_from_local_state(&state, realm);
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0].name, title);
    }
    assert!(channels_from_local_state(&state, "").is_empty());
}
