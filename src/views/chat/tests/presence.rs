//! Exact Signal identity, expiry, aggregation, and refresh regression checks.
use super::*;

fn presence_actor(name: &str, station: &str) -> arkret_sdk::ActorId {
    serde_json::from_value(json!({"kind":"account","account_id":{
        "principal_id":format!("ak:did_core:web:{name}"),
        "station_id":format!("ak:did_core:web:{station}")
    }}))
    .unwrap()
}

fn presence_body(actor: &arkret_sdk::ActorId, state: &str, age: i64) -> Value {
    let now = chrono::Utc::now();
    json!({"kind":"ak.presence","actor_id":actor,"state":state,
        "sent_at":now - chrono::Duration::seconds(age),
        "expires_at":now + chrono::Duration::seconds(60-age)})
}

#[test]
fn presence_roster_keeps_station_identity_through_projection_and_render_lookup() {
    let me = presence_actor("self.example", "station.example");
    let bob = presence_actor("bob.example", "station.example");
    let foreign = presence_actor("bob.example", "other.example");
    let mut roster = Vec::new();
    for actor in [&me, &bob, &foreign] {
        upsert_participant(
            &mut roster,
            actor,
            SpaceParticipantRole::Member,
            me.signing_principal_id().as_str(),
            None,
            None,
        );
    }
    let ids = presence_participant_ids(&roster);
    assert_eq!(ids.len(), 3);
    let (states, ..) = presence_maps_from_sync_events(
        &[presence_body(&bob, "online", 0)],
        &ids,
        &me.to_string(),
        "Me",
    )
    .unwrap();
    for participant in roster {
        let expected = if participant.actor_id.as_ref() == Some(&foreign) {
            "offline"
        } else {
            "online"
        };
        assert_eq!(
            states.get(&participant.roster_key()).map(String::as_str),
            Some(expected)
        );
    }
}

#[test]
fn presence_and_typing_require_the_canonical_actor_projection() {
    let alice = presence_actor("alice.example", "station.example");
    let other_station = presence_actor("alice.example", "other.example");
    let strand = "ak:strand:AI5OKPo7cL4WAh-kQD_G9aUudPNU0xGaEiCVn1F1nFGA";
    let mut body = presence_body(&alice, "online", 0);
    body["kind"] = json!("ak.typing");
    body["typing"] = json!(true);
    body["strand_id"] = json!(strand);
    assert_eq!(sync_presence_actor(&body), Some(alice.to_string()));
    assert_eq!(
        typing_actor_snapshot_from_signals(&[body.clone()], strand, &other_station.to_string())
            .actors,
        vec![alice.to_string()]
    );
    assert!(
        typing_actor_snapshot_from_signals(&[body.clone()], strand, &alice.to_string())
            .actors
            .is_empty()
    );
    body["actor_id"] = json!(alice.signing_principal_id());
    assert!(sync_presence_actor(&body).is_none());
    assert!(
        typing_actor_snapshot_from_signals(&[body], strand, &other_station.to_string())
            .actors
            .is_empty()
    );
    assert!(sync_presence_actor(&json!({"user_id":alice})).is_none());
    assert!(sync_presence_actor(&json!({"actor":alice})).is_none());
}

#[test]
fn presence_isolated_between_accounts_with_the_same_principal_at_different_stations() {
    let me = presence_actor("self.example", "station.example");
    let bob = presence_actor("bob.example", "station.example");
    let foreign_bob = presence_actor("bob.example", "other.example");
    let participants = vec![me.to_string(), bob.to_string(), foreign_bob.to_string()];
    let (states, labels, _) = presence_maps_from_sync_events(
        &[presence_body(&bob, "online", 0)],
        &participants,
        &me.to_string(),
        "Me",
    )
    .unwrap();
    assert_eq!(states[&me.to_string()], "online");
    assert_eq!(states[&bob.to_string()], "online");
    assert_eq!(states[&foreign_bob.to_string()], "offline");
    assert_eq!(labels[&me.to_string()], "Me");
    assert!(
        presence_maps_from_sync_events(
            &[presence_body(&foreign_bob, "online", 0)],
            &[me.to_string(), bob.to_string()],
            &me.to_string(),
            "Me"
        )
        .is_none()
    );
}

#[test]
fn presence_maps_from_sync_events_aggregates_live_device_envelopes() {
    let alice = presence_actor("alice.example", "station.example");
    let bob = presence_actor("bob.example", "station.example");
    let mut busy = presence_body(&bob, "dnd", 20);
    busy["device_id"] = json!("device-a");
    busy["status_message"] = json!("Heads down");
    let mut online = presence_body(&bob, "online", 10);
    online["device_id"] = json!("device-b");
    online["status_message"] = json!("Available soon");
    let mut expired = presence_body(&bob, "dnd", 70);
    expired["status_message"] = json!("Expired override");
    let (states, _, messages) = presence_maps_from_sync_events(
        &[busy, online, expired],
        &[alice.to_string(), bob.to_string()],
        &alice.to_string(),
        "Alice",
    )
    .unwrap();
    assert_eq!(states[&bob.to_string()], "dnd");
    assert_eq!(messages[&bob.to_string()], "Available soon");
}

#[test]
fn presence_rejects_expired_missing_expiry_and_legacy_projection_fields() {
    let alice = presence_actor("alice.example", "station.example");
    let bob = presence_actor("bob.example", "station.example");
    let participants = vec![alice.to_string(), bob.to_string()];
    let valid = presence_body(&bob, "online", 0);
    let mut cases = vec![presence_body(&bob, "online", 61)];
    for field in ["expires_at", "kind"] {
        let mut invalid = valid.clone();
        invalid.as_object_mut().unwrap().remove(field);
        cases.push(invalid);
    }
    for alias in ["status", "presence"] {
        let mut invalid = valid.clone();
        invalid.as_object_mut().unwrap().remove("state");
        invalid[alias] = json!("online");
        cases.push(invalid);
    }
    let mut nested = valid.clone();
    nested.as_object_mut().unwrap().remove("state");
    nested["payload"] = json!({"state":"online"});
    cases.push(nested);
    cases.push(presence_body(&bob, "unavailable", 0));
    for body in cases {
        assert!(
            presence_maps_from_sync_events(&[body], &participants, &alice.to_string(), "Alice")
                .is_none()
        );
    }
}

#[test]
fn presence_projection_refresh_key_changes_without_a_cursor_advance() {
    let bob = presence_actor("bob.example", "station.example");
    let online = vec![presence_body(&bob, "online", 0)];
    let mut offline = online.clone();
    offline[0]["state"] = json!("offline");
    let key = presence_projection_refresh_key("realm", "cursor-7", &online);
    assert_eq!(
        key,
        presence_projection_refresh_key("realm", "cursor-7", &online)
    );
    assert_ne!(
        key,
        presence_projection_refresh_key("realm", "cursor-7", &offline)
    );
}

#[test]
fn presence_retries_once_after_mount_then_uses_the_normal_refresh_cadence() {
    assert_eq!(presence_heartbeat_delay_secs(0), 2);
    assert_eq!(presence_heartbeat_delay_secs(1), 25);
    assert_eq!(presence_heartbeat_delay_secs(u64::MAX), 25);
}

#[test]
fn watch_level_wire_round_trip() {
    for level in [
        WatchLevel::MentionsOnly,
        WatchLevel::Participating,
        WatchLevel::All,
        WatchLevel::Muted,
    ] {
        assert_eq!(watch_level_from_wire(watch_level_wire_value(level)), level);
    }
    assert_eq!(watch_level_from_wire("none"), WatchLevel::Muted);
}
