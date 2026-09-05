//! Presence maps, refresh cadence and watch-level wire shape.

use super::*;

#[test]
fn presence_maps_from_sync_events_prefers_account_subscribe_presence() {
    let now = chrono::Utc::now();
    let sent_at = now - chrono::Duration::seconds(5);
    let expires_at = now + chrono::Duration::seconds(55);
    let participants = vec![
        "ak:did_core:web:alice.example".to_owned(),
        "ak:did_core:web:bob.example".to_owned(),
        "ak:did_core:web:carol.example".to_owned(),
    ];
    let events = vec![
        json!({
            "kind": "ak.presence",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "device_id": "ak:device:bob",
            "sent_at": sent_at,
            "expires_at": expires_at,
            "payload": {
                "state": "online",
                "status_message": "On vacation until May 5",
                "ttl_ms": 60000
            }
        }),
        json!({
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:carol.example","station_id":"ak:did_core:web:principal.example"}},
            // Matrix `unavailable` fails closed to offline.
            "status": "unavailable"
        }),
        json!({
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:mallory.example","station_id":"ak:did_core:web:principal.example"}},
            "state": "online"
        }),
    ];

    let (states, labels, status_messages) = presence_maps_from_sync_events(
        &events,
        &participants,
        "ak:did_core:web:alice.example",
        "Alice",
    )
    .expect("presence events should match participants");

    assert_eq!(
        states.get("ak:did_core:web:alice.example"),
        Some(&"online".to_owned())
    );
    assert_eq!(
        states.get("ak:did_core:web:bob.example"),
        Some(&"online".to_owned())
    );
    assert_eq!(
        states.get("ak:did_core:web:carol.example"),
        Some(&"offline".to_owned())
    );
    assert_eq!(
        labels.get("ak:did_core:web:alice.example"),
        Some(&"Alice".to_owned())
    );
    assert_eq!(
        status_messages.get("ak:did_core:web:bob.example"),
        Some(&"On vacation until May 5".to_owned())
    );
    assert!(!states.contains_key("ak:did_core:web:mallory.example"));
}

#[test]
fn presence_projection_refresh_key_changes_without_a_cursor_advance() {
    let online = vec![json!({
        "kind": "ak.presence",
        "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
        "state": "online",
    })];
    let offline = vec![json!({
        "kind": "ak.presence",
        "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
        "state": "offline",
    })];

    let online_key = presence_projection_refresh_key("realm|participants", "cursor-7", &online);
    assert_eq!(
        online_key,
        presence_projection_refresh_key("realm|participants", "cursor-7", &online)
    );
    assert_ne!(
        online_key,
        presence_projection_refresh_key("realm|participants", "cursor-7", &offline)
    );
}

#[test]
fn presence_retries_once_after_mount_then_uses_the_normal_refresh_cadence() {
    assert_eq!(presence_heartbeat_delay_secs(0), 2);
    assert_eq!(presence_heartbeat_delay_secs(1), 25);
    assert_eq!(presence_heartbeat_delay_secs(u64::MAX), 25);
}

#[test]
fn presence_maps_from_sync_events_aggregates_live_device_envelopes() {
    let now = chrono::Utc::now();
    let participants = vec![
        "ak:did_core:web:alice.example".to_owned(),
        "ak:did_core:web:bob.example".to_owned(),
    ];
    let events = vec![
        json!({
            "kind": "ak.presence",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "device_id": "ak:device:bob-a",
            "sent_at": now - chrono::Duration::seconds(20),
            "expires_at": now + chrono::Duration::seconds(40),
            "payload": {
                "state": "dnd",
                "status_message": "Heads down",
                "ttl_ms": 60000
            }
        }),
        json!({
            "kind": "ak.presence",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "device_id": "ak:device:bob-b",
            "sent_at": now - chrono::Duration::seconds(10),
            "expires_at": now + chrono::Duration::seconds(50),
            "payload": {
                "state": "online",
                "status_message": "Available soon",
                "ttl_ms": 60000
            }
        }),
        json!({
            "kind": "ak.presence",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "device_id": "ak:device:bob-expired",
            "sent_at": now - chrono::Duration::seconds(70),
            "expires_at": now - chrono::Duration::seconds(10),
            "payload": {
                "state": "dnd",
                "status_message": "Expired override",
                "ttl_ms": 60000
            }
        }),
    ];

    let (states, _, status_messages) = presence_maps_from_sync_events(
        &events,
        &participants,
        "ak:did_core:web:alice.example",
        "Alice",
    )
    .expect("live remote presence should match participants");

    assert_eq!(
        states.get("ak:did_core:web:bob.example"),
        Some(&"dnd".to_owned())
    );
    assert_eq!(
        status_messages.get("ak:did_core:web:bob.example"),
        Some(&"Available soon".to_owned())
    );
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

// ── T7.4 crypto state helpers ────────────────────────────────
