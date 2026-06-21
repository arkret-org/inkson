use super::super::*;

#[test]
fn parses_server_and_sync_payloads() {
    let description = parse_server_description(json!({
        "service_did": "did:web:server.local",
        "trust_domain": "ck:trust_domain:server.local",
        "service_type": "principal_server",
        "protocol_version": "1.0",
        "supported_profiles": [],
        "supported_features": ["account.subscribe"],
        "supported_operations": ["ck.self.account.stream.subscribe"],
        "supported_bindings": [{"kind": "http_json"}],
        "auth_metadata": {},
        "limits": {"storage": "memory"},
        "plaintext_visibility": {"default": "encrypted"},
        "implemented_features": [],
        "claimed_profiles": [],
        "verified_profiles": [],
        "experimental_features": [],
        "compat_surfaces": [],
        "development_mode": true,
    }))
    .unwrap();
    assert_eq!(description.protocol_version, "1.0");

    let sync = parse_sync(json!({
        "cursor": "ck:cursor:test-1",
        "realms": {
            "ck:realm:0196419b-0000-7000-8000-000000000000": {"summary": {}}
        },
        "to_device": [],
        "account_data": [],
        "device_lists": {"changed": [], "left": []}
    }))
    .unwrap();
    assert_eq!(sync.realms.len(), 1);
    assert_eq!(sync.cursor, "ck:cursor:test-1");

    // Spec-aligned wire shape per `client-sync.md §2`: flat
    // `realms` keyed by realm id, explicit `left_realms`,
    // flat arrays for top-level streams. The SDK's canonical account
    // subscribe snapshot shape.
    let sync_v1 = parse_sync(json!({
        "cursor": "ck:cursor:v1",
        "realms": {
            "ck:realm:joined": {
                "summary": {"title": "Joined"}
            }
        },
        "left_realms": ["ck:realm:left"],
        "to_device": [{"type": "ck.mls.welcome"}],
        "account_data": [{"data_type": "client.ui", "content": {"theme": "system"}}],
        "device_lists": {"changed": [], "left": []},
        "notifications": {"events": []},
        "presence": []
    }))
    .unwrap();
    assert_eq!(sync_v1.cursor, "ck:cursor:v1");
    assert!(sync_v1.realms.contains_key("ck:realm:joined"));
    assert_eq!(sync_v1.left_realms, vec!["ck:realm:left".to_owned()]);
    assert_eq!(sync_v1.to_device.len(), 1);
    assert_eq!(sync_v1.account_data.len(), 1);
    assert!(sync_v1.notifications.is_object());
    assert!(sync_v1.presence.is_empty());

    let account_frame = parse_account_subscribe_snapshot(
        br#"{"kind":"delta","cursor":"ck:cursor:account-1","realms":{"ck:realm:019e4cdc-b435-7e52-9ada-39d5ec134729":{"summary":{"title":"Test"}}},"to_device":{"messages":[]},"device_lists":{"changed":[],"left":[]},"account_data":{"events":[]},"presence":{"events":[]},"notifications":null,"partial":false}
{"kind":"catchup_complete","cursor":"ck:cursor:account-1"}
"#,
    )
    .unwrap();
    assert_eq!(account_frame.cursor, "ck:cursor:account-1");
    assert!(
        account_frame
            .realms
            .contains_key("ck:realm:019e4cdc-b435-7e52-9ada-39d5ec134729")
    );
    assert!(account_frame.left_realms.is_empty());

    let reconnect = parse_account_subscribe_snapshot_outcome(
        br#"{"kind":"resync_required","reason":"compaction","reconnect_after_ms":10000}
"#,
    )
    .unwrap();
    match reconnect {
        AccountSubscribeSnapshotResult::ReconnectAfter {
            reconnect_after_ms,
            reason,
            reset_cursor,
        } => {
            assert_eq!(reconnect_after_ms, 10_000);
            assert_eq!(reason.as_deref(), Some("compaction"));
            assert!(reset_cursor);
        }
        other => panic!("expected reconnect outcome, got {other:?}"),
    }

    let directory = parse_directory_describe(json!({
        "service_did": "did:web:server.local",
        "trust_domain": "ck:trust_domain:server.local",
        "service_type": "directory_service",
        "protocol_version": "1.0",
        "supported_profiles": ["ck.profile.directory_service.v1"],
        "supported_operations": ["ck.find.directory.query.describe"],
        "supported_bindings": [{"kind": "http_json"}],
        "supported_features": [],
        "auth_metadata": {"mode": "public_no_auth"},
        "limits": {},
        "plaintext_visibility": {},
        "rate_limit_policy": {},
        "implemented_features": [],
        "claimed_profiles": [],
        "verified_profiles": [],
        "experimental_features": [],
        "compat_surfaces": [],
        "development_mode": false,
        "resource_types": ["realm", "organization", "actor"],
        "discovery_profiles": ["ck.profile.directory_service.v1"],
        "restricted_query_proof": false,
        "ingest_modes": ["push"],
        "accept_policy_kind": "open",
        "default_ttl_seconds": 86400,
        "max_ttl_seconds": 604800,
        "revalidation_grace_seconds": 3600,
        "accepted_resource_kinds": ["realm", "organization", "actor"],
        "accepted_did_methods": ["did:web"],
        "rate_limits": {}
    }))
    .unwrap();
    assert!(
        directory
            .resource_types
            .contains(&cokret_sdk::models::DirectoryResourceKind::Realm)
    );

    let directory = parse_directory_describe(json!({
        "service_did": "did:web:server.local",
        "trust_domain": "ck:trust_domain:server.local",
        "service_type": "directory_service",
        "protocol_version": "1.0",
        "supported_profiles": ["ck.profile.directory_service.v1"],
        "supported_operations": ["ck.find.directory.query.describe"],
        "supported_bindings": [{"kind": "http_json"}],
        "supported_features": [],
        "auth_metadata": {"mode": "public_no_auth"},
        "limits": {},
        "plaintext_visibility": {},
        "rate_limit_policy": {},
        "implemented_features": [],
        "claimed_profiles": [],
        "verified_profiles": [],
        "experimental_features": [],
        "compat_surfaces": [],
        "development_mode": false,
        "resource_types": ["realm"],
        "discovery_profiles": ["ck.profile.directory_service.v1"],
        "ingest_modes": ["push"],
        "accept_policy_kind": "open",
        "default_ttl_seconds": 86400,
        "max_ttl_seconds": 604800,
        "revalidation_grace_seconds": 3600,
        "accepted_resource_kinds": ["realm"],
        "accepted_did_methods": ["did:web"],
        "rate_limits": {}
    }))
    .unwrap();
    assert_eq!(directory.restricted_query_proof, None);
}

#[test]
fn account_subscribe_fold_consumes_every_catchup_frame() {
    // YOU-01-010 — multi-frame catchup: both deltas must be folded
    // (timeline events appended) and the cursor must advance to the
    // LAST cursor-bearing frame (the catchup_complete), not stop at
    // the first delta.
    let folded = parse_account_subscribe_snapshot(
        br#"{"kind":"delta","cursor":"ck:cursor:1","realms":{"ck:realm:a":{"timeline":{"events":[{"event_id":"ck:event:1"}]}}}}
{"kind":"delta","cursor":"ck:cursor:2","realms":{"ck:realm:a":{"timeline":{"events":[{"event_id":"ck:event:2"}]}},"ck:realm:b":{"summary":{"title":"B"}}}}
{"kind":"catchup_complete","cursor":"ck:cursor:3"}
"#,
    )
    .unwrap();
    assert_eq!(folded.cursor, "ck:cursor:3");
    assert!(folded.realms.contains_key("ck:realm:b"));
    let events = folded.realms["ck:realm:a"]["timeline"]["events"]
        .as_array()
        .expect("merged timeline events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["event_id"], "ck:event:1");
    assert_eq!(events[1]["event_id"], "ck:event:2");
}

#[test]
fn parses_events_subscribe_ndjson_frames() {
    // Round 4 typed frames carry the discriminator-required fields:
    // `heartbeat` requires `emitted_at`; `frontier` requires a nested
    // `frontier` value; `catchup_complete` is a unit variant.
    let frames = parse_events_subscribe_ndjson_text(
        r#"
{"kind":"heartbeat","emitted_at":"2026-05-20T00:00:00Z"}
{"kind":"frontier","frontier":{"ck:realm:demo":["ck:event:01"]}}
{"kind":"catchup_complete"}
"#,
    )
    .unwrap();

    assert!(matches!(
        frames[0],
        cokret_sdk::EventsSubscribeFrameBody::Heartbeat { .. }
    ));
    assert!(matches!(
        &frames[1],
        cokret_sdk::EventsSubscribeFrameBody::Frontier { .. }
    ));
    assert!(matches!(
        &frames[2],
        cokret_sdk::EventsSubscribeFrameBody::CatchupComplete
    ));
}

#[test]
fn drains_split_events_subscribe_ndjson_chunks() {
    let mut pending = br#"{"kind":"heartbeat","emitted_at":"2026-05-20T00:00:00Z"}
{"kind":"resync_required""#
        .to_vec();
    let mut frames = Vec::new();
    drain_events_subscribe_ndjson_lines(&mut pending, &mut |frame| {
        frames.push(frame);
        Ok(())
    })
    .unwrap();
    assert_eq!(frames.len(), 1);
    assert!(matches!(
        frames[0],
        cokret_sdk::EventsSubscribeFrameBody::Heartbeat { .. }
    ));

    pending.extend_from_slice(
        br#","reason":"server restart"}
"#,
    );
    drain_events_subscribe_ndjson_lines(&mut pending, &mut |frame| {
        frames.push(frame);
        Ok(())
    })
    .unwrap();

    assert!(pending.is_empty());
    assert!(matches!(
        &frames[1],
        cokret_sdk::EventsSubscribeFrameBody::ResyncRequired { reason, .. } if reason == "server restart"
    ));
}
