use std::collections::BTreeSet;

use chrono::Utc;
use reqwest::StatusCode;
use serde_json::json;
use yougen::account_data::{
    AccountDataKey, ContactRemark, RealmRemark, contact_remark_account_data_key,
    realm_remark_account_data_key,
};
use yougen::api::{
    CokretApiError, decode_cokret_error, is_auth_expired_error, parse_directory_describe,
    parse_events_subscribe_ndjson_text, parse_resolve_realm, parse_server_description, parse_sync,
    parse_sync_describe,
};
use yougen::config::{ClientConfig, LocalConfigStore};
use yougen::models::ServerDescriptionExt;
use yougen::operation::OperationBuilder;
use yougen::push::validate_blind_wakeup_payload;
use yougen::telemetry::{UserActionOutcome, build_user_action_entry, format_user_action_line};

fn snapshot_contract_event_id(suffix: &str) -> cokret_sdk::EventId {
    cokret_sdk::EventId::new(format!("ck:event:01904100-0000-7000-8000-{suffix}")).unwrap()
}

fn snapshot_contract_hash(seed: u8) -> cokret_sdk::Hash {
    cokret_sdk::Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).unwrap()
}

fn snapshot_contract_manifest_payload() -> serde_json::Value {
    let snapshot_id =
        cokret_sdk::SnapshotId::new("ck:snapshot:01904100-0000-7000-8000-0000000000cc").unwrap();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-0000000000cc").unwrap();
    let service_did = cokret_sdk::Did::new("did:web:server.local").unwrap();
    let items = vec![cokret_sdk::SnapshotMaterializedItem {
        kind: "realm".to_owned(),
        id: realm_id.to_string(),
        object: json!({
            "id": realm_id.to_string(),
            "title": "Contract Snapshot Realm"
        }),
        source_event_id: snapshot_contract_event_id("0000000000c1"),
    }];
    let state_digest = cokret_sdk::state_digest_from_items(&items).unwrap();
    let built = cokret_sdk::build_snapshot_chunks(
        &snapshot_id,
        cokret_sdk::SNAPSHOT_REDUCER_PROFILE_V1,
        items,
        4096,
    )
    .unwrap();
    let created_at = Utc::now();
    let mut manifest = cokret_sdk::SnapshotManifest {
        id: snapshot_id,
        realm_id,
        reducer_profile: cokret_sdk::SNAPSHOT_REDUCER_PROFILE_V1.to_owned(),
        schema_profile_refs: vec!["ck.profile.core_event_store.v1".to_owned()],
        state_digest,
        frontier: cokret_sdk::SnapshotFrontier {
            event_ids: vec![snapshot_contract_event_id("0000000000c1")],
            timeline_hlc: cokret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        },
        event_set_commitment: cokret_sdk::EventSetCommitment {
            algorithm: cokret_sdk::EventSetCommitmentAlgorithm::MerkleEventSetV1,
            root: snapshot_contract_hash(9),
            covered_event_count: 1,
            covered_frontier: vec![snapshot_contract_event_id("0000000000c1")],
            actor_seq_ranges: Vec::new(),
        },
        chunks: built.into_iter().map(|chunk| chunk.descriptor).collect(),
        security_class: cokret_sdk::SnapshotSecurityClass::Standard,
        verification_hints: None,
        created_by: service_did.clone(),
        created_at,
        authority_binding: cokret_sdk::AuthorityBinding {
            issuer: service_did,
            authority_kind: cokret_sdk::SnapshotAuthorityKind::RealmPolicySnapshotIssuer,
            auth_state_digest: snapshot_contract_hash(1),
            auth_frontier: vec![snapshot_contract_event_id("0000000000c1")],
            checked_at: created_at,
            witness_attestations: Vec::new(),
        },
        signature: cokret_sdk::DetachedJwsProof::eddsa(
            "did:web:server.local#snapshot".to_owned(),
            snapshot_contract_hash(2),
            created_at,
            "header..signature".to_owned(),
        ),
    };
    manifest.signature.payload_digest = manifest.expected_signature_digest().unwrap();
    serde_json::to_value(manifest).unwrap()
}

#[test]
fn yougen_accepts_server_contract_payloads() {
    let describe = parse_server_description(json!({
        "service_did": "did:web:server.local",
        "trust_domain": "ck:trust_domain:server.local",
        "service_type": "principal_server",
        "protocol_version": "1.0",
        "supported_profiles": ["ck.schema.core.v1"],
        "supported_features": [
            "account.subscribe",
            "sync.backfill",
            "directory.search_realms",
            "directory.resolve_realm",
            "index.query",
            "authz.check",
            "profile.presence",
            "push.register_device",
            "moderation.report"
        ],
        "supported_operations": [
            "ck.self.account.subscribe",
            "ck.self.events.query",
            "ck.self.events.subscribe",
            "ck.self.snapshot.head",
            "ck.find.directory.describe",
            "ck.find.directory.search_realms",
            "ck.find.directory.resolve_realm",
            "ck.index.describe",
            "ck.index.query",
            "ck.self.authz.check",
            "ck.self.authz.get_effective_grants",
            "ck.self.authz.get_invites",
            "ck.edge.push.register_device",
            "ck.edge.push.unregister_device",
            "ck.self.moderation.report"
        ],
        "supported_bindings": [{"kind": "http_json", "base_path": "/_cokret"}],
        "supported_reducer_profiles": ["ck.reducer.v1"],
        "supported_schema_profiles": ["ck.schema.core.v1"],
        "auth_metadata": {"mode": "development"},
        "limits": {"storage": "memory", "max_limit": 100},
        "plaintext_visibility": {"default": "encrypted"},
        "implemented_features": [],
        "claimed_profiles": [],
        "verified_profiles": [],
        "experimental_features": [],
        "compat_surfaces": [],
        "development_mode": true,
    }))
    .unwrap();
    assert_eq!(describe.service_type, "principal_server");
    assert!(
        describe
            .supported_operations
            .contains(&"ck.index.query".to_owned())
    );
    assert_eq!(describe.supported_bindings[0]["base_path"], "/_cokret");

    let identity: yougen::models::IdentityDescribeOutcome = serde_json::from_value(json!({
        "service_did": "did:web:server.local",
        "registry_mode": "development_local",
        "supported_receipts": ["local"],
        "protocol_version": "1.0",
        "profiles": ["ck.identity.local-dev.v1"]
    }))
    .unwrap();
    assert_eq!(identity.registry_mode, "development_local");

    let resolved_identity: yougen::models::IdentityResolveOutcome = serde_json::from_value(json!({
        "did_document": {
            "did": "did:web:alice.example",
            "document": {"id": "did:web:alice.example"}
        },
        "key_log_head": null,
        "seq": 0,
        "receipts": [],
        "method_evidence": {"mode": "development_local"}
    }))
    .unwrap();
    assert_eq!(
        resolved_identity.did_document.document["id"],
        "did:web:alice.example"
    );

    let sync_describe = parse_sync_describe(json!({
        "service_did": "did:web:server.local",
        "supported_sync_profiles": ["initial", "incremental"],
        "limits": {"max_realms": 50, "max_timeline_events": 100},
        "frontier": {"storage": "memory"}
    }))
    .unwrap();
    assert!(
        sync_describe
            .supported_sync_profiles
            .contains(&"initial".to_owned())
    );

    let sync = parse_sync(json!({
        "cursor": "ck:cursor:contract-sync",
        "realms": {
            "ck:realm:0196419b-0000-7000-8000-000000000000": {
                "summary": {
                    "title": "Cokret Demo Realm",
                    "summary": "Shared demo Realm served by server",
                    "tags": ["demo"],
                    "category": "collaboration"
                },
                "timeline": {"events": [], "limited": false},
                "state": [],
                "ephemeral": [],
                "unread": {"notification_count": 0, "highlight_count": 0}
            }
        },
        "left_realms": [],
        "to_device": [],
        "account_data": [],
        "device_lists": {"changed": [], "left": []}
    }))
    .unwrap();
    assert!(
        sync.realms
            .contains_key("ck:realm:0196419b-0000-7000-8000-000000000000")
    );

    let directory = parse_directory_describe(json!({
        "service_did": "did:web:server.local",
        "resource_types": ["space", "organization", "actor"],
        "discovery_profiles": ["ck.profile.directory.v1"],
        "restricted_query_proof": false
    }))
    .unwrap();
    assert_eq!(directory.discovery_profiles[0], "ck.profile.directory.v1");

    let resolved = parse_resolve_realm(json!({
        "realm_preview": {
            "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
            "title": "Cokret Demo Realm",
            "description": "Shared demo Realm served by server",
            "tags": ["demo"],
            "public": true,
            "category": "collaboration"
        },
        "stripped_state": [],
        "join_rule": "public",
        "join_candidates": [{
            "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
            "service_did": "did:web:server.local",
            "service_type": "principal_server",
            "role": "primary",
            "endpoint": "http://server",
            "operations": ["ck.self.events.submit"],
            "join_methods": ["invite_accept", "member_join"],
            "priority": 0,
            "source": "directory_ingest",
            "as_of": "2026-05-30T00:00:00Z",
            "expires_at": "2099-01-01T00:00:00Z"
        }]
    }))
    .unwrap();
    assert_eq!(resolved.join_rule, Some(cokret_sdk::JoinRule::Public));
    assert_eq!(
        resolved.join_candidates[0].service_did.as_str(),
        "did:web:server.local"
    );

    let submit: yougen::models::SubmitEventOutcome = serde_json::from_value(json!({
        "status": "accepted",
        "accepted": ["ck:event:019640ca-0000-7000-8000-000000000000"],
        "duplicate": [],
        "rejected": [],
        "actor_frontier": {},
        "realm_frontier": {},
        "cursor": "sx:1760000000000"
    }))
    .unwrap();
    assert_eq!(submit.status, "accepted");
    assert_eq!(
        submit.event_id,
        "ck:event:019640ca-0000-7000-8000-000000000000"
    );
    assert_eq!(submit.cursor, "sx:1760000000000");

    let snapshot_head: cokret_sdk::SnapshotManifest =
        serde_json::from_value(snapshot_contract_manifest_payload()).unwrap();
    assert_eq!(
        snapshot_head.reducer_profile,
        cokret_sdk::SNAPSHOT_REDUCER_PROFILE_V1
    );
    assert_eq!(snapshot_head.created_by.as_str(), "did:web:server.local");
    assert!(
        snapshot_head
            .signature
            .payload_digest
            .as_str()
            .starts_with("sha256:")
    );
    assert!(
        serde_json::from_value::<cokret_sdk::SnapshotManifest>(json!({
            "anchor": "ck:anchor:sha256:00",
            "chunk_count": 1,
            "merkle_root": format!("sha256:{}", "00".repeat(32)),
            "generator_proof": {}
        }))
        .is_err()
    );

    let login: yougen::models::DevLoginOutcome = serde_json::from_value(json!({
        "access_token": "sx_token",
        "token_type": "Bearer",
        "actor": "did:web:alice.example",
        "device_id": "dev_yougen",
        "expires_at": "2026-04-28T12:00:00Z"
    }))
    .unwrap();
    assert_eq!(login.token_type, "Bearer");

    let authz: yougen::models::AuthzCheckOutcome = serde_json::from_value(json!({
        "decision": "allow",
        "reason_code": null,
        "grants": [{"actor": "did:web:alice.example"}],
        "obligations": []
    }))
    .unwrap();
    assert_eq!(authz.decision, cokret_sdk::model::AuthzDecision::Allow);

    // `GrantList` is the SDK authoritative wire type (soland serialises it
    // verbatim), so rows must be full `ck.schema.capability_grant.v1`
    // grants rather than free-form objects.
    let grants: yougen::models::GrantList = serde_json::from_value(json!({
        "grants": [{
            "id": "ck:grant:0196419b-0000-7000-8000-000000000000",
            "schema": "ck.schema.capability_grant.v1",
            "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000001",
            "issuer": "did:web:server.local",
            "subject": "did:web:alice.example",
            "actions": ["ck.space.write_message"],
            "resources": [
                {"kind": "realm", "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000001"}
            ],
            "issued_at": "2026-04-28T12:00:00Z",
            "proofs": []
        }],
        "state_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "evaluated_at": "2026-04-28T12:00:00Z"
    }))
    .unwrap();
    assert_eq!(grants.grants.len(), 1);

    let invites: yougen::models::InvitesOutcome = serde_json::from_value(json!({
        "invites": [],
        "next_cursor": null
    }))
    .unwrap();
    assert!(invites.invites.is_empty());

    let keys: yougen::models::KeysUploadOutcome = serde_json::from_value(json!({
        "one_time_key_counts": {"signed_curve25519": 1},
        "fallback_keys": {}
    }))
    .unwrap();
    assert_eq!(keys.one_time_key_counts["signed_curve25519"], 1);

    let claimed: yougen::models::KeysClaimOutcome = serde_json::from_value(json!({
        "one_time_keys": {"did:web:alice.example": {"ck:device:0196419b-0000-7000-8000-000000000000": {"key_id": "alice-otk-1"}}},
        "failures": []
    }))
    .unwrap();
    assert!(!claimed.one_time_keys.is_empty());

    let device_send: yougen::models::DeviceMessagesPutOutcome = serde_json::from_value(json!({
        "ok": true,
        "delivered": {"did:web:alice.example": ["dev_alice"]},
        "unknown_devices": {}
    }))
    .unwrap();
    assert!(device_send.ok);

    let device_receive: yougen::models::DeviceMessagesGetOutcome = serde_json::from_value(json!({
        "events": [],
        "next_cursor": "ck:cursor:device-messages",
        "limited": false
    }))
    .unwrap();
    assert!(!device_receive.limited);

    let push: yougen::models::PushRegisterOutcome = serde_json::from_value(json!({
        "ok": true,
        "registration_id": "ck:push:dev_alice",
        "expires_at": null
    }))
    .unwrap();
    assert_eq!(push.registration_id.as_deref(), Some("ck:push:dev_alice"));

    let ok: yougen::models::OkOutcome = serde_json::from_value(json!({"ok": true})).unwrap();
    assert!(ok.ok);

    // Spec rename: blob upload response uses `size_bytes` and
    // `content_digest`; no serde aliases in aggressive migration mode.
    let blob_digest = format!("sha256:{}", "ab".repeat(32));
    let blob: yougen::models::BlobUploadOutcome = serde_json::from_value(json!({
        "blob_ref": format!("ck:blob:{blob_digest}"),
        "size_bytes": 23,
        "media_type": "application/octet-stream",
        "content_digest": blob_digest,
        "upload_receipt": {"service_did": "did:web:server.local"}
    }))
    .unwrap();
    assert_eq!(blob.size_bytes, 23);
    assert_eq!(
        blob.content_digest.as_str(),
        format!("sha256:{}", "ab".repeat(32))
    );

    let report: yougen::models::SolandModerationReportOutcome = serde_json::from_value(json!({
        "report_id": "ck:report:1760000000000",
        "status": "queued",
        "routed_to": ["did:web:server.local#moderation"]
    }))
    .unwrap();
    assert_eq!(report.status, "queued");

    let error = decode_cokret_error(
        StatusCode::CONFLICT,
        br#"{"ok":false,"error":{"code":"expected_head_mismatch","message":"expected_head mismatch","retry_after_ms":null}}"#,
    );
    assert_eq!(error.code(), "expected_head_mismatch");
    assert_eq!(error.message(), "expected_head mismatch");
}

#[test]
fn server_description_gates_event_envelope_write_plane() {
    let events_ready = parse_server_description(json!({
        "service_did": "did:web:soland.local",
        "trust_domain": "ck:trust_domain:soland.local",
        "service_type": "principal_server",
        "protocol_version": "1.0",
        "supported_profiles": [
            "ck.profile.core_event_store.v1",
            "ck.profile.principal_server_events_api.v1"
        ],
        "supported_operations": [
            "ck.self.events.describe",
            "ck.self.events.submit",
            "ck.self.account.subscribe"
        ],
        "supported_bindings": [{"kind": "http_json"}],
        "supported_features": ["events.submit", "account.subscribe"],
        "auth_metadata": {},
        "limits": {},
        "plaintext_visibility": {"default": "e2ee", "allowed_services": []},
        "implemented_features": [],
        "claimed_profiles": [],
        "verified_profiles": [],
        "experimental_features": [],
        "compat_surfaces": [],
        "development_mode": true,
    }))
    .unwrap();
    assert!(events_ready.supports_event_envelope_write_plane());
    assert!(events_ready.is_v1_principal_server_ready());
    assert!(
        events_ready
            .missing_event_envelope_write_requirements()
            .is_empty()
    );

    let soland_compat_surface = serde_json::to_value(
        cokret_sdk::CompatSurfaceEntry::external_interop("soland_private_local_routes")
            .with_extra_string("base_path", "/_soland")
            .with_extra_string("status", "soland_private_local")
            .with_notes(
                "non-registry REST routes were moved out of /_cokret; clients should prefer \
                 operation-registry canonical paths",
            ),
    )
    .unwrap();
    let soland_with_local_compat_surface = parse_server_description(json!({
        "service_did": "did:web:local.host",
        "trust_domain": "ck:trust_domain:local.host",
        "service_type": "principal_server",
        "protocol_version": "1.0",
        "supported_profiles": [
            "ck.profile.core_event_store.v1",
            "ck.profile.principal_server_events_api.v1"
        ],
        "supported_operations": [
            "ck.self.events.describe",
            "ck.self.events.submit"
        ],
        "supported_bindings": [{"kind": "http_json", "base_url": "https://local.host"}],
        "supported_features": ["ck.feature.soland.events.describe"],
        "auth_metadata": {"mode": "development"},
        "limits": {"storage": "postgres"},
        "plaintext_visibility": {"default": "encrypted"},
        "implemented_features": ["ck.feature.soland.events.describe"],
        "claimed_profiles": [
            {
                "profile_id": "ck.profile.core_event_store.v1",
                "claim_kind": "self_claimed"
            }
        ],
        "verified_profiles": [],
        "experimental_features": [],
        "compat_surfaces": [soland_compat_surface],
        "development_mode": true,
    }))
    .unwrap();
    assert_eq!(
        soland_with_local_compat_surface.compat_surfaces[0].name,
        "soland_private_local_routes"
    );

    // A partial / pre-v2 describe payload now fails to deserialize at all —
    // the SDK type is strict per `service-describe.schema.json`, so yougen
    // can no longer accept a stripped-down describe and flag it post-hoc.
    // This is the spec-correct fail-closed behaviour for v2.
    assert!(
        parse_server_description(json!({
            "service_did": "did:web:minimal.local",
            "service_type": "principal_server",
            "protocol_version": "1.0",
            "supported_profiles": [],
            "supported_operations": ["ck.self.account.subscribe"],
            "supported_features": ["account.subscribe"]
        }))
        .is_err()
    );

    // A v2-shaped payload that still omits the event write requirements is
    // accepted by the SDK parser but flagged by the yougen helpers.
    let events_missing = parse_server_description(json!({
        "service_did": "did:web:minimal.local",
        "trust_domain": "ck:trust_domain:minimal.local",
        "service_type": "principal_server",
        "protocol_version": "1.0",
        "supported_profiles": [],
        "supported_operations": ["ck.self.account.subscribe"],
        "supported_bindings": [{"kind": "http_json"}],
        "supported_features": ["account.subscribe"],
        "auth_metadata": {},
        "limits": {},
        "plaintext_visibility": {"default": "encrypted"},
        "implemented_features": [],
        "claimed_profiles": [],
        "verified_profiles": [],
        "experimental_features": [],
        "compat_surfaces": [],
        "development_mode": true,
    }))
    .unwrap();
    assert!(!events_missing.supports_event_envelope_write_plane());
    assert_eq!(
        events_missing.missing_event_envelope_write_requirements(),
        vec![
            "ck.profile.core_event_store.v1",
            "ck.self.events.describe",
            "ck.self.events.submit"
        ]
    );
    // `plaintext_visibility` is now present + non-null, so it falls out of
    // the missing list; only the event write requirements remain.
    assert_eq!(
        events_missing.missing_v1_principal_server_requirements(),
        vec![
            "ck.profile.core_event_store.v1",
            "ck.self.events.describe",
            "ck.self.events.submit",
        ]
    );
}

#[test]
fn yougen_accepts_v1_sync_buckets_and_subscribe_ndjson_contract() {
    // Spec-aligned wire shape per `cokret-spec/.../client-sync.md §2`:
    // flat `realms` keyed by realm id, explicit top-level
    // `left_realms`, flat arrays for `to_device` / `account_data` /
    // `presence`. The SDK's `SyncOutcome` is the single source of
    // truth; yougen no longer owns a custom deserializer.
    let sync = parse_sync(json!({
        "cursor": "sx:v1-bucket",
        "realms": {
            "ck:realm:joined": {
                "summary": {"title": "Joined Realm"},
                "timeline": {"events": [], "limited": false},
                "state": [],
                "ephemeral": [],
                "unread": {"notification_count": 0, "highlight_count": 0}
            }
        },
        "left_realms": ["ck:realm:left"],
        "to_device": [{"type": "ck.mls.welcome"}],
        "account_data": [{
            "data_type": "ck.push_rules",
            "content": {"global": {"enabled": true}}
        }],
        "device_lists": {"changed": [], "left": []},
        "notifications": {"rooms": {"ck:realm:joined": {"count": 1}}},
        "presence": [{"actor_id": "did:web:alice.example"}]
    }))
    .unwrap();
    assert_eq!(sync.cursor, "sx:v1-bucket");
    assert!(sync.realms.contains_key("ck:realm:joined"));
    assert_eq!(sync.left_realms, vec!["ck:realm:left".to_owned()]);
    assert_eq!(sync.to_device.len(), 1);
    assert_eq!(sync.account_data.len(), 1);
    assert_eq!(sync.notifications["rooms"]["ck:realm:joined"]["count"], 1);
    assert_eq!(sync.presence[0]["actor_id"], "did:web:alice.example");
    assert!(sync.presence[0].get("sender").is_none());

    let frames = parse_events_subscribe_ndjson_text(
        r#"{"kind":"heartbeat","emitted_at":"2026-05-20T00:00:00Z"}
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
fn account_data_canonical_contact_and_realm_remark_keys_contract() {
    assert_eq!(
        realm_remark_account_data_key("ck:realm:contract"),
        "ck.contacts.realm.ck:realm:contract"
    );
    assert_eq!(
        contact_remark_account_data_key("did:web:alice.example"),
        "ck.contacts.actor.did:web:alice.example"
    );
    assert_eq!(
        AccountDataKey::ClientReadReceipts.as_wire(),
        "ck.read_receipt.preferences"
    );
    assert_eq!(
        AccountDataKey::ClientNotifications.as_wire(),
        "ck.push_rules"
    );
    assert_eq!(
        AccountDataKey::ClientDndSchedule.as_wire(),
        "ck.dnd_schedule"
    );
}

#[test]
fn local_remarks_do_not_leak_into_event_push_search_log_or_directory_surfaces() {
    fn assert_no_secret<T: serde::Serialize>(label: &str, value: &T, secret: &str) {
        let wire = serde_json::to_string(value).unwrap();
        assert!(
            !wire.contains(secret),
            "{label} leaked private remark secret: {wire}"
        );
    }

    let secret = "Alice from Ops Private";
    let contact_remark = ContactRemark::new("did:web:alice.example", secret);
    let _realm_remark = RealmRemark::new("ck:realm:contract", secret);

    let event = OperationBuilder::new(
        "ck:realm:contract",
        "did:web:local.example",
        "ck.message.create",
    )
    .body(json!({
        "body": "hello",
        "mentions": [{
            "kind": "actor",
            "target": contact_remark.actor_id,
            "token": "@alice"
        }]
    }))
    .build("contract-test");
    assert_no_secret("event", &event, secret);

    let blind_push = json!({
        "type": "ck.push.blind_wakeup.v1",
        "reason": "background_sync_needed"
    });
    validate_blind_wakeup_payload(&blind_push).unwrap();
    validate_blind_wakeup_payload(&json!({"local_name": secret}))
        .expect_err("blind push must reject local remark fields");

    let search = yougen::models::IndexSearchOutcome {
        query: "hello".to_owned(),
        results: vec![json!({
            "kind": "message",
            "space_id": "ck:space:contract",
            "actor_id": "did:web:alice.example",
            "content": {"body": "hello"}
        })],
        next_cursor: None,
    };
    assert_no_secret("search", &search, secret);

    let log_line = format_user_action_line(
        "did:web:local.example",
        "message.create",
        UserActionOutcome::Success,
        None,
    );
    assert!(!log_line.contains(secret));
    let log_entry = build_user_action_entry(
        "did:web:local.example",
        "message.create",
        UserActionOutcome::Success,
        None,
    );
    assert_no_secret("log", &log_entry, secret);

    let directory = yougen::models::SearchRealmsOutcome {
        results: vec![yougen::models::RealmTreeNode {
            id: "ck:realm:contract".to_owned(),
            title: "Contract Realm".to_owned(),
            description: Some("Public description".to_owned()),
            tags: BTreeSet::from(["contract".to_owned()]),
            public: true,
            category: Some("collaboration".to_owned()),
            parent_space_id: None,
            child_space_ids: Vec::new(),
            kind: yougen::models::RealmTreeNodeKind::Realm,
            realm_id: "ck:realm:contract".to_owned(),
        }],
        next_cursor: None,
    };
    assert_no_secret("directory", &directory, secret);
}

#[test]
fn yougen_config_store_preserves_server_actor_device_and_token() {
    let mut store = LocalConfigStore::default();
    let config = ClientConfig::from_fields(
        "http://127.0.0.1:8788",
        "did:web:contract.example",
        "dev_contract",
        "sx_contract_token",
    );

    store.save(config.clone());

    assert_eq!(store.load(), config);
}

#[test]
fn yougen_e2ee_workflow_matches_protocol_mls_envelope_behavior() {
    let mut alice = yougen::crypto::LocalMlsDevice::new(
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-000000000001",
    )
    .unwrap();
    let mut bob = yougen::crypto::LocalMlsDevice::new(
        "did:web:bob.example",
        "ck:device:01904100-0000-7000-8000-000000000002",
    )
    .unwrap();
    let bob_keys = bob.key_package_record().unwrap();

    alice
        .create_group(b"ck:realm:0196419b-0000-7000-8000-000000000000")
        .unwrap();
    let add_result = alice.add_member(&bob_keys).unwrap();
    bob.join_from_welcome(&add_result.welcome).unwrap();

    let encrypted = alice
        .encrypt_message(
            "ck:message:contract-1",
            br#"{"content":{"kind":"ck.content.text","body":"hello via MLS"}}"#,
        )
        .unwrap();
    assert_eq!(encrypted.payload.scheme.as_str(), "mls-rfc9420");
    assert_eq!(
        encrypted.payload.content_type,
        "application/vnd.cokret.message+json"
    );

    let decrypted = bob.decrypt_or_preserve(encrypted).unwrap();
    let cokret_sdk::MessageCryptoDecrypt::Plaintext { plaintext, .. } = decrypted else {
        panic!("joined device should decrypt protocol MLS payload");
    };
    assert_eq!(
        plaintext,
        br#"{"content":{"kind":"ck.content.text","body":"hello via MLS"}}"#
    );
}

// (Move/Anchor pipeline tests removed — all writes now go through
// ck.self.events.submit; the SubmitEventOutcome wire shape is exercised by
// soland's own integration tests and the cokret-spec fixtures.)

/// Regression: `is_auth_expired_error` MUST treat a bare 401
/// (server returned 401 with no parseable error envelope, e.g. a
/// reverse-proxy injected HTML page) as a *transient*
/// denial — not as session death. Otherwise a brief upstream hiccup
/// wipes the user's persisted session and forces a fresh sign-in.
#[test]
fn bare_401_does_not_count_as_session_loss() {
    let bare: anyhow::Error = CokretApiError {
        status: StatusCode::UNAUTHORIZED,
        error: decode_cokret_error(StatusCode::UNAUTHORIZED, b""),
    }
    .into();
    assert!(!is_auth_expired_error(&bare));

    // A 401 with an unrelated error code (e.g. rate-limit / policy_denied
    // wrapped at the 401 layer) must also stay transient. Only explicit
    // session-death codes from the spec — auth_expired / unauthenticated /
    // soft_logged_out / invalid_token / token_expired —
    // should drop the session.
    for code in [
        "auth_expired",
        "unauthenticated",
        "soft_logged_out",
        "invalid_token",
        "token_expired",
    ] {
        let body =
            format!(r#"{{"ok":false,"error":{{"code":"{code}","message":"unknown token"}}}}"#);
        let envelope: anyhow::Error = CokretApiError {
            status: StatusCode::UNAUTHORIZED,
            error: decode_cokret_error(StatusCode::UNAUTHORIZED, body.as_bytes()),
        }
        .into();
        assert!(
            is_auth_expired_error(&envelope),
            "code {code} should be classified as expired"
        );
    }

    let unrelated: anyhow::Error = CokretApiError {
        status: StatusCode::UNAUTHORIZED,
        error: decode_cokret_error(
            StatusCode::UNAUTHORIZED,
            br#"{"ok":false,"error":{"code":"rate_limited","message":"slow down"}}"#,
        ),
    }
    .into();
    assert!(!is_auth_expired_error(&unrelated));
}

/// Regression: `decode_cokret_error` MUST tolerate the current
/// on-the-wire shapes (canonical wrapped and plain envelope without
/// `request_id`) and synthesise a stable `http_status` envelope when
/// none match. A regression here silently degrades every error message
/// in the UI.
#[test]
fn decoder_handles_all_envelope_shapes() {
    // 1. Canonical wrapped: { "error": ErrorEnvelope }. Extra hints (e.g. the cell ref the server
    //    is reporting the conflict on) must flow through the `details` map so the conflict UI can
    //    surface them.
    let wrapped = decode_cokret_error(
        StatusCode::CONFLICT,
        br#"{"ok":false,"error":{"code":"expected_head_mismatch","message":"head mismatch","retry_after_ms":250,"details":{"cell":"ck:cell:ck.component.flow.position.v1:demo"}}}"#,
    );
    assert_eq!(wrapped.code(), "expected_head_mismatch");
    assert_eq!(wrapped.retry_after_ms(), Some(250));
    assert_eq!(
        wrapped.details()["cell"],
        "ck:cell:ck.component.flow.position.v1:demo"
    );

    // 2. Plain envelope without `request_id`.
    let plain = decode_cokret_error(
        StatusCode::BAD_REQUEST,
        br#"{"ok":false,"error":{"code":"invalid_param","message":"bad did"}}"#,
    );
    assert_eq!(plain.code(), "invalid_param");

    // 3. Garbage / non-JSON: synthesised fallback.
    let fallback = decode_cokret_error(StatusCode::SERVICE_UNAVAILABLE, b"<html>busy</html>");
    assert_eq!(fallback.code(), "http_status");
    assert!(fallback.message().contains("503"));
}
