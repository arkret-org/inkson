use chrono::Utc;
use inkson::account_data::{
    AccountDataKey, ContactRemark, RealmRemark, contact_remark_account_data_key,
    realm_remark_account_data_key,
};
use inkson::api_error::{TransportClientError, decode_arkret_error, is_auth_expired_error};
use inkson::config::{ClientConfig, LocalConfigStore};
use inkson::models::{
    missing_event_envelope_write_requirements, missing_v1_principal_server_requirements,
    service_is_v1_principal_server_ready, service_supports_event_envelope_write_plane,
};
use inkson::operation::OperationBuilder;
use inkson::push::validate_blind_wakeup_payload;
use inkson::service_parse::parse_server_description;
use inkson::telemetry::{UserActionOutcome, build_user_action_entry, format_user_action_line};
use reqwest::StatusCode;
use serde_json::json;

fn snapshot_contract_event_id(suffix: &str) -> arkret_sdk::EventId {
    arkret_sdk::EventId::new(format!("ak:event:01904100-0000-7000-8000-{suffix}")).unwrap()
}

fn snapshot_contract_hash(seed: u8) -> arkret_sdk::Hash {
    arkret_sdk::Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).unwrap()
}

fn snapshot_contract_manifest_payload() -> serde_json::Value {
    let snapshot_id =
        arkret_sdk::SnapshotId::new("ak:snapshot:01904100-0000-7000-8000-0000000000cc").unwrap();
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-0000000000cc").unwrap();
    let service_id = arkret_sdk::Did::new("did:web:server.local").unwrap();
    let items = vec![arkret_sdk::SnapshotMaterializedItem {
        kind: "realm".to_owned(),
        id: realm_id.to_string(),
        object: json!({
            "id": realm_id.to_string(),
            "title": "Contract Snapshot Realm"
        }),
        source_event_id: snapshot_contract_event_id("0000000000c1"),
    }];
    let state_digest = arkret_sdk::state_digest_from_items(&items).unwrap();
    let built = arkret_sdk::build_snapshot_chunks(
        &snapshot_id,
        arkret_sdk::SNAPSHOT_REDUCER_PROFILE_V1,
        items,
        4096,
    )
    .unwrap();
    let created_at = Utc::now();
    let mut manifest = arkret_sdk::SnapshotManifest {
        id: snapshot_id,
        realm_id,
        reducer_profile: arkret_sdk::SNAPSHOT_REDUCER_PROFILE_V1.to_owned(),
        schema_profile_refs: vec!["ak.profile.core_event_store.v1".to_owned()],
        state_digest,
        frontier: arkret_sdk::SnapshotFrontier {
            event_ids: vec![snapshot_contract_event_id("0000000000c1")],
            timeline_hlc: arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        },
        event_set_commitment: arkret_sdk::EventSetCommitment {
            algorithm: arkret_sdk::EventSetCommitmentAlgorithm::MerkleEventSetV1,
            root: snapshot_contract_hash(9),
            covered_event_count: 1,
            covered_seals: vec![snapshot_contract_event_id("0000000000c1")],
            actor_seq_ranges: Vec::new(),
        },
        chunks: built.into_iter().map(|chunk| chunk.descriptor).collect(),
        security_class: arkret_sdk::SnapshotSecurityClass::Standard,
        verification_hints: None,
        created_by: service_id.clone(),
        created_at,
        authority_binding: arkret_sdk::AuthorityBinding {
            issuer: service_id,
            authority_kind: arkret_sdk::SnapshotAuthorityKind::RealmPolicySnapshotIssuer,
            auth_state_digest: snapshot_contract_hash(1),
            auth_frontier: vec![snapshot_contract_event_id("0000000000c1")],
            checked_at: created_at,
            witness_attestations: Vec::new(),
        },
        signature: arkret_sdk::DetachedJwsProof::eddsa(
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
fn inkson_accepts_server_contract_payloads() {
    let describe = parse_server_description(json!({
        "service_id": "did:web:server.local",
        "trust_domain": "ak:trust_domain:server.local",
        "service_type": "principal_server",
        "protocol_version": "1.0",
        "supported_profiles": ["ak.schema.core.v1"],
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
            "ak.self.account.stream.subscribe",
            "ak.self.events.query.scan",
            "ak.self.events.stream.subscribe",
            "ak.self.snapshot.query.manifest_head",
            "ak.find.directory.query.describe",
            "ak.find.directory.query.search_realms",
            "ak.find.directory.query.resolve_realm",
            "ak.index.describe",
            "ak.index.query",
            "ak.self.authz.query.check",
            "ak.self.authz.grants.query.effective",
            "ak.self.authz.invites.query.list",
            "ak.edge.push.command.register_device",
            "ak.edge.push.command.unregister_device",
            "ak.self.moderation.command.report"
        ],
        "supported_bindings": [{"kind": "http_json", "base_url": "/_arkret"}],
        "supported_reducer_profiles": ["ak.reducer.v1"],
        "supported_schema_profiles": ["ak.schema.core.v1"],
        "auth_metadata": {"mode": "development"},
        "limits": {"storage": "memory", "max_limit": 100},
        "plaintext_visibility": {"data_classes": [], "max_visibility": "none"},
        "implemented_features": [],
        "claimed_profiles": [],
        "verified_profiles": [],
        "experimental_features": [],
        "compat_surfaces": [],
        "development_mode": true,
    }))
    .unwrap();
    assert_eq!(
        describe.service_type,
        arkret_sdk::ServiceType::PrincipalServer
    );
    assert!(
        describe
            .supported_operations
            .contains(&"ak.index.query".to_owned())
    );
    assert_eq!(
        describe.supported_bindings[0].base_url.as_deref(),
        Some("/_arkret")
    );

    let identity: inkson::models::IdentityDescribeOutcome = serde_json::from_value(json!({
        "service_id": "did:web:server.local",
        "registry_mode": "development_local",
        "supported_receipts": ["local"],
        "protocol_version": "1.0",
        "profiles": ["ak.identity.local-dev.v1"]
    }))
    .unwrap();
    assert_eq!(identity.registry_mode, "development_local");

    let resolved_identity: inkson::models::IdentityResolveOutcome = serde_json::from_value(json!({
        "did_document": {
            "id": "did:web:alice.example"
        },
        "key_log_head": null,
        "seq": 0,
        "receipts": []
    }))
    .unwrap();
    assert_eq!(
        resolved_identity.did_document["id"],
        "did:web:alice.example"
    );

    let sync_describe: arkret_sdk::ServiceDescribe = serde_json::from_value(json!({
        "service_id": "did:web:server.local",
        "trust_domain": "ak:trust_domain:server.local",
        "service_type": "principal_server",
        "protocol_version": "1.0",
        "supported_profiles": ["ak.profile.minimal_client.v1"],
        "supported_features": [],
        "supported_operations": ["ak.self.account.query.describe"],
        "supported_bindings": [],
        "auth_metadata": {"mode": "development"},
        "limits": {},
        "plaintext_visibility": {"data_classes": [], "max_visibility": "none"},
        "implemented_features": [],
        "claimed_profiles": [],
        "verified_profiles": [],
        "experimental_features": [],
        "compat_surfaces": [],
        "development_mode": false
    }))
    .unwrap();
    assert!(
        sync_describe
            .supported_profiles
            .contains(&"ak.profile.minimal_client.v1".to_owned())
    );

    let frame: arkret_sdk::AccountSubscribeFrame = serde_json::from_value(json!({
        "kind": "delta",
        "cursor": "ak:cursor:contract-sync",
        "realms": {
            "ak:realm:0196419b-0000-7000-8000-000000000000": {
                "timeline": {"events": [], "limited": false}
            }
        }
    }))
    .unwrap();
    let sync = inkson::models::AccountSyncStep::from_batch(arkret_sdk::AccountSubscribeBatch {
        cursor: "ak:cursor:contract-sync".to_owned(),
        frames: vec![frame],
    })
    .unwrap();
    assert!(
        sync.realm_projections
            .contains_key("ak:realm:0196419b-0000-7000-8000-000000000000")
    );

    let directory: inkson::models::ServiceDescribe = serde_json::from_value(json!({
        "service_id": "did:web:server.local",
        "trust_domain": "ak:trust_domain:server.local",
        "service_type": "directory_service",
        "protocol_version": "1.0",
        "supported_profiles": ["ak.profile.directory_service.v1"],
        "supported_operations": ["ak.find.directory.query.describe"],
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
        "discovery_profiles": ["ak.profile.directory_service.v1"],
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
    assert_eq!(
        directory.discovery_profiles[0],
        "ak.profile.directory_service.v1"
    );

    let resolved: inkson::models::ResolveRealmOutcome = serde_json::from_value(json!({
        "realm_preview": {
            "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000000",
            "title": "Arkret Demo Realm",
            "summary": "Shared demo Realm served by server",
            "tags": ["demo"],
            "public": true,
            "category": "collaboration",
            "as_of": "2026-05-30T00:00:00.000Z",
            "source_refs": ["ak:event:0196419b-0000-7000-8000-000000000001"],
            "policy_revision": "contract-rev"
        },
        "stripped_state": [],
        "join_rule": "public",
        "join_candidates": [{
            "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000000",
            "service_id": "did:web:server.local",
            "service_type": "principal_server",
            "role": "primary",
            "endpoint": "http://server",
            "operations": ["ak.self.events.command.submit"],
            "join_methods": ["invite_accept", "member_join"],
            "priority": 0,
            "source": "directory_ingest",
            "seal_basis": {
                "leaves": ["ak:seal:sha256:1111111111111111111111111111111111111111111111111111111111111111"],
                "control_event_set_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                "state_root": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
            },
            "as_of": "2026-05-30T00:00:00.000Z",
            "expires_at": "2099-01-01T00:00:00.000Z"
        }]
    }))
    .unwrap();
    assert_eq!(resolved.join_rule, Some(arkret_sdk::JoinRule::Public));
    assert_eq!(
        resolved.join_candidates[0].service_id.as_str(),
        "did:web:server.local"
    );

    let submit: inkson::models::SubmitEventResult = serde_json::from_value(json!({
        "status": "accepted",
        "accepted": ["ak:event:019640ca-0000-7000-8000-000000000000"],
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
        "ak:event:019640ca-0000-7000-8000-000000000000"
    );
    assert_eq!(submit.cursor, "sx:1760000000000");

    let snapshot_head: arkret_sdk::SnapshotManifest =
        serde_json::from_value(snapshot_contract_manifest_payload()).unwrap();
    assert_eq!(
        snapshot_head.reducer_profile,
        arkret_sdk::SNAPSHOT_REDUCER_PROFILE_V1
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
        serde_json::from_value::<arkret_sdk::SnapshotManifest>(json!({
            "seal": "ak:seal:sha256:00",
            "chunk_count": 1,
            "merkle_root": format!("sha256:{}", "00".repeat(32)),
            "generator_proof": {}
        }))
        .is_err()
    );

    let authz: inkson::models::AuthzCheckOutcome = serde_json::from_value(json!({
        "decision": "allow",
        "reason_code": null,
        "grants": [{"actor": "did:web:alice.example"}],
        "obligations": []
    }))
    .unwrap();
    assert_eq!(authz.decision, arkret_sdk::models::AuthzDecision::Allow);

    // `GrantList` is the SDK authoritative wire type (soland serialises it
    // verbatim), so rows must be full `ak.schema.capability_grant.v1`
    // grants rather than free-form objects.
    let grants: inkson::models::GrantList = serde_json::from_value(json!({
        "grants": [{
            "id": "ak:grant:0196419b-0000-7000-8000-000000000000",
            "schema": "ak.schema.capability_grant.v1",
            "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000001",
            "issuer": "did:web:server.local",
            "subject": "did:web:alice.example",
            "actions": ["ak.space.write_message"],
            "resources": [
                {"kind": "realm", "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000001"}
            ],
            "issued_at": "2026-04-28T12:00:00.000Z",
            "proofs": []
        }],
        "state_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "evaluated_at": "2026-04-28T12:00:00.000Z"
    }))
    .unwrap();
    assert_eq!(grants.grants.len(), 1);

    let invites: inkson::models::AuthzInviteList = serde_json::from_value(json!({
        "invites": [],
        "next_cursor": null,
        "has_more": false
    }))
    .unwrap();
    assert!(invites.invites.is_empty());

    let keys: inkson::models::KeysUploadOutcome = serde_json::from_value(json!({
        "one_time_key_counts": {"signed_curve25519": 1},
        "fallback_keys": {}
    }))
    .unwrap();
    let signed_curve25519 = arkret_sdk::NonEmptyString::new("signed_curve25519").unwrap();
    assert_eq!(keys.one_time_key_counts[&signed_curve25519], 1);

    let claimed: inkson::models::KeysClaimOutcome = serde_json::from_value(json!({
        "one_time_keys": {
            "did:web:alice.example": {
                "ak:device:0196419b-0000-7000-8000-000000000000": {
                    "signed_curve25519": {
                        "key": "YWxpY2Utb3RrLTE",
                        "algorithm": "signed_curve25519",
                        "signature": {
                            "kid": "did:web:alice.example#device-key",
                            "alg": "EdDSA",
                            "sig": "c2ln"
                        },
                        "key_id": "alice-otk-1"
                    }
                }
            }
        },
        "failures": []
    }))
    .unwrap();
    assert!(!claimed.one_time_keys.is_empty());

    let device_send: inkson::models::DeviceMessagesSendOutcome = serde_json::from_value(json!({
        "ok": true,
        "delivered": {"did:web:alice.example": ["dev_alice"]},
        "unknown_devices": {}
    }))
    .unwrap();
    assert!(device_send.ok);

    // SDK shape: the to-device queue field is `messages`, not the old `events`.
    let device_receive: inkson::models::DeviceMessagesGetOutcome = serde_json::from_value(json!({
        "messages": [],
        "next_cursor": "ak:cursor:device-messages",
        "limited": false
    }))
    .unwrap();
    assert!(!device_receive.limited);

    let push: inkson::models::PushRegisterView = serde_json::from_value(json!({
        "ok": true,
        "registration_id": "ak:push:dev_alice",
        "expires_at": null
    }))
    .unwrap();
    assert_eq!(push.registration_id.as_deref(), Some("ak:push:dev_alice"));

    let ok: inkson::models::OkOutcome = serde_json::from_value(json!({"ok": true})).unwrap();
    assert!(ok.ok);

    // Spec rename: blob upload response uses `size_bytes` and
    // `content_digest`; no serde aliases in aggressive migration mode.
    let blob_digest = format!("sha256:{}", "ab".repeat(32));
    let blob: inkson::models::BlobUploadOutcome = serde_json::from_value(json!({
        "blob_ref": format!("ak:blob:{blob_digest}"),
        "size_bytes": 23,
        "media_type": "application/octet-stream",
        "content_digest": blob_digest,
        "upload_receipt": {
            "blob_ref": format!("ak:blob:{blob_digest}"),
            "content_digest": blob_digest,
            "size_bytes": 23,
            "received_at": "2026-04-28T12:00:00.000Z",
            "issuer_service_id": "did:web:server.local",
            "signature": {
                "kid": "did:web:server.local",
                "alg": "EdDSA",
                "sig": "c2ln"
            }
        }
    }))
    .unwrap();
    assert_eq!(blob.size_bytes, 23);
    assert_eq!(
        blob.content_digest.as_str(),
        format!("sha256:{}", "ab".repeat(32))
    );

    // SDK spec shape: status is `submitted`, and routed_to is a pure DID array
    // without fragments.
    let report: inkson::models::ModerationReportOutcome = serde_json::from_value(json!({
        "report_id": "ak:report:1760000000000",
        "status": "submitted",
        "routed_to": ["did:web:server.local"]
    }))
    .unwrap();
    assert_eq!(report.status, "submitted");
    assert_eq!(report.routed_to.len(), 1);
    assert_eq!(report.routed_to[0].as_str(), "did:web:server.local");

    let error = decode_arkret_error(
        StatusCode::CONFLICT,
        br#"{"ok":false,"error":{"code":"expected_head_mismatch","message":"expected_head mismatch","retry_after_ms":null},"request_id":"ak:request:server-contract"}"#,
    );
    assert_eq!(error.code(), "expected_head_mismatch");
    assert_eq!(error.message(), "expected_head mismatch");
}

#[test]
fn server_description_gates_event_envelope_write_plane() {
    let events_ready = parse_server_description(json!({
        "service_id": "did:web:soland.local",
        "trust_domain": "ak:trust_domain:soland.local",
        "service_type": "principal_server",
        "protocol_version": "1.0",
        "supported_profiles": [
            "ak.profile.core_event_store.v1",
            "ak.profile.principal_server_events_api.v1"
        ],
        "supported_operations": [
            "ak.self.events.query.describe",
            "ak.self.events.command.submit",
            "ak.self.account.stream.subscribe"
        ],
        "supported_bindings": [{"kind": "http_json"}],
        "supported_features": ["events.submit", "account.subscribe"],
        "auth_metadata": {"mode": "development"},
        "limits": {},
        "plaintext_visibility": {"data_classes": [], "max_visibility": "none"},
        "implemented_features": [],
        "claimed_profiles": [],
        "verified_profiles": [],
        "experimental_features": [],
        "compat_surfaces": [],
        "development_mode": true,
    }))
    .unwrap();
    assert!(service_supports_event_envelope_write_plane(&events_ready));
    assert!(service_is_v1_principal_server_ready(&events_ready));
    assert!(missing_event_envelope_write_requirements(&events_ready).is_empty());

    let external_compat_surface = serde_json::to_value(
        arkret_sdk::CompatSurfaceEntry::external_interop("external_mimi_provider")
            .with_extra_string("base_path", "https://mimi.example.com/_arkret/open/mimi")
            .with_extra_string("status", "external_interop")
            .with_notes("external interop surfaces must not redefine principal-server routes"),
    )
    .unwrap();
    let described_with_external_compat_surface = parse_server_description(json!({
        "service_id": "did:web:local.host",
        "trust_domain": "ak:trust_domain:local.host",
        "service_type": "principal_server",
        "protocol_version": "1.0",
        "supported_profiles": [
            "ak.profile.core_event_store.v1",
            "ak.profile.principal_server_events_api.v1"
        ],
        "supported_operations": [
            "ak.self.events.query.describe",
            "ak.self.events.command.submit"
        ],
        "supported_bindings": [{"kind": "http_json", "base_url": "https://local.host"}],
        "supported_features": ["ak.feature.soland.events.describe"],
        "auth_metadata": {"mode": "development"},
        "limits": {"storage": "postgres"},
        "plaintext_visibility": {"data_classes": [], "max_visibility": "none"},
        "implemented_features": ["ak.feature.soland.events.describe"],
        "claimed_profiles": [
            {
                "profile_id": "ak.profile.core_event_store.v1",
                "claim_kind": "self_claimed"
            }
        ],
        "verified_profiles": [],
        "experimental_features": [],
        "compat_surfaces": [external_compat_surface],
        "development_mode": true,
    }))
    .unwrap();
    assert_eq!(
        described_with_external_compat_surface.compat_surfaces[0].name,
        "external_mimi_provider"
    );

    // A partial / pre-v2 describe payload now fails to deserialize at all —
    // the SDK type is strict per `service-describe.schema.json`, so inkson
    // can no longer accept a stripped-down describe and flag it post-hoc.
    // This is the spec-correct fail-closed behaviour for v2.
    assert!(
        parse_server_description(json!({
            "service_id": "did:web:minimal.local",
            "service_type": "principal_server",
            "protocol_version": "1.0",
            "supported_profiles": [],
            "supported_operations": ["ak.self.account.stream.subscribe"],
            "supported_features": ["account.subscribe"]
        }))
        .is_err()
    );

    // A v2-shaped payload that still omits the event write requirements is
    // accepted by the SDK parser but flagged by the inkson helpers.
    let events_missing = parse_server_description(json!({
        "service_id": "did:web:minimal.local",
        "trust_domain": "ak:trust_domain:minimal.local",
        "service_type": "principal_server",
        "protocol_version": "1.0",
        "supported_profiles": [],
        "supported_operations": ["ak.self.account.stream.subscribe"],
        "supported_bindings": [{"kind": "http_json"}],
        "supported_features": ["account.subscribe"],
        "auth_metadata": {"mode": "development"},
        "limits": {},
        "plaintext_visibility": {"data_classes": [], "max_visibility": "none"},
        "implemented_features": [],
        "claimed_profiles": [],
        "verified_profiles": [],
        "experimental_features": [],
        "compat_surfaces": [],
        "development_mode": true,
    }))
    .unwrap();
    assert!(!service_supports_event_envelope_write_plane(
        &events_missing
    ));
    assert_eq!(
        missing_event_envelope_write_requirements(&events_missing),
        vec![
            "ak.profile.core_event_store.v1",
            "ak.self.events.query.describe",
            "ak.self.events.command.submit"
        ]
    );
    // `plaintext_visibility` is now present + non-null, so it falls out of
    // the missing list; only the event write requirements remain.
    assert_eq!(
        missing_v1_principal_server_requirements(&events_missing),
        vec![
            "ak.profile.core_event_store.v1",
            "ak.self.events.query.describe",
            "ak.self.events.command.submit",
        ]
    );
}

#[test]
fn inkson_accepts_v1_sync_buckets_and_subscribe_ndjson_contract() {
    // Spec-aligned wire shape per `arkret-spec/.../client-sync.md §2`:
    // flat `realms` keyed by realm id, explicit top-level
    // `left_realms`, flat arrays for `to_device` / `account_data` /
    let frame: arkret_sdk::AccountSubscribeFrame = serde_json::from_value(json!({
        "kind": "delta",
        "cursor": "ak:cursor:v1-bucket",
        "realms": {
            "ak:realm:0196419b-0000-7000-8000-000000000001": {
                "timeline": {"events": [], "limited": false}
            }
        },
        "device_lists": {"changed": [], "left": []},
        "notifications": {"items": []}
    }))
    .unwrap();
    let sync = inkson::models::AccountSyncStep::from_batch(arkret_sdk::AccountSubscribeBatch {
        cursor: "ak:cursor:v1-bucket".to_owned(),
        frames: vec![frame],
    })
    .unwrap();
    assert_eq!(sync.cursor, "ak:cursor:v1-bucket");
    assert!(
        sync.realm_projections
            .contains_key("ak:realm:0196419b-0000-7000-8000-000000000001")
    );
    assert!(sync.updates.to_device.is_empty());
    assert!(sync.updates.account_data.is_empty());
    assert!(sync.updates.notifications.is_empty());

    let frames = [
        r#"{"kind":"heartbeat"}"#,
        r#"{"cursor":"ak:cursor:frontier","kind":"frontier"}"#,
        r#"{"cursor":"ak:cursor:live","kind":"catchup_complete"}"#,
    ]
    .into_iter()
    .map(|line| {
        arkret_sdk::EventsSubscribeFrame::from_ndjson_line(line)
            .unwrap()
            .unwrap()
    })
    .collect::<Vec<_>>();
    assert_eq!(
        frames[0].kind,
        arkret_sdk::EventsSubscribeFrameKind::Heartbeat
    );
    assert_eq!(
        frames[1].kind,
        arkret_sdk::EventsSubscribeFrameKind::Frontier
    );
    assert_eq!(
        frames[2].kind,
        arkret_sdk::EventsSubscribeFrameKind::CatchupComplete
    );
}

#[test]
fn account_data_canonical_contact_and_realm_remark_keys_contract() {
    assert_eq!(
        realm_remark_account_data_key("ak:realm:contract"),
        "ak.contacts.realm.ak:realm:contract"
    );
    assert_eq!(
        contact_remark_account_data_key("did:web:alice.example"),
        "ak.contacts.actor.did:web:alice.example"
    );
    assert_eq!(
        AccountDataKey::ClientReadReceipts.as_wire(),
        "ak.read_receipt.preferences"
    );
    assert_eq!(
        AccountDataKey::ClientNotifications.as_wire(),
        "ak.push_rules"
    );
    assert_eq!(
        AccountDataKey::ClientDndSchedule.as_wire(),
        "ak.dnd_schedule"
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
    let realm_id = "ak:realm:01904100-0000-7000-8000-0000000000cd";
    let _realm_remark = RealmRemark::new(realm_id, secret);

    let event = OperationBuilder::new(
        realm_id,
        "did:web:local.example",
        arkret_sdk::events::kinds::EventKind::MessageCreate,
    )
    .body(json!({
        "body": "hello",
        "mentions": [{
            "kind": "mention",
            "subject_id": contact_remark.subject.did,
            "mention_text_original": "@alice"
        }]
    }))
    .build("contract-test");
    assert_no_secret("event", &event, secret);

    let blind_push = json!({
        "type": "ak.push.blind_wakeup.v1",
        "reason": "background_sync_needed"
    });
    validate_blind_wakeup_payload(&blind_push).unwrap();
    validate_blind_wakeup_payload(&json!({"local_name": secret}))
        .expect_err("blind push must reject local remark fields");

    let search = inkson::models::IndexSearchView {
        query: "hello".to_owned(),
        results: vec![json!({
            "kind": "message",
            "space_id": "ak:space:contract",
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

    let directory = arkret_sdk::models::DirectoryRealmSearchOutcome {
        realms: vec![arkret_sdk::models::RealmPreview {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:01904100-0000-7000-8000-000000000001".to_owned(),
            )
            .unwrap(),
            alias: None,
            title: Some("Contract Realm".to_owned()),
            avatar_blob_ref: None,
            organization_did: None,
            join_rule: Some("public".to_owned()),
            member_count_bucket: Some(arkret_sdk::models::RealmMemberCountBucket::Bucket(
                arkret_sdk::models::RealmMemberCountBucketLabel::OneToTen,
            )),
            summary: Some("Public description".to_owned()),
            owning_organizations: Vec::new(),
            preview_ref: None,
            discoverability: Some("public".to_owned()),
            history_visibility: None,
            join_candidates: Vec::new(),
            as_of: Utc::now(),
            source_refs: vec!["ak:event:01904100-0000-7000-8000-000000000002".to_owned()],
            policy_revision: "contract-rev".to_owned(),
            stale: None,
            divergent: None,
        }],
        next_cursor: None,
        has_more: false,
    };
    assert_no_secret("directory", &directory, secret);
}

#[test]
fn inkson_config_store_preserves_server_actor_device_and_token() {
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
fn inkson_e2ee_workflow_matches_protocol_mls_envelope_behavior() {
    let mut alice = inkson::crypto::LocalMlsDevice::new(
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000001",
    )
    .unwrap();
    let mut bob = inkson::crypto::LocalMlsDevice::new(
        "did:web:bob.example",
        "ak:device:01904100-0000-7000-8000-000000000002",
    )
    .unwrap();
    let bob_keys = bob.key_package_record().unwrap();

    alice
        .create_group(b"ak:realm:0196419b-0000-7000-8000-000000000000")
        .unwrap();
    let add_result = alice.add_member(&bob_keys).unwrap();
    bob.join_from_welcome(&add_result.welcome).unwrap();

    let encrypted = alice
        .encrypt_message(
            "ak:message:contract-1",
            br#"{"content":{"kind":"ak.content.text","body":"hello via MLS"}}"#,
        )
        .unwrap();
    assert_eq!(encrypted.payload.scheme.as_str(), "mls-rfc9420");
    assert_eq!(
        encrypted.payload.content_type,
        "application/vnd.arkret.message+json"
    );

    let decrypted = bob.decrypt_or_preserve(encrypted).unwrap();
    let arkret_sdk::MessageCryptoDecrypt::Plaintext { plaintext, .. } = decrypted else {
        panic!("joined device should decrypt protocol MLS payload");
    };
    assert_eq!(
        plaintext,
        br#"{"content":{"kind":"ak.content.text","body":"hello via MLS"}}"#
    );
}

// (Move/Seal pipeline tests removed — all writes now go through
// ak.self.events.command.submit; the SubmitEventResult decoder is exercised by
// soland's own integration tests and the arkret-spec fixtures.)

/// Regression: `is_auth_expired_error` MUST treat a bare 401
/// (server returned 401 with no parseable error envelope, e.g. a
/// reverse-proxy injected HTML page) as a *transient*
/// denial — not as session death. Otherwise a brief upstream hiccup
/// wipes the user's persisted session and forces a fresh sign-in.
#[test]
fn bare_401_does_not_count_as_session_loss() {
    let bare: anyhow::Error = TransportClientError {
        status: StatusCode::UNAUTHORIZED,
        error: decode_arkret_error(StatusCode::UNAUTHORIZED, b""),
    }
    .into();
    assert!(!is_auth_expired_error(&bare));

    // A 401 with an unrelated error code (e.g. rate-limit / policy_denied
    // wrapped at the 401 layer) must also stay transient. Only explicit
    // session-death codes from the spec — auth_expired / unauthenticated /
    // soft_logged_out —
    // should drop the session.
    for code in ["auth_expired", "unauthenticated", "soft_logged_out"] {
        let body = format!(
            r#"{{"ok":false,"error":{{"code":"{code}","message":"unknown token"}},"request_id":"ak:request:server-contract"}}"#
        );
        let envelope: anyhow::Error = TransportClientError {
            status: StatusCode::UNAUTHORIZED,
            error: decode_arkret_error(StatusCode::UNAUTHORIZED, body.as_bytes()),
        }
        .into();
        assert!(
            is_auth_expired_error(&envelope),
            "code {code} should be classified as expired"
        );
    }

    let unrelated: anyhow::Error = TransportClientError {
        status: StatusCode::UNAUTHORIZED,
        error: decode_arkret_error(
            StatusCode::UNAUTHORIZED,
            br#"{"ok":false,"error":{"code":"rate_limited","message":"slow down"},"request_id":"ak:request:server-contract"}"#,
        ),
    }
    .into();
    assert!(!is_auth_expired_error(&unrelated));
}

/// Regression: `decode_arkret_error` MUST tolerate the current
/// on-the-wire shapes (canonical wrapped and direct envelopes) and synthesise
/// a stable `http_status` envelope when none match. A regression here silently
/// degrades every error message in the UI.
#[test]
fn decoder_handles_all_envelope_shapes() {
    // 1. Canonical wrapped: { "error": ErrorEnvelope }. Extra hints (e.g. the cell ref the server
    //    is reporting the conflict on) must strand through the `details` map so the conflict UI can
    //    surface them.
    let wrapped = decode_arkret_error(
        StatusCode::CONFLICT,
        br#"{"error":{"ok":false,"error":{"code":"expected_head_mismatch","message":"head mismatch","retry_after_ms":250,"details":{"cell":"ak:cell:ak.component.strand.position.v1:demo"}},"request_id":"ak:request:server-contract-wrapped"}}"#,
    );
    assert_eq!(wrapped.code(), "expected_head_mismatch");
    assert_eq!(wrapped.retry_after_ms(), Some(250));
    assert_eq!(
        wrapped.details()["cell"],
        "ak:cell:ak.component.strand.position.v1:demo"
    );

    // 2. Direct canonical envelope.
    let plain = decode_arkret_error(
        StatusCode::BAD_REQUEST,
        br#"{"ok":false,"error":{"code":"invalid_param","message":"bad did"},"request_id":"ak:request:server-contract-direct"}"#,
    );
    assert_eq!(plain.code(), "invalid_param");

    // 3. Garbage / non-JSON: synthesised fallback.
    let fallback = decode_arkret_error(StatusCode::SERVICE_UNAVAILABLE, b"<html>busy</html>");
    assert_eq!(fallback.code(), "http_status");
    assert!(fallback.message().contains("503"));
}
