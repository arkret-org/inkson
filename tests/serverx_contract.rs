use reqwest::StatusCode;
use serde_json::json;
use yougen::{
    api::{
        decode_contrix_error, parse_directory_describe, parse_index_describe, parse_repo_describe,
        parse_resolve_space, parse_server_description, parse_sync, parse_sync_describe,
    },
    config::{ClientConfig, LocalConfigStore},
};

#[test]
fn yougen_accepts_serverx_contract_payloads() {
    let describe = parse_server_description(json!({
        "service_did": "did:web:serverx.local",
        "service_type": "principal_server",
        "protocol_version": "1.0",
        "supported_profiles": ["cx.schema.core.v1"],
        "supported_features": [
            "repo.submit_commit",
            "repo.read",
            "sync.account",
            "sync.backfill",
            "directory.search_spaces",
            "directory.resolve_space",
            "index.query",
            "authz.check",
            "profile.presence",
            "push.register_device",
            "moderation.report"
        ],
        "supported_operations": [
            "cx.repo.describe",
            "cx.repo.list_commits",
            "cx.repo.get_operations",
            "cx.repo.sync",
            "cx.repo.submit_commit",
            "cx.sync.account",
            "cx.events.query",
            "cx.events.subscribe",
            "cx.sync.get_snapshot_head",
            "cx.directory.describe",
            "cx.directory.search_spaces",
            "cx.directory.resolve_space",
            "cx.index.describe",
            "cx.index.query",
            "cx.authz.check",
            "cx.authz.get_effective_grants",
            "cx.authz.get_invites",
            "cx.push.register_device",
            "cx.push.unregister_device",
            "cx.moderation.report"
        ],
        "supported_bindings": [{"kind": "http_json", "base_path": "/api/v1"}],
        "supported_reducer_profiles": ["cx.reducer.v1"],
        "supported_schema_profiles": ["cx.schema.core.v1"],
        "auth_metadata": {"mode": "development"},
        "limits": {"storage": "memory", "max_limit": 100}
    }))
    .unwrap();
    assert_eq!(describe.service_type, "principal_server");
    assert!(
        describe
            .supported_operations
            .contains(&"cx.index.query".to_owned())
    );
    assert_eq!(describe.supported_bindings[0]["base_path"], "/api/v1");

    let identity: yougen::models::IdentityDescribeResponse = serde_json::from_value(json!({
        "service_did": "did:web:serverx.local",
        "registry_mode": "development_local",
        "supported_receipts": ["local"],
        "protocol_version": "1.0",
        "profiles": ["cx.identity.local-dev.v1"]
    }))
    .unwrap();
    assert_eq!(identity.registry_mode, "development_local");

    let resolved_identity: yougen::models::IdentityResolveResponse =
        serde_json::from_value(json!({
            "did_document": {"id": "did:web:alice.example"},
            "key_log_head": null,
            "seq": 0,
            "receipts": [],
            "method_evidence": {"mode": "development_local"}
        }))
        .unwrap();
    assert_eq!(
        resolved_identity.did_document["id"],
        "did:web:alice.example"
    );

    let sync_describe = parse_sync_describe(json!({
        "service_did": "did:web:serverx.local",
        "supported_sync_profiles": ["initial", "incremental"],
        "limits": {"max_spaces": 50, "max_timeline_events": 100},
        "frontier": {"storage": "memory"}
    }))
    .unwrap();
    assert!(
        sync_describe
            .supported_sync_profiles
            .contains(&"initial".to_owned())
    );

    let sync = parse_sync(json!({
        "next_batch": "sx:1760000000000",
        "spaces": {
            "cx:space:01js0sp0000000000000000000": {
                "summary": {
                    "title": "Contrix Demo Space",
                    "summary": "Shared demo Space served by serverx",
                    "tags": ["demo"],
                    "category": "collaboration"
                },
                "timeline": {"events": [], "limited": false},
                "state": [],
                "ephemeral": [],
                "unread": {"notification_count": 0, "highlight_count": 0}
            }
        },
        "to_device": [],
        "account_data": [],
        "device_lists": {"changed": [], "left": []}
    }))
    .unwrap();
    assert!(
        sync.spaces
            .contains_key("cx:space:01js0sp0000000000000000000")
    );

    let directory = parse_directory_describe(json!({
        "service_did": "did:web:serverx.local",
        "resource_types": ["space", "organization", "actor"],
        "discovery_profiles": ["cx.profile.directory.v1"],
        "restricted_query_proof": false
    }))
    .unwrap();
    assert_eq!(directory.discovery_profiles[0], "cx.profile.directory.v1");

    let resolved = parse_resolve_space(json!({
        "space_preview": {
            "space_id": "cx:space:01js0sp0000000000000000000",
            "name": "Contrix Demo Space",
            "description": "Shared demo Space served by serverx",
            "tags": ["demo"],
            "public": true,
            "category": "collaboration"
        },
        "stripped_state": [],
        "join_rule": "public",
        "via_services": ["did:web:serverx.local"]
    }))
    .unwrap();
    assert_eq!(resolved.join_rule, "public");

    let index_describe = parse_index_describe(json!({
        "service_did": "did:web:serverx.local",
        "reducer_profiles": ["cx.reducer.v1"],
        "schema_profiles": ["cx.schema.core.v1"],
        "query_features": ["space_preview", "entity_type_filter", "space_filter"],
        "frontier": {"next_batch": "sx:1760000000000"}
    }))
    .unwrap();
    assert!(
        index_describe
            .query_features
            .contains(&"space_preview".to_owned())
    );

    let index: yougen::models::IndexQueryResponse = serde_json::from_value(json!({
        "results": [{
            "kind": "space_preview",
            "space_id": "cx:space:01js0sp0000000000000000000",
            "title": "Contrix Demo Space",
            "summary": "Shared demo Space served by serverx",
            "entity_types": []
        }],
        "next_cursor": null,
        "frontier": {"next_batch": "sx:1760000000000"}
    }))
    .unwrap();
    assert_eq!(index.results.len(), 1);

    let repo = parse_repo_describe(json!({
        "repo_did": "did:web:serverx.local",
        "head_commit": null,
        "supported_signatures": ["detached_jws", "http_message_signature"],
        "limits": {"max_commits": 100, "max_operations": 500}
    }))
    .unwrap();
    assert!(
        repo.supported_signatures
            .contains(&"detached_jws".to_owned())
    );

    let commits: yougen::models::ListCommitsResponse = serde_json::from_value(json!({
        "commits": [],
        "next_cursor": null,
        "has_more": false
    }))
    .unwrap();
    assert!(!commits.has_more);

    let operations: yougen::models::GetOperationsResponse = serde_json::from_value(json!({
        "operations": [],
        "missing": [],
        "unauthorized": []
    }))
    .unwrap();
    assert!(operations.missing.is_empty());

    let repo_sync: yougen::models::RepoSyncResponse = serde_json::from_value(json!({
        "operations": [],
        "next_cursor": "sx:1760000000000",
        "has_more": false
    }))
    .unwrap();
    assert_eq!(repo_sync.next_cursor.as_deref(), Some("sx:1760000000000"));

    let submit: yougen::models::SubmitCommitResponse = serde_json::from_value(json!({
        "status": "accepted",
        "commit_id": "cx:commit:01js0cm0000000000000000000",
        "head_commit": "cx:commit:01js0cm0000000000000000000",
        "sync_token": "sx:1760000000000"
    }))
    .unwrap();
    assert_eq!(submit.status, "accepted");

    let snapshot: yougen::models::SnapshotHeadResponse = serde_json::from_value(json!({
        "snapshot_ref": "cx:snapshot:cx:space:01js0sp0000000000000000000:head",
        "state_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "frontier": {"space_id": "cx:space:01js0sp0000000000000000000"},
        "signature": {"kid": "did:web:serverx.local#dev", "alg": "none", "sig": ""}
    }))
    .unwrap();
    assert!(snapshot.snapshot_ref.starts_with("cx:snapshot:"));

    let login: yougen::models::DevLoginResponse = serde_json::from_value(json!({
        "access_token": "sx_token",
        "token_type": "Bearer",
        "actor": "did:web:alice.example",
        "device_id": "dev_yougen",
        "expires_at": "2026-04-28T12:00:00Z"
    }))
    .unwrap();
    assert_eq!(login.token_type, "Bearer");

    let authz: yougen::models::AuthzCheckResponse = serde_json::from_value(json!({
        "allowed": true,
        "reason_code": null,
        "grants": [{"actor": "did:web:alice.example"}],
        "obligations": []
    }))
    .unwrap();
    assert!(authz.allowed);

    let grants: yougen::models::EffectiveGrantsResponse = serde_json::from_value(json!({
        "grants": [{"subject": "did:web:alice.example"}],
        "state_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "evaluated_at": "2026-04-28T12:00:00Z"
    }))
    .unwrap();
    assert_eq!(grants.grants.len(), 1);

    let invites: yougen::models::InvitesResponse = serde_json::from_value(json!({
        "invites": [],
        "next_cursor": null
    }))
    .unwrap();
    assert!(invites.invites.is_empty());

    let keys: yougen::models::KeysUploadResponse = serde_json::from_value(json!({
        "one_time_key_counts": {"signed_curve25519": 1},
        "fallback_keys": {}
    }))
    .unwrap();
    assert_eq!(keys.one_time_key_counts["signed_curve25519"], 1);

    let claimed: yougen::models::KeysClaimResponse = serde_json::from_value(json!({
        "one_time_keys": {"did:web:alice.example": {"dev_alice": {"key_id": "alice-otk-1"}}},
        "failures": {}
    }))
    .unwrap();
    assert!(claimed.one_time_keys.is_object());

    let device_send: yougen::models::DeviceMessagesSendResponse = serde_json::from_value(json!({
        "ok": true,
        "delivered": {"did:web:alice.example": ["dev_alice"]},
        "unknown_devices": {}
    }))
    .unwrap();
    assert!(device_send.ok);

    let device_receive: yougen::models::DeviceMessagesReceiveResponse =
        serde_json::from_value(json!({
            "events": [],
            "next_batch": "sx:1760000000000",
            "limited": false
        }))
        .unwrap();
    assert!(!device_receive.limited);

    let push: yougen::models::PushRegisterResponse = serde_json::from_value(json!({
        "ok": true,
        "registration_id": "cx:push:dev_alice",
        "expires_at": null
    }))
    .unwrap();
    assert_eq!(push.registration_id.as_deref(), Some("cx:push:dev_alice"));

    let ok: yougen::models::OkResponse = serde_json::from_value(json!({"ok": true})).unwrap();
    assert!(ok.ok);

    let blob: yougen::models::BlobUploadResponse = serde_json::from_value(json!({
        "blob_ref": "cx:blob:sha256:abc",
        "size": 23,
        "media_type": "application/octet-stream",
        "sha256": "abc",
        "upload_receipt": {"service_did": "did:web:serverx.local"}
    }))
    .unwrap();
    assert_eq!(blob.size, 23);

    let report: yougen::models::ModerationReportResponse = serde_json::from_value(json!({
        "report_id": "cx:report:1760000000000",
        "status": "queued",
        "routed_to": ["did:web:serverx.local#moderation"]
    }))
    .unwrap();
    assert_eq!(report.status, "queued");

    let error = decode_contrix_error(
        StatusCode::CONFLICT,
        br#"{"ok":false,"error":{"errcode":"expected_head_mismatch","error":"expected_head mismatch","retry_after_ms":null}}"#,
    );
    assert_eq!(error.errcode, "expected_head_mismatch");
    assert_eq!(error.error, "expected_head mismatch");
}

#[test]
fn server_description_gates_event_envelope_write_plane() {
    let events_ready = parse_server_description(json!({
        "service_did": "did:web:soland.local",
        "service_type": "principal_server",
        "protocol_version": "1.0",
        "supported_profiles": [
            "cx.profile.core_event_store.v1",
            "cx.profile.principal_server_events_api.v1"
        ],
        "supported_operations": [
            "cx.events.describe",
            "cx.events.submit",
            "cx.sync.account"
        ],
        "supported_features": ["events.submit", "sync.account"]
    }))
    .unwrap();
    assert!(events_ready.supports_event_envelope_write_plane());
    assert!(
        events_ready
            .missing_event_envelope_write_requirements()
            .is_empty()
    );

    let repo_only = parse_server_description(json!({
        "service_did": "did:web:legacy.local",
        "service_type": "principal_server",
        "protocol_version": "1.0",
        "supported_profiles": ["cx.profile.principal_server_repo_api.v1"],
        "supported_operations": [
            "cx.repo.describe",
            "cx.repo.submit_commit",
            "cx.sync.account"
        ],
        "supported_features": ["repo.submit_commit", "sync.account"]
    }))
    .unwrap();
    assert!(!repo_only.supports_event_envelope_write_plane());
    assert_eq!(
        repo_only.missing_event_envelope_write_requirements(),
        vec![
            "cx.profile.core_event_store.v1",
            "cx.events.describe",
            "cx.events.submit"
        ]
    );
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
    let mut alice =
        yougen::crypto::LocalMlsDevice::new("did:web:alice.example", "dev_alice_1").unwrap();
    let mut bob = yougen::crypto::LocalMlsDevice::new("did:web:bob.example", "dev_bob_1").unwrap();
    let bob_keys = bob.key_package_record().unwrap();

    alice
        .create_group(b"cx:space:01js0sp0000000000000000000")
        .unwrap();
    let add_result = alice.add_member(&bob_keys).unwrap();
    bob.join_from_welcome(&add_result.welcome).unwrap();

    let encrypted = alice
        .encrypt_message(
            "cx:message:contract-1",
            br#"{"msgtype":"m.text","body":"hello via MLS"}"#,
        )
        .unwrap();
    assert_eq!(encrypted.payload.scheme.as_str(), "mls-rfc9420");
    assert_eq!(
        encrypted.payload.content_type,
        "application/vnd.contrix.message+json"
    );

    let decrypted = bob.decrypt_or_preserve(encrypted).unwrap();
    let contrix_sdk::MessageCryptoDecrypt::Plaintext { plaintext, .. } = decrypted else {
        panic!("joined device should decrypt protocol MLS payload");
    };
    assert_eq!(plaintext, br#"{"msgtype":"m.text","body":"hello via MLS"}"#);
}
