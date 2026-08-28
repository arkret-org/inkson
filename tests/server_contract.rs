#![cfg(not(target_arch = "wasm32"))]

use chrono::Utc;
use inkson::account_data::{
    ContactRemark, RealmRemark, contact_remark_account_data_key, realm_remark_account_data_key,
};
use inkson::api_error::{TransportClientError, decode_arkret_error, is_auth_expired_error};
use inkson::config::{ClientConfig, LocalConfigStore};
use inkson::models::{
    missing_event_envelope_write_requirements, missing_v1_principal_server_requirements,
    service_supports_event_envelope_write_plane,
};
use inkson::operation::TypedOperationBuilder;

mod common;
use inkson::push::validate_blind_wakeup_payload;
use reqwest::StatusCode;
use serde_json::json;

fn parse_server_description(
    value: serde_json::Value,
) -> anyhow::Result<inkson::models::ServiceDescribe> {
    Ok(serde_json::from_value(value)?)
}

fn snapshot_contract_event_id(suffix: &str) -> arkret_sdk::EventId {
    let seed = u8::from_str_radix(&suffix[suffix.len() - 2..], 16).unwrap();
    arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [seed; 32])
}

fn snapshot_contract_hash(seed: u8) -> arkret_sdk::Hash {
    arkret_sdk::Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).unwrap()
}

fn service_resolution(full_id: &str) -> serde_json::Value {
    json!({
        "full_id": full_id,
        "method_history_head": "sha256:fixture",
        "version_id": "fixture-v1"
    })
}

fn problem_bytes(status: StatusCode, code: &str, detail: &str) -> Vec<u8> {
    serde_json::to_vec(
        &arkret_sdk::Problem::new(code, status.as_u16(), detail)
            .with_instance("ak:request:server-contract"),
    )
    .unwrap()
}

fn snapshot_contract_manifest_payload() -> serde_json::Value {
    let snapshot_id =
        arkret_sdk::SnapshotId::new("ak:snapshot:01904100-0000-7000-8000-0000000000cc").unwrap();
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:AeI0Z4D734iPt9RpF51PAg0CRjLSQmxPqv9NgUmBJiQi").unwrap();
    let service_id = arkret_sdk::DidCoreId::new("ak:did_core:web:server.local").unwrap();
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
        arkret_sdk::CORE_REDUCER_PROFILE,
        items,
        4096,
    )
    .unwrap();
    let created_at = Utc::now();
    let mut manifest = arkret_sdk::SnapshotManifest {
        id: snapshot_id,
        realm_id,
        reducer_profile: arkret_sdk::CORE_REDUCER_PROFILE.to_owned(),
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
            actor_seq_ranges: Vec::new(),
        },
        chunks: built.into_iter().map(|chunk| chunk.descriptor).collect(),
        security_class: arkret_sdk::SnapshotSecurityClass::Standard,
        verification_hints: None,
        created_by: service_id.clone(),
        created_at,
        authority_binding: arkret_sdk::AuthorityBinding {
            authority_kind: arkret_sdk::SnapshotAuthorityKind::RealmPolicySnapshotIssuer,
            auth_state_digest: snapshot_contract_hash(1),
            auth_frontier: vec![snapshot_contract_event_id("0000000000c1")],
            checked_at: created_at,
            witness_attestations: Vec::new(),
        },
        signature: arkret_sdk::DetachedJwsProof::ed25519(
            arkret_sdk::DidUrl::new("did:web:server.local#snapshot").unwrap(),
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
        "service_id": "ak:did_core:web:server.local",
        "service_resolution": service_resolution("did:web:server.local"),
        "trust_domain": "ak:trust_domain:server.local",
        "service_kind": "principal_server",
        "protocol_version": "1.0",
        "supported_profiles": ["ak.profile.core_event_store.v1"],
        "supported_operation_bundles": [
            "ak.operation_bundle.principal_server.describe.v1",
            "ak.operation_bundle.principal_server.http_core.v1"
        ],
        "transport_bindings": [{
            "kind": "http_json",
            "base_url": "https://server.local/_arkret",
            "extension_profile_required": null
        }],
        "supported_features": [],
        "supported_reducer_profiles": ["ak.reducer.core.v1"],
        "auth_metadata": {"mode": "development"},
        "limits": {"storage": "memory", "max_limit": 100},
        "rate_limit_policy": {},
        "plaintext_visibility": {"data_classes": [], "max_visibility": "none"},
        "claimed_profiles": [],
        "verified_profiles": [],
        "interop_surfaces": [],
        "development_mode": true,
    }))
    .unwrap();
    assert_eq!(
        describe.service_kind,
        arkret_sdk::ServiceKind::PrincipalServer
    );
    assert!(describe.supports_operation(arkret_sdk::ServiceOperationId::SelfAuthzReadCheckV1));
    assert_eq!(
        describe.transport_bindings[0].base_url(),
        "https://server.local/_arkret"
    );

    let mut identity = describe.clone();
    identity.service_kind = arkret_sdk::ServiceKind::IdentityRegistry;
    identity.supported_operation_bundles =
        vec!["ak.operation_bundle.identity_registry.describe.v1".to_owned()];
    identity
        .validate()
        .expect("identity describe uses canonical ServiceDescribe");

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
        "service_id": "ak:did_core:web:server.local",
        "service_resolution": service_resolution("did:web:server.local"),
        "trust_domain": "ak:trust_domain:server.local",
        "service_kind": "principal_server",
        "protocol_version": "1.0",
        "supported_profiles": ["ak.profile.minimal_client.v1"],
        "supported_operation_bundles": [
            "ak.operation_bundle.principal_server.describe.v1",
            "ak.operation_bundle.principal_server.http_core.v1"
        ],
        "transport_bindings": [],
        "supported_features": [],
        "auth_metadata": {"mode": "development"},
        "limits": {},
        "plaintext_visibility": {"data_classes": [], "max_visibility": "none"},
        "claimed_profiles": [],
        "verified_profiles": [],
        "interop_surfaces": [],
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
            "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk": {
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
            .contains_key("ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk")
    );

    let directory: inkson::models::ServiceDescribe = serde_json::from_value(json!({
        "service_id": "ak:did_core:web:server.local",
        "service_resolution": service_resolution("did:web:server.local"),
        "trust_domain": "ak:trust_domain:server.local",
        "service_kind": "directory_service",
        "protocol_version": "1.0",
        "supported_profiles": [],
        "supported_operation_bundles": [
            "ak.operation_bundle.directory_service.describe.v1",
            "ak.operation_bundle.directory_service.http_core.v1"
        ],
        "transport_bindings": [{
            "kind": "http_json",
            "base_url": "https://directory.local/_arkret/find/directory",
            "extension_profile_required": null
        }],
        "supported_features": [],
        "auth_metadata": {"mode": "public_no_auth"},
        "limits": {},
        "plaintext_visibility": {},
        "rate_limit_policy": {},
        "claimed_profiles": [],
        "verified_profiles": [],
        "interop_surfaces": [],
        "development_mode": false,
        "resource_kinds": ["realm", "organization", "actor"],
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
        directory.service_kind,
        arkret_sdk::ServiceKind::DirectoryService
    );

    let resolved: inkson::models::DirectoryRealmResolutionOutcome = serde_json::from_value(json!({
        "realm_preview": {
            "realm_id": "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk",
            "title": "Arkret Demo Realm",
            "summary": "Shared demo Realm served by server",
            "tags": ["demo"],
            "public": true,
            "category": "collaboration",
            "as_of": "2026-05-30T00:00:00.000Z",
            "source_refs": ["ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"],
            "policy_revision": "contract-rev"
        },
        "stripped_state": [],
        "join_rule": "public",
        "join_candidates": [{
            "realm_id": "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk",
            "service_id": "ak:did_core:web:server.local",
            "service_resolution": {
                "current_record_url": "https://server.local/_arkret/open/services/ak%3Adid_core%3Aweb%3Aserver.local/resolution"
            },
            "service_kind": "principal_server",
            "role": "joined_member_principal_server",
            "endpoint": "http://server",
            "operations": ["ak.peer.events.command.submit.v1"],
            "join_methods": ["invite_accept", "member_join"],
            "encryption_profile": "mls_rfc9420",
            "digest_algorithm": "sha256",
            "priority": 0,
            "source": "member_delivery_binding",
            "seal_basis": {
                "leaves": ["ak:seal:sha256:1111111111111111111111111111111111111111111111111111111111111111"]
            },
            "as_of": "2026-05-30T00:00:00.000Z",
            "expires_at": "2099-01-01T00:00:00.000Z"
        }]
    }))
    .unwrap();
    assert_eq!(resolved.join_rule, Some(arkret_sdk::JoinRule::Public));
    assert_eq!(
        resolved.join_candidates[0].service_id.as_str(),
        "ak:did_core:web:server.local"
    );

    let submit: inkson::models::SubmitEventResult = serde_json::from_value(json!({
        "status": "accepted",
        "pending_delivery_count": 0,
        "accepted": ["ak:event:AVH7487ydDzo_3WXy2IlHWvtBeElcucZHd5d5hYKcjZl"],
        "duplicate": [],
        "rejected": [],
        "realm_actor_frontiers": [],
        "realm_frontiers": [],
        "cursor": "sx:1760000000000"
    }))
    .unwrap();
    assert_eq!(submit.status, arkret_sdk::EventsSubmitStatus::Accepted);
    assert_eq!(
        submit.event_id,
        "ak:event:AVH7487ydDzo_3WXy2IlHWvtBeElcucZHd5d5hYKcjZl"
    );
    assert_eq!(submit.cursor, "sx:1760000000000");

    let snapshot_head: arkret_sdk::SnapshotManifest =
        serde_json::from_value(snapshot_contract_manifest_payload()).unwrap();
    assert_eq!(
        snapshot_head.reducer_profile,
        arkret_sdk::CORE_REDUCER_PROFILE
    );
    assert_eq!(
        snapshot_head.created_by.as_str(),
        "ak:did_core:web:server.local"
    );
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
    assert_eq!(authz.decision, arkret_wire::AuthzDecision::Allow);

    // `GrantList` is the SDK authoritative wire type (soland serialises it
    // verbatim), so rows must be full canonical capability grants rather than
    // free-form objects.
    let grants: inkson::models::GrantList = serde_json::from_value(json!({
        "grants": [{
            "id": "ak:grant:AfpU2UOijpNUdGOoAgQdaqV0xwreLXwLE3yXXHvB6n7X",
            "schema": arkret_wire::SchemaId::CAPABILITY_V1,
            "realm_id": "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
            "issuer": "ak:did_core:web:server.local",
            "issuer_principal_server_id": "ak:did_core:web:server.local",
            "subject": "ak:did_core:web:alice.example",
            "subject_principal_server_id": "ak:did_core:web:server.local",
            "issuer_authority_refs": [{
                "kind": "realm_root",
                "realm_id": "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                "controller_epoch_at_issuance": 0,
                "authority_generation": 0
            }],
            "actions": ["ak.message.create"],
            "resources": [
                {"kind": "realm", "realm_id": "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"}
            ],
            "issued_at": "2026-04-28T12:00:00.000Z"
        }],
        "state_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "evaluated_at": "2026-04-28T12:00:00.000Z"
    }))
    .unwrap();
    assert_eq!(grants.grants.len(), 1);
    assert_eq!(grants.grants[0].issuer_authority_refs.len(), 1);

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
                            "signature_algorithm": "Ed25519",
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
        "delivered": {"did:web:alice.example": ["dev_alice"]},
        "unknown_devices": {}
    }))
    .unwrap();
    assert_eq!(
        device_send.delivered["did:web:alice.example"],
        json!(["dev_alice"])
    );

    // SDK shape: the to-device queue field is `messages`, not the old `events`.
    let device_receive: inkson::models::DeviceMessagesGetOutcome = serde_json::from_value(json!({
        "messages": [],
        "next_cursor": "ak:cursor:device-messages",
        "limited": false
    }))
    .unwrap();
    assert!(!device_receive.limited);

    let push: inkson::models::PushRegisterDeviceOutcome = serde_json::from_value(json!({
        "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
        "registration_id": "push:dev_alice",
        "expires_at": null
    }))
    .unwrap();
    assert_eq!(push.registration_id.as_deref(), Some("push:dev_alice"));

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
            "issuer_service_id": "ak:did_core:web:server.local",
            "signature": {
                "kid": "ak:did_core:web:server.local",
                "signature_algorithm": "Ed25519",
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

    // SDK spec shape: status is `submitted`, and routed_to carries principal cores.
    let report: inkson::models::ModerationReportOutcome = serde_json::from_value(json!({
        "report_id": "ak:report:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
        "status": "submitted",
        "routed_to": ["ak:did_core:web:server.local"]
    }))
    .unwrap();
    assert_eq!(report.status, arkret_sdk::ModerationReportStatus::Submitted);
    assert_eq!(report.routed_to.len(), 1);
    assert_eq!(report.routed_to[0].as_str(), "ak:did_core:web:server.local");

    let error = decode_arkret_error(
        StatusCode::CONFLICT,
        &problem_bytes(
            StatusCode::CONFLICT,
            "expected_head_mismatch",
            "expected_head mismatch",
        ),
    );
    assert_eq!(error.code(), "expected_head_mismatch");
    assert_eq!(error.message(), "expected_head mismatch");
}

#[test]
fn server_description_gates_event_envelope_write_plane() {
    let events_ready = parse_server_description(json!({
        "service_id": "ak:did_core:web:soland.local",
        "service_resolution": service_resolution("did:web:soland.local"),
        "trust_domain": "ak:trust_domain:soland.local",
        "service_kind": "principal_server",
        "protocol_version": "1.0",
        "supported_profiles": [
            "ak.profile.core_event_store.v1",
            "ak.profile.principal_server_events_api.v1"
        ],
        "supported_operation_bundles": [
            "ak.operation_bundle.principal_server.describe.v1",
            "ak.operation_bundle.principal_server.http_core.v1"
        ],
        "transport_bindings": [{
            "kind": "http_json",
            "base_url": "https://soland.local/_arkret",
            "extension_profile_required": null
        }],
        "supported_features": [],
        "auth_metadata": {"mode": "development"},
        "limits": {},
        "plaintext_visibility": {"data_classes": [], "max_visibility": "none"},
        "claimed_profiles": [],
        "verified_profiles": [],
        "interop_surfaces": [],
        "development_mode": true,
    }))
    .unwrap();
    assert!(service_supports_event_envelope_write_plane(&events_ready));
    assert!(missing_v1_principal_server_requirements(&events_ready).is_empty());
    assert!(missing_event_envelope_write_requirements(&events_ready).is_empty());

    // `service-describe.schema.json` closes the interop-surface object
    // (`additionalProperties: false`) precisely so a product-private route root
    // cannot be smuggled in through extension keys, so the free-form
    // `base_path` / `status` members the pre-v1 fixture attached no longer
    // exist. `notes` is the one free-text member left.
    let external_interop_surface = serde_json::to_value(
        arkret_sdk::InteropSurfaceEntry::external_interop("external_mimi_provider")
            .with_notes("external interop surfaces must not redefine principal-server routes"),
    )
    .unwrap();
    let described_with_external_interop_surface = parse_server_description(json!({
        "service_id": "ak:did_core:web:local.host",
        "service_resolution": service_resolution("did:web:local.host"),
        "trust_domain": "ak:trust_domain:local.host",
        "service_kind": "principal_server",
        "protocol_version": "1.0",
        "supported_profiles": [
            "ak.profile.core_event_store.v1",
            "ak.profile.principal_server_events_api.v1"
        ],
        "supported_operation_bundles": [
            "ak.operation_bundle.principal_server.describe.v1",
            "ak.operation_bundle.principal_server.http_core.v1"
        ],
        "transport_bindings": [{
            "kind": "http_json",
            "base_url": "https://local.host/_arkret",
            "extension_profile_required": null
        }],
        "supported_features": [],
        "auth_metadata": {"mode": "development"},
        "limits": {"storage": "postgres"},
        "plaintext_visibility": {"data_classes": [], "max_visibility": "none"},
        "claimed_profiles": [
            {
                "profile_id": "ak.profile.core_event_store.v1",
                "claim_kind": "self_claimed"
            }
        ],
        "verified_profiles": [],
        "interop_surfaces": [external_interop_surface],
        "development_mode": true,
    }))
    .unwrap();
    assert_eq!(
        described_with_external_interop_surface.interop_surfaces[0].name,
        "external_mimi_provider"
    );
    // And the closure is load-bearing: an entry that carries its own route root
    // as an extension key MUST NOT parse.
    assert!(
        serde_json::from_value::<arkret_sdk::InteropSurfaceEntry>(json!({
            "name": "external_mimi_provider",
            "kind": "external_interop",
            "base_path": "https://mimi.example.com/_arkret/open/mimi"
        }))
        .is_err()
    );

    // A partial / pre-v2 describe payload now fails to deserialize at all —
    // the SDK type is strict per `service-describe.schema.json`, so inkson
    // can no longer accept a stripped-down describe and flag it post-hoc.
    // This is the spec-correct fail-closed behaviour for v2.
    assert!(
        parse_server_description(json!({
            "service_id": "ak:did_core:web:minimal.local",
            "service_kind": "principal_server",
            "protocol_version": "1.0",
            "supported_profiles": [],
            "supported_operation_bundles": [
                "ak.operation_bundle.principal_server.describe.v1",
                "ak.operation_bundle.principal_server.websocket.v1"
            ],
            "supported_features": []
        }))
        .is_err()
    );

    // A complete payload that still omits the event write requirements is
    // accepted by the SDK parser but flagged by the inkson helpers.
    let events_missing = parse_server_description(json!({
        "service_id": "ak:did_core:web:minimal.local",
        "service_resolution": service_resolution("did:web:minimal.local"),
        "trust_domain": "ak:trust_domain:minimal.local",
        "service_kind": "principal_server",
        "protocol_version": "1.0",
        "supported_profiles": [],
        "supported_operation_bundles": [
            "ak.operation_bundle.principal_server.agent_pairing_handoff.v1",
            "ak.operation_bundle.principal_server.describe.v1"
        ],
        "transport_bindings": [{
            "kind": "http_json",
            "base_url": "https://minimal.local/_arkret",
            "extension_profile_required": null
        }],
        "supported_features": [],
        "auth_metadata": {"mode": "development"},
        "limits": {},
        "plaintext_visibility": {"data_classes": [], "max_visibility": "none"},
        "claimed_profiles": [],
        "verified_profiles": [],
        "interop_surfaces": [],
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
            "ak.self.events.read.describe.v1",
            "ak.self.events.command.submit.v1"
        ]
    );
    // `plaintext_visibility` is now present + non-null, so it falls out of
    // the missing list; only the event write requirements remain.
    assert_eq!(
        missing_v1_principal_server_requirements(&events_missing),
        vec![
            "ak.profile.core_event_store.v1",
            "ak.self.events.read.describe.v1",
            "ak.self.events.command.submit.v1",
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
            "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-": {
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
            .contains_key("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-")
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
        realm_remark_account_data_key("ak:realm:AWBsC7hBNqnZ5M_TybXfFGKJokXyNzSLp3vORrEQnNLE"),
        "ak.contacts.realm.ak:realm:AWBsC7hBNqnZ5M_TybXfFGKJokXyNzSLp3vORrEQnNLE"
    );
    let namespace_key: Vec<u8> = (0u8..=31).collect();
    let principal_id = arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
    assert_eq!(
        contact_remark_account_data_key(&namespace_key, &principal_id).unwrap(),
        "ak.contacts.actor.pD0U2utjPMaXROrStCFHbCtquoTSVsA7mo9nVniePkY"
    );
}

#[test]
fn local_remarks_do_not_leak_into_event_push_search_log_or_directory_surfaces() {
    inkson::operation::set_authoring_principal_server_id(Some(
        arkret_sdk::DidCoreId::new("ak:did_core:web:server.local").unwrap(),
    ));
    fn assert_no_secret<T: serde::Serialize>(label: &str, value: &T, secret: &str) {
        let wire = serde_json::to_string(value).unwrap();
        assert!(
            !wire.contains(secret),
            "{label} leaked private remark secret: {wire}"
        );
    }

    let secret = "Alice from Ops Private";
    let contact_remark = ContactRemark::new(
        arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        secret,
        chrono::Utc::now(),
    );
    assert_eq!(contact_remark.petname, secret);
    let realm_id = "ak:realm:ATEG2QCavtpxeXB5vkEeQqzkPjtieb9NlGtUvdteawYZ";
    let mut realm_remark = RealmRemark::new(
        arkret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
        chrono::Utc::now(),
    );
    realm_remark.local_name = secret.to_owned();

    let event = TypedOperationBuilder::new::<arkret_sdk::event_spec::MessageCreate>(
        realm_id,
        "did:web:local.example",
        arkret_sdk::MessageCreatePayload::with_content(
            arkret_sdk::StrandId::new(
                "ak:strand:ATNFZ7OyO1sA-yc6npfN39mg4TRii1-srFlAECgEuwdk".to_owned(),
            )
            .unwrap(),
            "discussion",
            arkret_sdk::ContentBlock::text("hello"),
        ),
    )
    .build("contract-test");
    // The leak check runs over what actually leaves the device, which is the
    // authored envelope.
    assert_no_secret("event", &common::author(event), secret);

    let blind_push = json!({
        "type": "ak.push.blind_wakeup.v1",
        "reason": "background_sync_needed"
    });
    validate_blind_wakeup_payload(&blind_push).unwrap();
    validate_blind_wakeup_payload(&json!({"local_name": secret}))
        .expect_err("blind push must reject local remark fields");
    validate_blind_wakeup_payload(&json!({"petname": secret}))
        .expect_err("blind push must reject contact petnames");

    let search = inkson::models::IndexSearchView {
        query: "hello".to_owned(),
        results: vec![json!({
            "kind": "message",
            "space_id": "ak:space:contract",
            "actor_id": "ak:did_core:web:alice.example",
            "content": {"body": "hello"}
        })],
        next_cursor: None,
    };
    assert_no_secret("search", &search, secret);

    let directory = arkret_models_discovery::DirectoryRealmSearchOutcome {
        realms: vec![arkret_models_discovery::RealmPreview {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
            )
            .unwrap(),
            alias: None,
            title: Some("Contract Realm".to_owned()),
            avatar_blob_ref: None,
            organization_principal_id: None,
            join_rule: Some("public".to_owned()),
            member_count_bucket: Some(arkret_models_discovery::RealmMemberCountBucket::Bucket(
                arkret_models_discovery::RealmMemberCountBucketLabel::OneToTen,
            )),
            summary: Some("Public description".to_owned()),
            owning_organizations: Vec::new(),
            preview_ref: None,
            discoverability: Some("public".to_owned()),
            history_access: None,
            join_candidates: Vec::new(),
            as_of: Utc::now(),
            source_refs: vec!["ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1".to_owned()],
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
fn inkson_config_store_preserves_signed_out_state_without_placeholder_identity() {
    let mut store = LocalConfigStore::default();
    let config = ClientConfig::default();

    store.save(config.clone());

    let loaded = store.load();
    assert!(loaded.active_account.is_none());
    assert!(loaded.session_credential.is_empty());
}

// (Move/Seal pipeline tests removed — all writes now go through
// ak.self.events.command.submit.v1; the SubmitEventResult decoder is exercised by
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
        let body = problem_bytes(StatusCode::UNAUTHORIZED, code, "unknown token");
        let envelope: anyhow::Error = TransportClientError {
            status: StatusCode::UNAUTHORIZED,
            error: decode_arkret_error(StatusCode::UNAUTHORIZED, &body),
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
            &problem_bytes(StatusCode::UNAUTHORIZED, "rate_limited", "slow down"),
        ),
    }
    .into();
    assert!(!is_auth_expired_error(&unrelated));
}

/// Regression: `decode_arkret_error` accepts the single canonical Problem
/// shape and synthesises a stable `http_status` envelope when it does not
/// match. A regression here silently degrades every error message in the UI.
#[test]
fn decoder_handles_problem_and_non_problem() {
    let problem = serde_json::to_vec(
        &arkret_sdk::Problem::new(
            "expected_head_mismatch",
            StatusCode::CONFLICT.as_u16(),
            "head mismatch",
        )
        .with_instance("ak:request:server-contract")
        .with_extension("retry_after_ms", json!(250))
        .with_extension(
            "cell",
            json!("ak:cell:ak.component.strand.position.v1:demo"),
        ),
    )
    .unwrap();
    let decoded = decode_arkret_error(StatusCode::CONFLICT, &problem);
    assert_eq!(decoded.code(), "expected_head_mismatch");
    assert_eq!(decoded.retry_after_ms(), Some(250));
    assert_eq!(
        decoded.details()["cell"],
        "ak:cell:ak.component.strand.position.v1:demo"
    );

    let fallback = decode_arkret_error(StatusCode::SERVICE_UNAVAILABLE, b"<html>busy</html>");
    assert_eq!(fallback.code(), "http_status");
    assert!(fallback.message().contains("503"));
}
