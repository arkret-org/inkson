#![cfg(not(target_arch = "wasm32"))]

use chrono::Utc;
use inkson::account_data::{
    ContactRemark, RealmRemark, contact_remark_account_data_key, realm_remark_account_data_key,
};
use inkson::api_error::{TransportClientError, decode_arkret_error, is_auth_expired_error};
use inkson::config::{ClientConfig, LocalConfigStore};
use inkson::models::{
    missing_event_envelope_write_requirements, missing_v1_station_requirements,
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

fn service_resolution(did: &str) -> serde_json::Value {
    json!({
        "did": did,
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

#[test]
fn inkson_accepts_server_contract_payloads() {
    let describe = parse_server_description(json!({
        "service_id": "ak:did_core:web:server.local",
        "service_resolution": service_resolution("did:web:server.local"),
        "trust_domain": "ak:trust_domain:server.local",
        "service_kind": "station",
        "protocol_version": "1.0",
        "supported_profiles": ["ak.profile.core_event_store.v1"],
        "supported_operation_bundles": [
            "ak.operation_bundle.station.describe.v1",
            "ak.operation_bundle.station.http_core.v1"
        ],
        "transport_bindings": [{
            "kind": "http_json",
            "base_url": "https://server.local/_arkret",
            "extension_profile_required": null
        }],
        "supported_features": [],
        "auth_metadata": {},
        "limits": {"x_storage": "memory", "x_max_limit": 100},
        "rate_limit_policy": {},
        "plaintext_visibility": {"data_classes": [], "max_visibility": "none"},
        "verified_profiles": [],
        "interop_surfaces": [],
        "development_mode": true,
    }))
    .unwrap();
    assert_eq!(describe.service_kind, arkret_sdk::ServiceKind::Station);
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
        "service_kind": "station",
        "protocol_version": "1.0",
        "supported_profiles": ["ak.profile.minimal_client.v1"],
        "supported_operation_bundles": [
            "ak.operation_bundle.station.describe.v1",
            "ak.operation_bundle.station.http_core.v1"
        ],
        "transport_bindings": [],
        "supported_features": [],
        "auth_metadata": {},
        "limits": {},
        "plaintext_visibility": {"data_classes": [], "max_visibility": "none"},
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
        "auth_metadata": {},
        "limits": {},
        "plaintext_visibility": {},
        "rate_limit_policy": {},
        "verified_profiles": [],
        "interop_surfaces": [],
        "development_mode": false,
        "resource_kinds": ["realm"]
    }))
    .unwrap();
    assert_eq!(
        directory.service_kind,
        arkret_sdk::ServiceKind::DirectoryService
    );

    let authz: inkson::models::AuthzCheckOutcome = serde_json::from_value(json!({
        "decision": "allow",
        "reason_code": null,
        "matched_grants": [{"actor_id": "ak:did_core:web:alice.example"}],
        "obligations": []
    }))
    .unwrap();
    assert_eq!(authz.decision, arkret_wire::AuthzDecision::Allow);

    // `GrantList` is the SDK authoritative wire type. Every row binds the
    // canonical grant and its exact current-result revision atomically.
    let grants: inkson::models::GrantList = serde_json::from_value(json!({
        "grants": [{
            "grant": {
                "id": "ak:grant:AfpU2UOijpNUdGOoAgQdaqV0xwreLXwLE3yXXHvB6n7X",
                "schema": arkret_wire::SchemaId::CAPABILITY_V1,
                "realm_id": "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                "issuer_id": {
                    "kind": "account",
                    "account_id": {
                        "principal_id": "ak:did_core:web:server.local",
                        "station_id": "ak:did_core:web:server.local"
                    }
                },
                "subject": {
                    "kind": "account",
                    "account_id": {
                        "principal_id": "ak:did_core:web:alice.example",
                        "station_id": "ak:did_core:web:server.local"
                    }
                },
                "issuer_authority_refs": [{
                    "kind": "realm_root",
                    "realm_id": "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                    "authority_event_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                    "authority_generation": 0,
                }],
                "authority_depth": 0,
                "authority_root_refs": [{
                    "kind": "realm_root",
                    "realm_id": "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                    "authority_event_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                    "authority_generation": 0
                }],
                "actions": ["ak.message.create"],
                "status": "active",
                "resources": [
                    {"kind": "realm", "realm_id": "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"}
                ],
                "issued_at": "2026-04-28T12:00:00.000Z"
            },
            "revision": {
                "commit_id": "ak:realm_commit:AT33EWBTXdTx5CjY-ogbIIF2T4vh-v7jCMCQ80Fss2Rq",
                "stream_position": 2
            }
        }],
        "state_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "evaluated_at": "2026-04-28T12:00:00.000Z"
    }))
    .unwrap();
    assert_eq!(grants.grants.len(), 1);
    assert_eq!(grants.grants[0].grant.issuer_authority_refs.len(), 1);
    assert_eq!(grants.grants[0].revision.stream_position, 2);

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
        "one_time_keys": [{
            "account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": "ak:did_core:web:server.local"
            },
            "device_keys": {
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
        }],
        "failures": []
    }))
    .unwrap();
    assert!(!claimed.one_time_keys.is_empty());

    let device_send: inkson::models::DeviceMessagesSendOutcome = serde_json::from_value(json!({
        "delivered": {},
        "unknown_devices": {}
    }))
    .unwrap();
    assert!(device_send.delivered.is_empty());

    // SDK shape: the to-device queue field is `messages`, not the old `events`.
    let device_receive: inkson::models::DeviceMessagesGetOutcome = serde_json::from_value(json!({
        "messages": [],
        "next_cursor": "ak:cursor:device-messages",
        "has_more": false,
        "limited": false
    }))
    .unwrap();
    assert_eq!(device_receive.limited, Some(false));

    let push: inkson::models::PushRegisterDeviceOutcome = serde_json::from_value(json!({
        "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
        "registration_id": "push:dev_alice",
        "expires_at": null
    }))
    .unwrap();
    assert_eq!(push.registration_id.as_deref(), Some("push:dev_alice"));

    let ok: inkson::models::OkOutcome = serde_json::from_value(json!({"ok": true})).unwrap();
    assert!(ok.ok);

    // The content-addressed `blob_ref` is the sole carrier of the content
    // digest; the outcome and its receipt carry no sibling `content_digest`
    // (`conformance/encoding.md` §4.0.1).
    let blob_digest = format!("sha256:{}", "ab".repeat(32));
    let blob: inkson::models::BlobUploadOutcome = serde_json::from_value(json!({
        "blob_ref": format!("ak:blob:{blob_digest}"),
        "size_bytes": 23,
        "media_type": "application/octet-stream",
        "upload_receipt": {
            "blob_ref": format!("ak:blob:{blob_digest}"),
            "size_bytes": 23,
            "received_at": "2026-04-28T12:00:00.000Z",
            "issuer_id": "ak:did_core:web:server.local",
            "signature": {
                "kid": "ak:did_core:web:server.local",
                "signature_algorithm": "Ed25519",
                "sig": "c2ln"
            }
        }
    }))
    .unwrap();
    assert_eq!(blob.size_bytes, 23);
    assert_eq!(blob.blob_ref.as_str(), format!("ak:blob:{blob_digest}"));
    assert!(
        serde_json::from_value::<inkson::models::BlobUploadOutcome>(json!({
            "blob_ref": format!("ak:blob:{blob_digest}"),
            "size_bytes": 23,
            "content_digest": blob_digest
        }))
        .is_err()
    );

    // SDK spec shape: status is `submitted`, and routed_to_ids carries principal cores.
    let report: inkson::models::ModerationReportOutcome = serde_json::from_value(json!({
        "report_id": "ak:report:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
        "status": "submitted",
        "routed_to_ids": ["ak:did_core:web:server.local"]
    }))
    .unwrap();
    assert_eq!(report.status, arkret_sdk::ModerationReportStatus::Submitted);
    assert_eq!(report.routed_to_ids.len(), 1);
    assert_eq!(
        report.routed_to_ids[0].as_str(),
        "ak:did_core:web:server.local"
    );

    let error = decode_arkret_error(
        StatusCode::CONFLICT,
        &problem_bytes(
            StatusCode::CONFLICT,
            "expected_head_mismatch",
            "expected_head mismatch",
        ),
    );
    assert_eq!(error.code(), "expected_head_mismatch");
    assert_eq!(error.detail, "expected_head mismatch");
}

#[test]
fn server_description_gates_event_envelope_write_plane() {
    let events_ready = parse_server_description(json!({
        "service_id": "ak:did_core:web:soland.local",
        "service_resolution": service_resolution("did:web:soland.local"),
        "trust_domain": "ak:trust_domain:soland.local",
        "service_kind": "station",
        "protocol_version": "1.0",
        "supported_profiles": [
            "ak.profile.core_event_store.v1",
            "ak.profile.station_events_api.v1"
        ],
        "supported_operation_bundles": [
            "ak.operation_bundle.station.describe.v1",
            "ak.operation_bundle.station.http_core.v1"
        ],
        "transport_bindings": [{
            "kind": "http_json",
            "base_url": "https://soland.local/_arkret",
            "extension_profile_required": null
        }],
        "supported_features": [],
        "auth_metadata": {},
        "limits": {},
        "plaintext_visibility": {"data_classes": [], "max_visibility": "none"},
        "verified_profiles": [],
        "interop_surfaces": [],
        "development_mode": true,
    }))
    .unwrap();
    assert!(service_supports_event_envelope_write_plane(&events_ready));
    assert!(missing_v1_station_requirements(&events_ready).is_empty());
    assert!(missing_event_envelope_write_requirements(&events_ready).is_empty());

    // `service-describe.schema.json` closes the interop-surface object
    // (`additionalProperties: false`) precisely so a product-private route root
    // cannot be smuggled in through extension keys, so the free-form
    // `base_path` / `status` members the pre-v1 fixture attached no longer
    // exist. `notes` is the one free-text member left.
    let external_interop_surface = serde_json::to_value(
        arkret_sdk::InteropSurfaceEntry::external_interop("external_mimi_provider")
            .with_notes("external interop surfaces must not redefine station routes"),
    )
    .unwrap();
    let described_with_external_interop_surface = parse_server_description(json!({
        "service_id": "ak:did_core:web:local.host",
        "service_resolution": service_resolution("did:web:local.host"),
        "trust_domain": "ak:trust_domain:local.host",
        "service_kind": "station",
        "protocol_version": "1.0",
        "supported_profiles": [
            "ak.profile.core_event_store.v1",
            "ak.profile.station_events_api.v1"
        ],
        "supported_operation_bundles": [
            "ak.operation_bundle.station.describe.v1",
            "ak.operation_bundle.station.http_core.v1"
        ],
        "transport_bindings": [{
            "kind": "http_json",
            "base_url": "https://local.host/_arkret",
            "extension_profile_required": null
        }],
        "supported_features": [],
        "auth_metadata": {},
        "limits": {"x_storage": "postgres"},
        "plaintext_visibility": {"data_classes": [], "max_visibility": "none"},
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

    // A partial describe payload now fails to deserialize at all —
    // the SDK type is strict per `service-describe.schema.json`, so inkson
    // can no longer accept a stripped-down describe and flag it post-hoc.
    // This is the spec-correct fail-closed behaviour for v1.
    assert!(
        parse_server_description(json!({
            "service_id": "ak:did_core:web:minimal.local",
            "service_kind": "station",
            "protocol_version": "1.0",
            "supported_profiles": [],
            "supported_operation_bundles": [
                "ak.operation_bundle.station.describe.v1",
                "ak.operation_bundle.station.websocket.v1"
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
        "service_kind": "station",
        "protocol_version": "1.0",
        "supported_profiles": [],
        "supported_operation_bundles": [
            "ak.operation_bundle.station.agent_pairing_handoff.v1",
            "ak.operation_bundle.station.describe.v1"
        ],
        "transport_bindings": [{
            "kind": "http_json",
            "base_url": "https://minimal.local/_arkret",
            "extension_profile_required": null
        }],
        "supported_features": [],
        "auth_metadata": {},
        "limits": {},
        "plaintext_visibility": {"data_classes": [], "max_visibility": "none"},
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
            "ak.self.events.command.submit.v1"
        ]
    );
    // `plaintext_visibility` is now present + non-null, so it falls out of
    // the missing list; only the event write requirements remain.
    assert_eq!(
        missing_v1_station_requirements(&events_missing),
        vec![
            "ak.profile.core_event_store.v1",
            "ak.self.events.command.submit.v1",
        ]
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
    inkson::operation::set_authoring_station_id(Some(
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
        realms: vec![arkret_models_discovery::PublicRealmDirectoryEntry {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            )
            .unwrap(),
            public_metadata: arkret_models_discovery::PublicRealmMetadata {
                display_name: "Contract Realm".to_owned(),
                summary: Some("Public description".to_owned()),
                public_locator: None,
                avatar_blob_ref: None,
            },
            indexed_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(1),
        }],
        next_cursor: None,
        has_more: false,
    };
    directory.validate().unwrap();
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
        decoded.extensions["cell"],
        "ak:cell:ak.component.strand.position.v1:demo"
    );

    let fallback = decode_arkret_error(StatusCode::SERVICE_UNAVAILABLE, b"<html>busy</html>");
    assert_eq!(fallback.code(), "http_status");
    assert!(fallback.detail.contains("503"));
}

#[test]
fn authoring_fixture_uses_distinct_canonical_creation_times() {
    let first = common::pinned_created_at(1);
    let later = common::pinned_created_at(16);
    assert_eq!((later - first).num_milliseconds(), 15);
    assert_eq!(
        arkret_sdk::canonical::format_timestamp_canonical(first),
        "2026-09-19T00:00:00.001Z"
    );
}
