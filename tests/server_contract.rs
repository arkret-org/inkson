use reqwest::StatusCode;
use serde_json::json;
use yougen::{
    api::{
        ContrixApiError, decode_contrix_error, is_auth_expired_error, parse_directory_describe,
        parse_resolve_space, parse_server_description, parse_sync, parse_sync_describe,
    },
    config::{ClientConfig, LocalConfigStore},
};

#[test]
fn yougen_accepts_server_contract_payloads() {
    let describe = parse_server_description(json!({
        "service_did": "did:web:server.local",
        "service_type": "principal_server",
        "protocol_version": "1.0",
        "supported_profiles": ["cx.schema.core.v1"],
        "supported_features": [
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
        "service_did": "did:web:server.local",
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
        "service_did": "did:web:server.local",
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
            "cx:space:0196419b-0000-7000-8000-000000000000": {
                "summary": {
                    "title": "Contrix Demo Space",
                    "summary": "Shared demo Space served by server",
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
            .contains_key("cx:space:0196419b-0000-7000-8000-000000000000")
    );

    let directory = parse_directory_describe(json!({
        "service_did": "did:web:server.local",
        "resource_types": ["space", "organization", "actor"],
        "discovery_profiles": ["cx.profile.directory.v1"],
        "restricted_query_proof": false
    }))
    .unwrap();
    assert_eq!(directory.discovery_profiles[0], "cx.profile.directory.v1");

    let resolved = parse_resolve_space(json!({
        "space_preview": {
            "space_id": "cx:space:0196419b-0000-7000-8000-000000000000",
            "name": "Contrix Demo Space",
            "description": "Shared demo Space served by server",
            "tags": ["demo"],
            "public": true,
            "category": "collaboration"
        },
        "stripped_state": [],
        "join_rule": "public",
        "via_services": ["did:web:server.local"]
    }))
    .unwrap();
    assert_eq!(resolved.join_rule, "public");

    let submit: yougen::models::SubmitEventResponse = serde_json::from_value(json!({
        "status": "accepted",
        "event_id": "cx:event:019640ca-0000-7000-8000-000000000000",
        "canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "sync_token": "sx:1760000000000",
        "receipt": {
            "service_did": "did:web:server.local"
        }
    }))
    .unwrap();
    assert_eq!(submit.status, "accepted");

    let snapshot: yougen::models::SnapshotHeadResponse = serde_json::from_value(json!({
        "snapshot_ref": "cx:snapshot:cx:space:0196419b-0000-7000-8000-000000000000:head",
        "state_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "frontier": {"space_id": "cx:space:0196419b-0000-7000-8000-000000000000"},
        "signature": {"kid": "did:web:server.local#dev", "alg": "none", "sig": ""}
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
        "upload_receipt": {"service_did": "did:web:server.local"}
    }))
    .unwrap();
    assert_eq!(blob.size, 23);

    let report: yougen::models::ModerationReportResponse = serde_json::from_value(json!({
        "report_id": "cx:report:1760000000000",
        "status": "queued",
        "routed_to": ["did:web:server.local#moderation"]
    }))
    .unwrap();
    assert_eq!(report.status, "queued");

    let error = decode_contrix_error(
        StatusCode::CONFLICT,
        br#"{"ok":false,"error":{"errcode":"expected_head_mismatch","error":"expected_head mismatch","retry_after_ms":null}}"#,
    );
    assert_eq!(error.code(), "expected_head_mismatch");
    assert_eq!(error.message(), "expected_head mismatch");
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

    let events_missing = parse_server_description(json!({
        "service_did": "did:web:minimal.local",
        "service_type": "principal_server",
        "protocol_version": "1.0",
        "supported_profiles": [],
        "supported_operations": ["cx.sync.account"],
        "supported_features": ["sync.account"]
    }))
    .unwrap();
    assert!(!events_missing.supports_event_envelope_write_plane());
    assert_eq!(
        events_missing.missing_event_envelope_write_requirements(),
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
        .create_group(b"cx:space:0196419b-0000-7000-8000-000000000000")
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

// Move/Anchor wire-shape contract tests. These mirror soland's
// `routing::move_anchor` response shapes so a breaking change there is
// caught immediately at the yougen test layer.

#[test]
fn yougen_parses_submit_move_pending_response() {
    let body = json!({
        "move_id": "cx:move:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "state": "pending"
    });
    let parsed: yougen::models::SubmitMoveResponse = serde_json::from_value(body).unwrap();
    assert!(parsed.move_id.starts_with("cx:move:sha256:"));
    assert_eq!(parsed.state, "pending");
    assert!(parsed.reason.is_none());
}

#[test]
fn yougen_parses_submit_move_rejected_response() {
    let body = json!({
        "move_id": "cx:move:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "state": "rejected",
        "reason": "replay_window: HLC signed at 2024-... is too old"
    });
    let parsed: yougen::models::SubmitMoveResponse = serde_json::from_value(body).unwrap();
    assert_eq!(parsed.state, "rejected");
    assert!(parsed.reason.unwrap().contains("replay_window"));
}

#[test]
fn yougen_parses_sign_anchor_published_response() {
    let body = json!({
        "published": true,
        "anchor_id": "cx:anchor:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "accepted_move_ids": [
            "cx:move:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ],
        "rejected_moves": [],
        "post_state_root": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    });
    let parsed: yougen::models::SignAnchorResponse = serde_json::from_value(body).unwrap();
    assert!(parsed.published);
    assert_eq!(parsed.accepted_move_ids.len(), 1);
    assert!(parsed.rejected_moves.is_empty());
    assert!(
        parsed
            .post_state_root
            .as_deref()
            .unwrap()
            .starts_with("sha256:")
    );
}

#[test]
fn yougen_parses_sign_anchor_unpublished_response() {
    // No pending Moves → server returns `published=false` with no
    // anchor fields. Optional fields must deserialize as None.
    let body = json!({"published": false});
    let parsed: yougen::models::SignAnchorResponse = serde_json::from_value(body).unwrap();
    assert!(!parsed.published);
    assert!(parsed.anchor_id.is_none());
    assert!(parsed.accepted_move_ids.is_empty());
    assert!(parsed.post_state_root.is_none());
}

#[test]
fn yougen_parses_submit_anchor_response_with_rejected_moves() {
    let body = json!({
        "anchor_id": "cx:anchor:sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "accepted_move_ids": [
            "cx:move:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ],
        "rejected_moves": [
            {
                "move_id": "cx:move:sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "reason": "FSM invalid transition: from=invited, to=ban"
            }
        ],
        "post_state_root": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    });
    let parsed: yougen::models::SubmitAnchorResponse = serde_json::from_value(body).unwrap();
    assert_eq!(parsed.accepted_move_ids.len(), 1);
    assert_eq!(parsed.rejected_moves.len(), 1);
    assert!(parsed.rejected_moves[0].reason.contains("FSM"));
}

/// Regression: `is_auth_expired_error` MUST treat a bare 401
/// (server returned 401 with no parseable error envelope, e.g. a
/// reverse-proxy injected HTML page) as a *transient*
/// denial — not as session death. Otherwise a brief upstream hiccup
/// wipes the user's persisted session and forces a fresh sign-in.
#[test]
fn bare_401_does_not_count_as_session_loss() {
    let bare: anyhow::Error = ContrixApiError {
        status: StatusCode::UNAUTHORIZED,
        error: decode_contrix_error(StatusCode::UNAUTHORIZED, b""),
    }
    .into();
    assert!(!is_auth_expired_error(&bare));

    // A 401 with an unrelated error code (e.g. rate-limit / policy_denied
    // wrapped at the 401 layer) must also stay transient. Only explicit
    // session-death codes from the spec — auth_expired / M_UNKNOWN_TOKEN /
    // invalid_token / token_expired — should drop the session.
    for code in ["auth_expired", "M_UNKNOWN_TOKEN", "invalid_token", "token_expired"] {
        let body = format!(
            r#"{{"ok":false,"error":{{"code":"{code}","message":"unknown token"}}}}"#
        );
        let envelope: anyhow::Error = ContrixApiError {
            status: StatusCode::UNAUTHORIZED,
            error: decode_contrix_error(StatusCode::UNAUTHORIZED, body.as_bytes()),
        }
        .into();
        assert!(
            is_auth_expired_error(&envelope),
            "code {code} should be classified as expired"
        );
    }

    let unrelated: anyhow::Error = ContrixApiError {
        status: StatusCode::UNAUTHORIZED,
        error: decode_contrix_error(
            StatusCode::UNAUTHORIZED,
            br#"{"ok":false,"error":{"code":"rate_limited","message":"slow down"}}"#,
        ),
    }
    .into();
    assert!(!is_auth_expired_error(&unrelated));
}

/// Regression: `decode_contrix_error` MUST tolerate three
/// on-the-wire shapes (canonical wrapped, plain envelope without
/// `request_id`, Matrix-style legacy `errcode`) and synthesise a
/// stable `http_status` envelope when none match. A regression here
/// silently degrades every error message in the UI.
#[test]
fn decoder_handles_all_envelope_shapes() {
    // 1. Canonical wrapped: { "error": ErrorEnvelope }. Extra hints
    //    (e.g. the cell ref the server is reporting the conflict on)
    //    must flow through the `details` map so the conflict UI can
    //    surface them.
    let wrapped = decode_contrix_error(
        StatusCode::CONFLICT,
        br#"{"ok":false,"error":{"errcode":"expected_head_mismatch","error":"head mismatch","retry_after_ms":250,"cell":"cx:cell:cx.component.flow.position.v1:demo"}}"#,
    );
    assert_eq!(wrapped.code(), "expected_head_mismatch");
    assert_eq!(wrapped.retry_after_ms(), Some(250));
    assert_eq!(
        wrapped.details()["cell"],
        "cx:cell:cx.component.flow.position.v1:demo"
    );

    // 2. Plain envelope without `request_id`.
    let plain = decode_contrix_error(
        StatusCode::BAD_REQUEST,
        br#"{"ok":false,"error":{"code":"invalid_param","message":"bad did"}}"#,
    );
    assert_eq!(plain.code(), "invalid_param");

    // 3. Legacy Matrix-style.
    let legacy = decode_contrix_error(
        StatusCode::BAD_REQUEST,
        br#"{"errcode":"invalid_param","error":"bad did"}"#,
    );
    assert_eq!(legacy.code(), "invalid_param");

    // 4. Garbage / non-JSON: synthesised fallback.
    let fallback = decode_contrix_error(StatusCode::SERVICE_UNAVAILABLE, b"<html>busy</html>");
    assert_eq!(fallback.code(), "http_status");
    assert!(fallback.message().contains("503"));
}
