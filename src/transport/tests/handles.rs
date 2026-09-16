use serde_json::json;

use crate::directory_helpers::{
    ResolveHandleContext, canonical_invitee_handle, resolve_handle_request_body,
};
use crate::models::ResolveHandleView;

/// The directory `proofs[]` element is a `DirectoryRequestProof` — it commits to
/// `payload_digest` (the digest of the unsigned request payload), not to an
/// `event_digest`, because a directory read is not an Event.
fn test_payload_proof(
    payload_digest: arkret_sdk::Hash,
) -> arkret_models_discovery::DirectoryRequestProof {
    arkret_models_discovery::DirectoryRequestProof {
        kind: arkret_models_discovery::DirectoryRequestProofKind::DetachedJws,
        verification_method: arkret_sdk::DidUrl::new("did:web:alice.example#key-1".to_owned())
            .expect("test verification method is a DID URL"),
        payload_digest,
        created_at: chrono::DateTime::parse_from_rfc3339("2026-08-17T00:00:00Z")
            .expect("test timestamp")
            .with_timezone(&chrono::Utc),
        audience_id: arkret_sdk::DidCoreId::new("ak:did_core:web:directory.example".to_owned())
            .expect("test audience is a DID core ID"),
        jws: "a..b".to_owned(),
    }
}

#[test]
fn resolve_handle_request_body_carries_lookup_context() {
    let expected_account_id = arkret_sdk::AccountId::new(
        arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:bob-station.example").unwrap(),
    );
    let context = ResolveHandleContext {
        intent: Some("lookup"),
        requester: Some("ak:did_core:web:alice.example"),
        audience: Some("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"),
        realm_id: Some("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"),
        expected_account_id: Some(&expected_account_id),
        proof_challenge: Some("ak:challenge:test"),
        proofs: &[],
    };
    // `proofs[]` is excluded from the signed payload, so the digest is taken
    // from the proof-free body and then carried on the proof.
    let unsigned = resolve_handle_request_body("bob:local.host", context)
        .expect("resolve_handle request body builds");
    let payload_digest = unsigned.payload_digest().expect("payload digest");
    let proofs = [test_payload_proof(payload_digest.clone())];
    let body = resolve_handle_request_body(
        "bob:local.host",
        ResolveHandleContext {
            proofs: &proofs,
            ..context
        },
    )
    .expect("resolve_handle request body builds");
    // The transcript the proof signs comes from the SDK, never from a local
    // concatenation.
    body.proof_binding_bytes(&proofs[0])
        .expect("SDK builds the directory proof transcript");
    let body = serde_json::to_value(body).expect("request body serializes");

    assert_eq!(body["handle"], "bob:local.host");
    assert_eq!(body["intent"], "lookup");
    assert_eq!(body["requester_id"], "ak:did_core:web:alice.example");
    assert_eq!(
        body["audience"],
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
    );
    assert_eq!(
        body["realm_id"],
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
    );
    assert_eq!(
        body["expected_account_id"],
        json!({
            "principal_id": "ak:did_core:web:bob.example",
            "station_id": "ak:did_core:web:bob-station.example"
        })
    );
    assert_eq!(body["proof_challenge"], "ak:challenge:test");
    assert_eq!(body["proofs"].as_array().expect("proofs array").len(), 1);
    assert_eq!(
        body["proofs"][0]["payload_digest"],
        json!(payload_digest.as_str())
    );
    assert!(body["proofs"][0].get("event_digest").is_none());
}

#[test]
fn canonical_invitee_handle_accepts_display_alias() {
    assert_eq!(
        canonical_invitee_handle("@Bob:Local.Host").unwrap(),
        "bob:local.host"
    );
}

#[test]
fn handle_resolution_exposes_exact_station_bound_account() {
    let resolved: ResolveHandleView = serde_json::from_value(json!({
        "account_id": {
            "principal_id": "ak:did_core:web:bob.example",
            "station_id": "ak:did_core:web:local.host"
        },
        "handle": "bob:local.host",
        "verified": true,
        "claims": null,
        "source_refs": []
    }))
    .unwrap();

    assert_eq!(
        resolved.account_id.principal_id.as_str(),
        "ak:did_core:web:bob.example"
    );
    assert_eq!(
        resolved.account_id.station_id.as_str(),
        "ak:did_core:web:local.host"
    );
}
