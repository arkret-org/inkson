use serde_json::json;

use crate::directory_helpers::{
    ResolveHandleContext, canonical_invitee_handle, resolve_handle_request_body,
};
use crate::models::ResolveHandleView;

#[test]
fn resolve_handle_request_body_carries_lookup_context() {
    let body = resolve_handle_request_body(
        "bob:local.host",
        ResolveHandleContext {
            intent: Some("lookup"),
            requester: Some("did:web:alice.example"),
            audience: Some("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"),
            realm_id: Some("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"),
            expected_did: Some("did:web:bob.example"),
            proof_challenge: Some("ak:challenge:test"),
            proofs: &["proof-a", "  ", "proof-b"],
        },
    )
    .expect("resolve_handle request body builds");
    let body = serde_json::to_value(body).expect("request body serializes");

    assert_eq!(body["handle"], "bob:local.host");
    assert_eq!(body["intent"], "lookup");
    assert_eq!(body["requester"], "ak:did_core:web:alice.example");
    assert_eq!(
        body["audience"],
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
    );
    assert_eq!(
        body["realm_id"],
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
    );
    assert_eq!(body["expected_principal_id"], "ak:did_core:web:bob.example");
    assert_eq!(body["proof_challenge"], "ak:challenge:test");
    assert_eq!(body["proofs"], json!(["proof-a", "proof-b"]));
}

#[test]
fn canonical_invitee_handle_accepts_display_alias() {
    assert_eq!(
        canonical_invitee_handle("@Bob:Local.Host").unwrap(),
        "bob:local.host"
    );
}

#[test]
fn handle_resolution_exposes_delivery_binding_without_requiring_it_for_invites() {
    let realm_id = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let resolved: ResolveHandleView = serde_json::from_value(json!({
        "did": "did:web:bob.example",
        "handle": "bob:local.host",
        "handle_claim": {
            "subject": "ak:did_core:web:bob.example",
            "audience": realm_id,
            "member_delivery_binding": {
                "recipient_service_id": "ak:did_core:web:local.host",
                "recipient_service_kind": "principal_server",
                "binding_source": "explicit",
                "delivery_modes": ["events"]
            }
        }
    }))
    .unwrap();

    assert_eq!(resolved.subject_did(), Some("did:web:bob.example"));
    assert_eq!(
        resolved
            .member_delivery_binding_ref()
            .unwrap()
            .recipient_service_id
            .as_str(),
        "ak:did_core:web:local.host"
    );

    let missing_binding: ResolveHandleView = serde_json::from_value(json!({
        "did": "did:web:bob.example",
        "handle": "bob:local.host",
        "audience": realm_id
    }))
    .unwrap();
    assert_eq!(missing_binding.subject_did(), Some("did:web:bob.example"));
    assert!(missing_binding.member_delivery_binding_ref().is_none());
}
