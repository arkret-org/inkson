//! Capability revoke authoring only accepts governing-Station current carriers.

use arkret_models_collaboration::governance::authorization::GrantList;
use arkret_models_integration::AppletCapabilityRevokeIntent;
use inkson::operation::ak_ops::{
    capability_revoke, capability_revoke_from_applet_preview, capability_revoke_from_effective_row,
    effective_grant_row_for_revoke,
};
use serde_json::json;

const REALM_ID: &str = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
const GRANT_ID: &str = "ak:grant:AfpU2UOijpNUdGOoAgQdaqV0xwreLXwLE3yXXHvB6n7X";

fn select_authoring_station() {
    inkson::operation::set_authoring_station_id(Some(
        arkret_sdk::DidCoreId::new("ak:did_core:web:station.example".to_owned())
            .expect("test Station core id is canonical"),
    ));
}

fn effective_grants() -> GrantList {
    serde_json::from_value(json!({
        "grants": [{
            "grant": {
                "id": GRANT_ID,
                "schema": "ak.schema.capability.v1",
                "realm_id": REALM_ID,
                "issuer_id": {"kind": "account", "account_id": {
                    "principal_id": "ak:did_core:web:alice.example",
                    "station_id": "ak:did_core:web:station.example"
                }},
                "subject": {"kind": "account", "account_id": {
                    "principal_id": "ak:did_core:web:bob.example",
                    "station_id": "ak:did_core:web:station.example"
                }},
                "actions": ["ak.message.create"],
                "resources": [{"kind": "realm", "realm_id": REALM_ID}],
                "issuer_authority_refs": [{
                    "kind": "realm_root",
                    "realm_id": REALM_ID,
                    "authority_generation": 0,
                    "authority_event_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
                }],
                "authority_depth": 0,
                "authority_root_refs": [{
                    "kind": "realm_root",
                    "realm_id": REALM_ID,
                    "authority_generation": 0,
                    "authority_event_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
                }],
                "issued_at": "2026-01-01T00:00:00.000Z",
                "status": "active"
            },
            "revision": {
                "commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
                "stream_position": 41
            }
        }],
        "state_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "evaluated_at": "2026-01-01T00:00:01.000Z"
    }))
    .expect("effective Grant fixture is typed and active")
}

#[test]
fn owned_issuer_revoke_uses_exact_current_even_without_effective_grant_list() {
    select_authoring_station();
    let effective = effective_grants().grants.remove(0);
    let mut value = serde_json::to_value(&effective.grant).unwrap();
    let authority = json!({
        "kind":"owned_agent", "realm_id":REALM_ID,
        "controller_account_id":value["issuer_id"]["account_id"],
        "controller_join_event_id":"ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "agent_join_event_id":"ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
    });
    value["issuer_authority_refs"] = json!([authority.clone()]);
    value["authority_root_refs"] = json!([authority]);
    value["authority_depth"] = json!(1);
    value["constraints"] = json!([{"constraint_kind":"authority_control","effect":"allow","max_authority_depth":0,"authority_regrant_allowed":false}]);
    let mut row: arkret_sdk::exact_current_results::CapabilityGrantExactCurrentResult =
        serde_json::from_value(json!({
            "selector":{"kind":"capability_grant","grant_id":GRANT_ID},
            "source_stream_ref":{"kind":"realm","realm_id":REALM_ID},
            "revision":effective.revision, "value":value
        }))
        .unwrap();
    let build = |row: &arkret_sdk::exact_current_results::CapabilityGrantExactCurrentResult,
                 actor: &str| {
        inkson::operation::ak_ops::capability_revoke_from_owned_current(REALM_ID, actor, row, None)
    };
    let operation = build(&row, "did:web:alice.example")
        .unwrap()
        .build_sdk_event("inkson")
        .unwrap();
    assert_eq!(
        operation.payload()["expected_revision"],
        serde_json::to_value(&row.revision).unwrap()
    );
    assert!(build(&row, "did:web:bob.example").is_err());
    row.value.status = arkret_sdk::CapabilityGrantStatus::Revoked;
    assert!(build(&row, "did:web:alice.example").is_err());
    row.value.status = arkret_sdk::CapabilityGrantStatus::Active;
    row.value.issuer_authority_refs.clear();
    assert!(build(&row, "did:web:alice.example").is_err());
}

#[test]
fn manual_revoke_uses_only_the_effective_row_revision() {
    select_authoring_station();
    let grants = effective_grants();
    let row =
        effective_grant_row_for_revoke(&grants, GRANT_ID).expect("exact active row is available");
    let operation = capability_revoke_from_effective_row(
        REALM_ID,
        "did:web:alice.example",
        row,
        Some("operator_request"),
    )
    .unwrap()
    .build_sdk_event("inkson")
    .unwrap();

    assert_eq!(operation.payload()["grant_id"], GRANT_ID);
    assert_eq!(
        operation.payload()["expected_revision"]["stream_position"],
        41
    );
    assert!(!operation.payload().contains_key("grant_ref"));
}

#[test]
fn manual_revoke_fails_closed_without_one_exact_row() {
    let mut grants = effective_grants();
    assert!(effective_grant_row_for_revoke(&grants, "ak:grant:missing").is_err());
    grants.grants.push(grants.grants[0].clone());
    assert!(effective_grant_row_for_revoke(&grants, GRANT_ID).is_err());
    assert!(
        capability_revoke(
            REALM_ID,
            "did:web:alice.example",
            GRANT_ID,
            Some("operator_request")
        )
        .is_err()
    );
}

#[test]
fn applet_revoke_copies_the_preview_revision_and_reason_unchanged() {
    select_authoring_station();
    let intent: AppletCapabilityRevokeIntent = serde_json::from_value(json!({
        "event_kind": "ak.capability.revoke",
        "grant_id": GRANT_ID,
        "expected_revision": {
            "commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            "stream_position": 41
        },
        "registration_epoch": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "reason_code": "operator_revocation"
    }))
    .unwrap();
    let operation =
        capability_revoke_from_applet_preview(REALM_ID, "did:web:alice.example", &intent)
            .unwrap()
            .build_sdk_event("inkson")
            .unwrap();

    assert_eq!(
        operation.payload()["expected_revision"],
        serde_json::to_value(&intent.expected_revision).unwrap()
    );
    assert_eq!(operation.payload()["reason"], intent.reason_code.as_str());

    let mut wrong_kind = intent;
    wrong_kind.event_kind = "ak.capability.grant".to_owned();
    assert!(
        capability_revoke_from_applet_preview(REALM_ID, "did:web:alice.example", &wrong_kind)
            .is_err()
    );
}
