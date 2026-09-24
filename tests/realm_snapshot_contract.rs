#![cfg(not(target_arch = "wasm32"))]

use chrono::Utc;
use serde_json::{Value, json};

fn hash(seed: u8) -> arkret_sdk::Hash {
    arkret_sdk::Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).unwrap()
}

fn snapshot_payload() -> Value {
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:AeI0Z4D734iPt9RpF51PAg0CRjLSQmxPqv9NgUmBJiQi").unwrap();
    let commit_id = arkret_sdk::RealmCommitId::from_digest([0x31; 32]);
    let created_at = Utc::now();
    serde_json::to_value(arkret_sdk::RealmStateSnapshot {
        snapshot_id: arkret_sdk::RealmSnapshotId::from_digest([0xcc; 32]),
        realm_id: realm_id.clone(),
        governance_generation: 4,
        visible_stream_heads: vec![arkret_sdk::CommitStreamHead {
            stream_ref: arkret_sdk::CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            stream_position: 7,
            commit_id: commit_id.clone(),
        }],
        current_state_entries: vec![arkret_sdk::TypedCurrentResult::Value {
            selector: arkret_sdk::CurrentSelector::RealmProfile,
            source_stream_ref: arkret_sdk::CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            revision: arkret_sdk::CurrentRevision {
                commit_id,
                stream_position: 7,
            },
            value: json!({
                "schema": "ak.schema.realm_profile.v1",
                "title": "Contract Realm"
            }),
        }],
        retention_and_history_floor: arkret_sdk::RetentionAndHistoryFloor {
            history_access: arkret_sdk::HistoryAccess::SinceJoin,
            stream_floors: Vec::new(),
        },
        created_at,
        signature: arkret_sdk::DetachedObjectSignature {
            context: arkret_sdk::DetachedSignatureContext::RealmSnapshot,
            signature_algorithm: arkret_sdk::DetachedSignatureAlgorithm::Ed25519,
            verification_method: arkret_sdk::DidUrl::new(
                "did:web:server.local#snapshot".to_owned(),
            )
            .unwrap(),
            signed_digest: hash(2),
            created_at,
            sig: arkret_sdk::Base64UrlString::new("AQ".to_owned()).unwrap(),
        },
    })
    .unwrap()
}

#[test]
fn realm_snapshot_is_one_complete_inline_response_without_paging() {
    let snapshot: arkret_sdk::RealmStateSnapshot =
        serde_json::from_value(snapshot_payload()).unwrap();
    assert_eq!(snapshot.current_state_entries.len(), 1);

    let mut private_paging_dialect = snapshot_payload();
    private_paging_dialect["next_cursor"] = json!("ak:cursor:private");
    assert!(
        serde_json::from_value::<arkret_sdk::RealmStateSnapshot>(private_paging_dialect).is_err()
    );
}

#[test]
fn snapshot_capacity_rejection_is_explicitly_actionable() {
    let problem = arkret_sdk::Problem::from_code(
        arkret_sdk::error_codes::ErrorCode::FAILED_PRECONDITION,
        "candidate RealmCommit would exceed the inline snapshot budget",
    )
    .with_extension(
        "reason_code",
        Value::String("snapshot_capacity_exceeded".to_owned()),
    );
    let error = anyhow::Error::new(arkret_sdk::http_client::Error::Api {
        status: 412,
        error: Box::new(problem),
    });

    assert_eq!(
        inkson::api_error::display_user_facing(&error),
        "This change would make the Realm too large for a complete state snapshot. Reduce the Realm state before trying again."
    );
}
