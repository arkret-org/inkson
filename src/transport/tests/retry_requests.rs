use chrono::TimeZone as _;

use crate::ephemeral::{authority_rejected_for_reason, ensure_authority_accepted};

fn accepted_commit() -> arkret_wire::RealmCommit {
    let realm_id = arkret_wire::RealmId::new(
        "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs".to_owned(),
    )
    .unwrap();
    arkret_wire::RealmCommit {
        commit_id: arkret_wire::RealmCommitId::from_digest([2; 32]),
        realm_id: realm_id.clone(),
        stream_ref: arkret_wire::CommitStreamRef::Realm { realm_id },
        stream_position: 1,
        previous_commit_ref: Some(arkret_wire::RealmCommitId::from_digest([1; 32])),
        event_ref: arkret_wire::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [3; 32]),
        governance_generation: 1,
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            arkret_wire::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [4; 32]),
        ),
        committed_at: chrono::Utc.with_ymd_and_hms(2026, 9, 22, 0, 0, 0).unwrap(),
        producer_signer_fact_digest: None,
        signature: arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::RealmCommit,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: arkret_wire::DidUrl::new(
                "did:web:authority.example#key-1".to_owned(),
            )
            .unwrap(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            created_at: chrono::Utc.with_ymd_and_hms(2026, 9, 22, 0, 0, 0).unwrap(),
            sig: arkret_wire::Base64UrlString::new("AA".to_owned()).unwrap(),
        },
    }
}

#[test]
fn authority_submit_outcome_preserves_accepted_commit_or_typed_rejection() {
    let commit = accepted_commit();
    let accepted = arkret_wire::AuthoritySubmitOutcome::Accepted {
        status: arkret_wire::AuthorityCommitStatus::Committed,
        commit: commit.clone(),
    };
    assert_eq!(ensure_authority_accepted(accepted).unwrap(), commit);

    let rejected = arkret_wire::AuthoritySubmitOutcome::Rejected {
        status: arkret_wire::AuthorityRejectionStatus::Rejected,
        reason_code: "permission_denied".to_owned(),
    };
    let error = ensure_authority_accepted(rejected).expect_err("rejection must fail closed");
    assert!(authority_rejected_for_reason(&error, "permission_denied"));
    assert!(!authority_rejected_for_reason(&error, "dependency_missing"));
    assert!(error.to_string().contains("status=Rejected"));
    assert!(error.to_string().contains("reason_code=permission_denied"));
}
