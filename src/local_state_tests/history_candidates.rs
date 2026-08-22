use super::*;

fn candidate(
    seed: u8,
    observed_at: chrono::DateTime<Utc>,
) -> (
    arkret_sdk::HistoryCandidateMaterialKey,
    Vec<u8>,
    arkret_sdk::HistoryCandidateOriginAttribution,
) {
    let realm_id = arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::canonical::DigestSuite::Sha256,
        [0x31; 32],
    ));
    let scope = arkret_sdk::HistoryEffectiveScope::Realm { realm_id };
    let mls_group_id = scope.canonical_mls_group_id().unwrap();
    let secret = vec![seed; 32];
    let key = arkret_sdk::HistoryCandidateMaterialKey {
        effective_scope: scope,
        mls_group_id,
        epoch: 7,
        candidate_digest: arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(&secret))
            .unwrap(),
    };
    let attribution = arkret_sdk::HistoryCandidateOriginAttribution::ResponseSender {
        material_key: key.clone(),
        origin_quota_domain: arkret_sdk::ResponseSenderQuotaDomain {
            source_sender_domain: "ak:device:history-source".to_owned(),
        },
        origin_ref: arkret_sdk::ResponseSenderOriginRef {
            response_id: arkret_sdk::HistoryResponseId::new(format!(
                "ak:history_response:01904100-0000-7000-8000-{seed:012x}"
            ))
            .unwrap(),
            source_record_digest: arkret_sdk::Hash::new(format!(
                "sha256:{}",
                format!("{seed:02x}").repeat(32)
            ))
            .unwrap(),
        },
        first_observed_at: observed_at,
        expires_at: observed_at + chrono::Duration::days(30),
    };
    (key, secret, attribution)
}

#[tokio::test]
async fn external_candidate_material_is_bounded_and_durable() {
    let path = temp_state_path("history-candidate-bound");
    let mut store = LocalStateStore::with_path(path.clone());
    let secrets = crate::secure_key_store::MemorySecureKeyStore::new();
    let observed_at = Utc::now();
    let mut keys = Vec::new();
    for seed in 1..=9 {
        let (key, secret, attribution) = candidate(seed, observed_at);
        store
            .receive_history_candidate(&secrets, &secret, attribution, observed_at)
            .await
            .unwrap();
        keys.push(key);
    }

    let reloaded = LocalStateStore::with_path(path);
    let resident = reloaded
        .history_candidates_for(
            &secrets,
            &keys[0].effective_scope,
            &keys[0].mls_group_id,
            keys[0].epoch,
        )
        .unwrap();
    assert_eq!(resident.len(), 8);
    assert!(!resident.iter().any(|entry| entry.material_key == keys[0]));
    assert!(resident.iter().any(|entry| entry.material_key == keys[8]));
}

#[tokio::test]
async fn event_candidate_binding_outcome_is_immutable() {
    let mut store = LocalStateStore::with_path(temp_state_path("history-candidate-binding"));
    let observed_at = Utc::now();
    let event_id =
        arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [0x44; 32]);
    let (material_key, ..) = candidate(4, observed_at);
    let binding_key = arkret_sdk::EventCandidateBindingKey {
        effective_scope: material_key.effective_scope,
        mls_group_id: material_key.mls_group_id,
        epoch: material_key.epoch,
        event_digest: event_id.identity_key().event_digest(),
        event_id,
        verified_sender_domain: "ak:device:verified-sender".to_owned(),
    };
    let binding = arkret_sdk::EventCandidateBinding {
        event_binding_key: binding_key,
        candidate_digest: material_key.candidate_digest,
        outcome: arkret_sdk::EventCandidateBindingOutcome::Failure,
        first_observed_at: observed_at,
        expires_at: observed_at + chrono::Duration::days(30),
    };
    store
        .record_history_candidate_binding(binding.clone(), observed_at)
        .unwrap();
    let mut contradictory = binding;
    contradictory.outcome = arkret_sdk::EventCandidateBindingOutcome::Success;
    assert!(
        store
            .record_history_candidate_binding(contradictory, observed_at)
            .is_err()
    );
}
