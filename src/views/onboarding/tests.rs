use super::*;

fn test_active_account() -> crate::config::ActiveAccountContext {
    let did = arkret_sdk::Did::new("did:webvh:z6mkfixture:principal.example".to_owned()).unwrap();
    crate::config::ActiveAccountContext::new(
        "ak:profile:test".to_owned(),
        arkret_sdk::AccountId::new(
            arkret_sdk::project_did_to_core_id(&did).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkfixture:server.example".to_owned())
                .unwrap(),
        ),
        arkret_sdk::PrincipalResolutionProjection {
            did,
            method_history_head: "head-test".to_owned(),
            version_id: "version-test".to_owned(),
            resolution_event_ref: "event-test".to_owned(),
            updated_at: "2026-08-22T00:00:00Z".parse().unwrap(),
        },
        arkret_sdk::DeviceId::new("ak:device:019f0000-0000-7000-8000-000000000001".to_owned())
            .unwrap(),
        url::Url::parse("https://principal.example").unwrap(),
    )
    .unwrap()
}

#[test]
fn hosting_label_hides_protocol_details() {
    assert_eq!(
        hosting_label("https://identity.example/path"),
        "identity.example"
    );
    assert_eq!(hosting_label("not a url"), "your selected service");
}

#[test]
fn only_first_enrollment_continuations_may_create_the_account_mls_root() {
    use crate::identity::account_auth::transition::OnboardingCompletionOrigin;

    assert!(onboarding_may_create_account_mls_root(
        OnboardingCompletionOrigin::FreshBind
    ));
    assert!(onboarding_may_create_account_mls_root(
        OnboardingCompletionOrigin::ResumeRestore
    ));
    assert!(onboarding_may_create_account_mls_root(
        OnboardingCompletionOrigin::ResumeReissue
    ));
    assert!(!onboarding_may_create_account_mls_root(
        OnboardingCompletionOrigin::RecoveryCompletion
    ));
}

#[test]
fn accepted_and_durable_recovery_stages_are_both_resumable() {
    assert_eq!(
        recovery_material_continuation(crate::state::PendingPrincipalRegistrationStage::Accepted,)
            .unwrap(),
        RecoveryMaterialContinuation::SubmitAndPersist,
    );
    assert_eq!(
        recovery_material_continuation(
            crate::state::PendingPrincipalRegistrationStage::RecoveryMaterialComplete,
        )
        .unwrap(),
        RecoveryMaterialContinuation::FinalizeDurableEvidence,
    );
    assert!(
        recovery_material_continuation(
            crate::state::PendingPrincipalRegistrationStage::RegisterRequestPrepared,
        )
        .is_err()
    );
}

fn restorable_resume_facts() -> garth::BoundCompletionResumeFacts {
    garth::BoundCompletionResumeFacts {
        handoff: garth::BoundCompletionHandoffState::ActiveBound,
        checkpoint_stage: garth::BoundCompletionCheckpointStage::Accepted,
        recovery_policy: garth::BoundCompletionMaterialState::NotRequired,
        device_id: garth::BoundCompletionMaterialState::Present,
        signing_seed: garth::BoundCompletionMaterialState::Present,
        grant_binding_key: garth::BoundCompletionMaterialState::Present,
        session_grant: garth::BoundCompletionMaterialState::Present,
        recovery_evidence: garth::BoundCompletionMaterialState::Absent,
        hpke_private_key: garth::BoundCompletionMaterialState::Present,
        authority_matches: true,
        device_slot_matches: true,
        grant_matches_account: true,
        grant_is_live: true,
        grant_binding_matches_handoff: true,
    }
}

#[test]
fn accepted_resume_material_matrix_has_honest_routes() {
    use garth::{
        BoundCompletionMaterialState as Material, BoundCompletionResumeDisposition as Disposition,
    };

    let live = restorable_resume_facts();
    for facts in [
        garth::BoundCompletionResumeFacts {
            session_grant: Material::Absent,
            ..live
        },
        garth::BoundCompletionResumeFacts {
            grant_is_live: false,
            ..live
        },
        garth::BoundCompletionResumeFacts {
            grant_binding_key: Material::Absent,
            ..live
        },
        garth::BoundCompletionResumeFacts {
            grant_binding_matches_handoff: false,
            ..live
        },
    ] {
        assert_eq!(
            garth::classify_bound_completion_resume(facts).unwrap(),
            Disposition::ReissueGrant
        );
    }
    assert_eq!(
        garth::classify_bound_completion_resume(garth::BoundCompletionResumeFacts {
            signing_seed: Material::Absent,
            recovery_policy: Material::Present,
            ..live
        })
        .unwrap(),
        Disposition::RecoverWithPolicy
    );
    assert_eq!(
        garth::classify_bound_completion_resume(garth::BoundCompletionResumeFacts {
            signing_seed: Material::Absent,
            recovery_policy: Material::Absent,
            ..live
        })
        .unwrap(),
        Disposition::StrandedIdentity
    );
    assert_eq!(
        garth::classify_bound_completion_resume(garth::BoundCompletionResumeFacts {
            handoff: garth::BoundCompletionHandoffState::MissingOrExpired,
            ..live
        })
        .unwrap(),
        Disposition::ReauthRequired
    );
    assert_eq!(
        garth::classify_bound_completion_resume(garth::BoundCompletionResumeFacts {
            checkpoint_stage: garth::BoundCompletionCheckpointStage::RecoveryMaterialComplete,
            recovery_evidence: Material::Absent,
            ..live
        })
        .unwrap(),
        Disposition::Contradiction {
            reason: garth::BoundCompletionContradiction::CompletedStageMissingEvidence
        }
    );
    assert_eq!(
        garth::classify_bound_completion_resume(garth::BoundCompletionResumeFacts {
            recovery_policy: Material::NotRequired,
            ..live
        })
        .unwrap(),
        Disposition::RestoreRuntime,
        "a present signer/session must not read recovery-policy state"
    );
    assert!(
        garth::classify_bound_completion_resume(garth::BoundCompletionResumeFacts {
            signing_seed: Material::Absent,
            recovery_policy: Material::ReadError,
            ..live
        })
        .is_err(),
        "a missing signer still requires proved server recovery-policy state"
    );
}

#[test]
fn resume_material_read_error_is_not_absence() {
    let mut errors = Vec::new();
    let (state, value) = observe_resume_material::<String, _>(
        "session grant",
        Err(std::io::Error::other("keyring locked")),
        &mut errors,
    );
    assert_eq!(state, garth::BoundCompletionMaterialState::ReadError);
    assert!(value.is_none());
    assert_eq!(errors, ["session grant: keyring locked"]);

    let classified = garth::classify_bound_completion_resume(garth::BoundCompletionResumeFacts {
        session_grant: state,
        ..restorable_resume_facts()
    });
    assert!(classified.is_err());
}

#[test]
fn resume_inventory_reads_the_same_typed_memory_store_path_as_production() {
    let secure = crate::secure_key_store::MemorySecureKeyStore::default();
    let account = test_active_account();
    let user_store = crate::secure_key_store::UserLocalStore::new(
        account.authority.clone(),
        account.device_id.clone(),
    )
    .unwrap();
    let mut errors = Vec::new();
    let (missing, _) = observe_resume_material(
        "accepted device signer",
        user_store.load_signing_seed(&secure),
        &mut errors,
    );
    assert_eq!(missing, garth::BoundCompletionMaterialState::Absent);
    assert!(errors.is_empty());

    user_store.save_signing_seed(&secure, &[17_u8; 32]).unwrap();
    let (present, material) = observe_resume_material(
        "accepted device signer",
        user_store.load_signing_seed(&secure),
        &mut errors,
    );
    assert_eq!(present, garth::BoundCompletionMaterialState::Present);
    assert_eq!(material.unwrap().seed, [17_u8; 32]);
    assert!(errors.is_empty());
}

#[test]
fn accepted_account_client_uses_the_accepted_dpop_session() {
    use base64::Engine as _;

    let account = test_active_account();
    let seed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([23_u8; 32]);
    let record =
        crate::identity::account_auth::grant_dpop::dpop_device_key_record_from_seed(&seed).unwrap();
    let dpop = crate::identity::account_auth::grant_dpop::device_handle_from_seed(
        &record.seed_b64,
        &record.jkt,
    )
    .unwrap();
    let grant = crate::state::PersistedSessionGrant {
        grant_jwt: "signed.session.grant".to_owned(),
        session_private_key_pem: String::new(),
        grant_id: "ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW".to_owned(),
        audience_id: account.authority.station_id.clone(),
        account_id: account.authority.clone(),
        device_id: account.device_id.clone(),
        station_url: account.server_url.clone(),
        grant_expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        stored_at: chrono::Utc::now(),
    };

    let api = accepted_account_session_client(&account, dpop.jkt(), &grant, &dpop).unwrap();

    assert_eq!(api.context().credential, grant.grant_jwt);
    assert_eq!(
        api.context().dpop.as_ref().map(|handle| handle.jkt()),
        Some(dpop.jkt())
    );

    let mut wrong_audience = grant;
    wrong_audience.audience_id =
        arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkfixture:other.example").unwrap();
    assert!(
        accepted_account_session_client(&account, dpop.jkt(), &wrong_audience, &dpop,).is_err()
    );
}

#[test]
fn completed_account_namespace_switch_is_replay_safe() {
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000020",
        Some("lease-1"),
        Some(1),
    );
    let checkpoint = test_checkpoint(
        &handoff,
        &recovery_key,
        crate::state::PendingPrincipalRegistrationStage::Accepted,
    );
    let account = test_active_account();
    let mut store = crate::state::isolated_store_for_tests("completed-account-replay");
    store.begin_pending_login(&account.device_id, Some(&handoff.holder_jkt));
    store
        .set_pending_account_handoff(Some(handoff.clone()))
        .unwrap();
    store
        .set_pending_principal_registration(Some(checkpoint.clone()))
        .unwrap();

    assert!(store.switch_active_account(&account).unwrap());
    assert_eq!(store.pending_account_handoff(), Some(handoff.clone()));
    assert_eq!(
        store.pending_principal_registration(),
        Some(checkpoint.clone())
    );

    assert!(!store.switch_active_account(&account).unwrap());
    assert_eq!(store.pending_account_handoff(), Some(handoff));
    assert_eq!(store.pending_principal_registration(), Some(checkpoint));
}

#[test]
fn recovery_metadata_is_written_after_the_account_namespace_switch() {
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let account = test_active_account();
    let mut store = crate::state::isolated_store_for_tests("account-recovery-metadata");

    activate_account_and_save_recovery_metadata(&mut store, &account, &recovery_key).unwrap();

    assert!(store.active_account_matches(account.principal_id()));
    assert!(crate::views::recovery::recovery_options_configured(&store,));
    crate::views::recovery::local_recovery_public_key_result(&store).unwrap();
}

#[test]
fn current_deployment_exposes_only_its_connected_human_anchor_method() {
    assert_eq!(CURRENT_DEPLOYMENT_HUMAN_ANCHOR_METHOD, "did:webvh");
}

#[test]
fn onboarding_uses_full_phrase_confirmation() {
    let key = crate::recovery_crypto::generate_recovery_key().unwrap();
    assert_eq!(
        recovery_key_confirmation_diff(&key, &key),
        RecoveryKeyConfirmationDiff::Match
    );
}

#[test]
fn onboarding_recovery_download_uses_account_handle() {
    let handle = "alice:local.host".to_owned();
    assert_eq!(
        crate::components::mls_backup_prompt::recovery_key_filename_from_handles(
            std::slice::from_ref(&handle),
        ),
        "arkret-recovery-key-alice.txt"
    );
}

#[tokio::test]
async fn prepared_registration_rehydrates_its_pending_signer_before_retry() {
    let _signer_guard = crate::event_signer::ActiveSignerTestGuard::replace(None);
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000010",
        Some("lease-1"),
        Some(1),
    );
    let checkpoint = test_checkpoint(
        &handoff,
        &recovery_key,
        crate::state::PendingPrincipalRegistrationStage::RegisterRequestPrepared,
    );
    let secure_store = crate::secure_key_store::MemorySecureKeyStore::default();
    let pending_store = crate::secure_key_store::PendingLocalStore::new(
        arkret_sdk::DeviceId::new(handoff.device_id.clone()).unwrap(),
    );
    pending_store
        .save_signing_seed(&secure_store, &[7; 32])
        .unwrap();
    crate::event_signer::activate_device_signer_from_seed_for_device(
        [9; 32],
        None,
        Some("ak:device:019f0000-0000-7000-8000-000000000099"),
    )
    .unwrap();

    let signer = activate_pending_registration_signer(
        &checkpoint,
        &handoff.device_id,
        &pending_store,
        &secure_store,
    )
    .await
    .unwrap();

    assert_eq!(signer.signer_did(), checkpoint.did.as_str());
    assert_eq!(signer.device_id(), Some(handoff.device_id.as_str()));
    assert!(
        signer
            .verification_method()
            .ends_with(&format!("#{}", handoff.device_id))
    );
}

#[test]
fn bootstrap_seal_retry_reuses_the_byte_exact_checkpoint_value() {
    let frozen = serde_json::json!({
        "id": "ak:seal:frozen",
        "notary_seq": 0,
        "hlc": "01970e589d21-0004-a13f9c2e"
    });

    validate_exact_bootstrap_seal_replay(&frozen, &frozen.clone()).unwrap();

    let changed = serde_json::json!({
        "id": "ak:seal:frozen",
        "notary_seq": 1,
        "hlc": "01970e589d21-0004-a13f9c2e"
    });
    let error = validate_exact_bootstrap_seal_replay(&frozen, &changed).unwrap_err();
    assert!(
        error
            .downcast_ref::<BootstrapSealReplayContradiction>()
            .is_some()
    );
}

#[tokio::test]
async fn prepared_registration_never_rotates_a_missing_pending_signer() {
    let _signer_guard = crate::event_signer::ActiveSignerTestGuard::replace(None);
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000010",
        Some("lease-1"),
        Some(1),
    );
    let checkpoint = test_checkpoint(
        &handoff,
        &recovery_key,
        crate::state::PendingPrincipalRegistrationStage::RegisterRequestPrepared,
    );
    let secure_store = crate::secure_key_store::MemorySecureKeyStore::default();
    let pending_store = crate::secure_key_store::PendingLocalStore::new(
        arkret_sdk::DeviceId::new(handoff.device_id.clone()).unwrap(),
    );

    let error = activate_pending_registration_signer(
        &checkpoint,
        &handoff.device_id,
        &pending_store,
        &secure_store,
    )
    .await
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("no durable pending device signer")
    );
    assert!(crate::event_signer::active_signer().is_none());
}

fn test_checkpoint(
    handoff: &crate::state::PendingAccountHandoff,
    recovery_key: &str,
    stage: crate::state::PendingPrincipalRegistrationStage,
) -> crate::state::PendingPrincipalRegistration {
    let mut checkpoint = crate::identity::principal_registration::prepare_registration_checkpoint(
        handoff,
        &handoff.device_id,
        recovery_key,
    )
    .unwrap();
    checkpoint.stage = stage;
    checkpoint
}

#[test]
fn a_fresh_handoff_never_yields_the_surface_to_a_foreign_draft() {
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let previous_handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000010",
        Some("lease-1"),
        Some(1),
    );
    let stale = test_checkpoint(
        &previous_handoff,
        &recovery_key,
        crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed,
    );
    let mut new_account_handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000011",
        Some("lease-2"),
        Some(2),
    );
    new_account_handoff.account_handle = "bob:auth.example".to_owned();

    // The newly authenticated account must reach its own Recovery Key
    // generation, not be asked for 24 words it never saw.
    assert_eq!(
        onboarding_surface(Some(&new_account_handoff), Some(&stale)),
        OnboardingSurface::IdentityCreation
    );
    // Even a live session for the stale draft's DID cannot outrank the
    // handoff that just authenticated someone else on this device.
    assert_eq!(
        onboarding_surface(Some(&new_account_handoff), Some(&stale)),
        OnboardingSurface::IdentityCreation
    );
}

#[test]
fn an_interrupted_creation_stays_in_the_server_handoff_flow() {
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000010",
        Some("lease-1"),
        Some(1),
    );
    let checkpoint = test_checkpoint(
        &handoff,
        &recovery_key,
        crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed,
    );

    assert_eq!(
        onboarding_surface(Some(&handoff), Some(&checkpoint)),
        OnboardingSurface::IdentityCreation
    );
}

#[test]
fn a_draft_that_never_bound_its_account_cannot_resume_without_its_handoff() {
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000010",
        Some("lease-1"),
        Some(1),
    );
    let checkpoint = test_checkpoint(
        &handoff,
        &recovery_key,
        crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed,
    );

    // The lease and the handoff credential are what bind the account, so a
    // live session for this DID cannot stand in for the missing handoff.
    assert_eq!(
        onboarding_surface(None, Some(&checkpoint)),
        OnboardingSurface::StaleCheckpoint
    );
}

#[test]
fn every_local_phase_requires_a_server_handoff_before_resuming() {
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000010",
        Some("lease-1"),
        Some(1),
    );
    for stage in [
        crate::state::PendingPrincipalRegistrationStage::RegisterRequestPrepared,
        crate::state::PendingPrincipalRegistrationStage::Accepted,
        crate::state::PendingPrincipalRegistrationStage::RecoveryMaterialComplete,
    ] {
        let checkpoint = test_checkpoint(&handoff, &recovery_key, stage);

        // A local checkpoint never authorizes continuation by itself,
        // even if a session for the same DID is present. Signing in must
        // first obtain a fresh Account Authority snapshot and handoff.
        assert_eq!(
            onboarding_surface(None, Some(&checkpoint)),
            OnboardingSurface::StaleCheckpoint
        );
    }
}

#[test]
fn discarding_a_registered_binding_is_flagged_as_irreversible() {
    // The two warnings are trivially easy to swap, and swapping them tells
    // a user that throwing away the only copy of a registered identity's
    // setup costs nothing.
    assert!(discard_consequence(true).contains("authenticated abandonment"));
    assert!(discard_consequence(false).contains("Nothing has been registered"));
}

#[test]
fn account_summary_requires_a_typed_active_account() {
    let account = test_active_account();
    assert!(!account_summary_complete(false, ""));
    assert!(account_summary_complete(true, account.did().as_str()));
}

#[test]
fn a_latched_creation_surface_never_goes_empty_when_its_handoff_disappears() {
    let account = test_active_account();
    assert_eq!(
        missing_creation_handoff_surface(true, false, ""),
        MissingCreationHandoffSurface::Finishing
    );
    assert_eq!(
        missing_creation_handoff_surface(false, true, account.did().as_str()),
        MissingCreationHandoffSurface::Complete
    );
    assert_eq!(
        missing_creation_handoff_surface(false, false, ""),
        MissingCreationHandoffSurface::SignInRequired
    );
}

#[test]
fn onboarding_without_a_draft_follows_the_handoff() {
    let handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000010",
        Some("lease-1"),
        Some(1),
    );

    assert_eq!(
        onboarding_surface(Some(&handoff), None),
        OnboardingSurface::IdentityCreation
    );
    assert_eq!(
        onboarding_surface(None, None),
        OnboardingSurface::AccountSummary
    );
}

#[test]
fn contradictory_bound_and_reserved_server_state_fails_closed() {
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let mut handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000010",
        Some("lease-1"),
        Some(1),
    );
    let checkpoint = test_checkpoint(
        &handoff,
        &recovery_key,
        crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed,
    );
    handoff.bound_principal_id = Some(arkret_sdk::project_did_to_core_id(&checkpoint.did).unwrap());
    handoff.bound_principal_did = Some(checkpoint.did.clone());
    handoff.reserved_identity = Some(
        arkret_sdk::ReservedIdentityCreation::from_operation(checkpoint.did_operation.clone())
            .unwrap(),
    );
    handoff.identity_creation_state = Some(arkret_sdk::IdentityCreationLeaseState::Reserved);

    assert_eq!(
        onboarding_surface(Some(&handoff), None),
        OnboardingSurface::ServerStateConflict
    );
    assert_eq!(
        onboarding_surface(Some(&handoff), Some(&checkpoint)),
        OnboardingSurface::ServerStateConflict
    );
    assert!(must_enter_reserved_recovery_key(&handoff));
}

#[test]
fn exact_bound_creation_checkpoint_finishes_on_the_creation_surface() {
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    for stage in [
        crate::state::PendingPrincipalRegistrationStage::RegisterRequestPrepared,
        crate::state::PendingPrincipalRegistrationStage::Accepted,
        crate::state::PendingPrincipalRegistrationStage::RecoveryMaterialComplete,
    ] {
        let mut handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            Some("lease-1"),
            Some(1),
        );
        let checkpoint = test_checkpoint(&handoff, &recovery_key, stage);
        handoff.lease_id = None;
        handoff.lease_fence = None;
        handoff.lease_expires_at = None;
        handoff.identity_creation_state = None;
        handoff.bound_principal_id =
            Some(arkret_sdk::project_did_to_core_id(&checkpoint.did).unwrap());
        handoff.bound_principal_did = Some(checkpoint.did.clone());

        assert_eq!(
            onboarding_surface(Some(&handoff), Some(&checkpoint)),
            OnboardingSurface::IdentityCreation,
            "bound + exact {stage:?} checkpoint is the same registration transaction"
        );
    }
}

#[test]
fn reauthenticated_bound_creation_renews_only_the_handoff_request_fence() {
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let original = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000009",
        Some("lease-1"),
        Some(1),
    );
    let checkpoint = test_checkpoint(
        &original,
        &recovery_key,
        crate::state::PendingPrincipalRegistrationStage::Accepted,
    );
    let mut reauthenticated = original;
    reauthenticated.request_id = "ak:request:019f0000-0000-7000-8000-000000000010".to_owned();
    reauthenticated.lease_id = None;
    reauthenticated.lease_fence = None;
    reauthenticated.lease_expires_at = None;
    reauthenticated.identity_creation_state = None;
    reauthenticated.bound_principal_id =
        Some(arkret_sdk::project_did_to_core_id(&checkpoint.did).unwrap());
    reauthenticated.bound_principal_did = Some(checkpoint.did.clone());

    let resumed = checkpoint_for_handoff(&checkpoint, &reauthenticated, &recovery_key).unwrap();

    assert_eq!(resumed.handoff_request_id, reauthenticated.request_id);
    assert_eq!(resumed.did, checkpoint.did);
    assert_eq!(resumed.device_id, checkpoint.device_id);
    assert_eq!(resumed.pcr_genesis_unit, checkpoint.pcr_genesis_unit);
}

#[test]
fn bound_account_without_verified_creation_continuation_uses_recovery() {
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let mut handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000010",
        Some("lease-1"),
        Some(1),
    );
    let checkpoint = test_checkpoint(
        &handoff,
        &recovery_key,
        crate::state::PendingPrincipalRegistrationStage::Accepted,
    );
    handoff.lease_id = None;
    handoff.lease_fence = None;
    handoff.lease_expires_at = None;
    handoff.identity_creation_state = None;
    handoff.bound_principal_id = Some(arkret_sdk::project_did_to_core_id(&checkpoint.did).unwrap());
    handoff.bound_principal_did = Some(checkpoint.did.clone());
    // account-lifecycle.md 2.1.2: only the closed `NoReturningDevice`
    // normalization result opens Device Setup on a bound account. An
    // absent result is not "no device" and must keep failing closed.
    handoff.bound_device_entry_state = Some(crate::state::BoundDeviceEntryState::NoReturningDevice);

    assert_eq!(
        onboarding_surface(Some(&handoff), None),
        OnboardingSurface::DeviceSetupRequired
    );
    let mut foreign = checkpoint;
    foreign.device_id = "ak:device:019f0000-0000-7000-8000-000000000099".to_owned();
    assert_eq!(
        onboarding_surface(Some(&handoff), Some(&foreign)),
        OnboardingSurface::DeviceSetupRequired,
        "a foreign checkpoint must not inherit the first-device continuation"
    );
}

#[test]
fn a_server_reservation_never_generates_a_replacement_recovery_key() {
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000010",
        Some("lease-1"),
        Some(1),
    );
    let checkpoint = test_checkpoint(
        &handoff,
        &recovery_key,
        crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed,
    );
    let mut renewed = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000011",
        Some("lease-2"),
        Some(2),
    );
    renewed.reserved_identity = Some(
        arkret_sdk::ReservedIdentityCreation::from_operation(checkpoint.did_operation.clone())
            .unwrap(),
    );
    renewed.identity_creation_state = Some(arkret_sdk::IdentityCreationLeaseState::Reserved);

    // The checkpoint matches the exact server reservation, so the single
    // handoff flow continues it instead of treating the local checkpoint
    // as an independent authority source.
    assert_eq!(
        onboarding_surface(Some(&renewed), Some(&checkpoint)),
        OnboardingSurface::IdentityCreation
    );
    assert!(must_enter_reserved_recovery_key(&renewed));
}

#[test]
fn every_unfinished_server_phase_uses_one_handoff_flow() {
    let mut handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000010",
        Some("lease-1"),
        Some(1),
    );
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let checkpoint = test_checkpoint(
        &handoff,
        &recovery_key,
        crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed,
    );
    let reserved_identity =
        arkret_sdk::ReservedIdentityCreation::from_operation(checkpoint.did_operation).unwrap();
    for state in [
        arkret_sdk::IdentityCreationLeaseState::Active,
        arkret_sdk::IdentityCreationLeaseState::Reserved,
        arkret_sdk::IdentityCreationLeaseState::DidPublished,
        arkret_sdk::IdentityCreationLeaseState::PcrAccepted,
        arkret_sdk::IdentityCreationLeaseState::AccountBound,
    ] {
        handoff.identity_creation_state = Some(state);
        handoff.reserved_identity = state
            .has_reserved_identity()
            .then(|| reserved_identity.clone());
        assert_eq!(
            onboarding_surface(Some(&handoff), None),
            OnboardingSurface::IdentityCreation,
            "server phase {state:?} must stay in the authoritative handoff flow"
        );
    }
}

#[test]
fn retained_or_reserved_key_material_skips_identity_choice() {
    let mut handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000010",
        Some("lease-1"),
        Some(1),
    );
    assert_eq!(
        initial_identity_choice(Some(&handoff), false),
        IdentityChoice::Choose
    );
    assert_eq!(
        initial_identity_choice(Some(&handoff), true),
        IdentityChoice::Create
    );
    handoff.identity_creation_state = Some(arkret_sdk::IdentityCreationLeaseState::Reserved);
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let checkpoint = test_checkpoint(
        &handoff,
        &recovery_key,
        crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed,
    );
    handoff.reserved_identity = Some(
        arkret_sdk::ReservedIdentityCreation::from_operation(checkpoint.did_operation).unwrap(),
    );
    assert_eq!(
        initial_identity_choice(Some(&handoff), false),
        IdentityChoice::Create
    );
}

#[test]
fn renewed_handoff_reuses_the_server_reserved_identity() {
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let old_handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000010",
        Some("lease-1"),
        Some(1),
    );
    let mut checkpoint = crate::identity::principal_registration::prepare_registration_checkpoint(
        &old_handoff,
        &old_handoff.device_id,
        &recovery_key,
    )
    .unwrap();
    let did_operation = checkpoint.did_operation.clone();
    let reserved_identity =
        arkret_sdk::ReservedIdentityCreation::from_operation(did_operation).unwrap();
    checkpoint.account_handle.clear();
    let mut new_handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000011",
        Some("lease-2"),
        Some(2),
    );
    new_handoff.reserved_identity = Some(reserved_identity);
    new_handoff.identity_creation_state = Some(arkret_sdk::IdentityCreationLeaseState::Reserved);

    let resumed = checkpoint_for_handoff(&checkpoint, &new_handoff, &recovery_key).unwrap();

    assert_eq!(resumed.handoff_request_id, new_handoff.request_id);
    assert_eq!(resumed.lease_id, "lease-2");
    assert_eq!(resumed.lease_fence, 2);
    assert_eq!(resumed.did, checkpoint.did);
    assert_eq!(resumed.did_operation, checkpoint.did_operation);
}

#[test]
fn renewed_handoff_fails_closed_on_a_different_reservation() {
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let old_handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000010",
        Some("lease-1"),
        Some(1),
    );
    let checkpoint = crate::identity::principal_registration::prepare_registration_checkpoint(
        &old_handoff,
        &old_handoff.device_id,
        &recovery_key,
    )
    .unwrap();
    let other_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let other_checkpoint =
        crate::identity::principal_registration::prepare_registration_checkpoint(
            &old_handoff,
            &old_handoff.device_id,
            &other_key,
        )
        .unwrap();
    let other_operation = other_checkpoint.did_operation;
    let mut new_handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000011",
        Some("lease-2"),
        Some(2),
    );
    new_handoff.reserved_identity =
        Some(arkret_sdk::ReservedIdentityCreation::from_operation(other_operation).unwrap());
    new_handoff.identity_creation_state = Some(arkret_sdk::IdentityCreationLeaseState::Reserved);

    let error = checkpoint_for_handoff(&checkpoint, &new_handoff, &recovery_key).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not match the local checkpoint")
    );
}

/// A handle can be registered again — delete the account, or reset the
/// Account Authority's store, and the same handle returns as a different
/// identity. This used to reuse the abandoned draft, which is exactly how a
/// fresh registration ended up being asked for 24 words belonging to a DID
/// the server no longer had.
#[test]
fn a_re_registered_handle_does_not_inherit_the_abandoned_draft() {
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let old_handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000010",
        Some("lease-1"),
        Some(1),
    );
    let checkpoint = crate::identity::principal_registration::prepare_registration_checkpoint(
        &old_handoff,
        &old_handoff.device_id,
        &recovery_key,
    )
    .unwrap();
    // Same handle, new registration, and the server reserved nothing.
    let re_registration = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000011",
        Some("lease-2"),
        Some(2),
    );
    assert!(re_registration.reserved_identity.is_none());

    let error = checkpoint_for_handoff(&checkpoint, &re_registration, &recovery_key).unwrap_err();
    assert!(
        error.to_string().contains("an earlier registration"),
        "a re-registration must be told the draft is stale, not that it is someone \
         else's account: {error}"
    );
}

#[test]
fn renewed_handoff_does_not_treat_account_handle_as_identity_evidence() {
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let old_handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000010",
        Some("lease-1"),
        Some(1),
    );
    let checkpoint = crate::identity::principal_registration::prepare_registration_checkpoint(
        &old_handoff,
        &old_handoff.device_id,
        &recovery_key,
    )
    .unwrap();
    let mut new_account_handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000011",
        Some("lease-2"),
        Some(2),
    );
    new_account_handoff.account_handle = "bob:auth.example".to_owned();
    let operation = checkpoint.did_operation.clone();
    new_account_handoff.reserved_identity =
        Some(arkret_sdk::ReservedIdentityCreation::from_operation(operation).unwrap());
    new_account_handoff.identity_creation_state =
        Some(arkret_sdk::IdentityCreationLeaseState::Reserved);

    let resumed = checkpoint_for_handoff(&checkpoint, &new_account_handoff, &recovery_key).unwrap();

    assert_eq!(resumed.did, checkpoint.did);
    assert_eq!(resumed.did_operation, checkpoint.did_operation);
    assert_eq!(resumed.account_handle, checkpoint.account_handle);
}

#[test]
fn an_in_flight_server_reservation_does_not_turn_first_run_into_recovery() {
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let mut handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000010",
        Some("lease-1"),
        Some(1),
    );
    let key_source = RecoveryKeySource::for_initial_handoff(Some(&handoff), false);
    assert_eq!(key_source, RecoveryKeySource::GeneratedThisMount);

    // The first register attempt can durably reserve the DID before its
    // response fails. Reconciliation advances the authoritative server
    // state, but the mounted page still owns the generated key and must not
    // reinterpret it as an interrupted/recovery flow.
    let checkpoint = test_checkpoint(
        &handoff,
        &recovery_key,
        crate::state::PendingPrincipalRegistrationStage::RegisterRequestPrepared,
    );
    handoff.reserved_identity = Some(
        arkret_sdk::ReservedIdentityCreation::from_operation(checkpoint.did_operation).unwrap(),
    );
    handoff.identity_creation_state = Some(arkret_sdk::IdentityCreationLeaseState::Reserved);
    assert!(!key_source.requires_existing_key());

    // A reload with no validated key in secure storage must ask for the
    // original key. A reload that retained it returns to confirmation and
    // never claims that the server proved the user saved the words.
    assert_eq!(
        RecoveryKeySource::for_initial_handoff(Some(&handoff), false),
        RecoveryKeySource::ExistingReservation
    );
    assert_eq!(
        RecoveryKeySource::for_initial_handoff(Some(&handoff), true),
        RecoveryKeySource::RecoveredFromSecureStore
    );
    assert!(
        !RecoveryKeySource::RecoveredFromSecureStore.requires_existing_key(),
        "a securely retained key must return to confirmation, not existing-key recovery"
    );
    assert!(
        RecoveryKeySource::RecoveredFromSecureStore.was_recovered_from_secure_store(),
        "the UI must disclose that it is re-offering device-retained material"
    );
    assert!(
        !RecoveryKeySource::GeneratedThisMount.was_recovered_from_secure_store(),
        "a freshly generated key must keep first-run copy"
    );
}

#[test]
fn onboarding_state_rejects_core_ids_in_did_slots() {
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let mut handoff = test_handoff(
        "ak:request:019f0000-0000-7000-8000-000000000020",
        Some("lease-1"),
        Some(1),
    );
    handoff.bound_principal_id =
        Some(arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap());
    handoff.bound_principal_did =
        Some(arkret_sdk::Did::new("did:web:alice.example".to_owned()).unwrap());
    let mut handoff_json = serde_json::to_value(&handoff).unwrap();
    handoff_json["bound_principal_did"] = serde_json::json!("ak:did_core:web:alice.example");
    assert!(
        serde_json::from_value::<crate::state::PendingAccountHandoff>(handoff_json).is_err(),
        "a bound-account DID slot must reject a core id"
    );

    let checkpoint = test_checkpoint(
        &handoff,
        &recovery_key,
        crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed,
    );
    let mut checkpoint_json = serde_json::to_value(&checkpoint).unwrap();
    assert_eq!(checkpoint_json["did"], checkpoint.did.as_str());
    checkpoint_json["did"] = serde_json::json!("ak:did_core:web:alice.example");
    assert!(
        serde_json::from_value::<crate::state::PendingPrincipalRegistration>(checkpoint_json)
            .is_err(),
        "a registration DID slot must reject a core id"
    );
}

fn test_handoff(
    request_id: &str,
    lease_id: Option<&str>,
    lease_fence: Option<u64>,
) -> crate::state::PendingAccountHandoff {
    crate::state::PendingAccountHandoff {
        station_url: "https://principal.example".to_owned(),
        gate_account_base_url: "https://auth.example/_arkret/gate/account".to_owned(),
        request_id: request_id.to_owned(),
        oidc_state: None,
        account_handle: "alice:auth.example".to_owned(),
        account_subject: Some(arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap()),
        holder_jkt: "holder-jkt".to_owned(),
        audience_id: arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkfixture:principal.example")
            .unwrap(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        lease_id: lease_id.map(ToOwned::to_owned),
        lease_fence,
        lease_expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(15)),
        identity_creation_state: Some(arkret_sdk::IdentityCreationLeaseState::Active),
        reserved_identity: None,
        identity_abandonment: None,
        retry_after_ms: None,
        device_id: "ak:device:019f0000-0000-7000-8000-000000000001".to_owned(),
        // `ak:trust_domain:<scope>` — the hyphenated spelling stopped
        // parsing as an Arkret identifier and failed every test built on
        // this fixture inside `prepare_registration_checkpoint`.
        trust_domain: "ak:trust_domain:auth.example".to_owned(),
        bound_principal_id: None,
        bound_principal_did: None,
        bound_device_entry_state: None,
    }
}
