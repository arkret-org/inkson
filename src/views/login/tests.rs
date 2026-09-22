use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::*;

#[test]
fn oidc_callback_completion_claims_are_scoped_to_the_transaction_state() {
    let mut claims = OidcCallbackCompletionClaims::default();

    assert!(claims.claim("state-a"));
    assert!(
        !claims.claim("state-a"),
        "a duplicate Dioxus mount must not exchange one authorization code twice"
    );
    assert!(
        claims.claim("state-b"),
        "a BFCache-restored wasm instance must accept a later authorization transaction"
    );
    assert!(!claims.claim("state-b"));
}

fn dpop_record_for_seed(seed: [u8; 32]) -> crate::state::DpopDeviceKeyRecord {
    crate::identity::account_auth::grant_dpop::dpop_device_key_record_from_seed(
        &URL_SAFE_NO_PAD.encode(seed),
    )
    .expect("dpop record")
}

fn test_active_account(did: &str, device_id: &str) -> crate::config::ActiveAccountContext {
    let did = arkret_sdk::Did::new(did.to_owned()).unwrap();
    let authority = arkret_sdk::AccountId::new(
        arkret_sdk::project_did_to_core_id(&did).unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
    );
    crate::config::ActiveAccountContext::new(
        "ak:profile:test".to_owned(),
        authority,
        arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap(),
        arkret_sdk::PrincipalResolutionProjection {
            did,
            method_history_head: "head-test".to_owned(),
            version_id: "version-test".to_owned(),
            resolution_event_ref: "event-test".to_owned(),
            updated_at: "2026-08-22T00:00:00Z".parse().unwrap(),
        },
        arkret_sdk::DeviceId::new(device_id.to_owned()).unwrap(),
        url::Url::parse("https://principal.example").unwrap(),
    )
    .unwrap()
}

fn dummy_grant() -> PersistedSessionGrant {
    let now = chrono::Utc::now();
    PersistedSessionGrant {
        grant_jwt: "test.grant.jwt".to_owned(),
        session_private_key_pem: "PEM".to_owned(),
        grant_id: "grant-1".to_owned(),
        audience_id: arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        granted_scope: Vec::new(),
        account_id: arkret_sdk::AccountId::new(
            crate::mls_api_helpers::principal_core_id("did:web:alice.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        ),
        device_id: arkret_sdk::DeviceId::new(
            "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
        )
        .unwrap(),
        station_url: url::Url::parse("https://principal.example").unwrap(),
        grant_expires_at: Some(now + chrono::Duration::seconds(3600)),
        stored_at: now,
    }
}

fn pending_handoff_for_test(
    request_id: &str,
    account_handle: &str,
) -> crate::state::PendingAccountHandoff {
    crate::state::PendingAccountHandoff {
        station_url: "https://principal.example".to_owned(),
        gate_account_base_url: "https://auth.example/_arkret/gate/account".to_owned(),
        request_id: request_id.to_owned(),
        oidc_state: None,
        account_handle: account_handle.to_owned(),
        account_subject: Some(arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap()),
        holder_jkt: "holder-jkt".to_owned(),
        audience_id: arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkfixture:principal.example")
            .unwrap(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        lease_id: Some("lease-1".to_owned()),
        lease_fence: Some(1),
        lease_expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(15)),
        identity_creation_state: Some(arkret_sdk::IdentityCreationLeaseState::Active),
        reserved_identity: None,
        identity_abandonment: None,
        retry_after_ms: None,
        device_id: "ak:device:019f0000-0000-7000-8000-000000000001".to_owned(),
        trust_domain: "ak:trust_domain:auth.example".to_owned(),
        bound_principal_id: None,
        bound_principal_did: None,
        bound_device_entry_state: None,
    }
}

#[test]
fn callback_handoff_does_not_use_account_handle_as_identity_evidence() {
    let mut store = crate::state::isolated_store_for_tests("foreign-callback-checkpoint");
    let old_handoff = pending_handoff_for_test(
        "ak:request:019f0000-0000-7000-8000-000000000010",
        "alice:auth.example",
    );
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let checkpoint = crate::identity::principal_registration::prepare_registration_checkpoint(
        &old_handoff,
        &old_handoff.device_id,
        &recovery_key,
    )
    .unwrap();
    store
        .set_pending_principal_registration(Some(checkpoint))
        .unwrap();
    let new_handoff = pending_handoff_for_test(
        "ak:request:019f0000-0000-7000-8000-000000000010",
        "bob:auth.example",
    );

    persist_pending_account_handoff(&mut store, new_handoff.clone()).unwrap();

    assert!(store.pending_principal_registration().is_some());
    assert_eq!(store.pending_account_handoff(), Some(new_handoff));
}

#[tokio::test]
async fn callback_handoff_checkpoint_can_be_awaited_before_full_page_navigation() {
    let path = std::env::temp_dir().join(format!(
        "inkson-test-callback-handoff-durable-{}.json",
        crate::operation::uuid_v7()
    ));
    let mut store = crate::state::LocalStateStore::with_path(path.clone());
    let handoff = pending_handoff_for_test(
        "ak:request:019f0000-0000-7000-8000-000000000013",
        "alice:auth.example",
    );

    persist_pending_account_handoff(&mut store, handoff.clone()).unwrap();
    store.begin_durable_flush().unwrap().wait().await.unwrap();
    drop(store);

    let reopened = crate::state::LocalStateStore::with_path(path);
    assert_eq!(reopened.pending_account_handoff(), Some(handoff));
}

#[test]
fn sign_in_recovers_pending_handoff_holder_from_secure_grant_binding_seed() {
    let mut store = crate::state::isolated_store_for_tests("recover-pending-handoff-holder");
    let secure_store = crate::secure_key_store::MemorySecureKeyStore::default();
    let mut handoff = pending_handoff_for_test(
        "ak:request:019f0000-0000-7000-8000-000000000011",
        "alice:auth.example",
    );
    let pending_store = crate::secure_key_store::PendingLocalStore::new(
        arkret_sdk::DeviceId::new(handoff.device_id.clone()).unwrap(),
    );
    let seed = pending_store
        .ensure_grant_binding_seed(&secure_store)
        .expect("grant-binding seed")
        .seed;
    let expected = dpop_record_for_seed(seed);
    handoff.holder_jkt = expected.jkt.clone();
    let device_id = handoff.device_id.clone();
    let typed_device_id = arkret_sdk::DeviceId::new(device_id.clone()).unwrap();
    store
        .set_pending_account_handoff(Some(handoff))
        .expect("pending handoff");

    assert!(!store.can_resume_pending_login(&typed_device_id));
    assert!(recover_pending_handoff_for_sign_in(
        &mut store,
        &secure_store,
        &device_id
    ));
    assert_eq!(
        store.dpop_device_key().expect("public holder record").jkt,
        expected.jkt
    );
}

#[test]
fn sign_in_recovers_pending_holder_when_handoff_response_was_lost() {
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
    let mut store = crate::state::isolated_store_for_tests("lost-handoff-response");
    let secure_store = crate::secure_key_store::MemorySecureKeyStore::default();
    let device_id =
        arkret_sdk::DeviceId::new("ak:device:019f0000-0000-7000-8000-000000000014".to_owned())
            .unwrap();
    let pending_store = crate::secure_key_store::PendingLocalStore::new(device_id.clone());
    store.begin_pending_login(&device_id, None);
    let seed = pending_store
        .ensure_grant_binding_seed(&secure_store)
        .unwrap()
        .seed;
    let expected = dpop_record_for_seed(seed);
    pending_store
        .save_signing_seed(&secure_store, &[17; 32])
        .unwrap();

    assert!(store.pending_account_handoff().is_none());
    assert!(recover_pending_handoff_for_sign_in(
        &mut store,
        &secure_store,
        device_id.as_str()
    ));
    assert_eq!(store.dpop_device_key().unwrap().jkt, expected.jkt);
    assert!(store.resume_pending_login(&device_id));
    assert_eq!(
        store.pending_login().unwrap().dpop_jkt.as_deref(),
        Some(expected.jkt.as_str())
    );
    assert_eq!(
        pending_store
            .load_grant_binding_seed(&secure_store)
            .unwrap()
            .unwrap()
            .seed,
        seed
    );
    assert!(store.pending_account_handoff().is_none());
    assert_eq!(
        pending_store
            .load_signing_seed(&secure_store)
            .unwrap()
            .unwrap()
            .seed,
        [17; 32]
    );
}

#[test]
fn response_loss_resume_rejects_foreign_device_and_holder() {
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
    let mut store = crate::state::isolated_store_for_tests("lost-handoff-owner-mismatch");
    let secure_store = crate::secure_key_store::MemorySecureKeyStore::default();
    let device_id =
        arkret_sdk::DeviceId::new("ak:device:019f0000-0000-7000-8000-000000000015".to_owned())
            .unwrap();
    let other_device =
        arkret_sdk::DeviceId::new("ak:device:019f0000-0000-7000-8000-000000000016".to_owned())
            .unwrap();
    let pending_store = crate::secure_key_store::PendingLocalStore::new(device_id.clone());
    store.begin_pending_login(&device_id, Some("different-holder"));
    pending_store
        .ensure_grant_binding_seed(&secure_store)
        .unwrap();
    assert!(!recover_pending_handoff_for_sign_in(
        &mut store,
        &secure_store,
        device_id.as_str()
    ));
    assert!(!store.can_resume_pending_login(&device_id));
    assert!(!recover_pending_handoff_for_sign_in(
        &mut store,
        &secure_store,
        other_device.as_str()
    ));
}

#[test]
fn sign_in_starts_fresh_when_pending_handoff_holder_is_missing() {
    let mut store = crate::state::isolated_store_for_tests("missing-pending-handoff-holder");
    let secure_store = crate::secure_key_store::MemorySecureKeyStore::default();
    let handoff = pending_handoff_for_test(
        "ak:request:019f0000-0000-7000-8000-000000000012",
        "alice:auth.example",
    );
    let device_id = handoff.device_id.clone();
    store
        .set_pending_account_handoff(Some(handoff))
        .expect("pending handoff");

    assert!(!recover_pending_handoff_for_sign_in(
        &mut store,
        &secure_store,
        &device_id
    ));
}

#[test]
fn session_status_signed_out_without_token_or_grant() {
    assert_eq!(compute_session_status("", None), "signed-out");
    // Whitespace-only token counts as no token.
    assert_eq!(compute_session_status("   ", None), "signed-out");
}

#[test]
fn session_status_session_expired_when_grant_outlives_token() {
    // Soft-logout state: the live credential is absent but the grant is
    // still present. Refresh button can restore/rotate it.
    let grant = dummy_grant();
    assert_eq!(compute_session_status("", Some(&grant)), "session-expired");
}

#[test]
fn session_status_signed_in_when_token_present() {
    let grant = dummy_grant();
    assert_eq!(
        compute_session_status("nonempty.token", Some(&grant)),
        "signed-in"
    );
    // Token without grant (dev-login style) is also signed-in.
    assert_eq!(compute_session_status("dev.token", None), "signed-in");
}

#[test]
fn failed_callback_prompts_fresh_sign_in() {
    assert_eq!(
        discard_failed_oidc_callback("Account Authority handoff failed".to_owned()),
        "Account Authority handoff failed Start sign-in again."
    );
}

fn api_exchange_error(status: u16, code: &str) -> garth::Error {
    garth::Error::Api {
        status,
        error: Box::new(arkret_sdk::Problem::from_code(code, "fixture")),
    }
}

#[test]
fn returning_session_errors_preserve_retry_setup_and_security_boundaries() {
    assert!(matches!(
        classify_returning_session_exchange_error(garth::Error::Http("offline".to_owned())),
        ReturningSessionExchangeError::Retryable(_)
    ));
    for code in [
        arkret_sdk::error_codes::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
        arkret_sdk::error_codes::ErrorCode::SESSION_GRANT_REPLAY_EXPIRED,
        arkret_sdk::error_codes::ErrorCode::SESSION_GRANT_REPLAY_TERMINAL,
    ] {
        assert!(matches!(
            classify_returning_session_exchange_error(api_exchange_error(503, code)),
            ReturningSessionExchangeError::Fatal(_)
        ));
    }
    for status in [429, 503] {
        assert!(matches!(
            classify_returning_session_exchange_error(api_exchange_error(
                status,
                "auth_unavailable"
            )),
            ReturningSessionExchangeError::Retryable(_)
        ));
    }
    assert!(matches!(
        classify_returning_session_exchange_error(api_exchange_error(
            403,
            arkret_sdk::error_codes::ErrorCode::DEVICE_UNAUTHORIZED,
        )),
        ReturningSessionExchangeError::DeviceSetupRequired(_)
    ));
    assert!(matches!(
        classify_returning_session_exchange_error(api_exchange_error(
            409,
            arkret_sdk::error_codes::ErrorCode::DEVICE_REVOCATION_PENDING,
        )),
        ReturningSessionExchangeError::Blocked(ReturningDeviceBlockReason::RevocationPending, _)
    ));
    assert!(matches!(
        classify_returning_session_exchange_error(api_exchange_error(
            403,
            arkret_sdk::error_codes::ErrorCode::DEVICE_REVOKED,
        )),
        ReturningSessionExchangeError::Blocked(ReturningDeviceBlockReason::Revoked, _)
    ));
    assert!(matches!(
        classify_returning_session_exchange_error(api_exchange_error(
            403,
            arkret_sdk::error_codes::ErrorCode::DEVICE_GENERATION_FENCED,
        )),
        ReturningSessionExchangeError::Blocked(ReturningDeviceBlockReason::GenerationFenced, _)
    ));
    assert!(matches!(
        classify_returning_session_exchange_error(api_exchange_error(
            404,
            arkret_sdk::error_codes::ErrorCode::PRINCIPAL_UNKNOWN,
        )),
        ReturningSessionExchangeError::Fatal(message)
            if message.contains("No new identity was created")
                && message.contains("recovery or diagnostics")
    ));
    assert!(matches!(
        classify_returning_session_exchange_error(api_exchange_error(
            401,
            arkret_sdk::error_codes::ErrorCode::SIGNATURE_INVALID,
        )),
        ReturningSessionExchangeError::Fatal(_)
    ));
}

#[test]
fn returning_verification_retries_transport_but_not_invalid_evidence() {
    assert_eq!(
        returning_callback_resume_url(
            "http://127.0.0.1:8080/auth/callback?code=secret&state=old#fragment",
            "bound state"
        )
        .unwrap(),
        "http://127.0.0.1:8080/auth/callback?state=bound+state"
    );
    use arkret_sdk::http_client::Error;
    for status in [429, 503] {
        let error = anyhow::Error::new(Error::Api {
            status,
            error: Box::new(arkret_sdk::Problem::from_code(
                "temporarily_unavailable",
                "fixture",
            )),
        })
        .context("current principal");
        assert!(matches!(
            classify_returning_verification_error("verification", error),
            ReturningSessionExchangeError::Retryable(_)
        ));
    }
    assert!(matches!(
        classify_returning_verification_error("verification", Error::Http("offline".into()).into()),
        ReturningSessionExchangeError::Retryable(_)
    ));
    for error in [
        anyhow::anyhow!("503 in untrusted evidence is not a transport status"),
        Error::Api {
            status: 403,
            error: Box::new(arkret_sdk::Problem::from_code("device_revoked", "fixture")),
        }
        .into(),
        Error::Protocol("authorization event mismatch".into()).into(),
    ] {
        assert!(matches!(
            classify_returning_verification_error("verification", error),
            ReturningSessionExchangeError::Fatal(_)
        ));
    }
}

#[test]
fn oidc_callback_restores_bootstrap_device_seed_scope() {
    let authority = arkret_sdk::AccountId::new(
        crate::mls_api_helpers::principal_core_id("did:web:old.example").unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
    );
    let device_id =
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000000".to_owned())
            .unwrap();
    let _scope =
        crate::secure_key_store::DeviceSeedScopeTestGuard::replace(Some((&authority, &device_id)));
    let _signer = crate::event_signer::ActiveSignerTestGuard::replace(None);

    restore_oidc_callback_device_seed_scope("ak:device:01964137-0000-7000-8000-000000000001")
        .expect("pending local store");

    assert_eq!(crate::secure_key_store::active_device_seed_scope(), None);
    assert_eq!(
        crate::secure_key_store::pending_login_device_id()
            .as_ref()
            .map(arkret_sdk::DeviceId::as_str),
        Some("ak:device:01964137-0000-7000-8000-000000000001")
    );
}

#[test]
fn account_first_sign_in_has_no_returning_principal() {
    assert_eq!(returning_sign_in_principal("").unwrap(), None);
}

#[test]
fn returning_sign_in_keeps_the_resolvable_principal_assertion() {
    let actor = "did:webvh:z6mkfixture:alice.example";

    assert_eq!(
        returning_sign_in_principal(actor)
            .unwrap()
            .expect("returning principal")
            .as_str(),
        actor
    );
}

#[test]
fn core_only_profile_is_not_repaired_into_resolution_material() {
    let principal = arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
    let principal_core = arkret_sdk::project_did_to_core_id(&principal).unwrap();
    assert!(returning_sign_in_principal(principal_core.as_str()).is_err());
}

#[test]
fn returning_handoff_resume_is_bound_to_the_exact_coauth_callback() {
    let mut handoff = pending_handoff_for_test(
        "ak:request:019f0000-0000-7000-8000-000000000013",
        "alice:auth.example",
    );
    handoff.oidc_state = Some("state-a".to_owned());
    handoff.bound_principal_id =
        Some(arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap());
    handoff.bound_principal_did =
        Some(arkret_sdk::Did::new("did:web:alice.example".to_owned()).unwrap());

    assert!(can_resume_returning_handoff_for_callback(
        &handoff,
        "state-a",
        &handoff.device_id,
        &handoff.holder_jkt,
        &handoff.gate_account_base_url,
    ));
    assert!(
        !can_resume_returning_handoff_for_callback(
            &handoff,
            "state-b",
            &handoff.device_id,
            &handoff.holder_jkt,
            &handoff.gate_account_base_url,
        ),
        "a new Coauth callback must observe its newly selected account"
    );
}

#[test]
fn bound_handoff_uses_returning_device_only_for_the_same_account() {
    let alice = arkret_sdk::Did::new("did:web:alice.example".to_owned()).unwrap();
    let bob = arkret_sdk::Did::new("did:web:bob.example".to_owned()).unwrap();
    let device =
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001".to_owned())
            .unwrap();
    let disposition = AccountHandoffDisposition::Bound {
        principal_id: arkret_sdk::project_did_to_core_id(&alice).unwrap(),
        did: alice.clone(),
    };

    assert_eq!(
        authenticated_account_route(&disposition, Some(&alice), Some(&device)),
        AuthenticatedAccountRoute::ReturningSession(device.clone()),
    );
    assert_eq!(
        authenticated_account_route(&disposition, Some(&bob), Some(&device)),
        AuthenticatedAccountRoute::DeviceSetupRequired,
        "a different Coauth account must enter device setup",
    );
    assert_eq!(
        authenticated_account_route(&disposition, Some(&alice), None),
        AuthenticatedAccountRoute::DeviceSetupRequired,
        "a matching account without durable device material is a new device",
    );
}

#[test]
fn server_identity_creation_states_ignore_local_returning_candidates() {
    let principal = arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
    let device =
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001".to_owned())
            .unwrap();
    let active = AccountHandoffDisposition::IdentityCreationActive(Box::new(
        arkret_sdk::IdentityCreationLease {
            identity_creation_lease_id: "lease-fixture".to_owned(),
            fence: 1,
            state: arkret_sdk::IdentityCreationLeaseState::Active,
            expires_at: Utc::now() + chrono::Duration::minutes(15),
            reserved_identity: None,
        },
    ));
    let busy = AccountHandoffDisposition::IdentityCreationBusy {
        retry_after_ms: 1_000,
        expires_at: Utc::now() + chrono::Duration::minutes(15),
    };

    assert_eq!(
        authenticated_account_route(&active, Some(&principal), Some(&device)),
        AuthenticatedAccountRoute::IdentityCreation,
    );
    assert_eq!(
        authenticated_account_route(&busy, Some(&principal), Some(&device)),
        AuthenticatedAccountRoute::IdentityCreationBusy,
    );
}

#[test]
fn returning_sign_in_requires_the_durable_device_identity_key() {
    let secure_store = crate::secure_key_store::MemorySecureKeyStore::default();
    let account = test_active_account(
        "did:web:alice.example",
        "ak:device:01964137-0000-7000-8000-000000000001",
    );
    let user_store = crate::secure_key_store::UserLocalStore::new(
        account.authority.clone(),
        account.device_id.clone(),
    )
    .unwrap();
    user_store
        .save_device_id(&secure_store, &account.device_id)
        .unwrap();

    assert_eq!(
        returning_device_id(&secure_store, &account).unwrap(),
        None,
        "a public device id without its long-term signing key is a new device"
    );

    user_store
        .save_signing_seed(&secure_store, &[41_u8; 32])
        .unwrap();
    assert_eq!(
        returning_device_id(&secure_store, &account)
            .unwrap()
            .as_deref(),
        Some(account.device_id.as_str()),
        "the typed profile and secure scope select the same device"
    );
}

#[tokio::test]
async fn completed_login_promotes_verified_authority_and_preserves_device_key() {
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
    let _signer = crate::event_signer::ActiveSignerTestGuard::replace(None);
    let mut store = crate::state::isolated_store_for_tests("completed-login-dpop-key");
    let secure_store = crate::secure_key_store::MemorySecureKeyStore::default();
    let device = "ak:device:01964137-0000-7000-8000-000000000001";
    let account = test_active_account("did:web:alice.example", device);
    let pending_device = "ak:device:01964137-0000-7000-8000-000000000002";
    let pending_device_id = arkret_sdk::DeviceId::new(pending_device.to_owned()).unwrap();
    let old_seed = [3_u8; 32];
    let new_record = dpop_record_for_seed([7_u8; 32]);

    let user_store = crate::secure_key_store::UserLocalStore::new(
        account.authority.clone(),
        account.device_id.clone(),
    )
    .unwrap();
    user_store
        .save_signing_seed(&secure_store, &old_seed)
        .expect("old account seed");
    store.begin_pending_login(&pending_device_id, Some(&new_record.jkt));

    let prepared =
        prepare_completed_login_dpop_key(&secure_store, &account, pending_device, &new_record)
            .await
            .expect("prepare completed login dpop");
    assert!(
        store.active_principal_id().is_none(),
        "fallible secure preparation must not switch the public account"
    );
    let mut grant = dummy_grant();
    grant.account_id = account.authority.clone();
    grant.device_id = account.device_id.clone();
    promote_completed_login_state(
        &mut store,
        &secure_store,
        &account,
        &new_record,
        prepared,
        Some("alice"),
        grant.clone(),
    )
    .expect("promote completed login");

    assert_eq!(store.active_authority(), Some(account.authority.clone()));
    assert_eq!(
        store.known_profile_id_for_authority(&account.authority),
        Some(account.profile_id.clone())
    );
    assert_eq!(store.load().primary_handle, "alice");
    assert_eq!(store.session_grant(), Some(grant));
    assert!(store.pending_login().is_none());

    let loaded_seed = user_store
        .load_signing_seed(&secure_store)
        .expect("load account seed")
        .expect("account seed");
    assert_eq!(loaded_seed.seed, old_seed);
    let grant_binding = crate::secure_key_store::load_grant_binding_seed(&secure_store)
        .expect("load grant-binding seed")
        .expect("grant-binding seed");
    assert_eq!(grant_binding.seed, [7_u8; 32]);
    let loaded_record = store
        .load_dpop_device_key_with_secure_store(&secure_store)
        .expect("load account dpop")
        .expect("account dpop");
    assert_eq!(loaded_record.jkt, new_record.jkt);
    let public_record = store.dpop_device_key().expect("public dpop");
    assert_eq!(public_record.jkt, new_record.jkt);
    assert!(public_record.seed_b64.is_empty());
}
