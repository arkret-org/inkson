use super::*;

fn test_client_config(
    server_url: &str,
    principal: impl AsRef<str>,
    device_id: impl AsRef<str>,
    credential: impl Into<String>,
) -> ClientConfig {
    ClientConfig::authenticated(
        test_active_account(principal.as_ref(), server_url, device_id.as_ref()),
        credential.into(),
    )
}

fn test_active_account(
    principal: &str,
    server_url: &str,
    device_id: &str,
) -> crate::config::ActiveAccountContext {
    crate::test_support::AccountFixture::new(principal)
        .server_url(server_url)
        .device(device_id)
        .build()
}

fn test_authority(principal: &str) -> arkret_sdk::AccountId {
    crate::test_support::authority(principal)
}

#[test]
fn direct_route_resolves_agent_peer_independently_of_reply_participation() {
    let contacts: Vec<crate::models::ContactListRow> = serde_json::from_value(serde_json::json!([
        {
            "peer": {"kind": "human", "account_id": {
                "principal_id": "ak:did_core:web:example.com:users:alice",
                "station_id": "ak:did_core:web:principal.example"
            }},
            "state": "accepted",
            "next_prepare_input": {
                "contact_round_id": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "version": 2,
                "predecessor_event_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
            },
            "granted_to_peer_scopes": ["direct_message"],
            "granted_by_peer_scopes": ["direct_message"],
            "bidirectional_scopes": ["direct_message"],
            "contact_agents": [{
                "actor_id": {
                    "kind": "service",
                    "service_id": "ak:did_core:web:example.com:agents:aa"
                },
                "controller_account_id": {
                    "principal_id": "ak:did_core:web:example.com:users:alice",
                    "station_id": "ak:did_core:web:principal.example"
                },
                "agent_slug": "aa",
                "direct_conversation": {
                    "realm_id": "ak:realm:AUuXpUO-yBwwyCNB7AS1IIm5_sgsxyEsG7PBmmkXdFog",
                    "main_strand_id": "ak:strand:AYdzR-cxE5CaMt7Xeab7lJ6oTMVcXRDFIfPqcXOahgQ4",
                    "binding_event_ref": "ak:event:AQmnyvvBmKOWOEOSD2rAYsVBQn6vJ_wdbdUY8CKUGB5c",
                    "state": "found"
                }
            }]
        }
    ]))
    .expect("contact fixture");

    assert_eq!(
        route_surface::direct_conversation_peer_id(
            &contacts,
            "ak:realm:AUuXpUO-yBwwyCNB7AS1IIm5_sgsxyEsG7PBmmkXdFog",
            "ak:strand:AYdzR-cxE5CaMt7Xeab7lJ6oTMVcXRDFIfPqcXOahgQ4",
        ),
        "ak:did_core:web:example.com:agents:aa"
    );
}

#[test]
fn unchanged_session_refresh_is_a_noop_for_reactive_and_persisted_state() {
    let grant = session_grant(3600);
    let config = test_client_config(
        "https://example.test",
        grant.account_id.principal_id.clone(),
        grant.device_id.clone(),
        grant.grant_jwt.clone(),
    );

    assert_eq!(
        session_refresh_write_plan(Some(&grant), &grant.grant_jwt, &config, &grant, &config,),
        SessionRefreshWritePlan {
            grant: false,
            credential: false,
            config: false,
        }
    );
}

#[test]
fn personal_handle_from_account_handle_keeps_full_handle_verbatim() {
    // `account.handle` from `account_me` is the FULL canonical handle. It must
    // be returned as-is — never have the server domain appended again, which
    // produced the `alice:local.host:local.host` double-domain regression.
    assert_eq!(
        personal_handle_from_account_handle("alice:local.host").as_deref(),
        Some("alice:local.host")
    );
    assert_eq!(
        personal_handle_from_account_handle("@alice:local.host").as_deref(),
        Some("alice:local.host")
    );
    // A handle on a different domain than the active server is preserved, not
    // rewritten to the server's domain.
    assert_eq!(
        personal_handle_from_account_handle("alice:example.com").as_deref(),
        Some("alice:example.com")
    );
}

#[test]
fn personal_handle_from_account_handle_rejects_missing_or_invalid_claim_handle() {
    assert_eq!(personal_handle_from_account_handle("@alice"), None);
    assert_eq!(personal_handle_from_account_handle("  "), None);
}

#[test]
fn merge_personal_handles_adds_and_deduplicates_sources() {
    let merged = merge_personal_handles(
        &[
            "alice:local.host".to_owned(),
            "bob:remote.example".to_owned(),
        ],
        [
            "@Alice:Local.Host".to_owned(),
            "carol:local.host".to_owned(),
            " ".to_owned(),
        ],
    );

    assert_eq!(
        merged,
        vec![
            "alice:local.host".to_owned(),
            "bob:remote.example".to_owned(),
            "carol:local.host".to_owned(),
        ]
    );
    assert_eq!(personal_handles_status_for(&merged), "3 handles");
}

/// The App component installs a default push-token provider on
/// first render so `device-summary` never
/// shows the `"no PushTokenProvider installed"` warning in
/// production. The helper is idempotent (`OnceLock` inside
/// `set_push_token_provider`) — calling it twice in the same
/// process is safe.
#[test]
fn ensure_default_push_token_provider_installs_a_provider_and_is_idempotent() {
    // Provider state is process-wide via `OnceLock`. We don't
    // assert which concrete provider was installed (varies by
    // target_arch / target_os); we only assert the slot becomes
    // populated and stays populated across a second call.
    super::ensure_default_push_token_provider();
    let after_first = crate::push::push_token_provider();
    assert!(
        after_first.is_some(),
        "first ensure call must install a provider"
    );
    super::ensure_default_push_token_provider();
    assert!(
        crate::push::push_token_provider().is_some(),
        "second ensure call must keep the provider installed"
    );
}

#[test]
fn unread_notification_count_ignores_read_and_archived_items() {
    let realm_id = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let mut projection = (1..=5)
        .map(|ordinal| {
            crate::state::projection::notifications::test_event_notification(
                ordinal,
                arkret_sdk::NotificationKind::Message,
                realm_id,
                None,
                serde_json::json!({}),
            )
        })
        .collect::<Vec<_>>();
    if let crate::state::StoredNotification::Event { notification } = &mut projection[1] {
        notification.state = arkret_sdk::NotificationState::Read;
    }
    if let crate::state::StoredNotification::Event { notification } = &mut projection[4] {
        notification.state = arkret_sdk::NotificationState::Archived;
    }
    let mut snapshot = ClientLocalState {
        notification_projection: projection,
        ..ClientLocalState::default()
    };
    snapshot.notification_client_state.insert(
        "ak:notification:0196419b-0000-7000-8000-000000000003".to_owned(),
        crate::state::NotificationClientState {
            read: true,
            archived: false,
        },
    );
    snapshot.notification_client_state.insert(
        "ak:notification:0196419b-0000-7000-8000-000000000004".to_owned(),
        crate::state::NotificationClientState {
            read: false,
            archived: true,
        },
    );

    assert_eq!(unread_notification_count(&snapshot), 1);
}

fn session_grant(grant_expires_in: i64) -> PersistedSessionGrant {
    let now = chrono::Utc::now();
    PersistedSessionGrant {
        grant_jwt: "grant.jwt".to_owned(),
        session_private_key_pem: "PEM".to_owned(),
        grant_id: "grant-1".to_owned(),
        audience_id: arkret_sdk::DidCoreId::new("ak:did_core:web:local.host").unwrap(),
        granted_scope: Vec::new(),
        account_id: arkret_sdk::AccountId::new(
            crate::mls_api_helpers::principal_core_id("did:web:alice.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:local.host").unwrap(),
        ),
        device_id: arkret_sdk::DeviceId::new(
            "ak:device:01964137-0000-7000-8000-000000000001".to_owned(),
        )
        .unwrap(),
        station_url: url::Url::parse("https://local.host").unwrap(),
        grant_expires_at: Some(now + chrono::Duration::seconds(grant_expires_in)),
        stored_at: now,
    }
}

fn session_grant_for_config(grant_expires_in: i64, config: &ClientConfig) -> PersistedSessionGrant {
    let mut grant = session_grant(grant_expires_in);
    grant.audience_id = config
        .active_account
        .as_ref()
        .expect("test config has an active account")
        .authority
        .station_id
        .clone();
    grant
}

#[test]
fn account_scope_owner_alone_is_not_bootstrap_refresh_material() {
    let actor = "did:web:alice.example";
    let mut store = crate::state::isolated_store_for_tests("account-scope-no-restore");
    store.switch_test_account(actor);
    let account = test_active_account(
        actor,
        "https://local.host",
        "ak:device:01964137-0000-7000-8000-000000000001",
    );

    assert!(!has_bootstrap_refresh_material(&store, Some(&account)));
}

#[test]
fn current_device_authorization_detects_verified_current_device() {
    let device = "ak:device:01964137-0000-7000-8000-000000000001";
    let viewer = serde_json::json!({
        "devices": [{
            "device_id": device,
            "status": "active",
            "verification_state": "verified"
        }]
    });

    assert_eq!(
        current_device_authorization_from_account_viewer(&viewer, device),
        Some(true)
    );
}

#[test]
fn current_device_authorization_detects_unresolved_new_device() {
    let device = "ak:device:01964137-0000-7000-8000-000000000002";
    let viewer = serde_json::json!({
        "devices": [{
            "device_id": device,
            "status": "active",
            "verification_state": "unresolved"
        }]
    });

    assert_eq!(
        current_device_authorization_from_account_viewer(&viewer, device),
        Some(false)
    );
}

#[test]
fn current_device_authorization_treats_missing_current_device_as_unauthorized() {
    let device = "ak:device:01964137-0000-7000-8000-000000000002";
    let viewer = serde_json::json!({
        "devices": [{
            "device_id": "ak:device:01964137-0000-7000-8000-000000000001",
            "status": "active",
            "verification_state": "verified"
        }]
    });

    assert_eq!(
        current_device_authorization_from_account_viewer(&viewer, device),
        Some(false)
    );
}

#[test]
fn current_device_authorization_rejects_active_status_without_trust_evidence() {
    let device = "ak:device:01964137-0000-7000-8000-000000000001";
    let viewer = serde_json::json!({
        "devices": [{
            "device_id": device,
            "status": "active"
        }]
    });

    assert_eq!(
        current_device_authorization_from_account_viewer(&viewer, device),
        Some(false)
    );
}

#[test]
fn current_device_authorization_accepts_verified_status_even_when_sdk_status_is_active() {
    let device = "ak:device:01964137-0000-7000-8000-000000000001";
    let viewer = serde_json::json!({
        "devices": [{
            "device_id": device,
            "status": "active",
            "verification_state": "verified"
        }]
    });

    assert_eq!(
        current_device_authorization_from_account_viewer(&viewer, device),
        Some(true)
    );
}

#[test]
fn current_device_authorization_rejects_stale_verification() {
    let device = "ak:device:01964137-0000-7000-8000-000000000001";
    let viewer = serde_json::json!({
        "devices": [{
            "device_id": device,
            "status": "active",
            "verification_state": "stale"
        }]
    });

    assert_eq!(
        current_device_authorization_from_account_viewer(&viewer, device),
        Some(false)
    );
}

#[test]
fn current_device_authorization_rejects_revoked_status() {
    let device = "ak:device:01964137-0000-7000-8000-000000000001";
    let viewer = serde_json::json!({
        "devices": [{
            "device_id": device,
            "status": "revoked"
        }]
    });

    assert_eq!(
        current_device_authorization_from_account_viewer(&viewer, device),
        Some(false)
    );
}

#[test]
fn account_has_other_active_devices_detects_prior_device() {
    let current = "ak:device:01964137-0000-7000-8000-000000000002";
    let prior = "ak:device:01964137-0000-7000-8000-000000000001";
    let viewer = serde_json::json!({
        "devices": [
            {
                "device_id": prior,
                "status": "active",
                "verification_state": "verified"
            },
            {
                "device_id": current,
                "status": "active",
                "verification_state": "unresolved"
            }
        ]
    });

    assert!(account_has_other_active_devices_from_account_viewer(
        &viewer, current
    ));
}

#[test]
fn account_has_other_active_devices_ignores_revoked_prior_device() {
    let current = "ak:device:01964137-0000-7000-8000-000000000002";
    let prior = "ak:device:01964137-0000-7000-8000-000000000001";
    let viewer = serde_json::json!({
        "devices": [
            {
                "device_id": prior,
                "status": "revoked",
                "verification_state": "verified",
                "revoked_at": "2026-06-14T00:00:00.000Z"
            },
            {
                "device_id": current,
                "status": "active",
                "verification_state": "verified"
            }
        ]
    });

    assert!(!account_has_other_active_devices_from_account_viewer(
        &viewer, current
    ));
}

#[test]
fn current_device_authorization_rejects_authorized_at_without_verification() {
    let device = "ak:device:01964137-0000-7000-8000-000000000001";
    let viewer = serde_json::json!({
        "devices": [{
            "device_id": device,
            "authorized_at": "2026-04-28T12:00:00.000Z"
        }]
    });

    assert_eq!(
        current_device_authorization_from_account_viewer(&viewer, device),
        Some(false)
    );
}

#[test]
fn current_device_authorization_rejects_current_record_without_authorization_evidence() {
    let device = "ak:device:01964137-0000-7000-8000-000000000001";
    let viewer = serde_json::json!({
        "devices": [{
            "device_id": device
        }]
    });

    assert_eq!(
        current_device_authorization_from_account_viewer(&viewer, device),
        Some(false)
    );
}

#[test]
fn device_authorization_required_fails_closed_without_device_inventory() {
    let device = "ak:device:01964137-0000-7000-8000-000000000001";
    assert!(device_authorization_required_from_account_viewer(
        &serde_json::json!({}),
        device
    ));
    assert!(device_authorization_required_from_account_viewer(
        &serde_json::json!({ "devices": [] }),
        device
    ));
}

#[test]
fn device_authorization_required_allows_only_verified_device() {
    let device = "ak:device:01964137-0000-7000-8000-000000000001";
    assert!(!device_authorization_required_from_account_viewer(
        &serde_json::json!({
            "devices": [{
                "device_id": device,
                "verification_state": "verified"
            }]
        }),
        device
    ));
    assert!(device_authorization_required_from_account_viewer(
        &serde_json::json!({
            "devices": [{
                "device_id": device,
                "verification_state": "unverified"
            }]
        }),
        device
    ));
}

#[test]
fn recovery_setup_prompt_waits_for_server_state() {
    assert!(recovery_setup_prompt_required_for_local_state(
        Some(false),
        false
    ));
    assert!(!recovery_setup_prompt_required_for_local_state(
        Some(false),
        true
    ));
    assert!(recovery_setup_prompt_required_for_account_state(
        Some(false),
        false,
        false
    ));
    assert!(!recovery_setup_prompt_required_for_account_state(
        Some(false),
        false,
        true
    ));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn recovery_auto_prompt_ignores_old_shown_flag_for_local_only_key() {
    let mut store = isolated_store("recovery-local-only-auto_prompt");
    store.save_plain_local_data(RECOVERY_AUTO_PROMPT_SHOWN_KEY, "1");
    store.save_plain_local_data(
        "recovery.state.v1",
        serde_json::json!({
            "recovery_key_fingerprint": "sha256:abc",
            "recovery_key_rotated_at": "2026-06-13T00:00:00.000Z"
        })
        .to_string(),
    );

    assert_eq!(
        recovery_auto_prompt_pending_local_only_fingerprint(&store, Some(false)).as_deref(),
        Some("sha256:abc")
    );
    assert!(!recovery_auto_prompt_already_prompted(&store, Some(false)));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn recovery_auto_prompt_local_only_key_is_prompted_once_per_fingerprint() {
    let mut store = isolated_store("recovery-local-only-auto_prompt-once");
    store.save_plain_local_data(RECOVERY_AUTO_PROMPT_SHOWN_KEY, "1");
    store.save_plain_local_data(
        "recovery.state.v1",
        serde_json::json!({
            "recovery_key_fingerprint": "sha256:abc",
            "recovery_key_rotated_at": "2026-06-13T00:00:00.000Z"
        })
        .to_string(),
    );
    store.save_plain_local_data(RECOVERY_AUTO_PROMPT_LOCAL_ONLY_SHOWN_KEY, "sha256:abc");

    assert!(recovery_auto_prompt_pending_local_only_fingerprint(&store, Some(false)).is_none());
    assert!(recovery_auto_prompt_already_prompted(&store, Some(false)));
}

// Shared hermetic state-store fixture from `local_state`.

#[cfg(not(target_arch = "wasm32"))]
use crate::state::isolated_store_for_tests as isolated_store;

#[test]
fn boot_session_credential_ignores_config_token_without_boot_material() {
    let state = ClientLocalState::default();
    let config = test_client_config(
        "https://local.host",
        "did:web:alice.example",
        "ak:device:01964137-0000-7000-8000-000000000001",
        "config-token",
    );

    assert_eq!(
        initial_session_credential_from_state(&state, &config, 1_000),
        ""
    );
}

#[test]
fn boot_session_credential_uses_fresh_session_grant() {
    let now = chrono::Utc::now().timestamp();
    let config = test_client_config(
        "https://local.host",
        "did:web:alice.example",
        "ak:device:01964137-0000-7000-8000-000000000001",
        "bridge-token",
    );
    let state = ClientLocalState {
        session_grant: Some(session_grant_for_config(3600, &config)),
        ..Default::default()
    };

    assert_eq!(
        initial_session_credential_from_state(&state, &config, now),
        "grant.jwt"
    );
}

#[test]
fn boot_session_credential_ignores_expired_session_grant() {
    let now = chrono::Utc::now().timestamp();
    let config = test_client_config(
        "https://local.host",
        "did:web:alice.example",
        "ak:device:01964137-0000-7000-8000-000000000001",
        "bridge-token",
    );
    let state = ClientLocalState {
        session_grant: Some(session_grant_for_config(-1, &config)),
        ..Default::default()
    };

    assert_eq!(
        initial_session_credential_from_state(&state, &config, now),
        ""
    );
}

#[test]
fn boot_session_credential_ignores_session_grant_for_other_server() {
    let now = chrono::Utc::now().timestamp();
    let config = test_client_config(
        "https://local.host",
        "did:web:alice.example",
        "ak:device:01964137-0000-7000-8000-000000000001",
        "bridge-token",
    );
    let mut grant = session_grant_for_config(3600, &config);
    grant.station_url = url::Url::parse("https://other.local.host").unwrap();
    let state = ClientLocalState {
        session_grant: Some(grant),
        ..Default::default()
    };

    assert_eq!(
        initial_session_credential_from_state(&state, &config, now),
        ""
    );
}

#[test]
fn boot_session_credential_requires_the_complete_active_account_binding() {
    let now = chrono::Utc::now().timestamp();
    let config = test_client_config(
        "https://local.host",
        "did:web:alice.example",
        "ak:device:01964137-0000-7000-8000-000000000001",
        "",
    );

    let valid_grant = session_grant_for_config(3600, &config);
    let mut wrong_principal = valid_grant.clone();
    wrong_principal.account_id.principal_id =
        crate::mls_api_helpers::principal_core_id("did:web:bob.example").unwrap();
    let mut wrong_device = valid_grant.clone();
    wrong_device.device_id =
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000099".to_owned())
            .unwrap();
    let mut wrong_audience = valid_grant;
    wrong_audience.audience_id =
        arkret_sdk::DidCoreId::new("ak:did_core:web:other.local.host").unwrap();

    for grant in [wrong_principal, wrong_device, wrong_audience] {
        let state = ClientLocalState {
            session_grant: Some(grant),
            ..Default::default()
        };
        assert_eq!(
            initial_session_credential_from_state(&state, &config, now),
            ""
        );
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn bootstrap_can_start_with_session_grant_without_live_credential() {
    let mut store = isolated_store("bootstrap-grant");
    let mut grant = session_grant(3600);
    let account = test_active_account(
        grant.account_id.principal_id.as_str(),
        grant.station_url.as_str(),
        grant.device_id.as_str(),
    );
    grant.audience_id = account.authority.station_id.clone();
    store.set_session_grant(Some(grant));

    assert!(has_bootstrap_refresh_material(&store, Some(&account)));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn onboarding_grant_cannot_start_bootstrap_before_account_commit() {
    let mut store = isolated_store("bootstrap-onboarding-transaction");
    store.set_session_grant(Some(session_grant(3600)));

    assert!(!has_bootstrap_refresh_material(&store, None));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn bootstrap_rejects_grant_for_a_different_active_account() {
    let mut store = isolated_store("bootstrap-account-mismatch");
    store.set_session_grant(Some(session_grant(3600)));
    let other = test_active_account(
        "did:web:bob.example",
        "https://local.host",
        "ak:device:01964137-0000-7000-8000-000000000002",
    );

    assert!(!has_bootstrap_refresh_material(&store, Some(&other)));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn bootstrap_ignores_session_grant_for_other_server() {
    let mut store = isolated_store("bootstrap-other-server");
    let mut grant = session_grant(3600);
    grant.station_url = url::Url::parse("https://other.local.host").unwrap();
    store.set_session_grant(Some(grant));
    let account = test_active_account(
        "did:web:alice.example",
        "https://local.host",
        "ak:device:01964137-0000-7000-8000-000000000001",
    );

    assert!(!has_bootstrap_refresh_material(&store, Some(&account)));
}

#[test]
fn boot_state_restores_when_refresh_material_exists_without_token() {
    assert_eq!(
        SessionBootState::from_boot_material("", true),
        SessionBootState::Restoring
    );
    assert_eq!(
        SessionBootState::from_boot_material("sx-live", true),
        SessionBootState::Checking
    );
    assert_eq!(
        SessionBootState::from_boot_material("", false),
        SessionBootState::Unauthenticated
    );
}

#[test]
fn boot_state_waits_for_secure_store_before_auth_state_is_known() {
    let account = test_active_account(
        "did:web:alice.example",
        "https://local.host",
        "ak:device:01964137-0000-7000-8000-000000000001",
    );
    assert_eq!(
        session_boot_state_from_bootstrap_material("", false, account.did().as_str(), false),
        SessionBootState::Restoring
    );
    assert_eq!(
        session_boot_state_from_bootstrap_material("", false, "", false),
        SessionBootState::Restoring
    );
    assert_eq!(
        session_boot_state_from_bootstrap_material("", false, account.did().as_str(), true),
        SessionBootState::Unauthenticated
    );
    assert_eq!(
        session_boot_state_from_bootstrap_material("sx-live", false, account.did().as_str(), false,),
        SessionBootState::Checking
    );
}

#[test]
fn rehydrated_session_credential_only_matches_active_config() {
    let account = test_active_account(
        "did:web:alice.example",
        "https://local.host",
        "ak:device:01964137-0000-7000-8000-000000000001",
    );
    let config = ClientConfig::authenticated(account.clone(), "sx-live".to_owned());

    assert_eq!(
        rehydrated_session_credential_for_active_config(&config, Some(&account)).as_deref(),
        Some("sx-live")
    );
    let relocated = test_active_account(
        "did:web:alice.example",
        "https://other.local.host",
        "ak:device:01964137-0000-7000-8000-000000000001",
    );
    assert_eq!(
        rehydrated_session_credential_for_active_config(&config, Some(&relocated)).as_deref(),
        Some("sx-live")
    );

    let other_authority = crate::config::ActiveAccountContext::new(
        "ak:profile:019b0000-0000-7000-8000-000000000002".to_owned(),
        arkret_sdk::AccountId::new(
            account.authority.principal_id.clone(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:other-principal.example".to_owned())
                .unwrap(),
        ),
        account.resolution.clone(),
        account.device_id.clone(),
        account.server_url.clone(),
    )
    .unwrap();
    assert!(
        rehydrated_session_credential_for_active_config(&config, Some(&other_authority)).is_none()
    );

    let predecessor = test_active_account(
        "did:webvh:zAlice:old.example:users:alice",
        "https://local.host",
        "ak:device:01964137-0000-7000-8000-000000000001",
    );
    let predecessor_config =
        ClientConfig::authenticated(predecessor.clone(), "sx-successor".to_owned());
    let mut successor = predecessor.clone();
    successor
        .update_resolution(arkret_sdk::PrincipalResolutionProjection {
            did: arkret_sdk::Did::new("did:webvh:zAlice:new.example:people:alice".to_owned())
                .unwrap(),
            method_history_head: "head-2".to_owned(),
            version_id: "2".to_owned(),
            resolution_event_ref: format!("ak:event:{}", "B".repeat(44)),
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
    assert_eq!(
        rehydrated_session_credential_for_active_config(&predecessor_config, Some(&successor))
            .as_deref(),
        Some("sx-successor")
    );

    for candidate in [
        test_active_account(
            "did:web:bob.example",
            "https://local.host",
            "ak:device:01964137-0000-7000-8000-000000000001",
        ),
        test_active_account(
            "did:web:alice.example",
            "https://local.host",
            "ak:device:01964137-0000-7000-8000-000000000099",
        ),
    ] {
        assert!(
            rehydrated_session_credential_for_active_config(&config, Some(&candidate)).is_none()
        );
    }
    assert!(rehydrated_session_credential_for_active_config(&config, None).is_none());
}

#[test]
fn auth_surface_hides_login_while_session_is_restoring() {
    assert_eq!(
        auth_surface_for_route(&Route::Dashboard, false, SessionBootState::Restoring, false),
        AuthSurface::Restoring
    );
    assert_eq!(
        auth_surface_for_route(&Route::Login, false, SessionBootState::Restoring, false),
        AuthSurface::Restoring
    );
    assert_eq!(
        auth_surface_for_route(&Route::Dashboard, false, SessionBootState::Restoring, true),
        AuthSurface::Restoring
    );
    assert_eq!(
        auth_surface_for_route(
            &Route::Login,
            false,
            SessionBootState::Unauthenticated,
            true,
        ),
        AuthSurface::Login
    );
}

#[test]
fn onboarding_mounts_after_secure_store_even_when_connection_bootstrap_is_paused() {
    assert_eq!(
        auth_surface_for_route(
            &Route::Onboarding,
            false,
            SessionBootState::Restoring,
            false,
        ),
        AuthSurface::Restoring,
        "onboarding must still wait for secure storage itself"
    );
    assert_eq!(
        auth_surface_for_route(&Route::Onboarding, false, SessionBootState::Restoring, true,),
        AuthSurface::Onboarding,
        "onboarding owns its pre-session flow without mounting the authenticated shell"
    );
}

#[test]
fn oidc_callback_waits_for_secure_store_before_mounting() {
    assert_eq!(
        auth_surface_for_route(
            &Route::AuthCallback,
            false,
            SessionBootState::Restoring,
            false,
        ),
        AuthSurface::Restoring
    );
    assert_eq!(
        auth_surface_for_route(
            &Route::AuthCallback,
            false,
            SessionBootState::Unauthenticated,
            true,
        ),
        AuthSurface::Callback
    );
}

#[test]
fn session_boot_state_leaves_restoring_when_secure_store_is_ready_without_material() {
    let account = test_active_account(
        "did:web:alice.example",
        "https://local.host",
        "ak:device:01964137-0000-7000-8000-000000000001",
    );
    assert_eq!(
        session_boot_state_from_bootstrap_material("", false, account.did().as_str(), false,),
        SessionBootState::Restoring
    );
    assert_eq!(
        session_boot_state_from_bootstrap_material("", false, account.did().as_str(), true),
        SessionBootState::Unauthenticated
    );
    assert_eq!(
        auth_surface_for_route(
            &Route::Dashboard,
            false,
            SessionBootState::Unauthenticated,
            true,
        ),
        AuthSurface::Login
    );
}

#[test]
fn auth_surface_shows_shell_while_live_session_is_checking() {
    assert_eq!(
        auth_surface_for_route(&Route::Dashboard, true, SessionBootState::Checking, true),
        AuthSurface::AppShell
    );
}

#[test]
fn auth_surface_waits_for_secure_store_even_when_memory_has_a_token() {
    assert_eq!(
        auth_surface_for_route(&Route::Dashboard, true, SessionBootState::Checking, false),
        AuthSurface::Restoring
    );
}

#[test]
fn auth_surface_routes_authenticated_login_to_app_shell() {
    assert_eq!(
        auth_surface_for_route(&Route::Login, true, SessionBootState::Authenticated, true),
        AuthSurface::AppShell
    );
    assert_eq!(
        auth_surface_for_route(
            &Route::AuthCallback,
            true,
            SessionBootState::Authenticated,
            true,
        ),
        AuthSurface::AppShell
    );
}

#[test]
fn post_login_navigation_preserves_authenticated_deep_links() {
    assert!(should_redirect_to_dashboard_after_login(&Route::Login));
    assert!(should_redirect_to_dashboard_after_login(
        &Route::AuthCallback
    ));
    assert!(!should_redirect_to_dashboard_after_login(
        &Route::NotificationsSettings
    ));
    assert!(!should_redirect_to_dashboard_after_login(
        &Route::SetupSection {
            section: "realms".to_owned(),
        }
    ));
}

#[test]
fn authenticated_auth_routes_render_dashboard_without_a_second_login_panel() {
    for route in [Route::Login, Route::Register, Route::AuthCallback] {
        assert_eq!(authenticated_content_route(&route, true), Route::Dashboard);
    }
    assert_eq!(
        authenticated_content_route(&Route::Settings, true),
        Route::Settings
    );
}

#[test]
fn realm_top_nav_is_board_only() {
    let surfaces = RealmSurface::top_nav();

    assert_eq!(surfaces, [RealmSurface::Board]);
}

#[test]
fn setup_section_route_labels_match_realm_and_space_forms() {
    // `route_label_key` returns i18n keys; the dictionaries carry the display
    // text (`route.setup_realms` = "New Realm" / "新建 Realm").
    assert_eq!(route_label_key(&Route::Setup), "route.setup_realms");
    assert_eq!(
        route_label_key(&Route::SetupSection {
            section: "realms".to_owned()
        }),
        "route.setup_realms"
    );
    assert_eq!(
        route_label_key(&Route::SetupSection {
            section: "new-space".to_owned()
        }),
        "route.setup_new_space"
    );
}

#[test]
fn kanban_board_route_uses_realm_context_for_mls_bootstrap() {
    let route = Route::KanbanBoard {
        realm_id: "ak:realm:AUf2ZqXlKTr5IIncoCa4UlpeBVoaSUsvUwd8LUD9kCtw".to_owned(),
        board_id: "ak:space:AesqLH8RhGikjlM4RLUj-JoBx4kk_5wjP_27TFgpETVa".to_owned(),
    };

    assert!(route_uses_realm_context(&route));
    assert_eq!(
        route.realm_id(),
        Some("ak:realm:AUf2ZqXlKTr5IIncoCa4UlpeBVoaSUsvUwd8LUD9kCtw")
    );
}

#[test]
fn kanban_board_task_route_uses_realm_context_for_mls_bootstrap() {
    let route = Route::KanbanBoardTask {
        realm_id: "ak:realm:AUf2ZqXlKTr5IIncoCa4UlpeBVoaSUsvUwd8LUD9kCtw".to_owned(),
        board_id: "ak:space:AesqLH8RhGikjlM4RLUj-JoBx4kk_5wjP_27TFgpETVa".to_owned(),
        task_id: "ak:strand:AQt4LxD1aD9dynZHtoFAKW5nauq_7vWidI2B7LWO3IMY".to_owned(),
    };

    assert!(route_uses_realm_context(&route));
    assert_eq!(
        route.realm_id(),
        Some("ak:realm:AUf2ZqXlKTr5IIncoCa4UlpeBVoaSUsvUwd8LUD9kCtw")
    );
}

fn bootstrap_account_coordinates() -> (url::Url, arkret_sdk::AccountId, arkret_sdk::DeviceId) {
    let did = arkret_sdk::Did::new("did:web:inkson.example".to_owned()).unwrap();
    let principal_id = arkret_sdk::project_did_to_core_id(&did).unwrap();
    (
        url::Url::parse("http://localhost:8080").unwrap(),
        arkret_sdk::AccountId::new(
            principal_id,
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap(),
        ),
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001".to_owned())
            .unwrap(),
    )
}

#[test]
fn board_first_mls_bootstrap_key_never_prompts_for_passphrase() {
    let route = Route::KanbanBoard {
        realm_id: "ak:realm:AUf2ZqXlKTr5IIncoCa4UlpeBVoaSUsvUwd8LUD9kCtw".to_owned(),
        board_id: "ak:space:AesqLH8RhGikjlM4RLUj-JoBx4kk_5wjP_27TFgpETVa".to_owned(),
    };
    let realm_id = arkret_sdk::RealmId::new(
        route
            .realm_id()
            .expect("board route carries a realm id")
            .to_owned(),
    )
    .unwrap();
    let (server_url, authority, device_id) = bootstrap_account_coordinates();

    let key = mls_welcome_bootstrap_key(
        &server_url,
        "secret-session-token",
        &authority,
        &device_id,
        &realm_id,
        true,
        true,
    )
    .expect("board route should be eligible for App-owned MLS Welcome bootstrap");
    let missing_welcome = crate::mls::runtime::MlsRuntimeStatus::MissingWelcome.user_message();

    assert!(!key.contains("secret-session-token"));
    assert!(!missing_welcome.to_ascii_lowercase().contains("passphrase"));
    assert!(missing_welcome.contains("MLS Welcome"));
    assert!(missing_welcome.contains("encrypted MLS history backup"));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn mls_recovery_setup_missing_flags_encrypted_realm_without_account_backup() {
    let mut store = isolated_store("mls-recovery-missing");
    store.save_realm_tree_projection(
        "ak:realm:ACC_KtYySSLem-5NY0yqhOiMuglvO_bk9OnrD0Z8eQHI".to_owned(),
        serde_json::json!({
            "summary": {
                "title": "Encrypted",
                "encryption_profile": "mls_rfc9420",
            }
        }),
    );
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let payload = serde_json::json!({ "backups": [] });

    assert!(mls_recovery_setup_missing(
        &payload,
        &store,
        &secure,
        &test_authority("did:web:alice.example"),
        Some(false),
    ));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn mls_recovery_setup_missing_stays_false_when_account_backup_exists() {
    let mut store = isolated_store("mls-recovery-backed-up");
    store.save_realm_tree_projection(
        "ak:realm:ACC_KtYySSLem-5NY0yqhOiMuglvO_bk9OnrD0Z8eQHI".to_owned(),
        serde_json::json!({
            "summary": {
                "title": "Encrypted",
                "encryption_profile": "mls_rfc9420",
            }
        }),
    );
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let payload = serde_json::json!({
        "active_series": {"secret_storage": {
            "state": "active", "series_pointer_version": 1,
            "active_series_id": "ak:backup_series:01964137-1000-7000-8000-0000000000a1",
        }},
        "backups": [{
            "backup_id": "ak:backup:passphrase",
            "backup_kind": "secret_storage",
            "series_id": "ak:backup_series:01964137-1000-7000-8000-0000000000a1",
            "encryption": { "recipient_method": "passphrase_kdf" },
            "contents": [{
                "item_kind": crate::mls::account_recovery::MLS_ACCOUNT_SECRET_ITEM_KIND,
                "secret_id": crate::mls::account_recovery::MLS_ACCOUNT_SECRET_SECRET_ID,
            }],
        }]
    });

    assert!(!mls_recovery_setup_missing(
        &payload,
        &store,
        &secure,
        &test_authority("did:web:alice.example"),
        Some(false),
    ));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn mls_recovery_setup_missing_stays_false_when_account_recovery_is_configured() {
    let mut store = isolated_store("mls-recovery-account-configured");
    store.save_realm_tree_projection(
        "ak:realm:ACC_KtYySSLem-5NY0yqhOiMuglvO_bk9OnrD0Z8eQHI".to_owned(),
        serde_json::json!({
            "summary": {
                "title": "Encrypted",
                "encryption_profile": "mls_rfc9420",
            }
        }),
    );
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let payload = serde_json::json!({ "backups": [] });

    assert!(!mls_recovery_setup_missing(
        &payload,
        &store,
        &secure,
        &test_authority("did:web:alice.example"),
        Some(true),
    ));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn mls_recovery_setup_missing_stays_false_for_local_recovery_key_and_secret_storage_backup() {
    let mut store = isolated_store("mls-recovery-local-did-backup");
    store.save_realm_tree_projection(
        "ak:realm:ACC_KtYySSLem-5NY0yqhOiMuglvO_bk9OnrD0Z8eQHI".to_owned(),
        serde_json::json!({
            "summary": {
                "title": "Encrypted",
                "encryption_profile": "mls_rfc9420",
            }
        }),
    );
    store.save_plain_local_data(
        "recovery.state.v1",
        serde_json::json!({
            "recovery_key_fingerprint": "sha256:abc",
            "recovery_key_rotated_at": "2026-06-13T00:00:00.000Z"
        })
        .to_string(),
    );
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let payload = serde_json::json!({
        "backups": [{
            "backup_id": "ak:backup:secret-storage",
            "backup_kind": "secret_storage",
            "encryption": { "recipient_method": "recovery_public_key" },
        }]
    });

    assert!(!mls_recovery_setup_missing(
        &payload,
        &store,
        &secure,
        &test_authority("did:web:alice.example"),
        None,
    ));
}

#[test]
fn mls_welcome_bootstrap_key_waits_for_e2ee_profile_and_sync() {
    let (mut base, authority, device) = bootstrap_account_coordinates();
    base.set_scheme("https").unwrap();
    base.set_host(Some("local.host")).unwrap();
    base.set_port(None).unwrap();
    let session = "session-token";
    let realm = arkret_sdk::RealmId::new(
        "ak:realm:AUf2ZqXlKTr5IIncoCa4UlpeBVoaSUsvUwd8LUD9kCtw".to_owned(),
    )
    .unwrap();

    assert_eq!(
        mls_welcome_bootstrap_key(&base, session, &authority, &device, &realm, false, true),
        None
    );
    assert_eq!(
        mls_welcome_bootstrap_key(&base, session, &authority, &device, &realm, true, false),
        None
    );
    assert_eq!(
        mls_welcome_bootstrap_key(&base, "", &authority, &device, &realm, true, true),
        None
    );
    assert!(
        mls_welcome_bootstrap_key(&base, session, &authority, &device, &realm, true, true)
            .is_some()
    );
}

#[test]
fn mls_key_package_publish_key_waits_for_e2ee_profile_and_sync() {
    let (mut base, authority, device) = bootstrap_account_coordinates();
    base.set_scheme("https").unwrap();
    base.set_host(Some("local.host")).unwrap();
    base.set_port(None).unwrap();
    let session = "session-token";

    assert_eq!(
        mls_key_package_publish_key(&base, session, &authority, &device, false, true),
        None
    );
    assert_eq!(
        mls_key_package_publish_key(&base, session, &authority, &device, true, false),
        None
    );
    assert_eq!(
        mls_key_package_publish_key(&base, "", &authority, &device, true, true),
        None
    );
    let key = mls_key_package_publish_key(&base, session, &authority, &device, true, true)
        .expect("ready session should publish an MLS KeyPackage");
    assert!(!key.contains(session));
}

#[test]
fn merge_projection_events_keeps_existing_messages_on_summary_only_delta() {
    let mut summary = ProjectionEvent::system_notice("summary-ak:realm:test", "server", "old");
    summary.realm_id = Some("ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw".to_owned());
    let message = ProjectionEvent {
        id: "ak:event:AMRFFcIrNlRzkEP8vLsl4eBWTFBOBX6eR89IhQWPENxE".to_owned(),
        realm_id: Some("ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw".to_owned()),
        body: "welcome".to_owned(),
        ..ProjectionEvent::default()
    };
    let mut updated_summary =
        ProjectionEvent::system_notice("summary-ak:realm:test", "server", "new");
    updated_summary.realm_id =
        Some("ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw".to_owned());

    let merged = merge_projection_events(&[summary, message], vec![updated_summary]);

    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].body, "new");
    assert_eq!(merged[1].body, "welcome");
}

/// R4 — the account cursor has exactly one "not ready yet" representation.
///
/// `sync/api-conventions.md` fixes the cursor wire form at
/// `ak:cursor:<base64url(canonical_json)>`, so a placeholder token is not a
/// protocol cursor. Boot therefore starts empty, like every reset path, and the
/// readiness predicate is the only thing derived from the token.
#[test]
fn bootstrap_sync_cursor_is_empty_and_not_ready() {
    assert_eq!(initial_sync_cursor(None), "");
    assert!(!account_sync_ready(&initial_sync_cursor(None)));
    assert!(!account_sync_ready("   "));

    let persisted = "ak:cursor:eyJhIjoxfQ";
    assert_eq!(initial_sync_cursor(Some(persisted.to_owned())), persisted);
    assert!(account_sync_ready(persisted));
}

/// The bootstrap default must never reach a `wait_for` query or a cursor
/// header, and the retired dash placeholder is not a cursor the normalizer
/// would have accepted either.
#[test]
fn bootstrap_sync_cursor_never_reaches_wait_for_or_a_cursor_header() {
    use crate::api_error::normalize_wait_for_sync_token;

    assert_eq!(
        normalize_wait_for_sync_token(&initial_sync_cursor(None)),
        None
    );
    assert_eq!(normalize_wait_for_sync_token("-"), None);
    assert!(arkret_sdk::identifiers::Cursor::new("-".to_owned()).is_err());
    assert_eq!(
        normalize_wait_for_sync_token("ak:cursor:eyJhIjoxfQ").as_deref(),
        Some("ak:cursor:eyJhIjoxfQ")
    );
}

/// Booting without a persisted cursor must not write a synthetic one back into
/// local state: `sync_cursor` stays `None` until the server hands over a real
/// resume checkpoint.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn bootstrap_sync_cursor_is_never_persisted() {
    let mut store = isolated_store("bootstrap-sync-cursor");
    assert_eq!(store.sync_cursor(), None);
    assert_eq!(initial_sync_cursor(store.sync_cursor()), "");
    assert_eq!(store.sync_cursor(), None);

    store.save_sync_cursor("ak:cursor:eyJhIjoxfQ");
    assert_eq!(
        initial_sync_cursor(store.sync_cursor()),
        "ak:cursor:eyJhIjoxfQ"
    );
}
