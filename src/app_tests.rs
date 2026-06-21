use super::*;

#[test]
fn personal_handle_from_account_handle_keeps_full_handle_verbatim() {
    // `account.handle` from `account_me` is the FULL canonical handle. It must
    // be returned as-is — never have the server domain appended again, which
    // produced the `alice:local.host:local.host` double-domain regression.
    assert_eq!(
        personal_handle_from_account_handle("alice:local.host", "https://local.host").as_deref(),
        Some("alice:local.host")
    );
    assert_eq!(
        personal_handle_from_account_handle("@alice:local.host", "https://local.host").as_deref(),
        Some("alice:local.host")
    );
    // A handle on a different domain than the active server is preserved, not
    // rewritten to the server's domain.
    assert_eq!(
        personal_handle_from_account_handle("alice:example.com", "https://local.host").as_deref(),
        Some("alice:example.com")
    );
}

#[test]
fn personal_handle_from_account_handle_synthesises_bare_localpart() {
    // Defensive fallback: a legacy bare localpart (no domain) gets the active
    // server's domain appended exactly once.
    assert_eq!(
        personal_handle_from_account_handle("@alice", "https://local.host").as_deref(),
        Some("alice:local.host")
    );
    assert_eq!(
        personal_handle_from_account_handle("  ", "https://local.host"),
        None
    );
    assert_eq!(
        personal_handle_from_account_handle("@alice", "not a server URL"),
        None
    );
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
    let mut snapshot = ClientLocalState {
        notification_projection: vec![
            serde_json::json!({
                "notification_id": "unread",
                "read": false
            }),
            serde_json::json!({
                "notification_id": "server-read",
                "read": true
            }),
            serde_json::json!({
                "notification_id": "client-read"
            }),
            serde_json::json!({
                "notification_id": "client-archived"
            }),
            serde_json::json!({
                "notification_id": "server-archived",
                "read": false,
                "archived": true
            }),
        ],
        ..ClientLocalState::default()
    };
    snapshot.notification_client_state.insert(
        "client-read".to_owned(),
        crate::local_state::NotificationClientState {
            read: true,
            archived: false,
        },
    );
    snapshot.notification_client_state.insert(
        "client-archived".to_owned(),
        crate::local_state::NotificationClientState {
            read: false,
            archived: true,
        },
    );

    assert_eq!(unread_notification_count(&snapshot), 1);
}

fn oidc_bundle(access_token: &str, expires_at_unix: Option<i64>) -> OidcTokenBundle {
    OidcTokenBundle {
        access_token: access_token.to_owned(),
        refresh_token: Some("rt-test".to_owned()),
        token_type: "Bearer".to_owned(),
        expires_at_unix,
        id_token: None,
        scope: None,
        audience: Some("https://local.host".to_owned()),
        stored_at: chrono::Utc::now(),
    }
}

fn session_grant(session_expires_in: i64, grant_expires_in: i64) -> PersistedSessionGrant {
    let now = chrono::Utc::now();
    PersistedSessionGrant {
        grant_jwt: "grant.jwt".to_owned(),
        session_private_key_pem: "PEM".to_owned(),
        grant_id: "grant-1".to_owned(),
        audience: "https://local.host/api".to_owned(),
        principal_id: "did:web:alice.example".to_owned(),
        device_id: "ck:device:01964137-0000-7000-8000-000000000001".to_owned(),
        principal_server_url: "https://local.host".to_owned(),
        session_grant_exchange_path: "_cokret/gate/account/session-grants".to_owned(),
        grant_expires_at: Some(now + chrono::Duration::seconds(grant_expires_in)),
        session_expires_at: Some(now + chrono::Duration::seconds(session_expires_in)),
        stored_at: now,
    }
}

#[test]
fn oidc_refresh_error_invalidates_grant_for_invalid_grant_response() {
    let error = anyhow::anyhow!(
        "refresh endpoint returned 400 Bad Request: {{\"error\":\"invalid_grant\",\"error_description\":\"The provided access grant is invalid, expired, or revoked.\"}}"
    );

    assert!(oidc_refresh_error_invalidates_grant(&error));
}

#[test]
fn oidc_refresh_error_keeps_bundle_for_transient_failures() {
    let network_error = anyhow::anyhow!("refresh token endpoint POST failed");
    let server_error =
        anyhow::anyhow!("refresh endpoint returned 503 Service Unavailable: retry later");

    assert!(!oidc_refresh_error_invalidates_grant(&network_error));
    assert!(!oidc_refresh_error_invalidates_grant(&server_error));
}

#[test]
fn account_scope_owner_alone_is_not_bootstrap_refresh_material() {
    let actor = "did:web:alice.example";
    let mut store = crate::local_state::isolated_store_for_tests("account-scope-no-restore");
    store.adopt_account_scope(actor);

    assert!(!has_bootstrap_refresh_material(
        &store,
        "https://local.host",
        actor
    ));
}

#[test]
fn current_device_authorization_detects_verified_current_device() {
    let device = "ck:device:01964137-0000-7000-8000-000000000001";
    let viewer = serde_json::json!({
        "current_device_id": device,
        "devices": [{
            "device_id": device,
            "verification_state": "verified"
        }]
    });

    assert_eq!(
        current_device_authorization_from_account_viewer(&viewer, device),
        Some(true)
    );
}

#[test]
fn current_device_authorization_detects_unverified_new_device() {
    let device = "ck:device:01964137-0000-7000-8000-000000000002";
    let viewer = serde_json::json!({
        "current_device_id": device,
        "devices": [{
            "device_id": device,
            "verification_state": "unverified"
        }]
    });

    assert_eq!(
        current_device_authorization_from_account_viewer(&viewer, device),
        Some(false)
    );
}

#[test]
fn current_device_authorization_treats_missing_current_device_as_unauthorized() {
    let device = "ck:device:01964137-0000-7000-8000-000000000002";
    let viewer = serde_json::json!({
        "devices": [{
            "device_id": "ck:device:01964137-0000-7000-8000-000000000001",
            "status": "active"
        }]
    });

    assert_eq!(
        current_device_authorization_from_account_viewer(&viewer, device),
        Some(false)
    );
}

#[test]
fn current_device_authorization_rejects_active_status_without_trust_evidence() {
    let device = "ck:device:01964137-0000-7000-8000-000000000001";
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
    let device = "ck:device:01964137-0000-7000-8000-000000000001";
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
fn current_device_authorization_accepts_explicit_authorized_status() {
    let device = "ck:device:01964137-0000-7000-8000-000000000001";
    let viewer = serde_json::json!({
        "devices": [{
            "device_id": device,
            "status": "authorized"
        }]
    });

    assert_eq!(
        current_device_authorization_from_account_viewer(&viewer, device),
        Some(true)
    );
}

#[test]
fn current_device_authorization_rejects_revoked_status() {
    let device = "ck:device:01964137-0000-7000-8000-000000000001";
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
    let current = "ck:device:01964137-0000-7000-8000-000000000002";
    let prior = "ck:device:01964137-0000-7000-8000-000000000001";
    let viewer = serde_json::json!({
        "current_device_id": current,
        "devices": [
            {
                "device_id": prior,
                "verification_state": "verified"
            },
            {
                "device_id": current,
                "verification_state": "unverified"
            }
        ]
    });

    assert!(account_has_other_active_devices_from_account_viewer(
        &viewer, current
    ));
}

#[test]
fn account_has_other_active_devices_ignores_revoked_prior_device() {
    let current = "ck:device:01964137-0000-7000-8000-000000000002";
    let prior = "ck:device:01964137-0000-7000-8000-000000000001";
    let viewer = serde_json::json!({
        "current_device_id": current,
        "devices": [
            {
                "device_id": prior,
                "verification_state": "verified",
                "revoked_at": "2026-06-14T00:00:00Z"
            },
            {
                "device_id": current,
                "verification_state": "verified"
            }
        ]
    });

    assert!(!account_has_other_active_devices_from_account_viewer(
        &viewer, current
    ));
}

#[test]
fn current_device_authorization_accepts_authorized_at_without_status() {
    let device = "ck:device:01964137-0000-7000-8000-000000000001";
    let viewer = serde_json::json!({
        "devices": [{
            "device_id": device,
            "authorized_at": "2026-04-28T12:00:00Z"
        }]
    });

    assert_eq!(
        current_device_authorization_from_account_viewer(&viewer, device),
        Some(true)
    );
}

#[test]
fn current_device_authorization_rejects_current_record_without_authorization_evidence() {
    let device = "ck:device:01964137-0000-7000-8000-000000000001";
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
    let device = "ck:device:01964137-0000-7000-8000-000000000001";
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
    let device = "ck:device:01964137-0000-7000-8000-000000000001";
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
    assert!(!recovery_setup_prompt_required(None));
    assert!(!recovery_setup_prompt_required(Some(true)));
    assert!(recovery_setup_prompt_required(Some(false)));
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
    let actor = "did:web:alice.example";
    let mut store = isolated_store("recovery-local-only-auto_prompt");
    store.save_private_data(actor, RECOVERY_AUTO_PROMPT_SHOWN_KEY, "1");
    store.save_private_data(
        actor,
        "recovery.state.v1",
        serde_json::json!({
            "recovery_key_fingerprint": "sha256:abc",
            "recovery_key_rotated_at": "2026-06-13T00:00:00Z"
        })
        .to_string(),
    );

    assert_eq!(
        recovery_auto_prompt_pending_local_only_fingerprint(&store, actor, Some(false)).as_deref(),
        Some("sha256:abc")
    );
    assert!(!recovery_auto_prompt_already_prompted(
        &store,
        actor,
        Some(false)
    ));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn recovery_auto_prompt_local_only_key_is_prompted_once_per_fingerprint() {
    let actor = "did:web:alice.example";
    let mut store = isolated_store("recovery-local-only-auto_prompt-once");
    store.save_private_data(actor, RECOVERY_AUTO_PROMPT_SHOWN_KEY, "1");
    store.save_private_data(
        actor,
        "recovery.state.v1",
        serde_json::json!({
            "recovery_key_fingerprint": "sha256:abc",
            "recovery_key_rotated_at": "2026-06-13T00:00:00Z"
        })
        .to_string(),
    );
    store.save_private_data(
        actor,
        RECOVERY_AUTO_PROMPT_LOCAL_ONLY_SHOWN_KEY,
        "sha256:abc",
    );

    assert!(
        recovery_auto_prompt_pending_local_only_fingerprint(&store, actor, Some(false)).is_none()
    );
    assert!(recovery_auto_prompt_already_prompted(
        &store,
        actor,
        Some(false)
    ));
}

// YOU-05-010: shared hermetic state-store fixture from `local_state`.
#[cfg(not(target_arch = "wasm32"))]
use crate::local_state::isolated_store_for_tests as isolated_store;

#[test]
fn boot_session_token_uses_fresh_oidc_access_token() {
    let now = 1_000;
    let state = ClientLocalState {
        oidc_tokens: Some(oidc_bundle("sx-fresh", Some(now + 120))),
        ..Default::default()
    };
    let config = ClientConfig::from_fields(
        "https://local.host",
        "did:web:alice.example",
        "ck:device:01964137-0000-7000-8000-000000000001",
        "config-token",
    );

    assert_eq!(
        initial_session_token_from_state(&state, &config, now),
        "sx-fresh"
    );
}

#[test]
fn boot_session_token_ignores_expired_oidc_access_token() {
    let now = 1_000;
    let state = ClientLocalState {
        oidc_tokens: Some(oidc_bundle("sx-expired", Some(now - 1))),
        ..Default::default()
    };
    let config = ClientConfig::from_fields(
        "https://local.host",
        "did:web:alice.example",
        "ck:device:01964137-0000-7000-8000-000000000001",
        "config-token",
    );

    assert_eq!(initial_session_token_from_state(&state, &config, now), "");
}

#[test]
fn boot_session_token_ignores_nearly_expired_oidc_access_token() {
    let now = 1_000;
    let state = ClientLocalState {
        oidc_tokens: Some(oidc_bundle(
            "sx-nearly-expired",
            Some(now + BOOT_ACCESS_TOKEN_SKEW_SECS),
        )),
        ..Default::default()
    };
    let config = ClientConfig::from_fields(
        "https://local.host",
        "did:web:alice.example",
        "ck:device:01964137-0000-7000-8000-000000000001",
        "config-token",
    );

    assert_eq!(initial_session_token_from_state(&state, &config, now), "");
}

#[test]
fn boot_session_token_ignores_config_token_without_boot_material() {
    let state = ClientLocalState::default();
    let config = ClientConfig::from_fields(
        "https://local.host",
        "did:web:alice.example",
        "ck:device:01964137-0000-7000-8000-000000000001",
        "config-token",
    );

    assert_eq!(initial_session_token_from_state(&state, &config, 1_000), "");
}

#[test]
fn boot_session_token_uses_fresh_session_grant_bearer() {
    let now = chrono::Utc::now().timestamp();
    let state = ClientLocalState {
        session_grant: Some(session_grant(120, 3600)),
        ..Default::default()
    };
    let config = ClientConfig::from_fields(
        "https://local.host",
        "did:web:alice.example",
        "ck:device:01964137-0000-7000-8000-000000000001",
        "bridge-token",
    );

    assert_eq!(
        initial_session_token_from_state(&state, &config, now),
        "grant.jwt"
    );
}

#[test]
fn boot_session_token_falls_back_to_session_grant_when_oidc_is_expired() {
    let now = chrono::Utc::now().timestamp();
    let state = ClientLocalState {
        oidc_tokens: Some(oidc_bundle("sx-expired-oidc", Some(now - 1))),
        session_grant: Some(session_grant(120, 3600)),
        ..Default::default()
    };
    let config = ClientConfig::from_fields(
        "https://local.host",
        "did:web:alice.example",
        "ck:device:01964137-0000-7000-8000-000000000001",
        "bridge-token",
    );

    assert_eq!(
        initial_session_token_from_state(&state, &config, now),
        "grant.jwt"
    );
}

#[test]
fn boot_session_token_uses_session_grant_when_cached_bearer_expired() {
    let now = chrono::Utc::now().timestamp();
    let state = ClientLocalState {
        session_grant: Some(session_grant(-1, 3600)),
        ..Default::default()
    };
    let config = ClientConfig::from_fields(
        "https://local.host",
        "did:web:alice.example",
        "ck:device:01964137-0000-7000-8000-000000000001",
        "bridge-token",
    );

    assert_eq!(
        initial_session_token_from_state(&state, &config, now),
        "grant.jwt"
    );
}

#[test]
fn boot_session_token_ignores_expired_session_grant() {
    let now = chrono::Utc::now().timestamp();
    let state = ClientLocalState {
        session_grant: Some(session_grant(-1, -1)),
        ..Default::default()
    };
    let config = ClientConfig::from_fields(
        "https://local.host",
        "did:web:alice.example",
        "ck:device:01964137-0000-7000-8000-000000000001",
        "bridge-token",
    );

    assert_eq!(initial_session_token_from_state(&state, &config, now), "");
}

#[test]
fn boot_session_token_ignores_session_grant_for_other_server() {
    let now = chrono::Utc::now().timestamp();
    let mut grant = session_grant(120, 3600);
    grant.principal_server_url = "https://other.local.host".to_owned();
    let state = ClientLocalState {
        session_grant: Some(grant),
        ..Default::default()
    };
    let config = ClientConfig::from_fields(
        "https://local.host",
        "did:web:alice.example",
        "ck:device:01964137-0000-7000-8000-000000000001",
        "bridge-token",
    );

    assert_eq!(initial_session_token_from_state(&state, &config, now), "");
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn bootstrap_can_start_with_oidc_refresh_material_without_bearer() {
    let mut store = isolated_store("bootstrap-oidc");
    let state = ClientLocalState {
        oidc_tokens: Some(oidc_bundle("sx-expired", Some(1))),
        ..Default::default()
    };
    store.save(state);

    assert!(has_bootstrap_refresh_material(
        &store,
        "https://local.host",
        "did:web:alice.example"
    ));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn bootstrap_can_start_with_session_grant_without_bearer() {
    let mut store = isolated_store("bootstrap-grant");
    store.set_session_grant(Some(session_grant(-1, 3600)));

    assert!(has_bootstrap_refresh_material(
        &store,
        "https://local.host",
        "did:web:alice.example"
    ));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn bootstrap_ignores_session_grant_for_other_server() {
    let mut store = isolated_store("bootstrap-other-server");
    let mut grant = session_grant(-1, 3600);
    grant.principal_server_url = "https://other.local.host".to_owned();
    store.set_session_grant(Some(grant));

    assert!(!has_bootstrap_refresh_material(
        &store,
        "https://local.host",
        "did:web:alice.example"
    ));
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
fn boot_state_waits_for_secure_store_before_known_account_is_signed_out() {
    assert_eq!(
        session_boot_state_from_bootstrap_material("", false, "did:web:alice.example", false),
        SessionBootState::Restoring
    );
    assert_eq!(
        session_boot_state_from_bootstrap_material("", false, "", false),
        SessionBootState::Unauthenticated
    );
    assert_eq!(
        session_boot_state_from_bootstrap_material("", false, "did:web:alice.example", true),
        SessionBootState::Unauthenticated
    );
    assert_eq!(
        session_boot_state_from_bootstrap_material(
            "sx-live",
            false,
            "did:web:alice.example",
            false
        ),
        SessionBootState::Checking
    );
}

#[test]
fn rehydrated_session_token_only_matches_active_config() {
    let config = ClientConfig::from_fields(
        "https://local.host",
        "did:web:alice.example",
        "ck:device:01964137-0000-7000-8000-000000000001",
        "sx-live",
    );

    assert_eq!(
        rehydrated_session_token_for_active_config(
            &config,
            "https://local.host",
            "did:web:alice.example",
            "ck:device:01964137-0000-7000-8000-000000000001",
        )
        .as_deref(),
        Some("sx-live")
    );
    assert!(
        rehydrated_session_token_for_active_config(
            &config,
            "https://other.local.host",
            "did:web:alice.example",
            "ck:device:01964137-0000-7000-8000-000000000001",
        )
        .is_none()
    );
    assert!(
        rehydrated_session_token_for_active_config(
            &config,
            "https://local.host",
            "did:web:bob.example",
            "ck:device:01964137-0000-7000-8000-000000000001",
        )
        .is_none()
    );
}

#[test]
fn auth_surface_hides_login_while_session_is_restoring() {
    assert_eq!(
        auth_surface_for_route(&Route::Dashboard, false, SessionBootState::Restoring),
        AuthSurface::Restoring
    );
    assert_eq!(
        auth_surface_for_route(&Route::Login, false, SessionBootState::Restoring),
        AuthSurface::Restoring
    );
    assert_eq!(
        auth_surface_for_route(&Route::Login, false, SessionBootState::Unauthenticated),
        AuthSurface::Login
    );
}

#[test]
fn auth_surface_waits_while_live_session_is_checking() {
    assert_eq!(
        auth_surface_for_route(&Route::Dashboard, true, SessionBootState::Checking),
        AuthSurface::Restoring
    );
}

#[test]
fn auth_surface_routes_authenticated_login_to_app_shell() {
    assert_eq!(
        auth_surface_for_route(&Route::Login, true, SessionBootState::Authenticated),
        AuthSurface::AppShell
    );
    assert_eq!(
        auth_surface_for_route(&Route::AuthCallback, true, SessionBootState::Authenticated),
        AuthSurface::Callback
    );
}

#[test]
fn space_top_nav_excludes_discussion_surface() {
    let surfaces = RealmSurface::top_nav();

    assert_eq!(
        surfaces,
        [
            RealmSurface::Timeline,
            RealmSurface::Board,
            RealmSurface::Document
        ]
    );
    assert_eq!(
        RealmSurface::from_preference("discussion"),
        Some(RealmSurface::Board)
    );
}

#[test]
fn setup_section_route_labels_match_realm_and_space_forms() {
    assert_eq!(route_label(&Route::Setup), "New Realm");
    assert_eq!(
        route_label(&Route::SetupSection {
            section: "realms".to_owned()
        }),
        "New Realm"
    );
    assert_eq!(
        route_label(&Route::SetupSection {
            section: "new-space".to_owned()
        }),
        "New Space"
    );
}

#[test]
fn kanban_board_route_uses_realm_context_for_mls_bootstrap() {
    let route = Route::KanbanBoard {
        realm_id: "ck:realm:019e67a5-8edc-7347-9ca1-a0b880987bdc".to_owned(),
        board_id: "ck:space:019e67ae-e633-7ef4-8a64-1f736d75d8ad".to_owned(),
    };

    assert!(route_uses_realm_context(&route));
    assert_eq!(
        route.realm_id(),
        Some("ck:realm:019e67a5-8edc-7347-9ca1-a0b880987bdc")
    );
}

#[test]
fn board_first_mls_bootstrap_key_never_prompts_for_passphrase() {
    let route = Route::KanbanBoard {
        realm_id: "ck:realm:019e67a5-8edc-7347-9ca1-a0b880987bdc".to_owned(),
        board_id: "ck:space:019e67ae-e633-7ef4-8a64-1f736d75d8ad".to_owned(),
    };
    let realm_id = route.realm_id().expect("board route carries a realm id");

    let key = mls_welcome_bootstrap_key(
        "http://localhost:8080",
        "secret-session-token",
        "did:web:yougen.example",
        "ck:device:01964137-0000-7000-8000-000000000001",
        realm_id,
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
        "ck:realm:encrypted".to_owned(),
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
        "did:web:alice.example",
    ));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn mls_recovery_setup_missing_stays_false_when_account_backup_exists() {
    let mut store = isolated_store("mls-recovery-backed-up");
    store.save_realm_tree_projection(
        "ck:realm:encrypted".to_owned(),
        serde_json::json!({
            "summary": {
                "title": "Encrypted",
                "encryption_profile": "mls_rfc9420",
            }
        }),
    );
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let payload = serde_json::json!({
        "backups": [{
            "backup_id": "ck:backup:passphrase",
            "encryption": { "recipient_method": "passphrase_kdf" },
            "contents": [{
                "item_type": crate::mls::account_recovery::MLS_ACCOUNT_SECRET_ITEM_TYPE,
                "secret_id": crate::mls::account_recovery::MLS_ACCOUNT_SECRET_SECRET_ID,
            }],
        }]
    });

    assert!(!mls_recovery_setup_missing(
        &payload,
        &store,
        &secure,
        "did:web:alice.example",
    ));
}

#[test]
fn mls_welcome_bootstrap_key_waits_for_e2ee_profile_and_sync() {
    let base = "https://local.host/";
    let session = "session-token";
    let actor = "did:web:yougen.example";
    let device = "ck:device:01964137-0000-7000-8000-000000000001";
    let realm = "ck:realm:019e67a5-8edc-7347-9ca1-a0b880987bdc";

    assert_eq!(
        mls_welcome_bootstrap_key(base, session, actor, device, realm, false, true),
        None
    );
    assert_eq!(
        mls_welcome_bootstrap_key(base, session, actor, device, realm, true, false),
        None
    );
    assert_eq!(
        mls_welcome_bootstrap_key(base, "", actor, device, realm, true, true),
        None
    );
    assert!(mls_welcome_bootstrap_key(base, session, actor, device, realm, true, true).is_some());
}

#[test]
fn merge_timeline_events_keeps_existing_messages_on_summary_only_delta() {
    let mut summary = TimelineEvent::system_notice("summary-ck:realm:test", "server", "old");
    summary.realm_id = Some("ck:realm:test".to_owned());
    let message = TimelineEvent {
        id: "ck:event:message".to_owned(),
        realm_id: Some("ck:realm:test".to_owned()),
        body: "welcome".to_owned(),
        ..TimelineEvent::default()
    };
    let mut updated_summary =
        TimelineEvent::system_notice("summary-ck:realm:test", "server", "new");
    updated_summary.realm_id = Some("ck:realm:test".to_owned());

    let merged = merge_timeline_events(&[summary, message], vec![updated_summary]);

    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].body, "new");
    assert_eq!(merged[1].body, "welcome");
}
