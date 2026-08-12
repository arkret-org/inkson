use super::*;

#[derive(Clone, Copy, PartialEq)]
pub(super) struct SecureStoreEffectState {
    pub config_store: Signal<LocalConfigStore>,
    pub account_did: Signal<String>,
    pub device_id: Signal<String>,
    pub secure_store_bootstrap_ready: Signal<bool>,
    pub token: Signal<String>,
}

#[component]
pub(super) fn SecureStoreEffects(state: SecureStoreEffectState) -> Element {
    #[cfg(not(target_arch = "wasm32"))]
    let _ = state;
    #[cfg(target_arch = "wasm32")]
    let SecureStoreEffectState {
        config_store,
        account_did,
        device_id,
        secure_store_bootstrap_ready,
        token,
    } = state;
    #[cfg(target_arch = "wasm32")]
    let SessionContext {
        state_store,
        base_url,
        ..
    } = SessionContext::get();

    #[cfg(target_arch = "wasm32")]
    {
        let config_store_for_secure_upgrade = config_store;
        let base_url_for_secure_upgrade = base_url;
        let account_did_for_secure_upgrade = account_did;
        let mut device_id_for_secure_upgrade = device_id;
        let mut state_store_for_secure_upgrade = state_store;
        let mut secure_store_ready_for_upgrade = secure_store_bootstrap_ready;
        let mut token_for_secure_upgrade = token;
        use_future(move || async move {
            crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(1)).await;
            tracing::debug!(target: "secure_store", "initializing IndexedDB secure store");
            match crate::secure_key_store::initialize_wasm_secure_key_store_async("inkson").await {
                Ok(Some(secure_store)) => {
                    // The durable logout journal is IndexedDB-only on wasm.
                    // Retry it only after that backend is installed; the old
                    // application-wide boot effect raced this initialization
                    // and reported an expected unavailable backend as a fault.
                    crate::pending_logout::run_pending_logout_with_store(
                        chrono::Utc::now(),
                        secure_store.as_ref(),
                    )
                    .await;
                    #[cfg(feature = "wasm-localstorage-secrets-test")]
                    state_store_for_secure_upgrade
                        .write()
                        .switch_active_account(&account_did_for_secure_upgrade());
                    tracing::debug!(target: "secure_store", "secure store upgrade: Ok(Some) — IndexedDb tier installed");
                    // Hydrate the active account's main state from the IndexedDB
                    // encrypted entries store into `cached` before
                    // anything downstream reads it. Runs before the E2EE plaintext
                    // cache hydration (which merges plaintext INTO the account
                    // state) and before `secure_store_bootstrap_ready` is published
                    // so the account state is authoritative before session/connect.
                    state_store_for_secure_upgrade
                        .write()
                        .hydrate_active_account_state_from_secure_store(secure_store.as_ref());
                    let hydrated = state_store_for_secure_upgrade
                        .write()
                        .hydrate_e2ee_plaintext_cache_with_secure_store(secure_store.as_ref());
                    if let Err(error) = hydrated {
                        tracing::warn!(?error, "IndexedDB E2EE plaintext cache hydration failed",);
                    } else {
                        let secure_write = state_store_for_secure_upgrade
                            .read()
                            .e2ee_plaintext_cache_secure_write();
                        match secure_write {
                            Ok(Some((key, Some(json)))) => {
                                match secure_store.store_secret_durable(&key, &json).await {
                                    Ok(()) => {
                                        // Clear pre-decrypt recovery checkpoints only
                                        // after the combined snapshot + plaintext entry
                                        // has durably committed.
                                        if let Err(error) = state_store_for_secure_upgrade
                                            .write()
                                            .clear_mls_receive_recovery_snapshots()
                                        {
                                            tracing::warn!(
                                                ?error,
                                                "MLS receive recovery checkpoint cleanup failed",
                                            );
                                        }
                                    }
                                    Err(error) => {
                                        tracing::warn!(
                                            ?error,
                                            "IndexedDB E2EE state durable bootstrap persist failed",
                                        );
                                    }
                                }
                            }
                            Ok(Some((key, None))) => {
                                if let Err(error) = secure_store.delete_secret(&key) {
                                    tracing::warn!(
                                        ?error,
                                        "empty IndexedDB E2EE state cleanup failed",
                                    );
                                }
                            }
                            Ok(None) => {}
                            Err(error) => {
                                tracing::warn!(?error, "IndexedDB E2EE state encode failed");
                            }
                        }
                    }
                    #[cfg(feature = "wasm-localstorage-secrets-test")]
                    {
                        // Test fixtures are live startup writes. Apply them only
                        // after the durable account snapshot is authoritative;
                        // otherwise the asynchronous IndexedDB writer can race
                        // hydration and lose a resumable registration checkpoint.
                        let injected = inject_test_session_grant(
                            &mut state_store_for_secure_upgrade,
                            config_store_for_secure_upgrade,
                            &base_url_for_secure_upgrade(),
                            &account_did_for_secure_upgrade(),
                            &device_id_for_secure_upgrade(),
                            secure_store.as_ref(),
                        )
                        .or_else(|| {
                            inject_test_session_credential(
                                config_store_for_secure_upgrade,
                                &base_url_for_secure_upgrade(),
                                &account_did_for_secure_upgrade(),
                                &device_id_for_secure_upgrade(),
                            )
                        });
                        if let Some(credential) = injected {
                            token_for_secure_upgrade.set(credential);
                        }
                        apply_test_session_grant_expiry_override(
                            &mut state_store_for_secure_upgrade,
                            secure_store.as_ref(),
                        );
                    }
                    let loaded_config = config_store_for_secure_upgrade
                        .read()
                        .load_with_secure_store(secure_store.as_ref());
                    let held_token = token_for_secure_upgrade.peek().trim().to_owned();
                    let grant_present = state_store_for_secure_upgrade
                        .read()
                        .session_grant()
                        .map(|grant| !grant.grant_jwt.trim().is_empty())
                        .unwrap_or(false);
                    tracing::debug!(
                        target: "secure_store",
                        held_token_empty = held_token.is_empty(),
                        config_credential_present = !loaded_config.session_credential.trim().is_empty(),
                        local_state_session_grant_present = grant_present,
                        "secure store upgrade: post-upgrade credential sources (held_token from memory, config.session_credential, local_state.session_grant)"
                    );
                    if held_token.is_empty() && grant_present {
                        if let Some(rehydrated) = rehydrated_session_credential_for_active_config(
                            &loaded_config,
                            &base_url_for_secure_upgrade(),
                            &account_did_for_secure_upgrade(),
                            &device_id_for_secure_upgrade(),
                        ) {
                            tracing::debug!(target: "secure_store", "secure store upgrade: rehydrated token from config.session_credential — session should restore");
                            token_for_secure_upgrade.set(rehydrated);
                        }
                    } else if grant_present {
                        // A credential is already held in memory: sign-in completed
                        // BEFORE this IndexedDB secure-store upgrade was ready, so
                        // `config.rs` could only reach the localStorage tier, which
                        // refuses session credentials. Now that the upgraded store is
                        // installed, re-persist it so the session survives a reload /
                        // re-render instead of bouncing back to /login.
                        persist_config(
                            config_store_for_secure_upgrade,
                            base_url_for_secure_upgrade(),
                            account_did_for_secure_upgrade(),
                            device_id_for_secure_upgrade(),
                            held_token,
                        );
                    } else if !held_token.is_empty()
                        || !loaded_config.session_credential.trim().is_empty()
                    {
                        // A bearer string alone is not an authenticated Arkret
                        // session: request signing/rotation also requires the
                        // complete persisted grant and its durable DPoP key. Old
                        // builds could retain only the string when sign-in raced
                        // IndexedDB startup, leaving the UI apparently online while
                        // every self-path write failed. Do not preserve that
                        // impossible half-session; the user must obtain a fresh,
                        // atomically persisted grant through sign-in.
                        tracing::warn!(
                            target: "secure_store",
                            "discarding token-only session after secure-store bootstrap"
                        );
                        if !held_token.is_empty() {
                            token_for_secure_upgrade.set(String::new());
                        }
                        persist_config(
                            config_store_for_secure_upgrade,
                            base_url_for_secure_upgrade(),
                            account_did_for_secure_upgrade(),
                            device_id_for_secure_upgrade(),
                            String::new(),
                        );
                    }
                    let account_scope = account_did_for_secure_upgrade.peek().trim().to_owned();
                    let user_store = if account_scope.is_empty() {
                        None
                    } else {
                        match arkret_sdk::DidFullId::new(account_scope.clone())
                            .and_then(|full_id| arkret_sdk::project_full_id_to_core_id(&full_id))
                        {
                            Ok(core_id) => {
                                Some(crate::secure_key_store::UserLocalStore::new(core_id))
                            }
                            Err(error) => {
                                tracing::warn!(target: "secure_store", %error, "invalid active account principal");
                                None
                            }
                        }
                    };
                    if let Some(user_store) = user_store.as_ref() {
                        user_store.activate();
                        let dpop_record = {
                            let store = state_store_for_secure_upgrade.read();
                            store.load_dpop_device_key_with_secure_store(secure_store.as_ref())
                        };
                        match dpop_record {
                            Ok(Some(record)) => {
                                if let Err(error) = state_store_for_secure_upgrade
                                    .write()
                                    .set_dpop_device_key_with_secure_store(
                                        Some(record),
                                        secure_store.as_ref(),
                                    )
                                {
                                    tracing::warn!(
                                        ?error,
                                        "IndexedDB DPoP key metadata refresh failed",
                                    );
                                }
                            }
                            Ok(None) => {}
                            Err(error) => {
                                tracing::warn!(?error, "IndexedDB DPoP key load failed");
                            }
                        }
                    }
                    // Pin the stable, account-scoped `device_id` from the secure
                    // store as the authoritative source BEFORE the bootstrap
                    // `connect()` (gated on `secure_store_bootstrap_ready` below)
                    // publishes an MLS KeyPackage. The `config.json` blob's
                    // `device_id` is only a mirror: when the blob is not recovered
                    // at early boot, `LocalConfigStore::load()` falls back to a
                    // freshly-minted phantom `device_id`. An MLS KeyPackage
                    // published under a phantom strands its retained private init
                    // key (which is device-scoped in the secure store via
                    // `mls_key_package_identity_state_key`), so the to-device
                    // Welcome can never be decrypted ("no local KeyPackage identity
                    // state"). Resolving from the seed-paired secure-store entry
                    // makes `device_id` exactly as stable as the signing seed
                    // across reloads and re-logins of the same account.
                    let stable_device_id_for_signer = user_store.as_ref().and_then(|user_store| {
                        let store = secure_store.as_ref();
                            let current = device_id_for_secure_upgrade.peek().trim().to_owned();
                            let resolved = match user_store.load_device_id(store) {
                                Ok(Some(existing)) => Some(existing.to_string()),
                                Ok(None) => {
                                    let chosen = if crate::config::is_valid_device_id(&current) {
                                        current.clone()
                                    } else {
                                        crate::config::new_device_id()
                                    };
                                    match arkret_sdk::DeviceId::new(chosen.clone()) {
                                        Ok(device_id) => {
                                            match user_store.save_device_id(store, &device_id) {
                                                Ok(()) => Some(chosen),
                                                Err(error) => {
                                                    tracing::warn!(target: "secure_store", ?error, "persist stable device_id failed");
                                                    None
                                                }
                                            }
                                        }
                                        Err(error) => {
                                            tracing::warn!(target: "secure_store", ?error, "generated stable device_id was invalid");
                                            None
                                        }
                                    }
                                }
                                Err(error) => {
                                    tracing::warn!(target: "secure_store", ?error, "load stable device_id failed");
                                    None
                                }
                            };
                            match resolved {
                                Some(resolved) => {
                                    if resolved != current {
                                        tracing::warn!(
                                            target: "secure_store",
                                            stale = %current,
                                            stable = %resolved,
                                            "pinning stable device_id from secure store (config blob value was phantom/stale)"
                                        );
                                        device_id_for_secure_upgrade.set(resolved.clone());
                                        persist_config(
                                            config_store_for_secure_upgrade,
                                            base_url_for_secure_upgrade(),
                                            account_did_for_secure_upgrade(),
                                            resolved.clone(),
                                            token_for_secure_upgrade.peek().trim().to_owned(),
                                        );
                                    }
                                    Some(resolved)
                                }
                                None if crate::config::is_valid_device_id(&current) => {
                                    Some(current)
                                }
                                None => None,
                            }
                    });
                    if let (Some(user_store), Some(stable_device_id)) =
                        (user_store.as_ref(), stable_device_id_for_signer)
                    {
                        match crate::event_signer::bootstrap_default_signer_for_device(
                            "inkson",
                            &stable_device_id,
                        ) {
                            Ok(_) => {
                                tracing::info!(
                                    target: "secure_store",
                                    device_id = %stable_device_id,
                                    "IndexedDB device identity signer bootstrap succeeded"
                                );
                            }
                            Err(error) => {
                                tracing::warn!(
                                    target: "secure_store",
                                    ?error,
                                    "IndexedDB device identity signer bootstrap failed"
                                );
                            }
                        }
                        let _ = user_store;
                    }
                }
                Ok(None) => {
                    tracing::warn!(
                        target: "secure_store",
                        "secure store upgrade: Ok(None) — IndexedDB/SubtleCrypto reported UNAVAILABLE; staying on disabled localStorage tier; ALL account secrets and session credentials WILL fail (this is the Restoring-session hang root)"
                    );
                }
                Err(error) => {
                    tracing::warn!(target: "secure_store", ?error, "secure store upgrade: Err — IndexedDB secure-key-store upgrade failed");
                }
            }
            tracing::debug!(target: "secure_store", "secure store upgrade: settled, marking secure_store_bootstrap_ready=true");
            secure_store_ready_for_upgrade.set(true);
        });
    }
    rsx! {}
}

#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
const TEST_SESSION_GRANT_EXPIRY_OVERRIDE_KEY: &str = "inkson.test.session_grant_expiry_override.v1";

#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
fn apply_test_session_grant_expiry_override(
    state_store: &mut SyncSignal<LocalStateStore>,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) {
    let Some(window) = web_sys::window() else {
        return;
    };
    let Some(storage) = window.local_storage().ok().flatten() else {
        return;
    };
    let Some(raw) = storage
        .get_item(TEST_SESSION_GRANT_EXPIRY_OVERRIDE_KEY)
        .ok()
        .flatten()
    else {
        return;
    };
    let _ = storage.remove_item(TEST_SESSION_GRANT_EXPIRY_OVERRIDE_KEY);

    let parsed: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(error) => {
            tracing::warn!(?error, "invalid test session-grant expiry override");
            return;
        }
    };
    let expected_grant_jwt = parsed
        .get("expected_grant_jwt")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let seconds_from_now = parsed
        .get("seconds_from_now")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or_default();
    let result_key = parsed
        .get("result_key")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();

    let applied = (|| {
        if expected_grant_jwt.is_empty() || seconds_from_now <= 0 {
            return false;
        }
        let Ok(Some(mut grant)) = crate::state::load_session_grant_from_secure_store(secure_store)
        else {
            return false;
        };
        if grant.grant_jwt != expected_grant_jwt {
            return false;
        }
        let now = chrono::Utc::now();
        grant.grant_expires_at = Some(now + chrono::Duration::seconds(seconds_from_now));
        grant.stored_at = now;
        if crate::state::store_session_grant_in_secure_store(secure_store, &grant).is_err() {
            return false;
        }
        state_store.write().set_session_grant(Some(grant));
        // The session transport provider caches the grant state that was
        // loaded before this test-only expiry override ran. Drop that cached
        // provider so the next authenticated request restores the overridden
        // expiry and exercises the real due-refresh path.
        crate::identity::session_refresh::reset_session_grant_runtime();
        true
    })();

    if !result_key.is_empty()
        && let Ok(Some(session_storage)) = window.session_storage()
    {
        let _ = session_storage.set_item(result_key, if applied { "1" } else { "0" });
    }
}
