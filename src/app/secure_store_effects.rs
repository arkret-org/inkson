use super::*;

#[derive(Clone, Copy, PartialEq)]
pub(super) struct SecureStoreEffectState {
    pub config_store: Signal<LocalConfigStore>,
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
        secure_store_bootstrap_ready,
        token,
    } = state;
    #[cfg(target_arch = "wasm32")]
    let SessionContext {
        state_store,
        active_account,
        ..
    } = SessionContext::get();

    #[cfg(target_arch = "wasm32")]
    {
        let config_store_for_secure_upgrade = config_store;
        let active_account_for_secure_upgrade = active_account;
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
                    if let Some(account) = active_account_for_secure_upgrade() {
                        state_store_for_secure_upgrade
                            .write()
                            .switch_active_account(&account.profile_id, &account.authority);
                    }
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
                        let injected = active_account_for_secure_upgrade().and_then(|account| {
                            inject_test_session_grant(
                                &mut state_store_for_secure_upgrade,
                                config_store_for_secure_upgrade,
                                &account,
                                secure_store.as_ref(),
                            )
                            .or_else(|| {
                                inject_test_session_credential(
                                    config_store_for_secure_upgrade,
                                    &account,
                                )
                            })
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
                    let active_grant = state_store_for_secure_upgrade.read().session_grant();
                    let grant_present = active_grant
                        .as_ref()
                        .is_some_and(|grant| !grant.grant_jwt.trim().is_empty());
                    tracing::debug!(
                        target: "secure_store",
                        held_token_empty = held_token.is_empty(),
                        config_credential_present = !loaded_config.session_credential.trim().is_empty(),
                        local_state_session_grant_present = grant_present,
                        "secure store upgrade: post-upgrade credential sources (held_token from memory, config.session_credential, local_state.session_grant)"
                    );
                    if held_token.is_empty() && grant_present {
                        if let Some(rehydrated) = active_account_for_secure_upgrade()
                            .as_ref()
                            .and_then(|account| {
                                rehydrated_session_credential_for_active_config(
                                    &loaded_config,
                                    account,
                                )
                            })
                        {
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
                            active_account_for_secure_upgrade(),
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
                            active_account_for_secure_upgrade(),
                            String::new(),
                        );
                    }
                    let account = active_account_for_secure_upgrade();
                    let account_scope = account
                        .as_ref()
                        .map(|account| account.principal_id().to_string())
                        .unwrap_or_default();
                    let user_store = account.as_ref().and_then(|account| {
                        match crate::secure_key_store::UserLocalStore::new(
                            account.authority.clone(),
                            account.device_id.clone(),
                        ) {
                            Ok(store) => Some(store),
                            Err(error) => {
                                tracing::warn!(target: "secure_store", %error, "invalid active account secure scope");
                                None
                            }
                        }
                    });
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
                    let stable_device_id_for_signer = account.as_ref().and_then(|account| {
                        let user_store = user_store.as_ref()?;
                        match user_store.load_device_id(secure_store.as_ref()) {
                            Ok(Some(stored)) if stored == account.device_id => {
                                Some(stored.to_string())
                            }
                            Ok(Some(stored)) => {
                                tracing::warn!(
                                    target: "secure_store",
                                    stored = %stored,
                                    active = %account.device_id,
                                    "secure-store device does not match active account context"
                                );
                                None
                            }
                            Ok(None) => match user_store
                                .save_device_id(secure_store.as_ref(), &account.device_id)
                            {
                                Ok(()) => Some(account.device_id.to_string()),
                                Err(error) => {
                                    tracing::warn!(target: "secure_store", ?error, "persist active device_id failed");
                                    None
                                }
                            },
                            Err(error) => {
                                tracing::warn!(target: "secure_store", ?error, "load stable device_id failed");
                                None
                            }
                        }
                    });
                    if let (Some(user_store), Some(stable_device_id)) =
                        (user_store.as_ref(), stable_device_id_for_signer)
                    {
                        let signer_bootstrap =
                            crate::event_signer::bootstrap_default_signer_for_device(
                                "inkson",
                                &stable_device_id,
                            )
                            .map_err(|error| {
                                anyhow::anyhow!("load device identity signer: {error}")
                            })
                            .and_then(|_| {
                                let account = account.as_ref().ok_or_else(|| {
                                    anyhow::anyhow!("active account context is unavailable")
                                })?;
                                bind_active_signer_to_account_session(
                                    account,
                                    active_grant.as_ref(),
                                )
                            });
                        match signer_bootstrap {
                            Ok(()) => {
                                tracing::info!(
                                    target: "secure_store",
                                    principal = %account_scope,
                                    device_id = %stable_device_id,
                                    "IndexedDB account-bound device identity signer bootstrap succeeded"
                                );
                            }
                            Err(error) => {
                                crate::event_signer::clear_active_device_signer();
                                if active_grant.is_some()
                                    || !token_for_secure_upgrade.peek().trim().is_empty()
                                    || !loaded_config.session_credential.trim().is_empty()
                                {
                                    // Identity binding is part of the session transaction,
                                    // not a best-effort repair. Never publish secure-store
                                    // readiness with a grant that cannot be signed by this
                                    // account/device tuple; require a fresh sign-in instead.
                                    state_store_for_secure_upgrade
                                        .write()
                                        .set_session_grant(None);
                                    token_for_secure_upgrade.set(String::new());
                                    if let Some(account) = account.as_ref() {
                                        crate::config::clear_session_credential_secret(
                                            &account.authority,
                                            &account.device_id,
                                        );
                                    }
                                    persist_config(
                                        config_store_for_secure_upgrade,
                                        account.clone(),
                                        String::new(),
                                    );
                                }
                                tracing::warn!(
                                    target: "secure_store",
                                    principal = %account_scope,
                                    device_id = %stable_device_id,
                                    %error,
                                    "IndexedDB account-bound device identity signer bootstrap failed; session discarded"
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

/// A durable signing seed identifies a key, not the account identity that
/// authorizes that key. Rebind the freshly loaded key to the active account's
/// full DID on every boot before session refresh or Event authoring can run.
// The only production caller lives inside the `#[cfg(target_arch = "wasm32")]`
// secure-store upgrade block above; the remaining callers are this file's
// `#[cfg(test)]` tests. Gate on the union of both so native non-test builds
// do not report it as dead code.
#[cfg(target_arch = "wasm32")]
fn bind_active_signer_to_account_session(
    account: &crate::config::ActiveAccountContext,
    grant: Option<&PersistedSessionGrant>,
) -> anyhow::Result<()> {
    if let Some(grant) = grant {
        if grant.authority != account.authority {
            anyhow::bail!("session grant authority does not match the active account");
        }
        if grant.device_id != account.device_id {
            anyhow::bail!("session grant device does not match the active device");
        }
    }
    let signer = crate::event_signer::bind_active_signer_principal_device_id(
        account.full_id(),
        account.device_id.as_str(),
    )
    .map_err(|error| anyhow::anyhow!("bind active account signer: {error}"))?
    .ok_or_else(|| anyhow::anyhow!("active device identity signer is not installed"))?;
    if signer.signer_did() != account.full_id().as_str()
        || signer.device_id() != Some(account.device_id.as_str())
    {
        anyhow::bail!("active signer binding did not preserve the account/device identity");
    }
    Ok(())
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
