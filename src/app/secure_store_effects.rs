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
                    tracing::debug!(target: "secure_store", "secure store upgrade: Ok(Some) — IndexedDb tier installed");
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
                    let loaded_config = config_store_for_secure_upgrade
                        .read()
                        .load_with_secure_store(secure_store.as_ref());
                    let held_token = token_for_secure_upgrade.peek().trim().to_owned();
                    {
                        let grant_present = state_store_for_secure_upgrade
                            .read()
                            .session_grant()
                            .map(|g| !g.grant_jwt.trim().is_empty())
                            .unwrap_or(false);
                        tracing::warn!(
                            target: "secure_store",
                            held_token_empty = held_token.is_empty(),
                            config_credential_present = !loaded_config.session_credential.trim().is_empty(),
                            local_state_session_grant_present = grant_present,
                            "secure store upgrade: post-upgrade credential sources (held_token from memory, config.session_credential, local_state.session_grant)"
                        );
                    }
                    if held_token.is_empty() {
                        if let Some(rehydrated) = rehydrated_session_credential_for_active_config(
                            &loaded_config,
                            &base_url_for_secure_upgrade(),
                            &account_did_for_secure_upgrade(),
                            &device_id_for_secure_upgrade(),
                        ) {
                            tracing::debug!(target: "secure_store", "secure store upgrade: rehydrated token from config.session_credential — session should restore");
                            token_for_secure_upgrade.set(rehydrated);
                        }
                    } else {
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
                    }
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
                    let stable_device_id_for_signer = {
                        let store = secure_store.as_ref();
                        let account_scope = account_did_for_secure_upgrade.peek().trim().to_owned();
                        if account_scope.is_empty() {
                            tracing::warn!(
                                target: "secure_store",
                                "device identity signer bootstrap skipped: no account scope yet"
                            );
                            None
                        } else {
                            crate::secure_key_store::set_active_device_seed_scope(Some(
                                &account_scope,
                            ));
                            let current = device_id_for_secure_upgrade.peek().trim().to_owned();
                            let resolved = match crate::secure_key_store::load_device_id_scoped(
                                store,
                                Some(&account_scope),
                            ) {
                                Ok(Some(existing)) => Some(existing),
                                Ok(None) => {
                                    let chosen = if crate::config::is_valid_device_id(&current) {
                                        current.clone()
                                    } else {
                                        crate::config::new_device_id()
                                    };
                                    match crate::secure_key_store::store_device_id_scoped(
                                        store,
                                        Some(&account_scope),
                                        &chosen,
                                    ) {
                                        Ok(()) => Some(chosen),
                                        Err(error) => {
                                            tracing::warn!(target: "secure_store", ?error, "persist stable device_id failed");
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
                        }
                    };
                    match stable_device_id_for_signer {
                        Some(stable_device_id) => {
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
                        }
                        None => {
                            tracing::warn!(
                                target: "secure_store",
                                "IndexedDB device identity signer bootstrap skipped: no stable device_id"
                            );
                        }
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
