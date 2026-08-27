use super::*;

#[cfg(target_arch = "wasm32")]
fn trace_secure_store_bootstrap_stage(stage: &'static str) {
    // Keep startup diagnostics permanently visible in debug web builds. These
    // milestones contain no account identifiers or secret material and make a
    // browser-local IndexedDB/WebCrypto stall diagnosable from one screenshot.
    #[cfg(debug_assertions)]
    tracing::warn!(target: "secure_store", stage, "secure-store app bootstrap stage");
    #[cfg(not(debug_assertions))]
    tracing::info!(target: "secure_store", stage, "secure-store app bootstrap stage");
}

#[derive(Clone, Copy, PartialEq)]
pub(super) struct SecureStoreEffectState {
    pub config_store: Signal<LocalConfigStore>,
    pub principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
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
        principal_id,
        device_id,
        secure_store_bootstrap_ready,
        token,
    } = state;
    #[cfg(target_arch = "wasm32")]
    let SessionContext {
        state_store,
        base_url,
        active_account,
        ..
    } = SessionContext::get();

    #[cfg(target_arch = "wasm32")]
    {
        let config_store_for_secure_upgrade = config_store;
        let base_url_for_secure_upgrade = base_url;
        let principal_id_for_secure_upgrade = principal_id;
        let device_id_for_secure_upgrade = device_id;
        let mut state_store_for_secure_upgrade = state_store;
        let mut secure_store_ready_for_upgrade = secure_store_bootstrap_ready;
        let mut token_for_secure_upgrade = token;
        use_future(move || async move {
            crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(1)).await;
            trace_secure_store_bootstrap_stage("start backend initialization");
            match crate::secure_key_store::initialize_wasm_secure_key_store_async("inkson").await {
                Ok(Some(secure_store)) => {
                    trace_secure_store_bootstrap_stage("backend initialized");
                    // Hydrate the active account's main state from the IndexedDB
                    // encrypted entries store into `cached` before
                    // anything downstream reads it. Runs before the E2EE plaintext
                    // cache hydration (which merges plaintext INTO the account
                    // state) and before `secure_store_bootstrap_ready` is published
                    // so the account state is authoritative before session/connect.
                    state_store_for_secure_upgrade
                        .write()
                        .hydrate_active_account_state_from_secure_store(secure_store.as_ref());
                    trace_secure_store_bootstrap_stage("active account state hydrated");
                    let hydrated = state_store_for_secure_upgrade
                        .write()
                        .hydrate_e2ee_plaintext_cache_with_secure_store(secure_store.as_ref());
                    if let Err(error) = hydrated {
                        tracing::warn!(?error, "IndexedDB E2EE plaintext cache hydration failed",);
                    } else {
                        trace_secure_store_bootstrap_stage("E2EE cache hydrated");
                        let secure_write = state_store_for_secure_upgrade
                            .read()
                            .e2ee_plaintext_cache_secure_write();
                        match secure_write {
                            Ok(Some((key, Some(json)))) => {
                                // Commit the recovered combined snapshot before
                                // publishing readiness. Running this write in the
                                // background lets an older repair overwrite a newer
                                // cache write after normal effects have started. The
                                // underlying WebCrypto and IndexedDB awaits are
                                // timeout-bounded, so this barrier cannot hang forever.
                                match secure_store.store_secret_durable(&key, &json).await {
                                    Ok(()) => {
                                        // Clear pre-decrypt recovery checkpoints only
                                        // after the exact combined snapshot + plaintext
                                        // entry has durably committed.
                                        match state_store_for_secure_upgrade
                                            .write()
                                            .clear_mls_receive_recovery_snapshots_if_cache_unchanged(
                                                &key,
                                                &json,
                                            ) {
                                            Ok(true) => {}
                                            Ok(false) => tracing::warn!(
                                                target: "secure_store",
                                                "MLS receive recovery checkpoint cleanup deferred because newer state arrived"
                                            ),
                                            Err(error) => tracing::warn!(
                                                ?error,
                                                "MLS receive recovery checkpoint cleanup failed",
                                            ),
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
                            active_account.peek().clone(),
                            &device_id_for_secure_upgrade(),
                            secure_store.as_ref(),
                        )
                        .await
                        .or_else(|| {
                            inject_test_session_credential(
                                config_store_for_secure_upgrade,
                                &base_url_for_secure_upgrade(),
                                principal_id_for_secure_upgrade(),
                                &device_id_for_secure_upgrade(),
                            )
                        });
                        if let Some(credential) = injected {
                            token_for_secure_upgrade.set(credential);
                        }
                        apply_test_session_grant_expiry_override(
                            &mut state_store_for_secure_upgrade,
                            secure_store.as_ref(),
                        )
                        .await;
                    }
                    let loaded_config = config_store_for_secure_upgrade
                        .read()
                        .load_with_secure_store(secure_store.as_ref());
                    let held_token = token_for_secure_upgrade.peek().trim().to_owned();
                    // The session grant is an account-scoped secure-store
                    // secret, not part of the synchronously hydrated local
                    // snapshot. Restore it before classifying the remaining
                    // credential as an impossible token-only session.
                    let restored_grant = active_account.peek().as_ref().and_then(|account| {
                        crate::identity::session_refresh::load_account_session_grant_with_secure_store(
                            account,
                            secure_store.as_ref(),
                        )
                        .ok()
                    });
                    if state_store_for_secure_upgrade
                        .read()
                        .session_grant()
                        .is_none()
                        && let Some(grant) = restored_grant
                    {
                        state_store_for_secure_upgrade
                            .write()
                            .set_session_grant(Some(grant));
                    }
                    let restored_active_grant =
                        state_store_for_secure_upgrade.read().session_grant();
                    let restored_grant_present = restored_active_grant.is_some();
                    let active_grant = restored_active_grant.filter(|grant| {
                        active_account.peek().as_ref().is_some_and(|account| {
                            session_grant_boot_usable(
                                grant,
                                account,
                                chrono::Utc::now().timestamp(),
                            )
                        })
                    });
                    let grant_present = active_grant.is_some();
                    if restored_grant_present && active_grant.is_none() {
                        tracing::warn!(
                            target: "secure_store",
                            "discarding expired or account-mismatched session grant after secure-store bootstrap"
                        );
                        state_store_for_secure_upgrade
                            .write()
                            .set_session_grant(None);
                    }
                    tracing::debug!(
                        target: "secure_store",
                        held_token_empty = held_token.is_empty(),
                        config_credential_present = !loaded_config.session_credential.trim().is_empty(),
                        local_state_session_grant_present = grant_present,
                        "secure store upgrade: post-upgrade credential sources (held_token from memory, config.session_credential, local_state.session_grant)"
                    );
                    if let Some(active_grant) = active_grant.as_ref() {
                        // The complete account/device/audience-bound persisted grant
                        // is authoritative for the bearer string. A config or memory
                        // token can be left over from an interrupted rotation; using
                        // it with different restored grant metadata recreates an
                        // impossible half-session and makes introspection fail.
                        let authoritative_token = active_grant.grant_jwt.clone();
                        if held_token != authoritative_token {
                            tracing::warn!(
                                target: "secure_store",
                                held_token_empty = held_token.is_empty(),
                                "normalizing session credential to the restored account-bound grant"
                            );
                            token_for_secure_upgrade.set(authoritative_token.clone());
                        }
                        persist_config(
                            config_store_for_secure_upgrade,
                            base_url_for_secure_upgrade(),
                            principal_id_for_secure_upgrade(),
                            device_id_for_secure_upgrade(),
                            authoritative_token,
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
                            principal_id_for_secure_upgrade(),
                            device_id_for_secure_upgrade(),
                            String::new(),
                        );
                    }
                    let account = active_account.peek().clone();
                    trace_secure_store_bootstrap_stage("session material classified");
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
                    let active_signer_account = active_account.peek().clone();
                    if let (Some(user_store), Some(stable_device_id), Some(active_signer_account)) = (
                        user_store.as_ref(),
                        stable_device_id_for_signer,
                        active_signer_account,
                    ) {
                        let signer_bootstrap =
                            crate::event_signer::bootstrap_default_signer_for_device(
                                "inkson",
                                &stable_device_id,
                            )
                            .map_err(|error| {
                                anyhow::anyhow!("load device identity signer: {error}")
                            })
                            .and_then(|_| {
                                bind_active_signer_to_account_session(
                                    &active_signer_account,
                                    active_grant.as_ref(),
                                )
                            });
                        match signer_bootstrap {
                            Ok(()) => {
                                tracing::info!(
                                    target: "secure_store",
                                    principal = %active_signer_account.full_id(),
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
                                    if let Some(account) =
                                        SessionContext::get().active_account.peek().as_ref()
                                    {
                                        crate::config::clear_session_credential_secret(account);
                                    }
                                    persist_config(
                                        config_store_for_secure_upgrade,
                                        base_url_for_secure_upgrade(),
                                        Some(active_signer_account.principal_id().clone()),
                                        stable_device_id.clone(),
                                        String::new(),
                                    );
                                }
                                tracing::warn!(
                                    target: "secure_store",
                                    principal = %active_signer_account.full_id(),
                                    device_id = %stable_device_id,
                                    %error,
                                    "IndexedDB account-bound device identity signer bootstrap failed; session discarded"
                                );
                            }
                        }
                        let _ = user_store;
                    }
                    trace_secure_store_bootstrap_stage("device signer classified");

                    // A durable logout retry can perform authority discovery and
                    // network I/O. It must never be part of the one-shot secure
                    // storage readiness barrier: a slow/offline authority would
                    // otherwise leave every route permanently on the restoring
                    // splash. The journal is already durable, so run it after
                    // local hydration as an independent best-effort task.
                    let pending_logout_store = secure_store.clone();
                    wasm_bindgen_futures::spawn_local(async move {
                        crate::pending_logout::run_pending_logout_with_store(
                            chrono::Utc::now(),
                            pending_logout_store.as_ref(),
                        )
                        .await;
                    });
                    trace_secure_store_bootstrap_stage("background maintenance scheduled");
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
            trace_secure_store_bootstrap_stage("publishing ready signal");
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
#[cfg(any(target_arch = "wasm32", test))]
fn bind_active_signer_to_account_session(
    account: &crate::config::ActiveAccountContext,
    grant: Option<&PersistedSessionGrant>,
) -> anyhow::Result<()> {
    let principal_core = account.principal_id();
    let device = &account.device_id;
    if let Some(grant) = grant {
        let grant_principal =
            crate::identity::session_refresh::persisted_grant_principal_id(grant)?;
        if grant_principal != *principal_core {
            anyhow::bail!("session grant principal does not match the active account");
        }
        if grant.device_id != *device {
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

#[cfg(test)]
mod account_signer_boot_tests {
    use super::bind_active_signer_to_account_session;
    use crate::state::PersistedSessionGrant;

    fn account(principal: &str, device: &str) -> crate::config::ActiveAccountContext {
        let full_id = arkret_sdk::DidFullId::new(principal.to_owned()).unwrap();
        let authority = arkret_sdk::PrincipalAuthorityKey::new(
            arkret_sdk::project_full_id_to_core_id(&full_id).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
        );
        crate::config::ActiveAccountContext::new(
            "ak:profile:boot-test".to_owned(),
            authority,
            arkret_sdk::PrincipalResolutionProjection {
                full_id,
                method_history_head: "boot-test-head".to_owned(),
                version_id: "1".to_owned(),
                resolution_event_ref: "boot-test-event".to_owned(),
                updated_at: chrono::Utc::now(),
            },
            arkret_sdk::DeviceId::new(device.to_owned()).unwrap(),
            url::Url::parse("https://principal.example").unwrap(),
        )
        .unwrap()
    }

    fn session_grant(principal_id: String, device_id: &str) -> PersistedSessionGrant {
        PersistedSessionGrant {
            grant_jwt: "header.payload.signature".to_owned(),
            session_private_key_pem: String::new(),
            grant_id: "grant-boot-test".to_owned(),
            audience: "did:web:principal.example".to_owned(),
            principal_id: arkret_sdk::DidCoreId::new(principal_id).unwrap(),
            device_id: arkret_sdk::DeviceId::new(device_id.to_owned()).unwrap(),
            principal_server_url: url::Url::parse("https://principal.example").unwrap(),
            grant_expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            stored_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn boot_rebinds_loaded_device_key_to_active_account_full_id() {
        let _guard = crate::event_signer::ActiveSignerTestGuard::replace(None);
        let device = "ak:device:019f0000-0000-7000-8000-000000000041";
        let principal = "did:webvh:z6mkfixture:boot.example";
        crate::event_signer::activate_device_signer_from_seed_for_device(
            [41; 32],
            None,
            Some(device),
        )
        .unwrap();

        let principal_full = arkret_sdk::DidFullId::new(principal.to_owned()).unwrap();
        let principal_core = arkret_sdk::project_full_id_to_core_id(&principal_full).unwrap();
        let grant = session_grant(principal_core.to_string(), device);
        bind_active_signer_to_account_session(&account(principal, device), Some(&grant)).unwrap();

        let signer = crate::event_signer::active_signer().expect("bound signer");
        assert_eq!(signer.signer_did(), principal);
        assert_eq!(signer.device_id(), Some(device));
    }

    #[test]
    fn boot_rejects_a_session_grant_for_another_principal_before_binding() {
        let _guard = crate::event_signer::ActiveSignerTestGuard::replace(None);
        let device = "ak:device:019f0000-0000-7000-8000-000000000042";
        let principal = "did:webvh:z6mkfixture:boot.example";
        crate::event_signer::activate_device_signer_from_seed_for_device(
            [42; 32],
            None,
            Some(device),
        )
        .unwrap();
        let other =
            arkret_sdk::DidFullId::new("did:webvh:z6mkfixtureother:other.example".to_owned())
                .unwrap();
        let other_core = arkret_sdk::project_full_id_to_core_id(&other).unwrap();
        let grant = session_grant(other_core.to_string(), device);

        let error =
            bind_active_signer_to_account_session(&account(principal, device), Some(&grant))
                .unwrap_err();

        assert!(error.to_string().contains("principal does not match"));
        assert_ne!(
            crate::event_signer::active_signer()
                .expect("unbound signer remains installed")
                .signer_did(),
            principal
        );
    }
}

#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
const TEST_SESSION_GRANT_EXPIRY_OVERRIDE_KEY: &str = "inkson.test.session_grant_expiry_override.v1";

#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
async fn apply_test_session_grant_expiry_override(
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

    let applied = async {
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
        let Ok(user_store) = crate::state::active_user_local_store() else {
            return false;
        };
        let Ok(encoded) = serde_json::to_string(&grant) else {
            return false;
        };
        if user_store
            .save_secret_durable(
                secure_store,
                crate::state::LocalStateStore::SECURE_SESSION_GRANT_KEY,
                &encoded,
            )
            .await
            .is_err()
        {
            return false;
        }
        state_store.write().set_session_grant(Some(grant));
        // The session transport provider caches the grant state that was
        // loaded before this test-only expiry override ran. Drop that cached
        // provider so the next authenticated request restores the overridden
        // expiry and exercises the real due-refresh path.
        crate::identity::session_refresh::reset_session_grant_runtime();
        true
    }
    .await;

    if !result_key.is_empty()
        && let Ok(Some(session_storage)) = window.session_storage()
    {
        let _ = session_storage.set_item(result_key, if applied { "1" } else { "0" });
    }
}
