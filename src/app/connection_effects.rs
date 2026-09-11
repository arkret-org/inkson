use super::connection_handlers::ConnectionRuntimeSignals;
use super::*;

fn should_run_connection_bootstrap(bootstrap_pending: bool, authentication_active: bool) -> bool {
    bootstrap_pending && !authentication_active
}

#[derive(Clone, Copy, PartialEq)]
pub(super) struct ConnectionEffectState {
    pub runtime: ConnectionRuntimeSignals,
    pub secure_store_bootstrap_ready: Signal<bool>,
    pub session_generation: Signal<u64>,
    pub authentication_active: bool,
}

#[component]
pub(super) fn ConnectionEffects(state: ConnectionEffectState) -> Element {
    let ConnectionEffectState {
        runtime,
        secure_store_bootstrap_ready,
        mut session_generation,
        authentication_active,
    } = state;
    let ConnectionRuntimeSignals {
        mut connection_status,
        mut sync_cursor,
        mut token,
        principal_id,
        device_id,
        mut selected_realm_id,
        mut realm_tree_nodes,
        mut projection_events,
        mut device_queue,
        mut crypto_state,
        config_store,
        mut network_state,
        mut last_error,
        mut sync_generation,
        mut needs_device_authorization,
        mut device_authorization_check_complete,
        mut account_has_other_devices,
        mut sync_bootstrap_complete,
        session_boot_state,
        mut bootstrap_pending,
        ..
    } = runtime;
    let SessionContext {
        mut state_store,
        base_url,
        active_account,
        ..
    } = SessionContext::get();
    let runtime_services = use_context::<crate::runtime::services::RuntimeServices>();
    let navigator = use_navigator();
    let mut device_authorization_recheck_key = use_signal(String::new);
    let mut device_authorization_recheck_attempt = use_signal(|| 0_u32);

    {
        let invalidator_effects = runtime_services.effects.clone();
        let session_coordinator = runtime_services.session.clone();
        use_hook(move || {
            session_coordinator.set_invalidator(move |reason| {
                invalidator_effects.request_cancel_all();
                session_generation.set(session_generation() + 1);
                let rejected_grant = state_store.read().session_grant();
                let rejected_account = active_account.peek().clone();
                state_store.write().set_session_grant(None);
                bootstrap_pending.set(false);
                token.set(String::new());
                persist_config(
                    config_store,
                    base_url(),
                    principal_id(),
                    device_id(),
                    String::new(),
                );
                sync_cursor.set(String::new());
                selected_realm_id.set(String::new());
                realm_tree_nodes.set(Vec::new());
                projection_events.set(Vec::new());
                device_queue.set(0);
                crypto_state.set("Session expired".to_owned());
                connection_status.set("Session expired; sign in again".to_owned());
                network_state.set("online".to_owned());
                last_error.set(Some(reason));
                needs_device_authorization.set(false);
                device_authorization_check_complete.set(false);
                account_has_other_devices.set(false);
                sync_generation.set(sync_generation() + 1);
                transition_session_boot_state(
                    session_boot_state,
                    SessionBootState::Unauthenticated,
                    "session coordinator invalidated the active session",
                );
                let cleanup_generation = *session_generation.peek();
                spawn(async move {
                    let result = async {
                        let _commit =
                            crate::identity::session_refresh::session_credential_mutation_lock()
                                .lock()
                                .await;
                        anyhow::ensure!(
                            *session_generation.peek() == cleanup_generation,
                            "session changed before cleanup"
                        );
                        if let Some(account) = rejected_account {
                            let secure_store =
                                crate::secure_key_store::default_secure_key_store("inkson");
                            crate::identity::session_refresh::clear_rejected_session_grant(
                                &account,
                                rejected_grant.as_ref(),
                                secure_store.as_ref(),
                            )
                            .await?;
                            if *session_generation.peek() != cleanup_generation {
                                anyhow::bail!("session changed during rejected grant cleanup");
                            }
                            crate::config::clear_session_credential_secret_durable(&account)
                                .await?;
                        }
                        Ok::<_, anyhow::Error>(())
                    }
                    .await;
                    if *session_generation.peek() != cleanup_generation {
                        return;
                    }
                    match result {
                        Ok(()) => {
                            navigator.replace(Route::Login);
                        }
                        Err(error) => {
                            tracing::error!(%error, "rejected session cleanup failed");
                            last_error.set(Some(format!(
                                "Could not remove the expired session from secure storage: {error}"
                            )));
                        }
                    }
                });
            });
        });
    }

    use_effect(move || {
        let state = state_store.read().load();
        let next = realm_tree_nodes_from_sync_realms_with_roles(
            &state.realm_tree_projections,
            &state.realm_collaboration_roles,
        );
        if *realm_tree_nodes.peek() != next {
            realm_tree_nodes.set(next);
        }
    });

    {
        let mut recheck_needs_authorization = needs_device_authorization;
        let mut recheck_complete = device_authorization_check_complete;
        let mut recheck_has_other = account_has_other_devices;
        use_effect(move || {
            if !recheck_complete() || !recheck_needs_authorization() || !sync_bootstrap_complete() {
                return;
            }
            // Device pairing is approved on another device. The durable device
            // list/account-sync edge is therefore the signal to re-check the
            // exact directory signer and release MLS publication on this one.
            let cursor = sync_cursor();
            let session = token();
            let Some(actor) = active_account
                .peek()
                .as_ref()
                .map(|account| account.did().clone())
            else {
                return;
            };
            let Some(account) = active_account.peek().clone() else {
                return;
            };
            let base = account.server_url.to_string();
            let device = account.device_id.to_string();
            if cursor.trim().is_empty()
                || base.trim().is_empty()
                || session.trim().is_empty()
                || device.trim().is_empty()
            {
                return;
            }
            let key = format!("{cursor}|{}|{device}", actor.as_str());
            if device_authorization_recheck_key().as_str() == key {
                return;
            }
            device_authorization_recheck_key.set(key.clone());
            spawn(async move {
                let result =
                    crate::transport::auth::with_authed_api(&base, session, |api| async move {
                        super::connect::probe_device_authorization(&account, &device, &api).await
                    })
                    .await;
                match result {
                    Ok((needs_authorization, has_other)) => {
                        if *device_authorization_recheck_attempt.peek() != 0 {
                            device_authorization_recheck_attempt.set(0);
                        }
                        recheck_has_other.set(has_other);
                        recheck_needs_authorization.set(needs_authorization);
                        recheck_complete.set(true);
                    }
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            "device authorization re-check after account sync failed"
                        );
                        let attempt = *device_authorization_recheck_attempt.peek();
                        let retry_after_secs = (2_u64 << attempt.min(5)).min(60);
                        device_authorization_recheck_attempt.set(attempt.saturating_add(1).min(5));
                        crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(
                            retry_after_secs,
                        ))
                        .await;
                        // Clear only the attempt that failed. Reading this key
                        // reactively above makes the effect retry on the same
                        // durable cursor; it does not need an unrelated Realm
                        // event to recover from a transient directory error.
                        if device_authorization_recheck_key.peek().as_str() == key {
                            device_authorization_recheck_key.set(String::new());
                        }
                    }
                }
            });
        });
    }

    let mut previous_authentication_active = use_signal(|| false);
    if authentication_active != *previous_authentication_active.peek() {
        previous_authentication_active.set(authentication_active);
        if authentication_active {
            runtime_services.session.suspend();
            runtime_services.effects.request_cancel_all();
            let next_generation = (*session_generation.peek()).wrapping_add(1);
            session_generation.set(next_generation);
            bootstrap_pending.set(true);
            sync_bootstrap_complete.set(false);
        }
    }

    let secure_store_ready = secure_store_bootstrap_ready();
    if should_run_connection_bootstrap(bootstrap_pending(), authentication_active) {
        let active = active_account();
        let base = active
            .as_ref()
            .map(|account| account.server_url.to_string())
            .unwrap_or_else(|| base_url.read().clone());
        let mut session = token();
        if session.trim().is_empty() && secure_store_ready {
            let loaded = config_store.read().load();
            if let Some(rehydrated) =
                rehydrated_session_credential_for_active_config(&loaded, active.as_ref())
            {
                token.set(rehydrated.clone());
                session = rehydrated;
            }
        }
        if !session.trim().is_empty() {
            let stale_for_selected_server = state_store
                .read()
                .session_grant()
                .as_ref()
                .is_some_and(|grant| {
                    !crate::identity::session_refresh::grant_matches_station(grant, &base)
                });
            if stale_for_selected_server {
                token.set(String::new());
                transition_session_boot_state(
                    session_boot_state,
                    SessionBootState::Unauthenticated,
                    "persisted grant belongs to another Station",
                );
                persist_config(
                    config_store,
                    base.clone(),
                    principal_id(),
                    device_id(),
                    String::new(),
                );
                session.clear();
            }
        }
        let can_restore_session = {
            let store = state_store.read();
            has_bootstrap_refresh_material(&store, active.as_ref())
        };
        if !base.trim().is_empty()
            && secure_store_ready
            && (!session.trim().is_empty() || can_restore_session)
        {
            bootstrap_pending.set(false);
            sync_bootstrap_complete.set(false);
            let bootstrap_state = session_boot_state_from_bootstrap_material(
                &session,
                can_restore_session,
                crate::app::principal_id_text(&principal_id()),
                secure_store_ready,
            );
            transition_session_boot_state(
                session_boot_state,
                bootstrap_state,
                "bootstrap material is ready for connect",
            );
            connect(
                base,
                principal_id(),
                device_id(),
                runtime.connect_context(runtime_services.session.clone(), state_store),
            );
        } else if !base.trim().is_empty() {
            let bootstrap_state = session_boot_state_from_bootstrap_material(
                &session,
                can_restore_session,
                crate::app::principal_id_text(&principal_id()),
                secure_store_ready,
            );
            if *session_boot_state.peek() != bootstrap_state {
                transition_session_boot_state(
                    session_boot_state,
                    bootstrap_state,
                    "secure-store bootstrap material classified",
                );
            }
        }
    }

    rsx! {}
}

#[cfg(test)]
mod tests {
    use super::should_run_connection_bootstrap;

    #[test]
    fn pauses_normal_session_bootstrap_during_onboarding() {
        assert!(!should_run_connection_bootstrap(true, true));
    }

    #[test]
    fn runs_only_pending_bootstrap_outside_onboarding() {
        assert!(should_run_connection_bootstrap(true, false));
        assert!(!should_run_connection_bootstrap(false, false));
        assert!(!should_run_connection_bootstrap(false, true));
    }
}
