use super::*;

fn should_run_connection_bootstrap(bootstrap_pending: bool, authentication_active: bool) -> bool {
    bootstrap_pending && !authentication_active
}

pub(super) fn install(
    scope: &glory::Scope,
    context: std::rc::Rc<crate::presentation::InksonContext>,
) {
    let runtime_services = context.services.clone();
    let state_revision = context.state_revision;
    let connection_status = context.connection_status;
    let sync_cursor = context.sync_cursor;
    let token = context.token;
    let principal_id = context.principal_id;
    let device_id = context.device_id;
    let selected_realm_id = context.selected_realm_id;
    let realm_tree_nodes = context.realm_tree_nodes;
    let projection_events = context.projection_events;
    let device_queue = context.device_queue;
    let crypto_state = context.crypto_state;
    let config_store = context.config_store;
    let network_state = context.network_state;
    let last_error = context.last_error;
    let sync_generation = context.sync_generation;
    let needs_device_authorization = context.needs_device_authorization;
    let device_authorization_check_complete = context.device_authorization_check_complete;
    let account_has_other_devices = context.account_has_other_devices;
    let sync_bootstrap_complete = context.sync_bootstrap_complete;
    let session_boot_state = context.session_boot_state;
    let bootstrap_pending = context.bootstrap_pending;
    let active_account = context.active_account;
    let base_url = context.base_url;
    let session_generation = context.session_generation;
    let secure_store_bootstrap_ready = context.secure_store_bootstrap_ready;
    let device_authorization_recheck_key = scope.cage(String::new());
    let device_authorization_recheck_attempt = scope.cage(0_u32);

    {
        let invalidator_effects = runtime_services.effects.clone();
        let session_coordinator = runtime_services.session.clone();
        let state_store = context.state_store.clone();
        let owner = scope.downgrade();
        let navigation = std::rc::Rc::downgrade(&context);
        {
            session_coordinator.set_invalidator(move |reason| {
                let Some(scope) = owner.upgrade() else { return };
                invalidator_effects.request_cancel_all();
                if let Some(context) = navigation.upgrade() {
                    context.clear_account_projections();
                }
                session_generation.revise(|current| *current = current.wrapping_add(1));
                let rejected_grant = state_store.read(|store| store.session_grant());
                let rejected_account = active_account.get_untracked().clone();
                state_store.write(|store| store.set_session_grant(None));
                bootstrap_pending.revise(|current| *current = false);
                token.revise(|current| *current = String::new());
                persist_config(
                    config_store,
                    &active_account.get_untracked(),
                    base_url.get(),
                    principal_id.get(),
                    device_id.get(),
                    String::new(),
                );
                sync_cursor.revise(|current| *current = String::new());
                selected_realm_id.revise(|current| *current = String::new());
                realm_tree_nodes.revise(|current| *current = Vec::new());
                projection_events.revise(|current| *current = Vec::new());
                device_queue.revise(|current| *current = 0);
                crypto_state.revise(|current| *current = "Session expired".to_owned());
                connection_status
                    .revise(|current| *current = "Session expired; sign in again".to_owned());
                network_state.revise(|current| *current = "online".to_owned());
                last_error.revise(|current| *current = Some(reason));
                needs_device_authorization.revise(|current| *current = false);
                device_authorization_check_complete.revise(|current| *current = false);
                account_has_other_devices.revise(|current| *current = false);
                sync_generation.revise(|current| *current = current.wrapping_add(1));
                transition_session_boot_state(
                    session_boot_state,
                    SessionBootState::Unauthenticated,
                    "session coordinator invalidated the active session",
                );
                let cleanup_generation = session_generation.get_untracked();
                let navigation = navigation.clone();
                if let Err(error) = scope.spawn(async move {
                    let result = async {
                        let _commit =
                            crate::identity::session_refresh::session_credential_mutation_lock()
                                .lock()
                                .await;
                        anyhow::ensure!(
                            session_generation.get_untracked() == cleanup_generation,
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
                            if session_generation.get_untracked() != cleanup_generation {
                                anyhow::bail!("session changed during rejected grant cleanup");
                            }
                            crate::config::clear_session_credential_secret_durable(&account)
                                .await?;
                        }
                        Ok::<_, anyhow::Error>(())
                    }
                    .await;
                    if session_generation.get_untracked() != cleanup_generation {
                        return;
                    }
                    match result {
                        Ok(()) => {
                            if let Some(context) = navigation.upgrade() {
                                context.navigate(Route::Login);
                            }
                        }
                        Err(error) => {
                            tracing::error!(%error, "rejected session cleanup failed");
                            last_error.revise(|current| *current = Some(format!(
                                "Could not remove the expired session from secure storage: {error}"
                            )));
                        }
                    }
                }) {
                    scope.report_error(error);
                }
            });
        }
    }

    let state_store = context.state_store.clone();
    scope.effect(move || {
        let _ = state_revision.get();
        let state = state_store.read(|store| store.load());
        let next = realm_tree_nodes_from_sync_realms_with_roles(
            &state.realm_tree_projections,
            &state.realm_collaboration_roles,
        );
        if realm_tree_nodes.get_untracked() != next {
            realm_tree_nodes.revise(|current| *current = next);
        }
    });

    {
        let recheck_needs_authorization = needs_device_authorization;
        let recheck_complete = device_authorization_check_complete;
        let recheck_has_other = account_has_other_devices;
        let state_store = context.state_store.clone();
        let owner = scope.downgrade();
        let recheck_context = std::rc::Rc::downgrade(&context);
        scope.effect(move || {
            let Some(scope) = owner.upgrade() else { return };
            let _ = state_revision.get();
            if !recheck_complete.get()
                || !recheck_needs_authorization.get()
                || !sync_bootstrap_complete.get()
            {
                return;
            }
            // Device pairing is approved on another device. The durable device
            // list/account-sync edge is therefore the signal to re-check the
            // exact directory signer and release MLS publication on this one.
            let cursor = sync_cursor.get();
            let session = token.get();
            let Some(actor) = active_account
                .get_untracked()
                .as_ref()
                .map(|account| account.did().clone())
            else {
                return;
            };
            let Some(account) = active_account.get_untracked().clone() else {
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
            if device_authorization_recheck_key.get().as_str() == key {
                return;
            }
            device_authorization_recheck_key.revise(|current| *current = key.clone());
            let state_store = state_store.clone();
            let expected_generation = session_generation.get_untracked();
            let expected_account = Some(account.clone());
            let recheck_context = recheck_context.clone();
            if let Err(error) = scope.spawn(async move {
                let result =
                    crate::transport::auth::with_authed_api(&base, session, |api| async move {
                        super::connect::probe_device_authorization(
                            &account,
                            &device,
                            &api,
                            &state_store,
                        )
                        .await
                    })
                    .await;
                if recheck_context.upgrade().is_none_or(|context| {
                    !context.session_matches(expected_generation, &expected_account)
                }) {
                    return;
                }
                match result {
                    Ok((needs_authorization, has_other)) => {
                        if device_authorization_recheck_attempt.get_untracked() != 0 {
                            device_authorization_recheck_attempt.revise(|current| *current = 0);
                        }
                        recheck_has_other.revise(|current| *current = has_other);
                        recheck_needs_authorization
                            .revise(|current| *current = needs_authorization);
                        recheck_complete.revise(|current| *current = true);
                    }
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            "device authorization re-check after account sync failed"
                        );
                        let attempt = device_authorization_recheck_attempt.get_untracked();
                        let retry_after_secs = (2_u64 << attempt.min(5)).min(60);
                        device_authorization_recheck_attempt
                            .revise(|current| *current = attempt.saturating_add(1).min(5));
                        crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(
                            retry_after_secs,
                        ))
                        .await;
                        // Clear only the attempt that failed. Reading this key
                        // reactively above makes the effect retry on the same
                        // durable cursor; it does not need an unrelated Realm
                        // event to recover from a transient directory error.
                        if device_authorization_recheck_key.get_untracked().as_str() == key {
                            device_authorization_recheck_key
                                .revise(|current| *current = String::new());
                        }
                    }
                }
            }) {
                scope.report_error(error);
            }
        });
    }

    let previous_authentication_active = scope.cage(false);
    let owner = scope.downgrade();
    let context = context.clone();
    scope.effect(move || {
        let Some(scope) = owner.upgrade() else { return };
        let state_store = context.state_store.clone();
        let runtime_services = context.services.clone();
        let authentication_active = route_owns_authentication(&context.route.get());
        let _ = state_revision.get();
        if authentication_active != previous_authentication_active.get_untracked() {
            previous_authentication_active.revise(|current| *current = authentication_active);
            if authentication_active {
                runtime_services.session.suspend();
                runtime_services.effects.request_cancel_all();
                let next_generation = (session_generation.get_untracked()).wrapping_add(1);
                session_generation.revise(|current| *current = next_generation);
                bootstrap_pending.revise(|current| *current = true);
                sync_bootstrap_complete.revise(|current| *current = false);
            }
        }

        let secure_store_ready = secure_store_bootstrap_ready.get();
        if should_run_connection_bootstrap(bootstrap_pending.get(), authentication_active) {
            let active = active_account.get();
            let base = active
                .as_ref()
                .map(|account| account.server_url.to_string())
                .unwrap_or_else(|| base_url.with(|store| store.clone()));
            let mut session = token.get();
            if session.trim().is_empty() && secure_store_ready {
                let loaded = config_store.with(|store| store.load());
                if let Some(rehydrated) =
                    rehydrated_session_credential_for_active_config(&loaded, active.as_ref())
                {
                    token.revise(|current| *current = rehydrated.clone());
                    session = rehydrated;
                }
            }
            if !session.trim().is_empty() {
                let stale_for_selected_server = state_store
                    .read(|store| store.session_grant())
                    .as_ref()
                    .is_some_and(|grant| {
                        !crate::identity::session_refresh::grant_matches_station(grant, &base)
                    });
                if stale_for_selected_server {
                    token.revise(|current| *current = String::new());
                    transition_session_boot_state(
                        session_boot_state,
                        SessionBootState::Unauthenticated,
                        "persisted grant belongs to another Station",
                    );
                    persist_config(
                        config_store,
                        &active_account.get_untracked(),
                        base.clone(),
                        principal_id.get(),
                        device_id.get(),
                        String::new(),
                    );
                    session.clear();
                }
            }
            let can_restore_session =
                state_store.read(|store| has_bootstrap_refresh_material(store, active.as_ref()));
            if !base.trim().is_empty()
                && secure_store_ready
                && (!session.trim().is_empty() || can_restore_session)
            {
                bootstrap_pending.revise(|current| *current = false);
                sync_bootstrap_complete.revise(|current| *current = false);
                let bootstrap_state = session_boot_state_from_bootstrap_material(
                    &session,
                    can_restore_session,
                    crate::app::principal_id_text(&principal_id.get()),
                    secure_store_ready,
                );
                transition_session_boot_state(
                    session_boot_state,
                    bootstrap_state,
                    "bootstrap material is ready for connect",
                );
                connect(
                    base,
                    principal_id.get(),
                    device_id.get(),
                    super::connect::ConnectContext::for_application(&scope, context.clone()),
                );
            } else if !base.trim().is_empty() {
                let bootstrap_state = session_boot_state_from_bootstrap_material(
                    &session,
                    can_restore_session,
                    crate::app::principal_id_text(&principal_id.get()),
                    secure_store_ready,
                );
                if session_boot_state.get_untracked() != bootstrap_state {
                    transition_session_boot_state(
                        session_boot_state,
                        bootstrap_state,
                        "secure-store bootstrap material classified",
                    );
                }
            }
        }
    });
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
