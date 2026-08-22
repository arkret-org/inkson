use super::*;

/// Application-wide effects whose lifecycle is the mounted session shell.
/// Route surfaces only consume their projections and never depend on the
/// order in which these effects were registered.
#[component]
pub(super) fn GlobalEffects(
    mut locale: Signal<Locale>,
    mut i18n_signal: crate::i18n::I18nSignal,
    base_url: Signal<String>,
    token: Signal<String>,
    state_store: SyncSignal<LocalStateStore>,
    mut connection_status: Signal<String>,
    mut last_error: Signal<Option<String>>,
    mut session_boot_state: Signal<SessionBootState>,
    mut is_server_admin: Signal<bool>,
    theme: Signal<String>,
    mut system_theme_is_night: Signal<bool>,
) -> Element {
    let runtime_services = use_context::<crate::runtime::services::RuntimeServices>();
    let active_account = crate::app::SessionContext::get().active_account;

    use_effect(move || {
        crate::i18n::set_locale(&mut i18n_signal, locale());
    });

    // The `language` field of the `ak.client.ui_state` account-data cell lands
    // in the device preference
    // (see `connect.rs`), which is the one place both the running shell and a
    // cold boot read. Observing it here is what turns "another device changed
    // the language" into a live switch rather than something the user sees
    // only after a restart.
    use_effect(move || {
        let Some(synced) = state_store
            .read()
            .device_pref("locale")
            .as_deref()
            .and_then(Locale::from_tag)
        else {
            return;
        };
        if *locale.peek() != synced {
            locale.set(synced);
        }
    });

    let viewer_admin = use_resource(move || {
        let base = base_url();
        let session = token();
        async move {
            if session.trim().is_empty() {
                return false;
            }
            crate::transport::auth::with_endpoint_clients(
                &base,
                session,
                None,
                |clients| async move { clients.account().viewer().await },
            )
            .await
            .map(|viewer| viewer.is_server_admin)
            .unwrap_or(false)
        }
    });
    use_effect(move || {
        let resolved = viewer_admin().unwrap_or(false);
        if *is_server_admin.peek() != resolved {
            is_server_admin.set(resolved);
        }
    });

    use_effect(move || {
        if theme() == "system"
            && let Some(is_night) = browser_shell_color_scheme_is_dark()
        {
            system_theme_is_night.set(is_night);
        }
    });
    use_effect(move || {
        let resolved_night = theme_renders_as_night(&theme(), system_theme_is_night());
        apply_document_root_theme(resolved_night);
    });

    // Proactive rotation shares the root session coordinator with reactive
    // request retries, so only one refresh can be in flight for a generation.
    use_future({
        let session = runtime_services.session.clone();
        move || {
            let session = session.clone();
            async move {
                crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(1)).await;
                loop {
                    if token().trim().is_empty() {
                        connection_status.set("Restoring session...".to_owned());
                        session_boot_state.set(SessionBootState::Restoring);
                    }
                    match session.refresh().await {
                        crate::runtime::session::CurrentSessionRefresh::Credential(_) => {
                            connection_status.set("Online".to_owned());
                            session_boot_state.set(SessionBootState::Authenticated);
                            last_error.set(None);
                        }
                        crate::runtime::session::CurrentSessionRefresh::SignInRequired {
                            reason,
                        } => {
                            last_error.set(Some(reason));
                            if token().trim().is_empty() {
                                connection_status
                                    .set("Session could not be restored; sign in again".to_owned());
                                session_boot_state.set(SessionBootState::Unauthenticated);
                            }
                        }
                        crate::runtime::session::CurrentSessionRefresh::LoginRequired {
                            reason,
                        } => {
                            last_error.set(Some(reason));
                            if token().trim().is_empty() {
                                connection_status.set("Session expired; sign in again".to_owned());
                                session_boot_state.set(SessionBootState::Unauthenticated);
                            }
                        }
                        crate::runtime::session::CurrentSessionRefresh::RetryLater { reason } => {
                            last_error.set(Some(format!(
                                "background session refresh pending: {reason}"
                            )));
                            if token().trim().is_empty() {
                                connection_status.set(
                                    "Session restore is unavailable; sign in again".to_owned(),
                                );
                                session_boot_state.set(SessionBootState::Unauthenticated);
                            }
                        }
                    }
                    crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(
                        crate::identity::session_refresh::POLL_INTERVAL_SECS,
                    ))
                    .await;
                }
            }
        }
    });

    // Scheduled-send expiry trigger (spec `models/personal-productivity.md`
    // §4): while a session is live, periodically scan the locally staged
    // `ak.scheduled_send.v1` plans and drive every due one through the durable
    // freeze-then-submit dispatch boundary.
    use_future({
        move || async move {
            loop {
                crate::runtime_helpers::sleep_for(crate::scheduled_send::DISPATCH_POLL_INTERVAL)
                    .await;
                let session = token();
                if session.trim().is_empty() {
                    continue;
                }
                let Some(account) = active_account() else {
                    continue;
                };
                let base = account.server_url.to_string();
                let authority = account.authority;
                if let Err(error) = crate::transport::auth::with_event_submitter(
                    &base,
                    session,
                    |submitter| async move {
                        crate::scheduled_send::dispatch_due_scheduled_sends(
                            &submitter,
                            &authority,
                            state_store,
                        )
                        .await
                    },
                )
                .await
                {
                    tracing::debug!(
                        error = %error.display_diagnostic(),
                        "scheduled-send dispatch tick deferred"
                    );
                }
            }
        }
    });

    rsx! {}
}
