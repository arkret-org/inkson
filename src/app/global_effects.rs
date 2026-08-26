use super::*;

fn should_run_proactive_session_refresh(secure_store_ready: bool, credential: &str) -> bool {
    secure_store_ready && !credential.trim().is_empty()
}

/// Application-wide effects whose lifecycle is the mounted session shell.
/// Route surfaces only consume their projections and never depend on the
/// order in which these effects were registered.
#[component]
pub(super) fn GlobalEffects(
    mut locale: Signal<UiLocale>,
    mut i18n_signal: crate::i18n::I18nSignal,
    base_url: Signal<String>,
    token: Signal<String>,
    state_store: SyncSignal<LocalStateStore>,
    mut last_error: Signal<Option<String>>,
    secure_store_bootstrap_ready: Signal<bool>,
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
            .and_then(UiLocale::from_tag)
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

    // Proactive rotation is steady-state maintenance only. Cold-boot restore
    // is owned by SecureStoreEffects + ConnectionEffects. In particular, an
    // empty token is a stable signed-out state after secure storage settles;
    // it must never be rewritten to Restoring on every poll tick.
    use_future({
        let session = runtime_services.session.clone();
        move || {
            let session = session.clone();
            async move {
                crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(1)).await;
                loop {
                    if !should_run_proactive_session_refresh(
                        secure_store_bootstrap_ready(),
                        &token(),
                    ) {
                        crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(
                            crate::identity::session_refresh::POLL_INTERVAL_SECS,
                        ))
                        .await;
                        continue;
                    }
                    match session.refresh().await {
                        crate::runtime::session::CurrentSessionRefresh::Credential(_) => {
                            // connect() owns Checking -> Authenticated. A
                            // maintenance refresh must not declare bootstrap
                            // complete or navigate while connect is in flight.
                        }
                        crate::runtime::session::CurrentSessionRefresh::SignInRequired {
                            reason,
                        } => {
                            last_error.set(Some(reason));
                        }
                        crate::runtime::session::CurrentSessionRefresh::LoginRequired {
                            reason,
                        } => {
                            last_error.set(Some(reason));
                        }
                        crate::runtime::session::CurrentSessionRefresh::RetryLater { reason } => {
                            last_error.set(Some(format!(
                                "background session refresh pending: {reason}"
                            )));
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

#[cfg(test)]
mod tests {
    use super::should_run_proactive_session_refresh;

    #[test]
    fn proactive_refresh_never_turns_a_signed_out_browser_into_restore() {
        assert!(!should_run_proactive_session_refresh(false, ""));
        assert!(!should_run_proactive_session_refresh(true, ""));
        assert!(!should_run_proactive_session_refresh(true, "   "));
        assert!(should_run_proactive_session_refresh(true, "sx:live"));
    }
}
