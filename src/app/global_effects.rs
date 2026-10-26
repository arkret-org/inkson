//! Global presentation preferences and authenticated maintenance owners.
use std::rc::Rc;

use glory::Scope;

use super::*;
use crate::presentation::widgets::{reactive_distinct, resource};
use crate::presentation::{InksonContext, View};

fn should_run_proactive_session_refresh(secure_store_ready: bool, credential: &str) -> bool {
    secure_store_ready && !credential.trim().is_empty()
}

pub(super) fn install(scope: &Scope, context: Rc<InksonContext>) -> View {
    let preference_context = context.clone();
    scope.effect(move || {
        let _ = preference_context.state_revision.get();
        let synced = preference_context
            .state_store
            .read(|store| store.device_pref("locale"))
            .as_deref()
            .and_then(UiLocale::from_tag);
        if let Some(synced) = synced
            && preference_context.locale.get_untracked() != synced
        {
            preference_context.locale.revise(|locale| *locale = synced);
        }
    });
    let theme_context = context.clone();
    scope.effect(move || {
        apply_document_root_theme(theme_renders_as_night(
            &theme_context.theme.get(),
            theme_context.system_theme_is_night.get(),
        ));
        #[cfg(target_arch = "wasm32")]
        if let Some(root) = web_sys::window()
            .and_then(|window| window.document())
            .and_then(|document| document.document_element())
        {
            let _ = root.set_attribute("lang", theme_context.locale.get().code());
        }
    });
    let authenticated = scope.bond({
        let context = context.clone();
        move || {
            !route_owns_authentication(&context.route.get())
                && context.secure_store_bootstrap_ready.get()
                && !context.token.get().trim().is_empty()
        }
    });
    reactive_distinct(authenticated, move |_, active| {
        if !active {
            return crate::presentation::widgets::empty();
        }
        let context = context.clone();
        Box::new(glory::ui::widget(move |scope| {
            install_authenticated(scope, context.clone());
            Ok(())
        }))
    })
}

fn install_authenticated(scope: &Scope, context: Rc<InksonContext>) {
    let secure_store_bootstrap_ready = context.secure_store_bootstrap_ready;
    let token = context.token;
    let active_account = context.active_account;
    let last_error = context.last_error;
    let admin_context = context.clone();
    let viewer = resource(scope, move || {
        let base = admin_context.base_url.get();
        let credential = admin_context.token.get();
        async move {
            let admin = crate::transport::auth::with_endpoint_clients(
                &base,
                credential,
                None,
                |clients| async move { clients.account().viewer().await },
            )
            .await
            .map(|viewer| viewer.is_server_admin)
            .unwrap_or(false);
            Ok::<_, String>(admin)
        }
    });
    let is_server_admin = context.is_server_admin;
    scope.effect(move || {
        let admin = viewer.data.get().and_then(Result::ok).unwrap_or(false);
        if is_server_admin.get_untracked() != admin {
            is_server_admin.revise(|value| *value = admin);
        }
    });
    {
        let session = context.services.session.clone();
        if let Err(error) = scope.spawn(async move {
            crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(1)).await;
            loop {
                if !should_run_proactive_session_refresh(
                    secure_store_bootstrap_ready.get_untracked(),
                    &token.get_untracked(),
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
                    crate::runtime::session::CurrentSessionRefresh::SignInRequired { reason } => {
                        last_error.revise(|current| *current = Some(reason));
                    }
                    crate::runtime::session::CurrentSessionRefresh::LoginRequired { reason } => {
                        last_error.revise(|current| *current = Some(reason));
                    }
                    crate::runtime::session::CurrentSessionRefresh::RetryLater { reason } => {
                        last_error.revise(|current| {
                            *current = Some(format!("background session refresh pending: {reason}"))
                        });
                    }
                }
                crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(
                    crate::identity::session_refresh::POLL_INTERVAL_SECS,
                ))
                .await;
            }
        }) {
            scope.report_error(error);
        }
    }
    {
        let state_store = context.state_store.clone();
        if let Err(error) = scope.spawn(async move {
            loop {
                crate::runtime_helpers::sleep_for(crate::scheduled_send::DISPATCH_POLL_INTERVAL)
                    .await;
                let session = token.get_untracked();
                if session.trim().is_empty() {
                    continue;
                }
                let Some(account) = active_account.get_untracked() else {
                    continue;
                };
                let base = account.server_url.to_string();
                let authority = account.authority;
                let store = state_store.handle();
                let tick_result = crate::transport::auth::with_event_submitter(
                    &base,
                    session,
                    |submitter| async move {
                        crate::scheduled_send::dispatch_due_scheduled_sends(
                            &submitter, &authority, &store,
                        )
                        .await
                    },
                )
                .await;
                if let Err(error) = tick_result {
                    tracing::debug!(
                        error = %error.display_diagnostic(),
                        "scheduled-send dispatch tick deferred"
                    );
                }
            }
        }) {
            scope.report_error(error);
        }
    }
    {
        let state_store = context.state_store.clone();
        if let Err(error) = scope.spawn(async move {
            loop {
                crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(30)).await;
                let session = token.get_untracked();
                if session.trim().is_empty() {
                    continue;
                }
                let Some(account) = active_account.get_untracked() else {
                    continue;
                };
                let store = state_store.handle();
                let (pending, write_pending, entries) = store.read(|state| {
                    (
                        state.pending_personal_block_sagas(),
                        state.personal_blocklist_write_pending(),
                        state.client_blocklist(),
                    )
                });
                if pending.is_empty() && !write_pending {
                    continue;
                }
                let base = account.server_url.to_string();
                let authority = account.authority;
                let result = crate::transport::auth::with_event_submitter(
                    &base,
                    session,
                    |submitter| async move {
                        if write_pending {
                            crate::transport::account::persist_personal_block_saga(
                                &submitter, &authority, &store, &entries,
                            )
                            .await
                            .map(|_| ())
                        } else {
                            crate::transport::account::resume_personal_block_contact_sagas(
                                submitter.http(),
                                &store,
                                &entries,
                            )
                            .await
                        }
                    },
                )
                .await;
                if let Err(error) = result {
                    tracing::debug!(
                        error = %error.display_diagnostic(),
                        "personal block saga retry deferred"
                    );
                }
            }
        }) {
            scope.report_error(error);
        }
    }
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
