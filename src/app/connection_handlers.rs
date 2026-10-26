use std::rc::Rc;

use glory::prelude::*;

use super::*;
use crate::api_error::is_auth_expired_error;
use crate::presentation::InksonContext;

pub(super) fn refresh_connection(_scope: &Scope, context: Rc<InksonContext>) {
    refresh_connection_using(context, connect);
}
pub(super) fn refresh_connection_using(
    context: Rc<InksonContext>,
    connector: impl FnOnce(String, Option<arkret_sdk::DidCoreId>, String, ConnectContext),
) {
    let Some(owner) = context.state_scope() else {
        return;
    };
    context
        .sync_generation
        .revise(|value| *value = value.wrapping_add(1));
    context
        .sync_bootstrap_complete
        .revise(|value| *value = false);
    connector(
        context.base_url.get(),
        context.principal_id.get(),
        context.device_id.get(),
        ConnectContext::for_application(&owner, context),
    );
}
pub(super) fn switch_server_and_connect(scope: &Scope, next: String, context: Rc<InksonContext>) {
    let next = normalize_server_url(&next);
    if !same_server_url(&context.base_url.get(), &next) {
        select_server(next, context.clone());
    }
    refresh_connection(scope, context);
}
#[derive(Clone)]
pub(super) struct ManualSessionRefreshContext {
    pub context: Rc<InksonContext>,
    pub account_session_state: Cage<String>,
    pub personal_handles_lookup_key: Cage<String>,
    pub account_identity_lookup_key: Cage<String>,
}
fn session_refresh_feedback(state: Cage<String>, message: impl Into<String>) {
    let message = message.into();
    let _ = state.try_revise(|value| *value = message);
}
pub(super) fn refresh_current_session(
    scope: &glory::Scope,
    base: String,
    ctx: ManualSessionRefreshContext,
) {
    let Some(window) = ctx.context.state_scope() else {
        return;
    };
    let api_token = ctx.context.token.get();
    let actor = ctx.context.principal_id.get();
    let Some(active) = ctx.context.active_account.get() else {
        let account_session_state = ctx.account_session_state;
        session_refresh_feedback(
            account_session_state,
            "Session identity is unavailable; sign in again.",
        );
        return;
    };
    let personal_handles_lookup_key = ctx.personal_handles_lookup_key;
    let account_identity_lookup_key = ctx.account_identity_lookup_key;
    let account_session_state = ctx.account_session_state;
    personal_handles_lookup_key.revise(|value| *value = String::new());
    account_identity_lookup_key.revise(|value| *value = String::new());
    session_refresh_feedback(account_session_state, "Refreshing session");
    let generation = ctx.context.session_generation.get();
    let owner = window.downgrade();
    if let Err(error) = window.spawn(async move {
        let principal_id = ctx.context.principal_id;
        let last_error = ctx.context.last_error;
        let account_primary_handle = ctx.context.account_primary_handle;
        let personal_handles = ctx.context.personal_handles;
        let personal_handles_status = ctx.context.personal_handles_status;
        match self_authed_api(&base, api_token.clone()) {
            Ok(api) => {
                match async { crate::transport::account::account_me(&api.sdk_http_client()?).await }
                    .await
                {
                    Ok(account) => {
                        if owner.upgrade().is_none() || !ctx.context.session_matches(generation, &Some(active.clone())) { return; }
                        let canonical_principal = match ctx.context.active_account.get_untracked().as_ref() {
                            Some(context) if context.principal_id() == &account.principal_id => {
                                Some(context.principal_id().clone())
                            }
                            _ => {
                                last_error.revise(|value| *value = Some(
                                "account viewer authority does not match the accepted active context"
                                    .to_owned(),
                            ));
                                session_refresh_feedback(account_session_state,"Session identity could not be restored; sign in again.");
                                return;
                            }
                        };
                        if let Some(personal_handle) =
                            personal_handle_from_account_handle(&account.handle)
                        {
                            account_primary_handle.revise(|value| *value = personal_handle.clone());
                            let handles =
                                merge_personal_handles(&personal_handles.get(), [personal_handle]);
                            personal_handles_status.revise(|value| *value = personal_handles_status_for(&handles));
                            personal_handles.revise(|value| *value = handles);
                        } else {
                            account_primary_handle.revise(|value| *value = String::new());
                            if personal_handles.get().is_empty() {
                                personal_handles_status.revise(|value| *value = "Not published".to_owned());
                            }
                        }
                        principal_id.revise(|value| *value = canonical_principal.clone());
                        persist_config(
                            ctx.context.config_store,
                            &Some(active.clone()),
                            active.server_url.to_string(),
                            Some(active.principal_id().clone()),
                            active.device_id.to_string(),
                            api_token,
                        );
                        session_refresh_feedback(account_session_state,format!(
                            "Session refresh ok: {}",
                            crate::app::principal_id_text(&canonical_principal)
                        ));
                    }
                    Err(error) => {
                        if owner.upgrade().is_none() || !ctx.context.session_matches(generation, &Some(active.clone())) { return; }
                        if is_auth_expired_error(&error) {
                            let refreshed=ctx.context.services.session.refresh().await;
                            if owner.upgrade().is_none() || !ctx.context.session_matches(generation,&Some(active.clone())) {return;}
                            match refreshed {
                            crate::runtime::session::CurrentSessionRefresh::Credential(fresh) => {
                                let canonical_principal = match self_authed_api(&base, fresh) {
                                    Ok(api) => async {
                                        crate::transport::account::account_me(&api.sdk_http_client()?)
                                            .await
                                    }
                                    .await
                                    .ok()
                                    .and_then(|account| {
                                        if owner.upgrade().is_none() || !ctx.context.session_matches(generation,&Some(active.clone())) { return None; }
                                        ctx.context.active_account
                                            .get_untracked()
                                            .as_ref()
                                            .filter(|context| {
                                                context.principal_id() == &account.principal_id
                                            })?;
                                        if let Some(personal_handle) =
                                            personal_handle_from_account_handle(&account.handle)
                                        {
                                            account_primary_handle.revise(|value| *value = personal_handle.clone());
                                            let handles = merge_personal_handles(
                                                &personal_handles.get(),
                                                [personal_handle],
                                            );
                                            personal_handles_status.revise(|value|*value=personal_handles_status_for(&handles));
                                            personal_handles.revise(|value| *value = handles);
                                        } else {
                                            account_primary_handle.revise(|value| *value = String::new());
                                            if personal_handles.get().is_empty() {
                                                personal_handles_status.revise(|value|*value="Not published".to_owned());
                                            }
                                        }
                                        Some(active.principal_id().clone())
                                    }),
                                    Err(_) => None,
                                }
                                .or(actor.clone());
                                if owner.upgrade().is_none() || !ctx.context.session_matches(generation,&Some(active.clone())) {return;}
                                principal_id.revise(|value| *value = canonical_principal.clone());
                                session_refresh_feedback(account_session_state,format!(
                                    "Session refresh ok: {}",
                                    crate::app::principal_id_text(&canonical_principal)
                                ));
                            }
                            crate::runtime::session::CurrentSessionRefresh::SignInRequired {
                                reason,
                            } => {
                                last_error.revise(|value| *value = Some(reason));
                                session_refresh_feedback(account_session_state,"Sign in again to refresh this session.");
                            }
                            crate::runtime::session::CurrentSessionRefresh::LoginRequired {
                                reason,
                            } => {
                                last_error.revise(|value| *value = Some(reason));
                                session_refresh_feedback(account_session_state,"Session expired. Sign in again.");
                            }
                            crate::runtime::session::CurrentSessionRefresh::RetryLater {
                                reason,
                            } => {
                                session_refresh_feedback(account_session_state,format!("Session refresh pending: {reason}"));
                            }
                        }
                        } else {
                            session_refresh_feedback(account_session_state,format!("Session refresh failed: {error}"));
                        }
                    }
                }
            }
            Err(error) => session_refresh_feedback(account_session_state,format!("Invalid server URL: {error}")),
        }
    }) { scope.report_error(error); }
}
