//! Explicit account commands retain durable logout intent until acknowledged.
use std::rc::Rc;

use glory::Cage;

use crate::presentation::InksonContext;

pub(super) fn logout(context: Rc<InksonContext>, status: Cage<String>) {
    let Some(active) = context.active_account.get() else {
        context
            .last_error
            .revise(|value| *value = Some("active account context is unavailable".into()));
        return;
    };
    let token = context.token.get();
    let grant = context.state_store.read(|store| store.session_grant());
    let handle = context
        .state_store
        .write(|store| crate::identity::account_auth::grant_dpop::ensure_device_key(store).ok());
    let pending = crate::pending_logout::PendingLogout {
        authority: active.authority.clone(),
        device_id: active.device_id.clone(),
        grant_jwt: grant.as_ref().map(|grant| grant.grant_jwt.clone()),
        device_seed_b64: handle
            .as_ref()
            .map(|handle| handle.seed_b64().as_str().to_owned()),
        device_jkt: handle.as_ref().map(|handle| handle.jkt().to_owned()),
        station_url: grant.as_ref().map(|grant| grant.station_url.clone()),
        gate_account_base_url: None,
        base_url: active.server_url.clone(),
        session_credential: token,
        principal_id: active.principal_id().clone(),
        created_at: chrono::Utc::now(),
    };
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    if let Err(error) = crate::pending_logout::persist_pending_logout(&pending, secure.as_ref()) {
        tracing::warn!(?error, "failed to journal pending logout");
    }
    status.revise(|value| *value = "Logging out".into());
    context
        .session_generation
        .revise(|value| *value = value.wrapping_add(1));
    context.services.effects.request_cancel_all();
    context
        .state_store
        .write(|store| store.clear_session_scoped_for_logout());
    let _ = crate::identity::account_auth::clear_all_persisted_oidc_scaffolds();
    context.clear_account_projections();
    context.device_queue.revise(|value| *value = 0);
    context.last_error.revise(|value| *value = None);
    context.token.revise(String::clear);
    crate::config::clear_session_credential_secret(&active);
    crate::views::helpers::persist_config(
        context.config_store,
        &Some(active.clone()),
        active.server_url.to_string(),
        Some(active.principal_id().clone()),
        active.device_id.to_string(),
        String::new(),
    );
    super::transition_session_boot_state(
        context.session_boot_state,
        super::SessionBootState::Unauthenticated,
        "user logged out",
    );
    context
        .sync_generation
        .revise(|value| *value = value.wrapping_add(1));
    super::connect::redirect_to_login(context.as_ref());
    let effects = context.services.effects.clone();
    // The application owns completion after the authenticated shell retires.
    if let Err(error) = context.spawn(async move {
        effects.cancel_all().await;
        let _ = crate::pending_logout::execute_pending_logout(&pending, secure.as_ref()).await;
    }) {
        tracing::warn!(%error, "logout intent remains journaled until the next application session");
    }
}
