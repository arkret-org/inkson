//! Explicit logout uses exact saved-account scopes and durable revocation journals.
use std::rc::Rc;

use glory::Cage;

use crate::config::ActiveAccountContext;
use crate::pending_logout::PendingLogout;
use crate::presentation::InksonContext;
use crate::secure_key_store::{SecureKeyStore, UserLocalStore};
use crate::state::{LocalStateStore, PersistedSessionGrant};

pub(super) fn logout(context: Rc<InksonContext>, status: Cage<String>) {
    start_logout(context, status, false);
}

pub(super) fn logout_all(context: Rc<InksonContext>, status: Cage<String>) {
    start_logout(context, status, true);
}

fn start_logout(context: Rc<InksonContext>, status: Cage<String>, all: bool) {
    if context.account_busy.get_untracked() {
        return;
    }
    context.account_busy.revise(|value| *value = true);
    context.account_error.revise(|value| *value = None);
    context.last_error.revise(|value| *value = None);
    status.revise(|value| *value = context.tr("app.account.signing_out"));
    let task_context = context.clone();
    if let Err(error) = context.spawn(async move {
        if let Err(error) = perform_logout(task_context.clone(), all).await {
            tracing::warn!(%error, "account logout did not complete");
            task_context.account_busy.revise(|value| *value = false);
            if task_context.account_view_retired.get_untracked() {
                task_context.account_blocked.revise(|value| *value = true);
                super::account_switch::AccountSessionRoot::from_context(task_context.clone())
                    .remount();
                super::connect::redirect_to_login(task_context.as_ref());
            }
            task_context
                .account_error
                .revise(|value| *value = Some(task_context.tr("app.account.sign_out_failed")));
            task_context
                .last_error
                .revise(|value| *value = Some(task_context.tr("app.account.sign_out_failed")));
        }
    }) {
        tracing::warn!(%error, "account logout could not start");
        context.account_busy.revise(|value| *value = false);
        context
            .last_error
            .revise(|value| *value = Some(context.tr("app.account.sign_out_failed")));
    }
}

async fn journal_accounts(
    accounts: &[ActiveAccountContext],
    active: &ActiveAccountContext,
    active_grant: Option<PersistedSessionGrant>,
    secure: &dyn SecureKeyStore,
) -> anyhow::Result<Vec<PendingLogout>> {
    let mut records = Vec::new();
    for account in accounts {
        let user = UserLocalStore::new(account.authority.clone(), account.device_id.clone())?;
        let grant = match user.load_secret(secure, LocalStateStore::SECURE_SESSION_GRANT_KEY)? {
            Some(raw) => Some(serde_json::from_str::<PersistedSessionGrant>(&raw)?),
            None if account.authority == active.authority
                && account.device_id == active.device_id =>
            {
                active_grant.clone()
            }
            None => None,
        };
        if let Some(grant) = &grant {
            anyhow::ensure!(
                grant.account_id == account.authority && grant.device_id == account.device_id,
                "saved grant belongs to a different account/device"
            );
        }
        let holder =
            crate::identity::account_auth::grant_dpop::load_user_device_key_with_secure_store(
                &user, secure,
            )?;
        if grant.is_none() && account.authority != active.authority {
            continue;
        }
        let record = PendingLogout {
            authority: account.authority.clone(),
            device_id: account.device_id.clone(),
            grant_jwt: grant.as_ref().map(|grant| grant.grant_jwt.clone()),
            device_seed_b64: holder
                .as_ref()
                .map(|holder| holder.seed_b64().as_str().to_owned()),
            device_jkt: holder.as_ref().map(|holder| holder.jkt().to_owned()),
            station_url: grant.as_ref().map(|grant| grant.station_url.clone()),
            gate_account_base_url: None,
            base_url: account.server_url.clone(),
            session_credential: String::new(),
            principal_id: account.principal_id().clone(),
            created_at: chrono::Utc::now(),
        };
        crate::pending_logout::persist_pending_logout_durable(&record, secure).await?;
        records.push(record);
    }
    Ok(records)
}

async fn clear_account_sessions(
    accounts: &[ActiveAccountContext],
    secure: &dyn SecureKeyStore,
) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    for account in accounts {
        let user = UserLocalStore::new(account.authority.clone(), account.device_id.clone())?;
        // Attempt every selected account even when one backend write fails.
        for key in [
            LocalStateStore::SECURE_SESSION_GRANT_KEY,
            LocalStateStore::SECURE_DPOP_DEVICE_KEY,
        ] {
            if let Err(error) = user.delete_secret_durable(secure, key).await {
                errors.push(error.to_string());
            }
        }
        if let Err(error) = user.delete_grant_binding_seed_durable(secure).await {
            errors.push(error.to_string());
        }
        if let Err(error) = crate::config::clear_session_credential_secret_durable(account).await {
            errors.push(error.to_string());
        }
    }
    anyhow::ensure!(
        errors.is_empty(),
        "one or more session stores could not be cleared: {}",
        errors.join("; ")
    );
    Ok(())
}

async fn perform_logout(context: Rc<InksonContext>, all: bool) -> anyhow::Result<()> {
    let active = context
        .active_account
        .get_untracked()
        .ok_or_else(|| anyhow::anyhow!("active account context is unavailable"))?;
    let profiles = context
        .config_store
        .with(|store| store.load_profile_metadata())?;
    let mut accounts: Vec<_> = if all {
        profiles
            .profiles
            .iter()
            .map(|profile| profile.account.clone())
            .collect()
    } else {
        Vec::new()
    };
    if !accounts.iter().any(|account| {
        account.authority == active.authority && account.device_id == active.device_id
    }) {
        accounts.push(active.clone());
    }
    let next = (!all)
        .then(|| {
            profiles
                .profiles
                .iter()
                .find(|profile| profile.account.profile_id != active.profile_id)
                .map(|profile| profile.account.profile_id.clone())
        })
        .flatten();
    let mut root = super::account_switch::AccountSessionRoot::from_context(context.clone());
    root.retire();
    context.services.effects.cancel_all().await;
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    let active_grant = context.state_store.read(|store| store.session_grant());
    let records = match journal_accounts(&accounts, &active, active_grant, secure.as_ref()).await {
        Ok(records) => records,
        Err(error) => {
            context.account_busy.revise(|value| *value = false);
            root.remount();
            return Err(error);
        }
    };
    let retry_secure = secure.clone();
    context.spawn(async move {
        for record in records {
            let _ =
                crate::pending_logout::execute_pending_logout(&record, retry_secure.as_ref()).await;
        }
    })?;
    let cleared = clear_account_sessions(&accounts, secure.as_ref()).await;
    context
        .state_store
        .write(|store| store.clear_session_memory_for_logout());
    let flush = context
        .state_store
        .read(|store| store.begin_durable_flush())?;
    flush.wait().await?;
    context
        .config_store
        .revise(|store| store.save_account_selection(Some(active.clone()), &profiles))?;
    context.profiles.revise(|profiles| {
        for profile in &mut profiles.profiles {
            if accounts.iter().any(|account| {
                account.authority == profile.account.authority
                    && account.device_id == profile.account.device_id
            }) {
                profile.session_credential.clear();
            }
        }
    });
    let _ = crate::identity::account_auth::clear_all_persisted_oidc_scaffolds();
    context.device_queue.revise(|value| *value = 0);
    context.token.revise(String::clear);
    context.account_busy.revise(|value| *value = false);
    super::transition_session_boot_state(
        context.session_boot_state,
        super::SessionBootState::Unauthenticated,
        "user signed out",
    );
    if let Err(error) = cleared {
        context.account_blocked.revise(|value| *value = true);
        root.remount();
        super::connect::redirect_to_login(context.as_ref());
        return Err(error);
    }
    if let Some(next) = next {
        if let Err(error) = root.clone().select_profile(next).await {
            tracing::warn!(%error, "signed out; the next saved account could not be restored");
            root.remount();
            super::connect::redirect_to_login(context.as_ref());
        } else {
            context.navigate(crate::routes::Route::Dashboard);
        }
    } else {
        root.remount();
        super::connect::redirect_to_login(context.as_ref());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
