//! Owner-scoped shell projection and identity work.
use std::rc::Rc;

use glory::prelude::*;

use super::shell_state::ShellState;
use super::*;
use crate::presentation::InksonContext;
use crate::presentation::widgets::resource;
fn set_state<T: 'static>(state: Cage<T>, value: T) {
    let _ = state.try_revise(|current| *current = value);
}
pub(super) fn install(scope: &Scope, context: Rc<InksonContext>, ui: Rc<ShellState>) {
    let base_url = context.base_url;
    let session_generation = context.session_generation;
    let active_account = context.active_account;
    let token = context.token;
    let principal_id = context.principal_id;
    let device_id = context.device_id;
    let account_primary_handle = context.account_primary_handle;
    let personal_handles = context.personal_handles;
    let personal_handles_status = context.personal_handles_status;
    let current_account_display_name = ui.display_name;
    let current_account_avatar_blob_ref = ui.avatar;
    let current_device_display_name = ui.device_name;
    let account_identity_lookup_key = ui.identity_key;
    let direct_contact_rows = context.contact_rows;
    let did_resolution_health = context.did_resolution_health;
    let state_store = context.state_store.clone();
    let identity_store = context.state_store.clone();
    let handle_mirror_store = context.state_store.clone();
    let sound_store = context.state_store.clone();
    let weak_identity = scope.downgrade();
    let identity_context = context.clone();
    let revision = context.state_revision;
    // Recheck failed bootstrap probes independently of session refresh. A
    // successful probe clears the banner without logging out or reloading.
    resource(scope, move || {
        let base = base_url.get();
        let generation = session_generation.get();
        async move {
            loop {
                crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(15)).await;
                if did_resolution_health.get_untracked()
                    == crate::components::DidResolutionHealth::Healthy
                {
                    continue;
                }
                let probe = async {
                    let api = crate::transport::TransportClient::unauthenticated(&base)?;
                    crate::transport::account::identity_describe(&api.sdk_http_client()?).await
                };
                let result = tokio::select! {
                    result = probe => result,
                    _ = crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(12)) =>
                        Err(anyhow::anyhow!("identity describe probe timed out")),
                };
                if base_url.get_untracked() != base
                    || session_generation.get_untracked() != generation
                {
                    return Ok(());
                }
                did_resolution_health.revise(|value| {
                    *value = match result {
                        Ok(description) => {
                            crate::components::DidResolutionHealth::from_identity_description(
                                &description,
                            )
                        }
                        Err(error) => {
                            crate::components::DidResolutionHealth::from_probe_error(&error)
                        }
                    }
                });
            }
            #[allow(unreachable_code)]
            Ok(())
        }
    });

    // Contact requests are read from the account contact projection, not the
    // Realm invite notification carrier. Keep this inbox live even when the
    // Contacts sidebar has never been opened. A session change cancels the
    // resource and fences responses from the previous account.
    resource(scope, move || {
        let account = active_account.get().map(|account| account.authority);
        let api_token = token.get();
        let base = base_url.get();
        let generation = session_generation.get();
        let state_store = state_store.clone();
        async move {
            direct_contact_rows.revise(|value| *value = Vec::new());
            if account.is_none() || api_token.trim().is_empty() {
                return Ok(());
            }
            loop {
                let result = crate::transport::auth::with_authed_sdk_client(
                    &base,
                    api_token.clone(),
                    |http| async move { crate::transport::account::contacts(&http).await },
                )
                .await;
                if session_generation.get_untracked() != generation
                    || active_account
                        .get_untracked()
                        .as_ref()
                        .map(|account| &account.authority)
                        != account.as_ref()
                    || base_url.get_untracked() != base
                    || token.get_untracked() != api_token
                {
                    return Ok(());
                }
                match result {
                    Ok(response) => {
                        state_store.write(|store| {
                            store.replace_accepted_human_contacts(&response.contacts)
                        });
                        direct_contact_rows.revise(|value| *value = response.contacts);
                    }
                    Err(error) => {
                        tracing::warn!(error = %error.display_diagnostic(), "contact inbox refresh failed")
                    }
                }
                crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(15)).await;
            }
            #[allow(unreachable_code)]
            Ok(())
        }
    });

    // Account-viewer is the authoritative source for the Actor Profile,
    // device display_name, and signed primary handle claim. Keep those
    // user-facing labels separate from protocol IDs and from the Account
    // Authority handoff's unsigned account_handle hint.
    scope.effect(move || {
        let lookup_base_url = base_url.get();
        let lookup_actor = crate::app::principal_id_owned(principal_id.get());
        let lookup_device = device_id.get();
        let lookup_token = token.get();
        let key = format!(
            "{}|{}|{}|{}",
            lookup_base_url,
            lookup_actor,
            lookup_device,
            !lookup_token.trim().is_empty(),
        );
        if account_identity_lookup_key.get() == key {
            return;
        }
        account_identity_lookup_key.revise(|value| *value = key);
        if lookup_token.trim().is_empty() || lookup_actor.trim().is_empty() {
            current_account_display_name.revise(|value| *value = String::new());
            current_account_avatar_blob_ref.revise(|value| *value = String::new());
            current_device_display_name.revise(|value| *value = String::new());
            return;
        }

        // Never keep the previous account's labels visible while a new
        // account/device lookup is in flight (or if that lookup fails).
        current_account_display_name.revise(|value| *value = String::new());
        current_account_avatar_blob_ref.revise(|value| *value = String::new());
        current_device_display_name.revise(|value| *value = String::new());
        account_primary_handle.revise(|value| *value = String::new());
        personal_handles.revise(|value| *value = Vec::new());
        personal_handles_status.revise(|value| *value = "Loading handles".to_owned());
        identity_store.write(|store| store.set_primary_handle_for_principal_id(&lookup_actor, ""));

        let base = lookup_base_url;
        let actor = lookup_actor;
        let device = lookup_device;
        let handle_store = identity_store.clone();
        let weak = weak_identity.clone();
        let generation = session_generation.get_untracked();
        let account = active_account.get_untracked();
        let application = identity_context.clone();
        let Some(owner) = weak.upgrade() else {
            return;
        };
        let _ = owner.spawn(async move {
            let result = crate::transport::auth::with_authed_sdk_client(
                &base,
                lookup_token,
                |http| async move { crate::transport::keys::list_devices(&http).await },
            )
            .await;
            if weak.upgrade().is_none() || !application.session_matches(generation, &account) {
                return;
            }
            let Ok(viewer) = result else {
                return;
            };
            // Ignore a late response from the previous account.
            if crate::app::principal_id_text(&principal_id.get()) != actor.trim() {
                return;
            }
            let display_name = viewer
                .profile
                .as_ref()
                .map(|profile| profile.display_name.trim().to_owned())
                .unwrap_or_default();
            let avatar_blob_ref = viewer
                .profile
                .as_ref()
                .and_then(|profile| profile.avatar_blob_ref.as_ref())
                .map(ToString::to_string)
                .unwrap_or_default();
            let device_display_name = viewer
                .devices
                .iter()
                .find(|summary| summary.device_id.as_str() == device.trim())
                .and_then(|summary| summary.display_name.as_deref())
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(ToOwned::to_owned)
                .unwrap_or_default();
            let primary_handle = crate::transport::account::primary_handle_from_viewer(&viewer);
            handle_store
                .write(|store| store.set_primary_handle_for_principal_id(&actor, &primary_handle));
            set_state(current_account_display_name, display_name);
            set_state(current_account_avatar_blob_ref, avatar_blob_ref);
            set_state(current_device_display_name, device_display_name);
            if !primary_handle.is_empty() {
                set_state(account_primary_handle, primary_handle.clone());
                set_state(
                    personal_handles_status,
                    personal_handles_status_for(std::slice::from_ref(&primary_handle)),
                );
                set_state(personal_handles, vec![primary_handle]);
            }
        });
    });

    scope.effect(move || {
        let handle = account_primary_handle.get();
        let account = crate::app::principal_id_owned(principal_id.get());
        if handle.trim().is_empty() || account.trim().is_empty() {
            return;
        }
        handle_mirror_store
            .write(|store| store.set_primary_handle_for_principal_id(&account, &handle));
    });

    let previous_unread_notification_count = scope.cage(Option::<usize>::None);
    scope.effect(move || {
        let _ = revision.get();
        let store = sound_store.read(|store| {
            (
                unread_notification_count(&store.load()),
                crate::notification_sound::notification_sound_enabled(store),
            )
        });
        let unread = store.0;
        let sound_enabled = store.1;
        let previous = previous_unread_notification_count.get_untracked();
        if crate::notification_sound::should_play_notification_sound(
            previous,
            unread,
            sound_enabled,
        ) {
            crate::notification_sound::play_notification_sound();
        }
        if previous != Some(unread) {
            previous_unread_notification_count.revise(|value| *value = Some(unread));
        }
    });

    let weak = scope.downgrade();
    scope.effect({
        let context = context.clone();
        let ui = ui.clone();
        move || {
            let _ = context.owned_agents_rev.get();
            let base = context.base_url.get();
            let token = context.token.get();
            if let Some(scope) = weak.upgrade() {
                load_own_agents_for_sidebar(
                    &scope,
                    context.clone(),
                    base,
                    token,
                    ui.agents,
                    ui.agents_loaded,
                );
            }
        }
    });
    let last = scope.cage(None::<String>);
    scope.effect(move || {
        match context.call_signal_hub.incoming_call.get() {
            Some(info)
                if crate::views::call::media_route_adapter_available()
                    && last.get_untracked().as_deref() != Some(info.call_id.as_str()) =>
            {
                last.revise(|value| *value = Some(info.call_id.clone()));
                context.navigate(Route::Call {
                    call_id: info.call_id,
                    peer: info.peer_actor,
                    realm_id: info.realm_id,
                    video: if info.video { "1" } else { "0" }.into(),
                    incoming: "1".into(),
                });
            }
            None => last.revise(|value| *value = None),
            _ => {}
        }
        if matches!(context.route.get(), Route::Recovery) {
            context.replace_route(Route::SettingsRecovery);
        }
    });
}
