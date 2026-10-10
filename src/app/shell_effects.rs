use super::*;

#[derive(Clone, Copy, PartialEq)]
pub(super) struct ShellEffectState {
    pub account_primary_handle: Signal<String>,
    pub principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    pub token: Signal<String>,
    pub personal_handles: Signal<Vec<String>>,
    pub personal_handles_status: Signal<String>,
    pub personal_handles_lookup_key: Signal<String>,
    pub device_id: Signal<String>,
    pub current_account_display_name: Signal<String>,
    pub current_account_avatar_blob_ref: Signal<String>,
    pub current_device_display_name: Signal<String>,
    pub account_identity_lookup_key: Signal<String>,
    pub contact_handles_lookup_key: Signal<String>,
    pub contact_handles_fetching: Signal<BTreeSet<String>>,
    pub direct_contact_rows: Signal<Vec<crate::models::ContactListRow>>,
    pub did_resolution_health: Signal<crate::components::DidResolutionHealth>,
}

#[component]
pub(super) fn ShellEffects(state: ShellEffectState) -> Element {
    let ShellEffectState {
        mut account_primary_handle,
        principal_id,
        token,
        mut personal_handles,
        mut personal_handles_status,
        personal_handles_lookup_key: _,
        device_id,
        mut current_account_display_name,
        mut current_account_avatar_blob_ref,
        mut current_device_display_name,
        mut account_identity_lookup_key,
        contact_handles_lookup_key: _,
        contact_handles_fetching: _,
        mut direct_contact_rows,
        mut did_resolution_health,
    } = state;
    let SessionContext {
        mut state_store,
        base_url,
        active_account,
        session_generation,
        ..
    } = SessionContext::get();
    let navigator = use_navigator();

    // Recheck failed bootstrap probes independently of session refresh. A
    // successful probe clears the banner without logging out or reloading.
    use_resource(move || async move {
        let base = base_url();
        let generation = session_generation();
        loop {
            crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(15)).await;
            if *did_resolution_health.peek() == crate::components::DidResolutionHealth::Healthy {
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
            if *base_url.peek() != base || *session_generation.peek() != generation {
                return;
            }
            did_resolution_health.set(match result {
                Ok(description) => {
                    crate::components::DidResolutionHealth::from_identity_description(&description)
                }
                Err(error) => crate::components::DidResolutionHealth::from_probe_error(&error),
            });
        }
    });

    // Contact requests are read from the account contact projection, not the
    // Realm invite notification carrier. Keep this inbox live even when the
    // Contacts sidebar has never been opened. A session change cancels the
    // resource and fences responses from the previous account.
    use_resource(move || async move {
        let account = active_account().map(|account| account.authority);
        let api_token = token();
        let base = base_url();
        let generation = session_generation();
        direct_contact_rows.set(Vec::new());
        if account.is_none() || api_token.trim().is_empty() {
            return;
        }
        loop {
            let result = crate::transport::auth::with_authed_sdk_client(
                &base,
                api_token.clone(),
                |http| async move { crate::transport::account::contacts(&http).await },
            )
            .await;
            if *session_generation.peek() != generation
                || active_account
                    .peek()
                    .as_ref()
                    .map(|account| &account.authority)
                    != account.as_ref()
                || *base_url.peek() != base
                || *token.peek() != api_token
            {
                return;
            }
            match result {
                Ok(response) => {
                    state_store
                        .write()
                        .replace_accepted_human_contacts(&response.contacts);
                    direct_contact_rows.set(response.contacts);
                }
                Err(error) => {
                    tracing::warn!(error = %error.display_diagnostic(), "contact inbox refresh failed")
                }
            }
            crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(15)).await;
        }
    });

    // Account-viewer is the authoritative source for the Actor Profile,
    // device display_name, and signed primary handle claim. Keep those
    // user-facing labels separate from protocol IDs and from the Account
    // Authority handoff's unsigned account_handle hint.
    use_effect(move || {
        let lookup_base_url = base_url();
        let lookup_actor = crate::app::principal_id_owned(principal_id());
        let lookup_device = device_id();
        let lookup_token = token();
        let key = format!(
            "{}|{}|{}|{}",
            lookup_base_url,
            lookup_actor,
            lookup_device,
            !lookup_token.trim().is_empty(),
        );
        if account_identity_lookup_key() == key {
            return;
        }
        account_identity_lookup_key.set(key);
        if lookup_token.trim().is_empty() || lookup_actor.trim().is_empty() {
            current_account_display_name.set(String::new());
            current_account_avatar_blob_ref.set(String::new());
            current_device_display_name.set(String::new());
            return;
        }

        // Never keep the previous account's labels visible while a new
        // account/device lookup is in flight (or if that lookup fails).
        current_account_display_name.set(String::new());
        current_account_avatar_blob_ref.set(String::new());
        current_device_display_name.set(String::new());
        account_primary_handle.set(String::new());
        personal_handles.set(Vec::new());
        personal_handles_status.set("Loading handles".to_owned());
        state_store
            .write()
            .set_primary_handle_for_principal_id(&lookup_actor, "");

        let base = lookup_base_url;
        let actor = lookup_actor;
        let device = lookup_device;
        let mut handle_store = state_store;
        spawn(async move {
            let result = crate::transport::auth::with_authed_sdk_client(
                &base,
                lookup_token,
                |http| async move { crate::transport::keys::list_devices(&http).await },
            )
            .await;
            let Ok(viewer) = result else {
                return;
            };
            // Ignore a late response from the previous account.
            if crate::app::principal_id_text(&principal_id()) != actor.trim() {
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
                .write()
                .set_primary_handle_for_principal_id(&actor, &primary_handle);
            try_set_signal(current_account_display_name, display_name);
            try_set_signal(current_account_avatar_blob_ref, avatar_blob_ref);
            try_set_signal(current_device_display_name, device_display_name);
            if !primary_handle.is_empty() {
                try_set_signal(account_primary_handle, primary_handle.clone());
                try_set_signal(
                    personal_handles_status,
                    personal_handles_status_for(std::slice::from_ref(&primary_handle)),
                );
                try_set_signal(personal_handles, vec![primary_handle]);
            }
        });
    });

    use_effect(move || {
        let handle = account_primary_handle();
        let account = crate::app::principal_id_owned(principal_id());
        if handle.trim().is_empty() || account.trim().is_empty() {
            return;
        }
        state_store
            .write()
            .set_primary_handle_for_principal_id(&account, &handle);
    });

    let mut previous_unread_notification_count = use_signal(|| Option::<usize>::None);
    use_effect(move || {
        let store = state_store.read();
        let unread = unread_notification_count(&store.load());
        let sound_enabled = crate::notification_sound::notification_sound_enabled(&store);
        let previous = *previous_unread_notification_count.peek();
        if crate::notification_sound::should_play_notification_sound(
            previous,
            unread,
            sound_enabled,
        ) {
            crate::notification_sound::play_notification_sound();
        }
        if previous != Some(unread) {
            previous_unread_notification_count.set(Some(unread));
        }
    });

    use_effect(move || {
        let _ = dioxus::document::eval(
            r#"
            (() => {
              if (window.__inksonShortcutDispatcherInstalled) return;
              window.__inksonShortcutDispatcherInstalled = true;
              window.addEventListener('keydown', (event) => {
                if (event.isComposing || event.repeat) return;
                const target = event.target;
                const tag = target && target.tagName ? target.tagName.toLowerCase() : '';
                const editable = target && (
                  target.isContentEditable ||
                  tag === 'input' ||
                  tag === 'textarea' ||
                  tag === 'select' ||
                  (target.closest && target.closest('[contenteditable="true"], [role="textbox"]'))
                );
                if (editable) return;
                const chord = event.ctrlKey || event.metaKey;
                const key = typeof event.key === 'string' ? event.key.toLowerCase() : '';
                let targetElement = null;
                if (key === 'escape') {
                  targetElement =
                    document.querySelector('[data-testid="shortcut-help-dismiss"]') ||
                    document.querySelector('[data-testid="notifications-drawer-close"]');
                } else if (chord && key === 'k') {
                  targetElement = document.querySelector('[data-testid="topbar-search-button"]');
                } else if (chord && key === 'f') {
                  targetElement = document.querySelector('[data-testid="global-search-shortcut-target"]');
                } else if (
                  (chord && key === '/') ||
                  (event.shiftKey && key === '/') ||
                  event.key === '?'
                ) {
                  targetElement = document.querySelector('[data-testid="topbar-shortcuts-button"]');
                }
                if (!(targetElement instanceof HTMLElement)) return;
                event.preventDefault();
                event.stopPropagation();
                targetElement.click();
              }, true);
            })();
            "#,
        );
    });

    let call_signal_hub = use_context::<crate::views::call_signals::CallSignalHub>();
    let mut last_incoming_nav = use_signal(|| Option::<String>::None);
    use_effect(move || match call_signal_hub.incoming_call.read().clone() {
        Some(_) if !crate::views::call::media_route_adapter_available() => {}
        Some(info) if last_incoming_nav.read().as_deref() != Some(info.call_id.as_str()) => {
            last_incoming_nav.set(Some(info.call_id.clone()));
            navigator.push(Route::Call {
                call_id: info.call_id,
                peer: info.peer_actor,
                realm_id: info.realm_id,
                video: if info.video { "1" } else { "0" }.to_owned(),
                incoming: "1".to_owned(),
            });
        }
        None if last_incoming_nav.read().is_some() => last_incoming_nav.set(None),
        _ => {}
    });

    let route = use_route::<Route>();
    use_effect(move || {
        if matches!(route, Route::Recovery) {
            let _ = navigator.replace(Route::SettingsRecovery);
        }
    });

    rsx! {}
}
