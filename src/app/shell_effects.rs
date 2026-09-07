use super::*;

#[derive(Clone, Copy, PartialEq)]
pub(super) struct ShellEffectState {
    pub account_primary_handle: Signal<String>,
    pub principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    pub token: Signal<String>,
    pub personal_handles: Signal<Vec<String>>,
    pub personal_handles_status: Signal<String>,
    pub personal_handles_lookup_key: Signal<String>,
    pub directory_handles_available: Signal<bool>,
    pub device_id: Signal<String>,
    pub current_account_display_name: Signal<String>,
    pub current_account_avatar_blob_ref: Signal<String>,
    pub current_device_display_name: Signal<String>,
    pub account_identity_lookup_key: Signal<String>,
    pub contact_handles_lookup_key: Signal<String>,
    pub contact_handles_fetching: Signal<BTreeSet<String>>,
    pub direct_contact_rows: Signal<Vec<crate::models::ContactListRow>>,
}

#[component]
pub(super) fn ShellEffects(state: ShellEffectState) -> Element {
    let ShellEffectState {
        mut account_primary_handle,
        principal_id,
        token,
        mut personal_handles,
        mut personal_handles_status,
        mut personal_handles_lookup_key,
        directory_handles_available,
        device_id,
        mut current_account_display_name,
        mut current_account_avatar_blob_ref,
        mut current_device_display_name,
        mut account_identity_lookup_key,
        contact_handles_lookup_key,
        contact_handles_fetching,
        mut direct_contact_rows,
    } = state;
    let SessionContext {
        mut state_store,
        base_url,
        active_account,
        session_generation,
        ..
    } = SessionContext::get();
    let navigator = use_navigator();

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
        if should_redirect_to_dashboard_after_login(&route) && !token().trim().is_empty() {
            // This is the sole authenticated-entry route canonicalizer. It
            // uses the Dioxus router only; a full document replacement would
            // restart secure-store hydration and re-enter the boot state
            // machine immediately after a successful login.
            spawn(async move {
                crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(1)).await;
                if let Some(failure) = navigator.replace(Route::Dashboard) {
                    tracing::warn!(
                        ?failure,
                        "session shell entry-route canonicalisation failed"
                    );
                }
            });
        } else if matches!(route, Route::Recovery) {
            let _ = navigator.replace(Route::SettingsRecovery);
        }
    });

    {
        use_effect(move || {
            let lookup_base_url = base_url();
            let lookup_actor = crate::app::principal_id_owned(principal_id());
            // The active account's own authority is already an exact
            // `AccountId`; the Directory subject query never assembles one.
            let lookup_account_id = active_account
                .read()
                .as_ref()
                .map(|account| account.authority.clone());
            let lookup_token = token();
            let key = format!(
                "{}|{}|{}",
                lookup_base_url,
                lookup_actor,
                !lookup_token.trim().is_empty(),
            );
            if personal_handles_lookup_key() == key {
                return;
            }
            personal_handles_lookup_key.set(key);
            let subject_account_id = lookup_account_id
                .filter(|_| !lookup_token.trim().is_empty() && !lookup_actor.trim().is_empty());
            let Some(subject_account_id) = subject_account_id else {
                account_primary_handle.set(String::new());
                personal_handles.set(Vec::new());
                personal_handles_status.set("No authenticated session".to_owned());
                return;
            };
            personal_handles_status.set("Loading handles".to_owned());
            let base = lookup_base_url.clone();
            let lookup_subject = lookup_actor.clone();
            let api_token = lookup_token.clone();
            let existing_personal_handles = personal_handles();
            let mut handle_store = state_store;
            spawn(async move {
                match crate::transport::auth::with_directory_sdk_client(
                    &base,
                    api_token,
                    |http| async move {
                        crate::transport::directory::list_handles_for_subject(
                            &http,
                            &subject_account_id,
                            None,
                            Some(arkret_models_discovery::DirectoryIntent::Lookup),
                        )
                        .await
                    },
                )
                .await
                {
                    Ok(res) => {
                        try_set_signal(directory_handles_available, true);
                        let directory_primary_handle = res
                            .primary_handle
                            .as_ref()
                            .map(|handle| handle.canonical().to_owned());
                        let directory_handles = display_handles_from_directory_response(&res);
                        if let Some(directory_primary_handle) = directory_primary_handle {
                            handle_store.write().set_primary_handle_for_principal_id(
                                &lookup_subject,
                                &directory_primary_handle,
                            );
                            try_set_signal(account_primary_handle, directory_primary_handle);
                        }
                        // Directory is the complete handle-set projection, but
                        // AccountView's signed primary claim remains a valid
                        // fallback if the two reads briefly cross during
                        // registration or projection refresh.
                        let handles = if directory_handles.is_empty() {
                            let viewer_primary_handle = account_primary_handle();
                            if viewer_primary_handle.trim().is_empty() {
                                Vec::new()
                            } else {
                                vec![viewer_primary_handle]
                            }
                        } else {
                            directory_handles
                        };
                        let status = if handles.is_empty() {
                            "No handles published".to_owned()
                        } else {
                            personal_handles_status_for(&handles)
                        };
                        try_set_signal(personal_handles_status, status);
                        try_set_signal(personal_handles, handles);
                    }
                    Err(err) => {
                        try_set_signal(directory_handles_available, false);
                        tracing::warn!(
                            ?err,
                            "directory list_handles_for_subject failed; keeping account primary handle claim"
                        );
                        if existing_personal_handles.is_empty() {
                            try_set_signal(personal_handles_status, "Not published".to_owned());
                        }
                    }
                }
            });
        });
    }
    {
        let mut contact_handles_lookup_key = contact_handles_lookup_key;
        let mut contact_handles_fetching = contact_handles_fetching;
        let mut state_store_for_contact_handles = state_store;
        use_effect(move || {
            let lookup_base_url = base_url();
            let lookup_token = token();
            // A Directory subject query needs the peer exact `AccountId`;
            // the Contact row already carries it, so nothing is assembled from
            // a principal here. `service` actors have no account subject.
            let mut peers = direct_contact_rows
                .read()
                .iter()
                .filter_map(|contact| match contact.peer.contact_actor_id() {
                    arkret_sdk::ActorId::Account { account_id } => Some(account_id),
                    arkret_sdk::ActorId::Service { .. } => None,
                })
                .collect::<BTreeSet<arkret_sdk::AccountId>>();
            if lookup_token.trim().is_empty() || peers.is_empty() {
                if !contact_handles_lookup_key().is_empty() {
                    contact_handles_lookup_key.set(String::new());
                }
                return;
            }
            peers.retain(|peer| {
                state_store_for_contact_handles
                    .read()
                    .cached_member_handle_lookup(peer, None, None)
                    .is_none()
                    && !contact_handles_fetching.read().contains(&peer.to_string())
            });
            if peers.is_empty() {
                if !contact_handles_lookup_key().is_empty() {
                    contact_handles_lookup_key.set(String::new());
                }
                return;
            }
            let peer_key = peers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let key = format!(
                "{}|{}|{}",
                lookup_base_url,
                !lookup_token.trim().is_empty(),
                peer_key,
            );
            if contact_handles_lookup_key() == key {
                return;
            }
            contact_handles_lookup_key.set(key);
            for peer in &peers {
                contact_handles_fetching.write().insert(peer.to_string());
            }
            let base = lookup_base_url.clone();
            let api_token = lookup_token.clone();
            spawn(async move {
                for subject_account_id in peers {
                    let fetching_key = subject_account_id.to_string();
                    let result = crate::transport::auth::with_directory_sdk_client(
                        &base,
                        api_token.clone(),
                        {
                            let subject_account_id = subject_account_id.clone();
                            move |http| async move {
                                crate::transport::directory::list_handles_for_subject(
                                    &http,
                                    &subject_account_id,
                                    None,
                                    Some(arkret_models_discovery::DirectoryIntent::Lookup),
                                )
                                .await
                            }
                        },
                    )
                    .await;
                    match result {
                        Ok(res) if res.account_id == subject_account_id => {
                            try_set_signal(directory_handles_available, true);
                            let primary = res
                                .primary_handle
                                .as_ref()
                                .map(|handle| handle.canonical().to_owned());
                            let claims_count = res.claims.len();
                            let earliest_expiry = res
                                .claims
                                .iter()
                                .filter_map(|claim| claim.claim.expires_at.as_ref().cloned())
                                .min();
                            state_store_for_contact_handles
                                .write()
                                .save_member_handle_lookup(
                                    &subject_account_id,
                                    None,
                                    None,
                                    primary,
                                    claims_count,
                                    Some(res.as_of),
                                    earliest_expiry,
                                );
                        }
                        Ok(_) => {
                            // The answer is about a different account, so it is
                            // recorded as unusable for the requested subject and
                            // never re-keyed onto the account that answered.
                            try_set_signal(directory_handles_available, true);
                            state_store_for_contact_handles
                                .write()
                                .save_member_handle_lookup(
                                    &subject_account_id,
                                    None,
                                    None,
                                    None,
                                    0,
                                    None,
                                    None,
                                );
                        }
                        Err(err) if !err.is_auth_expired() => {
                            try_set_signal(directory_handles_available, false);
                            state_store_for_contact_handles
                                .write()
                                .save_member_handle_lookup(
                                    &subject_account_id,
                                    None,
                                    None,
                                    None,
                                    0,
                                    None,
                                    None,
                                );
                        }
                        Err(_) => {}
                    }
                    contact_handles_fetching.write().remove(&fetching_key);
                }
            });
        });
    }
    rsx! {}
}
