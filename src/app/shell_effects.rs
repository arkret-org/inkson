use super::*;

#[derive(Clone, Copy, PartialEq)]
pub(super) struct ShellEffectState {
    pub account_primary_handle: Signal<String>,
    pub account_did: Signal<String>,
    pub token: Signal<String>,
    pub server_description: Signal<Option<ServiceDescribe>>,
    pub personal_handles: Signal<Vec<String>>,
    pub personal_handles_status: Signal<String>,
    pub personal_handles_lookup_key: Signal<String>,
    pub contact_handles_lookup_key: Signal<String>,
    pub contact_handles_fetching: Signal<BTreeSet<String>>,
    pub direct_contact_rows: Signal<Vec<crate::models::ContactListRow>>,
}

#[component]
pub(super) fn ShellEffects(state: ShellEffectState) -> Element {
    let ShellEffectState {
        mut account_primary_handle,
        account_did,
        token,
        server_description,
        mut personal_handles,
        mut personal_handles_status,
        mut personal_handles_lookup_key,
        contact_handles_lookup_key,
        contact_handles_fetching,
        direct_contact_rows,
    } = state;
    let SessionContext {
        mut state_store,
        base_url,
    } = SessionContext::get();
    let navigator = use_navigator();

    use_effect(move || {
        let handle = account_primary_handle();
        let account = account_did();
        if handle.trim().is_empty() || account.trim().is_empty() {
            return;
        }
        let storage_key = account_primary_handle_storage_key(&account);
        if state_store
            .peek()
            .load_private_data(&account, &storage_key)
            .as_deref()
            != Some(handle.as_str())
        {
            state_store
                .write()
                .save_private_data(&account, storage_key, handle);
        }
    });

    let mut previous_unread_notification_count = use_signal(|| Option::<usize>::None);
    use_effect(move || {
        let store = state_store.read();
        let unread = unread_notification_count(&store.load());
        let sound_enabled =
            crate::notification_sound::notification_sound_enabled(&store, &account_did());
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
              if (window.__inksonShortcutHelpBridgeInstalled) return;
              window.__inksonShortcutHelpBridgeInstalled = true;
              window.addEventListener('keydown', (event) => {
                const target = event.target;
                const tag = target && target.tagName ? target.tagName.toLowerCase() : '';
                const editable = target && (target.isContentEditable || tag === 'input' || tag === 'textarea' || tag === 'select');
                const chord = event.ctrlKey || event.metaKey;
                const key = typeof event.key === 'string' ? event.key.toLowerCase() : '';
                const testId = chord && key === 'k'
                  ? 'topbar-search-button'
                  : chord && key === 'f'
                    ? 'global-search-shortcut-target'
                    : chord && key === 'enter'
                      ? 'chat-composer'
                      : (!editable && event.key === '?')
                        ? 'shortcut-help-trigger'
                        : '';
                if (!testId) return;
                const targetElement = document.querySelector('[data-testid="' + testId + '"]');
                if (!(targetElement instanceof HTMLElement)) return;
                event.preventDefault();
                event.stopPropagation();
                if (testId === 'chat-composer') targetElement.focus();
                else targetElement.click();
              }, true);
            })();
            "#,
        );
    });

    let call_signal_hub = use_context::<crate::views::call_signals::CallSignalHub>();
    let mut last_incoming_nav = use_signal(|| Option::<String>::None);
    use_effect(move || match call_signal_hub.incoming_call.read().clone() {
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
        if matches!(route, Route::Login) && !token().trim().is_empty() {
            let _ = navigator.push(Route::Dashboard);
        } else if matches!(route, Route::Recovery) {
            let _ = navigator.replace(Route::SettingsRecovery);
        }
    });

    {
        use_effect(move || {
            let lookup_base_url = base_url();
            let lookup_actor = account_did();
            let lookup_token = token();
            let lookup_supported = server_description().as_ref().is_some_and(|description| {
                service_supports_operation(description, OP_LIST_HANDLES_FOR_SUBJECT)
            });
            let key = format!(
                "{}|{}|{}|{}",
                lookup_base_url,
                lookup_actor,
                !lookup_token.trim().is_empty(),
                lookup_supported,
            );
            if personal_handles_lookup_key() == key {
                return;
            }
            personal_handles_lookup_key.set(key);
            if lookup_token.trim().is_empty() || lookup_actor.trim().is_empty() {
                account_primary_handle.set(String::new());
                personal_handles.set(Vec::new());
                personal_handles_status.set("No authenticated session".to_owned());
                return;
            }
            if !lookup_supported {
                if personal_handles().is_empty() {
                    personal_handles_status.set("Not published".to_owned());
                }
                return;
            }
            personal_handles_status.set("Loading handles".to_owned());
            let base = lookup_base_url.clone();
            let actor = lookup_actor.clone();
            let api_token = lookup_token.clone();
            let existing_personal_handles = personal_handles();
            spawn(async move {
                match crate::transport::auth::with_authed_sdk_client(
                    &base,
                    api_token,
                    |http| async move {
                        crate::transport::directory::list_handles_for_subject(
                            &http,
                            &actor,
                            None,
                            Some("display"),
                        )
                        .await
                    },
                )
                .await
                {
                    Ok(res) => {
                        let directory_primary_handle = res
                            .primary_handle
                            .as_ref()
                            .map(|handle| handle.canonical().to_owned());
                        let directory_handles = display_handles_from_directory_response(&res);
                        if directory_handles.is_empty() {
                            // Mirror the error branches below: keep any
                            // account viewer primary handle claim already
                            // loaded instead of clobbering it with an empty
                            // directory page.
                            if existing_personal_handles.is_empty() {
                                try_set_signal(
                                    personal_handles_status,
                                    "No handles published".to_owned(),
                                );
                            }
                        } else {
                            if let Some(primary_handle) = directory_primary_handle {
                                try_set_signal(account_primary_handle, primary_handle);
                            }
                            let handles = merge_personal_handles(
                                &existing_personal_handles,
                                directory_handles,
                            );
                            try_set_signal(
                                personal_handles_status,
                                personal_handles_status_for(&handles),
                            );
                            try_set_signal(personal_handles, handles);
                        }
                    }
                    Err(err) => {
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
            let lookup_supported = server_description().as_ref().is_some_and(|description| {
                service_supports_operation(description, OP_LIST_HANDLES_FOR_SUBJECT)
            });
            let mut peers = direct_contact_rows
                .read()
                .iter()
                .map(|contact| contact.peer.trim().to_owned())
                .filter(|peer| peer.starts_with("did:"))
                .collect::<BTreeSet<_>>();
            if !lookup_supported || lookup_token.trim().is_empty() || peers.is_empty() {
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
                    && !contact_handles_fetching.read().contains(peer)
            });
            if peers.is_empty() {
                if !contact_handles_lookup_key().is_empty() {
                    contact_handles_lookup_key.set(String::new());
                }
                return;
            }
            let peer_key = peers.iter().cloned().collect::<Vec<_>>().join(",");
            let key = format!(
                "{}|{}|{}|{}",
                lookup_base_url,
                !lookup_token.trim().is_empty(),
                lookup_supported,
                peer_key,
            );
            if contact_handles_lookup_key() == key {
                return;
            }
            contact_handles_lookup_key.set(key);
            for peer in &peers {
                contact_handles_fetching.write().insert(peer.clone());
            }
            let base = lookup_base_url.clone();
            let api_token = lookup_token.clone();
            spawn(async move {
                for subject_id in peers {
                    let result =
                        crate::transport::auth::with_authed_sdk_client(&base, api_token.clone(), {
                            let subject_id = subject_id.clone();
                            move |http| async move {
                                crate::transport::directory::list_handles_for_subject(
                                    &http,
                                    &subject_id,
                                    None,
                                    Some("display"),
                                )
                                .await
                            }
                        })
                        .await;
                    match result {
                        Ok(res) => {
                            let primary = res
                                .primary_handle
                                .as_ref()
                                .map(|handle| handle.canonical().to_owned());
                            let claims_count = res.claims.len();
                            let earliest_expiry = res
                                .claims
                                .iter()
                                .filter_map(|claim| claim.expires_at.as_ref().cloned())
                                .min();
                            state_store_for_contact_handles
                                .write()
                                .save_member_handle_lookup(
                                    res.subject.as_str().to_owned(),
                                    None,
                                    None,
                                    primary,
                                    claims_count,
                                    Some(res.as_of),
                                    earliest_expiry,
                                );
                        }
                        Err(err) if !err.is_auth_expired() => {
                            state_store_for_contact_handles
                                .write()
                                .save_member_handle_lookup(
                                    subject_id.clone(),
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
                    contact_handles_fetching.write().remove(&subject_id);
                }
            });
        });
    }
    rsx! {}
}
