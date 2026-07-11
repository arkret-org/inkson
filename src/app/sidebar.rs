use super::*;

pub(super) fn pinned_realm_ids_from_store(store: &LocalStateStore) -> BTreeSet<String> {
    store
        .realm_remarks()
        .into_iter()
        .filter_map(|(realm_id, remark)| remark.pinned.then_some(realm_id))
        .collect()
}

pub(super) fn notification_projection_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn notification_projection_bool(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

pub(super) fn unread_notification_count(snapshot: &ClientLocalState) -> usize {
    snapshot
        .notification_projection
        .iter()
        .enumerate()
        .filter(|(index, value)| {
            let id = notification_projection_string(value, &["notification_id", "id"])
                .unwrap_or_else(|| format!("notification-{index}"));
            let client_state = snapshot.notification_client_state.get(&id);
            let archived = client_state.map(|state| state.archived).unwrap_or_else(|| {
                notification_projection_bool(value, "archived").unwrap_or(false)
            });
            let read = client_state
                .map(|state| state.read)
                .unwrap_or_else(|| notification_projection_bool(value, "read").unwrap_or(false))
                || crate::views::notifications::notification_value_read_by_cursor(
                    *index, value, snapshot,
                );
            !archived && !read
        })
        .count()
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct RealmManageRow {
    pub(super) realm_id: String,
    pub(super) display_name: String,
    pub(super) title: String,
    pub(super) encrypted: bool,
    pub(super) space_count: usize,
}

pub(super) fn sidebar_text_matches_query(normalized_query: &str, values: &[&str]) -> bool {
    normalized_query.is_empty()
        || values
            .iter()
            .any(|value| value.to_ascii_lowercase().contains(normalized_query))
}

pub(super) fn load_direct_contacts_and_agents_for_sidebar(
    base: String,
    api_token: String,
    mut direct_contact_rows: Signal<Vec<crate::models::ContactListRow>>,
    mut direct_contacts_loaded: Signal<bool>,
    mut own_agent_rows: Signal<Vec<arkret_sdk::AgentProjection>>,
    mut own_agents_loaded: Signal<bool>,
) {
    if api_token.trim().is_empty() {
        direct_contact_rows.set(Vec::new());
        direct_contacts_loaded.set(false);
        own_agent_rows.set(Vec::new());
        own_agents_loaded.set(false);
        return;
    }

    direct_contacts_loaded.set(true);
    own_agents_loaded.set(true);
    spawn(async move {
        match crate::transport::auth::with_authed_sdk_client(&base, api_token, |http| async move {
            let contacts = crate::transport::account::contacts(&http).await;
            let agents = http.agent_list().await.map_err(anyhow::Error::from);
            Ok((contacts, agents))
        })
        .await
        {
            Ok((contacts, agents)) => {
                match contacts {
                    Ok(response) => direct_contact_rows.set(response.contacts),
                    Err(err) => {
                        direct_contacts_loaded.set(false);
                        crate::components::feedback::toast_error(
                            "feedback.contacts_load_failed",
                            vec![],
                            Some(err.to_string()),
                        );
                    }
                }
                match agents {
                    // The Contacts sidebar is a chat surface: only agents that
                    // ever became effective belong here. Pending / expired /
                    // deactivated provisioning attempts stay in Settings →
                    // My Agents.
                    Ok(response) => own_agent_rows.set(
                        response
                            .agents
                            .into_iter()
                            .filter(|agent| {
                                matches!(
                                    agent.status,
                                    arkret_sdk::AgentStatus::Active
                                        | arkret_sdk::AgentStatus::Paused
                                )
                            })
                            .collect(),
                    ),
                    Err(err) => {
                        own_agents_loaded.set(false);
                        tracing::warn!(error = %err, "failed to load personal agents for Contacts sidebar");
                    }
                }
            }
            Err(err) => {
                direct_contacts_loaded.set(false);
                own_agents_loaded.set(false);
                crate::components::feedback::toast_error(
                    "feedback.contacts_load_failed",
                    vec![],
                    Some(err.display()),
                );
            }
        }
    });
}

pub(super) fn load_direct_contacts_for_sidebar(
    base: String,
    api_token: String,
    mut direct_contact_rows: Signal<Vec<crate::models::ContactListRow>>,
    mut direct_contacts_loaded: Signal<bool>,
) {
    if api_token.trim().is_empty() {
        direct_contact_rows.set(Vec::new());
        direct_contacts_loaded.set(false);
        return;
    }
    direct_contacts_loaded.set(true);
    spawn(async move {
        match crate::transport::auth::with_endpoint_clients(
            &base,
            api_token,
            None,
            |clients| async move { clients.account().contacts().await },
        )
        .await
        {
            Ok(response) => direct_contact_rows.set(response.contacts),
            Err(err) => {
                direct_contacts_loaded.set(false);
                crate::components::feedback::toast_error(
                    "feedback.contacts_load_failed",
                    vec![],
                    Some(err.display()),
                );
            }
        }
    });
}

pub(super) fn toggle_sidebar_realm_pin(
    realm_id: String,
    existing: Option<crate::account_data::RealmRemark>,
    next_pinned: bool,
    mut state_store: SyncSignal<LocalStateStore>,
    base_url: String,
    api_token: String,
) {
    let now_rfc3339 = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let next = crate::account_data::RealmRemark::with_pinned_preserving_fields(
        realm_id.clone(),
        existing.as_ref(),
        next_pinned,
        Some(now_rfc3339),
    );
    state_store
        .write()
        .set_realm_remark(realm_id.clone(), next.clone());
    crate::components::feedback::toast_success(
        if next_pinned {
            "realm.pinned"
        } else {
            "realm.unpinned"
        },
        vec![],
    );
    crate::views::settings::push_realm_remark_account_data_with_failure_toast(
        base_url, api_token, realm_id, next,
    );
}

pub(super) fn toggle_sidebar_contact_pin(
    actor_id: String,
    existing: Option<crate::account_data::ContactRemark>,
    next_pinned: bool,
    mut state_store: SyncSignal<LocalStateStore>,
    base_url: String,
    api_token: String,
) {
    let now_rfc3339 = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let next = crate::account_data::ContactRemark::with_pinned_preserving_fields(
        actor_id.clone(),
        existing.as_ref(),
        next_pinned,
        Some(now_rfc3339),
    );
    state_store
        .write()
        .set_contact_remark(actor_id.clone(), next.clone());
    crate::components::feedback::toast_success(
        if next_pinned {
            "contact.pinned"
        } else {
            "contact.unpinned"
        },
        vec![],
    );
    crate::views::settings::push_contact_remark_account_data(base_url, api_token, actor_id, next);
}

pub(super) fn leave_sidebar_realm(
    base_url: String,
    api_token: String,
    realm_id: String,
    account_did: String,
    mut state_store: SyncSignal<LocalStateStore>,
    mut realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    mut selected_realm_id: Signal<String>,
    mut sync_cursor: Signal<String>,
) {
    // Realm membership events are authored by the account/principal DID — the
    // server rejects any event whose `actor_id` differs from the authenticated
    // session actor
    // session actor (`actor_session_mismatch`). The local device DID is not the
    // session actor, so it must not be used here.
    let actor_id = account_did.trim().to_owned();
    if actor_id.is_empty() {
        crate::components::feedback::toast_error("feedback.account_not_connected", vec![], None);
        return;
    }
    let current_nodes = realm_tree_nodes();
    let mut ids_to_forget = descendant_node_ids(&current_nodes, &realm_id);
    if ids_to_forget.is_empty() {
        ids_to_forget.push(realm_id.clone());
    }
    let realm_label = short_protocol_id(&realm_id);
    crate::components::feedback::toast_info(
        "feedback.realm_leaving",
        vec![("realm", realm_label.clone())],
    );
    spawn(async move {
        let realm_for_api = realm_id.clone();
        match crate::transport::auth::with_event_submitter(&base_url, api_token, |sub| async move {
            crate::transport::realm_write::leave_realm(&sub, &realm_for_api, &actor_id).await
        })
        .await
        {
            Ok(_) => {
                let forgotten_ids = ids_to_forget.into_iter().collect::<BTreeSet<_>>();
                for id in &forgotten_ids {
                    state_store.write().forget_realm_tree_projection(id);
                }
                realm_tree_nodes.set(
                    realm_tree_nodes()
                        .into_iter()
                        .filter(|node| !forgotten_ids.contains(&node.id))
                        .collect(),
                );
                if forgotten_ids.contains(&selected_realm_id()) {
                    selected_realm_id.set(String::new());
                }
                sync_cursor.set(String::new());
                crate::components::feedback::toast_success(
                    "feedback.realm_left",
                    vec![("realm", realm_label)],
                );
            }
            Err(err) => crate::components::feedback::toast_error(
                "feedback.realm_leave_failed",
                vec![("realm", realm_label)],
                Some(err.display()),
            ),
        }
    });
}

/// Per-Realm UI pre-gate for the sidebar row menu's write actions
/// (Add Member / Settings). Presence of a `realm_id` key in the cache means
/// the authz probe has completed; the booleans mirror the server's
/// authoritative decision so the row menu can hide entries the actor cannot
/// use. This is advisory only — the server still makes the real call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct SidebarRowRealmPerms {
    pub(super) can_add_member: bool,
    pub(super) can_settings: bool,
}

/// Parse a `_arkret/self/authz/check` body into a simple allow boolean.
/// Mirrors `realm_admin::authz_json_allowed`. Fail-closed: any shape we do
/// not recognise reads as denied.
pub(super) fn sidebar_authz_allowed(value: &Value) -> bool {
    value
        .get("allowed")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| {
            value
                .get("decision")
                .and_then(Value::as_str)
                .map(|decision| matches!(decision, "allow" | "allowed"))
                .unwrap_or(false)
        })
}

/// Lazily probe whether `actor` may add members (`ak.invite.create`) or edit
/// settings (`ak.realm.update`) on `realm_id`, caching the verdict in
/// `perms_cache`.
///
/// Triggered when a sidebar row's kebab menu opens, so at most two authz
/// requests are issued for the single Realm whose menu is open — never the
/// `2*N` that eager per-row probing on every sidebar render would cost.
/// Fail-closed: a transport error or a non-allow body both leave the write
/// actions hidden, and we still cache that verdict so we don't re-probe a
/// Realm the actor plainly cannot manage on every menu open.
pub(super) fn ensure_sidebar_row_perms(
    base_url: String,
    api_token: String,
    actor: String,
    realm_id: String,
    mut perms_cache: Signal<BTreeMap<String, SidebarRowRealmPerms>>,
) {
    if api_token.trim().is_empty() || actor.trim().is_empty() || realm_id.trim().is_empty() {
        return;
    }
    if perms_cache.read().contains_key(&realm_id) {
        return;
    }
    spawn(async move {
        let perms = match crate::transport::auth::authed_api_with_sync(&base_url, api_token, None) {
            Ok(api) => {
                let invite = async {
                    crate::transport::realm_read::authz_check_raw(
                        &api.sdk_http_client()?,
                        &actor,
                        "ak.invite.create",
                        &realm_id,
                    )
                    .await
                }
                .await;
                let settings = async {
                    crate::transport::realm_read::authz_check_raw(
                        &api.sdk_http_client()?,
                        &actor,
                        "ak.realm.update",
                        &realm_id,
                    )
                    .await
                }
                .await;
                SidebarRowRealmPerms {
                    can_add_member: invite.as_ref().map(sidebar_authz_allowed).unwrap_or(false),
                    can_settings: settings
                        .as_ref()
                        .map(sidebar_authz_allowed)
                        .unwrap_or(false),
                }
            }
            Err(_) => SidebarRowRealmPerms::default(),
        };
        perms_cache.write().insert(realm_id, perms);
    });
}

pub(super) fn delete_sidebar_contact(
    base_url: String,
    api_token: String,
    peer: String,
    state_store: SyncSignal<LocalStateStore>,
    mut direct_contact_rows: Signal<Vec<crate::models::ContactListRow>>,
    mut direct_contacts_loaded: Signal<bool>,
) {
    let peer_label = crate::views::helpers::display_name_for_did(&state_store.read(), &peer);
    crate::components::feedback::toast_info(
        "feedback.contact_deleting",
        vec![("name", peer_label.clone())],
    );
    spawn(async move {
        let peer_for_api = peer.clone();
        match crate::transport::auth::with_authed_sdk_client(
            &base_url,
            api_token,
            |http| async move {
                crate::transport::account::tombstone_contact(&http, &peer_for_api, false).await
            },
        )
        .await
        {
            Ok(_) => {
                direct_contact_rows.set(
                    direct_contact_rows()
                        .into_iter()
                        .filter(|row| row.peer != peer)
                        .collect(),
                );
                direct_contacts_loaded.set(true);
                crate::components::feedback::toast_success(
                    "feedback.contact_deleted",
                    vec![("name", peer_label)],
                );
            }
            Err(err) => crate::components::feedback::toast_error(
                "feedback.contact_delete_failed",
                vec![("name", peer_label)],
                Some(err.display()),
            ),
        }
    });
}

/// One-shot push-token provider bootstrap.
///
/// Runs once on first App render. On wasm32 we install
/// `WebPushTokenProvider::new()` (drives the service-worker +
/// `pushManager.subscribe` path described in `push.rs::WebPushTokenProvider`).
/// On native builds we install `FcmPushTokenProvider` / `ApnsPushTokenProvider`.
/// The host adapter supplies the actual OS token through
/// `set_fcm_push_token` / `set_apns_push_token` after Firebase/APNs returns
/// it; local dev can inject the same token via env vars. Subsequent renders
/// short-circuit via `OnceLock` semantics inside `set_push_token_provider`.
pub(super) fn ensure_default_push_token_provider() {
    if crate::push::push_token_provider().is_some() {
        return;
    }
    #[cfg(target_arch = "wasm32")]
    {
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::WebPushTokenProvider::new(),
        ));
    }
    #[cfg(all(not(target_arch = "wasm32"), target_os = "android"))]
    {
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::FcmPushTokenProvider,
        ));
    }
    #[cfg(all(not(target_arch = "wasm32"), target_os = "ios"))]
    {
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::ApnsPushTokenProvider,
        ));
    }
    #[cfg(all(
        not(target_arch = "wasm32"),
        not(target_os = "android"),
        not(target_os = "ios")
    ))]
    {
        // Desktop / server builds: install the FCM provider as the
        // safe default. It reads `INKSON_FCM_PUSH_TOKEN`,
        // `FCM_PUSH_TOKEN`, or `CHASK_PUSH_KEY` for local bridge
        // testing, and otherwise reports "no token" without emitting a
        // placeholder to the gateway.
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::FcmPushTokenProvider,
        ));
    }
}
