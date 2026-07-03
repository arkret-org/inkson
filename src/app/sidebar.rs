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

pub(super) fn load_direct_contacts_for_sidebar(
    base: String,
    api_token: String,
    mut direct_contact_rows: Signal<Vec<crate::models::ContactListRow>>,
    mut direct_contacts_loaded: Signal<bool>,
    mut status: Signal<String>,
) {
    if api_token.trim().is_empty() {
        direct_contact_rows.set(Vec::new());
        direct_contacts_loaded.set(false);
        return;
    }

    direct_contacts_loaded.set(true);
    spawn(async move {
        match crate::views::helpers::with_authed_api(&base, api_token, |api| async move {
            api.contacts().await
        })
        .await
        {
            Ok(response) => direct_contact_rows.set(response.contacts),
            Err(err) => {
                direct_contacts_loaded.set(false);
                status.set(format!("direct conversations: {}", err.display()));
            }
        }
    });
}

pub(super) fn toggle_sidebar_realm_pin(
    realm_id: String,
    existing: Option<crate::account_data::RealmRemark>,
    next_pinned: bool,
    mut state_store: Signal<LocalStateStore>,
    base_url: String,
    api_token: String,
    mut status: Signal<String>,
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
    let action_status = if next_pinned {
        crate::i18n::tr("realm.pinned")
    } else {
        crate::i18n::tr("realm.unpin")
    };
    status.set(format!("{action_status}: {}", short_protocol_id(&realm_id)));
    crate::views::settings::push_realm_remark_account_data_with_failure_status(
        base_url, api_token, realm_id, next, status,
    );
}

pub(super) fn toggle_sidebar_contact_pin(
    actor_id: String,
    existing: Option<crate::account_data::ContactRemark>,
    next_pinned: bool,
    mut state_store: Signal<LocalStateStore>,
    base_url: String,
    api_token: String,
    mut status: Signal<String>,
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
    let action_status = if next_pinned {
        crate::i18n::tr("contact.pinned")
    } else {
        crate::i18n::tr("contact.unpinned")
    };
    let actor_label = crate::views::helpers::display_name_for_did(&state_store.read(), &actor_id);
    status.set(format!("{action_status}: {actor_label}"));
    crate::views::settings::push_contact_remark_account_data(base_url, api_token, actor_id, next);
}

pub(super) fn leave_sidebar_realm(
    base_url: String,
    api_token: String,
    realm_id: String,
    account_did: String,
    mut state_store: Signal<LocalStateStore>,
    mut realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    mut selected_realm_id: Signal<String>,
    mut sync_cursor: Signal<String>,
    mut status: Signal<String>,
) {
    // Realm membership events are authored by the account/principal DID — the
    // server rejects any event whose `actor_id` differs from the authenticated
    // session actor
    // session actor (`actor_session_mismatch`). The local device DID is not the
    // session actor, so it must not be used here.
    let actor_id = account_did.trim().to_owned();
    if actor_id.is_empty() {
        status.set("Leave Realm failed: account is not connected".to_owned());
        return;
    }
    let current_nodes = realm_tree_nodes();
    let mut ids_to_forget = descendant_node_ids(&current_nodes, &realm_id);
    if ids_to_forget.is_empty() {
        ids_to_forget.push(realm_id.clone());
    }
    let realm_label = short_protocol_id(&realm_id);
    status.set(format!("Leaving Realm: {realm_label}"));
    spawn(async move {
        let realm_for_api = realm_id.clone();
        match crate::views::helpers::with_authed_api(&base_url, api_token, |api| async move {
            api.leave_realm(&realm_for_api, &actor_id).await
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
                sync_cursor.set("-".to_owned());
                status.set(format!("Left Realm: {realm_label}"));
            }
            Err(err) => status.set(format!(
                "Leave Realm failed for {realm_label}: {}",
                err.display()
            )),
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

/// Parse a `_cokret/self/authz/check` body into a simple allow boolean.
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

/// Lazily probe whether `actor` may add members (`ck.invite.create`) or edit
/// settings (`ck.realm.update`) on `realm_id`, caching the verdict in
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
        let perms = match crate::views::helpers::authed_api_with_sync(&base_url, api_token, None) {
            Ok(api) => {
                let invite = api
                    .authz_check_raw(&actor, "ck.invite.create", &realm_id)
                    .await;
                let settings = api
                    .authz_check_raw(&actor, "ck.realm.update", &realm_id)
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
    state_store: Signal<LocalStateStore>,
    mut direct_contact_rows: Signal<Vec<crate::models::ContactListRow>>,
    mut direct_contacts_loaded: Signal<bool>,
    mut status: Signal<String>,
) {
    let peer_label = crate::views::helpers::display_name_for_did(&state_store.read(), &peer);
    status.set(format!("Deleting contact: {peer_label}"));
    spawn(async move {
        let peer_for_api = peer.clone();
        match crate::views::helpers::with_authed_api(&base_url, api_token, |api| async move {
            api.tombstone_contact(&peer_for_api, false).await
        })
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
                status.set(format!("Deleted contact: {peer_label}"));
            }
            Err(err) => status.set(format!(
                "Delete contact failed for {peer_label}: {}",
                err.display()
            )),
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
        // safe default. It reads `YOUGEN_FCM_PUSH_TOKEN`,
        // `FCM_PUSH_TOKEN`, or `CHASK_PUSH_KEY` for local bridge
        // testing, and otherwise reports "no token" without emitting a
        // placeholder to the gateway.
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::FcmPushTokenProvider,
        ));
    }
}
