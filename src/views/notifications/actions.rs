//! Notifications - network-driven action handlers (refresh, mark-all-read,
//! and the invite-accept flow). These own the `spawn`/IO plumbing that the
//! panel buttons trigger; all pure projection logic lives in
//! [`super::model`].

use std::collections::BTreeMap;

use dioxus::prelude::*;
use serde_json::Value;

use super::model::{
    UiNotification, UiNotificationAction, append_invite_notifications,
    apply_sync_projection_to_store, drop_joined_invite_notifications, hydrate_notifications,
    joined_realm_ids, merge_invite_notifications, notification_id_for_dedupe,
    raw_notifications_from_sources, read_cursor_targets, realm_title_hints_from_values,
};
use crate::api::{CokretApi, is_auth_expired_error};
use crate::local_state::LocalStateStore;
use crate::notification_rules::{dnd_settings_from_account_data, push_rules_from_account_data};
use crate::views::helpers::{short_protocol_id, with_authed_api};

/// Project the SDK `AuthzInviteList.invites` (typed `Invite` rows) into the
/// `Vec<Value>` shape the local notification pipeline folds through lenient
/// JSON accessors.
fn invites_to_values(invites: Vec<cokret_sdk::models::Invite>) -> Vec<Value> {
    invites
        .into_iter()
        .filter_map(|invite| serde_json::to_value(invite).ok())
        .collect()
}

pub(crate) async fn optional_invite_notifications(api: &CokretApi) -> anyhow::Result<Vec<Value>> {
    match api.invites().await {
        Ok(response) => Ok(invites_to_values(response.invites)),
        Err(error) if is_auth_expired_error(&error) => {
            match crate::session::refresh_current_session().await {
                crate::session::CurrentSessionRefresh::Credential(refreshed) => {
                    let refreshed_api = api.clone().with_bearer(refreshed);
                    Ok(invites_to_values(refreshed_api.invites().await?.invites))
                }
                crate::session::CurrentSessionRefresh::SignInRequired { reason } => {
                    Err(anyhow::anyhow!(
                        "session refresh cannot continue locally: {reason}; invites: {error}"
                    ))
                }
                crate::session::CurrentSessionRefresh::LoginRequired { reason } => Err(
                    anyhow::anyhow!("session refresh requires login: {reason}; invites: {error}"),
                ),
                crate::session::CurrentSessionRefresh::RetryLater { reason } => Err(
                    anyhow::anyhow!("session refresh pending: {reason}; invites: {error}"),
                ),
            }
        }
        Err(error) => {
            tracing::debug!(
                ?error,
                "notification refresh could not load invite notifications"
            );
            Ok(Vec::new())
        }
    }
}

pub(crate) fn refresh_notifications(
    base_url: String,
    session_credential: Signal<String>,
    mut state_store: Signal<LocalStateStore>,
    mut notifications: Signal<Vec<UiNotification>>,
    mut status_msg: Signal<String>,
) {
    spawn(async move {
        let session_credential = session_credential();
        match with_authed_api(&base_url, session_credential, |api| async move {
            let response = api.account_subscribe_snapshot(None).await?;
            let invite_notifications = optional_invite_notifications(&api).await?;
            Ok::<_, anyhow::Error>((response, invite_notifications))
        })
        .await
        {
            Ok((response, invite_notifications)) => {
                let push_rules = push_rules_from_account_data(&response.account_data);
                let account_dnd = dnd_settings_from_account_data(&response.account_data);
                let mut raw_notifications = raw_notifications_from_sources(
                    Some(&response.notifications),
                    &response.account_data,
                );
                let joined_realms = joined_realm_ids(&response);
                merge_invite_notifications(
                    &mut raw_notifications,
                    invite_notifications,
                    &joined_realms,
                );
                let hydrated = {
                    let mut store = state_store.write();
                    store.ingest_to_device_messages(&response.to_device);
                    store.save_notification_projection(raw_notifications.clone());
                    let local_state = store.load();
                    let effective_dnd = local_state
                        .notification_dnd_settings
                        .as_ref()
                        .or(account_dnd.as_ref());
                    hydrate_notifications(
                        raw_notifications,
                        &local_state,
                        push_rules.as_ref(),
                        effective_dnd,
                    )
                };
                notifications.set(hydrated);
                status_msg.set(String::new());
            }
            Err(err) => {
                status_msg.set(format!("Notification refresh: {}", err.display()));
            }
        }
    });
}

pub(crate) fn mark_all_notifications_read(
    base_url: String,
    session_credential: String,
    actor_id: String,
    device_id: String,
    mut state_store: Signal<LocalStateStore>,
    mut notifications: Signal<Vec<UiNotification>>,
    mut status_msg: Signal<String>,
) {
    let snapshot = notifications();
    let ids = snapshot
        .iter()
        .map(|notification| notification.id.clone())
        .collect::<Vec<_>>();
    let read_targets = read_cursor_targets(&snapshot);
    for notification in notifications.write().iter_mut() {
        notification.read = true;
    }
    // Perf (P1): "mark all read" used to flush the whole local
    // state once per notification. Coalesce into a single flush.
    let markers = {
        let mut store = state_store.write();
        store.batch(|store| {
            for id in ids {
                store.set_notification_read(id, true);
            }
        });
        if actor_id.trim().is_empty() || device_id.trim().is_empty() {
            Vec::new()
        } else {
            read_targets
                .into_iter()
                .map(|target| {
                    store.save_read_cursor(
                        actor_id.clone(),
                        device_id.clone(),
                        target.realm_id,
                        target.strand_id,
                        target.event_id,
                    )
                })
                .collect::<Vec<_>>()
        }
    };
    if markers.is_empty() {
        status_msg.set("All loaded notifications marked read locally.".to_owned());
        return;
    }

    status_msg.set(format!(
        "All loaded notifications marked read; syncing {} read cursor(s)...",
        markers.len()
    ));
    spawn(async move {
        let marker_count = markers.len();
        match with_authed_api(&base_url, session_credential, |api| async move {
            for marker in markers {
                api.submit_read_cursor_advance(&marker).await?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        {
            Ok(()) => status_msg.set(format!(
                "All loaded notifications marked read; synced {marker_count} read cursor(s)."
            )),
            Err(err) => status_msg.set(format!(
                "All loaded notifications marked read locally; read cursor sync failed: {}",
                err.display()
            )),
        }
    });
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn mark_notification_read_state(
    base_url: String,
    session_credential: String,
    actor_id: String,
    device_id: String,
    notification: UiNotification,
    read: bool,
    mut state_store: Signal<LocalStateStore>,
    mut notifications: Signal<Vec<UiNotification>>,
    mut status_msg: Signal<String>,
) {
    let notification_id = notification.id.clone();
    notifications.with_mut(|items| {
        if let Some(entry) = items
            .iter_mut()
            .find(|candidate| candidate.id == notification_id)
        {
            entry.read = read;
        }
    });
    let marker = {
        let mut store = state_store.write();
        store.batch(|store| {
            store.set_notification_read(notification_id.clone(), read);
            if !read || actor_id.trim().is_empty() || device_id.trim().is_empty() {
                return None;
            }
            let Some(event_id) = notification.source_event_id.clone() else {
                return None;
            };
            if notification.realm_id.trim().is_empty() {
                return None;
            }
            Some(store.save_read_cursor(
                actor_id.clone(),
                device_id.clone(),
                notification.realm_id.clone(),
                notification.strand_id.clone(),
                event_id,
            ))
        })
    };
    if !read {
        status_msg.set("Notification marked unread locally.".to_owned());
        return;
    }
    let Some(marker) = marker else {
        status_msg.set("Notification marked read locally.".to_owned());
        return;
    };

    status_msg.set("Notification marked read; syncing read cursor...".to_owned());
    spawn(async move {
        match with_authed_api(&base_url, session_credential, |api| async move {
            api.submit_read_cursor_advance(&marker).await?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        {
            Ok(()) => status_msg.set("Notification marked read and synced.".to_owned()),
            Err(err) => status_msg.set(format!(
                "Notification marked read locally; read cursor sync failed: {}",
                err.display()
            )),
        }
    });
}

pub(crate) fn run_notification_action(
    base_url: String,
    session_credential: Signal<String>,
    state_store: Signal<LocalStateStore>,
    notifications: Signal<Vec<UiNotification>>,
    status_msg: Signal<String>,
    notification_id: String,
    action: UiNotificationAction,
) {
    match action {
        UiNotificationAction::AcceptInvite {
            realm_id,
            invite_id,
            realm_label,
        } => accept_invite_notification(
            base_url,
            session_credential,
            state_store,
            notifications,
            status_msg,
            notification_id,
            realm_id,
            invite_id,
            realm_label,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn accept_invite_notification(
    base_url: String,
    session_credential: Signal<String>,
    mut state_store: Signal<LocalStateStore>,
    mut notifications: Signal<Vec<UiNotification>>,
    mut status_msg: Signal<String>,
    notification_id: String,
    realm_id: String,
    invite_id: String,
    realm_label: Option<String>,
) {
    let accepted_realm = realm_id;
    status_msg.set(format!(
        "Accepting Realm invite for {}...",
        short_protocol_id(&accepted_realm)
    ));
    spawn(async move {
        let accepted_realm_for_api = accepted_realm.clone();
        let session_credential = session_credential();
        match with_authed_api(&base_url, session_credential, |api| async move {
            let account = api.account_me().await?;
            let submit = api
                .accept_realm_invite(&accepted_realm_for_api, &account.did, &invite_id)
                .await?;
            let read_api = api.clone().with_wait_for(submit.cursor);
            let sync = read_api.account_subscribe_snapshot(None).await;
            let invite_notifications = optional_invite_notifications(&read_api).await?;
            Ok::<_, anyhow::Error>((sync, invite_notifications))
        })
        .await
        {
            Ok((Ok(sync), invite_notifications)) => {
                let push_rules = push_rules_from_account_data(&sync.account_data);
                let account_dnd = dnd_settings_from_account_data(&sync.account_data);
                let mut hidden_realms = joined_realm_ids(&sync);
                hidden_realms.insert(accepted_realm.clone());
                let mut realm_title_hints = BTreeMap::new();
                if let Some(label) = realm_label
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    realm_title_hints.insert(accepted_realm.clone(), label.to_owned());
                }

                let mut raw_notifications =
                    raw_notifications_from_sources(Some(&sync.notifications), &sync.account_data);
                for (realm_id, title) in realm_title_hints_from_values(&raw_notifications) {
                    realm_title_hints.entry(realm_id).or_insert(title);
                }
                for (realm_id, title) in realm_title_hints_from_values(&invite_notifications) {
                    realm_title_hints.entry(realm_id).or_insert(title);
                }
                drop_joined_invite_notifications(&mut raw_notifications, &hidden_realms);
                append_invite_notifications(
                    &mut raw_notifications,
                    invite_notifications,
                    &hidden_realms,
                );
                if raw_notifications.iter().all(|notification| {
                    notification_id_for_dedupe(notification).as_deref() != Some(&notification_id)
                }) {
                    state_store
                        .write()
                        .set_notification_archived(notification_id.clone(), true);
                }
                let hydrated = {
                    let mut store = state_store.write();
                    apply_sync_projection_to_store(&mut store, &sync, &realm_title_hints);
                    store.save_notification_projection(raw_notifications.clone());
                    let local_state = store.load();
                    let effective_dnd = local_state
                        .notification_dnd_settings
                        .as_ref()
                        .or(account_dnd.as_ref());
                    hydrate_notifications(
                        raw_notifications,
                        &local_state,
                        push_rules.as_ref(),
                        effective_dnd,
                    )
                };
                notifications.set(hydrated);
                status_msg.set(format!(
                    "Joined Realm {}.",
                    short_protocol_id(&accepted_realm)
                ));
            }
            Ok((Err(sync_err), _invite_notifications)) => {
                hide_accepted_invite_notification(
                    &mut state_store,
                    &mut notifications,
                    &notification_id,
                    &accepted_realm,
                );
                status_msg.set(format!(
                    "Joined Realm {}. Refresh pending: {}",
                    short_protocol_id(&accepted_realm),
                    sync_err
                ));
            }
            Err(err) => {
                status_msg.set(format!("Accept invite failed: {}", err.display()));
            }
        }
    });
}

fn hide_accepted_invite_notification(
    state_store: &mut Signal<LocalStateStore>,
    notifications: &mut Signal<Vec<UiNotification>>,
    notification_id: &str,
    accepted_realm: &str,
) {
    state_store
        .write()
        .set_notification_archived(notification_id.to_owned(), true);
    notifications.with_mut(|items| {
        items.retain(|notification| {
            notification.id != notification_id
                && !(notification.kind == "invite" && notification.realm_id == accepted_realm)
        });
    });
}
