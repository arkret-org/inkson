//! Notifications - network-driven action handlers (refresh, mark-all-read,
//! and the invite-accept flow). These own the `spawn`/IO plumbing that the
//! panel buttons trigger; all pure projection logic lives in
//! [`super::model`].

use std::collections::BTreeMap;

use dioxus::prelude::*;

use super::model::{
    UiNotification, UiNotificationAction, append_invite_notifications,
    apply_sync_projection_to_store, drop_joined_invite_notifications,
    hydrate_notifications_with_privacy_gate, joined_realm_ids, merge_invite_notifications,
    notification_id_for_dedupe, raw_notifications_from_sources, read_cursor_targets,
    realm_title_hints_from_invites,
};
use crate::api_error::is_auth_expired_error;
use crate::notification_rules::{dnd_settings_from_account_data, push_rules_from_account_data};
use crate::state::LocalStateStore;
use crate::transport::TransportClient;
use crate::transport::auth::{with_authed_api, with_event_submitter};
use crate::views::helpers::short_protocol_id;

pub(crate) async fn optional_invite_notifications(
    api: &TransportClient,
) -> anyhow::Result<Vec<arkret_models_collaboration::governance::operation_wire::Invite>> {
    match async { crate::transport::account::invites(&api.sdk_http_client()?).await }.await {
        Ok(response) => Ok(response.invites),
        Err(error) if is_auth_expired_error(&error) => Err(error),
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
    mut state_store: SyncSignal<LocalStateStore>,
    mut notifications: Signal<Vec<UiNotification>>,
    mut status_msg: Signal<String>,
) {
    spawn(async move {
        let session_credential = session_credential();
        match with_authed_api(&base_url, session_credential, |api| async move {
            let http = api.sdk_http_client()?;
            let response = crate::client_core::account_subscribe_snapshot(&http, None).await?;
            let invite_notifications = optional_invite_notifications(&api).await?;
            Ok::<_, anyhow::Error>((response, invite_notifications))
        })
        .await
        {
            Ok((response, invite_notifications)) => {
                let account_did = state_store.read().active_account_did().unwrap_or_default();
                let push_rules =
                    push_rules_from_account_data(&account_did, &response.updates.account_data);
                let account_dnd =
                    dnd_settings_from_account_data(&account_did, &response.updates.account_data);
                let mut raw_notifications = raw_notifications_from_sources(
                    Some(&response.updates.notifications),
                    &response.updates.account_data,
                );
                let joined_realms = joined_realm_ids(&response, &account_did);
                merge_invite_notifications(
                    &mut raw_notifications,
                    invite_notifications,
                    &joined_realms,
                );
                let hydrated = {
                    let mut store = state_store.write();
                    store.ingest_to_device_messages(&response.updates.to_device);
                    store.save_notification_projection(raw_notifications.clone());
                    let local_state = store.load();
                    let effective_dnd = local_state
                        .notification_dnd_settings
                        .as_ref()
                        .or(account_dnd.as_ref());
                    let privacy_gate =
                        crate::sidecar::SidecarPrivacyGate::from_store(&store, &account_did);
                    hydrate_notifications_with_privacy_gate(
                        raw_notifications,
                        &local_state,
                        push_rules.as_ref(),
                        effective_dnd,
                        &privacy_gate,
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
    mut state_store: SyncSignal<LocalStateStore>,
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
            Ok(Vec::new())
        } else {
            read_targets
                .into_iter()
                .map(|target| {
                    store.build_read_cursor_candidate(
                        actor_id.clone(),
                        device_id.clone(),
                        target.realm_id,
                        target.strand_id,
                        target.event_id,
                    )
                })
                .collect::<anyhow::Result<Vec<_>>>()
        }
    };
    let markers = match markers {
        Ok(markers) => markers,
        Err(error) => {
            status_msg.set(format!(
                "All loaded notifications marked read locally; read cursor creation failed: {error:#}"
            ));
            return;
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
        match with_event_submitter(&base_url, session_credential, |sub| async move {
            let mut outcomes = Vec::with_capacity(markers.len());
            for marker in markers {
                outcomes.push(
                    crate::transport::account::submit_read_cursor_advance(&sub, &marker).await?,
                );
            }
            Ok::<_, anyhow::Error>(outcomes)
        })
        .await
        {
            Ok(outcomes) => {
                let persisted = outcomes.into_iter().try_for_each(|outcome| {
                    state_store
                        .write()
                        .apply_read_cursor_outcome(outcome)
                        .map(|_| ())
                });
                match persisted {
                    Ok(()) => status_msg.set(format!(
                        "All loaded notifications marked read; synced {marker_count} read cursor(s)."
                    )),
                    Err(error) => status_msg.set(format!(
                        "Read cursors synced but local projection update failed: {error:#}"
                    )),
                }
            }
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
    mut state_store: SyncSignal<LocalStateStore>,
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
        });
        if !read || actor_id.trim().is_empty() || device_id.trim().is_empty() {
            None
        } else if let Some(event_id) = notification.source_event_id.clone()
            && !notification.realm_id.trim().is_empty()
        {
            match store.build_read_cursor_candidate(
                actor_id.clone(),
                device_id.clone(),
                notification.realm_id.clone(),
                notification.strand_id.clone(),
                event_id,
            ) {
                Ok(marker) => Some(marker),
                Err(error) => {
                    status_msg.set(format!(
                        "Notification marked read locally; read cursor creation failed: {error:#}"
                    ));
                    return;
                }
            }
        } else {
            None
        }
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
        match with_event_submitter(&base_url, session_credential, |sub| async move {
            crate::transport::account::submit_read_cursor_advance(&sub, &marker).await
        })
        .await
        {
            Ok(outcome) => match state_store.write().apply_read_cursor_outcome(outcome) {
                Ok(_) => status_msg.set("Notification marked read and synced.".to_owned()),
                Err(error) => status_msg.set(format!(
                    "Read cursor synced but local projection update failed: {error:#}"
                )),
            },
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
    state_store: SyncSignal<LocalStateStore>,
    notifications: Signal<Vec<UiNotification>>,
    status_msg: Signal<String>,
    notification_id: String,
    action: UiNotificationAction,
) {
    match action {
        UiNotificationAction::AcceptInvite {
            realm_id,
            invite_id,
            invite_token,
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
            invite_token,
            realm_label,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn accept_invite_notification(
    base_url: String,
    session_credential: Signal<String>,
    mut state_store: SyncSignal<LocalStateStore>,
    mut notifications: Signal<Vec<UiNotification>>,
    mut status_msg: Signal<String>,
    notification_id: String,
    realm_id: String,
    invite_id: String,
    invite_token: Option<String>,
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
        let mut accepted_status = status_msg;
        match with_authed_api(&base_url, session_credential, |api| async move {
            let account = crate::transport::account::account_me(&api.sdk_http_client()?).await?;
            let submit = api
                .accept_realm_invite(
                    &accepted_realm_for_api,
                    &account.did,
                    &invite_id,
                    invite_token.as_deref(),
                )
                .await?;
            // The accepted Event is the authoritative join boundary. Account
            // snapshot refresh and presence-key prefetch may take longer on a
            // large account, so acknowledge the successful join before doing
            // that best-effort convergence work.
            accepted_status.set(format!(
                "Joined Realm {}.",
                short_protocol_id(&accepted_realm_for_api)
            ));
            // The SDK's account-subscribe surface no longer accepts a
            // per-request wait-for option (client-sync.md: X-Arkret-Wait-For
            // belongs to read endpoints); the accepted invite folds in via the
            // snapshot or a following delta.
            let _ = &submit.cursor;
            let read_api = api.clone();
            let sync = match read_api.sdk_http_client() {
                Ok(http) => crate::client_core::account_subscribe_snapshot(&http, None).await,
                Err(error) => Err(error),
            };
            let invite_notifications = optional_invite_notifications(&read_api).await?;
            Ok::<_, anyhow::Error>((sync, invite_notifications))
        })
        .await
        {
            Ok((Ok(sync), invite_notifications)) => {
                let account_did = state_store.read().active_account_did().unwrap_or_default();
                let push_rules =
                    push_rules_from_account_data(&account_did, &sync.updates.account_data);
                let account_dnd =
                    dnd_settings_from_account_data(&account_did, &sync.updates.account_data);
                let mut hidden_realms = joined_realm_ids(&sync, &account_did);
                hidden_realms.insert(accepted_realm.clone());
                let mut realm_title_hints = BTreeMap::new();
                if let Some(label) = realm_label
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    realm_title_hints.insert(accepted_realm.clone(), label.to_owned());
                }

                let mut raw_notifications = raw_notifications_from_sources(
                    Some(&sync.updates.notifications),
                    &sync.updates.account_data,
                );
                for (realm_id, title) in realm_title_hints_from_invites(&invite_notifications) {
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
                    let account_did = store.active_account_did().unwrap_or_default();
                    let privacy_gate =
                        crate::sidecar::SidecarPrivacyGate::from_store(&store, &account_did);
                    hydrate_notifications_with_privacy_gate(
                        raw_notifications,
                        &local_state,
                        push_rules.as_ref(),
                        effective_dnd,
                        &privacy_gate,
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
    state_store: &mut SyncSignal<LocalStateStore>,
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
