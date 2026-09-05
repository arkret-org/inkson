//! Notifications - network-driven action handlers (refresh, mark-all-read,
//! and the invite-accept flow). These own the `spawn`/IO plumbing that the
//! panel buttons trigger; all pure projection logic lives in
//! [`super::model`].

use std::collections::BTreeMap;

use dioxus::prelude::*;

use super::model::{
    JoinedRealmIds, UiNotification, UiNotificationAction, apply_notification_snapshot_to_store,
    apply_sync_projection_to_store, hydrate_notifications_with_privacy_gate,
    notification_id_for_dedupe, read_cursor_targets,
};
use crate::notification_rules::{dnd_settings_from_account_data, push_rules_from_account_data};
use crate::state::LocalStateStore;
use crate::transport::auth::{with_authed_api, with_event_submitter};
use crate::views::helpers::short_protocol_id;

pub(crate) fn refresh_notifications(
    base_url: String,
    session_credential: Signal<String>,
    authority: arkret_sdk::AccountId,
    mut state_store: SyncSignal<LocalStateStore>,
    mut notifications: Signal<Vec<UiNotification>>,
    mut status_msg: Signal<String>,
) {
    spawn(async move {
        let session_credential = session_credential();
        match with_authed_api(&base_url, session_credential, |api| async move {
            let http = api.sdk_http_client()?;
            let response = crate::client_core::account_subscribe_snapshot(&http, None).await?;
            // `invite-addressing.md` §7 - the notify branch's durable carrier is
            // the holder-private `ak.account.invite_delivery` cell, and the
            // account-subscribe stream never carries CAS-only cells. The live
            // to-device fanout is a wake, not the record of truth, so a surface
            // that renders invites has to read the cell itself; otherwise an
            // invite whose wake was missed stays invisible until the next cold
            // start, and the visible refresh control cannot recover it. This is
            // the same recovery the sync engine performs on its initial step. A
            // failed read must not take the rest of the refresh down with it.
            let delivery_cell = match crate::transport::account::account_data_snapshot(
                &http,
                arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY,
            )
            .await
            {
                Ok(snapshot) => snapshot.entry.map(|entry| entry.content),
                Err(error) => {
                    tracing::debug!(?error, "invite-delivery notification recovery deferred");
                    None
                }
            };
            Ok((response, delivery_cell))
        })
        .await
        {
            Ok((response, delivery_cell)) => {
                let principal_id = state_store.read().active_principal_id().unwrap_or_default();
                let push_rules =
                    push_rules_from_account_data(&authority, &response.updates.account_data);
                let account_dnd =
                    dnd_settings_from_account_data(&authority, &response.updates.account_data);
                let joined_realms =
                    JoinedRealmIds::from_realm_entries(&response.realm_entries, &principal_id);
                let inbox_states =
                    crate::account_data::notification_inbox_states_from_account_data_events(
                        &authority,
                        &response.updates.account_data,
                    );
                let hydrated = {
                    let mut store = state_store.write();
                    if let Some(content) = &delivery_cell {
                        store.save_invite_delivery_cell(content);
                    }
                    let raw_notifications =
                        apply_notification_snapshot_to_store(&mut store, &response, &joined_realms);
                    apply_notification_inbox_states(&mut store, &inbox_states);
                    let local_state = store.load();
                    let effective_dnd = local_state
                        .notification_dnd_settings
                        .as_ref()
                        .or(account_dnd.as_ref());
                    let privacy_gate =
                        crate::sidecar::SidecarPrivacyGate::from_store(&store, &principal_id);
                    hydrate_notifications_with_privacy_gate(
                        raw_notifications,
                        &local_state,
                        &principal_id,
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

/// Archive / dismiss one notification and synchronize that decision to the
/// holder's other devices.
///
/// `read` / `unread` stay on the read cursor; only these two states belong in
/// `ak.notifications.inbox.<notification_id>`
/// (`zh/discovery/client-preferences.md` §3.2). The local projection flips
/// first and stays flipped: the cross-device write is convergence, not the
/// authority for this device.
#[allow(clippy::too_many_arguments)]
pub(crate) fn set_notification_inbox_state(
    base_url: String,
    session_credential: String,
    authority: arkret_sdk::AccountId,
    actor_id: String,
    device_id: String,
    notification_id: String,
    state: arkret_sdk::NotificationInboxState,
    mut state_store: SyncSignal<LocalStateStore>,
    mut notifications: Signal<Vec<UiNotification>>,
    mut status_msg: Signal<String>,
) {
    notifications.with_mut(|items| {
        if let Some(entry) = items
            .iter_mut()
            .find(|candidate| candidate.id == notification_id)
        {
            entry.archived = true;
        }
    });
    state_store
        .write()
        .set_notification_archived(notification_id.clone(), true);

    if actor_id.trim().is_empty() || device_id.trim().is_empty() {
        return;
    }
    spawn(async move {
        let candidate = match build_notification_inbox_candidate(
            &actor_id,
            &device_id,
            &notification_id,
            state,
        ) {
            Ok(candidate) => candidate,
            Err(error) => {
                status_msg.set(format!(
                    "Notification archived locally; cross-device sync unavailable: {error:#}"
                ));
                return;
            }
        };
        let account_data_key = candidate.account_data_key();
        match with_event_submitter(&base_url, session_credential, |submitter| async move {
            crate::transport::account::update_account_data_with_merge(
                &submitter,
                &account_data_key,
                |snapshot| {
                    crate::account_data::merge_notification_inbox_account_data(
                        &authority,
                        &account_data_key,
                        &candidate,
                        snapshot.entry.as_ref(),
                    )
                },
            )
            .await
        })
        .await
        {
            Ok(_) => status_msg.set("Notification archived on all your devices.".to_owned()),
            Err(err) => status_msg.set(format!(
                "Notification archived locally; cross-device sync failed: {}",
                err.display()
            )),
        }
    });
}

/// Fold the holder's cross-device inbox states into the local projection.
///
/// Both `dismissed` and `archived` hide the row here; the distinction the key
/// carries is preserved on the wire for clients that render them apart.
fn apply_notification_inbox_states(
    store: &mut LocalStateStore,
    inbox_states: &[arkret_sdk::NotificationInboxValue],
) {
    store.batch(|store| {
        for value in inbox_states {
            store.set_notification_archived(value.notification_id.as_str().to_owned(), true);
        }
    });
}

fn build_notification_inbox_candidate(
    actor_id: &str,
    device_id: &str,
    notification_id: &str,
    state: arkret_sdk::NotificationInboxState,
) -> anyhow::Result<arkret_sdk::NotificationInboxValue> {
    let actor = arkret_sdk::Did::new(actor_id.trim().to_owned())
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let updated_hlc =
        crate::signing_stamp::issue_account_data_hlc(actor.as_str(), device_id.trim())?;
    crate::account_data::notification_inbox_value(
        notification_id,
        state,
        updated_hlc.as_str(),
        device_id.trim(),
    )
}

pub(crate) fn run_notification_action(
    base_url: String,
    session_credential: Signal<String>,
    authority: arkret_sdk::AccountId,
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
        } => accept_invite_notification(
            base_url,
            session_credential,
            authority,
            state_store,
            notifications,
            status_msg,
            notification_id,
            realm_id,
            invite_id,
            invite_token,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn accept_invite_notification(
    base_url: String,
    session_credential: Signal<String>,
    authority: arkret_sdk::AccountId,
    mut state_store: SyncSignal<LocalStateStore>,
    mut notifications: Signal<Vec<UiNotification>>,
    mut status_msg: Signal<String>,
    notification_id: String,
    realm_id: String,
    invite_id: String,
    invite_token: Option<String>,
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
            // Catch-up path: the live `ak.account_data.update` fanout may have
            // raced ahead of this accept (or this device was offline), so when
            // no token is in local state pull the server-held delivery cell
            // once and use its credential directly.
            let mut invite_token = invite_token;
            let mut delivery_cell = None;
            if invite_token.is_none() {
                let snapshot = crate::transport::account::account_data_snapshot(
                    &api.sdk_http_client()?,
                    arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY,
                )
                .await?;
                if let Some(content) = snapshot.entry.map(|entry| entry.content) {
                    invite_token =
                        crate::state::invite_credentials::invite_delivery_entries_from_cell(
                            &content,
                        )
                        .into_iter()
                        .find(|(entry_invite_id, credential)| {
                            entry_invite_id == &invite_id
                                && !credential
                                    .expires_at
                                    .is_some_and(|expires_at| expires_at <= chrono::Utc::now())
                        })
                        .map(|(_, credential)| credential.invite_token);
                    delivery_cell = Some(content);
                }
            }
            // This notification is raised from a directed private invite
            // delivery, so the Invite stores this account and the accept both
            // joins the Realm and releases the inviter Realm's live-target slot
            // for it. A third-party invite reaches acceptance through
            // `ak.invite.claim` instead and carries no account here.
            let invitee_account_id = arkret_sdk::AccountId::new(
                account.principal_id.clone(),
                crate::operation::authoring_station_id()?,
            );
            let (submit, accepted_title) = api
                .accept_realm_invite(
                    &accepted_realm_for_api,
                    account.principal_id.as_str(),
                    &invite_id,
                    invite_token.as_deref(),
                    Some(invitee_account_id),
                )
                .await?;
            // The accepted Event is the authoritative join boundary, but the
            // client is not ready to author Realm events until it has verified
            // and durably pinned the accepted governance closure. Establish
            // that checkpoint before exposing the final Joined status.
            let checkpoint_error =
                crate::mls::creator_bootstrap::ensure_realm_governance_checkpoint(
                    &api,
                    crate::app::runtime_adapter::state_store_handle(state_store),
                    &accepted_realm_for_api,
                )
                .await
                .err();
            accepted_status.set(if let Some(error) = checkpoint_error.as_deref() {
                format!(
                    "Joined Realm {}. Governance verification pending: {error}",
                    short_protocol_id(&accepted_realm_for_api)
                )
            } else {
                format!(
                    "Joined Realm {}.",
                    short_protocol_id(&accepted_realm_for_api)
                )
            });
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
            Ok::<_, anyhow::Error>((sync, accepted_title, delivery_cell, checkpoint_error))
        })
        .await
        {
            Ok((Ok(sync), accepted_title, delivery_cell, checkpoint_error)) => {
                let principal_id = state_store.read().active_principal_id().unwrap_or_default();
                let push_rules =
                    push_rules_from_account_data(&authority, &sync.updates.account_data);
                let account_dnd =
                    dnd_settings_from_account_data(&authority, &sync.updates.account_data);
                let hidden_realms =
                    JoinedRealmIds::from_realm_entries(&sync.realm_entries, &principal_id)
                        .joined_now(accepted_realm.clone());
                let mut realm_title_hints = BTreeMap::new();
                // The Realm title comes from the directory resolve the accept
                // flow itself performed — the Invite object and the
                // notification carry no label (`governance-objects.md` §5.3).
                if let Some(title) = accepted_title
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    realm_title_hints.insert(accepted_realm.clone(), title.to_owned());
                }

                let hydrated = {
                    let mut store = state_store.write();
                    if let Some(content) = &delivery_cell {
                        // Persist the catch-up read so future hydration and
                        // sibling devices' accepts find the credential locally.
                        store.save_invite_delivery_cell(content);
                    }
                    apply_sync_projection_to_store(&mut store, &sync, &realm_title_hints);
                    let raw_notifications =
                        apply_notification_snapshot_to_store(&mut store, &sync, &hidden_realms);
                    if raw_notifications.iter().all(|notification| {
                        notification_id_for_dedupe(notification).as_deref()
                            != Some(&notification_id)
                    }) {
                        store.set_notification_archived(notification_id.clone(), true);
                    }
                    let local_state = store.load();
                    let effective_dnd = local_state
                        .notification_dnd_settings
                        .as_ref()
                        .or(account_dnd.as_ref());
                    let principal_id = store.active_principal_id().unwrap_or_default();
                    let privacy_gate =
                        crate::sidecar::SidecarPrivacyGate::from_store(&store, &principal_id);
                    hydrate_notifications_with_privacy_gate(
                        raw_notifications,
                        &local_state,
                        &principal_id,
                        push_rules.as_ref(),
                        effective_dnd,
                        &privacy_gate,
                    )
                };
                notifications.set(hydrated);
                status_msg.set(if let Some(error) = checkpoint_error.as_deref() {
                    format!(
                        "Joined Realm {}. Governance verification pending: {error}",
                        short_protocol_id(&accepted_realm)
                    )
                } else {
                    format!("Joined Realm {}.", short_protocol_id(&accepted_realm))
                });
            }
            Ok((Err(sync_err), ..)) => {
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
