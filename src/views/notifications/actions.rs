//! Notifications - network-driven action handlers (refresh, mark-all-read,
//! and the invite-accept flow). These own the `spawn`/IO plumbing that the
//! panel buttons trigger; all pure projection logic lives in
//! [`super::model`].

use dioxus::prelude::*;

use super::model::{
    NotificationFeedback, UiNotification, UiNotificationAction,
    hydrate_notifications_with_privacy_gate, read_cursor_targets,
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
    mut status_msg: Signal<NotificationFeedback>,
) {
    let epoch = crate::identity::device_directory::session_cache_epoch();
    spawn(async move {
        let session_credential = session_credential();
        match with_authed_api(&base_url, session_credential, |api| async move {
            let http = api.sdk_http_client()?;
            // `invite-addressing.md` §7 - the notify branch's durable carrier is
            // the holder-private `ak.account.invite_delivery` cell, and the
            // account-subscribe stream may race with this refresh. The live
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
            Ok(delivery_cell)
        })
        .await
        {
            Ok(delivery_cell) => {
                if epoch != crate::identity::device_directory::session_cache_epoch()
                    || state_store.read().active_authority().as_ref() != Some(&authority)
                {
                    return;
                }
                let account_data = state_store.read().current_account_data_events();
                let principal_id = state_store.read().active_principal_id().unwrap_or_default();
                let push_rules = push_rules_from_account_data(&authority, &account_data);
                let account_dnd = dnd_settings_from_account_data(&authority, &account_data);
                let account_actor = arkret_sdk::ActorId::account(authority.clone());
                let hydrated = {
                    let mut store = state_store.write();
                    if let Some(content) = &delivery_cell {
                        store.save_invite_delivery_cell(content);
                    }
                    let raw_notifications = store.notification_projection();
                    for event in &account_data {
                        if let Err(error) = store.apply_notification_inbox_event(&authority, event)
                        {
                            tracing::warn!(%error, "notification inbox refresh retained its last accepted disposition");
                        }
                    }
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
                        Some(&account_actor),
                        push_rules.as_ref(),
                        effective_dnd,
                        &privacy_gate,
                    )
                };
                notifications.set(hydrated);
                status_msg.set(NotificationFeedback::default());
            }
            Err(err) => {
                status_msg.set(
                    NotificationFeedback::new("notifications.feedback.refresh_failed")
                        .with_api_error(err),
                );
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
    mut status_msg: Signal<NotificationFeedback>,
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
            status_msg.set(
                NotificationFeedback::new("notifications.feedback.all_cursor_failed")
                    .with("error", format!("{error:#}")),
            );
            return;
        }
    };
    if markers.is_empty() {
        status_msg.set(NotificationFeedback::new(
            "notifications.feedback.all_read_local",
        ));
        return;
    }

    status_msg.set(
        NotificationFeedback::new("notifications.feedback.all_read_syncing")
            .with("count", markers.len()),
    );
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
                    Ok(()) => status_msg.set(
                        NotificationFeedback::new("notifications.feedback.all_read_synced")
                            .with("count", marker_count),
                    ),
                    Err(error) => status_msg.set(
                        NotificationFeedback::new("notifications.feedback.all_projection_failed")
                            .with("error", format!("{error:#}")),
                    ),
                }
            }
            Err(err) => status_msg.set(
                NotificationFeedback::new("notifications.feedback.all_sync_failed")
                    .with_api_error(err),
            ),
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
    mut status_msg: Signal<NotificationFeedback>,
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
                    status_msg.set(
                        NotificationFeedback::new("notifications.feedback.cursor_failed")
                            .with("error", format!("{error:#}")),
                    );
                    return;
                }
            }
        } else {
            None
        }
    };
    if !read {
        status_msg.set(NotificationFeedback::new(
            "notifications.feedback.unread_local",
        ));
        return;
    }
    let Some(marker) = marker else {
        status_msg.set(NotificationFeedback::new(
            "notifications.feedback.read_local",
        ));
        return;
    };

    status_msg.set(NotificationFeedback::new(
        "notifications.feedback.read_syncing",
    ));
    spawn(async move {
        match with_event_submitter(&base_url, session_credential, |sub| async move {
            crate::transport::account::submit_read_cursor_advance(&sub, &marker).await
        })
        .await
        {
            Ok(outcome) => match state_store.write().apply_read_cursor_outcome(outcome) {
                Ok(_) => status_msg.set(NotificationFeedback::new(
                    "notifications.feedback.read_synced",
                )),
                Err(error) => status_msg.set(
                    NotificationFeedback::new("notifications.feedback.projection_failed")
                        .with("error", format!("{error:#}")),
                ),
            },
            Err(err) => status_msg.set(
                NotificationFeedback::new("notifications.feedback.sync_failed").with_api_error(err),
            ),
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
    mut status_msg: Signal<NotificationFeedback>,
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

    if notification_id
        .parse::<arkret_wire::NotificationProjectionId>()
        .is_err()
        || actor_id.trim().is_empty()
        || device_id.trim().is_empty()
    {
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
                status_msg.set(
                    NotificationFeedback::new("notifications.feedback.archive_unavailable")
                        .with("error", format!("{error:#}")),
                );
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
            Ok(_) => status_msg.set(NotificationFeedback::new("notifications.feedback.archived")),
            Err(err) => status_msg.set(
                NotificationFeedback::new("notifications.feedback.archive_failed")
                    .with_api_error(err),
            ),
        }
    });
}

/// A restore is visible only after the holder's exact deletion is accepted.
#[allow(clippy::too_many_arguments)]
pub(crate) fn restore_notification_inbox(
    base_url: String,
    session_credential: String,
    authority: arkret_sdk::AccountId,
    notification_id: String,
    mut state_store: SyncSignal<LocalStateStore>,
    mut notifications: Signal<Vec<UiNotification>>,
    mut status_msg: Signal<NotificationFeedback>,
    mut restoring: Signal<std::collections::BTreeSet<String>>,
) {
    if restoring.read().contains(&notification_id) {
        return;
    }
    if notification_id
        .parse::<arkret_wire::NotificationProjectionId>()
        .is_err()
    {
        return;
    }
    let Ok(key) = crate::account_data::notification_inbox_account_data_key(&notification_id) else {
        return;
    };
    if state_store.read().active_authority().as_ref() != Some(&authority) {
        return;
    }
    let guard = match crate::transport::auth::AuthoringSessionFence::capture() {
        Ok(guard) => guard,
        Err(error) => {
            status_msg.set(
                NotificationFeedback::new("notifications.feedback.restore_failed")
                    .with("error", format!("{error:#}")),
            );
            return;
        }
    };
    restoring.write().insert(notification_id.clone());
    status_msg.set(NotificationFeedback::new(
        "notifications.feedback.restoring",
    ));
    spawn(async move {
        if guard.check().is_err() {
            restoring.write().remove(&notification_id);
            return;
        }
        let expected = authority.clone();
        let outcome = with_event_submitter(&base_url, session_credential, |submitter| async move {
            anyhow::ensure!(
                submitter.authority()? == &expected,
                "notification restore account changed"
            );
            crate::transport::account::delete_account_data_event(&submitter, &key).await
        })
        .await
        .map_err(|error| anyhow::anyhow!(error.display()));
        restoring.write().remove(&notification_id);
        if guard.check_session_identity().is_err()
            || state_store.read().active_authority().as_ref() != Some(&authority)
        {
            return;
        }
        let outcome = outcome.and_then(|event| {
            anyhow::ensure!(
                state_store
                    .write()
                    .apply_confirmed_notification_inbox_delete(&authority, &event)?,
                "a newer inbox disposition superseded this restore"
            );
            Ok(())
        });
        match outcome {
            Ok(()) => {
                notifications.set(super::panel::rehydrate_notifications(
                    &state_store.read(),
                    &authority,
                    authority.principal_id.as_str(),
                ));
                status_msg.set(NotificationFeedback::new("notifications.feedback.restored"));
            }
            Err(error) => status_msg.set(
                NotificationFeedback::new("notifications.feedback.restore_failed")
                    .with("error", format!("{error:#}")),
            ),
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
    status_msg: Signal<NotificationFeedback>,
    notification_id: String,
    action: UiNotificationAction,
) {
    match action {
        UiNotificationAction::AcceptInvite {
            realm_id,
            invite_id,
            credential,
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
            credential,
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
    mut status_msg: Signal<NotificationFeedback>,
    notification_id: String,
    realm_id: String,
    invite_id: String,
    credential: Option<crate::state::StoredInviteCredential>,
) {
    let accepted_realm = realm_id;
    status_msg.set(
        NotificationFeedback::new("notifications.feedback.accepting")
            .with("realm", short_protocol_id(&accepted_realm)),
    );
    spawn(async move {
        let accepted_realm_for_api = accepted_realm.clone();
        let session_credential = session_credential();
        let mut accepted_status = status_msg;
        match with_authed_api(&base_url, session_credential, |api| async move {
            let account = crate::transport::account::account_me(&api.sdk_http_client()?).await?;
            // Catch-up path: the live `ak.account_data.update` fanout may have
            // raced ahead of this accept (or this device was offline), so when
            // no usable credential is in local state pull the server-held
            // delivery cell once and use its credential directly.
            let mut credential = credential;
            let mut delivery_cell = None;
            if credential.is_none() {
                let snapshot = crate::transport::account::account_data_snapshot(
                    &api.sdk_http_client()?,
                    arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY,
                )
                .await?;
                if let Some(content) = snapshot.entry.map(|entry| entry.content) {
                    credential =
                        crate::state::invite_credentials::invite_delivery_entries_from_cell(
                            &content,
                        )
                        .into_iter()
                        .find(|(entry_invite_id, credential)| {
                            entry_invite_id == &invite_id
                                && crate::state::invite_credentials::credential_usable(
                                    credential,
                                    chrono::Utc::now(),
                                )
                        })
                        .map(|(_, credential)| credential);
                    delivery_cell = Some(content);
                }
            }
            // This notification is raised from a directed private invite
            // delivery, so the Invite stores this account and the accept both
            // joins the Realm and releases the inviter Realm's live-target slot
            // for it. A third-party invite reaches acceptance through
            // `ak.invite.claim` instead and carries no account here.
            let invitee_account_id = state_store
                .read()
                .active_authority()
                .filter(|authority| authority.principal_id == account.principal_id)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "the authenticated account is not the active account; cannot accept the invite"
                    )
                })?;
            let (_submit_results, accepted_title) = api
                .accept_realm_invite(
                    &accepted_realm_for_api,
                    account.principal_id.as_str(),
                    &invite_id,
                    credential.as_ref(),
                    Some(invitee_account_id.clone()),
                )
                .await?;
            crate::realm_events_engine::refresh_joined_realm(
                &api.sdk_http_client()?,
                &invitee_account_id,
                &arkret_sdk::RealmId::new(accepted_realm_for_api.clone())?,
                crate::app::runtime_adapter::state_store_handle(state_store),
            )
            .await?;
            accepted_status.set(NotificationFeedback::new("notifications.feedback.joined").with("realm", short_protocol_id(&accepted_realm_for_api)));
            let account_data = state_store.write().current_account_data_events();
            Ok::<_, anyhow::Error>((account_data, accepted_title, delivery_cell))
        })
        .await
        {
            Ok((account_data, _accepted_title, delivery_cell)) => {
                let push_rules = push_rules_from_account_data(&authority, &account_data);
                let account_dnd = dnd_settings_from_account_data(&authority, &account_data);
                let account_actor = arkret_sdk::ActorId::account(authority.clone());

                let hydrated = {
                    let mut store = state_store.write();
                    if let Some(content) = &delivery_cell {
                        // Persist the catch-up read so future hydration and
                        // sibling devices' accepts find the credential locally.
                        store.save_invite_delivery_cell(content);
                    }

                    let raw_notifications = store.notification_projection();
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
                        Some(&account_actor),
                        push_rules.as_ref(),
                        effective_dnd,
                        &privacy_gate,
                    )
                };
                notifications.set(hydrated);
                hide_accepted_invite_notification(
                    &mut state_store,
                    &mut notifications,
                    &notification_id,
                    &accepted_realm,
                );
                status_msg.set(NotificationFeedback::new("notifications.feedback.joined").with("realm", short_protocol_id(&accepted_realm)));
            }
            Err(err) => {
                status_msg.set(NotificationFeedback::new("notifications.feedback.accept_failed").with_api_error(err));
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
