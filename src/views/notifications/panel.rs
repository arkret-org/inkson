//! The `NotificationsPanel` RSX component: grouping toolbar, the paged
//! notification feed, and the row-level read / archive / mute / action
//! controls. The network handlers it invokes live in [`super::actions`]
//! and the projection logic in [`super::model`].

use dioxus::prelude::*;

use super::actions::{
    mark_all_notifications_read, mark_notification_read_state, refresh_notifications,
    run_notification_action, set_notification_inbox_state,
};
use super::model::{
    UiNotificationGroup, hydrate_notifications_with_privacy_gate, notification_kind_enabled,
    notification_overrides_realm_mute, notification_scope_kind, realm_is_muted,
};
use crate::components::{EmptyState, EmptyStateKind, UiIcon};
use crate::notification_rules::{dnd_settings_from_account_data, push_rules_from_account_data};
use crate::state::LocalStateStore;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::views::helpers::short_protocol_id;

pub(super) fn rehydrate_notifications_for_blocklist_revision(
    store: &LocalStateStore,
    authority: &arkret_sdk::AccountId,
    principal_id: &str,
) -> Vec<super::model::UiNotification> {
    let local_state = store.load();
    let account_data = store.current_account_data_events();
    let push_rules = push_rules_from_account_data(authority, &account_data);
    let account_dnd = dnd_settings_from_account_data(authority, &account_data);
    let effective_dnd = local_state
        .notification_dnd_settings
        .as_ref()
        .or(account_dnd.as_ref());
    let privacy_gate = crate::sidecar::SidecarPrivacyGate::from_store(store, principal_id);
    hydrate_notifications_with_privacy_gate(
        local_state.notification_projection.clone(),
        &local_state,
        Some(&arkret_sdk::ActorId::account(authority.clone())),
        push_rules.as_ref(),
        effective_dnd,
        &privacy_gate,
    )
}

#[component]
pub fn NotificationsPanel(
    principal_id: String,
    device_id: String,
    token: Signal<String>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let session = crate::app::SessionContext::get();
    let contact_inbox = use_context::<crate::app::ContactInbox>();
    let mut state_store = session.state_store;
    let Some(account) = session.active_account() else {
        return rsx! { div { class: "event error-banner", "Active account context is unavailable." } };
    };
    let authority = account.authority;
    let (initial_state, initial_privacy_gate) = {
        let store = state_store.read();
        (
            store.load(),
            crate::sidecar::SidecarPrivacyGate::from_store(&store, &principal_id),
        )
    };
    let initial_notifications = hydrate_notifications_with_privacy_gate(
        initial_state.notification_projection.clone(),
        &initial_state,
        Some(&arkret_sdk::ActorId::account(authority.clone())),
        None,
        initial_state.notification_dnd_settings.as_ref(),
        &initial_privacy_gate,
    );

    let notifications = use_signal(move || initial_notifications.clone());
    let mut hydrated_blocklist_revision = use_signal(|| initial_state.client_blocklist_revision);
    let mut group_by = use_signal(|| UiNotificationGroup::Latest);
    let mut show_archived = use_signal(|| false);
    let mut did_bootstrap = use_signal(|| false);
    let mut status_msg = use_signal(String::new);

    if !did_bootstrap() {
        did_bootstrap.set(true);
        refresh_notifications(
            base_url.clone(),
            token,
            authority.clone(),
            state_store,
            notifications,
            status_msg,
        );
    }

    let authority_for_revision = authority.clone();
    let principal_for_revision = principal_id.clone();
    let mut notifications_for_revision = notifications;
    use_effect(move || {
        let store = state_store.read();
        let revision = store.client_blocklist_revision();
        if revision == hydrated_blocklist_revision() {
            return;
        }
        let hydrated = rehydrate_notifications_for_blocklist_revision(
            &store,
            &authority_for_revision,
            &principal_for_revision,
        );
        drop(store);
        hydrated_blocklist_revision.set(revision);
        notifications_for_revision.set(hydrated);
    });

    let local_state = state_store.read().load();
    let pending_contacts = contact_inbox.visible_pending(&local_state);
    let mut visible_notifications = notifications()
        .into_iter()
        .filter(|notification| {
            (show_archived() || !notification.archived)
                && notification_kind_enabled(&local_state, &notification.kind)
                && (!realm_is_muted(&local_state, &notification.realm_id)
                    || notification_overrides_realm_mute(notification))
        })
        .collect::<Vec<_>>();

    match group_by() {
        UiNotificationGroup::Latest => {
            visible_notifications.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
        }
        UiNotificationGroup::ByRealm => {
            visible_notifications.sort_by(|left, right| {
                left.realm_id
                    .cmp(&right.realm_id)
                    .then_with(|| right.timestamp.cmp(&left.timestamp))
            });
        }
        UiNotificationGroup::ByType => {
            visible_notifications.sort_by(|left, right| {
                left.kind
                    .cmp(&right.kind)
                    .then_with(|| right.timestamp.cmp(&left.timestamp))
            });
        }
    }

    let total_notifications = notifications().len();

    // F-NOTIF-VLIST-1: client-side paging — start by rendering only the
    // first 50 notifications and let the user expand the window via the
    // "Load more" button at the foot of the list. A user with 1000+
    // notifications no longer pays the full DOM cost on every render,
    // and the "0/N" badge below makes it obvious how much more is
    // available. Real virtualization (windowed rows) is a follow-up.
    let mut visible_limit = use_signal(|| 50usize);
    let visible_total = visible_notifications.len();
    let visible_window: usize = visible_total.min(visible_limit());
    let visible_notifications: Vec<_> = visible_notifications
        .into_iter()
        .take(visible_window)
        .collect();
    let has_more_to_load = visible_total > visible_window;
    let status_text = status_msg();

    rsx! {
        div { class: "timeline notifications-panel", "data-testid": "notifications-panel", role: "region", "aria-label": "Notifications",
            for contact in pending_contacts {
                ContactRequestNotification {
                    key: "{contact.peer.contact_actor_id()}",
                    contact,
                    token,
                }
            }
            div { class: "toolbar-row",
                div { class: "segmented-control", role: "tablist", "aria-label": "Notification grouping",
                    Button {
                        variant: ButtonVariant::Secondary,
                        class: if group_by() == UiNotificationGroup::Latest { "segment active" } else { "segment" },
                        onclick: move |_| group_by.set(UiNotificationGroup::Latest),
                        {crate::i18n::tr("notifications.view.latest")}
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        class: if group_by() == UiNotificationGroup::ByRealm { "segment active" } else { "segment" },
                        onclick: move |_| group_by.set(UiNotificationGroup::ByRealm),
                        {crate::i18n::tr("notifications.view.realm")}
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        class: if group_by() == UiNotificationGroup::ByType { "segment active" } else { "segment" },
                        onclick: move |_| group_by.set(UiNotificationGroup::ByType),
                        {crate::i18n::tr("notifications.view.type")}
                    }
                }
                div { class: "icon-actions",
                    Button {
                        variant: ButtonVariant::Ghost,
                        size: ButtonSize::Sm,
                        class: "btn icon",
                        "data-testid": "mark-all-read-button",
                        title: crate::i18n::tr("notifications.tooltip.mark_all_read"),
                        "aria-label": crate::i18n::tr("notifications.tooltip.mark_all_read"),
                        onclick: {
                            let base_url = base_url.clone();
                            let principal_id = principal_id.clone();
                            let device_id = device_id.clone();
                            move |_| {
                                mark_all_notifications_read(
                                    base_url.clone(),
                                    token(),
                                    principal_id.clone(),
                                    device_id.clone(),
                                    state_store,
                                    notifications,
                                    status_msg,
                                );
                            }
                        },
                        UiIcon { name: "check" }
                    }
                    Button {
                        variant: ButtonVariant::Ghost,
                        size: ButtonSize::Sm,
                        class: "btn icon",
                        "data-testid": "toggle-archived",
                        title: if show_archived() { crate::i18n::tr("notifications.tooltip.hide_archived") } else { crate::i18n::tr("notifications.tooltip.show_archived") },
                        "aria-label": if show_archived() { crate::i18n::tr("notifications.tooltip.hide_archived") } else { crate::i18n::tr("notifications.tooltip.show_archived") },
                        onclick: move |_| show_archived.set(!show_archived()),
                        UiIcon { name: "archive" }
                    }
                    Button {
                        variant: ButtonVariant::Ghost,
                        size: ButtonSize::Sm,
                        class: "btn icon",
                        "data-testid": "refresh-notifications",
                        title: crate::i18n::tr("notifications.tooltip.refresh"),
                        "aria-label": crate::i18n::tr("notifications.tooltip.refresh"),
                        onclick: {
                            let base_url = base_url.clone();
                            let authority = authority.clone();
                            move |_| {
                                refresh_notifications(
                                    base_url.clone(),
                                    token,
                                    authority.clone(),
                                    state_store,
                                    notifications,
                                    status_msg,
                                );
                            }
                        },
                        UiIcon { name: "refresh" }
                    }
                }
            }
            if !status_text.is_empty() {
                div {
                    class: "muted notifications-status",
                    "data-testid": "notifications-status",
                    role: "status",
                    "aria-live": "polite",
                    "{status_text}"
                }
            }

            for notification in visible_notifications.iter() {
                div {
                    class: "event",
                    "data-testid": "notification-item",
                    key: "{notification.id}",
                    style: if notification.read { "opacity: 0.6;" } else { "" },
                    div { class: "event-head",
                        // `title` may be server-provided copy or an i18n
                        // default-title key — `tr()` translates keys and
                        // passes unknown strings through unchanged.
                        span { {crate::i18n::tr(&notification.title)} }
                        span { "{notification.kind} / {notification.timestamp}" }
                    }
                    div {
                        class: if notification.read { "muted" } else { "entity-title" },
                        "{notification.body}"
                    }
                    if let Some(ref hint) = notification.watch_hint {
                        div {
                            class: "muted",
                            "data-testid": "notification-watch-hint",
                            // Watch hints are stored as i18n keys.
                            {crate::i18n::tr(hint)}
                        }
                    }
                    if !notification.realm_id.is_empty() {
                        {
                            let scope_kind = notification_scope_kind(notification);
                            let realm_label = notification
                                .realm_label
                                .as_deref()
                                .filter(|label| !label.trim().is_empty())
                                .map(ToOwned::to_owned)
                                .unwrap_or_else(|| short_protocol_id(&notification.realm_id));
                            rsx! {
                                div {
                                    class: "muted",
                                    title: "{notification.realm_id}",
                                    "{scope_kind}: {realm_label}"
                                }
                            }
                        }
                    }
                    if let Some(super::model::UiNotificationAction::AcceptInvite {
                        realm_id,
                        invite_id,
                        credential,
                    }) = notification.action.clone()
                    {
                        super::invite_preview::InvitePreview {
                            key: "{notification.id}-preview",
                            base_url: base_url.clone(),
                            token,
                            authority: authority.clone(),
                            realm_id,
                            invite_id,
                            credential,
                        }
                    }
                    div { class: "actions",
                        if !notification.read {
                            Button {
                                variant: ButtonVariant::Ghost,
                                size: ButtonSize::Sm,
                                class: "btn icon",
                                "data-testid": "mark-read-button",
                                title: "Mark read",
                                "aria-label": "Mark read",
                                onclick: {
                                    let base_url = base_url.clone();
                                    let principal_id = principal_id.clone();
                                    let device_id = device_id.clone();
                                    let notification = notification.clone();
                                    move |_| {
                                        mark_notification_read_state(
                                            base_url.clone(),
                                            token(),
                                            principal_id.clone(),
                                            device_id.clone(),
                                            notification.clone(),
                                            true,
                                            state_store,
                                            notifications,
                                            status_msg,
                                        );
                                    }
                                },
                                UiIcon { name: "check" }
                            }
                        } else {
                            Button {
                                variant: ButtonVariant::Ghost,
                                size: ButtonSize::Sm,
                                class: "btn icon",
                                "data-testid": "mark-unread-button",
                                title: "Mark unread",
                                "aria-label": "Mark unread",
                                onclick: {
                                    let base_url = base_url.clone();
                                    let principal_id = principal_id.clone();
                                    let device_id = device_id.clone();
                                    let notification = notification.clone();
                                    move |_| {
                                        mark_notification_read_state(
                                            base_url.clone(),
                                            token(),
                                            principal_id.clone(),
                                            device_id.clone(),
                                            notification.clone(),
                                            false,
                                            state_store,
                                            notifications,
                                            status_msg,
                                        );
                                    }
                                },
                                UiIcon { name: "bell" }
                            }
                        }
                        if !notification.archived {
                            Button {
                                variant: ButtonVariant::Ghost,
                                size: ButtonSize::Sm,
                                class: "btn icon",
                                "data-testid": "archive-button",
                                title: "Archive",
                                "aria-label": "Archive",
                                onclick: {
                                    let base_url = base_url.clone();
                                    let principal_id = principal_id.clone();
                                    let device_id = device_id.clone();
                                    let authority = authority.clone();
                                    let notification_id = notification.id.clone();
                                    move |_| {
                                        set_notification_inbox_state(
                                            base_url.clone(),
                                            token(),
                                            authority.clone(),
                                            principal_id.clone(),
                                            device_id.clone(),
                                            notification_id.clone(),
                                            arkret_sdk::NotificationInboxState::Archived,
                                            state_store,
                                            notifications,
                                            status_msg,
                                        );
                                    }
                                },
                                UiIcon { name: "archive" }
                            }
                        }
                        if !notification.realm_id.is_empty() {
                            Button {
                                variant: ButtonVariant::Ghost,
                                size: ButtonSize::Sm,
                                class: "btn icon",
                                "data-testid": "mute-realm-button",
                                title: "Mute this realm",
                                "aria-label": "Mute this realm",
                                onclick: {
                                    let realm_id = notification.realm_id.clone();
                                    move |_| {
                                        state_store.write().set_realm_muted(realm_id.clone(), true);
                                        status_msg.set(format!(
                                            "Muted notifications for {}.",
                                            short_protocol_id(&realm_id)
                                        ));
                                    }
                                },
                                UiIcon { name: "bell" }
                            }
                        }
                        if let Some(ref action) = notification.action_label {
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "notification-action",
                                onclick: {
                                    let action_to_run = notification.action.clone();
                                    let base_url = base_url.clone();
                                    let authority = authority.clone();
                                    let notification_id = notification.id.clone();
                                    // Translate now (default titles are i18n keys).
                                    let title = crate::i18n::tr(&notification.title);
                                    move |_| {
                                        if let Some(action_to_run) = action_to_run.clone() {
                                            run_notification_action(
                                                base_url.clone(),
                                                token,
                                                authority.clone(),
                                                state_store,
                                                notifications,
                                                status_msg,
                                                notification_id.clone(),
                                                action_to_run,
                                            );
                                        } else {
                                            status_msg.set(format!("Action queued for {title}."));
                                        }
                                    }
                                },
                                // Action labels are stored as i18n keys.
                                {crate::i18n::tr(action)}
                            }
                        }
                    }
                }
            }

            if total_notifications > 0 && visible_notifications.is_empty() {
                EmptyState {
                    title: crate::i18n::tr("notifications.feed_title"),
                    kind: EmptyStateKind::Filtered,
                    message: Some(crate::i18n::tr("notifications.filtered_body")),
                    test_id: Some("notifications-muted-empty".to_owned()),
                }
            }

            // F-NOTIF-VLIST-1: progress + "Load more" affordance for the
            // client-side paging window. We surface the visible / total
            // count so the user knows there's more to expand, then step
            // the window forward by another page when they click.
            if has_more_to_load {
                div { class: "actions", "data-testid": "notifications-load-more-row",
                    div { class: "muted",
                        {format!(
                            "{} {} / {}",
                            crate::i18n::tr("notifications.showing"),
                            visible_window,
                            visible_total,
                        )}
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "notifications-load-more",
                        onclick: move |_| {
                            visible_limit.with_mut(|n| *n = n.saturating_add(50));
                        },
                        {crate::i18n::tr("notifications.load_more")}
                    }
                }
            }
        }
    }
}

#[component]
fn ContactRequestNotification(
    contact: crate::models::ContactListRow,
    token: Signal<String>,
) -> Element {
    let session = crate::app::SessionContext::get();
    let mut inbox = use_context::<crate::app::ContactInbox>();
    let busy = use_signal(|| false);
    let status = use_signal(String::new);
    let peer = contact.peer.contact_actor_id().to_string();
    let request_event_ref = contact.request_event_ref.as_ref().map(ToString::to_string);
    let label = crate::views::helpers::contact_peer_label(&session.state_store.read(), &contact);
    rsx! {
        div { class: "event", "data-testid": "contact-request-notification",
            strong { {crate::i18n::tr("notifications.contact_request.title")} }
            span { "{label}" }
            if let Some(message) = &contact.request_message {
                p { class: "contact-request-message", "data-testid": "contact-request-message", "{message}" }
            }
            Button {
                variant: ButtonVariant::Primary,
                "data-testid": "notification-contact-accept",
                disabled: busy(),
                onclick: move |_| {
                    let generation = *session.session_generation.peek();
                    let completed_peer = peer.clone();
                    let completed_request = request_event_ref.clone();
                    crate::views::contacts::run_contact_action(
                        session.base_url.peek().clone(), token(),
                        crate::views::contacts::ContactRowAction::Respond {
                            requester: peer.clone(), request_event_ref: request_event_ref.clone(),
                            verb: "accept".to_owned(),
                        },
                        crate::i18n::tr("contacts.action.accepting"), busy, status,
                        EventHandler::new(move |_| {
                            if *session.session_generation.peek() == generation {
                                inbox.0.write().retain(|row| {
                                    !(row.state == arkret_sdk::ContactState::PendingIncoming
                                        && row.peer.contact_actor_id().to_string() == completed_peer
                                        && row.request_event_ref.as_ref().map(ToString::to_string) == completed_request)
                                });
                            }
                        }),
                        // The notification row shows no Profile evidence, so
                        // accepting from here records no identity confirmation.
                        None,
                    );
                },
                if busy() { {crate::i18n::tr("contacts.action.accepting")} }
                else { {crate::i18n::tr("contacts.action.accept")} }
            }
            if !status().is_empty() {
                div { role: "status", class: "muted", "{status}" }
            }
        }
    }
}
