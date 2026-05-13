use dioxus::prelude::*;
use serde_json::json;

use crate::{
    api::ContrixApi,
    local_state::LocalStateStore,
    models::SpacePreview,
    views::{
        helpers::{authed_api, authed_api_with_sync, handle_from_did},
        timeline::{TimelineEvent, message_create_operation},
    },
};

#[component]
pub fn ProductPanel(
    base_url: String,
    account_did: String,
    device_id: String,
    token: Signal<String>,
    mut selected_space: Signal<String>,
    mut spaces: Signal<Vec<SpacePreview>>,
    mut timeline: Signal<Vec<TimelineEvent>>,
    mut status: Signal<String>,
    mut sync_cursor: Signal<String>,
    mut frontier_state: Signal<String>,
    mut state_store: Signal<LocalStateStore>,
) -> Element {
    let mut member_did = use_signal(|| "did:web:bob.example".to_owned());
    let mut space_title = use_signal(|| "Product Flow Space".to_owned());
    let mut space_summary = use_signal(|| "Created from yougen product flow".to_owned());
    let mut space_discoverability = use_signal(|| "invite_only".to_owned());
    let mut space_policy_join_rule = use_signal(|| "restricted".to_owned());
    let mut space_policy_history_visibility = use_signal(|| "invited".to_owned());
    let mut message_body = use_signal(|| "persisted product flow message".to_owned());
    let mut register_did = use_signal(|| account_did.clone());
    let mut register_handle = use_signal(|| handle_from_did(&account_did));
    let mut register_display_name = use_signal(|| "yougen".to_owned());
    let mut register_device_id = use_signal(|| device_id.clone());
    let mut account_state = use_signal(|| "Not registered in this session".to_owned());
    let mut contact_target_did = use_signal(|| "did:web:bob.example".to_owned());
    let mut contact_requester_did = use_signal(|| "did:web:alice.example".to_owned());
    let mut contact_state = use_signal(|| "No contact operation yet".to_owned());
    let mut space_state = use_signal(|| "No lifecycle operation yet".to_owned());
    let mut message_state = use_signal(|| "No canonical message persisted".to_owned());
    let has_session = !token().trim().is_empty();

    rsx! {
        div { class: "timeline", "data-testid": "product-panel",
            // ── Account flow ─────────────────────────────────────
            div { class: "event", "data-testid": "account-flow",
                div { class: "event-head", span { "Account" } span { "register / login / logout" } }
                div { class: "muted", "{account_state}" }
                div { class: "workflow-form",
                    input {
                        "data-testid": "account-register-did-input",
                        value: "{register_did}",
                        oninput: move |event| {
                            let value = event.value();
                            register_handle.set(handle_from_did(&value));
                            register_did.set(value);
                        }
                    }
                    input {
                        "data-testid": "account-register-handle-input",
                        value: "{register_handle}",
                        oninput: move |event| register_handle.set(event.value())
                    }
                    input {
                        "data-testid": "account-register-display-name-input",
                        value: "{register_display_name}",
                        oninput: move |event| register_display_name.set(event.value())
                    }
                    input {
                        "data-testid": "account-register-device-id-input",
                        value: "{register_device_id}",
                        oninput: move |event| register_device_id.set(event.value())
                    }
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "register-account-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let base = base.clone();
                                let actor = register_did();
                                let handle = register_handle();
                                let display = register_display_name();
                                let device = register_device_id();
                                spawn(async move {
                                    match ContrixApi::new(&base) {
                                        Ok(api) => match api.register_account(
                                            &actor,
                                            &handle,
                                            Some(&display),
                                            Some(&device),
                                        ).await {
                                            Ok(account) => account_state.set(format!("registered {}", account.handle)),
                                            Err(error) => account_state.set(format!("register failed: {error}")),
                                        },
                                        Err(error) => account_state.set(format!("invalid server URL: {error}")),
                                    }
                                });
                            }
                        },
                        "Register"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "account-me-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let api_token = token();
                                let base = base.clone();
                                spawn(async move {
                                    match authed_api(&base, api_token) {
                                        Ok(api) => match api.account_me().await {
                                            Ok(account) => account_state.set(format!("me {}", account.did)),
                                            Err(error) => account_state.set(format!("me failed: {error}")),
                                        },
                                        Err(error) => account_state.set(format!("invalid server URL: {error}")),
                                    }
                                });
                            }
                        },
                        "Me"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "logout-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let api_token = token();
                                let base = base.clone();
                                spawn(async move {
                                    match authed_api(&base, api_token) {
                                        Ok(api) => match api.logout().await {
                                            Ok(_) => {
                                                token.set(String::new());
                                                account_state.set("logged out".to_owned());
                                            }
                                            Err(error) => account_state.set(format!("logout failed: {error}")),
                                        },
                                        Err(error) => account_state.set(format!("invalid server URL: {error}")),
                                    }
                                });
                            }
                        },
                        "Logout"
                    }
                }
            }

            // ── Contact flow ─────────────────────────────────────
            div { class: "event", "data-testid": "contact-flow",
                div { class: "event-head", span { "Contacts" } span { "request / respond / list" } }
                div { class: "workflow-form",
                    input {
                        "data-testid": "contact-target-did-input",
                        value: "{contact_target_did}",
                        oninput: move |event| contact_target_did.set(event.value())
                    }
                    input {
                        "data-testid": "contact-requester-did-input",
                        value: "{contact_requester_did}",
                        oninput: move |event| contact_requester_did.set(event.value())
                    }
                    div { class: "muted", "{contact_state}" }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "request-contact-button",
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let api_token = token();
                                    let base = base.clone();
                                    let target = contact_target_did();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.request_contact(&target).await {
                                                Ok(contact) => contact_state.set(format!("request {} -> {} {}", contact.requester, contact.target, contact.status)),
                                                Err(error) => contact_state.set(format!("request failed: {error}")),
                                            },
                                            Err(error) => contact_state.set(format!("invalid server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "Request"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "accept-contact-button",
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let api_token = token();
                                    let base = base.clone();
                                    let requester = contact_requester_did();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.respond_contact(&requester, "accept").await {
                                                Ok(contact) => contact_state.set(format!("respond {} -> {} {}", contact.requester, contact.target, contact.status)),
                                                Err(error) => contact_state.set(format!("accept failed: {error}")),
                                            },
                                            Err(error) => contact_state.set(format!("invalid server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "Accept"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "reject-contact-button",
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let api_token = token();
                                    let base = base.clone();
                                    let requester = contact_requester_did();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.respond_contact(&requester, "reject").await {
                                                Ok(contact) => contact_state.set(format!("respond {} -> {} {}", contact.requester, contact.target, contact.status)),
                                                Err(error) => contact_state.set(format!("reject failed: {error}")),
                                            },
                                            Err(error) => contact_state.set(format!("invalid server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "Reject"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "list-contacts-button",
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let api_token = token();
                                    let base = base.clone();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.contacts().await {
                                                Ok(result) => {
                                                    let summary = result.contacts.iter()
                                                        .map(|contact| format!("{} -> {} {}", contact.requester, contact.target, contact.status))
                                                        .collect::<Vec<_>>()
                                                        .join(", ");
                                                    contact_state.set(format!("contacts {} {}", result.contacts.len(), summary));
                                                }
                                                Err(error) => contact_state.set(format!("list failed: {error}")),
                                            },
                                            Err(error) => contact_state.set(format!("invalid server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "List"
                        }
                    }
                }
            }

            // ── Space lifecycle flow ─────────────────────────────
            div { class: "event", "data-testid": "space-lifecycle-flow",
                div { class: "event-head", span { "Space lifecycle" } span { "create / member / delete" } }
                div { class: "workflow-form",
                    input {
                        "data-testid": "space-title-input",
                        value: "{space_title}",
                        oninput: move |event| space_title.set(event.value())
                    }
                    input {
                        "data-testid": "space-summary-input",
                        value: "{space_summary}",
                        oninput: move |event| space_summary.set(event.value())
                    }
                    input {
                        "data-testid": "space-discoverability-input",
                        value: "{space_discoverability}",
                        oninput: move |event| space_discoverability.set(event.value())
                    }
                    input {
                        "data-testid": "member-did-input",
                        value: "{member_did}",
                        oninput: move |event| member_did.set(event.value())
                    }
                    input {
                        "data-testid": "selected-space-id-input",
                        value: "{selected_space}",
                        oninput: move |event| selected_space.set(event.value())
                    }
                    input {
                        "data-testid": "space-policy-join-rule-input",
                        value: "{space_policy_join_rule}",
                        oninput: move |event| space_policy_join_rule.set(event.value())
                    }
                    input {
                        "data-testid": "space-policy-history-visibility-input",
                        value: "{space_policy_history_visibility}",
                        oninput: move |event| space_policy_history_visibility.set(event.value())
                    }
                    div { class: "muted", "{space_state}" }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "create-space-button",
                            disabled: !has_session,
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let api_token = token();
                                    let base = base.clone();
                                    let title = space_title();
                                    let summary = space_summary();
                                    let discoverability = space_discoverability();
                                    let invitee = member_did();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.create_space(&title, Some(&summary), discoverability == "public", vec![invitee]).await {
                                                Ok(space) => {
                                                    selected_space.set(space.space_id.clone());
                                                    spaces.write().push(SpacePreview {
                                                        space_id: space.space_id.clone(),
                                                        name: title,
                                                        description: Some(summary),
                                                        tags: Default::default(),
                                                        public: discoverability == "public",
                                                        category: Some("collaboration".to_owned()),
                                                    });
                                                    space_state.set(format!("created {} with {} member(s)", space.space_id, space.members.len()));
                                                }
                                                Err(error) => space_state.set(format!("create failed: {error}")),
                                            },
                                            Err(error) => space_state.set(format!("invalid server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "Create Space"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "update-space-button",
                            disabled: !has_session,
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let api_token = token();
                                    let base = base.clone();
                                    let space = selected_space();
                                    let title = space_title();
                                    let summary = space_summary();
                                    let discoverability = space_discoverability();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.update_space(
                                                &space,
                                                json!({
                                                    "title": title,
                                                    "summary": summary,
                                                    "discoverability": discoverability,
                                                }),
                                            ).await {
                                                Ok(result) => space_state.set(format!("updated {}", result.space_id)),
                                                Err(error) => space_state.set(format!("update failed: {error}")),
                                            },
                                            Err(error) => space_state.set(format!("invalid server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "Update Space"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "set-space-policy-button",
                            disabled: !has_session,
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let api_token = token();
                                    let base = base.clone();
                                    let space = selected_space();
                                    let join_rule = space_policy_join_rule();
                                    let history_visibility = space_policy_history_visibility();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.set_space_policy(&space, &join_rule, &history_visibility).await {
                                                Ok(result) => space_state.set(format!("policy {} {}", result.join_rule, result.history_visibility)),
                                                Err(error) => space_state.set(format!("policy failed: {error}")),
                                            },
                                            Err(error) => space_state.set(format!("invalid server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "Set Policy"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "list-invites-button",
                            disabled: !has_session,
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let api_token = token();
                                    let base = base.clone();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.invites().await {
                                                Ok(result) => {
                                                    let summary = result.invites.iter()
                                                        .filter_map(|invite| invite.get("space_id").and_then(|value| value.as_str()))
                                                        .collect::<Vec<_>>()
                                                        .join(", ");
                                                    space_state.set(format!("invites {} {}", result.invites.len(), summary));
                                                }
                                                Err(error) => space_state.set(format!("invites failed: {error}")),
                                            },
                                            Err(error) => space_state.set(format!("invalid server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "List Invites"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "add-member-button",
                            disabled: !has_session,
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let api_token = token();
                                    let base = base.clone();
                                    let space = selected_space();
                                    let member = member_did();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.add_space_member(&space, &member).await {
                                                Ok(result) => space_state.set(format!("members {}", result.members.len())),
                                                Err(error) => space_state.set(format!("add member failed: {error}")),
                                            },
                                            Err(error) => space_state.set(format!("invalid server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "Add Member"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "remove-member-button",
                            disabled: !has_session,
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let api_token = token();
                                    let base = base.clone();
                                    let space = selected_space();
                                    let member = member_did();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.remove_space_member(&space, &member).await {
                                                Ok(result) => space_state.set(format!("removed; members {}", result.members.len())),
                                                Err(error) => space_state.set(format!("remove member failed: {error}")),
                                            },
                                            Err(error) => space_state.set(format!("invalid server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "Remove Member"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "delete-space-button",
                            disabled: !has_session,
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let api_token = token();
                                    let base = base.clone();
                                    let space = selected_space();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.delete_space(&space).await {
                                                Ok(result) => {
                                                    spaces.write().retain(|preview| preview.space_id != result.space_id);
                                                    space_state.set(format!("deleted {}", result.deleted));
                                                }
                                                Err(error) => space_state.set(format!("delete failed: {error}")),
                                            },
                                            Err(error) => space_state.set(format!("invalid server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "Delete Space"
                        }
                    }
                }
            }

            // ── Message persistence flow ─────────────────────────
            div { class: "event", "data-testid": "message-persistence-flow",
                div { class: "event-head", span { "Message persistence" } span { "operation / commit / sync token" } }
                div { class: "workflow-form",
                    input {
                        "data-testid": "persist-message-input",
                        value: "{message_body}",
                        oninput: move |event| message_body.set(event.value())
                    }
                    div { class: "muted", "{message_state}" }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "persist-message-button",
                            disabled: !has_session,
                            onclick: {
                                let base = base_url;
                                let actor = account_did.clone();
                                move |_| {
                                    let api_token = token();
                                    let base = base.clone();
                                    let actor = actor.clone();
                                    let space = selected_space();
                                    let body = message_body();
                                    let wait_for = active_sync_token(sync_cursor());
                                    spawn(async move {
                                        match authed_api_with_sync(&base, api_token, wait_for) {
                                            Ok(api) => {
                                                let op = message_create_operation(
                                                    &space,
                                                    &actor,
                                                    None,
                                                    &body,
                                                );
                                                match api.submit_operation_event(&op).await {
                                                Ok(sent) => {
                                                    sync_cursor.set(sent.sync_token.clone());
                                                    frontier_state.set(sent.event_id.clone());
                                                    {
                                                        let mut store = state_store.write();
                                                        store.save_sync_cursor(sent.sync_token.clone());
                                                        store.append_raw_operation(
                                                            op.operation_id.clone(),
                                                            Some(space.clone()),
                                                            json!({
                                                                "event_id": sent.event_id.clone(),
                                                                "kind": "cx.message.create",
                                                                "status": sent.status,
                                                            }),
                                                        );
                                                    }
                                                    timeline.write().push(TimelineEvent {
                                                        id: sent.event_id.clone(),
                                                        sender: actor.clone(),
                                                        sender_display: "product".to_owned(),
                                                        body: format!(
                                                            "persisted event {}",
                                                            sent.event_id
                                                        ),
                                                        timestamp: chrono::Utc::now()
                                                            .format("%Y-%m-%d %H:%M")
                                                            .to_string(),
                                                        operation_id: Some(op.operation_id.clone()),
                                                        event_id: Some(sent.event_id.clone()),
                                                        ..TimelineEvent::default()
                                                    });
                                                    message_state.set(format!("persisted {} via {}", op.operation_id, sent.event_id));
                                                }
                                                Err(error) => message_state.set(format!("persist failed: {error}")),
                                                }
                                            }
                                            Err(error) => message_state.set(format!("invalid server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "Persist Message"
                        }
                    }
                }
            }
        }
    }
}

fn active_sync_token(sync_cursor: String) -> Option<String> {
    let sync_cursor = sync_cursor.trim();
    sync_cursor
        .starts_with("sx:")
        .then(|| sync_cursor.to_owned())
}
