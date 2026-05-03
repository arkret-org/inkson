use dioxus::prelude::*;
use serde_json::json;

use crate::{
    api::ContrixApi,
    local_state::LocalStateStore,
    models::SpacePreview,
    views::{
        helpers::{authed_api, authed_api_with_sync, handle_from_did},
        timeline::TimelineEvent,
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
    mut repo_state: Signal<String>,
    mut state_store: Signal<LocalStateStore>,
) -> Element {
    let mut member_did = use_signal(|| "did:web:bob.example".to_owned());
    let mut space_title = use_signal(|| "Product Flow Space".to_owned());
    let mut message_body = use_signal(|| "persisted product flow message".to_owned());
    let mut account_state = use_signal(|| "Not registered in this session".to_owned());
    let mut space_state = use_signal(|| "No lifecycle operation yet".to_owned());
    let mut message_state = use_signal(|| "No canonical message persisted".to_owned());

    rsx! {
        div { class: "timeline", "data-testid": "product-panel",
            // ── Account flow ─────────────────────────────────────
            div { class: "event", "data-testid": "account-flow",
                div { class: "event-head", span { "Account" } span { "register / login / logout" } }
                div { class: "muted", "{account_state}" }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "register-account-button",
                        onclick: {
                            let base = base_url.clone();
                            let actor = account_did.clone();
                            let device = device_id.clone();
                            move |_| {
                                let base = base.clone();
                                let actor = actor.clone();
                                let device = device.clone();
                                spawn(async move {
                                    match ContrixApi::new(&base) {
                                        Ok(api) => match api.register_account(
                                            &actor,
                                            &handle_from_did(&actor),
                                            Some("yougen"),
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
                        "data-testid": "member-did-input",
                        value: "{member_did}",
                        oninput: move |event| member_did.set(event.value())
                    }
                    div { class: "muted", "{space_state}" }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "create-space-button",
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let api_token = token();
                                    let base = base.clone();
                                    let title = space_title();
                                    let invitee = member_did();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.create_space(&title, Some("Created from yougen product flow"), true, vec![invitee]).await {
                                                Ok(space) => {
                                                    selected_space.set(space.space_id.clone());
                                                    spaces.write().push(SpacePreview {
                                                        space_id: space.space_id.clone(),
                                                        name: title,
                                                        description: Some("Created from yougen product flow".to_owned()),
                                                        tags: Default::default(),
                                                        public: true,
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
                            "data-testid": "add-member-button",
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
                                            Ok(api) => match api.send_message(
                                                &space,
                                                None,
                                                json!({"msgtype": "m.text", "body": body}),
                                                false,
                                            ).await {
                                                Ok(sent) => {
                                                    sync_cursor.set(sent.sync_token.clone());
                                                    repo_state.set(sent.head_commit.clone().unwrap_or(sent.commit_id.clone()));
                                                    {
                                                        let mut store = state_store.write();
                                                        store.save_sync_cursor(sent.sync_token.clone());
                                                        store.append_raw_operation(
                                                            sent.operation_id.clone(),
                                                            Some(space.clone()),
                                                            json!({
                                                                "event_id": sent.event_id.clone(),
                                                                "commit_id": sent.commit_id.clone(),
                                                                "head_commit": sent.head_commit.clone(),
                                                                "kind": "cx.message.create",
                                                            }),
                                                        );
                                                    }
                                                    timeline.write().push(TimelineEvent {
                                                        id: sent.event_id.clone(),
                                                        sender: actor,
                                                        sender_display: "product".to_owned(),
                                                        body: format!(
                                                            "persisted event {} commit {}",
                                                            sent.event_id, sent.commit_id
                                                        ),
                                                        timestamp: chrono::Utc::now()
                                                            .format("%Y-%m-%d %H:%M")
                                                            .to_string(),
                                                        operation_id: Some(sent.operation_id.clone()),
                                                        commit_id: Some(sent.commit_id.clone()),
                                                        ..TimelineEvent::default()
                                                    });
                                                    message_state.set(format!("persisted {} via {}", sent.operation_id, sent.commit_id));
                                                }
                                                Err(error) => message_state.set(format!("persist failed: {error}")),
                                            },
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
    (!sync_cursor.trim().is_empty() && sync_cursor != "-").then_some(sync_cursor)
}
