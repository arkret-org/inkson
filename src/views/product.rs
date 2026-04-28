use dioxus::prelude::*;
use serde_json::json;

use crate::{
    api::ContrixApi,
    local_state::LocalStateStore,
    models::SpacePreview,
    views::helpers::{authed_api, handle_from_did},
};

#[component]
pub fn ProductPanel(
    base_url: String,
    account_did: String,
    device_id: String,
    token: Signal<String>,
    mut selected_space: Signal<String>,
    mut spaces: Signal<Vec<SpacePreview>>,
    mut timeline: Signal<Vec<String>>,
    mut status: Signal<String>,
    mut sync_cursor: Signal<String>,
    mut repo_state: Signal<String>,
    mut state_store: Signal<LocalStateStore>,
) -> Element {
    let mut contact_target = use_signal(|| "did:web:bob.example".to_owned());
    let mut member_did = use_signal(|| "did:web:bob.example".to_owned());
    let mut space_title = use_signal(|| "Product Flow Space".to_owned());
    let mut message_body = use_signal(|| "persisted product flow message".to_owned());
    let mut account_state = use_signal(|| "Not registered in this session".to_owned());
    let mut contact_state = use_signal(|| "No contacts loaded".to_owned());
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
                                            Some("clientx"),
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

            // ── Contacts flow ────────────────────────────────────
            div { class: "event", "data-testid": "contacts-flow",
                div { class: "event-head", span { "Contacts" } span { "request / list" } }
                div { class: "workflow-form",
                    input {
                        "data-testid": "contact-target-input",
                        value: "{contact_target}",
                        oninput: move |event| contact_target.set(event.value())
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
                                    let target = contact_target();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.request_contact(&target).await {
                                                Ok(contact) => contact_state.set(format!("contact {} {}", contact.target, contact.status)),
                                                Err(error) => contact_state.set(format!("contact failed: {error}")),
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
                            "data-testid": "list-contacts-button",
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let api_token = token();
                                    let base = base.clone();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.list_contacts().await {
                                                Ok(list) => contact_state.set(format!("{} contact(s)", list.contacts.len())),
                                                Err(error) => contact_state.set(format!("list failed: {error}")),
                                            },
                                            Err(error) => contact_state.set(format!("invalid server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "List"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "accept-contact-button",
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let api_token = token();
                                    let base = base.clone();
                                    let requester = contact_target();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.respond_contact(&requester, "accept").await {
                                                Ok(contact) => contact_state.set(format!("contact {} {}", contact.requester, contact.status)),
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
                                    let requester = contact_target();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.respond_contact(&requester, "reject").await {
                                                Ok(contact) => contact_state.set(format!("contact {} {}", contact.requester, contact.status)),
                                                Err(error) => contact_state.set(format!("reject failed: {error}")),
                                            },
                                            Err(error) => contact_state.set(format!("invalid server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "Reject"
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
                                            Ok(api) => match api.create_space(&title, Some("Created from clientx product flow"), true, vec![invitee]).await {
                                                Ok(space) => {
                                                    selected_space.set(space.space_id.clone());
                                                    spaces.write().push(SpacePreview {
                                                        space_id: space.space_id.clone(),
                                                        name: title,
                                                        description: Some("Created from clientx product flow".to_owned()),
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
                                move |_| {
                                    let api_token = token();
                                    let base = base.clone();
                                    let space = selected_space();
                                    let body = message_body();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
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
                                                            }),
                                                        );
                                                    }
                                                    timeline.write().push(format!("persisted event {} commit {}", sent.event_id, sent.commit_id));
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
