use dioxus::prelude::*;
use serde_json::{Value, json};

use crate::views::helpers::authed_api;

#[component]
pub fn SpaceAdminPanel(base_url: String, token: Signal<String>, selected_space: String) -> Element {
    let mut space_name = use_signal(|| String::new());
    let mut space_topic = use_signal(|| String::new());
    let mut space_description = use_signal(|| String::new());
    let mut join_rule = use_signal(|| "open".to_owned());
    let mut history_visibility = use_signal(|| "shared".to_owned());
    let mut invite_target = use_signal(String::new);
    let mut status_msg = use_signal(|| String::new());
    let members = use_signal(Vec::<String>::new);
    let space_invites = use_signal(Vec::<Value>::new);
    let mut discovery_enabled = use_signal(|| true);

    rsx! {
        div { class: "timeline", "data-testid": "space-admin-panel",
            // Space metadata editor
            div { class: "event", "data-testid": "space-metadata",
                div { class: "event-head", span { "Space Metadata" } span { "{selected_space}" } }
                div { class: "workflow-form",
                    label { "Name" }
                    input {
                        "data-testid": "space-name-input",
                        value: "{space_name}",
                        placeholder: "Space name",
                        oninput: move |evt| space_name.set(evt.value()),
                    }
                    label { "Topic" }
                    input {
                        "data-testid": "space-topic-input",
                        value: "{space_topic}",
                        placeholder: "Space topic",
                        oninput: move |evt| space_topic.set(evt.value()),
                    }
                    label { "Description" }
                    textarea {
                        "data-testid": "space-description-input",
                        value: "{space_description}",
                        placeholder: "Space description",
                        oninput: move |evt| space_description.set(evt.value()),
                    }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "update-metadata-button",
                            onclick: {
                                let base = base_url.clone();
                                let space = selected_space.clone();
                                move |_| {
                                    let base = base.clone();
                                    let space = space.clone();
                                    let api_token = token();
                                    let name = space_name();
                                    let topic = space_topic();
                                    let desc = space_description();
                                    spawn(async move {
                                        if let Ok(api) = authed_api(&base, api_token) {
                                            match api.update_space(&space, json!({
                                                "name": name,
                                                "topic": topic,
                                                "description": desc,
                                            })).await {
                                                Ok(_) => status_msg.set("Metadata updated".to_owned()),
                                                Err(e) => status_msg.set(format!("update failed: {e}")),
                                            }
                                        }
                                    });
                                }
                            },
                            "Save Metadata"
                        }
                    }
                }
            }

            // Join policy selector
            div { class: "event", "data-testid": "join-policy",
                div { class: "event-head", span { "Join Policy" } span { "access control" } }
                div { class: "actions",
                    button {
                        class: if join_rule() == "open" { "primary" } else { "secondary" },
                        onclick: move |_| join_rule.set("open".to_owned()),
                        "Open"
                    }
                    button {
                        class: if join_rule() == "invite" { "primary" } else { "secondary" },
                        onclick: move |_| join_rule.set("invite".to_owned()),
                        "Invite"
                    }
                    button {
                        class: if join_rule() == "request" { "primary" } else { "secondary" },
                        onclick: move |_| join_rule.set("request".to_owned()),
                        "Request"
                    }
                    button {
                        class: if join_rule() == "restricted" { "primary" } else { "secondary" },
                        onclick: move |_| join_rule.set("restricted".to_owned()),
                        "Restricted"
                    }
                }
                div { class: "muted", "Current: {join_rule}" }
            }

            // History visibility selector
            div { class: "event", "data-testid": "history-visibility",
                div { class: "event-head", span { "History Visibility" } span { "" } }
                div { class: "actions",
                    button {
                        class: if history_visibility() == "shared" { "primary" } else { "secondary" },
                        onclick: move |_| history_visibility.set("shared".to_owned()),
                        "Shared"
                    }
                    button {
                        class: if history_visibility() == "invited" { "primary" } else { "secondary" },
                        onclick: move |_| history_visibility.set("invited".to_owned()),
                        "Invited"
                    }
                    button {
                        class: if history_visibility() == "joined" { "primary" } else { "secondary" },
                        onclick: move |_| history_visibility.set("joined".to_owned()),
                        "Joined"
                    }
                    button {
                        class: if history_visibility() == "world_readable" { "primary" } else { "secondary" },
                        onclick: move |_| history_visibility.set("world_readable".to_owned()),
                        "World Readable"
                    }
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "apply-policy-button",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            move |_| {
                                let base = base.clone();
                                let space = space.clone();
                                let api_token = token();
                                let rule = join_rule();
                                let vis = history_visibility();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.set_space_policy(&space, &rule, &vis).await {
                                            Ok(resp) => status_msg.set(format!("policy: join={}, history={}", resp.join_rule, resp.history_visibility)),
                                            Err(e) => status_msg.set(format!("policy failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Apply Policy"
                    }
                }
            }

            // Invite member
            div { class: "event", "data-testid": "invite-member",
                div { class: "event-head", span { "Invite Member" } span { "" } }
                div { class: "workflow-form",
                    input {
                        "data-testid": "invite-target-input",
                        value: "{invite_target}",
                        placeholder: "DID or handle",
                        oninput: move |evt| invite_target.set(evt.value()),
                    }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "send-invite-button",
                            onclick: {
                                let base = base_url.clone();
                                let space = selected_space.clone();
                                move |_| {
                                    let base = base.clone();
                                    let space = space.clone();
                                    let api_token = token();
                                    let target = invite_target();
                                    spawn(async move {
                                        if let Ok(api) = authed_api(&base, api_token) {
                                            match api.invite_to_space(&space, &target, None).await {
                                                Ok(resp) => status_msg.set(format!("invited {} ({})", resp.target, resp.state)),
                                                Err(e) => status_msg.set(format!("invite failed: {e}")),
                                            }
                                        }
                                    });
                                }
                            },
                            "Send Invite"
                        }
                    }
                }
            }

            // Member table
            div { class: "event", "data-testid": "member-table",
                div { class: "event-head", span { "Members" } span { "{members().len()}" } }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "refresh-members-button",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            move |_| {
                                let base = base.clone();
                                let space = space.clone();
                                let api_token = token();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.resolve_space(&space).await {
                                            Ok(_) => status_msg.set("Space resolved".to_owned()),
                                            Err(e) => status_msg.set(format!("resolve failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Refresh"
                    }
                }
                for member in members() {
                    div { class: "event", "data-testid": "member-row",
                        div { class: "event-head",
                            span { "{member}" }
                            span { "member" }
                        }
                        div { class: "actions",
                            button {
                                class: "secondary",
                                "data-testid": "kick-member-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let space = selected_space.clone();
                                    let m = member.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let space = space.clone();
                                        let m = m.clone();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                match api.remove_space_member(&space, &m).await {
                                                    Ok(_) => status_msg.set(format!("kicked {m}")),
                                                    Err(e) => status_msg.set(format!("kick failed: {e}")),
                                                }
                                            }
                                        });
                                    }
                                },
                                "Kick"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "ban-member-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let space = selected_space.clone();
                                    let m = member.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let space = space.clone();
                                        let m = m.clone();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                match api.ban_member(&space, &m).await {
                                                    Ok(_) => status_msg.set(format!("banned {m}")),
                                                    Err(e) => status_msg.set(format!("ban failed: {e}")),
                                                }
                                            }
                                        });
                                    }
                                },
                                "Ban"
                            }
                        }
                    }
                }
                if members().is_empty() {
                    div { class: "muted", "No members loaded." }
                }
            }

            // Space invites
            div { class: "event", "data-testid": "space-invites",
                div { class: "event-head", span { "Invites" } span { "incoming" } }
                for invite in space_invites() {
                    div { class: "event", "data-testid": "invite-row",
                        div { class: "muted", "{invite}" }
                        div { class: "actions",
                            button {
                                class: "primary",
                                onclick: {
                                    let base = base_url.clone();
                                    let space = selected_space.clone();
                                    let invite_id = invite.get("invite_id").and_then(|v| v.as_str()).unwrap_or("").to_owned();
                                    move |_| {
                                        let base = base.clone();
                                        let space = space.clone();
                                        let invite_id = invite_id.clone();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                let _ = api.accept_space_invite(&space, &invite_id).await;
                                            }
                                        });
                                    }
                                },
                                "Accept"
                            }
                            button {
                                class: "secondary",
                                onclick: {
                                    let base = base_url.clone();
                                    let space = selected_space.clone();
                                    let invite_id = invite.get("invite_id").and_then(|v| v.as_str()).unwrap_or("").to_owned();
                                    move |_| {
                                        let base = base.clone();
                                        let space = space.clone();
                                        let invite_id = invite_id.clone();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                let _ = api.reject_space_invite(&space, &invite_id).await;
                                            }
                                        });
                                    }
                                },
                                "Reject"
                            }
                        }
                    }
                }
                if space_invites().is_empty() {
                    div { class: "muted", "No pending invites." }
                }
            }

            // Space discovery toggle
            div { class: "event", "data-testid": "discovery-toggle",
                div { class: "event-head", span { "Discovery" } span { "visibility" } }
                label {
                    input {
                        r#type: "checkbox",
                        checked: discovery_enabled(),
                        onchange: move |evt| discovery_enabled.set(evt.value() == "true"),
                    }
                    " Listed in directory"
                }
            }

            // MLS epoch rotation
            div { class: "event", "data-testid": "mls-rotation",
                div { class: "event-head", span { "MLS Epoch" } span { "rotation" } }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "rotate-space-epoch",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            move |_| {
                                let base = base.clone();
                                let space = space.clone();
                                let api_token = token();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.rotate_mls_epoch(&space).await {
                                            Ok(resp) => status_msg.set(format!("rotated to epoch {}", resp.epoch)),
                                            Err(e) => status_msg.set(format!("rotate failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Rotate Epoch"
                    }
                }
            }

            // Leave space
            div { class: "event", "data-testid": "leave-space",
                div { class: "event-head", span { "Leave Space" } span { "" } }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "leave-space-button",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            move |_| {
                                let base = base.clone();
                                let space = space.clone();
                                let api_token = token();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.leave_space(&space).await {
                                            Ok(_) => status_msg.set(format!("left {space}")),
                                            Err(e) => status_msg.set(format!("leave failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Leave"
                    }
                }
            }

            // Danger zone
            div { class: "event", "data-testid": "danger-zone",
                div { class: "event-head", span { "Danger Zone" } span { "destructive actions" } }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "archive-space-button",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            move |_| {
                                let base = base.clone();
                                let space = space.clone();
                                let api_token = token();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.archive_space(&space).await {
                                            Ok(resp) => status_msg.set(format!("archived: {}", resp.archived)),
                                            Err(e) => status_msg.set(format!("archive failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Archive Space"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "delete-space-button",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            move |_| {
                                let base = base.clone();
                                let space = space.clone();
                                let api_token = token();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.delete_space(&space).await {
                                            Ok(_) => status_msg.set(format!("deleted {space}")),
                                            Err(e) => status_msg.set(format!("delete failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Tombstone / Delete"
                    }
                }
            }

            if !status_msg().is_empty() {
                div { class: "muted", "data-testid": "space-admin-status", "{status_msg}" }
            }
        }
    }
}
