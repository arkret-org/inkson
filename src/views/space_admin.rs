use dioxus::prelude::*;
use serde_json::json;

use crate::{
    local_state::LocalStateStore,
    operation::{CommitBuilder, cx_ops},
    views::helpers::{active_sync_token, authed_api, authed_api_with_sync},
};

#[derive(Clone, Debug, PartialEq)]
struct InviteRecord {
    invite_id: String,
    target: String,
    role: Option<String>,
    state: String,
    operation_id: Option<String>,
    commit_id: Option<String>,
}

#[component]
pub fn SpaceAdminPanel(
    base_url: String,
    account_did: String,
    token: Signal<String>,
    selected_space: String,
    sync_cursor: Signal<String>,
    repo_state: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let mut space_name = use_signal(|| String::new());
    let mut space_topic = use_signal(|| String::new());
    let mut space_description = use_signal(|| String::new());
    let mut join_rule = use_signal(|| "open".to_owned());
    let mut history_visibility = use_signal(|| "shared".to_owned());
    let mut invite_target = use_signal(String::new);
    let mut status_msg = use_signal(|| String::new());
    let members = use_signal(Vec::<String>::new);
    let mut space_invites = use_signal(Vec::<InviteRecord>::new);
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
            div { class: "event", "data-testid": "admin-discussion-admission",
                div { class: "event-head", span { "Discussion-scoped external admission" } span { "policy proposal" } }
                div { class: "muted",
                    "External access is granted to a Discussion, not to the whole Space or linked Card. History visibility and capability grants remain separate."
                }
                div { class: "metric-grid",
                    div { class: "metric", strong { "Discussion" } span { "cx:flow:external-counsel" } div { class: "muted", "history: joined" } }
                    div { class: "metric", strong { "Capability" } span { "discussion.message.create" } div { class: "muted", "expires in 7 days" } }
                    div { class: "metric", strong { "Discussion Coupling" } span { "none" } div { class: "muted", "linked Discussion remains separately authorized" } }
                    div { class: "metric", strong { "Review" } span { "requires admin approval" } div { class: "muted", "danger actions require reason" } }
                }
                div { class: "actions",
                    button {
                        class: "secondary",
                                "data-testid": "queue-discussion-admission",
                        onclick: move |_| status_msg.set("queued Discussion-scoped external admission proposal".to_owned()),
                        "Queue admission proposal"
                    }
                    button {
                        class: "secondary",
                                "data-testid": "deny-discussion-admission",
                        onclick: move |_| status_msg.set("denied without leaking locked Discussion membership".to_owned()),
                        "Deny"
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
                                let actor = account_did.clone();
                                let space = selected_space.clone();
                                move |_| {
                                    let base = base.clone();
                                    let actor = actor.clone();
                                    let space = space.clone();
                                    let api_token = token();
                                    let target = invite_target().trim().to_owned();
                                    if target.is_empty() {
                                        status_msg.set("invite target is required".to_owned());
                                        return;
                                    }
                                    let wait_for = active_sync_token(&sync_cursor());
                                    let expected_head = expected_head(repo_state());
                                    spawn(async move {
                                        match authed_api_with_sync(&base, api_token, wait_for) {
                                            Ok(api) => match api.invite_to_space(&space, &target, None).await {
                                                Ok(resp) => {
                                                    let op = cx_ops::invite_create_structured(
                                                        &space,
                                                        &actor,
                                                        &resp.invite_id,
                                                        &resp.target,
                                                        None,
                                                        &resp.state,
                                                    )
                                                    .build("yougen");
                                                    let commit = CommitBuilder::new(actor.clone())
                                                        .add_operation(op.clone())
                                                        .build();
                                                    let commit_value = match serde_json::to_value(&commit) {
                                                        Ok(value) => value,
                                                        Err(error) => {
                                                            status_msg.set(format!("invite serialize failed: {error}"));
                                                            return;
                                                        }
                                                    };
                                                    match api
                                                        .submit_commit(
                                                            &actor,
                                                            commit_value,
                                                            expected_head.as_deref(),
                                                            Some(&op.operation_id),
                                                        )
                                                        .await
                                                    {
                                                        Ok(submitted) => {
                                                            space_invites.write().push(InviteRecord {
                                                                invite_id: resp.invite_id.clone(),
                                                                target: resp.target.clone(),
                                                                role: None,
                                                                state: resp.state.clone(),
                                                                operation_id: Some(op.operation_id.clone()),
                                                                commit_id: Some(submitted.commit_id.clone()),
                                                            });
                                                            repo_state.set(
                                                                submitted
                                                                    .head_commit
                                                                    .clone()
                                                                    .unwrap_or(submitted.commit_id.clone()),
                                                            );
                                                            sync_cursor.set(submitted.sync_token.clone());
                                                            {
                                                                let mut store = state_store.write();
                                                                store.save_sync_cursor(submitted.sync_token.clone());
                                                                store.append_raw_operation(
                                                                    op.operation_id.clone(),
                                                                    Some(space.clone()),
                                                                    json!({
                                                                        "kind": "cx.invite.create",
                                                                        "invite_id": resp.invite_id,
                                                                        "target": resp.target,
                                                                        "state": resp.state,
                                                                        "commit_id": submitted.commit_id,
                                                                    }),
                                                                );
                                                            }
                                                            invite_target.set(String::new());
                                                            status_msg.set(format!(
                                                                "invited {} ({}) fact {}",
                                                                target, "pending", op.operation_id
                                                            ));
                                                        }
                                                        Err(error) => status_msg.set(format!("invite fact failed: {error}")),
                                                    }
                                                }
                                                Err(e) => status_msg.set(format!("invite failed: {e}")),
                                            }
                                            Err(error) => status_msg.set(format!("invalid server URL: {error}")),
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
                div { class: "event-head", span { "Invites" } span { "lifecycle" } }
                for invite in space_invites() {
                    div { class: "event", "data-testid": "invite-row",
                        div { class: "event-head",
                            span { "{invite.target}" }
                            span { "{invite.state}" }
                        }
                        div { class: "muted", "data-testid": "invite-id", "{invite.invite_id}" }
                        if let Some(role) = &invite.role {
                            div { class: "muted", "role {role}" }
                        }
                        if let Some(operation_id) = &invite.operation_id {
                            div { class: "muted", "fact {operation_id}" }
                        }
                        if let Some(commit_id) = &invite.commit_id {
                            div { class: "muted", "commit {commit_id}" }
                        }
                        div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "accept-invite-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let space = selected_space.clone();
                                    let invite_id = invite.invite_id.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let actor = actor.clone();
                                        let space = space.clone();
                                        let invite_id = invite_id.clone();
                                        let api_token = token();
                                        let wait_for = active_sync_token(&sync_cursor());
                                        let expected_head = expected_head(repo_state());
                                        spawn(async move {
                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                Ok(api) => match api.accept_space_invite(&space, &invite_id).await {
                                                    Ok(resp) => {
                                                        let op = cx_ops::invite_accept(&space, &actor, &invite_id).build("yougen");
                                                        let commit = CommitBuilder::new(actor.clone())
                                                            .add_operation(op.clone())
                                                            .build();
                                                        let commit_value = match serde_json::to_value(&commit) {
                                                            Ok(value) => value,
                                                            Err(error) => {
                                                                status_msg.set(format!("accept serialize failed: {error}"));
                                                                return;
                                                            }
                                                        };
                                                        match api
                                                            .submit_commit(
                                                                &actor,
                                                                commit_value,
                                                                expected_head.as_deref(),
                                                                Some(&op.operation_id),
                                                            )
                                                            .await
                                                        {
                                                            Ok(submitted) => {
                                                                for row in space_invites.write().iter_mut() {
                                                                    if row.invite_id == invite_id {
                                                                        row.state = resp.state.clone();
                                                                        row.operation_id = Some(op.operation_id.clone());
                                                                        row.commit_id = Some(submitted.commit_id.clone());
                                                                    }
                                                                }
                                                                repo_state.set(
                                                                    submitted
                                                                        .head_commit
                                                                        .clone()
                                                                        .unwrap_or(submitted.commit_id.clone()),
                                                                );
                                                                sync_cursor.set(submitted.sync_token.clone());
                                                                {
                                                                    let mut store = state_store.write();
                                                                    store.save_sync_cursor(submitted.sync_token.clone());
                                                                    store.append_raw_operation(
                                                                        op.operation_id.clone(),
                                                                        Some(space.clone()),
                                                                        json!({
                                                                            "kind": "cx.invite.accept",
                                                                            "invite_id": invite_id,
                                                                            "state": resp.state,
                                                                            "commit_id": submitted.commit_id,
                                                                        }),
                                                                    );
                                                                }
                                                                status_msg.set(format!("accepted invite fact {}", op.operation_id));
                                                            }
                                                            Err(error) => status_msg.set(format!("accept fact failed: {error}")),
                                                        }
                                                    }
                                                    Err(error) => status_msg.set(format!("accept failed: {error}")),
                                                }
                                                Err(error) => status_msg.set(format!("invalid server URL: {error}")),
                                            }
                                        });
                                    }
                                },
                                "Accept"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "cancel-invite-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let space = selected_space.clone();
                                    let invite_id = invite.invite_id.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let actor = actor.clone();
                                        let space = space.clone();
                                        let invite_id = invite_id.clone();
                                        let api_token = token();
                                        let wait_for = active_sync_token(&sync_cursor());
                                        let expected_head = expected_head(repo_state());
                                        spawn(async move {
                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                Ok(api) => match api.reject_space_invite(&space, &invite_id).await {
                                                    Ok(resp) => {
                                                        let op = cx_ops::invite_cancel(
                                                            &space,
                                                            &actor,
                                                            &invite_id,
                                                            Some("declined"),
                                                        )
                                                        .build("yougen");
                                                        let commit = CommitBuilder::new(actor.clone())
                                                            .add_operation(op.clone())
                                                            .build();
                                                        let commit_value = match serde_json::to_value(&commit) {
                                                            Ok(value) => value,
                                                            Err(error) => {
                                                                status_msg.set(format!("cancel serialize failed: {error}"));
                                                                return;
                                                            }
                                                        };
                                                        match api
                                                            .submit_commit(
                                                                &actor,
                                                                commit_value,
                                                                expected_head.as_deref(),
                                                                Some(&op.operation_id),
                                                            )
                                                            .await
                                                        {
                                                            Ok(submitted) => {
                                                                for row in space_invites.write().iter_mut() {
                                                                    if row.invite_id == invite_id {
                                                                        row.state = resp.state.clone();
                                                                        row.operation_id = Some(op.operation_id.clone());
                                                                        row.commit_id = Some(submitted.commit_id.clone());
                                                                    }
                                                                }
                                                                repo_state.set(
                                                                    submitted
                                                                        .head_commit
                                                                        .clone()
                                                                        .unwrap_or(submitted.commit_id.clone()),
                                                                );
                                                                sync_cursor.set(submitted.sync_token.clone());
                                                                {
                                                                    let mut store = state_store.write();
                                                                    store.save_sync_cursor(submitted.sync_token.clone());
                                                                    store.append_raw_operation(
                                                                        op.operation_id.clone(),
                                                                        Some(space.clone()),
                                                                        json!({
                                                                            "kind": "cx.invite.cancel",
                                                                            "invite_id": invite_id,
                                                                            "state": resp.state,
                                                                            "commit_id": submitted.commit_id,
                                                                        }),
                                                                    );
                                                                }
                                                                status_msg.set(format!("canceled invite fact {}", op.operation_id));
                                                            }
                                                            Err(error) => status_msg.set(format!("cancel fact failed: {error}")),
                                                        }
                                                    }
                                                    Err(error) => status_msg.set(format!("cancel failed: {error}")),
                                                }
                                                Err(error) => status_msg.set(format!("invalid server URL: {error}")),
                                            }
                                        });
                                    }
                                },
                                "Cancel"
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

            // Capability grant explanation — claude-design desktop/space-admin.html
            // authz/capabilities.md (delegation, revocation, claim conditions)
            div { class: "event", "data-testid": "grant-explanation",
                div { class: "event-head",
                    span { "Capability Grants" }
                    span { "approval_constraint trail" }
                }
                div { class: "muted",
                    "Grant 是 reducer 接受/拒绝写入的依据。每次决策都可追溯到签名 grant；高风险动作叠加 approval_constraint。Handle / 邮箱仅作展示，权限主体以 DID 为准。"
                }
                div { class: "metric-grid", "data-testid": "grant-explanation-rows",
                    div { class: "metric",
                        strong { "Mei (admin)" }
                        span { "read · write · moderate · grant" }
                        div { class: "muted", "did:plc:8djrfj4… · 永久 · auto-renew" }
                    }
                    div { class: "metric",
                        strong { "Build-bot (applet)" }
                        span { "write_message · reaction" }
                        div { class: "muted", "did:web:bot.acme.example · 30d · approval=auto" }
                    }
                    div { class: "metric",
                        strong { "Researcher Agent" }
                        span { "read_flow (申请中)" }
                        div { class: "muted", "approval_constraint = 2 of 3 admin · 1/3 已批准" }
                    }
                    div { class: "metric",
                        strong { "Compliance Auditor (partner)" }
                        span { "read_flow + write_morph(audit_report)" }
                        div { class: "muted", "did:web:partner.example · weekly job · revocable" }
                    }
                }
                div { class: "actions", "data-testid": "grant-decision-actions",
                    button { class: "primary", "data-testid": "grant-approve-button", "批准 Researcher Agent" }
                    button { class: "secondary", "data-testid": "grant-deny-button", "拒绝并签名 cx.capability.revoke" }
                    button { class: "secondary", "data-testid": "grant-explain-button", "查看完整 grant trail (audit)" }
                }
                div { class: "muted",
                    "Reducer 决策入口：cx.capability.grant / cx.capability.revoke / approval_constraint resolved。详细 trail 在 /audit。"
                }
            }

            // Trust bundle import — claude-design desktop/space-admin.html
            // sync/federation.md + sync/sovereign-deployment.md
            div { class: "event", "data-testid": "trust-bundle-panel",
                div { class: "event-head",
                    span { "Trust Bundle (Federation)" }
                    span { "受信 organization / service DID" }
                }
                div { class: "muted",
                    "联邦 / 跨组织 / Controlled Collaboration Space 必须用显式 trust_bundle 列出可参与的 organization DID + service DID + trusted issuer。导入前请校验 method evidence、trust root 与 service delegation。"
                }
                div { class: "metric-grid", "data-testid": "trust-bundle-rows",
                    div { class: "metric",
                        strong { "did:web:partner.example" }
                        span { "trust_bundle v3" }
                        div { class: "muted", "active · federation_in" }
                    }
                    div { class: "metric",
                        strong { "did:web:beta.example" }
                        span { "trust_bundle v2 · pending" }
                        div { class: "muted", "缺 attestation issuer; trust root 未确认" }
                    }
                    div { class: "metric",
                        strong { "did:web:github-mirror.acme.example" }
                        span { "portal scope only" }
                        div { class: "muted", "applet · plaintext_visible(portal)" }
                    }
                    div { class: "metric",
                        strong { "did:web:hsm.contrix.social" }
                        span { "service · backup HSM" }
                        div { class: "muted", "1 次/年配额; recovery only" }
                    }
                }
                div { class: "actions", "data-testid": "trust-bundle-actions",
                    button { class: "primary", "data-testid": "trust-bundle-import-button", "导入 trust_bundle" }
                    button { class: "secondary", "data-testid": "trust-bundle-validate-button", "校验签名 + method evidence" }
                    button { class: "secondary", "data-testid": "trust-bundle-revoke-button", "Revoke federation_in (partner)" }
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

fn expected_head(repo_state: String) -> Option<String> {
    repo_state.starts_with("cx:commit:").then_some(repo_state)
}
