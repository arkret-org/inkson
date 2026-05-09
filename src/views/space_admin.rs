use dioxus::prelude::*;
use serde_json::json;

use crate::{
    hlc::Hlc,
    local_state::LocalStateStore,
    move_builder::{
        UnsignedMove, build_capability_grant_move, build_capability_revoke_move,
        build_member_state_transition_move, build_space_organization_update_move,
        did_key_from_verifying_key, did_key_verification_method, sign_unsigned_move,
    },
    operation::{CommitBuilder, cx_ops},
    views::{
        consent_demo::{demo_signing_key, format_submit_response},
        helpers::{active_sync_token, authed_api, authed_api_with_sync},
    },
};

/// Placeholder anchor frontier used until sync.rs (P0 M3) surfaces the
/// effective Anchor head. Mirrors `consent_demo::PLACEHOLDER_ANCHOR_REF`.
const PLACEHOLDER_ANCHOR_REF: &str =
    "cx:anchor:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Pure helper: build + sign a `cx.space.update` Move that writes the
/// space organization cas-register cell. Mirrors the consent-grant signing
/// flow so the Dioxus closure stays small. Until we have proper key
/// management, the issuer DID is derived from the demo signing key —
/// this is gated by the same `TODO(real-key-management)` as the consent
/// PoC.
pub(crate) fn build_signed_space_organization_update(
    space_id: &str,
    value: serde_json::Value,
    anchor_ref: &str,
    hlc: &str,
) -> anyhow::Result<contrix_sdk::Move> {
    let signing = demo_signing_key();
    let did = did_key_from_verifying_key(&signing.verifying_key());
    let vm = did_key_verification_method(&signing.verifying_key());
    let unsigned: UnsignedMove =
        build_space_organization_update_move(&did, space_id, value, anchor_ref, hlc)?;
    Ok(sign_unsigned_move(unsigned, &signing, &vm))
}

/// Pure helper: build + sign a `cx.capability.grant` Move (OrSet add)
/// targeting `cx.component.capability.grant.v1`. Mirrors the consent
/// helpers — same signing path, just a different cell family. Admins
/// use this from the Capability Grants section to extend a capability
/// to a principal.
pub(crate) fn build_signed_capability_grant(
    space_id: &str,
    grant_id: &str,
    tag: &str,
    anchor_ref: &str,
    hlc: &str,
) -> anyhow::Result<contrix_sdk::Move> {
    let signing = demo_signing_key();
    let did = did_key_from_verifying_key(&signing.verifying_key());
    let vm = did_key_verification_method(&signing.verifying_key());
    let unsigned: UnsignedMove =
        build_capability_grant_move(&did, space_id, grant_id, tag, anchor_ref, hlc)?;
    Ok(sign_unsigned_move(unsigned, &signing, &vm))
}

/// Pure helper: build + sign a `cx.capability.revoke` Move (OrSet remove)
/// on the same cell family as the grant. `reason` shows up in the audit
/// trail and lets the UI explain why the capability was dropped.
pub(crate) fn build_signed_capability_revoke(
    space_id: &str,
    grant_id: &str,
    tag: &str,
    reason: Option<&str>,
    anchor_ref: &str,
    hlc: &str,
) -> anyhow::Result<contrix_sdk::Move> {
    let signing = demo_signing_key();
    let did = did_key_from_verifying_key(&signing.verifying_key());
    let vm = did_key_verification_method(&signing.verifying_key());
    let unsigned: UnsignedMove = build_capability_revoke_move(
        &did, space_id, grant_id, tag, reason, anchor_ref, hlc,
    )?;
    Ok(sign_unsigned_move(unsigned, &signing, &vm))
}

/// Pure helper: build + sign a `cx.member.state` FSM transition Move.
/// Used by Kick / Ban / Unban Move-flow buttons in the member table.
pub(crate) fn build_signed_member_state_transition(
    space_id: &str,
    actor_id: &str,
    from_state: &str,
    to_state: &str,
    anchor_ref: &str,
    hlc: &str,
) -> anyhow::Result<contrix_sdk::Move> {
    let signing = demo_signing_key();
    let did = did_key_from_verifying_key(&signing.verifying_key());
    let vm = did_key_verification_method(&signing.verifying_key());
    let unsigned: UnsignedMove = build_member_state_transition_move(
        &did,
        space_id,
        actor_id,
        from_state,
        to_state,
        anchor_ref,
        hlc,
    )?;
    Ok(sign_unsigned_move(unsigned, &signing, &vm))
}

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
    // Capability grant/revoke Move-flow inputs (see capability-grant-card)
    let mut cap_grant_id = use_signal(|| "cap.demo-01".to_owned());
    let mut cap_tag = use_signal(|| "discussion.message.create".to_owned());
    let mut cap_revoke_reason =
        use_signal(|| "rotation policy".to_owned());
    // Read-only anchorer cell value fetched from /api/admin/v1/spaces/{id}/anchorer.
    // The endpoint may 404 in dev — surface that inline rather than blocking the page.
    let mut anchorer_cell_status = use_signal(String::new);
    let mut anchorer_cell_value = use_signal(String::new);

    // Read the local anchor view for this space once per render. Surfaces:
    //  - bottom_cells set → "concurrent candidates unresolved" banner (P0 M5)
    //  - frontier head    → debug visibility into what Move builders thread
    //  - state_root       → admin can confirm divergence between local + server
    let anchor_view = state_store.read().anchor_view_for(&selected_space);
    let bottom_cells: Vec<(String, String)> = anchor_view
        .bottom_cells
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let anchor_frontier_label = if anchor_view.frontier.is_empty() {
        "(no Anchor seen — using sha256(empty) sentinel)".to_owned()
    } else {
        anchor_view.frontier.join(", ")
    };
    let anchor_state_root_label = anchor_view
        .state_root
        .clone()
        .unwrap_or_else(|| "(not published)".to_owned());

    rsx! {
        div { class: "timeline", "data-testid": "space-admin-panel",
            // Bottom=expose conflict banner — only rendered when at least
            // one cell in the projection has unresolved concurrent
            // candidates. P0 M5.
            if !bottom_cells.is_empty() {
                div { class: "event", "data-testid": "bottom-cells-banner",
                    div { class: "event-head",
                        span { "Concurrent candidates unresolved" }
                        span { class: "badge red", "bottom=expose" }
                    }
                    div { class: "muted",
                        "One or more cells in this Space's projection are in the bottom-expose state — soland received concurrent Moves it cannot deterministically merge. An admin / moderator must resolve each conflict by submitting a head_in repair Move before downstream queries return a definitive value."
                    }
                    for (cell_ref, status) in &bottom_cells {
                        div { class: "muted", "data-testid": "bottom-cell-row",
                            "{cell_ref} · status={status}"
                        }
                    }
                }
            }
            // Anchor frontier debug — shows whether sync has surfaced a
            // real Anchor view yet. When empty this matches the sentinel
            // Move builders thread in.
            div { class: "event", "data-testid": "anchor-frontier-debug",
                div { class: "event-head",
                    span { "Anchor frontier" }
                    span { "leaves={anchor_view.leaves.len()}" }
                }
                div { class: "muted", "data-testid": "anchor-frontier-heads",
                    "frontier: {anchor_frontier_label}"
                }
                div { class: "muted", "data-testid": "anchor-state-root",
                    "state_root: {anchor_state_root_label}"
                }
            }
            // Anchorer cell (read-only, P0 M4) — fetches from
            // /api/admin/v1/spaces/{id}/anchorer; surfaces the
            // recovery-anchorer mode (single_did / threshold / open_set /
            // mixed) on this admin page. A separate agent is implementing
            // the endpoint on soland; on 404 we fall back to a clear
            // inline message.
            div { class: "event", "data-testid": "anchorer-cell-card",
                div { class: "event-head",
                    span { "Anchorer cell" }
                    span { "cx.component.anchorer.v1" }
                }
                div { class: "muted",
                    "Recovery anchorer mode for this Space — controls who can re-anchor a paused frontier. Read-only; modifications go through the dedicated anchorer-rotation flow."
                }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "anchorer-cell-refresh",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            move |_| {
                                let base = base.clone();
                                let space = space.clone();
                                let api_token = token();
                                spawn(async move {
                                    let api = match authed_api(&base, api_token) {
                                        Ok(api) => api,
                                        Err(error) => {
                                            anchorer_cell_status
                                                .set(format!("API client unavailable: {error}"));
                                            return;
                                        }
                                    };
                                    match api.admin_anchorer_describe(&space).await {
                                        Ok(value) => {
                                            anchorer_cell_status.set("ok".to_owned());
                                            anchorer_cell_value.set(value.to_string());
                                        }
                                        Err(error) => {
                                            // 404 / not-implemented falls through here.
                                            // Keep the message clear so the operator
                                            // knows it's a missing endpoint, not bad
                                            // data.
                                            anchorer_cell_status.set(format!(
                                                "anchorer endpoint unavailable ({error}); \
                                                 expected /api/admin/v1/spaces/{{id}}/anchorer \
                                                 (separate agent shipping)"
                                            ));
                                        }
                                    }
                                });
                            }
                        },
                        "Fetch anchorer cell"
                    }
                }
                if !anchorer_cell_status().is_empty() {
                    div { class: "muted", "data-testid": "anchorer-cell-status",
                        "{anchorer_cell_status}"
                    }
                }
                if !anchorer_cell_value().is_empty() {
                    div { class: "muted", "data-testid": "anchorer-cell-value",
                        "{anchorer_cell_value}"
                    }
                }
            }
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
                        // Alternate Move-flow path: build a cx.space.update
                        // Move targeting cx.component.space.organization.v1
                        // (cas-register) and POST /api/v1/moves. Soland's
                        // LatticeRegistry routes this into the cell; the
                        // direct-event button above stays available until
                        // every deployment is on the new pipeline.
                        button {
                            class: "secondary",
                            "data-testid": "update-metadata-via-move-button",
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
                                    let value = json!({
                                        "title": name,
                                        "topic": topic,
                                        "description": desc,
                                    });
                                    let hlc = Hlc::now("yougen").to_string();
                                    let anchor_ref =
                                        state_store.read().anchor_ref_for_move(&space);
                                    let signed = match build_signed_space_organization_update(
                                        &space,
                                        value,
                                        &anchor_ref,
                                        &hlc,
                                    ) {
                                        Ok(m) => m,
                                        Err(e) => {
                                            status_msg.set(format!("build move failed: {e}"));
                                            return;
                                        }
                                    };
                                    spawn(async move {
                                        if let Ok(api) = authed_api(&base, api_token) {
                                            match api.submit_move(&signed).await {
                                                Ok(resp) => status_msg
                                                    .set(format_submit_response(&resp)),
                                                Err(e) => status_msg.set(format!(
                                                    "submit_move failed: {e}"
                                                )),
                                            }
                                        }
                                    });
                                }
                            },
                            "Save Metadata (Move)"
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

            // Member state — authz/event-auth-state-resolution.md §5
            // 5 MembershipState variants: Invited / Joined / Left / Banned / Knocked
            // Legal transitions form a state machine; reducer rejects illegal moves
            // with state_mismatch.
            div { class: "event", "data-testid": "member-state-banner",
                div { class: "event-head",
                    span { "Member state machine" }
                    span { "cx.member.state · 5 variants" }
                }
                div { class: "muted",
                    "成员状态由 cx.member.state event 驱动。`knock` Space 允许未邀请的 actor 敲门，admin 同意后 transition 为 invited 再 join。"
                }
                div { class: "actions",
                    span { class: "badge blue", "Invited" }
                    span { class: "badge green", "Joined" }
                    span { class: "badge", "Left" }
                    span { class: "badge red", "Banned" }
                    span { class: "badge amber", "Knocked" }
                }
                div { class: "muted",
                    "合法转移：none → {{join, invite, knock}} | invite → {{join, leave}} | knock → {{invite, leave}} | join → {{leave, ban}} | leave → {{invite, knock}} | ban → leave (via unban)。"
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
                            // Move-flow alternates: build cx.member.state
                            // FSM transitions on cx.component.member.state.v1
                            // and POST /api/v1/moves. Kick = join→leave;
                            // Ban = join→ban. The direct-event buttons
                            // above remain wired until every deployment is
                            // on the new pipeline.
                            button {
                                class: "secondary",
                                "data-testid": "kick-member-via-move-button",
                                onclick: {
                                    let space = selected_space.clone();
                                    let m = member.clone();
                                    let base = base_url.clone();
                                    move |_| {
                                        let api_token = token();
                                        let hlc = Hlc::now("yougen").to_string();
                                        let anchor_ref =
                                            state_store.read().anchor_ref_for_move(&space);
                                        let signed = match build_signed_member_state_transition(
                                            &space,
                                            &m,
                                            "join",
                                            "leave",
                                            &anchor_ref,
                                            &hlc,
                                        ) {
                                            Ok(m) => m,
                                            Err(e) => {
                                                status_msg.set(format!("build move failed: {e}"));
                                                return;
                                            }
                                        };
                                        let actor_label = m.clone();
                                        let base = base.clone();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                match api.submit_move(&signed).await {
                                                    Ok(resp) => status_msg.set(format!(
                                                        "kick(Move) {actor_label}: {}",
                                                        format_submit_response(&resp)
                                                    )),
                                                    Err(e) => status_msg.set(format!(
                                                        "kick(Move) failed: {e}"
                                                    )),
                                                }
                                            }
                                        });
                                    }
                                },
                                "Kick (Move)"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "ban-member-via-move-button",
                                onclick: {
                                    let space = selected_space.clone();
                                    let m = member.clone();
                                    let base = base_url.clone();
                                    move |_| {
                                        let api_token = token();
                                        let hlc = Hlc::now("yougen").to_string();
                                        let anchor_ref =
                                            state_store.read().anchor_ref_for_move(&space);
                                        let signed = match build_signed_member_state_transition(
                                            &space,
                                            &m,
                                            "join",
                                            "ban",
                                            &anchor_ref,
                                            &hlc,
                                        ) {
                                            Ok(m) => m,
                                            Err(e) => {
                                                status_msg.set(format!("build move failed: {e}"));
                                                return;
                                            }
                                        };
                                        let actor_label = m.clone();
                                        let base = base.clone();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                match api.submit_move(&signed).await {
                                                    Ok(resp) => status_msg.set(format!(
                                                        "ban(Move) {actor_label}: {}",
                                                        format_submit_response(&resp)
                                                    )),
                                                    Err(e) => status_msg.set(format!(
                                                        "ban(Move) failed: {e}"
                                                    )),
                                                }
                                            }
                                        });
                                    }
                                },
                                "Ban (Move)"
                            }
                        }
                    }
                }
                if members().is_empty() {
                    div { class: "muted", "No members loaded." }
                }
            }

            // Space invites — sync/third-party-invites.md + invite event family
            // 6 canonical events drive the invite lifecycle:
            //   cx.invite.create        — 创建 invite（主动邀请已知 DID）
            //   cx.invite.third_party   — 邀请 3PID（邮箱 / 手机号），未知 DID 时使用
            //   cx.invite.claim         — 受邀人接收 invite proof（绑定到他们的 DID）
            //   cx.invite.accept        — 受邀人正式接受（写入 membership）
            //   cx.invite.cancel        — 邀请方撤销（receiver 未 claim 前）
            //   cx.invite.revoke        — 邀请方撤销（receiver 已 claim 但未 accept）
            div { class: "event", "data-testid": "invite-lifecycle-banner",
                div { class: "event-head",
                    span { "Invite lifecycle" }
                    span { "6 canonical events" }
                }
                div { class: "muted",
                    "Invite 不直接授予 capability — 接受后才进入有效集合。MUST 携带 expires_at；默认 7 天，高安全 Space 24 小时。"
                }
                div { class: "actions",
                    span { class: "badge blue", "cx.invite.create" }
                    span { class: "badge blue", "cx.invite.third_party" }
                    span { class: "badge", "cx.invite.claim" }
                    span { class: "badge green", "cx.invite.accept" }
                    span { class: "badge amber", "cx.invite.cancel" }
                    span { class: "badge red", "cx.invite.revoke" }
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

            // Audited E2EE assurance — crypto-media/audited-e2ee.md
            // Two profiles: cx.profile.attested_audit.e2ee.v1 (HW attestation forced)
            // and cx.profile.disclosed_audit.e2ee.v1 (procedural disclosure only).
            // UI MUST surface the policy choice + canonical join warning copy +
            // forbidden marketing terms (see audited-e2ee §3.1.1 / §3.5).
            div { class: "event", "data-testid": "audited-e2ee-assurance",
                div { class: "event-head",
                    span { "Audited E2EE assurance" }
                    span { "audit_disclosure policy" }
                }
                div { class: "muted",
                    "v1 core 把 audited E2EE 拆成 attested / disclosed 两类 hardening profile。Space policy 通过 audit_disclosure 对象 + audit_assurance enum 声明；UI join warning 与对外材料按 audited-e2ee.md §3.1.1 / §3.5 normative 分类与禁用措辞执行。"
                }
                div { class: "metric-grid", "data-testid": "audited-e2ee-tiers",
                    div { class: "metric",
                        strong { "none" }
                        span { class: "badge", "default" }
                        div { class: "muted", "标准 MLS E2EE，无 audit profile" }
                    }
                    div { class: "metric",
                        strong { "disclosed_audit" }
                        span { class: "badge amber", "disclosed_audit.e2ee.v1" }
                        div { class: "muted", "审计 agent 流程性披露；强制留痕 cx.audit.accessed；无密码学 attestation" }
                    }
                    div { class: "metric",
                        strong { "attested_audit" }
                        span { class: "badge red", "attested_audit.e2ee.v1" }
                        div { class: "muted", "硬件 attestation 强制；RYW receipt schema 强制 cx.audit.ryw_receipt" }
                    }
                }
                div { class: "muted",
                    "禁用 marketing 措辞：不得宣称 \"end-to-end encrypted\" 不加修饰；必须使用 \"E2EE with disclosed/attested audit\"。详见 audited-e2ee.md §3.5。"
                }
                div { class: "actions",
                    span { class: "muted", "Audit-bound key share events:" }
                    span { class: "badge blue", "cx.space_key.share" }
                    span { class: "badge", "cx.space_key.share_audit" }
                    span { class: "badge red", "cx.space_key.withheld" }
                }
                div { class: "actions",
                    button { class: "secondary", "data-testid": "audited-e2ee-set-none", "无 audit profile" }
                    button { class: "secondary", "data-testid": "audited-e2ee-set-disclosed", "启用 disclosed_audit" }
                    button { class: "secondary", "data-testid": "audited-e2ee-set-attested", "启用 attested_audit" }
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
            //
            // Constraint type model (Round 9, 2026-05-05): 14 types collapsed into
            // 8 family + subtype discriminator per `authz/constraint-schema.md` §2.2:
            //   temporal (subtype: edit_window / redact_window / session_lifetime / ...)
            //   field_access (subtype: field_write_allow / field_write_deny)
            //   type_restriction (subtype: object_type / morph_type / facet)
            //   scope_limitation (subtype: container_move / view_kind / branch / ...)
            //   delegation_control (subtype: max_depth / subset_only)
            //   quota (subtype: rate / resource)
            //   claim_based (subtype: approval / accountability / ...)
            //   confidentiality (subtype: encryption / visibility / sensitive_handling)
            // The grant-explanation rows below treat constraint as a description hint;
            // any future write UI MUST emit `(family, subtype)` pairs, not the legacy
            // 14-type names. v0 → v1 mapping table is in constraint-schema.md §2.2.
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

            // Capability grant / revoke Move-flow card (P0 M-capability /
            // 第二十轮). Mirrors the consent grant/revoke PoC but targets
            // cx.component.capability.grant.v1 (OrSet add/remove). Signed
            // with the demo session key (TODO real-key-management) and
            // POST'd to /api/v1/moves. Anchor frontier is threaded from
            // the local sync view.
            div { class: "event", "data-testid": "capability-grant-card",
                div { class: "event-head",
                    span { "Capability grant / revoke (Move PoC)" }
                    span { "cx.component.capability.grant.v1 · OrSet" }
                }
                div { class: "muted",
                    "Build a cx.capability.grant or cx.capability.revoke Move on the capability OrSet cell, sign with the admin's session key, and POST /api/v1/moves. Anchor predecessor is taken from the local /sync Anchor view; falls back to sha256(empty) when sync hasn't surfaced one."
                }
                label { "Grant ID (cell subject)" }
                input {
                    "data-testid": "cap-grant-id-input",
                    value: "{cap_grant_id}",
                    oninput: move |evt| cap_grant_id.set(evt.value()),
                }
                label { "Capability tag (action / scope)" }
                input {
                    "data-testid": "cap-grant-tag-input",
                    value: "{cap_tag}",
                    oninput: move |evt| cap_tag.set(evt.value()),
                }
                label { "Revoke reason (optional)" }
                input {
                    "data-testid": "cap-revoke-reason-input",
                    value: "{cap_revoke_reason}",
                    oninput: move |evt| cap_revoke_reason.set(evt.value()),
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "cap-grant-submit-button",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            move |_| {
                                let base = base.clone();
                                let space = space.clone();
                                let api_token = token();
                                let grant_val = cap_grant_id().trim().to_owned();
                                let tag_val = cap_tag().trim().to_owned();
                                if grant_val.is_empty() || tag_val.is_empty() {
                                    status_msg.set(
                                        "fill grant_id + tag before submitting capability grant".to_owned(),
                                    );
                                    return;
                                }
                                let hlc = Hlc::now("yougen").to_string();
                                let anchor_ref =
                                    state_store.read().anchor_ref_for_move(&space);
                                let signed = match build_signed_capability_grant(
                                    &space,
                                    &grant_val,
                                    &tag_val,
                                    &anchor_ref,
                                    &hlc,
                                ) {
                                    Ok(m) => m,
                                    Err(e) => {
                                        status_msg.set(format!(
                                            "build capability grant failed: {e}"
                                        ));
                                        return;
                                    }
                                };
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.submit_move(&signed).await {
                                            Ok(resp) => status_msg.set(format!(
                                                "capability.grant: {}",
                                                format_submit_response(&resp)
                                            )),
                                            Err(e) => status_msg.set(format!(
                                                "capability.grant submit failed: {e}"
                                            )),
                                        }
                                    }
                                });
                            }
                        },
                        "Grant capability (Move)"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "cap-revoke-submit-button",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            move |_| {
                                let base = base.clone();
                                let space = space.clone();
                                let api_token = token();
                                let grant_val = cap_grant_id().trim().to_owned();
                                let tag_val = cap_tag().trim().to_owned();
                                let reason_val = cap_revoke_reason();
                                let reason_opt = if reason_val.trim().is_empty() {
                                    None
                                } else {
                                    Some(reason_val.clone())
                                };
                                if grant_val.is_empty() || tag_val.is_empty() {
                                    status_msg.set(
                                        "fill grant_id + tag before submitting capability revoke".to_owned(),
                                    );
                                    return;
                                }
                                let hlc = Hlc::now("yougen").to_string();
                                let anchor_ref =
                                    state_store.read().anchor_ref_for_move(&space);
                                let signed = match build_signed_capability_revoke(
                                    &space,
                                    &grant_val,
                                    &tag_val,
                                    reason_opt.as_deref(),
                                    &anchor_ref,
                                    &hlc,
                                ) {
                                    Ok(m) => m,
                                    Err(e) => {
                                        status_msg.set(format!(
                                            "build capability revoke failed: {e}"
                                        ));
                                        return;
                                    }
                                };
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.submit_move(&signed).await {
                                            Ok(resp) => status_msg.set(format!(
                                                "capability.revoke: {}",
                                                format_submit_response(&resp)
                                            )),
                                            Err(e) => status_msg.set(format!(
                                                "capability.revoke submit failed: {e}"
                                            )),
                                        }
                                    }
                                });
                            }
                        },
                        "Revoke capability (Move)"
                    }
                }
            }

            // Organization governance — identity/identity-did.md §6 + content-moderation
            // Organization 作为 Principal（不是 Space）。一个 Space 可以由多个 organization
            // 共同治理，Space 的 organization 关系通过 cx.space.organization event 维护。
            div { class: "event", "data-testid": "organization-governance",
                div { class: "event-head",
                    span { "Organization governance" }
                    span { "Space ≠ Organization" }
                }
                div { class: "muted",
                    "Organization 是 Principal（DID），不是 Space。多组织共治通过 cx.space.organization 关系表达；组织目录与审核策略独立维护，不绑定到任何单一 Space。"
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Owning organizations" }
                        span { "cx.space.organization" }
                        div { class: "muted", "声明 Space 的归属组织（可多个）" }
                    }
                    div { class: "metric",
                        strong { "Org directory listing" }
                        span { "cx.organization.discovery" }
                        div { class: "muted", "组织级 discoverability policy（独立于 Space）" }
                    }
                    div { class: "metric",
                        strong { "Org moderation policy" }
                        span { "cx.organization.moderation_policy" }
                        div { class: "muted", "组织级审核策略；Space 可继承 / 覆写" }
                    }
                    div { class: "metric",
                        strong { "Sovereign DID policy" }
                        span { "cx.sovereign.did_policy" }
                        div { class: "muted", "高安全部署：限制可接受的 DID method / resolver trust" }
                    }
                }
            }

            // Space hierarchy — models/space-hierarchy.md
            // 4 canonical events for parent/child + lifecycle:
            //   cx.space.child  — 声明 child Space
            //   cx.space.parent — 声明 parent Space（双向 declaration）
            //   cx.space.upgrade — 升级 schema profile / reducer profile
            //   cx.space.lifecycle.set — active / archived / suspended / draft 状态切换
            div { class: "event", "data-testid": "space-hierarchy",
                div { class: "event-head",
                    span { "Space hierarchy & lifecycle" }
                    span { "models/space-hierarchy.md" }
                }
                div { class: "muted",
                    "Parent / child Space 关系可形成层级或图状组织。Child security-boundary Space 仍是独立边界 — 默认不级联 membership / capability / encryption。任何继承 MUST 由 child Space 显式声明。"
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Child link" }
                        span { "cx.space.child" }
                        div { class: "muted", "声明子 Space" }
                    }
                    div { class: "metric",
                        strong { "Parent link" }
                        span { "cx.space.parent" }
                        div { class: "muted", "声明父 Space" }
                    }
                    div { class: "metric",
                        strong { "Schema upgrade" }
                        span { "cx.space.upgrade" }
                        div { class: "muted", "升级 reducer / schema profile（不破坏现有 frontier）" }
                    }
                    div { class: "metric",
                        strong { "Lifecycle state" }
                        span { "cx.space.lifecycle.set" }
                        div { class: "muted", "active / archived / suspended / draft" }
                    }
                }
            }

            // Policy events — authz/policy-server.md
            // cx.policy.{rule,action,set} 三个 event 是 reducer 决策输入：
            //   cx.policy.rule    — 单条规则（match condition + effect + scope）
            //   cx.policy.action  — 单条 action 模板（被 rule 引用）
            //   cx.policy.set     — 把 rule + action 打包发布为 policy version
            div { class: "event", "data-testid": "policy-event-family",
                div { class: "event-head",
                    span { "Policy authoring" }
                    span { "cx.policy.{{rule,action,set}}" }
                }
                div { class: "muted",
                    "Policy 是 reducer / 服务节点判断请求是否可接受的输入。Policy 通过 rule + action 组合发布为 set；同一 policy_version 一次写入。"
                }
                div { class: "actions",
                    span { class: "badge blue", "cx.policy.rule" }
                    span { class: "badge", "cx.policy.action" }
                    span { class: "badge green", "cx.policy.set" }
                    span { class: "muted", "—— 三 event 联合发布为 policy version" }
                    span { class: "muted", "policy_version_ref 由 cx.space.policy.set 选取" }
                }
            }

            // Moderation events — governance/content-moderation.md
            // Two canonical events drive content-level moderation:
            //   cx.moderation.report — actor 提交举报（针对 message / flow / morph / actor）
            //   cx.moderation.frank  — E2EE franking proof（让加密内容也可被审核）
            // Quarantine / require_review 等是 reducer 决策结果，不是独立 event。
            div { class: "event", "data-testid": "moderation-events",
                div { class: "event-head",
                    span { "Moderation events" }
                    span { "governance/content-moderation.md" }
                }
                div { class: "muted",
                    "举报和审核证据由两 event 驱动；reducer 输出 (deny / quarantine / require_review) 通过 cx.policy.action 落地。E2EE 内容通过 franking 让审核者可验证发送方又不破坏密文。"
                }
                div { class: "actions",
                    span { class: "badge blue", "cx.moderation.report" }
                    span { class: "badge accent", "cx.moderation.frank" }
                    span { class: "muted", "→ reducer 输出 cx.policy.action（deny/quarantine/require_review）" }
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

#[cfg(test)]
mod move_flow_tests {
    use super::*;
    use contrix_sdk::LatticeOpType;

    fn fixed_anchor_ref() -> &'static str {
        PLACEHOLDER_ANCHOR_REF
    }

    fn fixed_hlc() -> &'static str {
        "0189c4d2af00-00000000-aabbccdd"
    }

    /// "Save Metadata (Move)" wiring: produces a cx.space.update Move
    /// targeting the cx.component.space.organization.v1 cas-register cell
    /// with the form values folded into the cell's value object.
    #[test]
    fn build_signed_space_organization_update_targets_organization_cell() {
        let space = "cx:space:0196419b-0000-7000-8000-000000000000";
        let signed = build_signed_space_organization_update(
            space,
            json!({"title": "Renamed", "topic": "new"}),
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        assert_eq!(signed.space_id.as_str(), space);
        assert_eq!(signed.effects.len(), 1);
        let effect = &signed.effects[0];
        assert!(
            effect
                .cell
                .as_str()
                .starts_with("cx:cell:cx.component.space.organization.v1:"),
            "space organization update must target the organization cell family"
        );
        assert_eq!(effect.op.op_type, LatticeOpType::Set);
        let value = effect.op.value.as_ref().expect("set op carries value");
        assert_eq!(value.get("title").and_then(|v| v.as_str()), Some("Renamed"));
        assert_eq!(value.get("topic").and_then(|v| v.as_str()), Some("new"));
        // Detached JWS attached so soland's verifier can validate.
        assert!(!signed.sig.jws.is_empty());
        let parts: Vec<&str> = signed.sig.jws.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    /// "Kick (Move)" wiring: produces an FSM transition from join → leave
    /// on cx.component.member.state.v1 keyed by the actor id.
    #[test]
    fn build_signed_member_state_transition_kick_produces_join_leave_fsm() {
        let signed = build_signed_member_state_transition(
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "did:web:alice.example",
            "join",
            "leave",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &signed.effects[0];
        assert!(
            effect
                .cell
                .as_str()
                .starts_with("cx:cell:cx.component.member.state.v1:"),
            "member state transition must target the member.state cell family"
        );
        assert_eq!(effect.op.op_type, LatticeOpType::Transition);
        assert_eq!(
            effect.op.from.as_ref().and_then(|v| v.as_str()),
            Some("join")
        );
        assert_eq!(
            effect.op.to.as_ref().and_then(|v| v.as_str()),
            Some("leave")
        );
    }

    /// "Ban (Move)" wiring: produces an FSM transition from join → ban
    /// on the same cell family (different terminal state).
    #[test]
    fn build_signed_member_state_transition_ban_produces_join_ban_fsm() {
        let signed = build_signed_member_state_transition(
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "did:web:alice.example",
            "join",
            "ban",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &signed.effects[0];
        assert_eq!(effect.op.op_type, LatticeOpType::Transition);
        assert_eq!(effect.op.to.as_ref().and_then(|v| v.as_str()), Some("ban"));
    }

    /// "Grant capability (Move)" wiring: produces a cx.capability.grant
    /// Move targeting cx.component.capability.grant.v1 with the form's
    /// tag added to the OrSet.
    #[test]
    fn build_signed_capability_grant_targets_capability_or_set_cell() {
        let signed = build_signed_capability_grant(
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cap.demo-01",
            "discussion.message.create",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &signed.effects[0];
        assert!(
            effect
                .cell
                .as_str()
                .starts_with("cx:cell:cx.component.capability.grant.v1:"),
            "capability grant must target the capability.grant.v1 cell family"
        );
        assert_eq!(effect.op.op_type, LatticeOpType::Add);
        assert_eq!(
            effect.op.tag.as_deref(),
            Some("discussion.message.create")
        );
        // Detached JWS attached so soland's verifier can validate.
        assert!(!signed.sig.jws.is_empty());
    }

    /// "Revoke capability (Move)" wiring: produces a cx.capability.revoke
    /// Move on the SAME OrSet cell — soland's causal-remove semantics
    /// require it. Reason field flows through.
    #[test]
    fn build_signed_capability_revoke_attaches_reason_and_remove_op() {
        let signed = build_signed_capability_revoke(
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cap.demo-01",
            "discussion.message.create",
            Some("rotation policy"),
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &signed.effects[0];
        assert!(
            effect
                .cell
                .as_str()
                .starts_with("cx:cell:cx.component.capability.grant.v1:"),
            "capability revoke targets the same OrSet cell as the grant"
        );
        assert_eq!(effect.op.op_type, LatticeOpType::Remove);
        assert_eq!(effect.op.reason.as_deref(), Some("rotation policy"));
    }

    /// Different from-state values produce different content-addressed
    /// move ids — ensures soland can distinguish kick from ban even if
    /// every other input is identical (form, hlc, anchor_ref).
    #[test]
    fn member_state_kick_and_ban_have_distinct_content_addresses() {
        let space = "cx:space:0196419b-0000-7000-8000-000000000000";
        let actor = "did:web:alice.example";
        let kick = build_signed_member_state_transition(
            space,
            actor,
            "join",
            "leave",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let ban = build_signed_member_state_transition(
            space,
            actor,
            "join",
            "ban",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        assert_ne!(kick.id.as_str(), ban.id.as_str());
    }
}
