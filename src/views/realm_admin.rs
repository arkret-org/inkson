use dioxus::prelude::*;
use dioxus_router::Link;
use serde_json::{Value, json};

use crate::hlc::Hlc;
use crate::local_state::{LocalStateStore, MoveSubmissionState};
use crate::models::RealmTreeNodeKind;
use crate::operation::cx_ops;
use crate::routes::Route;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;
use crate::views::helpers::{active_sync_token, authed_api_with_sync, short_protocol_id};

/// Default `covered_frontier_lag` warning threshold used by the
/// realm_admin alert banner. Mirrors sodmin's
/// `DEFAULT_LAG_WARN_THRESHOLD` so a member moving between the two
/// surfaces sees the same alert ceiling. Read from the user preference
/// signal in [`RealmAdminPanel`].
pub(crate) const DEFAULT_COVERED_FRONTIER_LAG_THRESHOLD: u64 = 5;

/// Number of member rows the list renders per page. The member list is
/// hydrated from the full local sync projection (which can hold tens of
/// thousands of entries for a large Realm), so we never mount every row
/// at once — we render this many and reveal more on demand. Keeps the DOM
/// node count bounded regardless of Realm size, mirroring how Telegram
/// pages its participant list rather than materializing the whole roster.
const MEMBER_PAGE_SIZE: usize = 50;

/// Once a Realm has more than this many members the inline search box is
/// shown. Below it, scanning the list by eye is faster than typing.
const MEMBER_SEARCH_THRESHOLD: usize = 8;

// NOTE: All build_signed_*_move helpers and record_submit_outcome have
// been removed — every Move-based write path was migrated to
// ck.self.events.submit via the cx_ops::* event builders. The original
// helpers (and their tests) are preserved in git history.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RealmAdminSection {
    Overview,
    Profile,
    Access,
    Security,
    Federation,
    Repair,
}

impl RealmAdminSection {
    fn from_slug(slug: Option<&str>) -> Self {
        match slug.unwrap_or_default() {
            "profile" => Self::Profile,
            "access" => Self::Access,
            "security" => Self::Security,
            "federation" => Self::Federation,
            "repair" => Self::Repair,
            _ => Self::Overview,
        }
    }

    fn slug(self) -> Option<&'static str> {
        match self {
            Self::Overview => None,
            Self::Profile => Some("profile"),
            Self::Access => Some("access"),
            Self::Security => Some("security"),
            Self::Federation => Some("federation"),
            Self::Repair => Some("repair"),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Profile => "Profile",
            Self::Access => "Access",
            Self::Security => "Security & MLS",
            Self::Federation => "Federation",
            Self::Repair => "Repair & Danger",
        }
    }

    fn sections() -> [Self; 6] {
        [
            Self::Overview,
            Self::Profile,
            Self::Access,
            Self::Security,
            Self::Federation,
            Self::Repair,
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MetadataSubject {
    kind: RealmTreeNodeKind,
    home_realm_id: String,
    title: String,
    summary: String,
    avatar_blob_ref: String,
}

fn projection_string(body: &Value, paths: &[&[&str]]) -> Option<String> {
    for path in paths {
        let mut current = body;
        let mut found = true;
        for segment in *path {
            if let Some(next) = current.get(*segment) {
                current = next;
            } else {
                found = false;
                break;
            }
        }
        if !found {
            continue;
        }
        if let Some(value) = current.as_str().map(str::trim).filter(|s| !s.is_empty()) {
            return Some(value.to_owned());
        }
    }
    None
}

fn projection_kind_for_admin(subject_id: &str, body: Option<&Value>) -> RealmTreeNodeKind {
    if subject_id.starts_with("ck:realm:") {
        return RealmTreeNodeKind::Realm;
    }
    let Some(body) = body else {
        return RealmTreeNodeKind::Realm;
    };
    match body
        .get("__kind")
        .and_then(Value::as_str)
        .or_else(|| body.get("schema").and_then(Value::as_str))
    {
        Some("space") | Some("ck.schema.space.v1") => RealmTreeNodeKind::Space,
        Some("realm") | Some("ck.schema.realm.v1") => RealmTreeNodeKind::Realm,
        _ => {
            let has_parent = projection_string(
                body,
                &[&["parent_space_id"], &["summary", "parent_space_id"]],
            )
            .is_some();
            if subject_id.starts_with("ck:realm:") && has_parent {
                RealmTreeNodeKind::Space
            } else {
                RealmTreeNodeKind::Realm
            }
        }
    }
}

fn projection_home_realm_for_admin(
    subject_id: &str,
    kind: RealmTreeNodeKind,
    body: Option<&Value>,
) -> String {
    if kind == RealmTreeNodeKind::Realm {
        return crate::operation::trim_realm_id(subject_id);
    }
    body.and_then(|body| projection_string(body, &[&["realm_id"], &["summary", "realm_id"]]))
        .unwrap_or_else(|| crate::operation::trim_realm_id(subject_id))
}

fn metadata_subject_for(store: &LocalStateStore, subject_id: &str) -> MetadataSubject {
    let state = store.load();
    let body = state.realm_tree_projections.get(subject_id);
    let kind = projection_kind_for_admin(subject_id, body);
    let title = body
        .and_then(|body| {
            projection_string(
                body,
                &[&["summary", "title"], &["title"], &["object", "title"]],
            )
        })
        .unwrap_or_default();
    let summary = body
        .and_then(|body| {
            projection_string(
                body,
                &[
                    &["summary", "summary"],
                    &["summary"],
                    &["description"],
                    &["object", "summary"],
                    &["object", "description"],
                ],
            )
        })
        .unwrap_or_default();
    let avatar_blob_ref = body
        .and_then(|body| {
            projection_string(
                body,
                &[
                    &["summary", "avatar_blob_ref"],
                    &["avatar_blob_ref"],
                    &["object", "avatar_blob_ref"],
                ],
            )
        })
        .unwrap_or_default();
    MetadataSubject {
        kind,
        home_realm_id: projection_home_realm_for_admin(subject_id, kind, body),
        title,
        summary,
        avatar_blob_ref,
    }
}

fn projected_members_for_realm(store: &LocalStateStore, realm_id: &str) -> Vec<String> {
    store
        .load()
        .realm_tree_projections
        .get(realm_id)
        .and_then(|proj| {
            proj.get("members").or_else(|| {
                proj.get("summary")
                    .and_then(|summary| summary.get("members"))
            })
        })
        .and_then(|members| members.as_array())
        .map(|members| {
            members
                .iter()
                .filter_map(|member| {
                    member.as_str().map(ToOwned::to_owned).or_else(|| {
                        member
                            .get("did")
                            .and_then(|did| did.as_str())
                            .map(ToOwned::to_owned)
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RealmMemberPermissions {
    loaded: bool,
    can_invite: bool,
    can_remove: bool,
}

fn authz_json_allowed(value: &Value) -> bool {
    value
        .get("allowed")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| {
            value
                .get("decision")
                .and_then(Value::as_str)
                .map(|decision| matches!(decision, "allow" | "allowed"))
                .unwrap_or(false)
        })
}

#[component]
pub fn RealmMembersPanel(
    base_url: String,
    account_did: String,
    token: Signal<String>,
    selected_realm_id: String,
    sync_cursor: Signal<String>,
    frontier_state: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let mut invite_target = use_signal(String::new);
    let mut status_msg = use_signal(String::new);
    let mut members = use_signal(Vec::<String>::new);
    let mut block_confirm_did = use_signal(|| Option::<String>::None);
    let mut permissions = use_signal(RealmMemberPermissions::default);
    // Invite is now a modal launched from the list header "+" button.
    let mut invite_modal_open = use_signal(|| false);
    // Client-side member search + incremental paging. `member_filter`
    // narrows the projected roster; `member_visible` caps how many rows we
    // actually mount so a 10k-member Realm doesn't render 10k DOM nodes.
    let mut member_filter = use_signal(String::new);
    let mut member_visible = use_signal(|| MEMBER_PAGE_SIZE);

    {
        let selected_realm_for_hydration = selected_realm_id.clone();
        use_effect(move || {
            let next =
                projected_members_for_realm(&state_store.read(), &selected_realm_for_hydration);
            if members() != next {
                members.set(next);
            }
        });
    }

    {
        let base = base_url.clone();
        let actor = account_did.clone();
        let realm = selected_realm_id.clone();
        use_effect(move || {
            let api_token = token();
            if api_token.trim().is_empty() || actor.trim().is_empty() || realm.trim().is_empty() {
                permissions.set(RealmMemberPermissions {
                    loaded: true,
                    ..RealmMemberPermissions::default()
                });
                return;
            }
            permissions.set(RealmMemberPermissions::default());
            let base = base.clone();
            let actor = actor.clone();
            let realm = realm.clone();
            spawn(async move {
                match authed_api_with_sync(&base, api_token, None) {
                    Ok(api) => {
                        let invite = api
                            .authz_check_raw(&actor, "ck.invite.create", &realm)
                            .await;
                        let remove = api
                            .authz_check_raw(&actor, "ck.member.remove", &realm)
                            .await;
                        let can_invite = invite.as_ref().map(authz_json_allowed).unwrap_or(false);
                        let can_remove = remove.as_ref().map(authz_json_allowed).unwrap_or(false);
                        if invite.is_err() && remove.is_err() {
                            status_msg.set(
                                "member action permission check failed; write controls hidden"
                                    .to_owned(),
                            );
                        }
                        permissions.set(RealmMemberPermissions {
                            loaded: true,
                            can_invite,
                            can_remove,
                        });
                    }
                    Err(error) => {
                        permissions.set(RealmMemberPermissions {
                            loaded: true,
                            ..RealmMemberPermissions::default()
                        });
                        status_msg.set(format!("member action permission check failed: {error}"));
                    }
                }
            });
        });
    }

    let member_permissions = permissions();
    let can_invite = member_permissions.can_invite;
    let can_remove = member_permissions.can_remove;

    // Roster → filtered → paged window. Filtering a Vec<String> by
    // substring is cheap even at tens of thousands of entries; the cost we
    // actually avoid is mounting every matching row, so only the first
    // `member_visible` of the filtered set is handed to the render loop.
    let all_members = members();
    let total_members = all_members.len();
    let filter_query = member_filter().trim().to_lowercase();
    let filtered_members: Vec<String> = if filter_query.is_empty() {
        all_members
    } else {
        all_members
            .into_iter()
            .filter(|m| m.to_lowercase().contains(&filter_query))
            .collect()
    };
    let filtered_count = filtered_members.len();
    let visible = member_visible().min(filtered_count);
    let visible_members: Vec<String> = filtered_members[..visible].to_vec();
    let has_more = visible < filtered_count;
    let show_search = total_members > MEMBER_SEARCH_THRESHOLD;
    // Icon buttons carry their label via title/aria-label instead of text.
    let refresh_label = crate::i18n::tr("realm_admin.refresh_members");

    rsx! {
        div { class: "timeline", "data-testid": "realm-members-panel",
            if can_invite && invite_modal_open() {
                crate::components::DismissiblePopup {
                    overlay_class: "modal-backdrop",
                    surface_class: "modal invite-modal",
                    overlay_test_id: Some("invite-member-modal".to_owned()),
                    aria_label: "Invite member",
                    on_dismiss: move |_| invite_modal_open.set(false),
                        div { class: "modal-head",
                            h3 { "Invite member" }
                            Button {
                                variant: ButtonVariant::Secondary,
                                class: "icon-button close",
                                "aria-label": "Close",
                                "data-testid": "invite-modal-close",
                                onclick: move |_| invite_modal_open.set(false),
                                "\u{2715}"
                            }
                        }
                        div { class: "modal-body workflow-form",
                            Label { html_for: "invite-target-input", "Invite locator" }
                            Input {
                                id: "invite-target-input",
                                "data-testid": "invite-target-input",
                                value: "{invite_target}",
                                placeholder: "Paste an invite locator link",
                                oninput: move |event: FormEvent| invite_target.set(event.value()),
                            }
                            div { class: "muted members-invite-hint",
                                {crate::i18n::tr("realm_admin.invite_hint")}
                            }
                        }
                        div { class: "modal-foot",
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "invite-modal-cancel",
                                onclick: move |_| invite_modal_open.set(false),
                                "Cancel"
                            }
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "send-invite-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let realm = selected_realm_id.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let actor = actor.clone();
                                        let realm = realm.clone();
                                        let api_token = token();
                                        let target = invite_target().trim().to_owned();
                                        if target.is_empty() {
                                            status_msg.set("invite locator is required".to_owned());
                                            return;
                                        }
                                        let wait_for = active_sync_token(sync_cursor());
                                        let invite_id = format!(
                                            "ck:invite:{}",
                                            crate::operation::uuid_v7()
                                        );
                                        spawn(async move {
                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                Ok(api) => {
                                                    let invitee = match api
                                                        .resolve_invitee_for_invite(
                                                            &target,
                                                            &realm,
                                                            &actor,
                                                        )
                                                        .await
                                                    {
                                                        Ok(did) => did,
                                                        Err(error) => {
                                                            status_msg.set(format!("invite locator resolve failed: {error}"));
                                                            return;
                                                        }
                                                    };
                                                    let invitee_label = invitee
                                                        .handle
                                                        .clone()
                                                        .unwrap_or_else(|| invitee.did.clone());
                                                    let op = cx_ops::invite_create_structured(
                                                        &realm,
                                                        &actor,
                                                        &invite_id,
                                                        &invitee.did,
                                                        None,
                                                        invitee.invite_delivery_target.clone(),
                                                        &invitee.introduction_evidence_digest,
                                                    )
                                                    .build("yougen");
                                                    let op_id = op.local_operation_id().to_owned();
                                                    status_msg.set(format!(
                                                        "submitting invite for {}",
                                                        invitee_label
                                                    ));
                                                    match api.submit_event_envelope(&op).await {
                                                        Ok(submitted) => {
                                                            frontier_state.set(submitted.event_id.clone());
                                                            {
                                                                let mut store = state_store.write();
                                                                store.append_raw_operation(
                                                                    op_id.clone(),
                                                                    Some(realm.clone()),
                                                                    json!({
                                                                        "kind": "ck.invite.create",
                                                                        "invite_id": invite_id,
                                                                        "invitee": invitee.did,
                                                                        "state": "pending",
                                                                        "event_id": submitted.event_id,
                                                                    }),
                                                                );
                                                            }
                                                            invite_target.set(String::new());
                                                            invite_modal_open.set(false);
                                                            status_msg.set(format!(
                                                                "invited {} (pending) fact {}",
                                                                invitee_label,
                                                                short_protocol_id(&op_id)
                                                            ));
                                                        }
                                                        Err(error) => status_msg.set(format!("invite failed: {error}")),
                                                    }
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

            div { class: "event member-list-card", "data-testid": "member-table",
                div { class: "event-head",
                    span { "Members" }
                    div { class: "member-head-actions",
                        span {
                            class: "badge member-count-badge",
                            "data-testid": "realm-members-count",
                            "{total_members}"
                        }
                        if can_invite {
                            Button {
                                variant: ButtonVariant::Secondary,
                                class: "member-head-icon-btn member-head-icon-btn-accent",
                                "data-testid": "open-invite-modal-button",
                                title: "Invite member",
                                "aria-label": "Invite member",
                                onclick: move |_| invite_modal_open.set(true),
                                crate::components::UiIcon { name: "plus" }
                            }
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            class: "member-head-icon-btn",
                            "data-testid": "refresh-members-button",
                            title: "{refresh_label}",
                            "aria-label": "{refresh_label}",
                            onclick: {
                                let realm = selected_realm_id.clone();
                                move |_| {
                                    let store = state_store.read();
                                    let next = projected_members_for_realm(&store, &realm);
                                    let count = next.len();
                                    members.set(next);
                                    member_visible.set(MEMBER_PAGE_SIZE);
                                    status_msg.set(format!(
                                        "members refreshed ({count}) from local sync state"
                                    ));
                                }
                            },
                            crate::components::UiIcon { name: "refresh" }
                        }
                    }
                }
                if !status_msg().is_empty() {
                    div { class: "muted", "data-testid": "realm-members-status", "{status_msg()}" }
                }
                if member_permissions.loaded && !can_invite && !can_remove {
                    div {
                        class: "muted",
                        "data-testid": "realm-member-actions-hidden",
                        "Member-management actions are not available for this account."
                    }
                }
                if show_search {
                    Input {
                        class: "member-search-input",
                        "data-testid": "member-search-input",
                        value: "{member_filter}",
                        placeholder: "Search members…",
                        oninput: move |event: FormEvent| {
                            member_filter.set(event.value());
                            member_visible.set(MEMBER_PAGE_SIZE);
                        },
                    }
                }
                for member in visible_members {
                    {
                        let member_label = short_protocol_id(&member);
                        rsx! {
                            div { class: "event", "data-testid": "member-row", "data-member-did": "{member}",
                                div { class: "event-head",
                                    {
                                        let initial = member
                                            .trim_start_matches("did:web:")
                                            .chars()
                                            .next()
                                            .map(|c| c.to_ascii_uppercase().to_string())
                                            .unwrap_or_else(|| "?".to_owned());
                                        rsx! {
                                            div {
                                                "data-testid": "member-avatar",
                                                "aria-hidden": "true",
                                                style: "display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 28px; border-radius: 50%; background: var(--bg-elevated, #2a2d33); color: var(--text-strong, #fff); font-size: 0.8rem; margin-right: 8px;",
                                                "{initial}"
                                            }
                                        }
                                    }
                                    span { title: "{member}", "{member_label}" }
                                    {
                                        let is_agent = state_store
                                            .read()
                                            .load()
                                            .raw_operations
                                            .iter()
                                            .any(|r| {
                                                r.payload
                                                    .get("kind")
                                                    .and_then(|k| k.as_str())
                                                    == Some("ck.agent.endpoint")
                                                    && r.realm_id
                                                        .as_deref()
                                                        .map(|s| s == selected_realm_id)
                                                        .unwrap_or(true)
                                                    && r.payload
                                                        .get("body")
                                                        .and_then(|b| b.get("agent_id"))
                                                        .and_then(|d| d.as_str())
                                                        == Some(member.as_str())
                                            });
                                        rsx! {
                                            if is_agent {
                                                span {
                                                    class: "badge member-badge member-badge-agent",
                                                    "data-testid": "member-badge-agent",
                                                    title: "Automated member (bot)",
                                                    "\u{1f916} "
                                                    {crate::i18n::tr("member.badge.agent")}
                                                }
                                            }
                                        }
                                    }
                                    span { "member" }
                                }
                                div { class: "actions",
                                    if can_remove {
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "kick-member-button",
                                            onclick: {
                                                let base = base_url.clone();
                                                let realm = selected_realm_id.clone();
                                                let m = member.clone();
                                                let actor_account_did = account_did.clone();
                                                move |_| {
                                                    let base = base.clone();
                                                    let realm = realm.clone();
                                                    let m = m.clone();
                                                    let api_token = token();
                                                    let actor_did = actor_account_did.clone();
                                                    spawn(async move {
                                                        let m_for_msg = m.clone();
                                                        let realm_for_api = realm.clone();
                                                        match crate::views::helpers::with_authed_api(
                                                            &base,
                                                            api_token,
                                                            |api| async move {
                                                                api.transition_member_state(
                                                                    &realm_for_api,
                                                                    &actor_did,
                                                                    &m,
                                                                    Some("join"),
                                                                    "leave",
                                                                    "admin_kick",
                                                                )
                                                                .await
                                                            },
                                                        )
                                                        .await
                                                        {
                                                            Ok(resp) => {
                                                                let mls_encrypted = state_store
                                                                    .read()
                                                                    .realm_projection_is_mls_encrypted(&realm);
                                                                if mls_encrypted {
                                                                    state_store.write().record_move_submission_with_event_id(
                                                                        resp.event_id.clone(),
                                                                        Some(resp.event_id.clone()),
                                                                        realm.clone(),
                                                                        "mls_member_remove",
                                                                        MoveSubmissionState::PendingMlsBinding,
                                                                        Some("epoch_update_required: membership frontier changed; MLS Remove commit required".to_owned()),
                                                                        None,
                                                                    );
                                                                }
                                                                let suffix = if mls_encrypted {
                                                                    "; epoch_update_required"
                                                                } else {
                                                                    ""
                                                                };
                                                                status_msg.set(format!(
                                                                    "kicked {}{}",
                                                                    short_protocol_id(&m_for_msg),
                                                                    suffix
                                                                ));
                                                            }
                                                            Err(err) => status_msg.set(format!(
                                                                "kick failed: {}", err.display()
                                                            )),
                                                        }
                                                    });
                                                }
                                            },
                                            {crate::i18n::tr("realm_admin.kick_member")}
                                        }
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "ban-member-button",
                                            onclick: {
                                                let base = base_url.clone();
                                                let realm = selected_realm_id.clone();
                                                let m = member.clone();
                                                let actor_account_did = account_did.clone();
                                                move |_| {
                                                    let base = base.clone();
                                                    let realm = realm.clone();
                                                    let m = m.clone();
                                                    let api_token = token();
                                                    let actor_did = actor_account_did.clone();
                                                    spawn(async move {
                                                        let m_for_msg = m.clone();
                                                        let realm_for_api = realm.clone();
                                                        match crate::views::helpers::with_authed_api(
                                                            &base,
                                                            api_token,
                                                            |api| async move {
                                                                api.ban_member(&realm_for_api, &actor_did, &m).await
                                                            },
                                                        )
                                                        .await
                                                        {
                                                            Ok(resp) => {
                                                                let mls_encrypted = state_store
                                                                    .read()
                                                                    .realm_projection_is_mls_encrypted(&realm);
                                                                if mls_encrypted {
                                                                    state_store.write().record_move_submission_with_event_id(
                                                                        resp.event_id.clone(),
                                                                        Some(resp.event_id.clone()),
                                                                        realm.clone(),
                                                                        "mls_member_remove",
                                                                        MoveSubmissionState::PendingMlsBinding,
                                                                        Some("epoch_update_required: membership frontier changed; MLS Remove commit required".to_owned()),
                                                                        None,
                                                                    );
                                                                }
                                                                let suffix = if mls_encrypted {
                                                                    "; epoch_update_required"
                                                                } else {
                                                                    ""
                                                                };
                                                                status_msg.set(format!(
                                                                    "banned {}{}",
                                                                    short_protocol_id(&m_for_msg),
                                                                    suffix
                                                                ));
                                                            }
                                                            Err(err) => status_msg.set(format!(
                                                                "ban failed: {}", err.display()
                                                            )),
                                                        }
                                                    });
                                                }
                                            },
                                            {crate::i18n::tr("realm_admin.ban_member")}
                                        }
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "member-row-block-button",
                                        onclick: {
                                            let m = member.clone();
                                            move |_| block_confirm_did.set(Some(m.clone()))
                                        },
                                        {crate::i18n::tr("member.block")}
                                    }
                                }
                                if block_confirm_did().as_deref() == Some(member.as_str()) {
                                    div {
                                        class: "event",
                                        "data-testid": "block-user-confirm-modal",
                                        div { class: "entity-title", {crate::i18n::tr("member.block_confirm.title")} }
                                        div { class: "muted", title: "{member}", "{member_label}" }
                                        div { class: "muted", {crate::i18n::tr("member.block_confirm.body")} }
                                        div { class: "actions",
                                            Button {
                                                variant: ButtonVariant::Primary,
                                                "data-testid": "block-user-confirm-button",
                                                onclick: {
                                                    let m = member.clone();
                                                    let base = base_url.clone();
                                                    move |_| {
                                                        let changed = state_store
                                                            .write()
                                                            .block_user(&m, None);
                                                        block_confirm_did.set(None);
                                                        if changed {
                                                            status_msg.set(format!(
                                                                "Blocked {}",
                                                                short_protocol_id(&m)
                                                            ));
                                                            let entries = state_store
                                                                .read()
                                                                .client_blocklist();
                                                            crate::views::settings::push_blocklist_account_data(
                                                                base.clone(),
                                                                token(),
                                                                entries,
                                                            );
                                                        } else {
                                                            status_msg.set(format!(
                                                                "{} is already blocked",
                                                                short_protocol_id(&m)
                                                            ));
                                                        }
                                                    }
                                                },
                                                {crate::i18n::tr("member.block_confirm.confirm")}
                                            }
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                "data-testid": "block-user-cancel-button",
                                                onclick: move |_| block_confirm_did.set(None),
                                                {crate::i18n::tr("timeline.cancel")}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if filtered_count == 0 {
                    div { class: "members-empty", "data-testid": "members-empty-state",
                        if total_members == 0 {
                            div { class: "members-empty-icon", crate::components::UiIcon { name: "users" } }
                            div { class: "members-empty-title", {crate::i18n::tr("realm_admin.no_members_loaded")} }
                            if can_invite {
                                div { class: "muted members-empty-hint",
                                    {crate::i18n::tr("realm_admin.members_empty_hint")}
                                }
                            }
                        } else {
                            div { class: "members-empty-icon", crate::components::UiIcon { name: "search" } }
                            div { class: "members-empty-title", {crate::i18n::tr("realm_admin.members_no_match")} }
                        }
                    }
                }
                if has_more {
                    div { class: "member-load-more",
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "load-more-members-button",
                            onclick: move |_| {
                                let next = member_visible() + MEMBER_PAGE_SIZE;
                                member_visible.set(next);
                            },
                            "Load more — showing {visible} of {filtered_count}"
                        }
                    }
                }
            }
        }
    }
}

fn split_policy_list(raw: &str) -> Vec<String> {
    let mut values = Vec::new();
    for value in raw
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_ascii_whitespace())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !values.iter().any(|existing| existing == value) {
            values.push(value.to_owned());
        }
    }
    values
}

fn normalize_did_method_entry(value: &str) -> Result<String, String> {
    let trimmed = value.trim().to_ascii_lowercase();
    let method = trimmed.strip_prefix("did:").unwrap_or(trimmed.as_str());
    if method.is_empty()
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(format!("invalid DID method: {value}"));
    }
    Ok(format!("did:{method}"))
}

fn normalize_did_list(raw: &str, label: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    for value in split_policy_list(raw) {
        cokret_sdk::Did::new(value.clone()).map_err(|err| format!("{label}: {err}"))?;
        if !values.iter().any(|existing| existing == &value) {
            values.push(value);
        }
    }
    Ok(values)
}

fn build_principal_admission_join_policy(
    enabled: bool,
    methods_raw: &str,
    allowed_dids_raw: &str,
    denied_dids_raw: &str,
) -> Result<Option<Value>, String> {
    if !enabled {
        return Ok(None);
    }
    let mut methods = Vec::new();
    for method in split_policy_list(methods_raw) {
        let method = normalize_did_method_entry(&method)?;
        if !methods.iter().any(|existing| existing == &method) {
            methods.push(method);
        }
    }
    let allowed_dids = normalize_did_list(allowed_dids_raw, "allowed principal DID")?;
    let denied_dids = normalize_did_list(denied_dids_raw, "denied principal DID")?;
    if methods.is_empty() && allowed_dids.is_empty() && denied_dids.is_empty() {
        return Err("principal admission requires a method, allowlist DID, or denylist DID".into());
    }
    let mut gate = json!({
        "gate_id": "principal-admission",
        "kind": "principal_admission",
        "auto_resolve": true
    });
    if !methods.is_empty() {
        gate["allowed_did_methods"] = json!(methods);
    }
    if !allowed_dids.is_empty() {
        gate["allowed_principal_dids"] = json!(allowed_dids);
    }
    if !denied_dids.is_empty() {
        gate["denied_principal_dids"] = json!(denied_dids);
    }
    Ok(Some(json!({
        "gates": [gate],
        "combinator": "all"
    })))
}

#[component]
pub fn RealmAdminPanel(
    base_url: String,
    account_did: String,
    device_id: String,
    token: Signal<String>,
    selected_realm_id: String,
    sync_cursor: Signal<String>,
    frontier_state: Signal<String>,
    state_store: Signal<LocalStateStore>,
    active_section: Option<String>,
) -> Element {
    let mut metadata_title = use_signal(String::new);
    let mut metadata_summary = use_signal(String::new);
    let mut metadata_avatar_blob_ref = use_signal(String::new);
    let mut metadata_loaded_for = use_signal(String::new);
    let mut join_rule = use_signal(|| "open".to_owned());
    let mut principal_admission_enabled = use_signal(|| false);
    let mut principal_admission_methods = use_signal(|| "did:webvh".to_owned());
    let mut principal_admission_allowed_dids = use_signal(String::new);
    let mut principal_admission_denied_dids = use_signal(String::new);
    let mut history_visibility = use_signal(|| "shared".to_owned());
    let mut status_msg = use_signal(String::new);
    // Capability grant/revoke Move-flow inputs (see capability-grant-card)
    let mut cap_grant_id = use_signal(|| "cap.demo-01".to_owned());
    let mut cap_tag = use_signal(|| "discussion.message.create".to_owned());
    let mut cap_revoke_reason = use_signal(|| "rotation policy".to_owned());
    // Structured constraint inputs for the capability grant.
    // `cap_constraint_kind` chooses the family (`temporal` / `quota` /
    // `scope_limitation` / `none`); the temporal MVP exposes `not_before`
    // / `expires_at` RFC 3339 timestamps (`not_after` is a forbidden wire
    // field name). Quota / scope_limitation are surfaced in the dropdown
    // but show a "coming soon" hint until matching widgets land.
    let mut cap_constraint_kind = use_signal(|| "none".to_owned());
    let mut cap_temporal_not_before = use_signal(String::new);
    let mut cap_temporal_expires_at = use_signal(String::new);
    // Covered_frontier alert threshold. Default 5 (mirrors sodmin's
    // `DEFAULT_LAG_WARN_THRESHOLD`); user can override via the numeric
    // input next to the banner.
    let mut covered_frontier_threshold = use_signal(|| DEFAULT_COVERED_FRONTIER_LAG_THRESHOLD);
    // Read-only anchorer cell value fetched from /_soland/admin/realms/{id}/anchorer.
    // The endpoint may 404 in dev — surface that inline rather than blocking the page.
    let mut anchorer_cell_status = use_signal(String::new);
    let mut anchorer_cell_value = use_signal(String::new);
    // Selected Move for the failure detail inline panel. Clicking a row
    // that's in a failed state stores its move_id here; the detail block
    // below renders the reason / anchor_ref.
    let mut move_detail_open = use_signal(|| Option::<String>::None);
    // Conflict-repair dialog state. Surfaces when the local projection
    // has bottom=expose cells; the operator picks two of the conflicting
    // heads + a recovery capability ref and submits a head_in repair
    // Move.
    let mut repair_target_cell = use_signal(String::new);
    let mut repair_head_a = use_signal(String::new);
    let mut repair_head_b = use_signal(String::new);
    let mut repair_capability_ref = use_signal(|| "cap.recovery-01".to_owned());
    let mut repair_state_witness_ref = use_signal(String::new);
    let mut repair_inclusion_proof_ref = use_signal(String::new);
    let mut repair_winner_json = use_signal(String::new);
    // Read the local anchor view for this realm once per render. Surfaces:
    //  - bottom_cells set → "concurrent candidates unresolved" banner (P0 M5)
    //  - frontier head    → debug visibility into what Move builders thread
    //  - state_root       → admin can confirm divergence between local + server
    let anchor_view = state_store.read().anchor_view_for_realm(&selected_realm_id);
    let bottom_cells: Vec<(String, crate::local_state::BottomCellInfo)> = anchor_view
        .bottom_cells
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    // Per-cell safer-winner suggestion, cloned out of the anchor_view so
    // the rsx! event handlers don't have to borrow it. Tuple is
    // (cell_ref, head_a_move_id, head_b_move_id, safer_value_json).
    let safer_suggestions: Vec<(String, String, String, String)> = bottom_cells
        .iter()
        .filter_map(|(cell_ref, _)| {
            let (head_a, head_b, value) = anchor_view.safer_winner_for(cell_ref)?;
            let json = serde_json::to_string_pretty(&value).ok()?;
            Some((cell_ref.clone(), head_a, head_b, json))
        })
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
    // MLS epoch + governance covered_frontier for the read-only widget.
    // `mls_epoch` is the cas-register value of ck.component.mls.epoch.v1;
    // `covered_frontier` is the
    // ck.component.governance.covered_frontier.v1 cell value. Both come
    // from the same anchor view the bottom-cells banner reads.
    let mls_epoch_label = anchor_view
        .mls_epoch
        .map(|epoch| epoch.to_string())
        .unwrap_or_else(|| "(no MLS epoch published)".to_owned());
    let covered_frontier_label = anchor_view
        .covered_frontier
        .clone()
        .unwrap_or_else(|| "(no governance covered_frontier published)".to_owned());
    // Covered_frontier_lag value + threshold check for the alert banner.
    // We render only when a lag value has actually been surfaced AND it
    // exceeds the (user-configurable) warning threshold - matches the
    // sodmin admin page UX.
    let covered_frontier_lag_value = anchor_view.covered_frontier_lag;
    let covered_frontier_lag_threshold = covered_frontier_threshold();
    let covered_frontier_alert =
        anchor_view.covered_frontier_lag_above(covered_frontier_lag_threshold);
    let covered_frontier_lag_label = covered_frontier_lag_value
        .map(|lag| lag.to_string())
        .unwrap_or_else(|| "-".to_owned());
    // per-Realm Move submission tracker. Drives the state-pill list +
    // the Realm-wide anchorer_paused banner.
    let move_submissions = state_store
        .read()
        .move_submissions_for_realm(&selected_realm_id);
    let realm_paused = state_store
        .read()
        .realm_has_paused_anchorer(&selected_realm_id);
    let realm_pending_mls_binding = state_store
        .read()
        .realm_has_pending_mls_binding(&selected_realm_id);
    let active_section = RealmAdminSection::from_slug(active_section.as_deref());
    let metadata_subject = metadata_subject_for(&state_store.read(), &selected_realm_id);
    if metadata_loaded_for() != selected_realm_id {
        metadata_title.set(metadata_subject.title.clone());
        metadata_summary.set(metadata_subject.summary.clone());
        metadata_avatar_blob_ref.set(metadata_subject.avatar_blob_ref.clone());
        metadata_loaded_for.set(selected_realm_id.clone());
    }
    let metadata_subject_label = match metadata_subject.kind {
        RealmTreeNodeKind::Realm => "Realm",
        RealmTreeNodeKind::Space => "Space",
    };
    let metadata_event_kind = match metadata_subject.kind {
        RealmTreeNodeKind::Realm => "ck.realm.update",
        RealmTreeNodeKind::Space => "ck.space.update",
    };
    let alert_count = usize::from(realm_paused)
        + usize::from(realm_pending_mls_binding)
        + usize::from(!bottom_cells.is_empty())
        + usize::from(covered_frontier_alert);
    let projected_member_count =
        projected_members_for_realm(&state_store.read(), &selected_realm_id).len();

    rsx! {
        div { class: "timeline", "data-testid": "realm-admin-panel",
            div { class: "actions", "data-testid": "realm-admin-sections",
                for section in RealmAdminSection::sections() {
                    if let Some(slug) = section.slug() {
                        Link {
                            class: if active_section == section { "primary" } else { "secondary" },
                            to: Route::RealmAdminSection {
                                realm_id: selected_realm_id.clone(),
                                section: slug.to_owned(),
                            },
                            "{section.label()}"
                        }
                    } else {
                        Link {
                            class: if active_section == section { "primary" } else { "secondary" },
                            to: Route::RealmAdmin {
                                realm_id: selected_realm_id.clone(),
                            },
                            "{section.label()}"
                        }
                    }
                }
            }
            if active_section == RealmAdminSection::Overview {
                div { class: "event", "data-testid": "realm-admin-overview",
                    div { class: "event-head",
                        span { "Realm settings" }
                        span { title: "{selected_realm_id}", "{short_protocol_id(&selected_realm_id)}" }
                    }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { {crate::i18n::tr("realm_admin.members")} }
                            span { "{projected_member_count} known" }
                            Link {
                                class: "secondary",
                                to: Route::RealmMembers {
                                    realm_id: selected_realm_id.clone(),
                                },
                                "Open Members"
                            }
                        }
                        div { class: "metric",
                            strong { "Profile" }
                            span { "{metadata_subject_label} title, summary, avatar" }
                            Link {
                                class: "secondary",
                                to: Route::RealmAdminSection {
                                    realm_id: selected_realm_id.clone(),
                                    section: "profile".to_owned(),
                                },
                                "Open Profile"
                            }
                        }
                        div { class: "metric",
                            strong { {crate::i18n::tr("realm_admin.access")} }
                            span { "{join_rule()} / {history_visibility()}" }
                            Link {
                                class: "secondary",
                                to: Route::RealmAdminSection {
                                    realm_id: selected_realm_id.clone(),
                                    section: "access".to_owned(),
                                },
                                "Open Access"
                            }
                        }
                        div { class: "metric",
                            strong { "Security & repair" }
                            span { "{alert_count} alerts · epoch {mls_epoch_label}" }
                            Link {
                                class: "secondary",
                                to: Route::RealmAdminSection {
                                    realm_id: selected_realm_id.clone(),
                                    section: "security".to_owned(),
                                },
                                "Open Security"
                            }
                        }
                    }
                }
            }
            // Realm-wide anchorer-paused banner. Fires whenever any tracked
            // Move for this Realm has surfaced `AnchorerPaused`. The Space
            // cannot advance until ops rotate the recovery anchorer.
            if realm_paused {
                div {
                    class: "event error-banner",
                    "data-testid": "anchorer-paused-banner",
                    div { class: "event-head",
                        span { "Realm halted, waiting for the recovery anchorer" }
                        span { class: "badge red", "anchorer_paused" }
                    }
                    div { class: "muted",
                        "soland's anchorer signing pipeline is offline for this Realm — Moves remain in MoveStore but no Anchor batch will close until ops rotate the recovery anchorer (sodmin H'8). All write attempts surface state=anchorer_paused."
                    }
                }
            }
            // Pending MLS binding toast — when a recent E2EE message Event
            // asserts a covered_frontier the local
            // MLS view has not yet acknowledged. Stays up until the
            // user clears the underlying Move record.
            if realm_pending_mls_binding {
                div {
                    class: "event",
                    "data-testid": "pending-mls-binding-toast",
                    div { class: "event-head",
                        span { "covered_frontier has not yet caught up to the required governance frontier" }
                        span { class: "badge amber", "pending_mls_binding" }
                    }
                    div { class: "muted",
                        "The MLS commit Move that should bind your last encrypted message has not yet been acknowledged by the governance frontier. Outgoing messages stay encrypted but won't deliver until the binding lands."
                    }
                }
            }
            // Move submission tracker - pill list of recent local writes
            // with state badges. Clicking a failed row reveals the reason
            // inline.
            if active_section == RealmAdminSection::Repair && !move_submissions.is_empty() {
                div { class: "event", "data-testid": "move-submission-tracker",
                    div { class: "event-head",
                        span { "Recent Move submissions" }
                        span { "{move_submissions.len()} tracked" }
                    }
                    div { class: "muted",
                        "Local Move/Anchor pipeline state for writes you've submitted from this device. Pending → Effective once anchored; failures expand inline."
                    }
                    for record in move_submissions.clone() {
                        {
                            let move_id_label = short_protocol_id(&record.move_id);
                            rsx! {
                                div { class: "event", "data-testid": "move-submission-row",
                                    div { class: "event-head",
                                        span { "{record.kind}" }
                                        span {
                                            class: "{record.state.badge_class()}",
                                            "data-testid": "move-state-badge",
                                            "data-state-slug": "{record.state.slug()}",
                                            "{record.state.label_zh()}"
                                        }
                                    }
                                    div { class: "muted", "data-testid": "move-submission-id",
                                        title: "{record.move_id}",
                                        "move {move_id_label}"
                                    }
                                    if let Some(event_id) = &record.event_id {
                                        {
                                            let event_id_label = short_protocol_id(event_id);
                                            rsx! {
                                                div { class: "muted", "data-testid": "move-submission-event-id",
                                                    title: "{event_id}",
                                                    "event {event_id_label}"
                                                }
                                            }
                                        }
                                    }
                                    if record.state.is_failed() {
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "move-failure-detail-toggle",
                                            onclick: {
                                                let mid = record.move_id.clone();
                                                move |_| {
                                                    let current = move_detail_open();
                                                    move_detail_open.set(if current.as_deref()
                                                        == Some(mid.as_str())
                                                    {
                                                        None
                                                    } else {
                                                        Some(mid.clone())
                                                    });
                                                }
                                            },
                                            "Failure detail"
                                        }
                                        if move_detail_open().as_deref() == Some(record.move_id.as_str()) {
                                            div {
                                                class: "muted",
                                                "data-testid": "move-failure-detail",
                                                if let Some(reason) = &record.reason {
                                                    div { "reason: {reason}" }
                                                } else {
                                                    div { "reason: (none reported)" }
                                                }
                                                if let Some(anchor) = &record.anchor_ref {
                                                    {
                                                        let anchor_label = short_protocol_id(anchor);
                                                        rsx! {
                                                            div { title: "{anchor}", "bound anchor: {anchor_label}" }
                                                        }
                                                    }
                                                }
                                                div { "submitted_at: {record.submitted_at}" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Bottom/conflict banner — rendered when the projection
            // exposes unresolved concurrent candidates. P0 M5.
            if active_section == RealmAdminSection::Repair && !bottom_cells.is_empty() {
                div { class: "event", "data-testid": "bottom-cells-banner",
                    div { class: "event-head",
                        span { "Concurrent candidates unresolved" }
                        span { class: "badge red", "bottom/conflict" }
                    }
                    div { class: "muted",
                        "One or more cells in this Realm's projection have unresolved bottom/conflict diagnostics — soland received concurrent Events it cannot deterministically merge. An admin / moderator must resolve each conflict by submitting a recovery repair Event before downstream queries return a definitive value."
                    }
                    for (cell_ref, info) in &bottom_cells {
                        {
                            let cell_ref_label = short_protocol_id(cell_ref);
                            rsx! {
                                div { class: "muted", "data-testid": "bottom-cell-row",
                                    title: "{cell_ref}",
                                    "{cell_ref_label} · status={info.status}"
                                }
                                // Side-by-side render of the competing heads so the
                                // operator can see what they're picking between
                                // instead of pasting blind JSON.
                                if !info.heads.is_empty() {
                                    div { class: "metric-grid", "data-testid": "bottom-cell-heads",
                                        for head in &info.heads {
                                            {
                                                let head_move_id_label = short_protocol_id(&head.move_id);
                                                rsx! {
                                                    div { class: "metric", "data-testid": "bottom-cell-head",
                                                        strong { "data-testid": "bottom-cell-head-move-id", title: "{head.move_id}", "{head_move_id_label}" }
                                                        span { "data-testid": "bottom-cell-head-value",
                                                            "{serde_json::to_string(&head.value).unwrap_or_default()}"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        // "Prefer safer side" prefill - only rendered for
                        // cell families where there's a semantic safety
                        // ordering (member.state, capability.grant). For
                        // everything else the operator picks manually below.
                        if let Some((_, head_a, head_b, winner_json)) = safer_suggestions
                            .iter()
                            .find(|(c, _, _, _)| c == cell_ref)
                            .cloned()
                        {
                            div { class: "actions",
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "prefer-safer-side-button",
                                    "data-cell": "{cell_ref}",
                                    onclick: {
                                        let cell_ref_owned = cell_ref.clone();
                                        move |_| {
                                            repair_target_cell.set(cell_ref_owned.clone());
                                            repair_head_a.set(head_a.clone());
                                            repair_head_b.set(head_b.clone());
                                            repair_winner_json.set(winner_json.clone());
                                        }
                                    },
                                    "Prefer safer side"
                                }
                            }
                        }
                    }
                }
                // Conflict-repair Event dialog - only rendered when
                // bottom_cells is non-empty (i.e. there is something to
                // repair). Admin / moderator only; soland's authz reducer
                // rejects unsigned-by-recovery capability submissions.
                div { class: "event", "data-testid": "conflict-repair-dialog",
                    div { class: "event-head",
                        span { "Conflict repair" }
                        span { class: "badge amber", "admin / moderator" }
                    }
                    div { class: "muted",
                        "Build a repair Event with the competing heads and recovery capability ref to merge the two concurrent histories. Soland's authz reducer requires the repair to be signed by a holder of the named recovery capability."
                    }
                    Label { html_for: "repair-target-cell-input", "Target cell (id of unresolved bottom/conflict cell)" }
                    Input {
                        id: "repair-target-cell-input",
                        "data-testid": "repair-target-cell-input",
                        value: "{repair_target_cell}",
                        placeholder: "ck:cell:ck.component.realm.organization.v1:...",
                        oninput: move |event: FormEvent| repair_target_cell.set(event.value()),
                    }
                    Label { html_for: "repair-head-a-input", "conflict_head_A" }
                    Input {
                        id: "repair-head-a-input",
                        "data-testid": "repair-head-a-input",
                        value: "{repair_head_a}",
                        placeholder: "ck:anchor:sha256:headA...",
                        oninput: move |event: FormEvent| repair_head_a.set(event.value()),
                    }
                    Label { html_for: "repair-head-b-input", "conflict_head_B" }
                    Input {
                        id: "repair-head-b-input",
                        "data-testid": "repair-head-b-input",
                        value: "{repair_head_b}",
                        placeholder: "ck:anchor:sha256:headB...",
                        oninput: move |event: FormEvent| repair_head_b.set(event.value()),
                    }
                    Label { html_for: "repair-capability-input", "recovery_capability ref" }
                    Input {
                        id: "repair-capability-input",
                        "data-testid": "repair-capability-input",
                        value: "{repair_capability_ref}",
                        placeholder: "cap.recovery-01",
                        oninput: move |event: FormEvent| repair_capability_ref.set(event.value()),
                    }
                    Label { html_for: "repair-state-witness-input", "state_witness ref" }
                    Input {
                        id: "repair-state-witness-input",
                        "data-testid": "repair-state-witness-input",
                        value: "{repair_state_witness_ref}",
                        placeholder: "ck:snapshot:sha256:...",
                        oninput: move |event: FormEvent| repair_state_witness_ref.set(event.value()),
                    }
                    Label { html_for: "repair-inclusion-proof-input", "inclusion_proof ref" }
                    Input {
                        id: "repair-inclusion-proof-input",
                        "data-testid": "repair-inclusion-proof-input",
                        value: "{repair_inclusion_proof_ref}",
                        placeholder: "ck:proof:sha256:...",
                        oninput: move |event: FormEvent| repair_inclusion_proof_ref.set(event.value()),
                    }
                    Label { html_for: "repair-winner-json-input", "Winner value (JSON)" }
                    Textarea {
                        id: "repair-winner-json-input",
                        "data-testid": "repair-winner-json-input",
                        value: "{repair_winner_json}",
                        placeholder: "{{\"title\": \"merged\"}}",
                        oninput: move |event: FormEvent| repair_winner_json.set(event.value()),
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "repair-submit-button",
                            onclick: {
                                let base = base_url.clone();
                                let realm = selected_realm_id.clone();
                                let actor_account_did = account_did.clone();
                                move |_| {
                                    let base = base.clone();
                                    let realm = realm.clone();
                                    let actor_did = actor_account_did.trim().to_owned();
                                    let api_token = token();
                                    let cell = repair_target_cell().trim().to_owned();
                                    let head_a = repair_head_a().trim().to_owned();
                                    let head_b = repair_head_b().trim().to_owned();
                                    let cap = repair_capability_ref().trim().to_owned();
                                    let witness = repair_state_witness_ref().trim().to_owned();
                                    let proof = repair_inclusion_proof_ref().trim().to_owned();
                                    let winner_str = repair_winner_json();
                                    if cell.is_empty() || head_a.is_empty() || head_b.is_empty()
                                        || cap.is_empty() || witness.is_empty() || proof.is_empty()
                                    {
                                        status_msg.set(
                                            "fill cell + both heads + recovery capability + state witness + inclusion proof before submitting repair"
                                                .to_owned(),
                                        );
                                        return;
                                    }
                                    let winner_value: serde_json::Value =
                                        match serde_json::from_str(&winner_str) {
                                            Ok(v) => v,
                                            Err(err) => {
                                                status_msg.set(format!(
                                                    "winner value is not valid JSON: {err}"
                                                ));
                                                return;
                                            }
                                        };
                                    let _hlc = Hlc::now("yougen").to_string();
                                    if actor_did.is_empty() {
                                        status_msg.set("account actor unavailable".to_owned());
                                        return;
                                    }
                                    let heads = vec![head_a, head_b];
                                    let envelope = crate::operation::cx_ops::conflict_repair(
                                        &realm,
                                        &actor_did,
                                        &cell,
                                        &heads,
                                        &cap,
                                        &witness,
                                        &proof,
                                        winner_value,
                                    )
                                    .build("yougen");
                                    let op_id = envelope.local_operation_id().to_owned();
                                    spawn(async move {
                                        match crate::views::helpers::with_authed_api(
                                            &base,
                                            api_token,
                                            |api| async move {
                                                api.submit_event_envelope(&envelope).await
                                            },
                                        )
                                        .await
                                        {
                                            Ok(resp) => status_msg.set(format!(
                                                "repair event {}: state=accepted event_id={}",
                                                short_protocol_id(&op_id),
                                                short_protocol_id(&resp.event_id)
                                            )),
                                            Err(err) => status_msg.set(format!(
                                                "repair submit failed: {}", err.display()
                                            )),
                                        }
                                    });
                                }
                            },
                            "Submit repair Move"
                        }
                    }
                }
            }
            if active_section == RealmAdminSection::Security {
                // Covered_frontier_lag alert banner. Mirrors sodmin's admin
                // page banner but stays client-side - it reads the lag from
                // the LocalAnchorView populated on /sync, compares to a
                // user-configurable threshold (default 5, see
                // DEFAULT_COVERED_FRONTIER_LAG_THRESHOLD), and only renders
                // when soland has surfaced a lag AND it exceeds threshold.
                // Operators see the same urgency cue here that sodmin shows
                // on the dedicated covered_frontier page.
                div { class: "event", "data-testid": "covered-frontier-threshold-row",
                    div { class: "event-head",
                        span { "covered_frontier alert threshold" }
                        span { "client-side" }
                    }
                    div { class: "muted",
                        "Surface a banner when soland's published covered_frontier_lag exceeds this value. Default 5 (mirrors sodmin)."
                    }
                    Label { html_for: "covered-frontier-threshold-input", "Threshold (Moves)" }
                    input {
                        id: "covered-frontier-threshold-input",
                        "data-testid": "covered-frontier-threshold-input",
                        r#type: "number",
                        min: "0",
                        value: "{covered_frontier_lag_threshold}",
                        oninput: move |evt| {
                            if let Ok(parsed) = evt.value().parse::<u64>() {
                                covered_frontier_threshold.set(parsed);
                            }
                        },
                    }
                    div { class: "muted", "data-testid": "covered-frontier-lag-value",
                        "current covered_frontier_lag: {covered_frontier_lag_label}"
                    }
                }
                if covered_frontier_alert {
                    div { class: "event", "data-testid": "covered-frontier-alert-banner",
                        div { class: "event-head",
                            span { "covered_frontier lag alert" }
                            span { class: "badge red", "above threshold" }
                        }
                        div { class: "muted", "data-testid": "covered-frontier-alert-message",
                            "Lag of {covered_frontier_lag_label} Moves is above the warn threshold {covered_frontier_lag_threshold}; investigate MLS group health (member offline, KeyPackage stale). Admin tools live on the sodmin covered_frontier page."
                        }
                    }
                }
                // MLS epoch + governance frontier read-only widget. Reads
                // from the same LocalAnchorView the bottom-cells banner
                // uses, so it costs no extra fetch - just surfaces two
                // well-known cells (mls.epoch.v1,
                // governance.covered_frontier.v1) for admin visibility into
                // E2EE rotation status and governance gating without leaving
                // the page.
                div { class: "event", "data-testid": "mls-epoch-widget",
                    div { class: "event-head",
                        span { "MLS epoch & governance frontier" }
                        span { "ck.component.mls.epoch.v1 · governance.covered_frontier.v1" }
                    }
                    div { class: "muted",
                        "Read-only view of the most recent MLS epoch published in the cell map and the governance covered_frontier value Move acceptance gates against. Updates as soon as sync surfaces a new anchor view — no fetch button needed."
                    }
                    div { class: "muted", "data-testid": "mls-epoch-value",
                        "MLS epoch: {mls_epoch_label}"
                    }
                    div { class: "muted", "data-testid": "governance-covered-frontier",
                        "covered_frontier: {covered_frontier_label}"
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
                // /_soland/admin/realms/{id}/anchorer; surfaces the
                // recovery-anchorer mode (single_did / threshold / open_set /
                // mixed) on this admin page. A separate agent is implementing
                // the endpoint on soland; on 404 we fall back to a clear
                // inline message.
                div { class: "event", "data-testid": "anchorer-cell-card",
                    div { class: "event-head",
                        span { "Anchorer cell" }
                        span { "ck.component.anchorer.v1" }
                    }
                    div { class: "muted",
                        "Recovery anchorer mode for this Realm — controls who can re-anchor a paused frontier. Read-only; modifications go through the dedicated anchorer-rotation flow."
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "anchorer-cell-refresh",
                            onclick: {
                                let base = base_url.clone();
                                let realm = selected_realm_id.clone();
                                move |_| {
                                    let base = base.clone();
                                    let realm = realm.clone();
                                    let api_token = token();
                                    spawn(async move {
                                        match crate::views::helpers::with_authed_api(
                                            &base,
                                            api_token,
                                            |api| async move {
                                                api.admin_anchorer_describe(&realm).await
                                            },
                                        )
                                        .await
                                        {
                                            Ok(value) => {
                                                anchorer_cell_status.set("ok".to_owned());
                                                anchorer_cell_value.set(value.to_string());
                                            }
                                            Err(err) => {
                                                // 404 / not-implemented falls through here.
                                                // Keep the message clear so the operator
                                                // knows it's a missing endpoint, not bad
                                                // data.
                                                anchorer_cell_status.set(format!(
                                                    "anchorer endpoint unavailable ({}); \
                                                     expected /_soland/admin/realms/{{id}}/anchorer \
                                                     (separate agent shipping)",
                                                    err.display()
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
            }
            if active_section == RealmAdminSection::Profile {
                // Realm / Space profile editor. Spec fields are `title`,
                // optional `summary`, and optional `avatar_blob_ref`.
                // Access policy lives in the Access tab.
                div { class: "event", "data-testid": "realm-profile",
                    div { class: "event-head",
                        span { "{metadata_subject_label} Profile" }
                        span { "{metadata_event_kind}" }
                    }
                    div { class: "muted",
                        span { class: "mono", title: "{selected_realm_id}", "{short_protocol_id(&selected_realm_id)}" }
                        if metadata_subject.kind == RealmTreeNodeKind::Space {
                            span { " · home Realm " }
                            span {
                                class: "mono",
                                title: "{metadata_subject.home_realm_id}",
                                "{short_protocol_id(&metadata_subject.home_realm_id)}"
                            }
                        }
                    }
                    div { class: "workflow-form",
                        Label { html_for: "realm-name-input", "Title" }
                        Input {
                            id: "realm-name-input",
                            "data-testid": "realm-name-input",
                            value: "{metadata_title}",
                            placeholder: "{metadata_subject_label} title",
                            oninput: move |event: FormEvent| metadata_title.set(event.value()),
                        }
                        Label { html_for: "realm-summary-input", "Summary" }
                        Textarea {
                            id: "realm-summary-input",
                            "data-testid": "realm-summary-input",
                            value: "{metadata_summary}",
                            placeholder: "Optional summary",
                            oninput: move |event: FormEvent| metadata_summary.set(event.value()),
                        }
                        label { "Avatar" }
                        crate::components::AvatarUploader {
                            current_blob_ref: metadata_avatar_blob_ref(),
                            alt_text: format!("{metadata_subject_label} avatar"),
                            base_url: base_url.clone(),
                            api_token: token(),
                            upload_realm_id: Some(metadata_subject.home_realm_id.clone()),
                            test_id_prefix: "realm-avatar".to_owned(),
                            on_uploaded: move |blob_ref: String| {
                                metadata_avatar_blob_ref.set(blob_ref);
                                status_msg.set("avatar uploaded; Save Profile publishes it".to_owned());
                            },
                            on_clear: move |_| {
                                metadata_avatar_blob_ref.set(String::new());
                                status_msg.set("avatar cleared; Save Profile publishes it".to_owned());
                            },
                        }
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "update-metadata-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let subject_id = selected_realm_id.clone();
                                    let subject_kind = metadata_subject.kind;
                                    let home_realm_id = metadata_subject.home_realm_id.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let subject_id = subject_id.clone();
                                        let home_realm_id = home_realm_id.clone();
                                        let api_token = token();
                                        let title = metadata_title().trim().to_owned();
                                        let summary = metadata_summary().trim().to_owned();
                                        let avatar_blob_ref = metadata_avatar_blob_ref().trim().to_owned();
                                        if title.is_empty() {
                                            status_msg.set(
                                                "profile update failed: title is required by spec".to_owned(),
                                            );
                                            return;
                                        }
                                        if !avatar_blob_ref.is_empty()
                                            && !avatar_blob_ref.starts_with("ck:blob:")
                                        {
                                            status_msg.set(
                                                "profile update failed: avatar_blob_ref must be a ck:blob:* reference".to_owned(),
                                            );
                                            return;
                                        }
                                        let actor_did = match state_store.write().ensure_local_identity() {
                                            Ok(id) => id.device_did.as_str().to_owned(),
                                            Err(err) => {
                                                status_msg.set(format!("identity unavailable: {err}"));
                                                return;
                                            }
                                        };
                                        let mut patch = serde_json::Map::new();
                                        patch.insert("title".to_owned(), json!(title));
                                        patch.insert(
                                            "summary".to_owned(),
                                            if summary.is_empty() {
                                                json!({ "$op": "unset" })
                                            } else {
                                                json!(summary)
                                            },
                                        );
                                        patch.insert(
                                            "avatar_blob_ref".to_owned(),
                                            if avatar_blob_ref.is_empty() {
                                                json!({ "$op": "unset" })
                                            } else {
                                                json!(avatar_blob_ref)
                                            },
                                        );
                                        let patch = Value::Object(patch);
                                        spawn(async move {
                                            match crate::views::helpers::with_authed_api(
                                                &base,
                                                api_token,
                                                |api| async move {
                                                    match subject_kind {
                                                        RealmTreeNodeKind::Realm => {
                                                            api.update_realm_metadata(&home_realm_id, &actor_did, patch).await
                                                        }
                                                        RealmTreeNodeKind::Space => {
                                                            api.update_space_metadata(&home_realm_id, &subject_id, &actor_did, patch).await
                                                        }
                                                    }
                                                },
                                            )
                                            .await
                                            {
                                                Ok(_) => status_msg.set(format!(
                                                    "{metadata_event_kind} profile updated"
                                                )),
                                                Err(err) => status_msg.set(format!(
                                                    "profile update failed: {}", err.display()
                                                )),
                                            }
                                        });
                                    }
                                },
                                {crate::i18n::tr("realm_admin.save_profile")}
                            }
                        }
                    }
                }
            }

            if active_section == RealmAdminSection::Access {
            // Join policy selector
            div { class: "event", "data-testid": "join-policy",
                div { class: "event-head", span { "Join Policy" } span { "access control" } }
                div { class: "actions",
                    Button {
                        variant: if join_rule() == "open" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| join_rule.set("open".to_owned()),
                        "Open"
                    }
                    Button {
                        variant: if join_rule() == "invite" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| join_rule.set("invite".to_owned()),
                        "Invite"
                    }
                    Button {
                        variant: if join_rule() == "request" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| join_rule.set("request".to_owned()),
                        "Request"
                    }
                    Button {
                        variant: if join_rule() == "restricted" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| join_rule.set("restricted".to_owned()),
                        "Restricted"
                    }
                }
                div { class: "muted", "Current: {join_rule}" }
            }

            div { class: "event", "data-testid": "principal-admission-policy",
                div { class: "event-head", span { "Principal Admission" } span { "hard gate" } }
                label {
                    input {
                        r#type: "checkbox",
                        checked: principal_admission_enabled(),
                        onchange: move |evt| principal_admission_enabled.set(evt.value() == "true"),
                    }
                    " Enabled"
                }
                if principal_admission_enabled() {
                    Label { html_for: "principal-admission-methods-input", "Allowed DID methods" }
                    Input {
                        id: "principal-admission-methods-input",
                        "data-testid": "principal-admission-methods-input",
                        value: "{principal_admission_methods}",
                        placeholder: "did:webvh, did:web",
                        oninput: move |event: FormEvent| principal_admission_methods.set(event.value()),
                    }
                    Label { html_for: "principal-admission-allowed-dids-input", "Allowed principal DIDs" }
                    Textarea {
                        id: "principal-admission-allowed-dids-input",
                        "data-testid": "principal-admission-allowed-dids-input",
                        value: "{principal_admission_allowed_dids}",
                        placeholder: "did:web:alice.example",
                        oninput: move |event: FormEvent| principal_admission_allowed_dids.set(event.value()),
                    }
                    Label { html_for: "principal-admission-denied-dids-input", "Denied principal DIDs" }
                    Textarea {
                        id: "principal-admission-denied-dids-input",
                        "data-testid": "principal-admission-denied-dids-input",
                        value: "{principal_admission_denied_dids}",
                        placeholder: "did:web:blocked.example",
                        oninput: move |event: FormEvent| principal_admission_denied_dids.set(event.value()),
                    }
                } else {
                    div { class: "muted", "Disabled" }
                }
            }

            // History visibility selector
            div { class: "event", "data-testid": "history-visibility",
                div { class: "event-head", span { "History Visibility" } span { "" } }
                div { class: "actions",
                    Button {
                        variant: if history_visibility() == "shared" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| history_visibility.set("shared".to_owned()),
                        "Shared"
                    }
                    Button {
                        variant: if history_visibility() == "invited" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| history_visibility.set("invited".to_owned()),
                        "Invited"
                    }
                    Button {
                        variant: if history_visibility() == "joined" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| history_visibility.set("joined".to_owned()),
                        "Joined"
                    }
                    Button {
                        variant: if history_visibility() == "world_readable" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| history_visibility.set("world_readable".to_owned()),
                        "World Readable"
                    }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "apply-policy-button",
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor = account_did.clone();
                            move |_| {
                                let base = base.clone();
                                let realm = realm.clone();
                                let actor = actor.clone();
                                let api_token = token();
                                let rule = join_rule();
                                let vis = history_visibility();
                                let join_policy = match build_principal_admission_join_policy(
                                    principal_admission_enabled(),
                                    &principal_admission_methods(),
                                    &principal_admission_allowed_dids(),
                                    &principal_admission_denied_dids(),
                                ) {
                                    Ok(policy) => policy,
                                    Err(err) => {
                                        status_msg.set(format!("policy failed: {err}"));
                                        return;
                                    }
                                };
                                spawn(async move {
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.set_realm_policy_events(
                                                &realm,
                                                &actor,
                                                &rule,
                                                &vis,
                                                join_policy,
                                            )
                                            .await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(resp) => status_msg.set(format!(
                                            "policy: join={}, history={}",
                                            resp.join_rule, resp.history_visibility
                                        )),
                                        Err(err) => status_msg.set(format!(
                                            "policy failed: {}", err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        {crate::i18n::tr("realm_admin.apply_policy")}
                    }
                }
            }
            } // closes `if active_section == RealmAdminSection::Access`

            if active_section == RealmAdminSection::Security {
            // MLS epoch rotation
            div { class: "event", "data-testid": "mls-rotation",
                div { class: "event-head", span { "MLS Epoch" } span { "rotation" } }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "rotate-realm-epoch",
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            move |_| {
                                let base = base.clone();
                                let realm = realm.clone();
                                let api_token = token();
                                spawn(async move {
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.rotate_mls_epoch(&realm).await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(resp) => status_msg.set(format!(
                                            "rotated to epoch {}", resp.epoch
                                        )),
                                        Err(err) => status_msg.set(format!(
                                            "rotate failed: {}", err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        {crate::i18n::tr("realm_admin.rotate_epoch")}
                    }
                }
            }

            // Leave Realm
            div { class: "event", "data-testid": "leave-realm",
                div { class: "event-head", span { "Leave Realm" } span { "" } }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "leave-realm-button",
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let mut state_store = state_store;
                            let mut sync_cursor = sync_cursor;
                            move |_| {
                                let base = base.clone();
                                let realm = realm.clone();
                                let api_token = token();
                                let actor_did = match state_store.write().ensure_local_identity() {
                                    Ok(id) => id.device_did.as_str().to_owned(),
                                    Err(err) => {
                                        status_msg.set(format!("identity unavailable: {err}"));
                                        return;
                                    }
                                };
                                spawn(async move {
                                    let realm_for_msg = realm.clone();
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.leave_realm(&realm, &actor_did).await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(_) => {
                                            state_store.write().forget_realm_tree_projection(&realm_for_msg);
                                            sync_cursor.set("-".to_owned());
                                            status_msg.set(format!(
                                                "left {realm_for_msg}; local cache cleared"
                                            ));
                                        }
                                        Err(err) => status_msg.set(format!(
                                            "leave failed: {}", err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        {crate::i18n::tr("realm_admin.leave_realm")}
                    }
                }
            }
            }

            if active_section == RealmAdminSection::Security {
            div { class: "event", "data-testid": "capability-grant-card",
                div { class: "event-head",
                    span { "Capability grant / revoke" }
                    span { "Advanced" }
                }
                Label { html_for: "cap-grant-id-input", "Grant ID (cell subject)" }
                Input {
                    id: "cap-grant-id-input",
                    "data-testid": "cap-grant-id-input",
                    value: "{cap_grant_id}",
                    oninput: move |event: FormEvent| cap_grant_id.set(event.value()),
                }
                Label { html_for: "cap-grant-tag-input", "Capability tag (action / scope)" }
                Input {
                    id: "cap-grant-tag-input",
                    "data-testid": "cap-grant-tag-input",
                    value: "{cap_tag}",
                    oninput: move |event: FormEvent| cap_tag.set(event.value()),
                }
                Label { html_for: "cap-revoke-reason-input", "Revoke reason (optional)" }
                Input {
                    id: "cap-revoke-reason-input",
                    "data-testid": "cap-revoke-reason-input",
                    value: "{cap_revoke_reason}",
                    oninput: move |event: FormEvent| cap_revoke_reason.set(event.value()),
                }
                // Capability constraint editor. Choose a family from the
                // dropdown (`temporal` / `quota` / `scope_limitation` /
                // `none`) and fill in the form for that family. Today only
                // `temporal` is fully wired - the other options surface
                // their hint copy but no inputs (matching the move_builder
                // constraint surface, which only provides a `temporal`
                // builder helper).
                div { class: "event-head", "data-testid": "cap-constraint-editor",
                    span { "Constraint" }
                    span { "temporal MVP · quota / scope_limitation soon" }
                }
                label { "Constraint family" }
                select {
                    "data-testid": "cap-constraint-kind-select",
                    value: "{cap_constraint_kind}",
                    onchange: move |evt| cap_constraint_kind.set(evt.value()),
                    option { value: "none", "none" }
                    option { value: "temporal", "temporal (not_before / expires_at)" }
                    option { value: "quota", "quota (coming soon)" }
                    option { value: "scope_limitation", "scope_limitation (coming soon)" }
                }
                if cap_constraint_kind() == "temporal" {
                    div { "data-testid": "cap-constraint-temporal-fields",
                        Label { html_for: "cap-constraint-not-before-input", "not_before (RFC 3339, optional)" }
                        input {
                            id: "cap-constraint-not-before-input",
                            "data-testid": "cap-constraint-not-before-input",
                            r#type: "datetime-local",
                            value: "{cap_temporal_not_before}",
                            oninput: move |evt| {
                                cap_temporal_not_before.set(evt.value());
                            },
                        }
                        Label { html_for: "cap-constraint-expires-at-input", "expires_at (RFC 3339, optional)" }
                        input {
                            id: "cap-constraint-expires-at-input",
                            "data-testid": "cap-constraint-expires-at-input",
                            r#type: "datetime-local",
                            value: "{cap_temporal_expires_at}",
                            oninput: move |evt| {
                                cap_temporal_expires_at.set(evt.value());
                            },
                        }
                    }
                } else if cap_constraint_kind() == "quota"
                    || cap_constraint_kind() == "scope_limitation"
                {
                    div {
                        class: "muted",
                        "data-testid": "cap-constraint-coming-soon",
                        "{cap_constraint_kind()} editor not yet implemented; the constraint "
                        "is forwarded as a free-form JSON object on the grant once a UI lands."
                    }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "cap-grant-submit-button",
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            move |_| {
                                let base = base.clone();
                                let realm = realm.clone();
                                let api_token = token();
                                let grant_val = cap_grant_id().trim().to_owned();
                                let tag_val = cap_tag().trim().to_owned();
                                if grant_val.is_empty() || tag_val.is_empty() {
                                    status_msg.set(
                                        "fill grant_id + tag before submitting capability grant".to_owned(),
                                    );
                                    return;
                                }
                                let actor_did =
                                    match state_store.write().ensure_local_identity() {
                                        Ok(id) => id.device_did.as_str().to_owned(),
                                        Err(err) => {
                                            status_msg.set(format!(
                                                "identity unavailable: {err}"
                                            ));
                                            return;
                                        }
                                    };
                                // Pull the active constraint from the editor
                                // signals into the wire shape. Empty input
                                // yields no constraint.
                                let kind = cap_constraint_kind();
                                let constraint_json: serde_json::Value =
                                    if kind == "temporal" {
                                        let nb = cap_temporal_not_before();
                                        let ea = cap_temporal_expires_at();
                                        let nb_trim = nb.trim();
                                        let ea_trim = ea.trim();
                                        if nb_trim.is_empty() && ea_trim.is_empty() {
                                            serde_json::Value::Null
                                        } else {
                                            let mut window = serde_json::Map::new();
                                            if !nb_trim.is_empty() {
                                                window.insert(
                                                    "not_before".into(),
                                                    serde_json::Value::String(nb_trim.to_owned()),
                                                );
                                            }
                                            if !ea_trim.is_empty() {
                                                // Validity upper bound is `expires_at`
                                                // (not_after is a forbidden wire field).
                                                window.insert(
                                                    "expires_at".into(),
                                                    serde_json::Value::String(ea_trim.to_owned()),
                                                );
                                            }
                                            json!([
                                                {
                                                    "kind": "temporal.window",
                                                    "value": serde_json::Value::Object(window),
                                                }
                                            ])
                                        }
                                    } else {
                                        serde_json::Value::Null
                                    };
                                let envelope = crate::operation::cx_ops::capability_grant(
                                    &realm,
                                    &actor_did,
                                    &grant_val,
                                    &tag_val,
                                    constraint_json,
                                )
                                .build("yougen");
                                let op_id = envelope.local_operation_id().to_owned();
                                spawn(async move {
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.submit_event_envelope(&envelope).await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(resp) => status_msg.set(format!(
                                            "ck.capability.grant event {}: event_id={}",
                                            short_protocol_id(&op_id),
                                            short_protocol_id(&resp.event_id)
                                        )),
                                        Err(err) => status_msg.set(format!(
                                            "capability.grant submit failed: {}", err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        {crate::i18n::tr("realm_admin.grant_capability_move")}
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "cap-revoke-submit-button",
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            move |_| {
                                let base = base.clone();
                                let realm = realm.clone();
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
                                let actor_did =
                                    match state_store.write().ensure_local_identity() {
                                        Ok(id) => id.device_did.as_str().to_owned(),
                                        Err(err) => {
                                            status_msg.set(format!(
                                                "identity unavailable: {err}"
                                            ));
                                            return;
                                        }
                                    };
                                let envelope = crate::operation::cx_ops::capability_revoke(
                                    &realm,
                                    &actor_did,
                                    &grant_val,
                                    &tag_val,
                                    reason_opt.as_deref(),
                                )
                                .build("yougen");
                                let op_id = envelope.local_operation_id().to_owned();
                                spawn(async move {
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.submit_event_envelope(&envelope).await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(resp) => status_msg.set(format!(
                                            "ck.capability.revoke event {}: event_id={}",
                                            short_protocol_id(&op_id),
                                            short_protocol_id(&resp.event_id)
                                        )),
                                        Err(err) => status_msg.set(format!(
                                            "capability.revoke submit failed: {}", err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        {crate::i18n::tr("realm_admin.revoke_capability_move")}
                    }
                }
            }
            }

            if active_section == RealmAdminSection::Federation {
                div { class: "event", "data-testid": "trust-bundle-panel",
                    div { class: "event-head",
                        span { "Federation trust" }
                        span { "Admin tooling" }
                    }
                    div { class: "muted",
                        "Trust bundle import, validation, and revocation are not wired in yougen. Use the deployment's admin tooling for federation trust changes."
                    }
                }
            }

            // Danger zone
            if active_section == RealmAdminSection::Repair {
            div { class: "event", "data-testid": "danger-zone",
                div { class: "event-head", span { "Danger Zone" } span { "destructive actions" } }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "archive-realm-button",
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            move |_| {
                                let base = base.clone();
                                let realm = realm.clone();
                                let api_token = token();
                                let actor_did = match state_store.write().ensure_local_identity() {
                                    Ok(id) => id.device_did.as_str().to_owned(),
                                    Err(err) => {
                                        status_msg.set(format!("identity unavailable: {err}"));
                                        return;
                                    }
                                };
                                let realm_for_msg = realm.clone();
                                spawn(async move {
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.archive_realm(&realm, &actor_did).await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(_) => status_msg.set(format!(
                                            "archive event submitted ({realm_for_msg})"
                                        )),
                                        Err(err) => status_msg.set(format!(
                                            "archive failed: {}", err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        {crate::i18n::tr("realm_admin.archive_realm")}
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "destroy-realm-button",
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            move |_| {
                                let base = base.clone();
                                let realm = realm.clone();
                                let api_token = token();
                                let actor_did = match state_store.write().ensure_local_identity() {
                                    Ok(id) => id.device_did.as_str().to_owned(),
                                    Err(err) => {
                                        status_msg.set(format!("identity unavailable: {err}"));
                                        return;
                                    }
                                };
                                spawn(async move {
                                    let realm_for_msg = realm.clone();
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.destroy_realm(&realm, &actor_did, "operator_request").await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(_) => status_msg.set(format!(
                                            "destroyed {}",
                                            short_protocol_id(&realm_for_msg)
                                        )),
                                        Err(err) => status_msg.set(format!("delete failed: {}", err.display())),
                                    }
                                });
                            }
                        },
                        {crate::i18n::tr("realm_admin.destroy_realm")}
                    }
                }
            }

            }

            if !status_msg().is_empty() {
                div { class: "muted", "data-testid": "realm-admin-status", "{status_msg}" }
            }
        }
    }
}

/// wasm-fallback for the MLS Remove handler. The
/// browser build can't decrypt the snapshot or talk to OpenMLS, so this
/// branch surfaces a clear "use desktop" notice and returns without
/// touching `state_store` or the network.
#[cfg(target_arch = "wasm32")]
async fn run_device_revoke_from_snapshot(
    _base_url: String,
    _api_token: String,
    _state_store: Signal<LocalStateStore>,
    _realm_id: String,
    _actor_did: String,
    _device_id: String,
    _target_did: String,
    mut status: Signal<String>,
) {
    status.set(
        "MLS Remove requires the desktop client (browser build has no OpenMLS runtime). Switch clients and try again."
            .to_owned(),
    );
}

/// Native handler that wraps
/// [`crate::device_revoke::execute_mls_remove_from_snapshot`]:
///
/// 1. read the encrypted MLS snapshot for the Space out of the local state store;
/// 2. validate inputs and load this device's snapshot secret;
/// 3. mint a UUIDv7 operation_id, parse typed `Did` / `RealmId`;
/// 4. run the SDK Remove (group decrypt → commit → re-export);
/// 5. submit the `mls_commit` Operation via `with_authed_api`;
/// 6. on submit success, re-encrypt the post-commit group state and save it back so the next boot
///    doesn't try to rehydrate the pre-revoke epoch.
///
/// Any error along the way is surfaced verbatim in the `status` signal;
/// the operator can inspect it inline and retry without page reload.
#[cfg(not(target_arch = "wasm32"))]
async fn run_device_revoke_from_snapshot(
    base_url: String,
    api_token: String,
    mut state_store: Signal<LocalStateStore>,
    realm_id: String,
    actor_did: String,
    device_id: String,
    target_did: String,
    mut status: Signal<String>,
) {
    if target_did.is_empty() {
        status.set("target device DID is required".to_owned());
        return;
    }
    let envelope = match state_store.read().mls_snapshot_for(&realm_id) {
        Some(env) => env,
        None => {
            status.set(format!(
                "no persisted MLS snapshot for realm {}; nothing to revoke against",
                short_protocol_id(&realm_id)
            ));
            return;
        }
    };
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let snapshot_secret = match crate::mls::runtime::load_device_snapshot_secret(
        secure_store.as_ref(),
        &actor_did,
        &device_id,
    ) {
        Ok(secret) => secret,
        Err(err) => {
            status.set(format!("device MLS snapshot secret unavailable: {err}"));
            return;
        }
    };
    let typed_target = match cokret_sdk::Did::new(target_did.clone()) {
        Ok(d) => d,
        Err(err) => {
            status.set(format!("invalid target DID: {err}"));
            return;
        }
    };
    let typed_realm = match cokret_sdk::RealmId::new(realm_id.clone()) {
        Ok(s) => s,
        Err(err) => {
            status.set(format!("invalid realm id: {err}"));
            return;
        }
    };
    let op_id_str = format!("ck:operation:{}", crate::operation::uuid_v7());
    let typed_op_id = match cokret_sdk::OperationId::new(op_id_str) {
        Ok(o) => o,
        Err(err) => {
            status.set(format!("internal: operation id minting failed: {err}"));
            return;
        }
    };
    let full = match crate::device_revoke::execute_mls_remove_from_snapshot(
        &envelope,
        &snapshot_secret,
        &typed_target,
        typed_op_id,
        typed_realm,
    ) {
        Ok(full) => full,
        Err(err) => {
            status.set(format!("MLS Remove execution failed: {err}"));
            return;
        }
    };
    let removed_count = full.output.result.removed_leaves.len();
    let post_state = full.post_state.clone();
    // The SDK's `commit_operation` returns an SDK-typed Operation. We
    // wrap its payload into yougen's EventEnvelope shape so the
    // existing `submit_event_envelope` path (Event envelope wrapper +
    // /_cokret/self/events POST) accepts it without a separate wire route.
    let actor = full
        .output
        .commit_operation
        .payload
        .get("creator")
        .and_then(|v| v.as_str())
        .unwrap_or("yougen-operator")
        .to_owned();
    let target_ref = full.output.commit_operation.object_id.clone();
    let mut envelope_builder =
        crate::operation::OperationBuilder::new(realm_id.clone(), actor, "mls_commit")
            .body(full.output.commit_operation.payload.clone());
    if let Some(tref) = target_ref {
        envelope_builder = envelope_builder.target_ref(tref);
    }
    let envelope = envelope_builder.build("yougen");
    let submit_result =
        crate::views::helpers::with_authed_api(&base_url, api_token.clone(), |api| async move {
            api.submit_event_envelope(&envelope).await
        })
        .await;
    match submit_result {
        Ok(_) => {
            // Re-encrypt and persist the post-commit group state so a
            // boot after the submit doesn't read the pre-revoke epoch.
            let mut salt = [0u8; 16];
            if let Err(err) = getrandom::fill(&mut salt) {
                status.set(format!(
                    "submit accepted but rng fill failed: {err}; re-encrypt deferred"
                ));
                return;
            }
            let serialized_state = match serde_json::to_vec(&post_state) {
                Ok(bytes) => bytes,
                Err(err) => {
                    status.set(format!(
                        "submit accepted but MLS state serialize failed: {err}; re-encrypt deferred"
                    ));
                    return;
                }
            };
            let new_envelope = crate::mls::persistence::encrypt_state(
                &realm_id,
                &post_state.group_id,
                post_state.epoch,
                &serialized_state,
                &snapshot_secret,
                &salt,
            );
            state_store
                .write()
                .save_mls_snapshot(realm_id.clone(), new_envelope);
            let snapshot = state_store.read().mls_snapshot_for(&realm_id);
            let backup_result = if let Some(snapshot) = snapshot {
                crate::views::helpers::with_authed_api(&base_url, api_token.clone(), |api| {
                    let actor_did = actor_did.clone();
                    let device_id = device_id.clone();
                    async move {
                        crate::mls::runtime::upload_mls_snapshot_backup(
                            &api, &snapshot, &actor_did, &device_id,
                        )
                        .await
                        .map_err(|err| anyhow::anyhow!(err.user_message()))
                    }
                })
                .await
                .map(Some)
            } else {
                Ok(None)
            };
            let backup_suffix = match backup_result {
                Ok(Some(backup_id)) => {
                    format!(
                        "; MLS history backup {} uploaded",
                        short_protocol_id(&backup_id)
                    )
                }
                Ok(None) => String::new(),
                Err(err) => format!("; MLS history backup failed: {}", err.display()),
            };
            status.set(format!(
                "MLS Remove submitted; {removed_count} leaf/leaves removed; post-state re-persisted (epoch {}){}",
                post_state.epoch,
                backup_suffix
            ));
        }
        Err(err) => {
            status.set(format!("MLS Remove submit failed: {}", err.display()));
        }
    }
}

#[cfg(test)]
mod principal_admission_policy_tests {
    use super::*;

    #[test]
    fn principal_admission_policy_normalizes_method() {
        let policy = build_principal_admission_join_policy(true, "webvh", "", "")
            .unwrap()
            .unwrap();
        assert_eq!(
            policy["gates"][0]["allowed_did_methods"],
            json!(["did:webvh"])
        );
        assert_eq!(policy["gates"][0]["kind"], "principal_admission");
    }

    #[test]
    fn principal_admission_policy_requires_selector() {
        let err = build_principal_admission_join_policy(true, "", "", "").unwrap_err();
        assert!(err.contains("requires"));
    }
}

// (Move-flow test module removed; the wire shapes are now covered by soland's events.submit tests
// and cokret-spec fixtures.)
