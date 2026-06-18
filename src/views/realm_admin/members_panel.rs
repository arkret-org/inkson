use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use serde_json::json;

use super::metadata::projected_members_for_realm;
use super::permissions::{RealmMemberPermissions, authz_json_allowed};
use crate::local_state::{LocalStateStore, MoveSubmissionState};
use crate::operation::ck_ops;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::views::helpers::{active_sync_token, authed_api_with_sync, short_protocol_id};

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
    // U3 - "Add from contacts" picker state. `invite_contacts` holds the user's
    // accepted contacts (lazily loaded when the modal opens); `selected_contacts`
    // is the multi-select set of DIDs to invite via the consent-grant path.
    let mut invite_contacts = use_signal(Vec::<crate::models::ContactListRow>::new);
    let mut invite_contacts_loaded = use_signal(|| false);
    let mut invite_contacts_status = use_signal(String::new);
    let mut selected_contacts = use_signal(std::collections::BTreeSet::<String>::new);

    // Lazily hydrate the contacts list the first time the invite modal opens.
    {
        let base = base_url.clone();
        use_effect(move || {
            if !invite_modal_open() || invite_contacts_loaded() {
                return;
            }
            invite_contacts_loaded.set(true);
            let api_token = token();
            let base = base.clone();
            invite_contacts_status.set(crate::i18n::tr("realm_admin.invite_loading_contacts"));
            spawn(async move {
                match crate::views::helpers::with_authed_api(&base, api_token, |api| async move {
                    api.contacts().await
                })
                .await
                {
                    Ok(response) => {
                        let accepted: Vec<crate::models::ContactListRow> = response
                            .contacts
                            .into_iter()
                            .filter(|c| c.state == "accepted")
                            .collect();
                        let count = accepted.len();
                        invite_contacts.set(accepted);
                        invite_contacts_status.set(if count == 0 {
                            crate::i18n::tr("realm_admin.invite_no_contacts")
                        } else {
                            String::new()
                        });
                    }
                    Err(err) => invite_contacts_status.set(
                        crate::i18n::tr("realm_admin.invite_contacts_failed")
                            .replace("{error}", &err.display()),
                    ),
                }
            });
        });
    }

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
                        // Member removal has no standalone capability action in
                        // v1; it is governed by Realm management authority. Probe
                        // the registered `ck.realm.admin` action (management,
                        // high-risk) instead of the unregistered placeholder
                        // `ck.member.remove`, which is not in
                        // capability-action-registry.json and would be treated as
                        // an unknown high-risk action (fail-closed) by a
                        // spec-conformant server.
                        let remove = api.authz_check_raw(&actor, "ck.realm.admin", &realm).await;
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
                            // U3 — primary, natural path: pull existing contacts
                            // into the Realm directly via their consent grant.
                            div { class: "invite-from-contacts", "data-testid": "realm-invite-from-contacts",
                                div { class: "event-head",
                                    span { {crate::i18n::tr("realm_admin.invite_from_contacts")} }
                                    span { {crate::i18n::tr("realm_admin.invite_recommended")} }
                                }
                                if !invite_contacts_status().is_empty() {
                                    div { class: "muted", "data-testid": "realm-invite-contacts-status", "{invite_contacts_status}" }
                                }
                                if !invite_contacts.read().is_empty() {
                                    div { class: "settings-list",
                                        for contact in invite_contacts.read().clone() {
                                            {
                                                let did = contact.peer.clone();
                                                let checked = selected_contacts.read().contains(&did);
                                                let eligible = contact.grants_me_invite();
                                                let has_ref = contact.invite_consent_ref().is_some();
                                                let usable = eligible && has_ref;
                                                // Distinguish "peer never authorised invite" (no real
                                                // consent grant ref) from other not-yet-usable states so
                                                // the badge tells the user why the row is disabled.
                                                let not_authorized = !usable;
                                                let did_for_toggle = did.clone();
                                                rsx! {
                                                    label {
                                                        class: "metric invite-contact-row",
                                                        "data-testid": "realm-invite-contact-{did}",
                                                        "data-eligible": "{usable}",
                                                        Checkbox {
                                                            checked: if checked { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                                            disabled: !usable,
                                                            on_checked_change: move |state: CheckboxState| {
                                                                let mut next = selected_contacts.read().clone();
                                                                if bool::from(state) {
                                                                    next.insert(did_for_toggle.clone());
                                                                } else {
                                                                    next.remove(&did_for_toggle);
                                                                }
                                                                selected_contacts.set(next);
                                                            },
                                                        }
                                                        span { class: "mono", title: "{did}", " {short_protocol_id(&did)}" }
                                                        if not_authorized {
                                                            span {
                                                                class: "badge",
                                                                "data-testid": "realm-invite-contact-unauthorized-{did}",
                                                                {crate::i18n::tr("realm_admin.invite_unauthorized")}
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    div { class: "actions",
                                        Button {
                                            variant: ButtonVariant::Primary,
                                            "data-testid": "realm-invite-send",
                                            disabled: selected_contacts.read().is_empty(),
                                            onclick: {
                                                let base = base_url.clone();
                                                let actor = account_did.clone();
                                                let realm = selected_realm_id.clone();
                                                move |_| {
                                                    let base = base.clone();
                                                    let actor = actor.clone();
                                                    let realm = realm.clone();
                                                    let api_token = token();
                                                    // Resolve the (did, consent_ref) pairs up front so the
                                                    // async task doesn't borrow the rendered rows.
                                                    let targets: Vec<(String, String)> = invite_contacts
                                                        .read()
                                                        .iter()
                                                        .filter(|c| selected_contacts.read().contains(&c.peer))
                                                        .filter_map(|c| {
                                                            c.invite_consent_ref().map(|r| (c.peer.clone(), r.to_owned()))
                                                        })
                                                        .collect();
                                                    if targets.is_empty() {
                                                        status_msg.set(crate::i18n::tr("realm_admin.invite_none_eligible"));
                                                        return;
                                                    }
                                                    let total = targets.len();
                                                    status_msg.set(
                                                        crate::i18n::tr("realm_admin.invite_sending")
                                                            .replace("{total}", &total.to_string()),
                                                    );
                                                    spawn(async move {
                                                        let api = match crate::views::helpers::authed_api(&base, api_token) {
                                                            Ok(api) => api,
                                                            Err(err) => {
                                                                status_msg.set(
                                                                    crate::i18n::tr("realm_admin.invite_bad_server")
                                                                        .replace("{error}", &err.to_string()),
                                                                );
                                                                return;
                                                            }
                                                        };
                                                        let mut ok = 0_usize;
                                                        let mut last_err = String::new();
                                                        for (did, consent_ref) in targets {
                                                            match api
                                                                .invite_contact_to_realm(&realm, &actor, &did, &consent_ref)
                                                                .await
                                                            {
                                                                Ok(event_id) => {
                                                                    ok += 1;
                                                                    frontier_state.set(event_id);
                                                                }
                                                                Err(err) => last_err = err.to_string(),
                                                            }
                                                        }
                                                        selected_contacts.set(std::collections::BTreeSet::new());
                                                        if ok == total {
                                                            invite_modal_open.set(false);
                                                            status_msg.set(
                                                                crate::i18n::tr("realm_admin.invite_sent")
                                                                    .replace("{ok}", &ok.to_string()),
                                                            );
                                                        } else {
                                                            status_msg.set(
                                                                crate::i18n::tr("realm_admin.invite_partial")
                                                                    .replace("{ok}", &ok.to_string())
                                                                    .replace("{total}", &total.to_string())
                                                                    .replace("{error}", &last_err),
                                                            );
                                                        }
                                                    });
                                                }
                                            },
                                            {crate::i18n::tr("realm_admin.invite_selected")}
                                        }
                                    }
                                }
                            }

                            div { class: "invite-divider muted", "data-testid": "realm-invite-divider", {crate::i18n::tr("realm_admin.invite_divider")} }

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
                                                    let op = match ck_ops::invite_create_structured(
                                                        &realm,
                                                        &actor,
                                                        &invite_id,
                                                        &invitee.did,
                                                        None,
                                                        invitee.invite_delivery_target.clone(),
                                                        &invitee.introduction_evidence_digest,
                                                    ) {
                                                        Ok(builder) => builder.build("yougen"),
                                                        Err(err) => {
                                                            status_msg.set(format!("invite failed: {err:#}"));
                                                            return;
                                                        }
                                                    };
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
                                size: ButtonSize::IconSm,
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
                            size: ButtonSize::IconSm,
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
                                                    let actor_id = actor_account_did.clone();
                                                    spawn(async move {
                                                        let m_for_msg = m.clone();
                                                        let realm_for_api = realm.clone();
                                                        match crate::views::helpers::with_authed_api(
                                                            &base,
                                                            api_token,
                                                            |api| async move {
                                                                api.transition_member_state(
                                                                    &realm_for_api,
                                                                    &actor_id,
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
                                                    let actor_id = actor_account_did.clone();
                                                    spawn(async move {
                                                        let m_for_msg = m.clone();
                                                        let realm_for_api = realm.clone();
                                                        match crate::views::helpers::with_authed_api(
                                                            &base,
                                                            api_token,
                                                            |api| async move {
                                                                api.ban_member(&realm_for_api, &actor_id, &m).await
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
