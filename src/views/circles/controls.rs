use dioxus::prelude::*;

use crate::transport::auth::with_authed_api;

#[component]
pub(super) fn CirclePolicyFields(
    mut visibility: Signal<arkret_sdk::CircleDirectoryVisibility>,
    mut join_rule: Signal<arkret_sdk::CircleJoinRule>,
) -> Element {
    rsx! {
        label { "Directory visibility" }
        select {
            "aria-label": "Circle directory visibility",
            value: if visibility() == arkret_sdk::CircleDirectoryVisibility::Members { "members" } else { "realm_members" },
            onchange: move |event| visibility.set(if event.value() == "members" { arkret_sdk::CircleDirectoryVisibility::Members } else { arkret_sdk::CircleDirectoryVisibility::RealmMembers }),
            option { value: "members", "Circle members only" }
            option { value: "realm_members", "Preview for Realm members" }
        }
        label { "Join rule" }
        select {
            "aria-label": "Circle join rule",
            value: match join_rule() { arkret_sdk::CircleJoinRule::Public => "public", arkret_sdk::CircleJoinRule::Knock => "knock", arkret_sdk::CircleJoinRule::Invite => "invite" },
            onchange: move |event| join_rule.set(match event.value().as_str() { "public" => arkret_sdk::CircleJoinRule::Public, "knock" => arkret_sdk::CircleJoinRule::Knock, _ => arkret_sdk::CircleJoinRule::Invite }),
            option { value: "public", "Any active Realm member" }
            option { value: "knock", "Request approval" }
            option { value: "invite", "Added by a Circle manager" }
        }
    }
}

fn self_transition(
    join_rule: arkret_sdk::CircleJoinRule,
    membership: Option<arkret_sdk::CircleMembership>,
) -> Option<(arkret_sdk::CircleMembership, &'static str)> {
    use arkret_sdk::{CircleJoinRule as Rule, CircleMembership as Member};
    match membership {
        Some(Member::Join) => Some((Member::Leave, "Leave Circle")),
        Some(Member::Knock) => Some((Member::Leave, "Withdraw request")),
        Some(Member::Ban) => None,
        Some(Member::Leave) | None => match join_rule {
            Rule::Public => Some((Member::Join, "Join Circle")),
            Rule::Knock => Some((Member::Knock, "Request to join")),
            Rule::Invite => None,
        },
    }
}

#[component]
pub(super) fn CircleSelfMembership(
    realm_id: String,
    circle_id: String,
    principal_id: String,
    join_rule: arkret_sdk::CircleJoinRule,
    membership: Option<arkret_sdk::CircleMembership>,
    terminal: bool,
    token: Signal<String>,
    mut busy: Signal<bool>,
    mut refresh: Signal<u64>,
    mut status: Signal<String>,
) -> Element {
    let session = crate::app::SessionContext::get();
    let base = crate::app::SessionContext::base_url_string();
    if terminal {
        return rsx! { p { class: "muted", "This Circle is permanently unavailable." } };
    }
    let Some((target, label)) = self_transition(join_rule, membership) else {
        return rsx! { p { class: "muted", "A Circle manager must grant access. Preview access does not include Circle content." } };
    };
    rsx! {
        button {
            class: "secondary", r#type: "button", "data-testid": "circle-self-membership",
            disabled: busy(),
            onclick: move |_| {
                let Some(account) = session.active_account() else {
                    status.set("An active account is required".to_owned());
                    return;
                };
                let member = arkret_sdk::ActorId::account(account.authority);
                let base = base.clone();
                let realm_id = realm_id.clone();
                let circle_id = circle_id.clone();
                let principal_id = principal_id.clone();
                let credential = token();
                busy.set(true);
                spawn(async move {
                    let outcome = with_authed_api(&base, credential, |api| async move {
                        let submitter = api.event_submitter()?;
                        let parent_revision = if target == arkret_sdk::CircleMembership::Join {
                            Some(submitter.read_parent_membership_revision(&arkret_sdk::RealmId::new(realm_id.clone())?, &member).await?)
                        } else { None };
                        let event = crate::operation::ak_ops::circle_member_state_with_expected(
                            &realm_id, &principal_id, &circle_id, &member, target,
                            // Preview does not disclose canonical viewer membership;
                            // missing deliberately leaves its FSM guard to admission.
                            membership.map(arkret_wire::WirePresence::Value).unwrap_or(arkret_wire::WirePresence::Missing),
                            parent_revision,
                        )?.build_sdk_event("inkson")?;
                        let body = arkret_sdk::CircleMemberRequestBody {
                            member_event: arkret_wire::EventAdmissionSubmission::new(submitter.author_for_direct_submission(&event).await?.into_event()),
                        };
                        api.http().circle_member_add(&circle_id, &body).await?;
                        Ok::<_, anyhow::Error>(())
                    }).await;
                    match outcome {
                        Ok(()) => { status.set(if target == arkret_sdk::CircleMembership::Knock { "Join request submitted" } else { "Membership updated" }.to_owned()); refresh += 1; }
                        Err(error) => status.set(format!("Membership update failed: {}", error.display())),
                    }
                    busy.set(false);
                });
            },
            "{label}"
        }
    }
}

#[component]
pub(super) fn CircleEditForm(
    realm_id: String,
    circle_id: String,
    initial_title: String,
    initial_summary: Option<String>,
    display: arkret_sdk::CircleDisplay,
    initial_visibility: arkret_sdk::CircleDirectoryVisibility,
    initial_join_rule: arkret_sdk::CircleJoinRule,
    principal_id: String,
    token: Signal<String>,
    mut busy: Signal<bool>,
    mut refresh: Signal<u64>,
    mut status: Signal<String>,
) -> Element {
    let mut title = use_signal(|| initial_title.clone());
    let mut summary = use_signal(|| initial_summary.clone().unwrap_or_default());
    let mut short_name = use_signal(|| display.short_name.clone());
    let visibility = use_signal(|| initial_visibility);
    let join_rule = use_signal(|| initial_join_rule);
    let base = crate::app::SessionContext::base_url_string();
    rsx! {
        details { class: "circle-edit", "data-testid": "circle-edit",
            summary { "Edit Circle" }
            p { class: "muted", "Changes require Circle management permission." }
            div { class: "workflow-form",
                label { "Title" }
                input { value: "{title}", "aria-label": "Circle title", oninput: move |event| title.set(event.value()) }
                label { "Short name (ASCII, unique in this Realm)" }
                input { value: "{short_name}", "aria-label": "Circle short name", oninput: move |event| short_name.set(event.value()) }
                label { "Summary" }
                textarea { value: "{summary}", "aria-label": "Circle summary", oninput: move |event| summary.set(event.value()) }
                CirclePolicyFields { visibility, join_rule }
                button {
                    class: "secondary", r#type: "button", "data-testid": "circle-edit-save",
                    disabled: busy() || title().trim().is_empty() || !super::valid_short_name(short_name().trim()),
                    onclick: move |_| {
                        let mut display = display.clone();
                        display.short_name = short_name().trim().to_owned();
                        let event = crate::operation::ak_ops::circle_update(
                            realm_id.as_str(), &principal_id, circle_id.as_str(),
                            &title(), &summary(), display, visibility(), join_rule(),
                        ).and_then(|builder| builder.build_sdk_event("inkson"));
                        let event = match event { Ok(event) => event, Err(error) => { status.set(error.to_string()); return; } };
                        let base = base.clone();
                        let credential = token();
                        busy.set(true);
                        spawn(async move {
                            let outcome = with_authed_api(&base, credential, |api| async move {
                                api.event_submitter()?.submit_sdk_event(&event).await
                            }).await;
                            match outcome {
                                Ok(_) => { status.set("Circle updated".to_owned()); refresh += 1; }
                                Err(error) => status.set(format!("Circle update failed: {}", error.display())),
                            }
                            busy.set(false);
                        });
                    },
                    "Save changes"
                }
            }
        }
    }
}

#[component]
pub(super) fn CircleTerminalActions(
    realm_id: String,
    circle_id: String,
    state: arkret_sdk::CircleState,
    history_access: arkret_sdk::HistoryAccess,
    principal_id: String,
    token: Signal<String>,
    mut busy: Signal<bool>,
    mut refresh: Signal<u64>,
    mut status: Signal<String>,
) -> Element {
    let mut history_confirm = use_signal(|| false);
    let mut terminal_confirm = use_signal(|| false);
    let base = crate::app::SessionContext::base_url_string();
    if state == arkret_sdk::CircleState::Tombstoned {
        return rsx! {};
    }
    rsx! {
        details { class: "circle-edit", "data-testid": "circle-terminal-actions",
            summary { "Irreversible changes" }
            p { class: "muted", "These actions require Circle management permission and cannot be undone." }
            if state == arkret_sdk::CircleState::Active && history_access == arkret_sdk::HistoryAccess::AllHistoryForCurrentMembers {
                label {
                    input { r#type: "checkbox", checked: history_confirm(), "data-testid": "circle-history-confirm", onchange: move |event| history_confirm.set(event.checked()) }
                    "I understand history will be restricted to each member's join boundary."
                }
                button {
                    class: "secondary", r#type: "button", disabled: busy() || !history_confirm(), "data-testid": "circle-history-restrict",
                    onclick: {
                        let base = base.clone();
                        let realm_id = realm_id.clone();
                        let circle_id = circle_id.clone();
                        let principal_id = principal_id.clone();
                        move |_| {
                            let event = crate::operation::ak_ops::circle_restrict_history(realm_id.as_str(), &principal_id, circle_id.as_str()).and_then(|builder| builder.build_sdk_event("inkson"));
                            let event = match event { Ok(event) => event, Err(error) => { status.set(error.to_string()); return; } };
                            let base = base.clone();
                            let credential = token();
                            busy.set(true);
                            spawn(async move {
                                let outcome = with_authed_api(&base, credential, |api| async move { api.event_submitter()?.submit_sdk_event(&event).await }).await;
                                match outcome {
                                    Ok(_) => { status.set("History restricted to since joining".to_owned()); history_confirm.set(false); refresh += 1; }
                                    Err(error) => status.set(format!("History change failed: {}", error.display())),
                                }
                                busy.set(false);
                            });
                        }
                    },
                    "Restrict history"
                }
            }
            label {
                input { r#type: "checkbox", checked: terminal_confirm(), "data-testid": "circle-tombstone-confirm", onchange: move |event| terminal_confirm.set(event.checked()) }
                "I understand this Circle will become permanently unavailable."
            }
            button {
                class: "secondary danger", r#type: "button", disabled: busy() || !terminal_confirm(), "data-testid": "circle-tombstone",
                onclick: move |_| {
                    let event = crate::operation::ak_ops::circle_lifecycle(realm_id.as_str(), &principal_id, circle_id.as_str(), arkret_sdk::EventKind::CircleTombstone, None).and_then(|builder| builder.build_sdk_event("inkson"));
                    let event = match event { Ok(event) => event, Err(error) => { status.set(error.to_string()); return; } };
                    let base = base.clone();
                    let credential = token();
                    busy.set(true);
                    spawn(async move {
                        let outcome = with_authed_api(&base, credential, |api| async move { api.event_submitter()?.submit_sdk_event(&event).await }).await;
                        match outcome {
                            Ok(_) => { status.set("Circle permanently retired".to_owned()); terminal_confirm.set(false); refresh += 1; }
                            Err(error) => status.set(format!("Circle retirement failed: {}", error.display())),
                        }
                        busy.set(false);
                    });
                },
                "Permanently retire Circle"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use arkret_sdk::{CircleJoinRule as Rule, CircleMembership as Member};

    use super::self_transition;

    #[test]
    fn self_actions_respect_join_rule_and_membership() {
        assert_eq!(self_transition(Rule::Public, None).unwrap().0, Member::Join);
        assert_eq!(self_transition(Rule::Knock, None).unwrap().0, Member::Knock);
        assert!(self_transition(Rule::Invite, None).is_none());
        for rule in [Rule::Public, Rule::Knock, Rule::Invite] {
            assert!(self_transition(rule, Some(Member::Ban)).is_none());
            assert_eq!(
                self_transition(rule, Some(Member::Join)).unwrap().0,
                Member::Leave
            );
            assert_eq!(
                self_transition(rule, Some(Member::Knock)).unwrap().0,
                Member::Leave
            );
        }
    }
}
