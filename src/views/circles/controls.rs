use dioxus::prelude::*;

use crate::transport::auth::with_authed_api;

#[component]
pub(super) fn CirclePolicyFields(
    mut visibility: Signal<arkret_sdk::CircleDirectoryVisibility>,
    mut join_rule: Signal<arkret_sdk::CircleJoinRule>,
) -> Element {
    rsx! {
        label { {crate::i18n::tr("circles.controls.directory_visibility")} }
        select {
            "aria-label": crate::i18n::tr("circles.controls.directory_visibility_aria"),
            value: if visibility() == arkret_sdk::CircleDirectoryVisibility::Members { "members" } else { "realm_members" },
            onchange: move |event| visibility.set(if event.value() == "members" { arkret_sdk::CircleDirectoryVisibility::Members } else { arkret_sdk::CircleDirectoryVisibility::RealmMembers }),
            option { value: "members", {crate::i18n::tr("circles.controls.members_only")} }
            option { value: "realm_members", {crate::i18n::tr("circles.controls.realm_preview")} }
        }
        label { {crate::i18n::tr("circles.controls.join_rule")} }
        select {
            "aria-label": crate::i18n::tr("circles.controls.join_rule_aria"),
            value: match join_rule() { arkret_sdk::CircleJoinRule::Public => "public", arkret_sdk::CircleJoinRule::Knock => "knock", arkret_sdk::CircleJoinRule::Invite => "invite" },
            onchange: move |event| join_rule.set(match event.value().as_str() { "public" => arkret_sdk::CircleJoinRule::Public, "knock" => arkret_sdk::CircleJoinRule::Knock, _ => arkret_sdk::CircleJoinRule::Invite }),
            option { value: "public", {crate::i18n::tr("circles.controls.public_join")} }
            option { value: "knock", {crate::i18n::tr("circles.controls.knock_join")} }
            option { value: "invite", {crate::i18n::tr("circles.controls.invite_join")} }
        }
    }
}

fn self_transition(
    join_rule: arkret_sdk::CircleJoinRule,
    membership: Option<arkret_sdk::CircleMembership>,
) -> Option<(arkret_sdk::CircleMembership, &'static str)> {
    use arkret_sdk::{CircleJoinRule as Rule, CircleMembership as Member};
    match membership {
        Some(Member::Join) => Some((Member::Leave, "circles.controls.leave")),
        Some(Member::Knock) => Some((Member::Leave, "circles.controls.withdraw")),
        Some(Member::Ban) => None,
        Some(Member::Leave) | None => match join_rule {
            Rule::Public => Some((Member::Join, "circles.controls.join")),
            Rule::Knock => Some((Member::Knock, "circles.controls.request_join")),
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
        return rsx! { p { class: "muted", {crate::i18n::tr("circles.controls.terminal_unavailable")} } };
    }
    let Some((target, label)) = self_transition(join_rule, membership) else {
        return rsx! { p { class: "muted", {crate::i18n::tr("circles.controls.manager_access")} } };
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
            {crate::i18n::tr(label)}
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
            summary { {crate::i18n::tr("circles.controls.edit")} }
            p { class: "muted", {crate::i18n::tr("circles.controls.management_required")} }
            div { class: "workflow-form",
                label { {crate::i18n::tr("circles.controls.title")} }
                input { value: "{title}", "aria-label": crate::i18n::tr("circles.controls.title_aria"), oninput: move |event| title.set(event.value()) }
                label { {crate::i18n::tr("circles.controls.short_name")} }
                input { value: "{short_name}", "aria-label": crate::i18n::tr("circles.controls.short_name_aria"), oninput: move |event| short_name.set(event.value()) }
                label { {crate::i18n::tr("circles.controls.summary")} }
                textarea { value: "{summary}", "aria-label": crate::i18n::tr("circles.controls.summary_aria"), oninput: move |event| summary.set(event.value()) }
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
                    {crate::i18n::tr("circles.controls.save_changes")}
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
            summary { {crate::i18n::tr("circles.controls.irreversible")} }
            p { class: "muted", {crate::i18n::tr("circles.controls.irreversible_permission")} }
            if state == arkret_sdk::CircleState::Active && history_access == arkret_sdk::HistoryAccess::AllHistoryForCurrentMembers {
                label {
                    input { r#type: "checkbox", checked: history_confirm(), "data-testid": "circle-history-confirm", onchange: move |event| history_confirm.set(event.checked()) }
                    {crate::i18n::tr("circles.controls.history_confirm")}
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
                    {crate::i18n::tr("circles.controls.restrict_history")}
                }
            }
            label {
                input { r#type: "checkbox", checked: terminal_confirm(), "data-testid": "circle-tombstone-confirm", onchange: move |event| terminal_confirm.set(event.checked()) }
                {crate::i18n::tr("circles.controls.terminal_confirm")}
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
                {crate::i18n::tr("circles.controls.retire")}
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

    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet};
    use std::rc::Rc;

    use arkret_sdk::CircleDirectoryVisibility as Visibility;
    use dioxus::prelude::*;

    use crate::i18n::{I18nSignal, UiLocale};

    type PolicyHandle = Rc<
        RefCell<(
            Option<I18nSignal>,
            Option<Signal<Visibility>>,
            Option<Signal<Rule>>,
            usize,
        )>,
    >;

    fn retained_policy_fields(handle: PolicyHandle) -> Element {
        let locale = use_context_provider(|| crate::i18n::init_i18n_with_locale(UiLocale::En));
        let visibility = use_signal(|| {
            handle.borrow_mut().3 += 1;
            Visibility::Members
        });
        let join_rule = use_signal(|| {
            handle.borrow_mut().3 += 1;
            Rule::Knock
        });
        {
            let mut state = handle.borrow_mut();
            state.0 = Some(locale);
            state.1 = Some(visibility);
            state.2 = Some(join_rule);
        }
        let label = self_transition(join_rule(), None)
            .map(|(_, key)| key)
            .unwrap_or("circles.controls.manager_access");
        rsx! {
            super::CirclePolicyFields { visibility, join_rule }
            // The production typed transition helper is exercised without
            // mounting session-dependent membership authoring lifecycle.
            p { {crate::i18n::tr(label)} }
            for membership in [Some(Member::Join), Some(Member::Knock)] {
                p { {crate::i18n::tr(self_transition(join_rule(), membership).expect("joined and pending members can leave").1)} }
            }
        }
    }

    fn apply_policy_edits(
        text: &mut BTreeMap<usize, String>,
        attrs: &mut BTreeMap<(usize, &'static str), String>,
        edits: dioxus::core::Mutations,
    ) -> usize {
        use dioxus::core::{AttributeValue, Mutation};
        let mut changed = 0;
        for edit in edits.edits {
            match edit {
                Mutation::CreateTextNode { id, value } | Mutation::SetText { id, value } => {
                    text.insert(id.0, value);
                    changed += 1;
                }
                Mutation::SetAttribute {
                    id,
                    name,
                    value: AttributeValue::Text(value),
                    ..
                } => {
                    attrs.insert((id.0, name), value);
                }
                _ => {}
            }
        }
        changed
    }

    fn policy_option_values(dom: &VirtualDom, node: &dioxus::core::VNode) -> BTreeSet<String> {
        fn visit(
            dom: &VirtualDom,
            node: &dioxus::core::VNode,
            template: &dioxus::core::TemplateNode,
            values: &mut BTreeSet<String>,
        ) {
            use dioxus::core::{DynamicNode, TemplateAttribute, TemplateNode};
            match template {
                TemplateNode::Element {
                    tag,
                    attrs,
                    children,
                    ..
                } => {
                    if *tag == "option" {
                        for attr in *attrs {
                            if let TemplateAttribute::Static {
                                name: "value",
                                value,
                                ..
                            } = attr
                            {
                                values.insert((*value).to_owned());
                            }
                        }
                    }
                    for child in *children {
                        visit(dom, node, child, values);
                    }
                }
                TemplateNode::Dynamic { id } => match &node.dynamic_nodes[*id] {
                    DynamicNode::Fragment(children) => {
                        for child in children {
                            values.extend(policy_option_values(dom, child));
                        }
                    }
                    DynamicNode::Component(component) => {
                        let scope = component
                            .mounted_scope(*id, node, dom)
                            .expect("policy component is mounted");
                        values.extend(policy_option_values(dom, scope.root_node()));
                    }
                    _ => {}
                },
                TemplateNode::Text { .. } => {}
            }
        }
        let mut values = BTreeSet::new();
        for root in node.template.roots {
            visit(dom, node, root, &mut values);
        }
        values
    }

    #[test]
    fn retained_circle_policy_labels_rerender_without_changing_typed_choices_or_membership_targets()
    {
        let handle = Rc::new(RefCell::new((None, None, None, 0)));
        let mut dom = VirtualDom::new_with_props(retained_policy_fields, handle.clone());
        let mut text = BTreeMap::new();
        let mut attrs = BTreeMap::new();
        apply_policy_edits(&mut text, &mut attrs, dom.rebuild_to_vec());
        let mut locale = handle.borrow().0.expect("policy locale");
        let mut visibility = handle.borrow().1.expect("typed visibility signal");
        let mut join_rule = handle.borrow().2.expect("typed join-rule signal");
        let visibility_id = attrs
            .iter()
            .find_map(|((id, name), value)| {
                (*name == "aria-label" && value == "Circle directory visibility").then_some(*id)
            })
            .expect("production visibility select");
        let join_rule_id = attrs
            .iter()
            .find_map(|((id, name), value)| {
                (*name == "aria-label" && value == "Circle join rule").then_some(*id)
            })
            .expect("production join-rule select");
        let wire_options = ["members", "realm_members", "public", "knock", "invite"]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            policy_option_values(&dom, dom.base_scope().root_node()),
            wire_options
        );
        for selected_visibility in [Visibility::Members, Visibility::RealmMembers] {
            for selected_rule in [Rule::Public, Rule::Knock, Rule::Invite] {
                dom.in_runtime(|| {
                    visibility.set(selected_visibility);
                    join_rule.set(selected_rule);
                });
                apply_policy_edits(&mut text, &mut attrs, dom.render_immediate_to_vec());
                let english = text.clone();
                let english_attrs = attrs.clone();
                let target = self_transition(selected_rule, None).map(|(target, _)| target);
                assert_eq!(
                    target,
                    match selected_rule {
                        Rule::Public => Some(Member::Join),
                        Rule::Knock => Some(Member::Knock),
                        Rule::Invite => None,
                    }
                );
                for language in [UiLocale::Zh, UiLocale::En] {
                    dom.in_runtime(|| crate::i18n::set_locale(&mut locale, language));
                    assert!(
                        apply_policy_edits(&mut text, &mut attrs, dom.render_immediate_to_vec())
                            > 0
                    );
                    dom.in_runtime(|| {
                        assert_eq!(visibility(), selected_visibility);
                        assert_eq!(join_rule(), selected_rule);
                    });
                    assert_eq!(
                        handle.borrow().3,
                        2,
                        "locale changes retain both typed signals"
                    );
                    assert_eq!(
                        self_transition(selected_rule, None).map(|(target, _)| target),
                        target
                    );
                    assert_eq!(
                        self_transition(selected_rule, Some(Member::Leave))
                            .map(|(target, _)| target),
                        target
                    );
                    assert!(self_transition(selected_rule, Some(Member::Ban)).is_none());
                    for membership in [Member::Join, Member::Knock] {
                        assert_eq!(
                            self_transition(selected_rule, Some(membership))
                                .map(|(target, _)| target),
                            Some(Member::Leave)
                        );
                    }
                    assert_eq!(
                        attrs.get(&(visibility_id, "value")).map(String::as_str),
                        Some(if selected_visibility == Visibility::Members {
                            "members"
                        } else {
                            "realm_members"
                        })
                    );
                    assert_eq!(
                        attrs.get(&(join_rule_id, "value")).map(String::as_str),
                        Some(match selected_rule {
                            Rule::Public => "public",
                            Rule::Knock => "knock",
                            Rule::Invite => "invite",
                        })
                    );
                    assert_eq!(
                        policy_option_values(&dom, dom.base_scope().root_node()),
                        wire_options
                    );
                    if language == UiLocale::Zh {
                        for expected in [
                            "目录可见性",
                            "仅 Circle 成员",
                            "允许 Realm 成员预览",
                            "加入规则",
                            "任何有效的 Realm 成员",
                            "申请批准",
                            "由 Circle 管理者添加",
                            "退出 Circle",
                            "撤回申请",
                        ] {
                            assert!(
                                text.values().any(|value| value == expected),
                                "missing label: {expected}"
                            );
                        }
                        assert_eq!(
                            attrs
                                .get(&(visibility_id, "aria-label"))
                                .map(String::as_str),
                            Some("Circle 目录可见性")
                        );
                        assert_eq!(
                            attrs.get(&(join_rule_id, "aria-label")).map(String::as_str),
                            Some("Circle 加入规则")
                        );
                        let expected = match selected_rule {
                            Rule::Public => "加入 Circle",
                            Rule::Knock => "申请加入",
                            Rule::Invite => {
                                "必须由 Circle 管理者授予访问权限。预览权限不包含 Circle 内容。"
                            }
                        };
                        assert!(text.values().any(|value| value == expected));
                    } else {
                        assert_eq!(text, english);
                        assert_eq!(attrs, english_attrs);
                    }
                }
            }
        }
    }
}
