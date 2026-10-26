//! Retained Circle forms and typed policy controls.
use arkret_sdk::{
    CircleDirectoryVisibility as Visibility, CircleJoinRule as Rule, CircleMembership as Member,
};

use super::*;
pub(super) fn self_transition(
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

fn options(
    _scope: &Scope,
    context: Rc<InksonContext>,
    key: &str,
    label: &str,
    value: Lotus<Option<String>>,
    items: &[(&str, &str)],
    change: impl FnMut(Option<String>) + 'static,
) -> View {
    let key = key.to_owned();
    let label = label.to_owned();
    let items = items
        .iter()
        .map(|(value, label)| (value.to_string(), label.to_string()))
        .collect::<Vec<_>>();
    let change = Rc::new(std::cell::RefCell::new(change));
    reactive(context.locale, move |scope, _| {
        let change = change.clone();
        let value = value.clone();
        let items = items.clone();
        let context = context.clone();
        let field_key = key.clone();
        let accessible_key = match label.as_str() {
            "circles.controls.directory_visibility" => "circles.controls.directory_visibility_aria",
            "circles.controls.join_rule" => "circles.controls.join_rule_aria",
            "circles.page.history" => "circles.page.history_label",
            _ => label.as_str(),
        }
        .to_owned();
        #[cfg(target_arch = "wasm32")]
        let accessible_name = context.translated(scope, accessible_key.clone());
        let select_key = format!("{key}-select");
        #[cfg(not(target_arch = "wasm32"))]
        let choice_label = accessible_key;
        Box::new(
            sapid::field(field_key)
                .unstyled()
                .label(context.translated(scope, label.clone()))
                .control(move |field| {
                    #[cfg(target_arch = "wasm32")]
                    {
                        sapid::select(select_key.clone())
                            .unstyled()
                            .field(field)
                            .name(accessible_name)
                            .value(value.clone())
                            .options(items.iter().map(|(value, label)| {
                                sapid::select_option(value.clone(), context.tr(label))
                                    .value(value.clone())
                            }))
                            .on_value_change({
                                let change = change.clone();
                                move |value| change.borrow_mut()(value)
                            })
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        use crate::presentation::native_choice::{
                            NativeChoiceOption, NativeChoiceProps, native_choice,
                        };
                        let change = change.clone();
                        let select_key = select_key.clone();
                        let context = context.clone();
                        let label = choice_label.clone();
                        let value = value.clone();
                        let items = items.clone();
                        widget(move |scope| {
                            let change = change.clone();
                            native_choice(
                                scope,
                                NativeChoiceProps::new(
                                    select_key.clone(),
                                    context.translated(scope, label.clone()),
                                    value.clone(),
                                    items
                                        .iter()
                                        .map(|(value, label)| {
                                            NativeChoiceOption::new(
                                                value.clone(),
                                                context.tr(label),
                                            )
                                        })
                                        .collect(),
                                    move |value| change.borrow_mut()(value),
                                )
                                .control_id(field.id.clone())
                                .close_label(context.translated(scope, "common.close")),
                            )
                            .build(scope)
                        })
                    }
                }),
        ) as View
    })
}
pub(super) fn policy_fields(
    scope: &Scope,
    context: Rc<InksonContext>,
    key: &str,
    visibility: Cage<Visibility>,
    rule: Cage<Rule>,
) -> View {
    let selected_visibility = scope.bond(move || {
        Some(
            if visibility.get() == Visibility::Members {
                "members"
            } else {
                "realm_members"
            }
            .to_owned(),
        )
    });
    let selected_rule = scope.bond(move || {
        Some(
            match rule.get() {
                Rule::Public => "public",
                Rule::Knock => "knock",
                Rule::Invite => "invite",
            }
            .to_owned(),
        )
    });
    block(
        "circle-policy-fields",
        vec![
            options(
                scope,
                context.clone(),
                &format!("{key}-visibility"),
                "circles.controls.directory_visibility",
                selected_visibility.into(),
                &[
                    ("members", "circles.controls.members_only"),
                    ("realm_members", "circles.controls.realm_preview"),
                ],
                move |next| {
                    visibility.revise(|value| {
                        *value = if next.as_deref() == Some("members") {
                            Visibility::Members
                        } else {
                            Visibility::RealmMembers
                        }
                    })
                },
            ),
            options(
                scope,
                context,
                &format!("{key}-rule"),
                "circles.controls.join_rule",
                selected_rule.into(),
                &[
                    ("public", "circles.controls.public_join"),
                    ("knock", "circles.controls.knock_join"),
                    ("invite", "circles.controls.invite_join"),
                ],
                move |next| {
                    rule.revise(|value| {
                        *value = match next.as_deref() {
                            Some("public") => Rule::Public,
                            Some("knock") => Rule::Knock,
                            _ => Rule::Invite,
                        }
                    })
                },
            ),
        ],
    )
}
pub(super) fn self_membership(
    scope: &Scope,
    context: Rc<InksonContext>,
    ui: Rc<CircleUi>,
    realm: String,
    circle: String,
    rule: Rule,
    membership: Option<Member>,
    terminal: bool,
) -> View {
    if terminal {
        return paragraph(
            "muted",
            context.translated(scope, "circles.controls.terminal_unavailable"),
        );
    }
    let Some((target, label)) = self_transition(rule, membership) else {
        return paragraph(
            "muted",
            context.translated(scope, "circles.controls.manager_access"),
        );
    };
    let Some(account) = context.active_account.get() else {
        return paragraph(
            "muted",
            context.translated(scope, "circles.feedback.account_required"),
        );
    };
    command_button(
        scope,
        context,
        ui,
        label,
        "secondary",
        commands::Change::SelfMembership {
            realm,
            circle,
            member: arkret_sdk::ActorId::account(account.authority),
            target,
            expected: membership,
        },
    )
}
fn retained_section(
    scope: &Scope,
    context: Rc<InksonContext>,
    key: &str,
    title: &str,
    body: View,
) -> View {
    let open = scope.cage(false);
    let class = key.to_owned();
    block(
        &class,
        vec![
            action(
                scope,
                context,
                key,
                title,
                "circle-details-summary",
                true,
                move || open.revise(|value| *value = !*value),
            ),
            Box::new(
                view()
                    .style(scope.bond(move || {
                        Style::new().display(if open.get() {
                            Display::Block
                        } else {
                            Display::None
                        })
                    }))
                    .fill(body),
            ),
        ],
    )
}
pub(super) fn edit_form(
    scope: &Scope,
    context: Rc<InksonContext>,
    ui: Rc<CircleUi>,
    circle: arkret_sdk::CircleView,
) -> View {
    let title = scope.cage(circle.title.clone());
    let summary = scope.cage(circle.summary.clone().unwrap_or_default());
    let short = scope.cage(circle.display.short_name.clone());
    let visibility = scope.cage(circle.directory_visibility);
    let rule = scope.cage(circle.join_rule);
    let weak = scope.downgrade();
    let save_context = context.clone();
    let save_ui = ui.clone();
    let enabled = scope.bond({
        let ui = ui.clone();
        move || {
            !ui.busy.get() && !title.get().trim().is_empty() && valid_short_name(short.get().trim())
        }
    });
    let save = action(
        scope,
        context.clone(),
        "circle-edit-save",
        "circles.controls.save_changes",
        "secondary",
        enabled,
        move || {
            let mut display = circle.display.clone();
            display.short_name = short.get().trim().to_owned();
            if let Some(scope) = weak.upgrade() {
                commands::run(
                    &scope,
                    save_context.clone(),
                    save_ui.clone(),
                    commands::Change::Update {
                        realm: circle.realm_id.to_string(),
                        circle: circle.circle_id.to_string(),
                        title: title.get(),
                        summary: summary.get(),
                        display,
                        visibility: visibility.get(),
                        rule: rule.get(),
                    },
                );
            }
        },
    );
    let body = block(
        "workflow-form",
        vec![
            paragraph(
                "muted",
                context.translated(scope, "circles.controls.management_required"),
            ),
            input(
                scope,
                context.clone(),
                "circle-edit-title",
                "circles.controls.title",
                title,
                true,
            ),
            input(
                scope,
                context.clone(),
                "circle-edit-short",
                "circles.controls.short_name",
                short,
                true,
            ),
            field(
                scope,
                context.clone(),
                "circle-edit-summary",
                "circles.controls.summary",
                summary,
                true,
                true,
                move |next| summary.revise(|value| *value = next),
            ),
            policy_fields(scope, context.clone(), "circle-edit", visibility, rule),
            save,
        ],
    );
    retained_section(scope, context, "circle-edit", "circles.controls.edit", body)
}
pub(super) fn terminal_actions(
    scope: &Scope,
    context: Rc<InksonContext>,
    ui: Rc<CircleUi>,
    circle: arkret_sdk::CircleView,
) -> View {
    if circle.state == arkret_sdk::CircleState::Tombstoned {
        return empty();
    }
    let history = scope.cage(false);
    let terminal = scope.cage(false);
    let mut children = vec![paragraph(
        "muted",
        context.translated(scope, "circles.controls.irreversible_permission"),
    )];
    if circle.state == arkret_sdk::CircleState::Active
        && circle.history_access == arkret_sdk::HistoryAccess::AllHistoryForCurrentMembers
    {
        children.push(toggle(
            scope,
            context.clone(),
            "circle-history-confirm",
            "circles.controls.history_confirm",
            history,
            true,
            move |next| history.revise(|value| *value = next),
        ));
        let weak = scope.downgrade();
        let command_context = context.clone();
        let command_ui = ui.clone();
        let realm = circle.realm_id.to_string();
        let id = circle.circle_id.to_string();
        children.push(action(
            scope,
            context.clone(),
            "circle-history-restrict",
            "circles.controls.restrict_history",
            "secondary",
            scope.bond({
                let ui = ui.clone();
                move || history.get() && !ui.busy.get()
            }),
            move || {
                if let Some(scope) = weak.upgrade() {
                    commands::run(
                        &scope,
                        command_context.clone(),
                        command_ui.clone(),
                        commands::Change::Restrict {
                            realm: realm.clone(),
                            circle: id.clone(),
                        },
                    );
                    history.revise(|value| *value = false);
                }
            },
        ));
    }
    children.push(toggle(
        scope,
        context.clone(),
        "circle-terminal-confirm",
        "circles.controls.terminal_confirm",
        terminal,
        true,
        move |next| terminal.revise(|value| *value = next),
    ));
    let weak = scope.downgrade();
    let command_context = context.clone();
    let command_ui = ui.clone();
    children.push(action(
        scope,
        context.clone(),
        "circle-tombstone",
        "circles.controls.retire",
        "secondary danger",
        scope.bond(move || terminal.get() && !ui.busy.get()),
        move || {
            if let Some(scope) = weak.upgrade() {
                commands::run(
                    &scope,
                    command_context.clone(),
                    command_ui.clone(),
                    commands::Change::Tombstone {
                        realm: circle.realm_id.to_string(),
                        circle: circle.circle_id.to_string(),
                    },
                );
                terminal.revise(|value| *value = false);
            }
        },
    ));
    retained_section(
        scope,
        context,
        "circle-terminal-actions",
        "circles.controls.irreversible",
        block("", children),
    )
}
pub(super) fn member_form(
    scope: &Scope,
    context: Rc<InksonContext>,
    ui: Rc<CircleUi>,
    realm: String,
    circle: String,
) -> View {
    let member = scope.cage(String::new());
    let state = scope.cage("join".to_owned());
    let weak = scope.downgrade();
    let command_context = context.clone();
    let command_ui = ui.clone();
    block(
        "workflow-form",
        vec![
            input(
                scope,
                context.clone(),
                "circle-member",
                "circles.page.member_actor",
                member,
                true,
            ),
            choice(
                scope,
                context.clone(),
                "circle-member-state",
                "circles.page.membership",
                state,
                vec![
                    ("join".into(), context.tr("circles.page.add_member")),
                    ("knock".into(), context.tr("circles.page.request")),
                    ("leave".into(), context.tr("circles.page.leave")),
                    ("ban".into(), context.tr("circles.page.ban")),
                ],
                true,
                move |next| state.revise(|value| *value = next),
            ),
            action(
                scope,
                context,
                "circle-member-apply",
                "circles.page.apply",
                "secondary",
                scope.bond(move || !ui.busy.get() && !member.get().trim().is_empty()),
                move || {
                    let Ok(member_id) =
                        serde_json::from_str::<arkret_sdk::ActorId>(member.get().trim())
                    else {
                        command_ui.status.revise(|value| {
                            *value = CircleFeedback::new("circles.feedback.invalid_member")
                        });
                        return;
                    };
                    let state = match state.get().as_str() {
                        "join" => Member::Join,
                        "knock" => Member::Knock,
                        "leave" => Member::Leave,
                        "ban" => Member::Ban,
                        _ => {
                            command_ui.status.revise(|value| {
                                *value = CircleFeedback::new("circles.feedback.invalid_transition")
                            });
                            return;
                        }
                    };
                    if let Some(scope) = weak.upgrade() {
                        commands::run(
                            &scope,
                            command_context.clone(),
                            command_ui.clone(),
                            commands::Change::Member {
                                realm: realm.clone(),
                                circle: circle.clone(),
                                member: member_id,
                                state,
                            },
                        );
                    }
                },
            ),
        ],
    )
}
pub(super) fn create_form(
    scope: &Scope,
    context: Rc<InksonContext>,
    ui: Rc<CircleUi>,
    realm: String,
) -> View {
    let title = scope.cage(String::new());
    let summary = scope.cage(String::new());
    let short = scope.cage(String::new());
    let encrypted = scope.cage(false);
    let visibility = scope.cage(Visibility::Members);
    let rule = scope.cage(Rule::Public);
    let history = scope.cage(arkret_sdk::HistoryAccess::SinceJoin);
    reactive(ui.create_open, move |scope, open| {
        if !open {
            return empty();
        }
        let child_context = context.clone();
        let child_ui = ui.clone();
        let realm = realm.clone();
        let dismiss = ui.clone();
        crate::components::dismissible_popup(
            scope,
            context.clone(),
            crate::components::DismissiblePopupProps {
                overlay_class: "discussion-modal-backdrop".into(),
                surface_class: "discussion-modal circle-create-modal".into(),
                aria_label: context.tr("circles.page.create"),
                overlay_test_id: None,
                surface_test_id: Some("circle-create-modal".into()),
                overlay_style: None,
                surface_style: None,
                on_dismiss: Rc::new(move |_| dismiss.create_open.revise(|value| *value = false)),
                children: Rc::new(move |scope| {
                    let context = child_context.clone();
                    let ui = child_ui.clone();
                    let weak = scope.downgrade();
                    let create_context = context.clone();
                    let create_ui = ui.clone();
                    let create_realm = realm.clone();
                    let body = block(
                        "workflow-form",
                        vec![
                            input(
                                scope,
                                context.clone(),
                                "circle-create-title",
                                "circles.page.title",
                                title,
                                true,
                            ),
                            Box::new(
                                sapid::field("circle-create-short")
                                    .unstyled()
                                    .class("circle-create-short")
                                    .label(context.translated(scope, "circles.page.short_name"))
                                    .control({
                                        let name = context
                                            .translated(scope, "circles.page.short_name_label");
                                        move |field| {
                                            sapid::text_field()
                                                .unstyled()
                                                .class("input")
                                                .field(field)
                                                .name(name)
                                                .value(short)
                                                .on_value_change(move |next| {
                                                    short.revise(|value| *value = next)
                                                })
                                        }
                                    }),
                            ),
                            field(
                                scope,
                                context.clone(),
                                "circle-create-summary",
                                "circles.page.summary",
                                summary,
                                true,
                                true,
                                move |next| summary.revise(|value| *value = next),
                            ),
                            policy_fields(
                                scope,
                                context.clone(),
                                "circle-create",
                                visibility,
                                rule,
                            ),
                            options(
                                scope,
                                context.clone(),
                                "circle-history",
                                "circles.page.history",
                                scope
                                    .bond(move || {
                                        Some(
                                                if history.get()
                                                    == arkret_sdk::HistoryAccess::SinceJoin
                                                {
                                                    "since_join"
                                                } else {
                                                    "all_history_for_current_members"
                                                }
                                                .into(),
                                            )
                                    })
                                    .into(),
                                &[
                                    ("since_join", "circles.page.since_join"),
                                    (
                                        "all_history_for_current_members",
                                        "circles.page.all_history",
                                    ),
                                ],
                                move |next| {
                                    history.revise(|value| {
                                        *value = if next.as_deref() == Some("since_join") {
                                            arkret_sdk::HistoryAccess::SinceJoin
                                        } else {
                                            arkret_sdk::HistoryAccess::AllHistoryForCurrentMembers
                                        }
                                    })
                                },
                            ),
                            toggle(
                                scope,
                                context.clone(),
                                "circle-encrypted",
                                "circles.page.e2ee",
                                encrypted,
                                true,
                                move |next| encrypted.revise(|value| *value = next),
                            ),
                            block(
                                "circle-boundary-preview",
                                vec![
                                    heading(
                                        3,
                                        "",
                                        context.translated(scope, "circles.page.boundary_preview"),
                                    ),
                                    paragraph(
                                        "",
                                        initial_member_label(&crate::app::principal_id_owned(
                                            context.principal_id.get(),
                                        )),
                                    ),
                                    paragraph(
                                        "",
                                        scope.bond(move || {
                                            crate::i18n::tr_args(
                                                "circles.page.directory_value",
                                                &[("value", format!("{:?}", visibility.get()))],
                                            )
                                        }),
                                    ),
                                    paragraph(
                                        "",
                                        scope.bond(move || {
                                            crate::i18n::tr_args(
                                                "circles.page.join_rule_value",
                                                &[("value", format!("{:?}", rule.get()))],
                                            )
                                        }),
                                    ),
                                    paragraph(
                                        "",
                                        scope.bond(move || {
                                            crate::i18n::tr_args(
                                                "circles.page.history_value",
                                                &[("value", format!("{:?}", history.get()))],
                                            )
                                        }),
                                    ),
                                    paragraph(
                                        "",
                                        context.translated(scope, "circles.page.boundary_help"),
                                    ),
                                ],
                            ),
                        ],
                    );
                    block(
                        "",
                        vec![
                            block(
                                "discussion-modal-head",
                                vec![
                                    heading(
                                        2,
                                        "",
                                        context.translated(scope, "circles.page.create"),
                                    ),
                                    action(
                                        scope,
                                        context.clone(),
                                        "circle-cancel",
                                        "common.cancel",
                                        "secondary",
                                        true,
                                        move || ui.create_open.revise(|value| *value = false),
                                    ),
                                ],
                            ),
                            body,
                            action(
                                scope,
                                context,
                                "circle-create",
                                "circles.page.create",
                                "primary",
                                scope.bond({
                                    let ui = create_ui.clone();
                                    move || {
                                        !ui.busy.get()
                                            && !title.get().trim().is_empty()
                                            && (short.get().is_empty()
                                                || valid_short_name(short.get().trim()))
                                    }
                                }),
                                move || {
                                    if let Some(scope) = weak.upgrade() {
                                        commands::create(
                                            &scope,
                                            create_context.clone(),
                                            create_ui.clone(),
                                            create_realm.clone(),
                                            commands::Create {
                                                title: title.get().trim().into(),
                                                summary: summary.get().trim().into(),
                                                short_name: short.get(),
                                                visibility: visibility.get(),
                                                rule: rule.get(),
                                                history: history.get(),
                                                encrypted: encrypted.get(),
                                            },
                                        );
                                    }
                                },
                            ),
                        ],
                    )
                }),
            },
        )
    })
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
