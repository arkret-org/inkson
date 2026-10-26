use super::*;
use crate::i18n::UiLocale;

fn context(app: &glory::ui::App) -> Rc<InksonContext> {
    let directory = tempfile::tempdir().unwrap();
    let config = crate::config::ClientConfig::default();
    let context = InksonContext::new(
        app.scope(),
        crate::presentation::BootState {
            config_store: crate::config::LocalConfigStore::with_path(
                directory.path().join("config.json"),
            ),
            config,
            state_store: crate::presentation::SharedStateStore::new(
                crate::state::LocalStateStore::with_path(directory.path().join("state.json")),
            ),
            initial_credential: String::new(),
            realm_tree_nodes: vec![],
        },
        Route::Dashboard,
        |_| Box::pin(async { crate::runtime::session::CurrentSessionRefresh::retry_later("test") }),
    );
    app.scope().retain(directory).unwrap();
    context.locale.revise(|value| *value = UiLocale::En);
    context
}
fn strings(app: &glory::ui::App) -> Vec<String> {
    fn walk(
        tree: &glory::render::memory::Memory,
        id: glory::render::NodeId,
        out: &mut Vec<String>,
    ) {
        let node = tree.node(id).unwrap();
        match node.descriptor.view().props {
            glory::render::Props::Text(props) => out.push(props.content.clone()),
            glory::render::Props::Select(props) => out.extend(
                props
                    .options()
                    .map(|(option, _)| format!("{}={}", option.value, option.label)),
            ),
            _ => {}
        }
        for child in node.children.iter().copied() {
            walk(tree, child, out);
        }
    }
    let tree = app.tree();
    let mut values = Vec::new();
    for id in tree.roots() {
        walk(&tree, *id, &mut values);
    }
    values
}
#[test]
fn retained_feedback_retranslates_without_repeating_actions_or_leaking_diagnostics() {
    let app = glory::ui::App::memory();
    let context = context(&app);
    let feedback = app.scope().cage(vec![
        CircleFeedback::new("circles.feedback.creating"),
        CircleFeedback::new("circles.feedback.created"),
        CircleFeedback::new("circles.feedback.invalid_member"),
        CircleFeedback::new("circles.feedback.prepare_failed"),
        CircleFeedback::new("circles.feedback.membership_failed").with_api_error(
            crate::transport::auth::ApiCallError::AuthExpired(anyhow::anyhow!(
                "private session diagnostic"
            )),
        ),
    ]);
    let language = context.locale;
    let labels = app.scope().bond(move || {
        let _ = language.get();
        feedback
            .get()
            .iter()
            .map(CircleFeedback::render)
            .collect::<Vec<_>>()
    });
    app.mount(reactive(labels, |_, labels| {
        block("", labels.into_iter().map(plain).collect())
    }))
    .unwrap();
    app.flush().unwrap();
    let english = strings(&app);
    assert!(english.iter().any(|value| value == "Circle created"));
    context.locale.revise(|value| *value = UiLocale::Zh);
    app.flush().unwrap();
    let chinese = strings(&app);
    for expected in [
        "正在创建圈子并设置初始成员…",
        "圈子已创建",
        "请输入完整的成员身份标识，包含身份类型及适用的托管站点。",
        "无法准备圈子变更，请刷新重试。",
        "更新成员状态失败：登录已过期。请重新登录以继续。",
    ] {
        assert!(
            chinese.iter().any(|value| value == expected),
            "missing {expected}"
        );
    }
    assert!(chinese.iter().all(|value| !value.contains("private")));
    context.locale.revise(|value| *value = UiLocale::En);
    app.flush().unwrap();
    assert_eq!(strings(&app), english);
    assert_eq!(feedback.get().len(), 5);
}
#[test]
fn retained_labels_translate_protocol_enum_copy_and_preserve_raw_user_text() {
    let app = glory::ui::App::memory();
    let context = context(&app);
    let locale = context.locale;
    let raw = "circles.page.membership_join {member} 原文";
    let labels = app.scope().bond(move || {
        let _ = locale.get();
        vec![
            lifecycle_label(arkret_sdk::CircleState::Active),
            lifecycle_label(arkret_sdk::CircleState::Archived),
            lifecycle_label(arkret_sdk::CircleState::Tombstoned),
            membership_label(Some(arkret_sdk::CircleMembership::Join)),
            membership_label(Some(arkret_sdk::CircleMembership::Knock)),
            membership_label(Some(arkret_sdk::CircleMembership::Leave)),
            membership_label(Some(arkret_sdk::CircleMembership::Ban)),
            membership_label(None),
            encryption_label(Some(raw)),
            encryption_label(None),
            initial_member_label(raw),
            raw.to_owned(),
        ]
    });
    app.mount(reactive(labels, |_, labels| {
        block("", labels.into_iter().map(plain).collect())
    }))
    .unwrap();
    app.flush().unwrap();
    let english = strings(&app);
    context.locale.revise(|value| *value = UiLocale::Zh);
    app.flush().unwrap();
    let translated = strings(&app);
    assert_ne!(translated, english);
    assert_eq!(translated.last().unwrap(), raw);
    assert!(translated.iter().any(|value| value.contains(raw)));
    context.locale.revise(|value| *value = UiLocale::En);
    app.flush().unwrap();
    assert_eq!(strings(&app), english);
}
#[test]
fn retained_policy_translation_preserves_all_typed_choices_and_membership_targets() {
    use arkret_sdk::{
        CircleDirectoryVisibility as Visibility, CircleJoinRule as Rule, CircleMembership as Member,
    };
    let app = glory::ui::App::memory();
    let context = context(&app);
    let visibility = app.scope().cage(Visibility::Members);
    let rule = app.scope().cage(Rule::Public);
    app.mount(controls::policy_fields(
        app.scope(),
        context.clone(),
        "retained-policy",
        visibility,
        rule,
    ))
    .unwrap();
    app.flush().unwrap();
    for expected_visibility in [Visibility::Members, Visibility::RealmMembers] {
        for expected_rule in [Rule::Public, Rule::Knock, Rule::Invite] {
            visibility.revise(|value| *value = expected_visibility);
            rule.revise(|value| *value = expected_rule);
            app.flush().unwrap();
            let target = controls::self_transition(expected_rule, None).map(|(target, _)| target);
            assert_eq!(
                target,
                match expected_rule {
                    Rule::Public => Some(Member::Join),
                    Rule::Knock => Some(Member::Knock),
                    Rule::Invite => None,
                }
            );
            for locale in [UiLocale::Zh, UiLocale::En] {
                context.locale.revise(|value| *value = locale);
                app.flush().unwrap();
                assert!(visibility.is_alive() && rule.is_alive());
                assert_eq!(visibility.get(), expected_visibility);
                assert_eq!(rule.get(), expected_rule);
                assert_eq!(
                    controls::self_transition(expected_rule, Some(Member::Leave))
                        .map(|(target, _)| target),
                    target
                );
                assert!(controls::self_transition(expected_rule, Some(Member::Ban)).is_none());
                for membership in [Member::Join, Member::Knock] {
                    assert_eq!(
                        controls::self_transition(expected_rule, Some(membership))
                            .map(|(target, _)| target),
                        Some(Member::Leave)
                    );
                }
            }
        }
    }
}
