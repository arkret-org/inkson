use glory::ui::{Widget, text};
use glory::{Bond, Cage};

use super::*;

pub(super) struct InputField {
    pub key: &'static str,
    pub label: &'static str,
    pub prompt: &'static str,
    pub value: Cage<String>,
    pub multiline: bool,
    pub required: bool,
    pub span_two: bool,
}

pub(super) fn input_field(
    scope: &Scope,
    context: Rc<InksonContext>,
    props: InputField,
    enabled: Bond<bool>,
) -> View {
    let value = props.value;
    let prompt = context.translated(scope, props.prompt);
    Box::new(
        sapid::field(props.key)
            .unstyled()
            .class(format!(
                "setup-field {}{}",
                props.key,
                if props.span_two {
                    " setup-field-span-2"
                } else {
                    ""
                }
            ))
            .label(context.translated(scope, props.label))
            .required(props.required)
            .enabled(enabled)
            .control(move |field| {
                glory::ui::widget(move |scope| {
                    input_prompt(
                        scope,
                        prompt.into(),
                        value,
                        Box::new(
                            sapid::text_field()
                                .unstyled()
                                .class("input")
                                .field(field.clone())
                                .value(value)
                                .multiline(props.multiline)
                                .enabled(enabled)
                                .on_value_change(move |next| value.revise(|value| *value = next)),
                        ),
                    )
                    .build(scope)
                })
            }),
    )
}

type AxisOption = (&'static str, &'static str, &'static str);

#[derive(Clone)]
pub(super) struct Axis {
    pub key: &'static str,
    pub label: &'static str,
    pub value: Cage<String>,
    pub options: Vec<AxisOption>,
    pub dependency: Option<Cage<String>>,
    pub enabled: Bond<bool>,
}

fn choose_axis(scope: &Scope, context: Rc<InksonContext>, props: &Axis, forbid_open: bool) -> View {
    let value = props.value;
    let label = context.translated(scope, props.label);
    let dependency = props.dependency;
    let options = props.options.clone();
    let publish = move |next: Option<String>| {
        let Some(next) = next else { return };
        if !options.iter().any(|option| option.0 == next)
            || next == "open"
                && dependency.is_some_and(|value| value.get_untracked() == "high_assurance")
        {
            return;
        }
        value.revise(|value| *value = next);
    };
    let selected = scope.bond(move || Some(value.get()));
    #[cfg(target_arch = "wasm32")]
    {
        Box::new(
            sapid::select(format!("{}-options", props.key))
                .unstyled()
                .class(format!("select {}", props.key))
                .name(label)
                .value(selected)
                .enabled(props.enabled)
                .options(props.options.iter().map(|(wire, text, _)| {
                    sapid::select_option(*wire, context.tr(text))
                        .disabled(forbid_open && *wire == "open")
                }))
                .on_value_change(publish),
        )
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use crate::presentation::native_choice::{
            NativeChoiceOption, NativeChoiceProps, native_choice,
        };
        native_choice(
            scope,
            NativeChoiceProps::new(
                props.key,
                label,
                selected,
                props
                    .options
                    .iter()
                    .map(|(wire, text, _)| {
                        NativeChoiceOption::new(*wire, context.tr(text))
                            .enabled(!(forbid_open && *wire == "open"))
                    })
                    .collect(),
                publish,
            )
            .enabled(props.enabled)
            .class(format!("select {}", props.key))
            .close_label(context.translated(scope, "common.close")),
        )
    }
}

pub(super) fn axis(scope: &Scope, context: Rc<InksonContext>, props: Axis) -> View {
    let value = props.value;
    let dependency = props.dependency;
    let locale = context.locale;
    let help_context = context.clone();
    let help_props = props.clone();
    let help = crate::presentation::widgets::reactive_distinct(
        scope.bond(move || {
            (
                value.get(),
                dependency.map(|value| value.get()),
                locale.get(),
            )
        }),
        move |scope, (selected, dependency, _)| {
            let mut parts = vec![
                help_context.tr(&format!("{}.question", help_props.label)),
                option_hint(
                    &help_props.options,
                    &selected,
                    &format!("{}.unset", help_props.label),
                ),
            ];
            if help_props.key == "realm-mls-activation-input" {
                parts.push(help_context.tr("setup.axis.mls_activation.separate"));
            }
            if help_props.key == "realm-federation-policy-input"
                && dependency.as_deref() == Some("high_assurance")
            {
                parts.push(help_context.tr("setup.axis.federation_policy.high_assurance"));
            }
            line(
                "setup-axis-card-heading",
                vec![
                    Box::new(
                        text()
                            .class("setup-axis-title")
                            .content(help_context.translated(scope, help_props.label)),
                    ) as View,
                    crate::components::help_tip(
                        scope,
                        help_context.clone(),
                        crate::components::HelpTipProps {
                            text: parts.join(" "),
                        },
                    ),
                ],
            )
        },
    );
    let control_context = context.clone();
    let control_props = props.clone();
    let control = crate::presentation::widgets::reactive_distinct(
        scope.bond(move || {
            (
                dependency.is_some_and(|value| value.get() == "high_assurance"),
                locale.get(),
            )
        }),
        move |scope, (forbid_open, _)| {
            choose_axis(scope, control_context.clone(), &control_props, forbid_open)
        },
    );
    let mut field = vec![control];
    if props.key == "realm-mls-activation-input"
        && let Some(history) = dependency
    {
        let warning_context = context.clone();
        field.push(crate::presentation::widgets::reactive_distinct(
            scope.bond(move || {
                mls_activation_history_hint(mls_activation_requested(&value.get()), &history.get())
            }),
            move |scope, hint| match hint {
                Some(hint) => stack(
                    "inline-warn",
                    vec![paragraph("body", warning_context.translated(scope, hint))],
                ),
                None => empty(),
            },
        ));
    }
    stack(
        "metric directory-axis-card setup-axis-card",
        vec![help, stack("workflow-form setup-field", field)],
    )
}

pub(super) fn bootstrap_status(
    scope: &Scope,
    context: Rc<InksonContext>,
    state: Cage<String>,
) -> View {
    stack(
        "setup-summary-list realm-create-status",
        vec![stack(
            "setup-summary-row setup-summary-row-stack",
            vec![
                Box::new(
                    text()
                        .class("setup-summary-label")
                        .content(context.translated(scope, "setup.state.bootstrap")),
                ) as View,
                paragraph("muted", state),
            ],
        )],
    )
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use glory::render::{Event, NodeId, Props};

    use super::*;

    fn harness() -> (glory::App, Rc<InksonContext>, tempfile::TempDir) {
        let app = glory::App::memory();
        let directory = tempfile::tempdir().unwrap();
        let context = InksonContext::new(
            app.scope(),
            crate::presentation::BootState {
                config_store: crate::config::LocalConfigStore::with_path(
                    directory.path().join("config.json"),
                ),
                config: crate::config::ClientConfig::default(),
                state_store: crate::presentation::SharedStateStore::new(
                    crate::state::LocalStateStore::with_path(directory.path().join("state.json")),
                ),
                initial_credential: String::new(),
                realm_tree_nodes: vec![],
            },
            Route::SetupSection {
                section: "realms".into(),
            },
            |_| Box::pin(std::future::pending()),
        );
        context
            .locale
            .revise(|locale| *locale = crate::i18n::UiLocale::En);
        (app, context, directory)
    }
    fn nodes(app: &glory::App) -> Vec<NodeId> {
        let tree = app.tree();
        let mut pending = tree.roots().to_vec();
        pending.reverse();
        let mut nodes = vec![];
        while let Some(id) = pending.pop() {
            nodes.push(id);
            let mut children = tree
                .node(id)
                .unwrap()
                .children
                .iter()
                .copied()
                .collect::<Vec<_>>();
            children.reverse();
            pending.extend(children);
        }
        nodes
    }
    fn class(app: &glory::App, class: &str) -> NodeId {
        nodes(app)
            .into_iter()
            .find(|id| {
                app.tree()
                    .node(*id)
                    .unwrap()
                    .descriptor
                    .view()
                    .classes
                    .iter()
                    .any(|value| value == class)
            })
            .unwrap()
    }

    #[test]
    fn production_title_is_required_and_the_boundary_keeps_its_advanced_options_folded() {
        let (app, context, _directory) = harness();
        let draft = super::super::super::SetupDraft::for_context(app.scope(), &context);
        app.mount(super::super::page(app.scope(), context, draft))
            .unwrap();
        app.flush().unwrap();
        let field = class(&app, "realm-title-input");
        let mut pending = vec![field];
        let input = loop {
            let id = pending.pop().unwrap();
            let tree = app.tree();
            let node = tree.node(id).unwrap();
            if matches!(node.descriptor.view().props, Props::Input(_)) {
                break id;
            }
            pending.extend(node.children.iter().copied());
        };
        let revision = {
            let tree = app.tree();
            let descriptor = tree.node(input).unwrap().descriptor.view();
            assert!(descriptor.semantics.as_ref().unwrap().required);
            assert!(descriptor.semantics.as_ref().unwrap().labelled_by.is_some());
            match descriptor.props {
                Props::Input(value) => value.revision,
                _ => unreachable!(),
            }
        };
        app.dispatch(
            input,
            Event::ValueChanged {
                value: "Realm 标题原文".into(),
                composing: false,
                revision,
            },
        )
        .unwrap();
        app.flush().unwrap();
        app.dispatch(class(&app, "new-realm-next-button"), Event::Activate)
            .unwrap();
        app.flush().unwrap();
        assert_eq!(draft.create_step.get_untracked(), NewRealmStep::Boundary);
        assert_eq!(
            nodes(&app)
                .into_iter()
                .filter(|id| app
                    .tree()
                    .node(*id)
                    .unwrap()
                    .descriptor
                    .view()
                    .classes
                    .iter()
                    .any(|value| value == "setup-axis-card"))
                .count(),
            7
        );
        assert!(!nodes(&app).into_iter().any(|id| matches!(
            app.tree().node(id).unwrap().descriptor.view().props,
            Props::Select(_)
        )));
        let trigger = class(&app, "sapid-collapsible-trigger");
        assert_eq!(
            app.tree()
                .node(trigger)
                .unwrap()
                .descriptor
                .view()
                .semantics
                .as_ref()
                .unwrap()
                .expanded,
            Some(false)
        );
        app.dispatch(trigger, Event::Activate).unwrap();
        app.flush().unwrap();
        assert_eq!(
            app.tree()
                .node(trigger)
                .unwrap()
                .descriptor
                .view()
                .semantics
                .as_ref()
                .unwrap()
                .expanded,
            Some(true)
        );
        class(&app, "realm-federation-policy-input");
        class(&app, "realm-hash-profile-input");
        assert_eq!(draft.realm_title.get_untracked(), "Realm 标题原文");
    }

    #[test]
    fn high_assurance_federation_open_stays_disabled_in_the_real_native_choice() {
        let (app, context, _directory) = harness();
        let draft = super::super::super::SetupDraft::for_context(app.scope(), &context);
        draft
            .create_step
            .revise(|step| *step = NewRealmStep::Boundary);
        draft
            .realm_security_class
            .revise(|value| *value = "high_assurance".into());
        app.mount(super::super::page(app.scope(), context, draft))
            .unwrap();
        app.flush().unwrap();
        app.dispatch(class(&app, "sapid-collapsible-trigger"), Event::Activate)
            .unwrap();
        app.flush().unwrap();
        app.dispatch(
            class(&app, "realm-federation-policy-input"),
            Event::Activate,
        )
        .unwrap();
        app.flush().unwrap();
        let open = nodes(&app).into_iter().find(|id| matches!(app.tree().node(*id).unwrap().descriptor.view().props, Props::Button(value) if value.label == "Open")).unwrap();
        assert!(
            matches!(app.tree().node(open).unwrap().descriptor.view().props, Props::Button(value) if !value.enabled)
        );
        let _ = app.dispatch(open, Event::Activate).unwrap();
        app.flush().unwrap();
        assert_eq!(draft.realm_federation_policy.get_untracked(), "restricted");
    }

    #[test]
    fn original_step_navigation_allows_blank_title_review_but_create_submission_stays_disabled() {
        let (app, context, _directory) = harness();
        context
            .token
            .revise(|token| *token = "fixture-session".into());
        context
            .secure_store_bootstrap_ready
            .revise(|ready| *ready = true);
        let draft = super::super::super::SetupDraft::for_context(app.scope(), &context);
        app.mount(super::super::page(app.scope(), context, draft))
            .unwrap();
        app.flush().unwrap();
        let steps = || {
            nodes(&app)
                .into_iter()
                .filter(|id| {
                    app.tree()
                        .node(*id)
                        .unwrap()
                        .descriptor
                        .view()
                        .classes
                        .iter()
                        .any(|class| class == "setup-step")
                })
                .collect::<Vec<_>>()
        };
        let initial = steps();
        assert_eq!(initial.len(), 4);
        for id in &initial[..3] {
            assert!(
                matches!(app.tree().node(*id).unwrap().descriptor.view().props, Props::Button(value) if value.enabled)
            );
        }
        assert!(
            matches!(app.tree().node(initial[3]).unwrap().descriptor.view().props, Props::Button(value) if !value.enabled)
        );
        app.dispatch(initial[1], Event::Activate).unwrap();
        app.flush().unwrap();
        assert_eq!(draft.create_step.get_untracked(), NewRealmStep::Boundary);
        assert!(draft.realm_title.get_untracked().is_empty());
        let create_step = steps()[2];
        app.dispatch(create_step, Event::Activate).unwrap();
        app.flush().unwrap();
        assert_eq!(draft.create_step.get_untracked(), NewRealmStep::Create);
        let submit = class(&app, "create-realm-button");
        assert!(
            matches!(app.tree().node(submit).unwrap().descriptor.view().props, Props::Button(value) if !value.enabled)
        );
        app.dispatch(submit, Event::Activate).unwrap();
        app.flush().unwrap();
        assert!(draft.realm_title.get_untracked().is_empty());
        assert!(draft.created_realm_id.get_untracked().is_empty());
        assert!(!draft.realm_create_busy.get_untracked());
        assert_eq!(draft.create_step.get_untracked(), NewRealmStep::Create);
    }
}
