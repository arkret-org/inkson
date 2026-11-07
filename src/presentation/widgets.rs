//! Product-neutral, owner-scoped semantic UI building blocks.
use std::cell::{Cell, RefCell};
use std::future::Future;
use std::rc::Rc;

use glory::prelude::*;
use glory::ui::Mounted;

use super::context::InksonContext;

pub type View = Box<dyn Widget>;

pub(crate) type WorkspaceHeader = Rc<dyn Fn(&Scope) -> View>;

pub(crate) fn workspace_detail(
    scope: &Scope,
    context: &Rc<InksonContext>,
    header: &WorkspaceHeader,
    class: &str,
    content: View,
) -> View {
    workspace_pane(
        scope,
        context,
        true,
        Box::new(view().class("workspace-detail-column").fill(vec![
            header(scope),
            Box::new(view().class(format!("workspace-detail-content {class}")).fill(content)),
        ])),
    )
}

pub(crate) fn workspace_pane(
    scope: &Scope,
    context: &Rc<InksonContext>,
    detail: bool,
    content: View,
) -> View {
    let navigation = context.workspace_navigation.clone();
    let visible = scope.bond(move || navigation.pane_visible(detail));
    Box::new(
        view()
            .class(scope.bond(move || {
                format!(
                    "workspace-pane workspace-pane-{}{}",
                    if detail { "detail" } else { "list" },
                    if visible.get() {
                        " is-visible"
                    } else {
                        " is-hidden"
                    }
                )
            }))
            .semantics(scope.bond(move || {
                Some(Box::new(glory::render::Semantics {
                    hidden: !visible.get(),
                    ..Default::default()
                }))
            }))
            .fill(content),
    )
}

pub(crate) fn navigation_heading(
    scope: &Scope,
    context: Rc<InksonContext>,
    key: &'static str,
    title: View,
    label: &'static str,
    query: Cage<String>,
    mut actions: Vec<View>,
) -> View {
    let input_label = context.translated(scope, label);
    let open = scope.cage(!query.get_untracked().is_empty());
    let focus_requested = scope.cage(false);
    let input_reference = scope.cage(None::<glory::render::NodeId>);
    let trigger_reference = scope.cage(None::<glory::render::NodeId>);
    let focus_scope = scope.downgrade();
    let focus_context = context.clone();
    scope.effect(move || {
        if !focus_requested.get() {
            return;
        }
        let Some(input) = input_reference.get() else {
            return;
        };
        focus_requested.revise(|value| *value = false);
        if focus_context.workspace_navigation.pane_visible(false)
            && let Some(scope) = focus_scope.upgrade()
        {
            focus_navigation_node(&scope, Some(input));
        }
    });
    let dismiss_scope = scope.downgrade();
    let count = actions.len() + 1;
    let mut children = vec![
        title,
        Box::new(
            sapid::collapsible(key)
                .unstyled()
                .class("workspace-search-disclosure")
                .label(input_label)
                .open(open)
                .trigger_ref(trigger_reference)
                .trigger_content(|| crate::components::ui_icon("search"))
                .on_open_change(move |next| {
                    open.revise(|value| *value = next);
                    focus_requested.revise(|value| *value = next);
                    if !next {
                        query.revise(|value| value.clear());
                    }
                })
                .content(move || {
                    sapid::text_field()
                        .unstyled()
                        .class("input workspace-search-input workspace-navigation-search-input")
                        .name(input_label)
                        .placeholder(input_label)
                        .value(query)
                        .node_ref(input_reference)
                        .on(glory::render::EventKind::Keyboard, {
                            let dismiss_scope = dismiss_scope.clone();
                            move |event| {
                                if matches!(
                                    event,
                                    glory::render::Event::Keyboard {
                                        command: glory::render::KeyboardCommand::Dismiss,
                                        ..
                                    }
                                ) && open.get_untracked()
                                {
                                    focus_requested.revise(|value| *value = false);
                                    query.revise(|value| value.clear());
                                    open.revise(|value| *value = false);
                                    if let Some(scope) = dismiss_scope.upgrade() {
                                        focus_navigation_node(
                                            &scope,
                                            trigger_reference.get_untracked(),
                                        );
                                    }
                                }
                            }
                        })
                        .on_value_change(move |next| query.revise(|value| *value = next))
                }),
        ) as View,
    ];
    children.append(&mut actions);
    Box::new(view().class(format!("workspace-list-heading workspace-navigation-heading workspace-navigation-heading-{count}")).fill(children))
}

fn focus_navigation_node(scope: &Scope, node: Option<glory::render::NodeId>) {
    let result = (|| -> glory::ui::Result {
        if scope.capabilities()?.focus
            && let Some(node) = node
            && scope.is_active(node)?
        {
            match scope.action(glory::render::Action::Focus(node)) {
                Ok(()) | Err(glory::ui::Error::Render(glory::render::Error::Unsupported(_))) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        scope.report_error(error);
    }
}

pub(crate) fn workspace_navigation_button(
    _scope: &Scope,
    context: Rc<InksonContext>,
    active: Bond<bool>,
) -> View {
    reactive_distinct(active, move |scope, active| {
        if !active {
            return empty();
        }
        let navigation = context.workspace_navigation.clone();
        let mobile = navigation.layout.mobile();
        let expanded = navigation.list_expanded;
        let label = scope.bond({
            let context = context.clone();
            move || {
                context.tr(if mobile.get() {
                    "workspace.back_to_list"
                } else if expanded.get() {
                    "workspace.collapse_list"
                } else {
                    "workspace.expand_list"
                })
            }
        });
        let icon = reactive_distinct(
            scope.bond(move || (mobile.get(), expanded.get())),
            |_, (mobile, expanded)| {
                crate::components::ui_icon(if mobile {
                    "chevron-left"
                } else if expanded {
                    "panel-left-close"
                } else {
                    "panel-left-open"
                })
            },
        );
        Box::new(
            sapid::button()
                .unstyled()
                .class("btn icon workspace-navigation-button")
                .name(label)
                .pressed(scope.bond(move || !mobile.get() && !expanded.get()))
                .fill(icon)
                .on_press(move || {
                    if mobile.get() {
                        navigation.show_list();
                    } else {
                        expanded.revise(|value| *value = !*value);
                    }
                }),
        ) as View
    })
}

/// Internal routes publish history themselves and retain mounted application state.
pub fn internal_link() -> glory::ui::Link {
    let link = glory::ui::link();
    #[cfg(target_arch = "wasm32")]
    let link = link.backend_options(glory::html::HtmlEventOptions::default().prevent_default(true));
    link
}

pub(crate) fn arkret_logo(class: &str) -> View {
    use base64::Engine as _;
    let source = format!(
        "data:image/png;base64,{}",
        base64::engine::general_purpose::STANDARD
            .encode(include_bytes!("../../assets/arkret-logo-512.png"))
    );
    Box::new(image().class(class.to_owned()).source(source).alt("Arkret"))
}

pub(crate) fn startup_screen(
    title: impl Into<Vary<String>>,
    message: impl Into<Vary<String>>,
) -> View {
    Box::new(
        view()
            .class("arkret-startup")
            .role(glory::render::Role::Status)
            .semantics(Some(Box::new(glory::render::Semantics {
                busy: Some(true),
                ..Default::default()
            })))
            .fill(vec![
                arkret_logo("startup-logo"),
                paragraph("startup-brand", "ARKRET"),
                heading(1, "", title),
                paragraph("startup-message", message),
                Box::new(view().class("startup-spinner")) as View,
            ]),
    )
}

pub fn empty() -> View {
    Box::new(widget(|_| Ok(())))
}

pub fn stack(class: impl Into<String>, children: Vec<View>) -> View {
    let class = class.into();
    Box::new(
        view()
            .class(if class.trim().is_empty() {
                "inkson-stack".to_owned()
            } else {
                class
            })
            .fill(children),
    )
}

pub fn line(class: impl Into<String>, children: Vec<View>) -> View {
    let class = class.into();
    Box::new(
        view()
            .class(if class.trim().is_empty() {
                "inkson-line".to_owned()
            } else {
                class
            })
            .fill(children),
    )
}

pub fn plain(value: impl Into<Vary<String>>) -> View {
    Box::new(text().content(value))
}

pub fn paragraph(class: impl Into<String>, value: impl Into<Vary<String>>) -> View {
    Box::new(
        text()
            .kind(TextKind::Paragraph)
            .class(class.into())
            .content(value),
    )
}

pub fn heading(level: u8, class: impl Into<String>, value: impl Into<Vary<String>>) -> View {
    Box::new(
        text()
            .kind(TextKind::Heading(level))
            .class(class.into())
            .content(value),
    )
}

pub fn panel(
    scope: &Scope,
    context: Rc<InksonContext>,
    title_key: &str,
    children: Vec<View>,
) -> View {
    Box::new(
        sapid::card()
            .unstyled()
            .class("panel")
            .title(context.translated(scope, title_key))
            .fill(stack("panel-content", children)),
    )
}

/// The container owns the replacement position as well as the child lifetime.
pub trait ReactiveSource: 'static {
    type Value: Clone + 'static;
    fn into_lotus(self) -> Vary<Self::Value>;
}
impl<T: Clone + 'static> ReactiveSource for Cage<T> {
    type Value = T;
    fn into_lotus(self) -> Vary<T> {
        self.into()
    }
}
impl<T: Clone + 'static> ReactiveSource for Bond<T> {
    type Value = T;
    fn into_lotus(self) -> Vary<T> {
        self.into()
    }
}
impl<T: Clone + 'static> ReactiveSource for Vary<T> {
    type Value = T;
    fn into_lotus(self) -> Vary<T> {
        self
    }
}

pub fn reactive<S: ReactiveSource>(
    source: S,
    render: impl Fn(&Scope, S::Value) -> View + 'static,
) -> View {
    reactive_checked(source.into_lotus(), None, render)
}

/// Keep a mounted owner when unrelated dependencies yield the same route phase.
pub fn reactive_distinct<S: ReactiveSource>(
    source: S,
    render: impl Fn(&Scope, S::Value) -> View + 'static,
) -> View
where
    S::Value: PartialEq,
{
    reactive_checked(
        source.into_lotus(),
        Some(Rc::new(|left, right| left == right)),
        render,
    )
}

type ReactiveEquality<T> = Rc<dyn Fn(&T, &T) -> bool>;

fn reactive_checked<T: Clone + 'static>(
    source: Vary<T>,
    equal: Option<ReactiveEquality<T>>,
    render: impl Fn(&Scope, T) -> View + 'static,
) -> View {
    let render = Rc::new(render);
    Box::new(group().fill(widget(move |scope| {
        let mounted = Rc::new(RefCell::new(None::<Mounted>));
        let previous = Rc::new(RefCell::new(None::<T>));
        scope.retain(mounted.clone())?;
        let weak = scope.downgrade();
        let render = render.clone();
        let source = source.clone();
        let equal = equal.clone();
        scope.effect(move || {
            let value = source.get();
            if equal.as_ref().is_some_and(|equal| {
                previous
                    .borrow()
                    .as_ref()
                    .is_some_and(|previous| equal(previous, &value))
            }) {
                return;
            }
            *previous.borrow_mut() = Some(value.clone());
            let Some(parent) = weak.upgrade() else { return };
            mounted.borrow_mut().take();
            let render = render.clone();
            match parent
                .mount_with(|| widget(move |child| render(child, value.clone()).build(child)))
            {
                Ok(next) => *mounted.borrow_mut() = Some(next),
                Err(error) => parent.report_error(error),
            }
        });
        Ok(())
    })))
}

pub struct Resource<T: Clone + 'static> {
    pub data: Cage<Option<std::result::Result<T, String>>>,
    revision: Cage<u64>,
}

impl<T: Clone + 'static> Clone for Resource<T> {
    fn clone(&self) -> Self {
        Self {
            data: self.data,
            revision: self.revision,
        }
    }
}

impl<T: Clone + 'static> Resource<T> {
    pub fn reload(&self) {
        self.revision
            .revise(|revision| *revision = revision.wrapping_add(1));
    }
}

/// Capture request dependencies synchronously in loader, before creating its future.
pub fn resource<T, F, Fut>(scope: &Scope, loader: F) -> Resource<T>
where
    T: Clone + 'static,
    F: Fn() -> Fut + 'static,
    Fut: Future<Output = std::result::Result<T, String>> + 'static,
{
    let data = scope.cage(None);
    let revision = scope.cage(0_u64);
    let generation = Rc::new(Cell::new(0_u64));
    let active = Rc::new(RefCell::new(None::<glory::core::TaskToken>));
    let weak = scope.downgrade();
    scope.effect(move || {
        let _ = revision.get();
        if let Some(task) = active.borrow_mut().take() {
            task.cancel();
        }
        let Some(scope) = weak.upgrade() else { return };
        let serial = generation.get().wrapping_add(1);
        generation.set(serial);
        data.revise(|value| *value = None);
        let future = loader();
        let generation = generation.clone();
        let owner = scope.downgrade();
        match scope.owner().spawn(async move {
            let result = future.await;
            if owner.upgrade().is_some() && generation.get() == serial {
                data.revise(|value| *value = Some(result));
            }
        }) {
            Ok(task) => *active.borrow_mut() = Some(task),
            Err(error) => data.revise(|value| *value = Some(Err(error.to_string()))),
        }
    });
    Resource { data, revision }
}

pub fn resource_content<T: Clone + 'static>(
    context: Rc<InksonContext>,
    key: impl Into<String>,
    source: Resource<T>,
    loading_key: impl Into<String>,
    render: impl Fn(&Scope, T) -> View + 'static,
) -> View {
    let key = key.into();
    let loading_key = loading_key.into();
    reactive(source.data, move |scope, value| match value {
        None => paragraph(
            "loading-state",
            context.translated(scope, loading_key.clone()),
        ),
        Some(Ok(value)) => render(scope, value),
        Some(Err(error)) => {
            let reload = source.clone();
            stack(
                "resource-error",
                vec![
                    Box::new(
                        sapid::alert(format!("{key}-error"))
                            .unstyled()
                            .class("alert alert-error")
                            .severity(sapid::AlertSeverity::Danger)
                            .content(error),
                    ) as View,
                    Box::new(
                        sapid::button()
                            .unstyled()
                            .class("btn btn-secondary")
                            .variant(sapid::ButtonVariant::Secondary)
                            .label(context.translated(scope, "common.retry"))
                            .on_press(move || reload.reload()),
                    ) as View,
                ],
            )
        }
    })
}

pub fn input_field(
    _context: Rc<InksonContext>,
    key: impl Into<String>,
    label: impl Into<Vary<String>>,
    value: Cage<String>,
    purpose: Purpose,
) -> View {
    Box::new(
        sapid::field(key.into())
            .unstyled()
            .label(label)
            .control(move |field| -> View {
                if purpose == Purpose::Password {
                    Box::new(
                        sapid::password_input()
                            .field(field)
                            .value(value)
                            .on_value_change(move |next| value.revise(|value| *value = next)),
                    )
                } else {
                    Box::new(
                        sapid::text_field()
                            .field(field)
                            .value(value)
                            .purpose(purpose)
                            .on_value_change(move |next| value.revise(|value| *value = next)),
                    )
                }
            }),
    )
}

/// Keys describe distinct table instances, never just a shared column label.
pub fn table(
    _context: Rc<InksonContext>,
    key: impl Into<String>,
    headers: Vec<Vary<String>>,
    rows: Vec<Vec<View>>,
) -> View {
    let head = sapid::table_head().row(sapid::table_row("head").cells(
        headers.into_iter().enumerate().map(|(column, label)| {
            sapid::table_header_cell(format!("column-{column}")).text(label)
        }),
    ));
    let body = sapid::table_body().rows(rows.into_iter().enumerate().map(|(row, cells)| {
        sapid::table_row(format!("row-{row}")).cells(cells.into_iter().enumerate().map(
            |(column, view)| {
                let mut view = Some(view);
                sapid::table_cell(format!("column-{column}"))
                    .content(move || view.take().unwrap_or_else(|| empty()))
            },
        ))
    }));
    Box::new(
        view()
            .class("table-scroll")
            .style(
                Style::new()
                    .min_width(Length::Px(0.0))
                    .overflow_x(Overflow::Auto),
            )
            .fill(
                sapid::table(key.into())
                    .unstyled()
                    .class("data-table")
                    .head(head)
                    .body(body),
            ),
    )
}

#[cfg(test)]
#[path = "widgets/group_tests.rs"]
mod group_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrelated_phase_updates_retain_the_mounted_form_and_its_draft() {
        let app = glory::ui::App::memory();
        let scope = app.scope();
        let language = scope.cage("en".to_owned());
        let signed_in = scope.cage(false);
        let phase = scope.bond(move || {
            let _ = language.get();
            signed_in.get()
        });
        let mounts = Rc::new(Cell::new(0));
        let observed = mounts.clone();
        let draft = Rc::new(RefCell::new(None::<Cage<String>>));
        let retained = draft.clone();
        app.mount(reactive_distinct(phase, move |scope, _| {
            observed.set(observed.get() + 1);
            let value = scope.cage(String::new());
            *retained.borrow_mut() = Some(value);
            Box::new(sapid::text_field().value(value))
        }))
        .unwrap();
        let editor = draft.borrow().expect("mounted editor");
        editor.revise(|value| *value = "unsaved message".into());
        language.revise(|value| *value = "zh".into());
        app.flush().unwrap();
        assert_eq!(mounts.get(), 1);
        assert_eq!(editor.get(), "unsaved message");
        signed_in.revise(|value| *value = true);
        app.flush().unwrap();
        assert_eq!(mounts.get(), 2);
        assert!(!editor.is_alive());
    }
}
