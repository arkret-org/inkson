//! One finite action menu shared by real timeline rows and host conformance fixtures.
use std::cell::{Cell, RefCell};

use glory::render::EventKind;

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageMenuAction {
    Reply,
    React,
    Edit,
    SharedPin,
    PrivateSave,
    Report,
    Redact,
}
impl MessageMenuAction {
    fn key(self) -> &'static str {
        match self {
            Self::Reply => "reply",
            Self::React => "react",
            Self::Edit => "edit",
            Self::SharedPin => "shared-pin",
            Self::PrivateSave => "private-save",
            Self::Report => "report",
            Self::Redact => "redact",
        }
    }
    fn class(self) -> &'static str {
        match self {
            Self::Reply => "message-context-reply-button",
            Self::React => "message-context-react-button",
            Self::Edit => "message-context-edit-button",
            Self::SharedPin => "message-shared-pin-button",
            Self::PrivateSave => "message-private-save-button",
            Self::Report => "danger message-context-report-button",
            Self::Redact => "danger message-context-redact-button",
        }
    }
}
#[derive(Clone)]
pub struct MessageMenuEntry {
    pub action: MessageMenuAction,
    pub label: Lotus<String>,
    pub enabled: Lotus<bool>,
}
pub struct MessageActionsMenuProps {
    pub key: String,
    pub label: Lotus<String>,
    pub open: Cage<bool>,
    pub entries: Vec<MessageMenuEntry>,
    pub on_open_change: Rc<dyn Fn(bool)>,
    pub on_action: Rc<dyn Fn(MessageMenuAction)>,
    pub boundary: Option<MessageMenuBoundary>,
}
#[derive(Clone, Copy)]
pub struct MessageMenuBoundary {
    pub node: Cage<Option<glory::render::NodeId>>,
    pub revision: Cage<u64>,
}
#[cfg(target_arch = "wasm32")]
pub(super) fn menu_items(
    entries: Vec<MessageMenuEntry>,
    on_action: Rc<dyn Fn(MessageMenuAction)>,
) -> Vec<sapid::MenuItem> {
    entries
        .into_iter()
        .map(|entry| {
            let action = entry.action;
            let invoke_action = on_action.clone();
            sapid::menu_item(action.key())
                .unstyled()
                .class(format!("message-context-menu-item {}", action.class()))
                .label(entry.label)
                .enabled(entry.enabled)
                .on_activate(move || invoke_action(action))
        })
        .collect()
}
struct ActionMenu {
    open: Cage<bool>,
    changed: Rc<dyn Fn(bool)>,
    collection: sapid::Collection,
    roving: sapid::RovingFocus,
    search: RefCell<sapid::Typeahead>,
    panel: Cage<Option<glory::render::NodeId>>,
    trigger: Cage<Option<glory::render::NodeId>>,
    boundary: Option<MessageMenuBoundary>,
    side: Cage<glory::render::AnchorSide>,
    max_height: Cage<Option<f64>>,
    measurement_revision: Cell<u64>,
    queries: RefCell<Vec<glory::render::QueryToken>>,
    measurement_task: RefCell<Option<glory::core::TaskToken>>,
    scroll_task: RefCell<Option<glory::core::TaskToken>>,
}

#[derive(Default)]
struct MenuMeasurement {
    feed: Option<glory::render::Rect>,
    trigger: Option<glory::render::Rect>,
    panel: Option<glory::render::Rect>,
    metrics: Option<glory::render::ScrollMetrics>,
}

impl ActionMenu {
    fn request(&self, next: bool) -> glory::ui::Result {
        if self.open.try_get()? != next {
            self.open.try_revise(|open| *open = next)?;
            (self.changed)(next);
        }
        if !next {
            if let Some(task) = self.scroll_task.take() {
                task.cancel();
            }
            self.measurement_revision
                .set(self.measurement_revision.get().wrapping_add(1));
            self.search.borrow_mut().clear();
            if self.max_height.get_untracked().is_some() {
                self.max_height.revise(|value| *value = None);
            }
            if self.side.get_untracked() != glory::render::AnchorSide::Bottom {
                self.side
                    .revise(|value| *value = glory::render::AnchorSide::Bottom);
            }
        }
        Ok(())
    }

    fn schedule_measure(self: &Rc<Self>, scope: &Scope) -> glory::ui::Result {
        let revision = self.measurement_revision.get().wrapping_add(1);
        self.measurement_revision.set(revision);
        if let Some(task) = self.measurement_task.take() {
            task.cancel();
        }
        for query in self.queries.take() {
            scope.cancel_request(query)?;
        }
        if self.boundary.is_none() || !self.open.get_untracked() || !scope.capabilities()?.measure {
            return Ok(());
        }
        let live = self.clone();
        let weak = scope.downgrade();
        let task = scope.spawn(async move {
            crate::runtime_helpers::sleep_for(std::time::Duration::ZERO).await;
            let Some(scope) = weak.upgrade() else { return };
            if live.measurement_revision.get() != revision || !live.open.get_untracked() {
                return;
            }
            if let Err(error) = live.measure(&scope) {
                scope.report_error(error);
            }
        })?;
        *self.measurement_task.borrow_mut() = Some(task);
        Ok(())
    }

    fn measure(self: &Rc<Self>, scope: &Scope) -> glory::ui::Result {
        use glory::render::{Query, QueryValue};
        let Some(boundary) = self.boundary else {
            return Ok(());
        };
        let revision = self.measurement_revision.get().wrapping_add(1);
        self.measurement_revision.set(revision);
        for query in self.queries.take() {
            scope.cancel_request(query)?;
        }
        if !self.open.try_get()? || !scope.capabilities()?.measure {
            return Ok(());
        }
        let (Some(feed), Some(trigger), Some(panel)) = (
            boundary.node.try_get()?,
            self.trigger.try_get()?,
            self.panel.try_get()?,
        ) else {
            return Ok(());
        };
        let measurement = Rc::new(RefCell::new(MenuMeasurement::default()));
        for (part, query) in [
            Query::Bounds(feed),
            Query::Bounds(trigger),
            Query::Bounds(panel),
            Query::ScrollMetrics(panel),
        ]
        .into_iter()
        .enumerate()
        {
            let live = self.clone();
            let observed = measurement.clone();
            let weak = scope.downgrade();
            let token = scope.request(query, move |result| {
                let Some(scope) = weak.upgrade() else { return };
                if live.measurement_revision.get() != revision || !live.open.get_untracked() {
                    return;
                }
                let result = (|| -> glory::ui::Result {
                    let mut observed = observed.borrow_mut();
                    match (part, result?) {
                        (0, QueryValue::Bounds(value)) => observed.feed = Some(value),
                        (1, QueryValue::Bounds(value)) => observed.trigger = Some(value),
                        (2, QueryValue::Bounds(value)) => observed.panel = Some(value),
                        (3, QueryValue::ScrollMetrics(value)) => observed.metrics = Some(value),
                        _ => {
                            return Err(glory::render::Error::InvalidProps(
                                "invalid menu geometry observation",
                            )
                            .into());
                        }
                    }
                    if let (Some(feed), Some(trigger), Some(panel), Some(metrics)) = (
                        observed.feed,
                        observed.trigger,
                        observed.panel,
                        observed.metrics,
                    ) {
                        live.apply_measurement(feed, trigger, panel, metrics)?;
                    }
                    Ok(())
                })();
                if let Err(error) = result {
                    scope.report_error(error);
                }
            })?;
            self.queries.borrow_mut().push(token);
        }
        Ok(())
    }

    fn apply_measurement(
        &self,
        feed: glory::render::Rect,
        trigger: glory::render::Rect,
        panel: glory::render::Rect,
        metrics: glory::render::ScrollMetrics,
    ) -> glory::ui::Result {
        use glory::render::AnchorSide;
        if trigger.x + trigger.width <= feed.x
            || trigger.x >= feed.x + feed.width
            || trigger.y + trigger.height <= feed.y
            || trigger.y >= feed.y + feed.height
        {
            return self.request(false);
        }
        let below = (feed.y + feed.height - 8.0 - trigger.y - trigger.height - 6.0).max(0.0);
        let above = (trigger.y - 6.0 - feed.y - 8.0).max(0.0);
        let natural_height =
            metrics.content_height + (panel.height - metrics.viewport_height).max(0.0);
        let (side, available) = if natural_height <= below || below >= above {
            (AnchorSide::Bottom, below)
        } else {
            (AnchorSide::Top, above)
        };
        if self.side.get_untracked() != side {
            self.side.revise(|value| *value = side);
        }
        if self.max_height.get_untracked() != Some(available) {
            self.max_height.revise(|value| *value = Some(available));
        }
        Ok(())
    }

    fn focus(self: &Rc<Self>, scope: &Scope, item: sapid::MountedItem) -> glory::ui::Result {
        self.roving.accept(&item)?;
        if scope.capabilities()?.focus {
            scope.action(glory::render::Action::Focus(item.node))?;
        }
        if let Some(task) = self.scroll_task.take() {
            task.cancel();
        }
        if scope.capabilities()?.scroll {
            let weak = scope.downgrade();
            let menu = self.clone();
            let member = item.member;
            let node = item.node;
            *self.scroll_task.borrow_mut() = Some(scope.spawn(async move {
                crate::runtime_helpers::sleep_for(std::time::Duration::ZERO).await;
                let Some(scope) = weak.upgrade() else { return };
                let reveal = || -> glory::ui::Result {
                    if menu.open.try_get()?
                        && menu.roving.current()?.as_ref() == Some(&member)
                        && scope.is_active(node)?
                        && scope.is_enabled(node)?
                    {
                        scope.action(glory::render::Action::ScrollIntoView(node))?;
                    }
                    Ok(())
                };
                if let Err(error) = reveal() {
                    scope.report_error(error);
                }
            })?);
        }
        Ok(())
    }

    fn boundary(self: &Rc<Self>, scope: &Scope, last: bool) -> glory::ui::Result {
        let items = self.collection.mounted()?;
        let item = if last {
            items.into_iter().rev().find(|item| item.enabled)
        } else {
            items.into_iter().find(|item| item.enabled)
        };
        if let Some(item) = item {
            self.focus(scope, item)?;
        }
        Ok(())
    }

    fn origin(&self, from: glory::render::NodeId) -> glory::ui::Result<glory::render::NodeId> {
        let items = self.collection.mounted()?;
        if items.iter().any(|item| item.node == from) {
            return Ok(from);
        }
        let current = self.roving.current()?;
        Ok(items
            .iter()
            .find(|item| Some(&item.member) == current.as_ref() && item.enabled)
            .or_else(|| items.iter().find(|item| item.enabled))
            .map_or(from, |item| item.node))
    }

    fn event(self: &Rc<Self>, scope: &Scope, event: Event) -> glory::ui::Result {
        use glory::render::MenuCommand;
        match event {
            Event::Dismiss(_) => self.request(false)?,
            Event::Menu { command, .. } => match command {
                MenuCommand::First | MenuCommand::Last => {
                    self.request(true)?;
                    self.boundary(scope, command == MenuCommand::Last)?;
                }
                MenuCommand::Close => self.request(false)?,
                MenuCommand::Exit { backwards } => {
                    self.request(false)?;
                    if scope.capabilities()?.focus
                        && let Some(node) = self.panel.try_get()?
                    {
                        scope.action(glory::render::Action::ExitMenu { node, backwards })?;
                    }
                }
                _ => {}
            },
            Event::Navigate { from, command } if self.open.try_get()? => {
                self.search.borrow_mut().clear();
                if let Some(item) = self.roving.destination(self.origin(from)?, command)? {
                    self.focus(scope, item)?;
                }
            }
            Event::Typeahead {
                from,
                text,
                at_millis,
            } if self.open.try_get()? => {
                let item = self.search.borrow_mut().search(
                    &self.collection,
                    self.origin(from)?,
                    &text,
                    at_millis,
                )?;
                if let Some(item) = item {
                    self.focus(scope, item)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// The finite timeline menu uses public layer placement and Sapid navigation.
pub(super) type MenuContent = Rc<dyn Fn(&Scope) -> View>;

pub(super) struct FiniteMenuEntry {
    pub key: String,
    pub class: Lotus<String>,
    pub label: Lotus<String>,
    pub enabled: Lotus<bool>,
    pub content: Option<MenuContent>,
    pub on_activate: Rc<dyn Fn()>,
}
pub(super) struct FiniteMenuProps {
    pub key: String,
    pub label: Lotus<String>,
    pub enabled: Lotus<bool>,
    pub open: Cage<bool>,
    pub entries: Vec<FiniteMenuEntry>,
    pub on_open_change: Rc<dyn Fn(bool)>,
    pub boundary: Option<MessageMenuBoundary>,
    pub wrapper_class: &'static str,
    pub trigger_class: &'static str,
    pub panel_class: &'static str,
    pub trigger_content: MenuContent,
    pub gap: f64,
}

pub fn message_actions_menu(_scope: &Scope, props: MessageActionsMenuProps) -> View {
    let entries = props
        .entries
        .into_iter()
        .map(|entry| {
            let action = entry.action;
            let invoke = props.on_action.clone();
            FiniteMenuEntry {
                key: action.key().into(),
                class: format!("message-context-menu-item {}", action.class()).into(),
                label: entry.label,
                enabled: entry.enabled,
                content: None,
                on_activate: Rc::new(move || invoke(action)),
            }
        })
        .collect();
    finite_menu(FiniteMenuProps {
        key: props.key,
        label: props.label,
        enabled: true.into(),
        open: props.open,
        entries,
        on_open_change: props.on_open_change,
        boundary: props.boundary,
        wrapper_class: "chat-message-actions chat-message-menu-button",
        trigger_class: "chat-action-menu-trigger",
        panel_class: "sapid-menu sapid-layer message-context-menu",
        trigger_content: Rc::new(|_| crate::components::ui_icon("more-horizontal")),
        gap: 6.0,
    })
}

pub(super) fn finite_menu(props: FiniteMenuProps) -> View {
    let mut props = Some(props);
    Box::new(widget(move |scope| {
        use glory::render::{
            AnchorAlign, AnchorPlacement, AnchorSide, FocusMode, Layer, LayerFocus, LayerPlacement,
            MenuItemKind, MenuItemSemantics, Orientation, PopupKind, Role, SemanticId, Semantics,
        };
        let props = props.take().ok_or(glory::ui::Error::Gone)?;
        let namespace = format!(
            "chat-actions-{}-{}",
            scope.id().slot(),
            &message_row::presentation_key(&props.key)[..16]
        );
        let trigger_id = SemanticId::new(format!("{namespace}-trigger"))?;
        let panel_id = SemanticId::new(format!("{namespace}-panel"))?;
        let collection = sapid::Collection::new(
            scope,
            sapid::CollectionLimits {
                items: props.entries.len(),
                label_bytes: 4096,
            },
        )?;
        let menu = Rc::new(ActionMenu {
            open: props.open,
            changed: props.on_open_change,
            roving: sapid::RovingFocus::new(scope, collection.clone(), true)?,
            collection,
            search: RefCell::new(sapid::Typeahead::new(sapid::TypeaheadConfig::default())?),
            panel: scope.cage(None),
            trigger: scope.cage(None),
            boundary: props.boundary,
            side: scope.cage(AnchorSide::Bottom),
            max_height: scope.cage(None),
            measurement_revision: Cell::new(0),
            queries: RefCell::new(Vec::new()),
            measurement_task: RefCell::new(None),
            scroll_task: RefCell::new(None),
        });
        let wrapper_node = scope.cage(None);
        let wrapper_class = props.wrapper_class;
        let open = props.open;
        let wrapper = view()
            .class(scope.bond(move || {
                if open.get() {
                    format!("{wrapper_class} is-open")
                } else {
                    wrapper_class.to_owned()
                }
            }))
            .node_ref(wrapper_node)
            .mount(scope)?;
        let content = wrapper
            .scope()
            .child_in(wrapper_node.get().ok_or(glory::ui::Error::Gone)?)?;
        let trigger_metadata = content.bond({
            let trigger_id = trigger_id.clone();
            let panel_id = panel_id.clone();
            let open = props.open;
            move || {
                Some(Box::new(Semantics {
                    id: Some(trigger_id.clone()),
                    popup: Some(if cfg!(target_arch = "wasm32") {
                        PopupKind::Menu
                    } else {
                        PopupKind::Dialog
                    }),
                    expanded: Some(open.get()),
                    controls: Some(panel_id.clone()),
                    ..Default::default()
                }))
            }
        });
        let live = menu.clone();
        let weak = content.downgrade();
        let trigger = glory::ui::button()
            .class(props.trigger_class)
            .name(props.label.clone())
            .enabled(props.enabled)
            .node_ref(menu.trigger)
            .fill((props.trigger_content)(&content))
            .semantics(trigger_metadata)
            .on(EventKind::Activate, move |_| {
                let Some(scope) = weak.upgrade() else { return };
                let result = live
                    .open
                    .try_get()
                    .map_err(glory::ui::Error::from)
                    .and_then(|open| live.request(!open));
                if let Err(error) = result {
                    scope.report_error(error);
                }
            });
        #[cfg(target_arch = "wasm32")]
        let trigger = {
            let live = menu.clone();
            let weak = content.downgrade();
            trigger.on(EventKind::Menu, move |event| {
                let Some(scope) = weak.upgrade() else { return };
                if let Err(error) = live.event(&scope, event) {
                    scope.report_error(error);
                }
            })
        };
        trigger.show_in(&content)?;
        let open = props.open;
        let panel_metadata = content.bond({
            let panel_id = panel_id.clone();
            let side = menu.side;
            let bounded = menu.boundary.is_some();
            let max_height = menu.max_height;
            let gap = props.gap;
            move || {
                Some(Box::new(Semantics {
                    id: Some(panel_id.clone()),
                    hidden: !open.get(),
                    navigation: cfg!(target_arch = "wasm32").then_some(Orientation::Vertical),
                    typeahead: cfg!(target_arch = "wasm32"),
                    layer: Some(Layer {
                        sheet: None,
                        modal: false,
                        escape: true,
                        outside: true,
                        focus: LayerFocus::Manage,
                        placement: LayerPlacement::Anchor({
                            let mut placement =
                                AnchorPlacement::new(side.get(), AnchorAlign::End).gap(gap);
                            placement.flip = !bounded || max_height.get().is_none();
                            placement
                        }),
                        anchor: Some(trigger_id.clone()),
                        initial_focus: None,
                        return_focus: Some(trigger_id.clone()),
                    }),
                    ..Default::default()
                }))
            }
        });
        let max_height = menu.max_height;
        let mut panel = view()
            .role(if cfg!(target_arch = "wasm32") {
                Role::Menu
            } else {
                Role::Dialog
            })
            .class(props.panel_class)
            .name(props.label)
            .node_ref(menu.panel)
            .focus(FocusMode::Programmatic)
            .style(content.bond(move || {
                let mut style = Style::new();
                style.max_height = max_height.get().map(glory::style::Limit::Px);
                style
            }))
            .semantics(panel_metadata);
        let mut kinds = vec![EventKind::Navigate, EventKind::Dismiss];
        if cfg!(target_arch = "wasm32") {
            kinds.extend([EventKind::Menu, EventKind::Typeahead]);
        }
        for kind in kinds {
            let live = menu.clone();
            let weak = content.downgrade();
            panel = panel.on(kind, move |event| {
                let Some(scope) = weak.upgrade() else { return };
                if let Err(error) = live.event(&scope, event) {
                    scope.report_error(error);
                }
            });
        }
        let panel = panel.mount(&content)?;
        let items_parent = panel
            .scope()
            .child_in(menu.panel.get().ok_or(glory::ui::Error::Gone)?)?;
        #[cfg(not(target_arch = "wasm32"))]
        let navigation_node = items_parent.cage(None);
        #[cfg(not(target_arch = "wasm32"))]
        let navigation = {
            let live = menu.clone();
            let weak = items_parent.downgrade();
            view()
                .role(Role::Group)
                .class("native-finite-menu-navigation")
                .node_ref(navigation_node)
                .semantics(Some(Box::new(Semantics {
                    navigation: Some(Orientation::Vertical),
                    ..Default::default()
                })))
                .on(EventKind::Navigate, move |event| {
                    let Some(scope) = weak.upgrade() else { return };
                    if let Err(error) = live.event(&scope, event) {
                        scope.report_error(error);
                    }
                })
                .mount(&items_parent)?
        };
        #[cfg(not(target_arch = "wasm32"))]
        let items = navigation
            .scope()
            .child_in(navigation_node.get().ok_or(glory::ui::Error::Gone)?)?;
        #[cfg(target_arch = "wasm32")]
        let items = items_parent;
        for entry in props.entries {
            let owner = items.child()?;
            let reference = owner.cage(None);
            let token = owner.cage(None::<sapid::CollectionMember>);
            let roving = menu.roving.clone();
            let focus = owner.bond(move || {
                if token
                    .get()
                    .is_some_and(|member| roving.is_tab_stop(&member).unwrap_or(false))
                {
                    FocusMode::TabStop
                } else {
                    FocusMode::Programmatic
                }
            });
            let live = menu.clone();
            let invoke = entry.on_activate;
            let weak = owner.downgrade();
            let item = glory::ui::button()
                .class(entry.class)
                .name(entry.label.clone())
                .fill(match entry.content {
                    Some(content) => content(&owner),
                    None => Box::new(text().content(entry.label.clone())) as View,
                })
                .enabled(entry.enabled.clone())
                .focus(focus)
                .node_ref(reference)
                .semantics(Some(Box::new(Semantics {
                    id: Some(SemanticId::new(format!("{namespace}-{}", entry.key))?),
                    menu_item: cfg!(target_arch = "wasm32").then(|| MenuItemSemantics {
                        kind: MenuItemKind::Action,
                        owner: panel_id.clone(),
                    }),
                    navigation_item: true,
                    ..Default::default()
                })))
                .on(EventKind::Activate, move |_| {
                    let Some(scope) = weak.upgrade() else { return };
                    match live.request(false) {
                        Ok(()) => invoke(),
                        Err(error) => scope.report_error(error),
                    }
                })
                .mount(&owner)?;
            let member = menu.collection.register(
                item.scope(),
                entry.key,
                reference,
                entry.enabled,
                entry.label,
            )?;
            token.revise(|token| *token = Some(member.clone()));
            let roving = menu.roving.clone();
            let weak = owner.downgrade();
            owner.on(
                reference.get().ok_or(glory::ui::Error::Gone)?,
                EventKind::FocusChanged,
                move |event| {
                    let Some(scope) = weak.upgrade() else { return };
                    if event == Event::FocusChanged(true)
                        && let Err(error) = roving.observe(&member)
                    {
                        scope.report_error(error);
                    }
                },
            )?;
            owner.retain(item)?;
            items.retain(owner)?;
        }
        menu.roving.repair(None)?;
        let live = menu.clone();
        let weak = content.downgrade();
        content.effect(move || {
            let Some(scope) = weak.upgrade() else { return };
            if let Err(error) = live.roving.repair(None) {
                scope.report_error(error);
            }
        });
        let live = menu.clone();
        let weak = content.downgrade();
        content.effect(move || {
            let Some(scope) = weak.upgrade() else { return };
            let _ = live.open.get();
            if let Some(boundary) = live.boundary {
                let _ = boundary.revision.get();
                let _ = boundary.node.get();
            }
            if let Err(error) = live.schedule_measure(&scope) {
                scope.report_error(error);
            }
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            navigation.scope().retain(items)?;
            items_parent.retain(navigation)?;
            panel.scope().retain(items_parent)?;
        }
        #[cfg(target_arch = "wasm32")]
        panel.scope().retain(items)?;
        content.retain(panel)?;
        wrapper.scope().retain(content)?;
        scope.retain(wrapper)?;
        Ok(())
    }))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn find(app: &glory::App, class: &str) -> glory::render::NodeId {
        fn visit(
            app: &glory::App,
            id: glory::render::NodeId,
            class: &str,
        ) -> Option<glory::render::NodeId> {
            let tree = app.tree();
            let node = tree.node(id).unwrap();
            if node
                .descriptor
                .view()
                .classes
                .iter()
                .any(|name| name == class)
            {
                return Some(id);
            }
            node.children
                .iter()
                .find_map(|child| visit(app, *child, class))
        }
        app.tree()
            .roots()
            .iter()
            .find_map(|id| visit(app, *id, class))
            .unwrap()
    }

    #[test]
    fn native_actions_use_a_real_dialog_and_keep_the_original_callback() {
        let app = glory::App::memory();
        let scope = app.scope();
        let open = scope.cage(false);
        let invoked = scope.cage(None::<MessageMenuAction>);
        app.mount(message_actions_menu(
            scope,
            MessageActionsMenuProps {
                key: "ak:event:original-business-key".into(),
                label: "Message actions".to_owned().into(),
                open,
                entries: vec![MessageMenuEntry {
                    action: MessageMenuAction::Reply,
                    label: "Reply".to_owned().into(),
                    enabled: true.into(),
                }],
                on_open_change: Rc::new(|_| {}),
                on_action: Rc::new(move |action| invoked.revise(|value| *value = Some(action))),
                boundary: None,
            },
        ))
        .unwrap();
        app.flush().unwrap();
        let trigger = find(&app, "chat-action-menu-trigger");
        let panel = find(&app, "message-context-menu");
        {
            let tree = app.tree();
            let node = tree.node(panel).unwrap().descriptor.view();
            assert_eq!(node.role, Some(glory::render::Role::Dialog));
            let semantics = node.semantics.as_ref().unwrap();
            assert!(!semantics.typeahead);
            assert!(semantics.context_menu.is_none());
            assert!(semantics.hidden);
            assert!(semantics.navigation.is_none());
        }
        let navigation = find(&app, "native-finite-menu-navigation");
        assert_eq!(
            app.tree()
                .node(navigation)
                .unwrap()
                .descriptor
                .view()
                .semantics
                .as_ref()
                .unwrap()
                .navigation,
            Some(glory::render::Orientation::Vertical)
        );
        app.dispatch(trigger, Event::Activate).unwrap();
        assert!(open.get_untracked());
        let reply = find(&app, "message-context-reply-button");
        assert!(
            app.tree()
                .node(reply)
                .unwrap()
                .descriptor
                .view()
                .semantics
                .as_ref()
                .unwrap()
                .menu_item
                .is_none()
        );
        app.dispatch(reply, Event::Activate).unwrap();
        assert_eq!(invoked.get_untracked(), Some(MessageMenuAction::Reply));
        assert!(!open.get_untracked());
        app.flush().unwrap();
    }

    #[test]
    fn rich_finite_options_keep_inline_descriptions_and_disabled_commands() {
        let app = glory::App::memory();
        let scope = app.scope();
        let open = scope.cage(false);
        let enabled = scope.cage(false);
        let calls = scope.cage(0);
        app.mount(finite_menu(FiniteMenuProps {
            key: "watch-notifications".into(),
            label: "Notifications".to_owned().into(),
            enabled: true.into(),
            open,
            entries: vec![FiniteMenuEntry {
                key: "mentions-only".into(),
                class: "watch-level-option".to_owned().into(),
                label: "Mentions only".to_owned().into(),
                enabled: enabled.into(),
                content: Some(Rc::new(|_| {
                    Box::new(
                        group().fill((
                            text().class("watch-level-check").content("✓"),
                            text()
                                .class("watch-level-option-label")
                                .content("Mentions only"),
                            text()
                                .class("watch-level-option-description")
                                .content("Notify me when I am mentioned"),
                        )),
                    )
                })),
                on_activate: Rc::new(move || calls.revise(|calls| *calls += 1)),
            }],
            on_open_change: Rc::new(|_| {}),
            boundary: None,
            wrapper_class: "watch-level-picker",
            trigger_class: "watch-level-toggle",
            panel_class: "sapid-layer watch-level-menu",
            trigger_content: Rc::new(|_| {
                Box::new(group().fill((
                    crate::components::ui_icon("bell"),
                    text().content("Notifications"),
                )))
            }),
            gap: 4.0,
        }))
        .unwrap();
        app.flush().unwrap();
        let trigger = find(&app, "watch-level-toggle");
        let option = find(&app, "watch-level-option");
        let description = find(&app, "watch-level-option-description");
        assert!(matches!(
            app.tree().node(description).unwrap().descriptor.view().props,
            glory::render::Props::Text(text) if text.content == "Notify me when I am mentioned"
        ));
        app.dispatch(trigger, Event::Activate).unwrap();
        app.dispatch(option, Event::Activate).unwrap();
        assert_eq!(calls.get_untracked(), 0);
        enabled.revise(|value| *value = true);
        app.flush().unwrap();
        assert_eq!(option, find(&app, "watch-level-option"));
        app.dispatch(option, Event::Activate).unwrap();
        assert_eq!(calls.get_untracked(), 1);
        assert!(!open.get_untracked());
    }
}
