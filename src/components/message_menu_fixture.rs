//! Browser conformance surface using the production typed message action menu.
use std::cell::RefCell;
use std::rc::Rc;

use glory::prelude::*;
use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::presentation::widgets::{line, paragraph, stack};
use crate::views::chat::{
    MessageActionsMenuProps, MessageMenuAction, MessageMenuBoundary, MessageMenuEntry,
    message_actions_menu,
};
thread_local! {static APP:RefCell<Option<glory::web::WebApp>>=const{RefCell::new(None)};}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Options {
    bottom: bool,
    long: bool,
    badges: bool,
    compact: bool,
}
#[wasm_bindgen(js_name=mountMessageMenuFixture)]
pub fn mount_message_menu_fixture(
    root: web_sys::Element,
    options_json: &str,
) -> std::result::Result<(), JsValue> {
    let options: Options = serde_json::from_str(options_json)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    APP.with(|slot| slot.borrow_mut().take());
    root.set_inner_html("");
    root.set_class_name("inkson-root inkson-theme-dark");
    let app = glory::web::launch_with(root, move |scope| fixture(scope, options))
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    crate::presentation::host::prioritize_browser_styles()?;
    APP.with(|slot| *slot.borrow_mut() = Some(app));
    Ok(())
}
fn fixture(scope: &Scope, options: Options) -> crate::presentation::View {
    let open = scope.cage(false);
    let feed_node = scope.cage(None::<glory::render::NodeId>);
    let feed_revision = scope.cage(0_u64);
    let action = scope.cage(String::new());
    let entries = [
        (MessageMenuAction::Reply, "回复", true),
        (MessageMenuAction::React, "回应", true),
        (MessageMenuAction::Edit, "编辑", false),
        (MessageMenuAction::SharedPin, "共享钉选", true),
        (MessageMenuAction::PrivateSave, "仅为我保存", true),
        (MessageMenuAction::Report, "举报", true),
        (MessageMenuAction::Redact, "撤回", true),
    ]
    .into_iter()
    .map(|(action, label, enabled)| MessageMenuEntry {
        action,
        label: label.to_owned().into(),
        enabled: enabled.into(),
    })
    .collect();
    let menu = message_actions_menu(
        scope,
        MessageActionsMenuProps {
            key: "layout-message-actions".into(),
            label: "消息操作".to_owned().into(),
            open,
            boundary: Some(MessageMenuBoundary {
                node: feed_node,
                revision: feed_revision,
            }),
            entries,
            on_open_change: Rc::new(|_| {}),
            on_action: Rc::new(move |next| action.revise(|value| *value = format!("{next:?}"))),
        },
    );
    let mut body = vec![];
    if options.badges {
        body.push(Box::new(
            sapid::button()
                .unstyled()
                .class("btn message-pin-indicator")
                .label("P"),
        ) as crate::presentation::View);
        body.push(paragraph("message-private-saved-indicator", "✓"));
    }
    body.push(line(
        "msg-head",
        vec![
            paragraph("name", "aa"),
            paragraph("badge member-badge member-badge-agent", "🤖 智能体"),
            paragraph("agent-owner-label", "agent of alice:local.host"),
            paragraph("message-time", "21:33"),
        ],
    ));
    let content = if options.long {
        format!(
            "你好！有什么需要帮忙的吗？{}",
            "\n这是一条很长的消息。".repeat(30)
        )
    } else {
        "你好！有什么需要帮忙的吗？".into()
    };
    body.push(paragraph("msg-content", content));
    body.push(menu);
    let row = stack(
        if options.badges {
            "discussion-message is-pinned"
        } else {
            "discussion-message"
        },
        vec![stack("msg-body", body)],
    );
    let spacer = Box::new(
        view()
            .class("fixture-spacer")
            .style(Style::new().height(Length::Px(if options.bottom { 440.0 } else { 0.0 }))),
    );
    let end = Box::new(
        view()
            .class("fixture-tail")
            .style(Style::new().height(Length::Px(900.0))),
    );
    Box::new(
        view().class("layout-message-fixture").fill(
            view()
                .class("discussion-chat-feed message-list")
                .node_ref(feed_node)
                .on(glory::render::EventKind::Scroll, move |_| {
                    feed_revision.revise(|revision| *revision = revision.wrapping_add(1));
                })
                .on(glory::render::EventKind::Resize, move |_| {
                    feed_revision.revise(|revision| *revision = revision.wrapping_add(1));
                })
                .style(Style::new().height(if options.compact {
                    Length::Px(210.0)
                } else {
                    Length::Percent(100.0)
                }))
                .fill(vec![spacer as crate::presentation::View, row, end]),
        ),
    )
}
