//! Real browser rendering of the lifecycle badge used by Kanban cards.
#![cfg(all(target_arch = "wasm32", feature = "web"))]
use std::cell::RefCell;
use std::rc::Rc;

use glory::Cage;
use inkson::components::{WriteState, WriteStateBadgeProps, write_state_badge};
use wasm_bindgen_test::*;
#[path = "support/glory_web.rs"]
mod glory_web;
wasm_bindgen_test_configure!(run_in_browser);
#[wasm_bindgen_test(async)]
async fn browser_badge_keeps_pending_unconfirmed_and_renders_acceptance_separately() {
    let root = glory_web::root();
    let control = Rc::new(RefCell::new(None::<Cage<WriteState>>));
    let mounted = control.clone();
    let app = glory::web::launch_with(root.clone(), move |scope| {
        let context = glory_web::context(scope);
        context
            .locale
            .revise(|value| *value = inkson::i18n::UiLocale::Zh);
        let state = scope.cage(WriteState::Queued);
        *mounted.borrow_mut() = Some(state);
        inkson::presentation::widgets::reactive(state, move |scope, state| {
            write_state_badge(
                scope,
                context.clone(),
                WriteStateBadgeProps {
                    state,
                    icon_only: None,
                },
            )
        })
    })
    .unwrap();
    let state = control.borrow().unwrap();
    for (tag, label, success) in [
        ("queued", "排队中", false),
        ("submitting", "发送中", false),
        ("pending", "发送中", false),
        ("pending_commit", "发送中", false),
        ("cas_conflict", "修改冲突", false),
        ("rejected", "未成功", false),
        ("queued", "排队中", false),
        ("accepted", "已接受", true),
        ("synced", "已同步", true),
    ] {
        let next = WriteState::from_local_state(tag).unwrap();
        state.revise(|value| *value = next);
        app.app().flush().unwrap();
        glory_web::settle().await;
        let badge = root.query_selector(".write-state-badge").unwrap().unwrap();
        let classes = badge.get_attribute("class").unwrap();
        assert!(
            classes
                .split_whitespace()
                .any(|value| value == format!("write-state-{}", next.data_state())),
            "{tag}"
        );
        assert_eq!(
            classes.split_whitespace().any(|value| value == "green"),
            success,
            "{tag}"
        );
        assert_eq!(
            badge
                .query_selector(".write-state-label")
                .unwrap()
                .unwrap()
                .text_content()
                .as_deref(),
            Some(label)
        );
        let icon = badge.query_selector(".write-state-icon").unwrap().unwrap();
        let accessible = icon.get_attribute("aria-label").unwrap_or_default();
        assert!(!accessible.contains("seal"));
        assert!(!accessible.contains("HLC"));
    }
    drop(app);
    root.remove();
}
