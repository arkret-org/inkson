//! Real browser rendering of the lifecycle badge used by Kanban cards.
#![cfg(all(target_arch = "wasm32", feature = "web"))]

use std::cell::RefCell;
use std::rc::Rc;

use dioxus::prelude::*;
use inkson::components::write_state::{WriteState, WriteStateBadge};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[derive(Clone)]
struct Control {
    state: Rc<RefCell<Option<Signal<WriteState>>>>,
}

fn badge_page(control: Control) -> Element {
    let state = use_signal(|| WriteState::Queued);
    *control.state.borrow_mut() = Some(state);
    use_context_provider(|| inkson::i18n::init_i18n_with_locale(inkson::i18n::UiLocale::Zh));
    rsx! { WriteStateBadge { state: state() } }
}

#[wasm_bindgen_test(async)]
async fn browser_badge_keeps_pending_unconfirmed_and_renders_acceptance_separately() {
    let document = web_sys::window().unwrap().document().unwrap();
    let root = document.create_element("div").unwrap();
    document.body().unwrap().append_child(&root).unwrap();
    let control = Control {
        state: Rc::new(RefCell::new(None)),
    };
    let dom = VirtualDom::new_with_props(badge_page, control.clone());
    let runtime = dom.runtime();
    let (abort, registration) = futures_util::future::AbortHandle::new_pair();
    let root_for_render = root.clone();
    wasm_bindgen_futures::spawn_local(async move {
        let _ = futures_util::future::Abortable::new(
            dioxus::web::run(dom, dioxus::web::Config::new().rootelement(root_for_render)),
            registration,
        )
        .await;
    });
    for _ in 0..100 {
        if control.state.borrow().is_some() {
            break;
        }
        gloo_timers::future::TimeoutFuture::new(10).await;
    }
    let mut state = control.state.borrow().expect("mounted badge");
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
        runtime.in_scope(ScopeId::ROOT, || state.set(next));
        for _ in 0..100 {
            let badge = root
                .query_selector("[data-testid='write-state-badge']")
                .unwrap();
            if badge
                .as_ref()
                .and_then(|node| node.get_attribute("data-write-state"))
                .as_deref()
                == Some(next.data_state())
            {
                break;
            }
            gloo_timers::future::TimeoutFuture::new(10).await;
        }
        let badge = root
            .query_selector("[data-testid='write-state-badge']")
            .unwrap()
            .unwrap();
        assert_eq!(
            badge.get_attribute("data-write-state").as_deref(),
            Some(next.data_state()),
            "{tag}"
        );
        assert_eq!(
            badge.get_attribute("class").unwrap().contains("green"),
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
        assert!(!badge.get_attribute("title").unwrap().contains("seal"));
        assert!(!badge.get_attribute("title").unwrap().contains("HLC"));
    }
    abort.abort();
    gloo_timers::future::TimeoutFuture::new(0).await;
    root.remove();
}
