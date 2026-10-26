//! Production reactive regions must remain boxless in the actual browser DOM.
#![cfg(all(target_arch = "wasm32", feature = "web"))]

use std::cell::RefCell;
use std::rc::Rc;

use glory::prelude::*;
use inkson::presentation::widgets::{empty, reactive};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

fn element_order(parent: &web_sys::Element) -> Vec<String> {
    let mut order = Vec::new();
    let mut next = parent.first_element_child();
    while let Some(element) = next {
        order.push(element.get_attribute("class").unwrap_or_default());
        next = element.next_element_sibling();
    }
    order
}

#[wasm_bindgen_test(async)]
async fn real_dom_preserves_direct_child_grid_rules_empty_position_and_locale_order() {
    let document = web_sys::window().unwrap().document().unwrap();
    let root = document.create_element("div").unwrap();
    let stylesheet = document.create_element("style").unwrap();
    stylesheet.set_text_content(Some(".inkson-reactive-proof{width:300px;display:grid;grid-template-columns:1fr 1fr;gap:0}.inkson-reactive-proof>.card{grid-column:1/-1;min-width:0}"));
    document.body().unwrap().append_child(&stylesheet).unwrap();
    document.body().unwrap().append_child(&root).unwrap();
    let handles = Rc::new(RefCell::new(None));
    let ready = handles.clone();
    let app = glory::web::launch_with(root.clone(), move |scope| {
        let phase = scope.cage(0_u8);
        let locale = scope.cage(false);
        *ready.borrow_mut() = Some((phase, locale));
        let source = scope.bond(move || (phase.get(), locale.get()));
        Box::new(
            view().class("inkson-reactive-proof").fill((
                input()
                    .class("before")
                    .name("Before")
                    .value("unsaved before"),
                reactive(source, move |_, (phase, locale)| {
                    let title = if locale { "中文" } else { "English" };
                    match phase {
                        0 => empty(),
                        1 => Box::new(view().class("card first").fill(text().content(title))),
                        _ => Box::new(group().fill((
                            view().class("card first").fill(text().content(title)),
                            view().class("card second").fill(text().content("Second")),
                        ))),
                    }
                }),
                input().class("after").name("After").value("unsaved after"),
            )),
        ) as inkson::presentation::View
    })
    .unwrap();
    gloo_timers::future::TimeoutFuture::new(35).await;
    let (phase, locale) = handles.borrow().unwrap();
    let parent = root
        .query_selector(".inkson-reactive-proof")
        .unwrap()
        .unwrap();
    let before = parent.query_selector(":scope > .before").unwrap().unwrap();
    let after = parent.query_selector(":scope > .after").unwrap().unwrap();
    for iteration in 1..=12 {
        let next = (iteration % 3) as u8;
        let language = iteration % 2 == 0;
        app.app()
            .scope()
            .batch(|| {
                phase.revise(|phase| *phase = next);
                locale.revise(|locale| *locale = language);
            })
            .unwrap();
        app.app().flush().unwrap();
        gloo_timers::future::TimeoutFuture::new(35).await;
        let mut expected = vec!["before".to_owned()];
        if next != 0 {
            expected.push("card first".to_owned());
        }
        if next == 2 {
            expected.push("card second".to_owned());
        }
        expected.push("after".to_owned());
        assert_eq!(element_order(&parent), expected);
        let current_before = parent.query_selector(":scope > .before").unwrap().unwrap();
        let current_after = parent.query_selector(":scope > .after").unwrap().unwrap();
        assert!(before.is_same_node(Some(current_before.as_ref())));
        assert!(after.is_same_node(Some(current_after.as_ref())));
        assert!(parent.query_selector(".inkson-region").unwrap().is_none());
        if next != 0 {
            let card = parent.query_selector(":scope > .card").unwrap().unwrap();
            assert!(
                (card.get_bounding_client_rect().width()
                    - parent.get_bounding_client_rect().width())
                .abs()
                    < 0.5
            );
            assert_eq!(
                card.text_content().unwrap(),
                if language { "中文" } else { "English" }
            );
        }
    }
    drop(app);
    assert!(root.first_element_child().is_none());
    root.remove();
    stylesheet.remove();
}
