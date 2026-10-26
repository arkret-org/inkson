//! Production invite controls mounted in the browser DOM.
#![cfg(all(target_arch = "wasm32", feature = "web"))]
use std::rc::Rc;

use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;
#[path = "support/glory_web.rs"]
mod glory_web;
wasm_bindgen_test_configure!(run_in_browser);
#[wasm_bindgen_test(async)]
async fn browser_revoke_removes_url_qr_and_disables_revoke_then_generate_disables_both() {
    let root = glory_web::root();
    let app = glory::web::launch_with(root.clone(), |scope| {
        let context = glory_web::context(scope);
        let state = scope.cage((
            "https://station.example/#token=secret".to_owned(),
            true,
            false,
        ));
        inkson::presentation::widgets::reactive(state, move |scope, (url, owned, busy)| {
            inkson::views::settings::invite_locator::invite_locator_card(
                scope,
                context.clone(),
                inkson::views::settings::invite_locator::InviteLocatorCardProps {
                    has_session: true,
                    url,
                    status: String::new(),
                    busy,
                    has_locator: owned,
                    onrefresh: Rc::new(move |()| {
                        state.revise(|value| {
                            *value = ("https://station.example/#token=new".into(), true, true)
                        })
                    }),
                    onrevoke: Rc::new(move |()| {
                        state.revise(|value| *value = (String::new(), false, false))
                    }),
                },
            )
        })
    })
    .unwrap();
    glory_web::settle().await;
    let button = |key: &str| {
        root.query_selector(&format!(".{key}"))
            .unwrap()
            .unwrap()
            .dyn_into::<web_sys::HtmlElement>()
            .unwrap()
    };
    assert!(
        root.query_selector(".settings-invite-locator-qr [data-gly-kind='graphic']")
            .unwrap()
            .is_some()
    );
    button("settings-invite-locator-revoke").click();
    glory_web::settle().await;
    assert!(
        root.query_selector(".settings-invite-locator-url-pane")
            .unwrap()
            .is_none()
    );
    assert!(button("settings-invite-locator-revoke").has_attribute("disabled"));
    assert!(!button("settings-invite-locator-refresh").has_attribute("disabled"));
    button("settings-invite-locator-refresh").click();
    glory_web::settle().await;
    assert!(button("settings-invite-locator-refresh").has_attribute("disabled"));
    assert!(button("settings-invite-locator-revoke").has_attribute("disabled"));
    drop(app);
    root.remove();
}
