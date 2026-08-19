//! Browser single-leader gate.
//!
//! Every browser tab has its own Rust/WASM memory but shares the origin's
//! IndexedDB, device keys and account state. Mounting [`super::AppBootstrap`]
//! in two tabs would therefore start two sync/MLS/to-device writers over the
//! same durable state. This component sits outside the router and only mounts
//! it after the tab owns the origin-wide leader lock.

use dioxus::prelude::*;
use dioxus_router::Router;

use crate::routes::Route;

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Debug, Eq, PartialEq)]
enum LeaderState {
    Pending,
    Leader,
    Follower,
    Unavailable,
}

#[component]
pub(super) fn WebLeaderGate() -> Element {
    #[cfg(not(target_arch = "wasm32"))]
    {
        return rsx! { Router::<Route> {} };
    }

    #[cfg(target_arch = "wasm32")]
    {
        let mut state = use_signal(|| LeaderState::Pending);
        use_effect(move || {
            spawn(async move {
                match browser::acquire_leadership().await {
                    Ok(browser::Leadership::WebLock) => state.set(LeaderState::Leader),
                    Ok(browser::Leadership::Follower) => state.set(LeaderState::Follower),
                    Err(error) => {
                        tracing::error!(%error, "browser single-leader gate unavailable");
                        state.set(LeaderState::Unavailable);
                    }
                }
            });
        });

        match state() {
            LeaderState::Leader => rsx! { Router::<Route> {} },
            LeaderState::Pending => rsx! {
                LeaderGatePage {
                    test_id: "web-leader-pending",
                    title: "Opening Inkson securely",
                    message: "Checking whether another Inkson tab is already active…",
                    retry: false,
                }
            },
            LeaderState::Follower => rsx! {
                LeaderGatePage {
                    test_id: "web-leader-follower",
                    title: "Inkson is already open",
                    message: "Another tab owns this browser profile. To protect encrypted state, this tab will not start synchronization.",
                    retry: true,
                }
            },
            LeaderState::Unavailable => rsx! {
                LeaderGatePage {
                    test_id: "web-leader-unavailable",
                    title: "Inkson could not start safely",
                    message: "This browser cannot guarantee a single encrypted-state writer. Close other Inkson tabs, then retry.",
                    retry: true,
                }
            },
        }
    }
}

#[cfg(target_arch = "wasm32")]
#[component]
fn LeaderGatePage(
    test_id: &'static str,
    title: &'static str,
    message: &'static str,
    retry: bool,
) -> Element {
    rsx! {
        main {
            class: "auth-page",
            "data-testid": test_id,
            section {
                class: "auth-card",
                role: "status",
                aria_live: "polite",
                h1 { "{title}" }
                p { "{message}" }
                if retry {
                    button {
                        class: "btn btn-primary",
                        r#type: "button",
                        "data-testid": "web-leader-retry",
                        onclick: move |_| reload_page(),
                        "Retry"
                    }
                }
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn reload_page() {
    if let Some(window) = web_sys::window() {
        let _ = window.location().reload();
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use std::cell::RefCell;
    use std::rc::Rc;

    use js_sys::{Function, Object, Promise, Reflect};
    use wasm_bindgen::JsCast;
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::prelude::JsValue;

    const LOCK_NAME: &str = "inkson:web-writer:v1";

    #[derive(Debug)]
    pub(super) enum Leadership {
        WebLock,
        Follower,
    }

    pub(super) async fn acquire_leadership() -> Result<Leadership, String> {
        let Some(acquired) = acquire_web_lock().await? else {
            return Err(
                "navigator.locks is required to guarantee a single encrypted-state writer"
                    .to_owned(),
            );
        };
        Ok(if acquired {
            Leadership::WebLock
        } else {
            Leadership::Follower
        })
    }

    /// Returns `Ok(None)` when Web Locks is not exposed by the browser.
    async fn acquire_web_lock() -> Result<Option<bool>, String> {
        let window = web_sys::window().ok_or("window unavailable")?;
        let navigator = JsValue::from(window.navigator());
        let locks = Reflect::get(&navigator, &JsValue::from_str("locks")).map_err(js_error)?;
        if locks.is_null() || locks.is_undefined() {
            return Ok(None);
        }
        let request = Reflect::get(&locks, &JsValue::from_str("request"))
            .map_err(js_error)?
            .dyn_into::<Function>()
            .map_err(|_| "navigator.locks.request is not callable".to_owned())?;

        let options = Object::new();
        Reflect::set(
            &options,
            &JsValue::from_str("mode"),
            &JsValue::from_str("exclusive"),
        )
        .map_err(js_error)?;
        Reflect::set(&options, &JsValue::from_str("ifAvailable"), &JsValue::TRUE)
            .map_err(js_error)?;

        let outcome = Rc::new(RefCell::new(None::<bool>));
        let outcome_for_callback = Rc::clone(&outcome);
        let callback = Closure::<dyn FnMut(JsValue) -> Promise>::new(move |lock: JsValue| {
            let acquired = !(lock.is_null() || lock.is_undefined());
            *outcome_for_callback.borrow_mut() = Some(acquired);
            if acquired {
                // Keep the callback promise pending for the lifetime of this
                // document. The browser releases the Web Lock on unload/crash.
                Promise::new(&mut |_resolve, _reject| {})
            } else {
                Promise::resolve(&JsValue::UNDEFINED)
            }
        });

        request
            .call3(
                &locks,
                &JsValue::from_str(LOCK_NAME),
                &options,
                callback.as_ref().unchecked_ref(),
            )
            .map_err(js_error)?;
        callback.forget();

        for _ in 0..100 {
            if let Some(acquired) = *outcome.borrow() {
                return Ok(Some(acquired));
            }
            crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(10)).await;
        }
        Err("navigator.locks did not resolve within one second".to_owned())
    }

    fn js_error(value: JsValue) -> String {
        value.as_string().unwrap_or_else(|| format!("{value:?}"))
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn gate_states_are_closed_and_distinct() {
        assert_ne!(LeaderState::Pending, LeaderState::Leader);
        assert_ne!(LeaderState::Leader, LeaderState::Follower);
        assert_ne!(LeaderState::Follower, LeaderState::Unavailable);
    }
}
