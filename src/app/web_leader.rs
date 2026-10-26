//! Only the browser tab holding the origin lock may start encrypted writers.
use glory::Scope;

use crate::presentation::View;

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Debug, Eq, PartialEq)]
enum LeaderState {
    Pending,
    Leader,
    Follower,
    Unavailable,
}

pub(super) fn gate(scope: &Scope) -> View {
    #[cfg(not(target_arch = "wasm32"))]
    {
        super::glory_root::bootstrap(scope)
    }
    #[cfg(target_arch = "wasm32")]
    {
        let state = scope.cage(LeaderState::Pending);
        if let Err(error) = scope.spawn(async move {
            let next = match browser::acquire_leadership().await {
                Ok(browser::Leadership::WebLock) => LeaderState::Leader,
                Ok(browser::Leadership::Follower) => LeaderState::Follower,
                Err(error) => {
                    tracing::error!(%error, "browser single-leader gate unavailable");
                    LeaderState::Unavailable
                }
            };
            state.revise(|value| *value = next);
        }) {
            scope.report_error(error);
        }
        crate::presentation::widgets::reactive_distinct(state, |scope, state| match state {
            LeaderState::Leader => super::glory_root::bootstrap(scope),
            LeaderState::Pending => gate_page(
                "Opening Inkson securely",
                "Checking whether another Inkson tab is already active…",
                false,
            ),
            LeaderState::Follower => gate_page(
                "Inkson is already open",
                "Another tab owns this browser profile. To protect encrypted state, this tab will not start synchronization.",
                true,
            ),
            LeaderState::Unavailable => gate_page(
                "Inkson could not start safely",
                "This browser cannot guarantee a single encrypted-state writer. Close other Inkson tabs, then retry.",
                true,
            ),
        })
    }
}

#[cfg(target_arch = "wasm32")]
fn gate_page(title: &str, message: &str, retry: bool) -> View {
    use glory::ui::view;

    use crate::presentation::widgets::{heading, paragraph};
    let mut children = vec![
        heading(1, "", title.to_owned()),
        paragraph("muted", message.to_owned()),
    ];
    if retry {
        children.push(Box::new(
            sapid::button()
                .unstyled()
                .class("btn btn-primary")
                .label("Try again")
                .on_press(|| {
                    if let Some(window) = web_sys::window()
                        && let Err(error) = window.location().reload()
                    {
                        tracing::warn!(?error, "leader retry reload failed");
                    }
                }),
        ));
    }
    Box::new(
        view().class("auth-shell").fill(Box::new(
            glory::ui::view()
                .class("auth-card auth-panel")
                .role(glory::render::Role::Status)
                .fill(children),
        ) as View),
    )
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
