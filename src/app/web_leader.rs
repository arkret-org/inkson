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
                    Ok(browser::Leadership::Lease(lease)) => {
                        state.set(LeaderState::Leader);
                        browser::maintain_lease(lease, state);
                    }
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

#[cfg(not(target_arch = "wasm32"))]
fn reload_page() {}

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

    use dioxus::prelude::{Signal, spawn};
    use js_sys::{Function, Object, Promise, Reflect};
    use serde::{Deserialize, Serialize};
    use wasm_bindgen::JsCast;
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::prelude::JsValue;

    use super::LeaderState;

    const LOCK_NAME: &str = "inkson:web-writer:v1";
    const LEASE_KEY: &str = "inkson.web_writer_lease.v1";
    const LEASE_TTL_MS: f64 = 8_000.0;
    const LEASE_RENEW_MS: u32 = 2_000;
    const LEASE_SETTLE_MS: u32 = 200;

    #[derive(Debug)]
    pub(super) enum Leadership {
        WebLock,
        Lease(Lease),
        Follower,
    }

    #[derive(Clone, Debug)]
    pub(super) struct Lease {
        owner: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    struct LeaseRecord {
        owner: String,
        expires_at_ms: f64,
    }

    pub(super) async fn acquire_leadership() -> Result<Leadership, String> {
        match acquire_web_lock().await? {
            Some(acquired) => {
                return Ok(if acquired {
                    Leadership::WebLock
                } else {
                    Leadership::Follower
                });
            }
            None => {}
        }

        acquire_storage_lease().await
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
        let callback = Closure::<dyn FnMut(JsValue) -> Promise>::new(move |lock| {
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
            gloo_timers::future::TimeoutFuture::new(10).await;
        }
        Err("navigator.locks did not resolve within one second".to_owned())
    }

    async fn acquire_storage_lease() -> Result<Leadership, String> {
        let storage = storage()?;
        let now = js_sys::Date::now();
        if let Some(record) = read_lease(&storage)?
            && record.expires_at_ms > now
        {
            return Ok(Leadership::Follower);
        }

        let owner = new_owner_id();
        write_lease(&storage, &owner, now + LEASE_TTL_MS)?;
        gloo_timers::future::TimeoutFuture::new(LEASE_SETTLE_MS).await;

        let confirmed = read_lease(&storage)?.is_some_and(|record| {
            record.owner == owner && record.expires_at_ms > js_sys::Date::now()
        });
        Ok(if confirmed {
            Leadership::Lease(Lease { owner })
        } else {
            Leadership::Follower
        })
    }

    pub(super) fn maintain_lease(lease: Lease, mut state: Signal<LeaderState>) {
        spawn(async move {
            loop {
                gloo_timers::future::TimeoutFuture::new(LEASE_RENEW_MS).await;
                let Ok(storage) = storage() else {
                    state.set(LeaderState::Unavailable);
                    return;
                };
                let owns_lease = read_lease(&storage)
                    .ok()
                    .flatten()
                    .is_some_and(|record| record.owner == lease.owner);
                if !owns_lease {
                    tracing::warn!("browser writer lease lost; unmounting authenticated app");
                    state.set(LeaderState::Follower);
                    return;
                }
                if write_lease(&storage, &lease.owner, js_sys::Date::now() + LEASE_TTL_MS).is_err()
                {
                    state.set(LeaderState::Unavailable);
                    return;
                }
            }
        });
    }

    fn storage() -> Result<web_sys::Storage, String> {
        web_sys::window()
            .ok_or("window unavailable")?
            .local_storage()
            .map_err(js_error)?
            .ok_or_else(|| "localStorage unavailable".to_owned())
    }

    fn read_lease(storage: &web_sys::Storage) -> Result<Option<LeaseRecord>, String> {
        storage
            .get_item(LEASE_KEY)
            .map_err(js_error)?
            .map(|raw| serde_json::from_str(&raw).map_err(|error| error.to_string()))
            .transpose()
    }

    fn write_lease(
        storage: &web_sys::Storage,
        owner: &str,
        expires_at_ms: f64,
    ) -> Result<(), String> {
        let value = serde_json::to_string(&LeaseRecord {
            owner: owner.to_owned(),
            expires_at_ms,
        })
        .map_err(|error| error.to_string())?;
        storage.set_item(LEASE_KEY, &value).map_err(js_error)
    }

    fn new_owner_id() -> String {
        let random = js_sys::Math::random().to_bits();
        format!("{:x}-{:x}", js_sys::Date::now().to_bits(), random)
    }

    fn js_error(value: JsValue) -> String {
        value.as_string().unwrap_or_else(|| format!("{value:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_states_are_closed_and_distinct() {
        assert_ne!(LeaderState::Pending, LeaderState::Leader);
        assert_ne!(LeaderState::Leader, LeaderState::Follower);
        assert_ne!(LeaderState::Follower, LeaderState::Unavailable);
    }
}
