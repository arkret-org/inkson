//! App-wide, single-flight principal-bearer refresher.
//!
//! The principal bearer (`token` signal, sent with every API call) is
//! short-lived. When a request comes back `auth_expired` the app must
//! silently re-mint a fresh bearer (OIDC `refresh_token` → coauth, or the
//! session-grant exchange) and only fall back to the login page when that
//! recovery genuinely fails.
//!
//! That recovery used to be hand-rolled at each call site — `connect()`,
//! the sync bootstrap, chat send, Realm create, the account-menu button —
//! and most of them got it subtly wrong (bounced straight to login, or
//! didn't refresh at all). This module is the single source of truth:
//!
//! * The app root registers one refresher closure ([`register_session_refresher`]) that captures
//!   the session signals and knows how to mint a fresh bearer.
//! * Every auth-expired handler anywhere reaches it through [`refresh_current_bearer`] — no signal
//!   threading, no duplicated policy.
//!
//! Concurrent callers **coalesce onto a single in-flight refresh**. A
//! short-lived bearer rolling over while several requests are in flight
//! would otherwise fire N competing refreshes; with a rotating upstream
//! refresh token those refreshes invalidate each other and exactly one
//! survives — the rest see `invalid_grant` and bounce the user to login.
//! Single-flight removes that race.
//!
//! The refresher lives at the app layer (not the HTTP client) on purpose:
//! the refresh future captures Dioxus signals and wasm `reqwest`, both of
//! which are `!Send`, so it cannot satisfy the `Send` bound a client-layer
//! interceptor hook would impose. Single-threaded `thread_local` ambient
//! state is the right tool here.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::time::Duration;

/// Boxed, single-threaded refresh future. `!Send` by design — it captures
/// Dioxus signals and wasm `reqwest`.
pub type LocalRefreshFuture = Pin<Box<dyn Future<Output = Option<String>>>>;

/// Registered refresher: produces a fresh refresh future each time it is
/// invoked (so a later rollover can refresh again).
type RefreshFn = Rc<dyn Fn() -> LocalRefreshFuture>;

/// Registered soft-logout hook. The app root owns the actual Dioxus
/// signals, so lower layers call this when they receive a terminal
/// session-grant denial and need live pollers to stop using the old
/// bearer.
type InvalidateFn = Rc<RefCell<dyn FnMut(String)>>;

thread_local! {
    static REFRESHER: RefCell<Option<RefreshFn>> = const { RefCell::new(None) };
    static INVALIDATOR: RefCell<Option<InvalidateFn>> = const { RefCell::new(None) };
    static IN_FLIGHT: Cell<bool> = const { Cell::new(false) };
    static LAST_RESULT: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Maximum time a coalescing caller waits for an in-flight refresh before
/// giving up (200 × 50 ms ≈ 10 s) — a backstop against a wedged refresh
/// hanging every other caller forever.
const COALESCE_POLL_INTERVAL_MS: u64 = 50;
const COALESCE_MAX_POLLS: usize = 200;

/// Clears the in-flight flag on drop so a panic inside the refresher can't
/// wedge every future refresh.
struct InFlightGuard;

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        IN_FLIGHT.with(|flag| flag.set(false));
    }
}

/// Install the app-wide refresher. Called once from the app root with a
/// closure that captures the session signals and performs the silent
/// re-mint, updating the live `token` signal + persisted config on success.
pub fn register_session_refresher(refresher: RefreshFn) {
    REFRESHER.with(|slot| *slot.borrow_mut() = Some(refresher));
}

/// Install the app-wide soft-logout hook. Called from the app root after
/// the session/config signals exist.
pub fn register_session_invalidator(invalidator: impl FnMut(String) + 'static) {
    INVALIDATOR.with(|slot| *slot.borrow_mut() = Some(Rc::new(RefCell::new(invalidator))));
}

/// Clear the active UI session through the registered app hook. Safe to
/// call from lower-level API helpers; if the hook has not been installed
/// yet, this is a no-op.
pub fn invalidate_current_session(reason: impl Into<String>) {
    let reason = reason.into();
    INVALIDATOR.with(|slot| {
        if let Some(invalidator) = slot.borrow().as_ref() {
            invalidator.borrow_mut()(reason);
        }
    });
}

/// Re-mint the principal bearer, coalescing concurrent callers onto a
/// single in-flight refresh.
///
/// Returns the fresh bearer on success, or `None` when no refresher is
/// registered or the session is genuinely dead (the caller routes to
/// login). Safe to call from any auth-expired handler.
pub async fn refresh_current_bearer() -> Option<String> {
    let refresher = REFRESHER.with(|slot| slot.borrow().clone())?;

    if IN_FLIGHT.with(Cell::get) {
        return wait_for_in_flight_refresh_result().await;
    }

    IN_FLIGHT.with(|flag| flag.set(true));
    let _guard = InFlightGuard;
    let result = refresher().await;
    LAST_RESULT.with(|slot| *slot.borrow_mut() = result.clone());
    result
}

/// If a bearer refresh is already running, wait for it and return the
/// resulting bearer. Does not start a new refresh.
pub async fn wait_for_current_bearer_refresh() -> Option<String> {
    if IN_FLIGHT.with(Cell::get) {
        wait_for_in_flight_refresh_result().await
    } else {
        None
    }
}

async fn wait_for_in_flight_refresh_result() -> Option<String> {
    for _ in 0..COALESCE_MAX_POLLS {
        crate::api::sleep_for(Duration::from_millis(COALESCE_POLL_INTERVAL_MS)).await;
        if !IN_FLIGHT.with(Cell::get) {
            break;
        }
    }
    LAST_RESULT.with(|slot| slot.borrow().clone())
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_registered_refresher_result() {
        register_session_refresher(Rc::new(|| {
            Box::pin(async { Some("fresh-bearer".to_owned()) })
        }));
        assert_eq!(
            refresh_current_bearer().await,
            Some("fresh-bearer".to_owned())
        );
    }

    #[tokio::test]
    async fn coalesces_concurrent_callers_into_one_refresh() {
        thread_local! {
            static CALLS: Cell<u32> = const { Cell::new(0) };
        }
        CALLS.with(|c| c.set(0));
        register_session_refresher(Rc::new(|| {
            Box::pin(async {
                CALLS.with(|c| c.set(c.get() + 1));
                // Hold the in-flight slot open long enough that the second
                // caller is forced onto the coalescing wait path.
                crate::api::sleep_for(Duration::from_millis(120)).await;
                Some("tok".to_owned())
            })
        }));

        let (first, second) = tokio::join!(refresh_current_bearer(), refresh_current_bearer());

        assert_eq!(first, Some("tok".to_owned()));
        assert_eq!(second, Some("tok".to_owned()));
        assert_eq!(
            CALLS.with(Cell::get),
            1,
            "concurrent callers must coalesce onto a single refresh"
        );
    }

    #[test]
    fn invalidator_invokes_registered_hook() {
        thread_local! {
            static REASON: RefCell<Option<String>> = const { RefCell::new(None) };
        }
        REASON.with(|slot| *slot.borrow_mut() = None);
        register_session_invalidator(|reason| {
            REASON.with(|slot| *slot.borrow_mut() = Some(reason));
        });

        invalidate_current_session("session grant revoked");

        assert_eq!(
            REASON.with(|slot| slot.borrow().clone()),
            Some("session grant revoked".to_owned())
        );
    }
}
