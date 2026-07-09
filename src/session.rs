//! App-wide, single-flight session-credential refresher.
//!
//! The current credential (`token` signal, sent with every API call) is the
//! active `ak.session.grant` JWT. When a request comes back `auth_expired`, the
//! app either restores the still-valid grant into memory or rotates it through
//! the Account Authority refresh endpoint. It clears the live session only when
//! the refresh endpoint returns a structured terminal grant error. Missing
//! local refresh material or a transient refresh failure is surfaced to the
//! caller without wiping the current credential.
//!
//! That recovery used to be hand-rolled at each call site — `connect()`,
//! the sync bootstrap, chat send, Realm create, the account-menu button —
//! and most of them got it subtly wrong (bounced straight to login, or
//! didn't refresh at all). This module is the single source of truth:
//!
//! * The app root registers one refresher closure ([`register_session_refresher`]) that captures
//!   the session signals and knows how to restore or rotate the grant.
//! * Every auth-expired handler anywhere reaches it through [`refresh_current_session_credential`]
//!   — no signal threading, no duplicated policy.
//!
//! Concurrent callers **coalesce onto a single in-flight refresh**. A
//! single-use grant rotation while several requests are in flight would
//! otherwise fire N competing refreshes; the first consumes the prior grant and
//! the rest see terminal grant errors. Single-flight removes that race.
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CurrentSessionRefresh {
    Credential(String),
    /// Recovery cannot continue locally, but the refresh endpoint did not
    /// return a terminal grant error. Callers may ask the user to sign in
    /// without clearing the current credential.
    SignInRequired {
        reason: String,
    },
    /// The refresh endpoint returned a terminal grant error and the app-wide
    /// invalidator has cleared the current credential.
    LoginRequired {
        reason: String,
    },
    RetryLater {
        reason: String,
    },
}

impl CurrentSessionRefresh {
    pub fn credential(self) -> Option<String> {
        match self {
            Self::Credential(value) => Some(value),
            Self::SignInRequired { .. } | Self::LoginRequired { .. } | Self::RetryLater { .. } => {
                None
            }
        }
    }

    pub fn retry_later(reason: impl Into<String>) -> Self {
        Self::RetryLater {
            reason: reason.into(),
        }
    }
}

/// Boxed, single-threaded refresh future. `!Send` by design — it captures
/// Dioxus signals and wasm `reqwest`.
pub type LocalRefreshFuture = Pin<Box<dyn Future<Output = CurrentSessionRefresh>>>;

/// Registered refresher: produces a fresh refresh future each time it is
/// invoked (so a later rollover can refresh again).
type RefreshFn = Rc<dyn Fn() -> LocalRefreshFuture>;

/// Registered soft-logout hook. The app root owns the actual Dioxus
/// signals, so lower layers call this when they receive a terminal
/// session-grant denial and need live pollers to stop using the old
/// credential.
type InvalidateFn = Rc<RefCell<dyn FnMut(String)>>;

thread_local! {
    static REFRESHER: RefCell<Option<RefreshFn>> = const { RefCell::new(None) };
    static INVALIDATOR: RefCell<Option<InvalidateFn>> = const { RefCell::new(None) };
    static IN_FLIGHT: Cell<bool> = const { Cell::new(false) };
    static LAST_RESULT: RefCell<Option<CurrentSessionRefresh>> = const { RefCell::new(None) };
    /// Wall-clock ms of the last refresh that produced a live credential.
    /// Backs the sequential-call cooldown in [`refresh_current_session`].
    static LAST_SUCCESS_AT_MS: Cell<u64> = const { Cell::new(0) };
}

/// How long a freshly rotated credential is reused before a subsequent
/// *sequential* refresh is allowed to rotate again. The single-flight guard
/// only coalesces concurrent callers; this closes the sequential gap where a
/// caller that keeps reclassifying the same failure as `auth_expired` would
/// otherwise rotate the grant — and re-resolve its uncached `/_arkret/describe`
/// — on every iteration, storming the network.
const REFRESH_COOLDOWN_MS: u64 = 3_000;

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
/// restore/rotation, updating the live `token` signal + persisted config on success.
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

/// Refresh the current session credential, coalescing concurrent callers onto a
/// single in-flight refresh.
///
/// Returns the current credential on success, or `None` when the richer
/// refresh result did not produce a credential. Callers that need to
/// distinguish terminal invalidation from retryable or sign-in-required
/// outcomes should use [`refresh_current_session`] instead.
pub async fn refresh_current_session_credential() -> Option<String> {
    refresh_current_session().await.credential()
}

/// Refresh the current session and preserve the reason when no credential can
/// be produced. Callers should use this instead of the legacy
/// `Option<String>` helper so missing refresh material and transient Account
/// Authority failures are not treated as definite logout.
pub async fn refresh_current_session() -> CurrentSessionRefresh {
    let Some(refresher) = REFRESHER.with(|slot| slot.borrow().clone()) else {
        return no_refresher_result();
    };

    if IN_FLIGHT.with(Cell::get) {
        return wait_for_in_flight_refresh_result().await;
    }

    // Sequential-call cooldown. The single-flight check above only coalesces
    // *concurrent* callers — sequential callers each ran a full rotation. A
    // driver that keeps re-classifying the same non-auth failure as
    // `auth_expired` (e.g. a self-re-running effect polling during MLS seal)
    // would rotate the grant, and pre-resolve its uncached `/_arkret/describe`,
    // on every iteration — the `describe` request storm seen on card create in
    // an encrypted Realm. If a refresh produced a live credential within the
    // cooldown, reuse it instead of rotating again: the rotated grant is still
    // valid, so returning it is correct as well as cheap. Terminal / sign-in
    // outcomes are never cached here, so a genuinely dead grant still escalates
    // once the window lapses.
    let now_ms = crate::clock::now_unix_ms();
    let within_cooldown = LAST_SUCCESS_AT_MS
        .with(Cell::get)
        .checked_add(REFRESH_COOLDOWN_MS)
        .is_some_and(|until| now_ms < until);
    if within_cooldown
        && let Some(cached @ CurrentSessionRefresh::Credential(_)) =
            LAST_RESULT.with(|slot| slot.borrow().clone())
    {
        return cached;
    }

    IN_FLIGHT.with(|flag| flag.set(true));
    let _guard = InFlightGuard;
    let result = refresher().await;
    LAST_RESULT.with(|slot| *slot.borrow_mut() = Some(result.clone()));
    if matches!(result, CurrentSessionRefresh::Credential(_)) {
        LAST_SUCCESS_AT_MS.with(|slot| slot.set(crate::clock::now_unix_ms()));
    }
    result
}

fn no_refresher_result() -> CurrentSessionRefresh {
    CurrentSessionRefresh::retry_later("session refresher is not registered")
}

/// If a credential refresh is already running, wait for it and return the
/// resulting credential. Does not start a new refresh.
pub async fn wait_for_current_session_credential_refresh() -> Option<String> {
    wait_for_current_session_refresh().await.credential()
}

pub async fn wait_for_current_session_refresh() -> CurrentSessionRefresh {
    if IN_FLIGHT.with(Cell::get) {
        wait_for_in_flight_refresh_result().await
    } else {
        CurrentSessionRefresh::retry_later("no session refresh is in flight")
    }
}

async fn wait_for_in_flight_refresh_result() -> CurrentSessionRefresh {
    for _ in 0..COALESCE_MAX_POLLS {
        crate::runtime_helpers::sleep_for(Duration::from_millis(COALESCE_POLL_INTERVAL_MS)).await;
        if !IN_FLIGHT.with(Cell::get) {
            break;
        }
    }
    LAST_RESULT
        .with(|slot| slot.borrow().clone())
        .unwrap_or_else(|| CurrentSessionRefresh::retry_later("session refresh did not finish"))
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_registered_refresher_result() {
        register_session_refresher(Rc::new(|| {
            Box::pin(async { CurrentSessionRefresh::Credential("fresh-credential".to_owned()) })
        }));
        assert_eq!(
            refresh_current_session_credential().await,
            Some("fresh-credential".to_owned())
        );
    }

    #[tokio::test]
    async fn preserves_retry_later_refresh_result() {
        register_session_refresher(Rc::new(|| {
            Box::pin(async { CurrentSessionRefresh::retry_later("account authority unavailable") })
        }));

        assert_eq!(
            refresh_current_session().await,
            CurrentSessionRefresh::RetryLater {
                reason: "account authority unavailable".to_owned(),
            }
        );
        assert_eq!(refresh_current_session_credential().await, None);
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
                crate::runtime_helpers::sleep_for(Duration::from_millis(120)).await;
                CurrentSessionRefresh::Credential("tok".to_owned())
            })
        }));

        let (first, second) = tokio::join!(
            refresh_current_session_credential(),
            refresh_current_session_credential()
        );

        assert_eq!(first, Some("tok".to_owned()));
        assert_eq!(second, Some("tok".to_owned()));
        assert_eq!(
            CALLS.with(Cell::get),
            1,
            "concurrent callers must coalesce onto a single refresh"
        );
    }

    #[tokio::test]
    async fn cooldown_reuses_fresh_credential_across_sequential_callers() {
        thread_local! {
            static CALLS: Cell<u32> = const { Cell::new(0) };
        }
        CALLS.with(|c| c.set(0));
        register_session_refresher(Rc::new(|| {
            Box::pin(async {
                CALLS.with(|c| c.set(c.get() + 1));
                CurrentSessionRefresh::Credential("tok".to_owned())
            })
        }));

        // First sequential call rotates; a second call within the cooldown must
        // reuse the fresh credential instead of rotating (and re-`describe`-ing)
        // again — this is what caps the refresh treadmill's request storm.
        let first = refresh_current_session_credential().await;
        let second = refresh_current_session_credential().await;

        assert_eq!(first, Some("tok".to_owned()));
        assert_eq!(second, Some("tok".to_owned()));
        assert_eq!(
            CALLS.with(Cell::get),
            1,
            "a sequential refresh within the cooldown must reuse the fresh credential, not rotate again"
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
