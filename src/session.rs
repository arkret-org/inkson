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
//! * The app root constructs one typed [`SessionCoordinator`] and provides it through
//!   [`crate::runtime::services::RuntimeServices`].
//! * Every auth-expired handler reaches the installed coordinator through
//!   [`refresh_current_session_credential`] while call sites migrate to receiving the coordinator
//!   explicitly.
//!
//! Rotation single-flight and cooldown semantics live in garth's long-lived
//! `SessionEngine`; this module only owns the app callback and result mapping.

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;

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

struct SessionCoordinatorState {
    refresher: RefreshFn,
    invalidator: Option<InvalidateFn>,
    credential: Option<String>,
    generation: u64,
}

#[derive(Clone)]
pub struct SessionCoordinator {
    state: Rc<RefCell<SessionCoordinatorState>>,
}

impl SessionCoordinator {
    pub fn new(refresher: impl Fn() -> LocalRefreshFuture + 'static) -> Self {
        Self {
            state: Rc::new(RefCell::new(SessionCoordinatorState {
                refresher: Rc::new(refresher),
                invalidator: None,
                credential: None,
                generation: 0,
            })),
        }
    }

    pub fn set_invalidator(&self, invalidator: impl FnMut(String) + 'static) {
        self.state.borrow_mut().invalidator = Some(Rc::new(RefCell::new(invalidator)));
    }

    pub fn replace(&self, credential: impl Into<String>) -> u64 {
        let mut state = self.state.borrow_mut();
        state.credential = Some(credential.into());
        state.generation = state.generation.wrapping_add(1);
        state.generation
    }

    pub fn generation(&self) -> u64 {
        self.state.borrow().generation
    }

    pub fn credential(&self) -> Option<String> {
        self.state.borrow().credential.clone()
    }

    pub async fn refresh(&self) -> CurrentSessionRefresh {
        let refresher = self.state.borrow().refresher.clone();
        let result = refresher().await;
        if let CurrentSessionRefresh::Credential(credential) = &result {
            self.state.borrow_mut().credential = Some(credential.clone());
        }
        result
    }

    pub fn invalidate(&self, reason: impl Into<String>) -> u64 {
        crate::session_refresh::reset_session_grant_runtime();
        let reason = reason.into();
        let invalidator = {
            let mut state = self.state.borrow_mut();
            state.credential = None;
            state.generation = state.generation.wrapping_add(1);
            state.invalidator.clone()
        };
        if let Some(invalidator) = invalidator {
            invalidator.borrow_mut()(reason);
        }
        self.generation()
    }
}

thread_local! {
    static CURRENT_COORDINATOR: RefCell<Option<SessionCoordinator>> = const { RefCell::new(None) };
}

/// Install the app-owned typed coordinator for compatibility call sites that
/// have not yet been migrated to receive it explicitly.
pub fn install_session_coordinator(coordinator: SessionCoordinator) {
    CURRENT_COORDINATOR.with(|slot| *slot.borrow_mut() = Some(coordinator));
}

/// Clear the active UI session through the registered app hook. Safe to
/// call from lower-level API helpers; if the hook has not been installed
/// yet, this is a no-op.
pub fn invalidate_current_session(reason: impl Into<String>) {
    let reason = reason.into();
    CURRENT_COORDINATOR.with(|slot| {
        if let Some(coordinator) = slot.borrow().as_ref() {
            coordinator.invalidate(reason);
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
    let Some(coordinator) = CURRENT_COORDINATOR.with(|slot| slot.borrow().clone()) else {
        return no_refresher_result();
    };
    coordinator.refresh().await
}

fn no_refresher_result() -> CurrentSessionRefresh {
    CurrentSessionRefresh::retry_later("session refresher is not registered")
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_registered_refresher_result() {
        install_session_coordinator(SessionCoordinator::new(|| {
            Box::pin(async { CurrentSessionRefresh::Credential("fresh-credential".to_owned()) })
        }));
        assert_eq!(
            refresh_current_session_credential().await,
            Some("fresh-credential".to_owned())
        );
    }

    #[tokio::test]
    async fn preserves_retry_later_refresh_result() {
        install_session_coordinator(SessionCoordinator::new(|| {
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

    #[test]
    fn invalidator_invokes_registered_hook() {
        thread_local! {
            static REASON: RefCell<Option<String>> = const { RefCell::new(None) };
        }
        REASON.with(|slot| *slot.borrow_mut() = None);
        let coordinator = SessionCoordinator::new(|| {
            Box::pin(async { CurrentSessionRefresh::retry_later("unused") })
        });
        coordinator.set_invalidator(|reason| {
            REASON.with(|slot| *slot.borrow_mut() = Some(reason));
        });
        install_session_coordinator(coordinator);

        invalidate_current_session("session grant revoked");

        assert_eq!(
            REASON.with(|slot| slot.borrow().clone()),
            Some("session grant revoked".to_owned())
        );
    }
}
