//! App-wide, single-flight session-credential coordinator.
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
//! * Every auth-expired handler receives the coordinator explicitly from
//!   [`crate::runtime::services::RuntimeServices`].
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
        crate::identity::device_directory::reset_session_cache();
        crate::identity::contact_profile::reset_session_cache();
        let mut state = self.state.borrow_mut();
        state.credential = Some(credential.into());
        state.generation = state.generation.wrapping_add(1);
        #[cfg(all(target_arch = "wasm32", debug_assertions))]
        tracing::warn!(
            target: "session_state",
            generation = state.generation,
            "session coordinator accepted replacement credential"
        );
        state.generation
    }

    pub fn generation(&self) -> u64 {
        self.state.borrow().generation
    }

    /// Fence work owned by the previous session without revoking or deleting it.
    pub fn suspend(&self) {
        let mut state = self.state.borrow_mut();
        state.generation = state.generation.wrapping_add(1);
        state.credential = None;
        crate::identity::session_refresh::reset_session_grant_runtime();
    }

    pub fn credential(&self) -> Option<String> {
        self.state.borrow().credential.clone()
    }

    pub async fn refresh(&self) -> CurrentSessionRefresh {
        let (refresher, refresh_generation) = {
            let state = self.state.borrow();
            (state.refresher.clone(), state.generation)
        };
        let result = refresher().await;
        {
            let state = self.state.borrow();
            if state.generation != refresh_generation {
                // A login, logout, account switch, or another accepted refresh
                // replaced this attempt while it was awaiting I/O. Never let
                // its late terminal result invalidate the newer session.
                return CurrentSessionRefresh::retry_later(
                    "session changed while refresh was in flight",
                );
            }
        }
        match &result {
            CurrentSessionRefresh::Credential(credential) => {
                self.state.borrow_mut().credential = Some(credential.clone());
            }
            CurrentSessionRefresh::LoginRequired { reason } => {
                self.invalidate(reason.clone());
            }
            CurrentSessionRefresh::SignInRequired { .. }
            | CurrentSessionRefresh::RetryLater { .. } => {}
        }
        result
    }

    pub fn invalidate(&self, reason: impl Into<String>) -> u64 {
        crate::identity::device_directory::reset_session_cache();
        // Resolved co-member Profiles were authorized by this holder's
        // memberships, so they must not survive into the next session.
        crate::identity::contact_profile::reset_session_cache();
        crate::identity::session_refresh::reset_session_grant_runtime();
        let reason = reason.into();
        let invalidator = {
            let mut state = self.state.borrow_mut();
            state.credential = None;
            state.generation = state.generation.wrapping_add(1);
            #[cfg(all(target_arch = "wasm32", debug_assertions))]
            tracing::warn!(
                target: "session_state",
                generation = state.generation,
                %reason,
                "session coordinator invalidated credential"
            );
            state.invalidator.clone()
        };
        if let Some(invalidator) = invalidator {
            invalidator.borrow_mut()(reason);
        }
        self.generation()
    }

    /// Invalidate only when the caller still belongs to the active session.
    ///
    /// Async bootstrap and projection tasks capture a generation before they
    /// await I/O. A completed login replaces the credential and advances the
    /// generation, so a late denial from the older task must not log out the
    /// replacement session.
    pub fn invalidate_if_generation(
        &self,
        expected_generation: u64,
        reason: impl Into<String>,
    ) -> bool {
        if self.generation() != expected_generation {
            return false;
        }
        self.invalidate(reason);
        true
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn authentication_transaction_fences_old_denials_without_logout() {
        // Session cache mutations share the signer/scope tests' process-wide fence.
        let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
        let coordinator = SessionCoordinator::new(|| {
            Box::pin(async { CurrentSessionRefresh::retry_later("unused") })
        });
        let old = coordinator.replace("old");
        let invalidations = Rc::new(RefCell::new(0));
        let observed = invalidations.clone();
        coordinator.set_invalidator(move |_| *observed.borrow_mut() += 1);
        coordinator.suspend();
        assert!(!coordinator.invalidate_if_generation(old, "late old 401"));
        assert_eq!(*invalidations.borrow(), 0);
        let pending = coordinator.generation();
        coordinator.replace("new");
        assert!(!coordinator.invalidate_if_generation(pending, "late callback-era 401"));
        assert_eq!(coordinator.credential().as_deref(), Some("new"));
    }

    #[tokio::test]
    async fn returns_registered_refresher_result() {
        let coordinator = SessionCoordinator::new(|| {
            Box::pin(async { CurrentSessionRefresh::Credential("fresh-credential".to_owned()) })
        });
        assert_eq!(
            coordinator.refresh().await,
            CurrentSessionRefresh::Credential("fresh-credential".to_owned())
        );
    }

    #[tokio::test]
    async fn preserves_retry_later_refresh_result() {
        // Session cache mutations share the signer/scope tests' process-wide fence.
        let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
        let coordinator = SessionCoordinator::new(|| {
            Box::pin(async { CurrentSessionRefresh::retry_later("account authority unavailable") })
        });
        let invalidated = Rc::new(RefCell::new(false));
        coordinator.set_invalidator({
            let invalidated = invalidated.clone();
            move |_| *invalidated.borrow_mut() = true
        });
        coordinator.replace("still-accepted-credential");

        assert_eq!(
            coordinator.refresh().await,
            CurrentSessionRefresh::RetryLater {
                reason: "account authority unavailable".to_owned(),
            }
        );
        assert!(!*invalidated.borrow());
        assert_eq!(
            coordinator.credential().as_deref(),
            Some("still-accepted-credential")
        );
    }

    #[tokio::test]
    async fn late_refresh_cannot_invalidate_a_replacement_session() {
        // Session cache mutations share the signer/scope tests' process-wide fence.
        let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let receiver = Rc::new(RefCell::new(Some(receiver)));
        let coordinator = SessionCoordinator::new({
            let receiver = receiver.clone();
            move || {
                let receiver = receiver
                    .borrow_mut()
                    .take()
                    .expect("refresh is invoked once");
                Box::pin(async move { receiver.await.expect("test refresh result") })
            }
        });
        let invalidated = Rc::new(RefCell::new(false));
        coordinator.set_invalidator({
            let invalidated = invalidated.clone();
            move |_| *invalidated.borrow_mut() = true
        });

        let mut pending_refresh = Box::pin(coordinator.refresh());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), &mut pending_refresh)
                .await
                .is_err(),
            "the old refresh must be waiting when the replacement is installed"
        );
        coordinator.replace("replacement-credential");
        sender
            .send(CurrentSessionRefresh::LoginRequired {
                reason: "old grant was revoked".to_owned(),
            })
            .expect("deliver stale refresh result");

        assert_eq!(
            pending_refresh.await,
            CurrentSessionRefresh::RetryLater {
                reason: "session changed while refresh was in flight".to_owned(),
            }
        );
        assert!(!*invalidated.borrow());
        assert_eq!(
            coordinator.credential().as_deref(),
            Some("replacement-credential")
        );
    }

    #[test]
    fn stale_task_cannot_invalidate_a_replacement_session() {
        // Session cache mutations share the signer/scope tests' process-wide fence.
        let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
        let coordinator = SessionCoordinator::new(|| {
            Box::pin(async { CurrentSessionRefresh::retry_later("unused") })
        });
        let invalidated = Rc::new(RefCell::new(false));
        coordinator.set_invalidator({
            let invalidated = invalidated.clone();
            move |_| *invalidated.borrow_mut() = true
        });

        let stale_generation = coordinator.generation();
        coordinator.replace("replacement-credential");

        assert!(!coordinator.invalidate_if_generation(stale_generation, "late bootstrap denial"));
        assert!(!*invalidated.borrow());
        assert_eq!(
            coordinator.credential().as_deref(),
            Some("replacement-credential")
        );
    }

    #[test]
    fn invalidator_invokes_registered_hook() {
        // Session cache mutations share the signer/scope tests' process-wide fence.
        let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
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
        coordinator.invalidate("session grant revoked");

        assert_eq!(
            REASON.with(|slot| slot.borrow().clone()),
            Some("session grant revoked".to_owned())
        );
    }
}
