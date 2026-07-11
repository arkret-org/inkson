//! Session-scoped shared handles provided once at the app root and read by
//! descendant components via `use_context`, replacing the `state_store` /
//! `base_url` prop-drilling chains (arch-review A4 / decision D17 step ②).
//!
//! Both fields are `Signal<_>`, which is `Copy`, so `SessionContext` is `Copy`
//! and reading it through `use_context` is zero-cost. Providing the same signal
//! handles that `RouterView` already owns keeps a single source of truth — the
//! context is a view onto those handles, not a second copy of the state.

use dioxus::prelude::*;

use crate::state::LocalStateStore;

/// Shared per-login-session handles. Provided in `RouterView` via
/// `use_context_provider`; consumed anywhere below via
/// `use_context::<SessionContext>()`.
#[derive(Clone, Copy)]
pub struct SessionContext {
    /// The app-wide local state store handle (persisted client projection).
    pub state_store: SyncSignal<LocalStateStore>,
    /// The active server base URL. A `Signal<String>` so components that read it
    /// re-render when the user switches servers, matching the old prop chain
    /// where the parent re-passed the value on change.
    pub base_url: Signal<String>,
}

impl SessionContext {
    /// Fetch the provided context. Panics if called outside a `RouterView`
    /// subtree, which is a programming error (every component runs under it).
    pub fn get() -> Self {
        use_context::<SessionContext>()
    }

    /// Convenience: the current base URL as an owned `String`. Subscribes the
    /// caller to base-url changes (same reactivity as the old `base_url: String`
    /// prop, which re-rendered when the parent re-passed it).
    pub fn base_url_string() -> String {
        Self::get().base_url.read().clone()
    }
}
