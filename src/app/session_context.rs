//! Session-scoped shared handles provided once at the app root and read by
//! descendant components via `use_context`, replacing the `state_store` /
//! `base_url` prop-drilling chains (arch-review A4 / decision D17 step ②).
//!
//! Both fields are `Signal<_>`, which is `Copy`, so `SessionContext` is `Copy`
//! and reading it through `use_context` is zero-cost. Providing the same signal
//! handles that `RouterView` already owns keeps a single source of truth — the
//! context is a view onto those handles, not a second copy of the state.

use dioxus::prelude::*;

use crate::identity::active_account::ActiveAccountContext;
use crate::state::LocalStateStore;

/// Shared per-login-session handles. Provided in `RouterView` via
/// `use_context_provider`; consumed anywhere below via
/// `use_context::<SessionContext>()`.
#[derive(Clone, Copy)]
pub struct SessionContext {
    /// The authenticated account and its four distinct identity coordinates.
    /// `None` is the only signed-out representation; descendants must not
    /// reconstruct an account from route or free-form DID strings.
    pub active_account: Signal<Option<crate::config::ActiveAccountContext>>,
    /// The app-wide local state store handle (persisted client projection).
    pub state_store: SyncSignal<LocalStateStore>,
    /// The active server base URL. A `Signal<String>` so components that read it
    /// re-render when the user switches servers, matching the old prop chain
    /// where the parent re-passed the value on change.
    pub base_url: Signal<String>,
    /// The authenticated account aggregate. `None` is the only signed-out
    /// representation; principal/full/service/route coordinates are never
    /// reconstructed from the derived UI strings.
    pub active_account: Signal<Option<ActiveAccountContext>>,
    /// Monotonic revision bumped whenever the signed-in account's owned-agent
    /// set changes in Settings → My Agents (provision/pair, pause, resume,
    /// deactivate). The Contacts sidebar subscribes to it and re-pulls
    /// `agent_list`, so a newly paired agent appears — or a deactivated one
    /// disappears — without the user re-opening the tab. My Agents and the
    /// sidebar each fetch their own view of the directory; this is the single
    /// change-notification that bridges them.
    pub owned_agents_rev: Signal<u64>,
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
