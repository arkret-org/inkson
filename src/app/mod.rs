//! Application composition over an explicit, single-window runtime.
use std::collections::BTreeSet;

#[cfg(any(
    test,
    all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test")
))]
use serde_json::Value;

use crate::config::{ClientConfig, LocalConfigStore, normalize_server_url};
use crate::conformance::StationFeature;
use crate::i18n::UiLocale;
use crate::models::{
    RealmTreeNode, ServiceDescribe, missing_v1_station_requirements,
    projection_realm_id_for_known_node,
};
pub(crate) use crate::realm_tree::realm_tree_nodes_from_sync_realms_with_roles;
use crate::routes::Route;
use crate::state::projection::ProjectionEvent;
use crate::state::{ClientLocalState, LocalStateStore, PersistedSessionGrant};
use crate::transport::TransportClient;
use crate::views::ConnectionState;
use crate::views::helpers::{persist_config, short_protocol_id};
#[path = "../bootstrap.rs"]
mod bootstrap;
pub(crate) use bootstrap::*;
mod theme;
pub(crate) use theme::*;
mod realm_surface;
mod web_leader;
pub(crate) use realm_surface::*;
pub mod account_switch;
mod clipboard;
pub(crate) mod runtime_adapter;
pub(crate) use clipboard::*;
mod command_palette;
mod connect;
use connect::*;
mod connection_effects;
mod connection_handlers;
mod context_bar;
pub(crate) mod direct_open;
mod feature_gate;
pub(crate) use feature_gate::*;
mod fold_evidence_effects;
mod global_effects;
#[cfg(any(target_arch = "wasm32", test))]
mod global_shortcuts;
mod glory_root;
#[cfg(all(not(target_arch = "wasm32"), feature = "desktop"))]
pub(crate) use glory_root::native_root;
pub use glory_root::root;
mod handles;
pub(crate) use handles::*;
mod manage_pages;
mod mls_recovery_effects;
mod mls_runtime_effects;
mod notifications_drawer;
mod projection_adapter;
mod recovery_effects;
mod recovery_reminder_effects;
mod route_surface;
pub(crate) use route_surface::direct_conversation_peer_id;
mod secure_store_effects;
mod session_boot;
pub(crate) use session_boot::*;
#[cfg(test)]
mod session_context;
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) use session_context::ContactInbox;
mod session_commands;
mod session_shell;
mod shell_effects;
mod shell_model;
mod shell_state;
mod sidebar;
use sidebar::*;
mod sidebar_width;
use sidebar_width::*;
mod signal_products;
mod sync_effects;
pub(crate) fn principal_id_text(principal_id: &Option<arkret_sdk::DidCoreId>) -> &str {
    principal_id
        .as_ref()
        .map(arkret_sdk::DidCoreId::as_str)
        .unwrap_or_default()
}

pub(crate) fn principal_id_owned(principal_id: Option<arkret_sdk::DidCoreId>) -> String {
    principal_id
        .map(|value| value.to_string())
        .unwrap_or_default()
}

const SIDEBAR_WIDTH_PREFERENCE_KEY: &str = "layout.sidebar.width";
const DEFAULT_SIDEBAR_WIDTH: f64 = 320.0;
const MIN_SIDEBAR_WIDTH: f64 = 280.0;
const MAX_SIDEBAR_WIDTH: f64 = 420.0;

/// Cursor the account-sync signal boots with.
///
/// A protocol cursor is always `ak:cursor:<base64url(canonical_json)>`
/// (`sync/api-conventions.md`), so "no resume checkpoint yet" has exactly one
/// representation: the empty string — the same value every reset path
/// (`connect`, sign-out, account switch) writes. A placeholder token would be
/// a fake cursor that readiness checks must special-case and that could be
/// echoed into a `wait_for` query or a cursor header.
pub(crate) fn initial_sync_cursor(persisted: Option<String>) -> String {
    persisted.unwrap_or_default()
}

/// Whether the account stream has produced a resume checkpoint yet.
///
/// Readiness is the ONLY thing view code may derive from the cursor: the token
/// is an opaque checkpoint the server may re-mint for the same frontier, so it
/// is not a render revision. Durable content freshness comes from the per-realm
/// live epoch instead.
pub(crate) fn account_sync_ready(cursor: &str) -> bool {
    !cursor.trim().is_empty()
}

#[cfg(not(target_arch = "wasm32"))]
fn read_native_bootstrap<T: Send + 'static>(read: impl FnOnce() -> T + Send + 'static) -> T {
    // Desktop rendering already runs inside Tokio. Secret Service's blocking
    // client owns another Tokio runtime, so boot reads need a separate thread.
    std::thread::spawn(read)
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

fn read_bootstrap_snapshot(
    config_store: LocalConfigStore,
    state_store: LocalStateStore,
) -> (ClientConfig, LocalStateStore, ClientLocalState) {
    let read = move || {
        let config = config_store.load();
        let state = state_store.load();
        (config, state_store, state)
    };
    #[cfg(not(target_arch = "wasm32"))]
    {
        read_native_bootstrap(read)
    }
    #[cfg(target_arch = "wasm32")]
    {
        read()
    }
}

#[cfg(test)]
#[path = "../app_tests.rs"]
mod tests;
