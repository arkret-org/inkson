use std::collections::{BTreeMap, BTreeSet};

use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use dioxus_router::hooks::*;
use dioxus_router::{Link, Navigator, Outlet, Router};
use serde_json::Value;

use crate::api::CokretApi;
use crate::api_error::is_auth_expired_error;
use crate::components::{SecurityStateBadge, UiIcon};
use crate::config::{ClientConfig, LocalConfigStore, normalize_device_id, normalize_server_url};
use crate::conformance::{
    PROFILE_E2EE_CLIENT, PROFILE_FULL_CLIENT, PROFILE_KANBAN_MVP, PROFILE_MINIMAL_CLIENT,
    profile_ready,
};
use crate::i18n::{Locale, TextDirection};
use crate::local_state::{
    ClientLocalState, LocalStateStore, PersistedSessionGrant, default_strand_id_for_realm,
};
use crate::models::{
    RealmTreeNode, RealmTreeNodeKind, ServerDescription, ServerDescriptionExt,
    projection_realm_id_for_known_node,
};
use crate::projection::ProjectionEvent;
// R28-B — realm-tree / projection / field-extraction helpers moved to
// `crate::realm_tree`. Re-export the two `pub` entry points used by
// `crate::sync_engine` so the existing `crate::app::…` call sites keep
// resolving without a sync_engine edit.
pub(crate) use crate::realm_tree::{
    descendant_node_ids, full_sync_projection_keep_set, realm_projection_is_encrypted,
    realm_tree_items_with_pinned_realms, realm_tree_node_looks_like_direct_conversation,
    realm_tree_nodes_from_sync_realms,
};
use crate::routes::Route;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::input::Input;
use crate::views::ConnectionState;
use crate::views::helpers::{display_name_for_did, persist_config, short_protocol_id};

const REALM_KEY_SHARE_ANSWER_RETRY_BACKOFF_MS: u64 = 60_000;

// YOU-07-001: post-login / startup-check effects and small types moved to
// `crate::app::bootstrap` (move-only; logic, signatures, and bytes unchanged).
// The re-export keeps existing app.rs call sites and `app_tests.rs`
// `use super::*` resolution paths unchanged.
#[path = "../bootstrap.rs"]
mod bootstrap;
pub(crate) use bootstrap::*;
// YOU-07-001: theme-resolution helpers (system/shell dark-mode detection, the
// `<html>` data-theme mirror, manual toggle) live in `app/theme.rs` (move only).
// The glob re-export keeps the inline call sites and `app_tests.rs` `use super::*`
// resolution unchanged.
mod theme;
pub(crate) use theme::*;
// YOU-07-001: per-realm surface selection (RealmSurface enum + preference
// load/persist + route→surface resolution) lives in `app/realm_surface.rs`
// (move only). The glob re-export keeps inline call sites and `app_tests.rs`
// `use super::*` resolution unchanged.
mod realm_surface;
pub(crate) use realm_surface::*;

// Structural split: non-component helpers, data-assembly routines, the
// session-boot state machine, and the secondary `#[component]` pages
// (`RealmsManagePage`, `ContactsManagePage`, `RealmContextBar`,
// `CommandPalette`, ...) moved out of this file into sibling `app/*.rs`
// modules (move only). The root `RouterView` component is left inline — it is
// a single Dioxus `#[component]` that cannot be split across files. Each glob
// re-export keeps the inline call sites and `app_tests.rs` `use super::*`
// resolution unchanged.
mod clipboard;
mod command_palette;
mod connect;
mod context_bar;
mod feature_gate;
mod handles;
mod manage_pages;
mod session_boot;
mod sidebar;
mod sidebar_width;
pub(crate) use clipboard::*;
pub(crate) use command_palette::*;
use connect::*;
pub(crate) use context_bar::*;
pub(crate) use feature_gate::*;
pub(crate) use handles::*;
pub(crate) use manage_pages::*;
use session_boot::*;
use sidebar::*;
use sidebar_width::*;

const UI_PREFERENCES_SCOPE: &str = "ui.browser";
const SIDEBAR_WIDTH_PREFERENCE_KEY: &str = "layout.sidebar.width";
const DEFAULT_SIDEBAR_WIDTH: f64 = 320.0;
const OP_LIST_HANDLES_FOR_SUBJECT: &str = "ck.find.directory.query.list_handles_for_subject";
const MIN_SIDEBAR_WIDTH: f64 = 280.0;
const MAX_SIDEBAR_WIDTH: f64 = 420.0;

fn try_set_signal<T: 'static>(mut signal: Signal<T>, value: T) {
    if let Ok(mut slot) = signal.try_write() {
        *slot = value;
    }
}

// Each stylesheet below is assembled from semantic section files via `concat!`.
// Injection order is explicit here rather than encoded in file-name prefixes.
const STYLE: &str = concat!(
    include_str!("../styles/app/base-auth-layout.css"),
    include_str!("../styles/app/accessibility-responsive-print.css"),
    include_str!("../styles/app/app-theme-shell.css"),
    include_str!("../styles/app/workflow-card-detail.css"),
    include_str!("../styles/app/workflow-card-assignees.css"),
    include_str!("../styles/app/workflow-editor-settings.css"),
    include_str!("../styles/app/shell-contacts-settings.css"),
);

const DESIGN_STYLE: &str = concat!(
    include_str!("../styles/design/tokens-reset-i18n.css"),
    include_str!("../styles/design/controls-gallery-chrome.css"),
    include_str!("../styles/design/common-components.css"),
    include_str!("../styles/design/auth-kanban-strand-chat.css"),
    include_str!("../styles/design/event-mobile-device-tables-call.css"),
    include_str!("../styles/design/discovery-metrics-errors-doc-content.css"),
);

const APP_OVERRIDES: &str = concat!(
    include_str!("../styles/app_overrides/theme-shell-overrides.css"),
    include_str!("../styles/app_overrides/watch-handle-e2ee-tabs.css"),
    include_str!("../styles/app_overrides/circle-composer-mentions.css"),
    include_str!("../styles/app_overrides/sidebar-actions.css"),
    include_str!("../styles/app_overrides/account-trigger-menu.css"),
    include_str!("../styles/app_overrides/members-agents-admin.css"),
);

/// C3: yoface shared-component design tokens. The first layer is shadcn
/// semantic tokens (`--primary/--background/--foreground/...`); the second
/// layer is dioxus-components compatibility aliases
/// (`--primary-color-N/--focused-border-color/...`) used by `yoface::ui::*`
/// `#[css_module]` styles. Values come from the inkson green palette (yoface
/// tokens.css matches inkson design.css), so this keeps the existing
/// `var(--dark,...)` / `var(--light,...)` and `[data-theme]` switches and the
/// current inkson green appearance. This replaces the vendored
/// `assets/dx-components-theme.css` black/white defaults. Injection order stays
/// before the three existing style blocks so later design.css/app_overrides can
/// override these tokens.
const DXC_THEME: &str = yoface::TOKENS_CSS;

#[component]
pub fn App() -> Element {
    ensure_default_push_token_provider();
    use_hook(crate::notification_sound::initialize_notification_audio);
    rsx! {
        Router::<Route> {}
    }
}

#[component]
pub fn RouterView() -> Element {
    let initial_config = LocalConfigStore::default().load();
    let initial_state_store = LocalStateStore::default();
    let initial_local_state = initial_state_store.load();
    let initial_session_credential = initial_session_credential_from_state(
        &initial_local_state,
        &initial_config,
        chrono::Utc::now().timestamp(),
    );
    let initial_can_restore_session = has_bootstrap_refresh_material(
        &initial_state_store,
        &initial_config.server_url,
        &initial_config.account_did,
    );
    let initial_secure_store_bootstrap_ready = !cfg!(target_arch = "wasm32");
    let initial_session_boot_state = session_boot_state_from_bootstrap_material(
        &initial_session_credential,
        initial_can_restore_session,
        &initial_config.account_did,
        initial_secure_store_bootstrap_ready,
    );
    let initial_realm_tree_nodes =
        realm_tree_nodes_from_sync_realms(&initial_local_state.realm_tree_projections);
    let initial_sidebar_width = load_sidebar_width_preference(&initial_state_store);
    let initial_locale = initial_state_store
        .load_private_data(&initial_config.account_did, "locale")
        .map(|code| Locale::from_code(&code))
        .unwrap_or_default();
    let initial_theme = initial_state_store
        .load_private_data(&initial_config.account_did, "theme")
        .filter(|theme| matches!(theme.as_str(), "light" | "night" | "system"))
        .unwrap_or_else(|| "night".to_owned());
    // Rehydrate the persisted primary handle for the booted account so any
    // signed-out diagnostics can identify the account by handle on a fresh
    // load, instead of falling back to the raw DID. Reads the per-account entry
    // by DID (not the active account), so it works regardless of which account
    // is currently active.
    let initial_account_primary_handle = initial_state_store
        .primary_handle_for_did(&initial_config.account_did)
        .filter(|handle| !handle.trim().is_empty())
        .or_else(|| {
            initial_state_store.load_private_data(
                &initial_config.account_did,
                &account_primary_handle_storage_key(&initial_config.account_did),
            )
        })
        .unwrap_or_default();
    let config_store = use_signal(LocalConfigStore::default);
    let mut state_store = use_signal(LocalStateStore::default);
    // Move-into-signal initialisers. Each `use_signal(...)` runs once on
    // first render, so we pre-extract the fields and hand each closure a
    // ready-to-move `String` instead of repeatedly cloning the whole
    // `initial_config` struct.
    let initial_server_url = initial_config.server_url.clone();
    let initial_account_did = initial_config.account_did.clone();
    let initial_device_id = initial_config.device_id.clone();
    // Pin the active per-account device-seed scope to the persisted account on
    // boot, before any async secure-store effect activates the device signer.
    // Without this the process-global scope would default to bootstrap after a
    // reload and the signer would read an empty bootstrap seed instead of this
    // account's device key. Login completion (`adopt_device_seed_scope_on_login`)
    // updates the scope when a different principal signs in.
    {
        let boot_seed_scope = initial_config.account_did.clone();
        use_hook(move || {
            let scope = boot_seed_scope.trim();
            crate::secure_key_store::set_active_device_seed_scope(
                (!scope.is_empty()).then_some(scope),
            );
        });
    }
    let base_url = use_signal(move || initial_server_url);
    let mut account_did = use_signal(move || initial_account_did);
    let device_id = use_signal(move || initial_device_id);
    let mut token = use_signal(move || initial_session_credential);
    let mut session_boot_state = use_signal(move || initial_session_boot_state);
    let mut session_generation = use_signal(|| 0_u64);

    // Install the app-wide, single-flight session credential refresher exactly once.
    // Every auth-expired handler (connect, sync, chat send, Realm create,
    // the account-menu button, the background poller) routes through
    // this one closure via `crate::session::refresh_current_session()`, so
    // refresh policy lives in a single place and concurrent rollovers
    // coalesce instead of racing.
    use_hook(move || {
        crate::session::register_session_refresher(std::rc::Rc::new(move || {
            Box::pin(refresh_session_credential_for_active_context(
                base_url,
                account_did,
                device_id,
                state_store,
                token,
                config_store,
                session_generation,
            )) as crate::session::LocalRefreshFuture
        }));
    });

    // Dev-only (wasm + `allow_localstorage_secrets`) real-grant injection for the
    // cotest joint e2e harness. Runs once, synchronously, ahead of the bootstrap
    // `connect()` below so the first `/_cokret/self/*` request already carries a
    // valid grant + DPoP proof. Inert in production (neither localStorage
    // key is set) and a no-op on native. See `inject_test_session_grant`.
    #[cfg(target_arch = "wasm32")]
    {
        let mut state_store = state_store;
        let mut token = token;
        use_hook(move || {
            if let Some(grant_jwt) = inject_test_session_grant(
                &mut state_store,
                config_store,
                &base_url(),
                &account_did(),
                &device_id(),
            ) {
                token.set(grant_jwt);
            }
        });
    }

    let navigator = use_navigator();
    let route = use_route::<Route>();
    let mut view = use_signal(|| route.to_view());
    let current_route_uses_realm_context = route_uses_realm_context(&route);
    let mut realm_events_route_enabled = use_signal(move || current_route_uses_realm_context);
    if *realm_events_route_enabled.peek() != current_route_uses_realm_context {
        realm_events_route_enabled.set(current_route_uses_realm_context);
    }
    // Connection-lifecycle status only (offline / restoring / online / session
    // expired). Operation feedback now goes through the toast queue in
    // `crate::components::feedback` — never through this signal.
    let connection_status = use_signal(|| ConnectionState::Offline.label().to_owned());
    let initial_sync_cursor = initial_local_state
        .sync_cursor
        .clone()
        .unwrap_or_else(|| "-".to_owned());
    let initial_selected_realm_id = initial_realm_tree_nodes
        .iter()
        .find(|node| node.kind == RealmTreeNodeKind::Realm)
        .map(|node| node.id.clone())
        .unwrap_or_default();
    let initial_push_state =
        crate::push::push_status_label(initial_local_state.push_registration.as_ref());
    let initial_realm_tree_nodes_for_signal = initial_realm_tree_nodes.clone();
    let mut sync_cursor = use_signal(move || initial_sync_cursor);
    // Liveness counter for the per-realm `events/subscribe` engine
    // (`crate::realm_events_engine`). Bumped when that engine folds fresh realm
    // events the account stream never delivered (cross-member case); the kanban
    // panel reads it as a second freshness axis besides `sync_cursor`.
    let realm_live_epoch = use_signal(|| 0u64);
    let mut selected_realm_id = use_signal(move || initial_selected_realm_id);
    let mut new_space_context_node = use_signal(String::new);
    let mut realm_tree_nodes = use_signal(move || initial_realm_tree_nodes_for_signal);
    let mut projection_events = use_signal(Vec::<ProjectionEvent>::new);
    let mut device_queue = use_signal(|| 0usize);
    let push_state = use_signal(move || initial_push_state);
    let frontier_state = use_signal(|| "Not loaded".to_owned());
    let crypto_state = use_signal(|| "No authenticated session".to_owned());
    let network_state = use_signal(|| "offline".to_owned());
    let mut last_error = use_signal(|| Option::<String>::None);
    let server_description = use_signal(|| Option::<ServerDescription>::None);
    let server_probe_status = use_signal(|| "server not probed".to_owned());
    let locale = use_signal(move || initial_locale);
    let secure_store_bootstrap_ready = use_signal(move || initial_secure_store_bootstrap_ready);
    #[cfg(target_arch = "wasm32")]
    {
        let config_store_for_secure_upgrade = config_store;
        let base_url_for_secure_upgrade = base_url;
        let account_did_for_secure_upgrade = account_did;
        let mut device_id_for_secure_upgrade = device_id;
        let mut state_store_for_secure_upgrade = state_store;
        let mut secure_store_ready_for_upgrade = secure_store_bootstrap_ready;
        let mut token_for_secure_upgrade = token;
        use_future(move || async move {
            crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(1)).await;
            tracing::warn!(target: "secure_store", "secure store upgrade: invoking upgrade_wasm_secure_key_store_async");
            match crate::secure_key_store::upgrade_wasm_secure_key_store_async("inkson").await {
                Ok(Some(secure_store)) => {
                    tracing::warn!(target: "secure_store", "secure store upgrade: Ok(Some) — IndexedDb tier installed");
                    let loaded_config = config_store_for_secure_upgrade
                        .read()
                        .load_with_secure_store(secure_store.as_ref());
                    let held_token = token_for_secure_upgrade.peek().trim().to_owned();
                    {
                        let grant_present = state_store_for_secure_upgrade
                            .read()
                            .session_grant()
                            .map(|g| !g.grant_jwt.trim().is_empty())
                            .unwrap_or(false);
                        tracing::warn!(
                            target: "secure_store",
                            held_token_empty = held_token.is_empty(),
                            config_credential_present = !loaded_config.session_credential.trim().is_empty(),
                            local_state_session_grant_present = grant_present,
                            "secure store upgrade: post-upgrade credential sources (held_token from memory, config.session_credential, local_state.session_grant)"
                        );
                    }
                    if held_token.is_empty() {
                        if let Some(rehydrated) = rehydrated_session_credential_for_active_config(
                            &loaded_config,
                            &base_url_for_secure_upgrade(),
                            &account_did_for_secure_upgrade(),
                            &device_id_for_secure_upgrade(),
                        ) {
                            tracing::warn!(target: "secure_store", "secure store upgrade: rehydrated token from config.session_credential — session should restore");
                            token_for_secure_upgrade.set(rehydrated);
                        }
                    } else {
                        // A credential is already held in memory: sign-in completed
                        // BEFORE this IndexedDB secure-store upgrade was ready, so
                        // `config.rs` could only reach the localStorage tier, which
                        // refuses session credentials. Now that the upgraded store is
                        // installed, re-persist it so the session survives a reload /
                        // re-render instead of bouncing back to /login.
                        persist_config(
                            config_store_for_secure_upgrade,
                            base_url_for_secure_upgrade(),
                            account_did_for_secure_upgrade(),
                            device_id_for_secure_upgrade(),
                            held_token,
                        );
                    }
                    let dpop_record = {
                        let store = state_store_for_secure_upgrade.read();
                        store.load_dpop_device_key_with_secure_store(secure_store.as_ref())
                    };
                    match dpop_record {
                        Ok(Some(record)) => {
                            if let Err(error) = state_store_for_secure_upgrade
                                .write()
                                .set_dpop_device_key_with_secure_store(
                                    Some(record),
                                    secure_store.as_ref(),
                                )
                            {
                                tracing::warn!(
                                    ?error,
                                    "IndexedDB DPoP key metadata refresh failed",
                                );
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            tracing::warn!(?error, "IndexedDB DPoP key load failed");
                        }
                    }
                    // Pin the stable, account-scoped `device_id` from the secure
                    // store as the authoritative source BEFORE the bootstrap
                    // `connect()` (gated on `secure_store_bootstrap_ready` below)
                    // publishes an MLS KeyPackage. The `config.json` blob's
                    // `device_id` is only a mirror: when the blob is not recovered
                    // at early boot, `LocalConfigStore::load()` falls back to a
                    // freshly-minted phantom `device_id`. An MLS KeyPackage
                    // published under a phantom strands its retained private init
                    // key (which is device-scoped in the secure store via
                    // `mls_key_package_identity_state_key`), so the to-device
                    // Welcome can never be decrypted ("no local KeyPackage identity
                    // state"). Resolving from the seed-paired secure-store entry
                    // makes `device_id` exactly as stable as the signing seed
                    // across reloads and re-logins of the same account.
                    let stable_device_id_for_signer = {
                        let store = secure_store.as_ref();
                        let account_scope = account_did_for_secure_upgrade.peek().trim().to_owned();
                        if account_scope.is_empty() {
                            tracing::warn!(
                                target: "secure_store",
                                "device identity signer bootstrap skipped: no account scope yet"
                            );
                            None
                        } else {
                            crate::secure_key_store::set_active_device_seed_scope(Some(
                                &account_scope,
                            ));
                            let current = device_id_for_secure_upgrade.peek().trim().to_owned();
                            let resolved = match crate::secure_key_store::load_device_id_scoped(
                                store,
                                Some(&account_scope),
                            ) {
                                Ok(Some(existing)) => Some(existing),
                                Ok(None) => {
                                    let chosen = if crate::config::is_valid_device_id(&current) {
                                        current.clone()
                                    } else {
                                        crate::config::new_device_id()
                                    };
                                    match crate::secure_key_store::store_device_id_scoped(
                                        store,
                                        Some(&account_scope),
                                        &chosen,
                                    ) {
                                        Ok(()) => Some(chosen),
                                        Err(error) => {
                                            tracing::warn!(target: "secure_store", ?error, "persist stable device_id failed");
                                            None
                                        }
                                    }
                                }
                                Err(error) => {
                                    tracing::warn!(target: "secure_store", ?error, "load stable device_id failed");
                                    None
                                }
                            };
                            match resolved {
                                Some(resolved) => {
                                    if resolved != current {
                                        tracing::warn!(
                                            target: "secure_store",
                                            stale = %current,
                                            stable = %resolved,
                                            "pinning stable device_id from secure store (config blob value was phantom/stale)"
                                        );
                                        device_id_for_secure_upgrade.set(resolved.clone());
                                        persist_config(
                                            config_store_for_secure_upgrade,
                                            base_url_for_secure_upgrade(),
                                            account_did_for_secure_upgrade(),
                                            resolved.clone(),
                                            token_for_secure_upgrade.peek().trim().to_owned(),
                                        );
                                    }
                                    Some(resolved)
                                }
                                None if crate::config::is_valid_device_id(&current) => {
                                    Some(current)
                                }
                                None => None,
                            }
                        }
                    };
                    match stable_device_id_for_signer {
                        Some(stable_device_id) => {
                            match crate::event_signer::bootstrap_default_signer_for_device(
                                "inkson",
                                &stable_device_id,
                            ) {
                                Ok(_) => {
                                    tracing::info!(
                                        target: "secure_store",
                                        device_id = %stable_device_id,
                                        "IndexedDB device identity signer bootstrap succeeded"
                                    );
                                }
                                Err(error) => {
                                    tracing::warn!(
                                        target: "secure_store",
                                        ?error,
                                        "IndexedDB device identity signer bootstrap failed"
                                    );
                                }
                            }
                        }
                        None => {
                            tracing::warn!(
                                target: "secure_store",
                                "IndexedDB device identity signer bootstrap skipped: no stable device_id"
                            );
                        }
                    }
                }
                Ok(None) => {
                    tracing::warn!(
                        target: "secure_store",
                        "secure store upgrade: Ok(None) — IndexedDB/SubtleCrypto reported UNAVAILABLE; staying on disabled localStorage tier; ALL account secrets and session credentials WILL fail (this is the Restoring-session hang root)"
                    );
                }
                Err(error) => {
                    tracing::warn!(target: "secure_store", ?error, "secure store upgrade: Err — IndexedDB secure-key-store upgrade failed");
                }
            }
            tracing::warn!(target: "secure_store", "secure store upgrade: settled, marking secure_store_bootstrap_ready=true");
            secure_store_ready_for_upgrade.set(true);
        });
    }
    // Provide i18n context for views that call `crate::i18n::tr(key)`.
    // The locale field stays in sync with `locale` via the use_effect
    // below; the dictionary tables are baked once at boot.
    let i18n_signal = use_context_provider::<crate::i18n::I18nSignal>(|| {
        crate::i18n::init_i18n_with_locale(initial_locale)
    });
    {
        let mut sig = i18n_signal;
        use_effect(move || {
            crate::i18n::set_locale(&mut sig, locale());
        });
    }
    // Cap-Gate-1: shared `Signal<CapabilityEngine>` for UI-side pre-gates.
    // Starts empty; views call `engine.ui_gate(...)` which returns an open
    // gate when no grants for the subject are loaded yet, so the existing
    // "trust the server" behavior is preserved until something hydrates
    // grants. The capability-grant hydrate path is a follow-up — once
    // `ck.capability.grant` projection events ship, the post-login strand
    // will `engine.write().add_grant(...)` and the kanban Archive /
    // Restore buttons will start gating themselves.
    use_context_provider::<Signal<crate::capability::CapabilityEngine>>(|| {
        Signal::new(crate::capability::CapabilityEngine::new())
    });
    // D0 — server-administrator signal sourced from
    // `AccountView.is_server_admin` (the server's configured admin principal
    // set), provided via context so operator-only surfaces (organization
    // create / bind) can gate their UI without prop drilling. This is the real
    // operator signal — distinct from any Realm-role `is_admin` placeholder.
    let mut is_server_admin =
        use_context_provider(|| crate::views::realm_admin::ServerAdminSignal(Signal::new(false))).0;
    {
        // Refresh the admin signal whenever the session credential or server
        // changes. Failures (offline, transient) leave it `false` (fail closed),
        // so the write UI never appears for a viewer we can't confirm.
        let base_url = base_url;
        let token = token;
        let viewer_admin = use_resource(move || {
            let base = base_url();
            let session = token();
            async move {
                if session.trim().is_empty() {
                    return false;
                }
                crate::views::helpers::with_authed_api(&base, session, |api| async move {
                    api.account_viewer().await
                })
                .await
                .map(|viewer| viewer.is_server_admin)
                .unwrap_or(false)
            }
        });
        use_effect(move || {
            let resolved = viewer_admin().unwrap_or(false);
            if *is_server_admin.peek() != resolved {
                is_server_admin.set(resolved);
            }
        });
    }
    // Y1 - session-scoped DID resolution cache handle.
    //
    // Mount point note: inkson app state is a set of scattered `use_signal`
    // handles rather than one aggregate struct, so this follows the same
    // minimal-intrusion pattern as `CapabilityEngine`: provide a shared
    // `Signal<DidResolutionCache>` with `use_context_provider`.
    //   * Authority resolution sites can fetch it via `use_context::<Signal<DidResolutionCache>>()`
    //     and use `did_resolver::resolve_with_cache` for cache-first resolution.
    //   * The same handle is copied into `SyncEngineContext.did_cache` below so the Y2 invalidation
    //     hook can `invalidate` / `clear` while ingesting projections.
    // The cache is pure in-memory state, is not persisted, and only lives for a
    // single login session, matching the `DidResolutionCache` docs.
    let mut did_cache =
        use_context_provider(|| Signal::new(crate::did_resolver::DidResolutionCache::default()));
    let did_resolution_health = use_signal(crate::components::DidResolutionHealth::healthy);
    let mut theme = use_signal(move || initial_theme);
    let system_theme_is_night = use_signal(browser_prefers_dark_theme);
    {
        let mut system_theme_is_night = system_theme_is_night;
        use_effect(move || {
            if theme() == "system"
                && let Some(is_night) = browser_shell_color_scheme_is_dark()
            {
                system_theme_is_night.set(is_night);
            }
        });
    }
    // Mirror the effective theme onto `<html>` so the vendored dxc palette
    // switch (declared on `:root`) and teleported dialogs resolve correctly.
    // Re-runs whenever the chosen theme or the OS preference changes.
    use_effect(move || {
        let resolved_night = theme_renders_as_night(&theme(), system_theme_is_night());
        apply_document_root_theme(resolved_night);
    });
    let mut mobile_nav_open = use_signal(|| false);
    let mut mobile_space_query = use_signal(String::new);
    let mut sidebar_collapsed = use_signal(|| false);
    let mut sidebar_width = use_signal(move || initial_sidebar_width);
    let mut sidebar_resizing = use_signal(|| false);
    let mut server_menu_open = use_signal(|| false);
    let mut account_menu_open = use_signal(|| false);
    let mut account_session_state = use_signal(|| "Session idle".to_owned());
    let mut account_primary_handle = use_signal(move || initial_account_primary_handle);
    let mut personal_handles = use_signal(Vec::<String>::new);
    let mut personal_handles_status = use_signal(|| "Not published".to_owned());
    let mut personal_handles_lookup_key = use_signal(String::new);
    // Persist the resolved primary handle per account (every code path that
    // updates `account_primary_handle` — login completion, account_me refresh,
    // directory lookup — flows through this one effect). Keyed by the current
    // account DID so a different account never reads a stale handle. Only
    // non-empty values are written: the transient empty resets on server /
    // account switch must not wipe a still-valid persisted handle. `peek`
    // (not `read`) compares the stored value so this effect does not subscribe
    // to the whole state store and re-fire on unrelated writes.
    {
        let account_did_for_handle = account_did;
        let mut state_store_for_handle = state_store;
        use_effect(move || {
            let handle = account_primary_handle();
            let account = account_did_for_handle();
            if handle.trim().is_empty() || account.trim().is_empty() {
                return;
            }
            let storage_key = account_primary_handle_storage_key(&account);
            let already = state_store_for_handle
                .peek()
                .load_private_data(&account, &storage_key);
            if already.as_deref() == Some(handle.as_str()) {
                return;
            }
            state_store_for_handle
                .write()
                .save_private_data(&account, storage_key, handle);
        });
    }
    let contact_handles_lookup_key = use_signal(String::new);
    let contact_handles_fetching = use_signal(BTreeSet::<String>::new);
    let mut global_query = use_signal(String::new);
    let mut palette_open = use_signal(|| false);
    let mut topbar_search_expanded = use_signal(|| false);
    let mut notifications_drawer_open = use_signal(|| false);
    let mut previous_unread_notification_count = use_signal(|| Option::<usize>::None);
    {
        let state_store_for_notification_sound = state_store;
        let account_did_for_notification_sound = account_did;
        use_effect(move || {
            let store = state_store_for_notification_sound.read();
            let unread = unread_notification_count(&store.load());
            let sound_enabled = crate::notification_sound::notification_sound_enabled(
                &store,
                &account_did_for_notification_sound(),
            );
            let previous = *previous_unread_notification_count.peek();
            if crate::notification_sound::should_play_notification_sound(
                previous,
                unread,
                sound_enabled,
            ) {
                crate::notification_sound::play_notification_sound();
            }
            if previous != Some(unread) {
                previous_unread_notification_count.set(Some(unread));
            }
        });
    }
    let mut sync_bootstrap_complete = use_signal(|| false);
    // A6.4 — `?` keyboard shortcut help overlay state.
    let mut shortcut_help_open = use_signal(|| false);
    use_effect(move || {
        let _ = dioxus::document::eval(
            r#"
            (() => {
              if (window.__inksonShortcutHelpBridgeInstalled) return;
              window.__inksonShortcutHelpBridgeInstalled = true;
              window.addEventListener('keydown', (event) => {
                const target = event.target;
                const tag = target && target.tagName ? target.tagName.toLowerCase() : '';
                const editable =
                  target && (target.isContentEditable || tag === 'input' || tag === 'textarea' || tag === 'select');
                const chord = event.ctrlKey || event.metaKey;
                const key = typeof event.key === 'string' ? event.key.toLowerCase() : '';
                if (chord && key === 'k') {
                  const button = document.querySelector('[data-testid="topbar-search-button"]');
                  if (button instanceof HTMLElement) {
                    event.preventDefault();
                    event.stopPropagation();
                    button.click();
                  }
                  return;
                }
                if (chord && key === 'f') {
                  const button = document.querySelector('[data-testid="global-search-shortcut-target"]');
                  if (button instanceof HTMLElement) {
                    event.preventDefault();
                    event.stopPropagation();
                    button.click();
                  }
                  return;
                }
                if (chord && key === 'enter') {
                  const composer =
                    target instanceof HTMLElement ? target.closest('[data-testid="chat-composer"]') : null;
                  const button = composer && composer.querySelector('[data-testid="send-chat-button"]');
                  if (button instanceof HTMLElement) {
                    event.preventDefault();
                    event.stopPropagation();
                    button.click();
                  }
                  return;
                }
                if (editable) return;
                const wantsHelp =
                  event.key === '?' ||
                  (event.shiftKey && (event.key === '/' || event.code === 'Slash'));
                if (!wantsHelp) return;
                const button = document.querySelector(
                  '[data-testid="topbar-shortcuts-button"], [data-testid="mobile-shortcuts-button"]'
                );
                if (!(button instanceof HTMLElement)) return;
                event.preventDefault();
                event.stopPropagation();
                button.click();
              }, true);
            })();
            "#,
        );
    });
    let mut realm_sidebar_tab = use_signal(|| "collaboration".to_owned());
    let mut collaboration_sidebar_query = use_signal(String::new);
    let mut direct_sidebar_query = use_signal(String::new);
    let realm_manage_query = use_signal(String::new);
    let contact_manage_query = use_signal(String::new);
    let manage_realm_selection = use_signal(BTreeSet::<String>::new);
    let manage_contact_selection = use_signal(BTreeSet::<String>::new);
    let manage_bulk_busy = use_signal(|| false);
    let direct_contact_rows = use_signal(Vec::<crate::models::ContactListRow>::new);
    let direct_contacts_loaded = use_signal(|| false);
    let mut sidebar_row_menu_open = use_signal(|| Option::<String>::None);
    // UI pre-gate cache for the row menu's Add Member / Settings entries,
    // keyed by realm_id. Filled lazily when a row kebab opens (see
    // `ensure_sidebar_row_perms`) so we never probe authz for Realms whose
    // menu the user never touches.
    let sidebar_row_perms = use_signal(BTreeMap::<String, SidebarRowRealmPerms>::new);
    let mls_key_package_publish_key_seen = use_signal(|| Option::<String>::None);
    let mls_welcome_bootstrap_key_seen = use_signal(|| Option::<String>::None);
    // Admin-side counterpart of the Welcome bootstrap: serialize admission
    // reconciliation so per-sync retries cannot overlap and double-admit.
    let mls_admission_reconcile_in_flight = use_signal(|| false);
    let mls_admission_reconcile_pending = use_signal(|| false);
    // Throttle key for the admission pre-filter diagnostic: only emit a WARN
    // when the (realm, blocking-reason) pair changes, so a genuinely stuck
    // admin gets ONE visible line per cause instead of one per sync tick.
    let mls_admission_diag_last = use_signal(String::new);
    // History sharing (encryption-and-audit.md): single-flight guard for the
    // to-device `ck.realm_key.share` ingest + `ck.realm_key.request` provider
    // response pass, so per-sync retries cannot overlap.
    let realm_key_sharing_in_flight = use_signal(|| false);
    // History sharing (receiver-initiated pull): dedup key of the last
    // `ck.realm_key.request` this device emitted, as
    // `"{realm}|{from}|{to}|{installed_signature}"`. The installed-secret
    // signature is folded in so that once a `ck.realm_key.share` lands and
    // installs a `history_secret`, the key changes and a still-open gap can be
    // re-requested — but an unchanged state never re-emits the same request on
    // every sync tick.
    let realm_key_request_dedup = use_signal(|| Option::<String>::None);
    let realm_key_answer_backoff_until = use_signal(BTreeMap::<String, u64>::new);
    // Step 3 of the account-MLS-secret auto-unlock strand: set by the bootstrap
    // effect when this device has no local account secret yet but the server
    // holds an `mls_account_secret` backup; consumed by `MlsUnlockPrompt`.
    let needs_mls_unlock = use_signal(|| false);
    // Mirror of `needs_mls_unlock` (task X3): set by the detection effects when
    // this account has used encryption (a local account MLS secret exists) but
    // the server holds NO `mls_account_secret` backup yet — so a fresh browser
    // would lose history. Consumed by `MlsBackupPrompt`. Mutually exclusive
    // with `needs_mls_unlock`: restore (unlock) always wins.
    let needs_mls_backup = use_signal(|| false);
    // Fresh-device diagnostic: encrypted Realm/history exists, but the server
    // has no passphrase-backed account-secret backup to unlock. This is
    // distinct from `needs_mls_unlock`: there is nothing this browser can
    // decrypt until an existing device creates the recovery backup.
    let needs_mls_recovery_setup = use_signal(|| false);
    let needs_device_authorization = use_signal(|| false);
    let device_authorization_check_complete = use_signal(|| false);
    let account_has_other_devices = use_signal(|| false);
    let mut recovery_key_setup_prompt = use_signal(|| false);
    // Session-scoped acknowledgement flag for the recommended-encryption-floor
    // auto-apply effect. `active_prompt == RecommendedEncryptionFloor` is
    // re-resolved every render; during Realm creation the prompt can churn away
    // and back as sync flushes new state, remounting `EncryptionFloorPrompt`.
    // Hoisting the flag prevents repeat auto-apply work in the same session.
    let encryption_floor_prompt_dismissed = use_signal(|| false);
    // In-memory "already auto-prompted recovery setup this session" guard. The
    // persisted localStorage flag handles across-session suppression, but a
    // session guard makes the one-time auto-open robust against the user
    // dismissing the modal and against sync re-flushing local state, so the
    // proactive nudge can never re-pop within a session.
    let recovery_auto_prompt_fired = use_signal(|| false);
    let mut account_recovery_configured = use_signal(|| Option::<bool>::None);
    let account_recovery_detection_key_seen = use_signal(|| Option::<String>::None);
    // X11.2 — expose `needs_mls_backup` via context so deep encrypted-write
    // success paths (kanban card detail update, chat secure send) can flip the
    // backup prompt on directly, WITHOUT relying on the fragile boot-time
    // detection effect (X11). See `maybe_flag_mls_backup_after_encrypted_write`.
    use_context_provider(|| crate::components::MlsBackupSignal(needs_mls_backup));
    // Call-signaling hub — the receive side of `ck.call.signal`. Provided
    // once at the app root; the sync apply paths route inbound envelopes into
    // it and `CallPanel` drains it to drive the transport / call FSM. See
    // `crate::views::call_signals`.
    let call_signal_hub = use_context_provider(crate::views::call_signals::CallSignalHub::new);
    // When an inbound `invite` lands on the hub (set by the sync apply path),
    // navigate to the incoming-ring surface so the user can accept/decline.
    // Tracks the last call_id navigated for so a re-render with the same
    // pending invite does not re-push the route.
    {
        let call_navigator = navigator;
        let mut last_incoming_nav = use_signal(|| Option::<String>::None);
        use_effect(move || {
            let pending = call_signal_hub.incoming_call.read().clone();
            match pending {
                Some(info) => {
                    if last_incoming_nav.read().as_deref() != Some(info.call_id.as_str()) {
                        last_incoming_nav.set(Some(info.call_id.clone()));
                        call_navigator.push(Route::Call {
                            call_id: info.call_id.clone(),
                            peer: info.peer_actor.clone(),
                            realm_id: info.realm_id.clone(),
                            video: if info.video { "1" } else { "0" }.to_owned(),
                            incoming: "1".to_owned(),
                        });
                    }
                }
                None => {
                    if last_incoming_nav.read().is_some() {
                        last_incoming_nav.set(None);
                    }
                }
            }
        });
    }
    let mls_restore_payload_cache = use_signal(|| Option::<Value>::None);
    let mls_unlock_detection_key_seen = use_signal(|| Option::<String>::None);

    // On first render with a live session, fetch the directory + sync so
    // the sidebar's Space list shows up after a page reload. The list
    // intentionally isn't persisted in localStorage — directory search
    // results live only in the in-memory `realm_tree_nodes` signal, so without
    // this kick we'd render "No Realm tree loaded" until the user clicks
    // Refresh.
    //
    // The flag is consumed only after we confirm base+session are both
    // populated. Otherwise a fresh user who lands without a session and
    // then signs in (on the same mount) would never auto-connect, since
    // the one-shot would have already been spent during the empty-session
    // first render.
    // Background session-refresh poller. Proactively rotates the grant
    // a little before it expires so requests rarely hit a cold 401. The
    // refresh itself goes through the shared single-flight refresher
    // (`crate::session`), so this poller and any reactive 401-retry can
    // never fire two competing refreshes for the same rollover.
    use_future({
        let mut status = connection_status;
        let mut last_error = last_error;
        let state_store = state_store;
        let token = token;
        let mut session_boot_state = session_boot_state;
        move || async move {
            crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(1)).await;
            loop {
                // Freshness gate — only refresh when the persisted grant is
                // near its own expiry. The read borrow is dropped before any
                // await, so concurrent `state_store.write()` callers never hit
                // `AlreadyBorrowedMut`.
                let due = {
                    let store = state_store.read();
                    matches!(
                        crate::session_refresh::refresh_decision(&store),
                        crate::session_refresh::RefreshDecision::Due
                    )
                };
                if due {
                    if token().trim().is_empty() {
                        status.set("Restoring session...".to_owned());
                        session_boot_state.set(SessionBootState::Restoring);
                    }
                    match crate::session::refresh_current_session().await {
                        crate::session::CurrentSessionRefresh::Credential(_) => {
                            status.set("Online".to_owned());
                            session_boot_state.set(SessionBootState::Authenticated);
                            last_error.set(None);
                        }
                        crate::session::CurrentSessionRefresh::SignInRequired { reason } => {
                            last_error.set(Some(reason));
                            if token().trim().is_empty() {
                                status
                                    .set("Session could not be restored; sign in again".to_owned());
                                session_boot_state.set(SessionBootState::Unauthenticated);
                            }
                        }
                        crate::session::CurrentSessionRefresh::LoginRequired { reason } => {
                            last_error.set(Some(reason));
                            if token().trim().is_empty() {
                                status.set("Session expired; sign in again".to_owned());
                                session_boot_state.set(SessionBootState::Unauthenticated);
                            }
                        }
                        crate::session::CurrentSessionRefresh::RetryLater { reason } => {
                            // Keep the current credential alive; a reactive 401
                            // handles a genuinely dead session. Surface the
                            // transient issue for dev tools.
                            last_error.set(Some(format!(
                                "background session refresh pending: {reason}"
                            )));
                            if token().trim().is_empty() {
                                status.set(
                                    "Session restore is unavailable; sign in again".to_owned(),
                                );
                                session_boot_state.set(SessionBootState::Unauthenticated);
                            }
                        }
                    }
                }
                crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(
                    crate::session_refresh::POLL_INTERVAL_SECS,
                ))
                .await;
            }
        }
    });

    // F7 — durable hard-logout retry. A logout journals its server-side
    // termination intent to localStorage before wiping local creds; if the
    // tab closed before the revoke completed (or coauth was unreachable),
    // finish it on the next boot so the rotation chain can never outlive a
    // "Log out" click. One-shot: reads no signals, so it runs once on mount.
    use_future(move || async move {
        crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(1)).await;
        crate::pending_logout::run_pending_logout_if_any(chrono::Utc::now()).await;
    });

    // SyncEngine generation counter. Declared up front so the
    // bootstrap connect() can pass it via `ConnectContext`. The engine
    // itself is spawned by the `use_effect` further down.
    let mut sync_generation = use_signal(|| 0u64);
    let mut sync_engine_active_generation = use_signal(|| Option::<u64>::None);
    // Dedup key (`<generation>|<realm_id>`) for the per-realm events engine, so
    // a base_url/token re-render doesn't stack a second loop on the same realm.
    let mut realm_events_engine_active_key = use_signal(|| Option::<String>::None);

    {
        let mut account_recovery_configured = account_recovery_configured;
        let mut account_recovery_detection_key_seen = account_recovery_detection_key_seen;
        let mut last_error = last_error;
        let state_store_for_recovery_state = state_store;
        use_effect(move || {
            let base = base_url();
            let session = token();
            let actor = account_did();
            let generation = sync_generation();
            if !matches!(session_boot_state(), SessionBootState::Authenticated)
                || base.trim().is_empty()
                || session.trim().is_empty()
                || actor.trim().is_empty()
            {
                account_recovery_configured.set(None);
                account_recovery_detection_key_seen.set(None);
                return;
            }
            let detection_key = format!("{generation}|{base}|{actor}");
            if account_recovery_detection_key_seen().as_deref() == Some(detection_key.as_str()) {
                return;
            }
            account_recovery_detection_key_seen.set(Some(detection_key.clone()));
            // DIAG (describe-storm): this effect re-fetches recovery-policy +
            // backups whenever `detection_key` changes. On a wedged account it
            // storms; log the key so consecutive values reveal which field
            // (generation) keeps flipping. Remove once the driver is fixed.
            tracing::warn!(target: "recovery_diag", key = %detection_key, "recovery_state re-fetch (recovery-policy+backups)");
            let local_fingerprint = {
                let store = state_store_for_recovery_state.read();
                crate::views::recovery::local_recovery_key_fingerprint(&store, &actor)
            };
            spawn(async move {
                match crate::views::helpers::with_authed_api(&base, session, |api| async move {
                    // The recovery-state reducer reads both payloads leniently via
                    // `Value` accessors; serialize the typed SDK outcomes back to
                    // their wire JSON.
                    let policy = serde_json::to_value(&api.get_recovery_policy().await?)?;
                    let backups = serde_json::to_value(&api.list_key_backups().await?)?;
                    Ok::<(serde_json::Value, serde_json::Value), anyhow::Error>((policy, backups))
                })
                .await
                {
                    Ok((policy, backups)) => {
                        let state = crate::recovery_strand::account_recovery_state_from_payloads(
                            &policy,
                            &backups,
                            local_fingerprint,
                        );
                        account_recovery_configured.set(Some(state.server_recovery_configured()));
                    }
                    Err(error) if error.is_auth_expired() => {
                        crate::session::invalidate_current_session(
                            "session expired while loading account recovery state",
                        );
                        account_recovery_configured.set(None);
                    }
                    Err(error) => {
                        last_error.set(Some(format!("recovery_state: {}", error.display())));
                        account_recovery_configured.set(None);
                    }
                }
            });
        });
    }

    // CKP-0007 P3B.4.3 — active multi-profile snapshot, threaded into
    // the sync engine context so the loop can detect a profile rotation
    // and exit cleanly. The shell is currently single-profile; the
    // signal stays default-empty until the account switcher writes to
    // it on the first user-driven add-account / switch action.
    let profiles_signal = use_signal(crate::config::MultiProfileConfig::default);

    // Lower-level API helpers cannot directly mutate app signals, but they
    // can receive terminal auth errors (notably `session grant is not
    // active: revoked`) from background pollers. Register one soft-logout
    // hook so those paths can clear the live credential and stop retry loops.
    {
        let mut invalidator_token = token;
        let mut invalidator_sync_cursor = sync_cursor;
        let mut invalidator_selected_realm_id = selected_realm_id;
        let mut invalidator_realm_tree_nodes = realm_tree_nodes;
        let mut invalidator_projection_events = projection_events;
        let mut invalidator_device_queue = device_queue;
        let mut invalidator_crypto_state = crypto_state;
        let mut invalidator_status = connection_status;
        let mut invalidator_network_state = network_state;
        let mut invalidator_last_error = last_error;
        let mut invalidator_session_boot_state = session_boot_state;
        let mut invalidator_state_store = state_store;
        let invalidator_config_store = config_store;
        let invalidator_base_url = base_url;
        let invalidator_account_did = account_did;
        let invalidator_device_id = device_id;
        let mut invalidator_needs_device_authorization = needs_device_authorization;
        let mut invalidator_device_authorization_check_complete =
            device_authorization_check_complete;
        let mut invalidator_account_has_other_devices = account_has_other_devices;
        let mut invalidator_sync_generation = sync_generation;
        let mut invalidator_session_generation = session_generation;
        let invalidator_navigator = navigator;
        use_hook(move || {
            crate::session::register_session_invalidator(move |reason| {
                invalidator_session_generation.set(invalidator_session_generation() + 1);
                invalidator_state_store.write().set_session_grant(None);
                invalidator_token.set(String::new());
                crate::config::clear_session_credential_secret(&invalidator_account_did());
                persist_config(
                    invalidator_config_store,
                    invalidator_base_url(),
                    invalidator_account_did(),
                    invalidator_device_id(),
                    String::new(),
                );
                invalidator_sync_cursor.set("-".to_owned());
                invalidator_selected_realm_id.set(String::new());
                invalidator_realm_tree_nodes.set(Vec::new());
                invalidator_projection_events.set(Vec::new());
                invalidator_device_queue.set(0);
                invalidator_crypto_state.set("Session expired".to_owned());
                invalidator_status.set("Session expired; sign in again".to_owned());
                invalidator_network_state.set("online".to_owned());
                invalidator_last_error.set(Some(reason));
                invalidator_needs_device_authorization.set(false);
                invalidator_device_authorization_check_complete.set(false);
                invalidator_account_has_other_devices.set(false);
                invalidator_sync_generation.set(invalidator_sync_generation() + 1);
                invalidator_session_boot_state.set(SessionBootState::Unauthenticated);
                let _ = invalidator_navigator.push(Route::Login);
            });
        });
    }

    // Single-source-of-truth for the sidebar. Anything that wants to
    // change the visible Space list writes to
    // `state_store.realm_tree_projections` (sync engine, connect()'s initial
    // bootstrap, setup's optimistic post-create insert, future
    // push-notification ingestion). This effect derives the `realm_tree_nodes`
    // Signal from those projections so consumers can keep reading
    // `realm_tree_nodes()` as before — but the only path into the data is
    // through the store. Avoids the "stale ghost space" class of bugs
    // where signal writers forgot to also update the projection (or
    // vice versa) and the two slid out of sync.
    use_effect(move || {
        let projections = state_store.read().load().realm_tree_projections;
        let next = realm_tree_nodes_from_sync_realms(&projections);
        // Perf (P1): this effect re-runs on *any* `state_store` write (drafts,
        // theme, notifications, read receipts, …), not just projection changes.
        // Skip the `set` when the derived list is unchanged so unrelated writes
        // don't cascade a re-render through every `realm_tree_nodes()` consumer (sidebar,
        // command palette, root shell).
        if *realm_tree_nodes.peek() != next {
            realm_tree_nodes.set(next);
        }
    });

    // Bootstrap handshake: on first render with a valid session, run
    // `connect()` exactly once to do the `/server/describe` +
    // account viewer probes and the initial server-authoritative full
    // sync. After that, the SyncEngine (below) owns continuous sync.
    let mut bootstrap_pending = use_signal(|| true);
    let secure_store_ready = secure_store_bootstrap_ready();
    if bootstrap_pending() {
        let base = base_url();
        let mut session = token();
        if session.trim().is_empty() && secure_store_ready {
            let rehydrated = {
                let loaded = config_store.read().load();
                rehydrated_session_credential_for_active_config(
                    &loaded,
                    &base,
                    &account_did(),
                    &device_id(),
                )
            };
            if let Some(rehydrated) = rehydrated {
                token.set(rehydrated.clone());
                session = rehydrated;
            }
        }
        if !session.trim().is_empty() {
            let stale_for_selected_server = {
                let store = state_store.read();
                store
                    .session_grant()
                    .as_ref()
                    .map(|grant| {
                        !crate::session_refresh::grant_matches_principal_server(grant, &base)
                    })
                    .unwrap_or(false)
            };
            if stale_for_selected_server {
                token.set(String::new());
                session_boot_state.set(SessionBootState::Unauthenticated);
                persist_config(
                    config_store,
                    base.clone(),
                    account_did(),
                    device_id(),
                    String::new(),
                );
                session.clear();
            }
        }
        let can_restore_session = {
            let store = state_store.read();
            has_bootstrap_refresh_material(&store, &base, &account_did())
        };
        if !base.trim().is_empty()
            && secure_store_ready
            && (!session.trim().is_empty() || can_restore_session)
        {
            bootstrap_pending.set(false);
            sync_bootstrap_complete.set(false);
            let bootstrap_state = session_boot_state_from_bootstrap_material(
                &session,
                can_restore_session,
                &account_did(),
                secure_store_ready,
            );
            tracing::warn!(target: "session_boot", ?bootstrap_state, secure_store_ready, "bootstrap: branch A (will call connect) — setting boot_state from material");
            session_boot_state.set(bootstrap_state);
            connect(
                base,
                account_did(),
                device_id(),
                ConnectContext {
                    connection_status,
                    sync_cursor,
                    token,
                    account_did,
                    device_id,
                    selected_realm_id,
                    realm_tree_nodes,
                    projection_events,
                    device_queue,
                    frontier_state,
                    crypto_state,
                    config_store,
                    state_store,
                    network_state,
                    last_error,
                    server_description,
                    server_probe_status,
                    account_primary_handle,
                    personal_handles,
                    personal_handles_status,
                    theme,
                    sync_generation,
                    needs_device_authorization,
                    device_authorization_check_complete,
                    account_has_other_devices,
                    sync_bootstrap_complete,
                    session_boot_state,
                    call_signal_hub,
                    did_cache,
                    did_resolution_health,
                },
            );
        } else if !base.trim().is_empty() {
            let bootstrap_state = session_boot_state_from_bootstrap_material(
                &session,
                can_restore_session,
                &account_did(),
                secure_store_ready,
            );
            // Idempotent: branch B runs on EVERY render (it never clears
            // `bootstrap_pending`, since it is waiting for the async secure-store
            // upgrade to flip `secure_store_ready`). Re-`set`ting the signal to
            // the value it already holds still notifies subscribers, which
            // re-renders RouterView, which re-enters this block — a synchronous
            // render loop that starves the very upgrade future we are waiting on
            // (it never gets an event-loop turn to drive its IndexedDB awaits).
            // Only `set` on an actual change so the loop quiesces and the future
            // can run.
            if *session_boot_state.peek() != bootstrap_state {
                tracing::warn!(target: "session_boot", ?bootstrap_state, secure_store_ready, "bootstrap: branch B (waiting on secure store) — boot_state changed, setting");
                session_boot_state.set(bootstrap_state);
            }
        }
    }

    // SyncEngine — long-poll loop that keeps `realm_tree_projections` +
    // derived signals continuously aligned with `/sync`. Spawn per
    // generation so logout / server-switch / account-change can stop
    // the previous loop cleanly by bumping the counter.
    //
    // The use_effect re-runs whenever `sync_generation`, `base_url`, or
    // `token` changes. Each respawn passes the engine the generation
    // value it started with so a stale iteration can self-check and
    // exit before writing back to signals owned by the new generation.
    use_effect(move || {
        let current_gen = sync_generation();
        let base = base_url();
        let session = token();
        if base.trim().is_empty() || session.trim().is_empty() || !sync_bootstrap_complete() {
            return;
        }
        if *sync_engine_active_generation.peek() == Some(current_gen) {
            return;
        }
        sync_engine_active_generation.set(Some(current_gen));
        let ctx = crate::sync_engine::SyncEngineContext {
            base_url,
            token,
            state_store,
            realm_tree_nodes,
            projection_events,
            sync_cursor,
            connection_status,
            network_state,
            last_error,
            device_queue,
            theme,
            account_did,
            device_id,
            selected_realm_id,
            profiles: profiles_signal,
            // Y1/Y2 - pass the session-scoped cache handle provided above into
            // the sync engine so the Y2 invalidation hook can invalidate/clear
            // entries while ingesting projections.
            did_cache,
            // Receive side of `ck.call.signal`: the engine routes inbound
            // call-signal envelopes from every incremental sync body into
            // this hub (the same hub `CallPanel` drains).
            call_signal_hub,
        };
        let mut active_generation = sync_engine_active_generation;
        spawn(async move {
            crate::sync_engine::run_sync_engine(current_gen, sync_generation, ctx).await;
            if *active_generation.peek() == Some(current_gen) {
                active_generation.set(None);
            }
        });
    });

    // Per-realm `events/subscribe` engine — the realm-scoped counterpart to the
    // account SyncEngine above. It long-polls the SELECTED realm's durable event
    // stream with that realm's OWN cursor, so cross-member events that never ride
    // the (delivery-routing-gated) account push still reach the board. Respawned
    // when the generation, realm, base_url, or token change; the previous loop
    // self-exits when its realm no longer matches the selection.
    use_effect(move || {
        let current_gen = sync_generation();
        let base = base_url();
        let session = token();
        let realm_id = selected_realm_id();
        let route_enabled = realm_events_route_enabled();
        if base.trim().is_empty()
            || session.trim().is_empty()
            || realm_id.trim().is_empty()
            || !route_enabled
            || !sync_bootstrap_complete()
        {
            return;
        }
        let active_key = format!("{current_gen}|{realm_id}");
        if realm_events_engine_active_key.peek().as_deref() == Some(active_key.as_str()) {
            return;
        }
        realm_events_engine_active_key.set(Some(active_key.clone()));
        let ctx = crate::realm_events_engine::RealmEventsEngineContext {
            base_url,
            token,
            state_store,
            selected_realm_id,
            route_enabled: realm_events_route_enabled,
            realm_live_epoch,
            profiles: profiles_signal,
        };
        let mut active_key_signal = realm_events_engine_active_key;
        spawn(async move {
            crate::realm_events_engine::run_realm_events_engine(
                current_gen,
                sync_generation,
                realm_id,
                ctx,
            )
            .await;
            if active_key_signal.peek().as_deref() == Some(active_key.as_str()) {
                active_key_signal.set(None);
            }
        });
    });

    // D1: detect the account-MLS unlock requirement as soon as a logged-in
    // session finishes bootstrap, without waiting for the user to enter a
    // Space/Board/Document route that runs the per-Realm Welcome bootstrap.
    {
        let mut seen_detection_key = mls_unlock_detection_key_seen;
        let mut needs_mls_unlock = needs_mls_unlock;
        let mut needs_mls_backup = needs_mls_backup;
        let mut needs_mls_recovery_setup = needs_mls_recovery_setup;
        let mut restore_payload_cache = mls_restore_payload_cache;
        let mut state_store_for_detection = state_store;
        let secure_store_ready_for_detection = secure_store_bootstrap_ready;
        let account_recovery_configured_for_detection = account_recovery_configured;
        use_effect(move || {
            if !secure_store_ready_for_detection() {
                return;
            }
            let base = base_url();
            let session = token();
            let actor = account_did();
            let device = device_id();
            let generation = sync_generation();
            let account_recovery_configured_value = account_recovery_configured_for_detection();
            if !matches!(session_boot_state(), SessionBootState::Authenticated) {
                needs_mls_unlock.set(false);
                needs_mls_backup.set(false);
                needs_mls_recovery_setup.set(false);
                restore_payload_cache.set(None);
                seen_detection_key.set(None);
                return;
            }
            if session.trim().is_empty() {
                needs_mls_unlock.set(false);
                needs_mls_backup.set(false);
                needs_mls_recovery_setup.set(false);
                restore_payload_cache.set(None);
                seen_detection_key.set(None);
                return;
            }
            // X10.1: do NOT gate on `sync_bootstrap_complete()` here. A fresh
            // browser sits on Dashboard with sync still pending; the MLS
            // unlock/backup detection only needs a live session + a server
            // `list_key_backups` call, NOT a completed sync. Gating on sync
            // meant the unlock prompt never surfaced on a new device until the
            // user manually entered a Space — i.e. "switched browser, never
            // asked for my passphrase". Run as soon as session/actor/device
            // are present; the `seen_detection_key` guard still prevents
            // repeat runs, and re-running after sync (snap= flips) is handled
            // by the detection key below.
            if base.trim().is_empty() || actor.trim().is_empty() || device.trim().is_empty() {
                return;
            }
            // BUG X4: the account MLS secret is created lazily on the
            // first encrypted write — at register / first space entry it
            // does not exist yet, so `mls_backup_prompt_required` returns
            // false and this effect would never re-fire to surface the
            // backup prompt once the secret appears. Two changes fix that:
            //   1. Read a `state_store` signal in the *synchronous* effect body
            //      (`has_local_mls_snapshot`) so Dioxus re-runs this effect when the first
            //      encrypted write saves a snapshot.
            //   2. Fold the local account-secret presence into the detection key (`sec=`) so the
            //      `seen` guard no longer matches once the secret flips false→true, letting the
            //      detection re-run and re-evaluate the backup prompt.
            let state_for_detection_key = state_store_for_detection.read();
            let has_local_mls_snapshot = !state_for_detection_key.mls_snapshots().is_empty();
            let has_encrypted_realm_projection =
                local_state_has_encrypted_realm(&state_for_detection_key);
            let local_mls_epoch_floor = local_mls_epoch_floor_all(&state_for_detection_key);
            let recovery_key_fingerprint = crate::views::recovery::local_recovery_key_fingerprint(
                &state_for_detection_key,
                &actor,
            )
            .unwrap_or_default();
            drop(state_for_detection_key);
            let has_local_account_secret = crate::mls::runtime::load_account_mls_secret(
                crate::secure_key_store::default_secure_key_store("inkson").as_ref(),
                &actor,
            )
            .map(|secret| secret.is_some())
            .unwrap_or(false);
            let detection_key = format!(
                "{generation}|{base}|{actor}|{device}|sec={has_local_account_secret}|snap={has_local_mls_snapshot}|enc={has_encrypted_realm_projection}|epoch={local_mls_epoch_floor}|rk={recovery_key_fingerprint}|recovery={account_recovery_configured_value:?}"
            );
            if seen_detection_key().as_deref() == Some(detection_key.as_str()) {
                return;
            }
            seen_detection_key.set(Some(detection_key.clone()));
            // DIAG (describe-storm): this effect re-fetches backups (+ sidecar)
            // whenever `detection_key` changes. On a wedged-recovery account it
            // storms; log the full key so consecutive values reveal which
            // component (sec/snap/enc/epoch/rk/recovery/generation) keeps
            // flipping. Remove once the driver is fixed.
            tracing::warn!(target: "recovery_diag", key = %detection_key, "mls_unlock detection re-fetch (backups)");
            let seen_detection_key_for_result = seen_detection_key;

            spawn(async move {
                let actor_for_sidecar_restore = actor.clone();
                let device_for_sidecar_restore = device.clone();
                match crate::views::helpers::with_authed_api(
                    &base,
                    session.clone(),
                    |api| async move {
                        let payload =
                            crate::mls::account_recovery::fetch_mls_restore_payload(&api).await?;
                        let sidecar_body_for_local_restore = if has_local_account_secret {
                            crate::mls::account_recovery::fetch_mls_private_plaintext_backup_body(
                                &api,
                                &actor_for_sidecar_restore,
                                &device_for_sidecar_restore,
                            )
                            .await
                            .ok()
                            .flatten()
                        } else {
                            None
                        };
                        Ok((payload, sidecar_body_for_local_restore))
                    },
                )
                .await
                {
                    Ok((payload, sidecar_body_for_local_restore)) => {
                        if seen_detection_key_for_result().as_deref()
                            != Some(detection_key.as_str())
                        {
                            return;
                        }
                        let secure_store =
                            crate::secure_key_store::default_secure_key_store("inkson");
                        let configured_backup_id =
                            crate::mls::account_recovery::select_preferred_mls_account_secret_backup(
                                &payload,
                            )
                            .and_then(|backup| {
                                backup
                                    .get("backup_id")
                                    .and_then(serde_json::Value::as_str)
                                    .map(str::to_owned)
                            });
                        {
                            let mut store = state_store_for_detection.write();
                            if let Some(backup_id) = configured_backup_id.as_deref() {
                                crate::components::mark_mls_recovery_backup_configured(
                                    &mut store, &actor, backup_id,
                                );
                            }
                            let report = crate::mls::account_recovery::restore_mls_history_with_local_secret_from_payload(
                                &payload,
                                &mut store,
                                secure_store.as_ref(),
                                &actor,
                                &device,
                            );
                            if report.failed > 0 {
                                tracing::warn!(
                                    failed = report.failed,
                                    restored = report.restored,
                                    first_error = ?report.first_error,
                                    "mls history restore from local secret failed"
                                );
                            }
                            if let Some(sidecar_body) = sidecar_body_for_local_restore.as_ref() {
                                let sidecar_payload =
                                    serde_json::json!({ "backups": [sidecar_body.clone()] });
                                let report = crate::mls::account_recovery::restore_mls_history_with_local_secret_from_payload(
                                    &sidecar_payload,
                                    &mut store,
                                    secure_store.as_ref(),
                                    &actor,
                                    &device,
                                );
                                if report.failed > 0 {
                                    tracing::warn!(
                                        failed = report.failed,
                                        restored = report.restored,
                                        first_error = ?report.first_error,
                                        "mls sidecar restore from local secret failed"
                                    );
                                }
                            }
                        }
                        let should_unlock = {
                            let store = state_store_for_detection.read();
                            crate::mls::account_recovery::mls_restore_prompt_required(
                                &payload,
                                &store,
                                secure_store.as_ref(),
                                &actor,
                                &device,
                            )
                        };
                        // Mutual exclusion (task X3): restore (unlock) always
                        // wins. Only evaluate the backup prompt when restore is
                        // not required.
                        if should_unlock {
                            restore_payload_cache.set(Some(payload.clone()));
                            needs_mls_unlock.set(true);
                            needs_mls_backup.set(false);
                            needs_mls_recovery_setup.set(false);
                        } else if needs_mls_unlock() {
                            // Multiple detection effects can race with different
                            // restore-payload snapshots. Once one detects a real
                            // unlock requirement, keep the modal open until the
                            // user restores successfully or the session resets.
                            needs_mls_backup.set(false);
                            needs_mls_recovery_setup.set(false);
                        } else {
                            restore_payload_cache.set(None);
                            needs_mls_unlock.set(false);
                            let should_backup =
                                crate::mls::account_recovery::mls_backup_prompt_required(
                                    &payload,
                                    secure_store.as_ref(),
                                    &actor,
                                    &device,
                                );
                            if should_backup {
                                crate::components::maybe_auto_backup_mls_after_encrypted_write(
                                    base.clone(),
                                    session.clone(),
                                    actor.clone(),
                                    device.clone(),
                                    state_store_for_detection,
                                    needs_mls_backup,
                                )
                                .await;
                            } else {
                                needs_mls_backup.set(false);
                            }
                            let should_recovery_setup = {
                                let store = state_store_for_detection.read();
                                mls_recovery_setup_missing(
                                    &payload,
                                    &store,
                                    secure_store.as_ref(),
                                    &actor,
                                    account_recovery_configured_value,
                                )
                            };
                            needs_mls_recovery_setup.set(!should_backup && should_recovery_setup);
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            error = %error.display(),
                            "MLS account-secret login unlock detection failed"
                        );
                    }
                }
            });
        });
    }

    let routed_realm_id = route.realm_id().map(str::to_owned);
    let remembered_realm_id = selected_realm_id();
    let effective_realm_id = routed_realm_id.clone().or_else(|| {
        if remembered_realm_id.trim().is_empty() {
            None
        } else {
            Some(remembered_realm_id.clone())
        }
    });
    let active_realm_id = effective_realm_id.clone().unwrap_or_default();
    if let Some(route_realm_id) = routed_realm_id.as_deref()
        && remembered_realm_id != route_realm_id
    {
        selected_realm_id.set(route_realm_id.to_owned());
    }

    let active_server_description = server_description();
    let active_service_did = active_server_description
        .as_ref()
        .map(|description| description.service_did.as_str().to_owned())
        .unwrap_or_default();
    let can_list_handles_for_subject = active_server_description
        .as_ref()
        .is_some_and(|description| description.supports_operation(OP_LIST_HANDLES_FOR_SUBJECT));
    let has_session = !token().trim().is_empty();
    let boot_state = session_boot_state();
    let auth_surface = auth_surface_for_route(&route, has_session, boot_state);
    {
        let redirect_route = route.clone();
        let redirect_navigator = navigator;
        use_effect(move || {
            if matches!(redirect_route, Route::Login) && !token().trim().is_empty() {
                let _ = redirect_navigator.push(Route::Dashboard);
            } else if matches!(redirect_route, Route::Recovery) {
                let _ = redirect_navigator.replace(Route::SettingsRecovery);
            }
        });
    }
    {
        // Proactive one-time 24-word Recovery Key setup nudge for new users.
        // When the account is otherwise healthy but no recovery path is
        // configured (the RecoverySetupReminder state), open the setup modal
        // once and persist a flag so it never auto-pops again — the passive
        // dashboard banner remains as the steady-state reminder. The
        // in-memory `recovery_auto_prompt_fired` guard makes "once" robust within
        // a session. See account_health::should_auto_prompt_recovery_setup and
        // docs/user-strands-key-lifecycle.md §3/S1.
        let mut recovery_key_setup_prompt = recovery_key_setup_prompt;
        let mut recovery_auto_prompt_fired = recovery_auto_prompt_fired;
        let mut state_store = state_store;
        use_effect(move || {
            if recovery_auto_prompt_fired() || recovery_key_setup_prompt() {
                return;
            }
            let session = token();
            let actor = account_did();
            if session.trim().is_empty() || actor.trim().is_empty() {
                return;
            }
            // Recovery setup requires an enrollment-capable session. Establishing
            // the account recovery policy needs this device authorized as a
            // key-management device, which goes through the account authority
            // (coauth) and therefore requires an active `ck.session.grant`. A
            // grant-less compatibility session can never pass that
            // gate, so auto-prompting it only loops on `recovery_policy_device_
            // not_authorized` and blocks the UI behind the modal. Don't prompt.
            if state_store.read().session_grant().is_none() {
                return;
            }
            let (inputs, already_prompted, local_only_fingerprint) = {
                let store = state_store.read();
                let account_recovery_configured = account_recovery_configured();
                let local_recovery_configured =
                    crate::views::recovery::recovery_options_configured(&store, &actor);
                let local_only_fingerprint = recovery_auto_prompt_pending_local_only_fingerprint(
                    &store,
                    &actor,
                    account_recovery_configured,
                );
                let inputs = crate::account_health::AccountHealthInputs {
                    has_session: true,
                    sync_bootstrap_complete: sync_bootstrap_complete(),
                    device_check_complete: device_authorization_check_complete(),
                    // Route doesn't gate this one-time nudge; the guards do.
                    on_recovery_route: false,
                    recovery_check_complete: account_recovery_configured.is_some(),
                    needs_device_authorization: needs_device_authorization(),
                    needs_mls_unlock: needs_mls_unlock(),
                    needs_mls_backup: needs_mls_backup(),
                    needs_mls_recovery_setup: needs_mls_recovery_setup(),
                    floor_low:
                        crate::components::encryption_floor_prompt::account_needs_recommended_encryption_prompt(
                            &store, &actor,
                        ),
                    recovery_unconfigured: recovery_setup_prompt_required_for_account_state(
                        account_recovery_configured,
                        local_recovery_configured,
                        account_has_other_devices(),
                    ),
                };
                let already = recovery_auto_prompt_already_prompted(
                    &store,
                    &actor,
                    account_recovery_configured,
                );
                (inputs, already, local_only_fingerprint)
            };
            if crate::account_health::should_auto_prompt_recovery_setup(inputs, already_prompted) {
                recovery_auto_prompt_fired.set(true);
                let mut store = state_store.write();
                store.save_private_data(&actor, RECOVERY_AUTO_PROMPT_SHOWN_KEY, "1".to_owned());
                if let Some(fingerprint) = local_only_fingerprint {
                    store.save_private_data(
                        &actor,
                        RECOVERY_AUTO_PROMPT_LOCAL_ONLY_SHOWN_KEY,
                        fingerprint,
                    );
                }
                recovery_key_setup_prompt.set(true);
            }
        });
    }
    {
        use_effect(move || {
            let lookup_base_url = base_url();
            let lookup_actor = account_did();
            let lookup_token = token();
            let lookup_supported = server_description().as_ref().is_some_and(|description| {
                description.supports_operation(OP_LIST_HANDLES_FOR_SUBJECT)
            });
            let key = format!(
                "{}|{}|{}|{}",
                lookup_base_url,
                lookup_actor,
                !lookup_token.trim().is_empty(),
                lookup_supported,
            );
            if personal_handles_lookup_key() == key {
                return;
            }
            personal_handles_lookup_key.set(key);
            if lookup_token.trim().is_empty() || lookup_actor.trim().is_empty() {
                account_primary_handle.set(String::new());
                personal_handles.set(Vec::new());
                personal_handles_status.set("No authenticated session".to_owned());
                return;
            }
            if !lookup_supported {
                if personal_handles().is_empty() {
                    personal_handles_status.set("Not published".to_owned());
                }
                return;
            }
            personal_handles_status.set("Loading handles".to_owned());
            let base = lookup_base_url.clone();
            let actor = lookup_actor.clone();
            let api_token = lookup_token.clone();
            let existing_personal_handles = personal_handles();
            spawn(async move {
                match CokretApi::new(&base)
                    .and_then(|api| api.with_bearer(api_token).sdk_http_client())
                {
                    Ok(http) => match crate::directory_api::list_handles_for_subject(
                        &http,
                        &actor,
                        None,
                        Some("display"),
                    )
                    .await
                    {
                        Ok(res) => {
                            let directory_handles = display_handles_from_directory_response(&res);
                            if directory_handles.is_empty() {
                                // Mirror the error branches below: keep any
                                // account viewer primary handle claim already
                                // loaded instead of clobbering it with an empty
                                // directory page.
                                if existing_personal_handles.is_empty() {
                                    try_set_signal(
                                        personal_handles_status,
                                        "No handles published".to_owned(),
                                    );
                                }
                            } else {
                                let handles = merge_personal_handles(
                                    &existing_personal_handles,
                                    directory_handles,
                                );
                                try_set_signal(
                                    personal_handles_status,
                                    personal_handles_status_for(&handles),
                                );
                                try_set_signal(personal_handles, handles);
                            }
                        }
                        Err(err) => {
                            tracing::warn!(
                                ?err,
                                "directory list_handles_for_subject failed; keeping account primary handle claim"
                            );
                            if existing_personal_handles.is_empty() {
                                try_set_signal(personal_handles_status, "Not published".to_owned());
                            }
                        }
                    },
                    Err(err) => {
                        tracing::warn!(
                            ?err,
                            "directory list_handles_for_subject skipped for invalid server URL"
                        );
                        if existing_personal_handles.is_empty() {
                            try_set_signal(personal_handles_status, "Not published".to_owned());
                        }
                    }
                }
            });
        });
    }
    {
        let mut contact_handles_lookup_key = contact_handles_lookup_key;
        let mut contact_handles_fetching = contact_handles_fetching;
        let mut state_store_for_contact_handles = state_store;
        use_effect(move || {
            let lookup_base_url = base_url();
            let lookup_token = token();
            let lookup_supported = server_description().as_ref().is_some_and(|description| {
                description.supports_operation(OP_LIST_HANDLES_FOR_SUBJECT)
            });
            let mut peers = direct_contact_rows
                .read()
                .iter()
                .map(|contact| contact.peer.trim().to_owned())
                .filter(|peer| peer.starts_with("did:"))
                .collect::<BTreeSet<_>>();
            if !lookup_supported || lookup_token.trim().is_empty() || peers.is_empty() {
                if !contact_handles_lookup_key().is_empty() {
                    contact_handles_lookup_key.set(String::new());
                }
                return;
            }
            peers.retain(|peer| {
                state_store_for_contact_handles
                    .read()
                    .cached_member_handle_lookup(peer, None, None)
                    .is_none()
                    && !contact_handles_fetching.read().contains(peer)
            });
            if peers.is_empty() {
                if !contact_handles_lookup_key().is_empty() {
                    contact_handles_lookup_key.set(String::new());
                }
                return;
            }
            let peer_key = peers.iter().cloned().collect::<Vec<_>>().join(",");
            let key = format!(
                "{}|{}|{}|{}",
                lookup_base_url,
                !lookup_token.trim().is_empty(),
                lookup_supported,
                peer_key,
            );
            if contact_handles_lookup_key() == key {
                return;
            }
            contact_handles_lookup_key.set(key);
            for peer in &peers {
                contact_handles_fetching.write().insert(peer.clone());
            }
            let base = lookup_base_url.clone();
            let api_token = lookup_token.clone();
            spawn(async move {
                for subject_id in peers {
                    let result =
                        crate::views::helpers::with_authed_sdk_client(&base, api_token.clone(), {
                            let subject_id = subject_id.clone();
                            move |http| async move {
                                crate::directory_api::list_handles_for_subject(
                                    &http,
                                    &subject_id,
                                    None,
                                    Some("display"),
                                )
                                .await
                            }
                        })
                        .await;
                    match result {
                        Ok(res) => {
                            let primary = res
                                .primary_handle
                                .as_ref()
                                .map(|handle| handle.canonical().to_owned());
                            let claims_count = res.claims.len();
                            let earliest_expiry = res
                                .claims
                                .iter()
                                .filter_map(|claim| claim.expires_at.as_ref().cloned())
                                .min();
                            state_store_for_contact_handles
                                .write()
                                .save_member_handle_lookup(
                                    res.subject.as_str().to_owned(),
                                    None,
                                    None,
                                    primary,
                                    claims_count,
                                    Some(res.as_of),
                                    earliest_expiry,
                                );
                        }
                        Err(err) if !err.is_auth_expired() => {
                            state_store_for_contact_handles
                                .write()
                                .save_member_handle_lookup(
                                    subject_id.clone(),
                                    None,
                                    None,
                                    None,
                                    0,
                                    None,
                                    None,
                                );
                        }
                        Err(_) => {}
                    }
                    contact_handles_fetching.write().remove(&subject_id);
                }
            });
        });
    }
    let active_server_label = normalize_server_url(&base_url());
    let account_did_value = account_did();
    let device_id_value = device_id();
    let account_did_label = short_protocol_id(&account_did_value);
    let device_id_label = short_protocol_id(&device_id_value);
    let personal_handles_value = personal_handles();
    let account_handles_label =
        account_handles_display(&personal_handles_value, &personal_handles_status());
    let account_handles_title = if personal_handles_value.is_empty() {
        account_handles_label.clone()
    } else {
        personal_handles_value.join(", ")
    };
    let account_label = if has_session {
        personal_handles_value
            .first()
            .map(|handle| format!("@{handle}"))
            .unwrap_or_else(|| display_name_for_did(&state_store.read(), &account_did_value))
    } else {
        "Not signed in".to_owned()
    };
    let account_detail = if has_session {
        format!("device {device_id_label}")
    } else {
        "Refresh server metadata, then sign in".to_owned()
    };
    // Topbar account avatar — mirror the Account identity avatar from
    // settings so the menu trigger shows the same uploaded photo (or the
    // same default letter + tone circle) instead of a generic person glyph.
    let topbar_avatar_initial =
        crate::views::settings::default_avatar_initial(&personal_handles_value, &account_did_value);
    let topbar_avatar_tone =
        crate::views::settings::default_avatar_tone(&personal_handles_value, &account_did_value);
    // Wrapped in `use_memo` so the App only re-renders when the avatar ref
    // actually changes — reading `state_store` directly here would subscribe
    // the whole shell to every (frequent) state_store write (drafts, etc.).
    let topbar_avatar_blob_ref = use_memo(move || {
        if token().trim().is_empty() {
            String::new()
        } else {
            state_store
                .read()
                .load_private_data(&account_did(), "avatar_blob_ref")
                .unwrap_or_default()
        }
    })();
    let frontier_label = frontier_state();
    let frontier_label_display = short_protocol_id(&frontier_label);
    let push_label = push_state();
    let crypto_label = crypto_state();
    let account_session_label = account_session_state();
    let queue_label = device_queue().to_string();
    let minimal_ready = profile_ready(active_server_description.as_ref(), PROFILE_MINIMAL_CLIENT);
    let kanban_ready = profile_ready(active_server_description.as_ref(), PROFILE_KANBAN_MVP);
    let full_ready = profile_ready(active_server_description.as_ref(), PROFILE_FULL_CLIENT);
    let e2ee_ready = profile_ready(active_server_description.as_ref(), PROFILE_E2EE_CLIENT);
    let event_write_ready = active_server_description
        .as_ref()
        .map(|description| description.supports_event_envelope_write_plane())
        .unwrap_or(false);
    let route_uses_realm_context = route_uses_realm_context(&route);
    let context_realm_id = if route_uses_realm_context {
        effective_realm_id.clone()
    } else {
        None
    };
    {
        let mut seen_publish_key = mls_key_package_publish_key_seen;
        let secure_store_ready_for_publish = secure_store_bootstrap_ready;
        use_effect(move || {
            if !secure_store_ready_for_publish() {
                return;
            }
            if crate::event_signer::active_signer().is_none() {
                return;
            }
            // Gate on device authorization. Publishing a KeyPackage requires an
            // ACCEPTED `ck.device.authorize` — soland rejects the upload with
            // `claim_generation_mismatch` ("accepted device authorization is
            // required") otherwise. The device-authorization check + auto-enroll
            // (app/connect.rs) runs CONCURRENTLY with this publish effect; without
            // this gate the upload can lose the race, fail, and — because the
            // publish is deduped on `seen_publish_key` (set before the spawn) — it
            // is NEVER retried, so the device stays KeyPackage-less and every
            // invite of it dies at admission with `mls_keypackage_not_found`.
            // Reading both signals subscribes this effect, so it re-fires and
            // publishes once the device becomes authorized.
            if !device_authorization_check_complete() || needs_device_authorization() {
                return;
            }
            let base = base_url();
            let session = token();
            let actor = account_did();
            let device = device_id();
            let description = server_description();
            let Some(publish_key) = mls_key_package_publish_key(
                &base,
                &session,
                &actor,
                &device,
                profile_ready(description.as_ref(), PROFILE_E2EE_CLIENT),
                sync_bootstrap_complete(),
            ) else {
                return;
            };
            let publish_hint = local_mls_key_package_publish_hint(&base, &actor, &device);
            let publish_key = format!("{publish_key}|kp={publish_hint}");
            if seen_publish_key().as_deref() == Some(publish_key.as_str()) {
                return;
            }
            seen_publish_key.set(Some(publish_key));
            spawn(async move {
                match ensure_local_mls_key_package_published(base, session, actor, device).await {
                    Ok(Some(key_package_id)) => {
                        tracing::debug!(
                            key_package_id = %short_protocol_id(&key_package_id),
                            "local MLS KeyPackage is published"
                        );
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::warn!(%error, "MLS KeyPackage publish bootstrap failed");
                    }
                }
            });
        });
    }
    {
        // Admin-side MLS admission reconciliation — the producer counterpart of
        // the invitee Welcome bootstrap below. When a member actually joins an
        // encrypted Realm this device administers, (re)admit anyone not yet in
        // the MLS group so their `ck.mls.welcome` is finally produced. Closes
        // the invite-time race where admission ran before the invitee had
        // published a KeyPackage: re-runs each sync round (via `sync_cursor`)
        // so a member who publishes their KeyPackage after joining is picked up.
        // Also observes `realm_live_epoch`, because join/accept events may
        // arrive through the per-Realm stream without advancing account sync.
        let admit_state_store = state_store;
        let admit_sync_cursor = sync_cursor;
        let admit_realm_live_epoch = realm_live_epoch;
        let mut admit_in_flight = mls_admission_reconcile_in_flight;
        let mut admit_pending = mls_admission_reconcile_pending;
        let mut admit_last_error = last_error;
        let mut admit_diag_last = mls_admission_diag_last;
        let secure_store_ready_for_admit = secure_store_bootstrap_ready;
        let admit_route_enabled = realm_events_route_enabled;
        use_effect(move || {
            if !secure_store_ready_for_admit() {
                return;
            }
            if !admit_route_enabled() {
                return;
            }
            let description = server_description();
            if !profile_ready(description.as_ref(), PROFILE_E2EE_CLIENT)
                || !sync_bootstrap_complete()
            {
                return;
            }
            let base = base_url();
            let session = token();
            let actor = account_did();
            let device = device_id();
            if base.trim().is_empty() || session.trim().is_empty() || actor.trim().is_empty() {
                return;
            }
            // Re-fire on every sync round so a late-published KeyPackage is
            // retried; cheap pre-filter avoids work when there is nothing to do.
            let _ = admit_sync_cursor();
            let _ = admit_realm_live_epoch();
            let _ = admit_pending();
            let candidate_realms = {
                let store = admit_state_store.read();
                crate::views::realm_admin::mls_admission_candidate_realms_for_actor(&store, &actor)
            };
            if candidate_realms.is_empty() {
                // Make a stuck admin observable: an encrypted Realm with an
                // invitee waiting for a Welcome but the admin never admitting is
                // exactly this branch. wasm tracing is capped at WARN, so INFO/
                // DEBUG here would be invisible — emit a throttled WARN naming
                // the blocking cause. (mls-admission-debug)
                let Some(diag) = ({
                    let store = admit_state_store.read();
                    let encrypted_local_realms = store
                        .load()
                        .realm_tree_projections
                        .keys()
                        .filter(|realm_id| {
                            realm_id.starts_with("ck:realm:")
                                && store.realm_projection_is_mls_encrypted(realm_id)
                        })
                        .count();
                    if encrypted_local_realms == 0 {
                        None
                    } else {
                        let encrypted_snapshot_realms = store
                            .mls_snapshots()
                            .keys()
                            .filter(|realm_id| {
                                realm_id.starts_with("ck:realm:")
                                    && store.realm_projection_is_mls_encrypted(realm_id)
                            })
                            .count();
                        Some(format!(
                            "candidate_realms=0 encrypted_local_realms={encrypted_local_realms} encrypted_snapshot_realms={encrypted_snapshot_realms}"
                        ))
                    }
                }) else {
                    return;
                };
                if admit_diag_last() != diag {
                    admit_diag_last.set(diag.clone());
                    tracing::warn!(
                        target: "mls_admission",
                        %diag,
                        "admission pre-filter blocked: no joined non-self member is visible in any local encrypted Realm"
                    );
                }
                return;
            }
            let candidate_diag = candidate_realms
                .iter()
                .map(|(realm_id, joined_sig)| format!("{realm_id}:joined=[{joined_sig}]"))
                .collect::<Vec<_>>()
                .join("|");
            if admit_diag_last() != candidate_diag {
                admit_diag_last.set(candidate_diag.clone());
                tracing::warn!(
                    target: "mls_admission",
                    candidate_count = candidate_realms.len(),
                    diag = %candidate_diag,
                    "admission pre-filter passed: reconciling local encrypted Realm candidates"
                );
            }
            // Read in-flight with `peek()` (NOT `()`) so this effect does not
            // subscribe to the guard and self-spin on set(true)/set(false).
            // If a real sync/realm-stream edge arrives while a reconcile is
            // running, remember one pending rerun; completion flips that bit
            // back to false and lets the subscribed effect run once more.
            if *admit_in_flight.peek() {
                // Write ONLY on a real false→true transition. This effect
                // subscribes to `admit_pending` (see the `admit_pending()`
                // read above), and a plain `set()` marks the signal dirty even
                // when the value is unchanged — so an unconditional set() here
                // would re-fire this very effect and spin the main thread
                // (same class as the in_flight self-spin fixed earlier).
                if !*admit_pending.peek() {
                    admit_pending.set(true);
                }
                return;
            }
            // Same guard on the reset path: an unconditional `set(false)` runs
            // on every non-in-flight pass and is the loop seed — it retriggers
            // the subscribed effect with no external change. Only clear a flag
            // that is actually set.
            if *admit_pending.peek() {
                admit_pending.set(false);
            }
            admit_in_flight.set(true);
            spawn(async move {
                let outcome =
                    crate::views::helpers::with_authed_api(&base, session, |api| async move {
                        let mut admitted_total = 0_usize;
                        let mut failures = Vec::<String>::new();
                        for (realm_id, _) in candidate_realms {
                            match crate::views::realm_admin::reconcile_mls_admissions_for_realm(
                                &api,
                                admit_state_store,
                                realm_id.clone(),
                                actor.clone(),
                                device.clone(),
                            )
                            .await
                            {
                                Ok(admitted) => admitted_total += admitted,
                                Err(error) => failures
                                    .push(format!("{}: {error:?}", short_protocol_id(&realm_id))),
                            }
                        }
                        Ok::<_, anyhow::Error>((admitted_total, failures))
                    })
                    .await;
                admit_in_flight.set(false);
                if *admit_pending.peek() {
                    admit_pending.set(false);
                }
                match outcome {
                    Ok((admitted, failures)) if admitted > 0 => {
                        tracing::warn!(
                            target: "mls_admission",
                            admitted,
                            "admitted joined members into MLS group"
                        );
                        if !failures.is_empty() {
                            tracing::warn!(
                                target: "mls_admission",
                                failures = %failures.join("; "),
                                "MLS admission reconcile had per-Realm failures after admitting some members"
                            );
                            admit_last_error.set(Some(format!(
                                "MLS admission reconcile: {}",
                                failures.join("; ")
                            )));
                        }
                    }
                    Ok((_, failures)) if !failures.is_empty() => {
                        tracing::warn!(
                            target: "mls_admission",
                            failures = %failures.join("; "),
                            "MLS admission reconcile failed for all attempted Realm candidates"
                        );
                        admit_last_error.set(Some(format!(
                            "MLS admission reconcile: {}",
                            failures.join("; ")
                        )));
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(
                            target: "mls_admission",
                            ?error,
                            "MLS admission reconcile failed"
                        );
                        admit_last_error.set(Some(format!("MLS admission reconcile: {error:?}")));
                    }
                }
            });
        });
    }
    {
        // History sharing (encryption-and-audit.md): drain the to-device inbox
        // for this Realm, (a) installing every inbound `ck.realm_key.share`'s
        // sealed `history_secret`s so pre-join content becomes decryptable
        // (tier-3), and (b) — as a provider — answering every inbound
        // `ck.realm_key.request` by sealing the retained history range back to
        // the requester. Re-runs each sync round so a late share/request is
        // picked up; a single-flight guard prevents overlap.
        let share_route_uses_realm_context = route_uses_realm_context;
        let share_context_realm_id = context_realm_id.clone();
        let mut share_state_store = state_store;
        let share_sync_cursor = sync_cursor;
        let mut share_in_flight = realm_key_sharing_in_flight;
        let mut share_request_dedup = realm_key_request_dedup;
        let mut share_answer_backoff = realm_key_answer_backoff_until;
        let secure_store_ready_for_share = secure_store_bootstrap_ready;
        let share_did_cache = did_cache;
        use_effect(move || {
            if !secure_store_ready_for_share() {
                return;
            }
            let active_realm_id = share_route_uses_realm_context
                .then(|| {
                    share_context_realm_id
                        .clone()
                        .unwrap_or_else(|| selected_realm_id())
                })
                .filter(|realm_id| !realm_id.trim().is_empty());
            let description = server_description();
            if !profile_ready(description.as_ref(), PROFILE_E2EE_CLIENT)
                || !sync_bootstrap_complete()
            {
                return;
            }
            let base = base_url();
            let session = token();
            let actor = account_did();
            let device = device_id();
            if base.trim().is_empty()
                || session.trim().is_empty()
                || actor.trim().is_empty()
                || device.trim().is_empty()
            {
                return;
            }
            // Re-fire on every sync round so a freshly delivered share/request is
            // consumed.
            let _ = share_sync_cursor();
            // Cheap pre-filter: drain inbound realm-key envelopes globally by
            // their own Realm binding. Provider response is a to-device duty,
            // not a page-local action; the active Realm only matters for this
            // device's receiver-initiated pull.
            let (shares_by_realm, requests, pull_request_key) = {
                let store = share_state_store.read();
                let inbox = store.to_device_inbox();
                let answer_backoff = share_answer_backoff.peek().clone();
                let now_ms = crate::clock::now_unix_ms();
                let mut shares_by_realm = BTreeMap::<String, Vec<serde_json::Value>>::new();
                for message in &inbox {
                    let kind = message
                        .get("kind")
                        .or_else(|| message.get("type"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();
                    if kind != cokret_sdk::events::kinds::REALM_KEY_SHARE {
                        continue;
                    }
                    if let Some(share_realm_id) =
                        crate::mls::runtime::realm_key_share_message_realm_id(message)
                    {
                        shares_by_realm
                            .entry(share_realm_id)
                            .or_default()
                            .push(message.clone());
                    }
                }
                let requests: Vec<_> = inbox
                    .iter()
                    .filter_map(crate::views::realm_admin::parse_realm_key_request_envelope)
                    .filter(|request| {
                        request.payload.target_principal_id.as_str().trim() == actor.trim()
                            && request.payload.target_source_ref.trim() == device.trim()
                            && answer_backoff
                                .get(
                                    &crate::views::realm_admin::realm_key_request_answer_dedup_key(
                                        request,
                                    ),
                                )
                                .is_none_or(|retry_after_ms| *retry_after_ms <= now_ms)
                    })
                    .collect();
                let pull_request_key = active_realm_id.as_ref().and_then(|realm_id| {
                    crate::views::realm_admin::pending_history_request_dedup_key(
                        &store, realm_id, &actor,
                    )
                });
                (shares_by_realm, requests, pull_request_key)
            };
            let needs_pull = pull_request_key
                .as_deref()
                .is_some_and(|key| share_request_dedup().as_deref() != Some(key));
            if shares_by_realm.is_empty() && requests.is_empty() && !needs_pull {
                return;
            }
            if share_in_flight() {
                return;
            }
            share_in_flight.set(true);
            // (b) Answer inbound requests (network).
            spawn(async move {
                // (a) Install inbound shares locally. SEC-02: before verifying
                // each share's `sender_device_signature` we MUST resolve the
                // sender device's authoritative directory key, so the
                // synchronous verifier can fail-closed on a Miss (an
                // unauthenticated empty signature is no longer tolerated). The
                // resolution is a `keys/query` per missing sender device, primed
                // here into the shared device-directory cache the verifier reads.
                if !shares_by_realm.is_empty() {
                    let sender_pairs: Vec<(String, String)> = shares_by_realm
                        .values()
                        .flat_map(|shares| shares.iter())
                        .filter_map(crate::mls::runtime::realm_key_share_sender_device_pair)
                        .collect();
                    if !sender_pairs.is_empty() {
                        let _ = crate::views::helpers::with_authed_api(
                            &base,
                            session.clone(),
                            |api| async move {
                                crate::sync_engine::prefetch_device_key_pairs(
                                    &api,
                                    sender_pairs,
                                    share_did_cache,
                                )
                                .await;
                                Ok::<(), anyhow::Error>(())
                            },
                        )
                        .await;
                    }
                    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                    let mut store = share_state_store.write();
                    let mut installed_by_realm = BTreeMap::<String, usize>::new();
                    let mut installed_share_ids = Vec::<String>::new();
                    for (share_realm_id, shares) in &shares_by_realm {
                        for share in shares {
                            let count = crate::mls::runtime::ingest_realm_key_share(
                                &mut store,
                                secure_store.as_ref(),
                                share_realm_id,
                                &actor,
                                &device,
                                share,
                            );
                            if count > 0 {
                                *installed_by_realm
                                    .entry(share_realm_id.to_string())
                                    .or_default() += count;
                                if let Some(operation_id) =
                                    crate::mls::runtime::realm_key_share_message_operation_id(share)
                                {
                                    installed_share_ids.push(operation_id);
                                }
                            }
                        }
                    }
                    for operation_id in installed_share_ids {
                        let _ = store.dismiss_realm_key_share_to_device_message(&operation_id);
                    }
                    for (share_realm_id, count) in installed_by_realm {
                        tracing::info!(
                            installed = count,
                            realm = %short_protocol_id(&share_realm_id),
                            "installed history_secret(s) from ck.realm_key.share"
                        );
                    }
                }
                for request_envelope in requests {
                    let realm = request_envelope.realm_id.clone();
                    let realm_for_log = realm.clone();
                    let request_id = request_envelope.request_id.clone();
                    let request_key = crate::views::realm_admin::realm_key_request_answer_dedup_key(
                        &request_envelope,
                    );
                    let request = request_envelope.payload;
                    let actor_c = actor.clone();
                    let device_c = device.clone();
                    let outcome = crate::views::helpers::with_authed_api(
                        &base,
                        session.clone(),
                        |api| async move {
                            crate::views::realm_admin::share_history_to_requester(
                                &api,
                                share_state_store,
                                realm,
                                actor_c,
                                device_c,
                                &request,
                            )
                            .await
                        },
                    )
                    .await;
                    match outcome {
                        Ok(true) => {
                            share_answer_backoff.write().remove(&request_key);
                            if let Some(request_id) = request_id {
                                let removed = share_state_store
                                    .write()
                                    .dismiss_realm_key_request_to_device_message(&request_id);
                                if removed > 0 {
                                    tracing::debug!(
                                        request_id = %short_protocol_id(&request_id),
                                        "dismissed answered ck.realm_key.request from local inbox"
                                    );
                                }
                            }
                        }
                        Ok(false) => {
                            let retry_after_ms = crate::clock::now_unix_ms()
                                .saturating_add(REALM_KEY_SHARE_ANSWER_RETRY_BACKOFF_MS);
                            share_answer_backoff
                                .write()
                                .insert(request_key, retry_after_ms);
                        }
                        Err(error) => {
                            let retry_after_ms = crate::clock::now_unix_ms()
                                .saturating_add(REALM_KEY_SHARE_ANSWER_RETRY_BACKOFF_MS);
                            share_answer_backoff
                                .write()
                                .insert(request_key, retry_after_ms);
                            tracing::warn!(
                                realm = %short_protocol_id(&realm_for_log),
                                ?error,
                                "ck.realm_key.share answer failed; backing off request retry"
                            );
                        }
                    }
                }
                // (c) Receiver-initiated pull: ask a joined provider device to
                // seal the missing pre-join history range to this device. Guarded
                // by `needs_pull` (dedup against the installed-secret signature) so
                // we emit at most one request per distinct gap state.
                if needs_pull && let Some(realm) = active_realm_id {
                    let realm_for_log = realm.clone();
                    let actor_c = actor.clone();
                    let device_c = device.clone();
                    let outcome = crate::views::helpers::with_authed_api(
                        &base,
                        session.clone(),
                        |api| async move {
                            crate::views::realm_admin::request_history_keys_for_realm(
                                &api,
                                share_state_store,
                                realm,
                                actor_c,
                                device_c,
                            )
                            .await
                        },
                    )
                    .await;
                    match outcome {
                        // Record the dedup key only after a request was actually
                        // emitted. `pending_history_request_dedup_key` and the
                        // async requester read state at different times; if the
                        // second read observes a transiently incomplete inbox /
                        // projection and returns `None`, deduping would suppress
                        // the only retry path for late-join history.
                        Ok(Some(_)) => {
                            if let Some(key) = pull_request_key.clone() {
                                share_request_dedup.set(Some(key));
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            tracing::debug!(
                                realm = %short_protocol_id(&realm_for_log),
                                ?error,
                                "history key request deferred (will retry on next sync)"
                            );
                        }
                    }
                }
                share_in_flight.set(false);
            });
        });
    }
    {
        let bootstrap_route_uses_realm_context = route_uses_realm_context;
        let bootstrap_context_realm_id = context_realm_id.clone();
        let mut seen_bootstrap_key = mls_welcome_bootstrap_key_seen;
        let state_store_for_bootstrap = state_store;
        let crypto_state_for_bootstrap = crypto_state;
        let last_error_for_bootstrap = last_error;
        let mut needs_mls_unlock_for_bootstrap = needs_mls_unlock;
        let mut needs_mls_backup_for_bootstrap = needs_mls_backup;
        let mut needs_mls_recovery_setup_for_bootstrap = needs_mls_recovery_setup;
        let mut restore_payload_cache_for_bootstrap = mls_restore_payload_cache;
        let secure_store_ready_for_bootstrap = secure_store_bootstrap_ready;
        let account_recovery_configured_for_bootstrap = account_recovery_configured;
        use_effect(move || {
            if !secure_store_ready_for_bootstrap() {
                return;
            }
            let selected = selected_realm_id();
            if !bootstrap_route_uses_realm_context {
                return;
            }
            let bootstrap_realm_id = bootstrap_context_realm_id
                .clone()
                .filter(|space| !space.trim().is_empty())
                .unwrap_or(selected);
            let base = base_url();
            let session = token();
            let actor = account_did();
            let device = device_id();
            let description = server_description();
            let account_recovery_configured_value = account_recovery_configured_for_bootstrap();
            let Some(bootstrap_key) = mls_welcome_bootstrap_key(
                &base,
                &session,
                &actor,
                &device,
                &bootstrap_realm_id,
                profile_ready(description.as_ref(), PROFILE_E2EE_CLIENT),
                sync_bootstrap_complete(),
            ) else {
                return;
            };
            // BUG X4: the per-Realm bootstrap caches its `seen` key, so after
            // the user's first encrypted write *creates* the account MLS
            // secret (and this Realm's MLS snapshot) the detection would
            // never re-run and the backup prompt would never appear. Read a
            // `state_store` signal in the synchronous body (`has_local_mls_snapshot`)
            // so Dioxus re-fires this effect when the write saves the snapshot,
            // and fold both the local account-secret presence (`sec=`) and the
            // snapshot presence (`snap=`) into the key so the `seen` guard no
            // longer matches once they flip false→true. The matching local
            // Welcome hint is also folded in so a sync-delivered pending
            // Welcome retriggers the drain after an earlier empty probe.
            let state_for_bootstrap_key = state_store_for_bootstrap.read();
            let has_local_mls_snapshot = state_for_bootstrap_key
                .mls_snapshot_for(&bootstrap_realm_id)
                .is_some();
            let has_encrypted_realm_projection =
                state_for_bootstrap_key.realm_projection_is_mls_encrypted(&bootstrap_realm_id);
            let local_mls_epoch_floor = crate::mls::runtime::mls_restore_epoch_floor(
                &state_for_bootstrap_key,
                &bootstrap_realm_id,
            );
            let recovery_key_fingerprint = crate::views::recovery::local_recovery_key_fingerprint(
                &state_for_bootstrap_key,
                &actor,
            )
            .unwrap_or_default();
            let local_pending_welcome_hint = crate::mls::runtime::local_mls_welcome_hint_for_realm(
                &state_for_bootstrap_key.to_device_inbox(),
                &bootstrap_realm_id,
            );
            drop(state_for_bootstrap_key);
            let has_local_account_secret = crate::mls::runtime::load_account_mls_secret(
                crate::secure_key_store::default_secure_key_store("inkson").as_ref(),
                &actor,
            )
            .map(|secret| secret.is_some())
            .unwrap_or(false);
            let bootstrap_key = format!(
                "{bootstrap_key}|sec={has_local_account_secret}|snap={has_local_mls_snapshot}|enc={has_encrypted_realm_projection}|epoch={local_mls_epoch_floor}|rk={recovery_key_fingerprint}|welcome={local_pending_welcome_hint}|recovery={account_recovery_configured_value:?}"
            );
            if seen_bootstrap_key().as_deref() == Some(bootstrap_key.as_str()) {
                return;
            }
            seen_bootstrap_key.set(Some(bootstrap_key.clone()));
            let seen_bootstrap_key_for_probe = seen_bootstrap_key;

            let state_store_task = state_store_for_bootstrap;
            let mut crypto_state_task = crypto_state_for_bootstrap;
            let mut last_error_task = last_error_for_bootstrap;
            let realm_label = short_protocol_id(&bootstrap_realm_id);
            // Detection-step clones: the originals are moved into the Welcome
            // bootstrap call below; we reuse these for the account-secret
            // unlock probe afterwards.
            let detect_base = base.clone();
            let detect_session = session.clone();
            let detect_actor = actor.clone();
            let detect_device = device.clone();
            let mut state_store_for_probe = state_store_for_bootstrap;
            spawn(async move {
                match bootstrap_mls_welcome_for_realm(
                    base,
                    session,
                    actor,
                    device,
                    bootstrap_realm_id,
                    state_store_task,
                    needs_mls_backup_for_bootstrap,
                )
                .await
                {
                    Ok(outcome) if outcome.applied > 0 => {
                        let backup_label = outcome
                            .backup_id
                            .as_deref()
                            .map(short_protocol_id)
                            .unwrap_or_else(|| "not uploaded".to_owned());
                        crypto_state_task.set(format!(
                            "MLS Welcome applied for {realm_label}: {} group(s); history backup {backup_label}",
                            outcome.applied
                        ));
                    }
                    Ok(_) => {}
                    Err(error) => {
                        last_error_task.set(Some(format!("MLS Welcome bootstrap: {error}")));
                    }
                }

                // Step-3 detection: if this device has no local account MLS
                // secret yet OR local MLS history is missing/stale, and the
                // server holds recovery material, flag the unlock prompt.
                // Detection errors must NOT block or fail boot — log and
                // leave the flag false.
                let has_local_account_secret = crate::mls::runtime::load_account_mls_secret(
                    crate::secure_key_store::default_secure_key_store("inkson").as_ref(),
                    &detect_actor,
                )
                .map(|secret| secret.is_some())
                .unwrap_or(false);
                let actor_for_sidecar_restore = detect_actor.clone();
                let device_for_sidecar_restore = detect_device.clone();
                match crate::views::helpers::with_authed_api(
                    &detect_base,
                    detect_session.clone(),
                    |api| async move {
                        let payload =
                            crate::mls::account_recovery::fetch_mls_restore_payload(&api).await?;
                        let sidecar_body_for_local_restore = if has_local_account_secret {
                            crate::mls::account_recovery::fetch_mls_private_plaintext_backup_body(
                                &api,
                                &actor_for_sidecar_restore,
                                &device_for_sidecar_restore,
                            )
                            .await
                            .ok()
                            .flatten()
                        } else {
                            None
                        };
                        Ok((payload, sidecar_body_for_local_restore))
                    },
                )
                .await
                {
                    Ok((payload, sidecar_body_for_local_restore)) => {
                        if seen_bootstrap_key_for_probe().as_deref() != Some(bootstrap_key.as_str())
                        {
                            return;
                        }
                        let secure_store =
                            crate::secure_key_store::default_secure_key_store("inkson");
                        let configured_backup_id =
                            crate::mls::account_recovery::select_preferred_mls_account_secret_backup(
                                &payload,
                            )
                            .and_then(|backup| {
                                backup
                                    .get("backup_id")
                                    .and_then(serde_json::Value::as_str)
                                    .map(str::to_owned)
                            });
                        {
                            let mut store = state_store_for_probe.write();
                            if let Some(backup_id) = configured_backup_id.as_deref() {
                                crate::components::mark_mls_recovery_backup_configured(
                                    &mut store,
                                    &detect_actor,
                                    backup_id,
                                );
                            }
                            let report = crate::mls::account_recovery::restore_mls_history_with_local_secret_from_payload(
                                &payload,
                                &mut store,
                                secure_store.as_ref(),
                                &detect_actor,
                                &detect_device,
                            );
                            if report.failed > 0 {
                                tracing::warn!(
                                    failed = report.failed,
                                    restored = report.restored,
                                    first_error = ?report.first_error,
                                    "mls history restore from local secret failed"
                                );
                            }
                            if let Some(sidecar_body) = sidecar_body_for_local_restore.as_ref() {
                                let sidecar_payload =
                                    serde_json::json!({ "backups": [sidecar_body.clone()] });
                                let report = crate::mls::account_recovery::restore_mls_history_with_local_secret_from_payload(
                                    &sidecar_payload,
                                    &mut store,
                                    secure_store.as_ref(),
                                    &detect_actor,
                                    &detect_device,
                                );
                                if report.failed > 0 {
                                    tracing::warn!(
                                        failed = report.failed,
                                        restored = report.restored,
                                        first_error = ?report.first_error,
                                        "mls sidecar restore from local secret failed"
                                    );
                                }
                            }
                        }
                        let should_unlock = {
                            let store = state_store_for_probe.read();
                            crate::mls::account_recovery::mls_restore_prompt_required(
                                &payload,
                                &store,
                                secure_store.as_ref(),
                                &detect_actor,
                                &detect_device,
                            )
                        };
                        // Mutual exclusion (task X3): restore (unlock) wins.
                        // Otherwise, if the user just created an encrypted
                        // realm (local secret now exists) but has no server
                        // backup, flag the one-time backup prompt instead.
                        if should_unlock {
                            restore_payload_cache_for_bootstrap.set(Some(payload.clone()));
                            needs_mls_unlock_for_bootstrap.set(true);
                            needs_mls_backup_for_bootstrap.set(false);
                            needs_mls_recovery_setup_for_bootstrap.set(false);
                        } else if needs_mls_unlock_for_bootstrap() {
                            // Keep an already-rendered unlock modal stable when
                            // the boot-time and per-Realm probes resolve out of
                            // order with different payload freshness.
                            needs_mls_backup_for_bootstrap.set(false);
                            needs_mls_recovery_setup_for_bootstrap.set(false);
                        } else {
                            let should_backup =
                                crate::mls::account_recovery::mls_backup_prompt_required(
                                    &payload,
                                    secure_store.as_ref(),
                                    &detect_actor,
                                    &detect_device,
                                );
                            if should_backup {
                                crate::components::maybe_auto_backup_mls_after_encrypted_write(
                                    detect_base.clone(),
                                    detect_session.clone(),
                                    detect_actor.clone(),
                                    detect_device.clone(),
                                    state_store_for_probe,
                                    needs_mls_backup_for_bootstrap,
                                )
                                .await;
                            } else {
                                needs_mls_backup_for_bootstrap.set(false);
                            }
                            let should_recovery_setup = {
                                let store = state_store_for_probe.read();
                                mls_recovery_setup_missing(
                                    &payload,
                                    &store,
                                    secure_store.as_ref(),
                                    &detect_actor,
                                    account_recovery_configured_value,
                                )
                            };
                            needs_mls_recovery_setup_for_bootstrap
                                .set(!should_backup && should_recovery_setup);
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            error = %error.display(),
                            "MLS account-secret unlock detection failed"
                        );
                    }
                }
            });
        });
    }
    let resolved_realm_surface = resolve_realm_surface(
        &route,
        &state_store(),
        &account_did(),
        context_realm_id.as_deref(),
    );
    let realm_members_active = matches!(&route, Route::RealmMembers { .. });
    if let (Some(realm_id), Some(surface)) = (routed_realm_id.as_deref(), resolved_realm_surface)
        && matches!(
            &route,
            Route::KanbanRealm { .. } | Route::KanbanBoard { .. } | Route::KanbanBoardTask { .. }
        )
    {
        let stored_surface =
            load_realm_surface_preference(&state_store(), &account_did(), realm_id);
        if stored_surface != surface {
            persist_realm_surface_preference(
                &mut state_store.write(),
                &account_did(),
                realm_id,
                surface,
            );
        }
    }

    let loaded_realm_tree_nodes = realm_tree_nodes();
    // The principal control / self Realm (device ledger, key log, and the
    // holder's own private uploads — see key-management.md §4.1) is account
    // infrastructure, not a collaboration workspace, so it MUST NOT show up in
    // the sidebar realm list. Derive its canonical id from the account DID and
    // hide that node plus its descendants, mirroring the direct-conversation
    // filter below.
    let self_realm_id: Option<String> = cokret_sdk::Did::new(account_did())
        .ok()
        .map(|did| cokret_sdk::auth::principal_control_realm_id(&did));
    let hidden_realm_tree_node_ids: BTreeSet<String> = loaded_realm_tree_nodes
        .iter()
        .filter(|node| {
            node.kind == RealmTreeNodeKind::Realm
                && (realm_tree_node_looks_like_direct_conversation(node)
                    || self_realm_id.as_deref() == Some(node.id.as_str()))
        })
        .flat_map(|node| descendant_node_ids(&loaded_realm_tree_nodes, &node.id))
        .collect();
    let collaboration_realm_tree_nodes: Vec<_> = loaded_realm_tree_nodes
        .iter()
        .filter(|node| !hidden_realm_tree_node_ids.contains(node.id.as_str()))
        .cloned()
        .collect();
    let selected_preview = loaded_realm_tree_nodes
        .iter()
        .find(|node| context_realm_id.as_deref() == Some(node.id.as_str()))
        .cloned();
    let active_projection_realm_id =
        projection_realm_id_for_known_node(&loaded_realm_tree_nodes, &active_realm_id)
            .unwrap_or_default();
    let direct_contact_count = direct_contact_rows.read().len();
    let pinned_realm_ids = {
        let store = state_store.read();
        pinned_realm_ids_from_store(&store)
    };
    let realm_tree =
        realm_tree_items_with_pinned_realms(&collaboration_realm_tree_nodes, &pinned_realm_ids);
    let realm_tree_projections = state_store.read().load().realm_tree_projections;
    let collaboration_sidebar_query_value =
        collaboration_sidebar_query().trim().to_ascii_lowercase();
    let direct_sidebar_query_value = direct_sidebar_query().trim().to_ascii_lowercase();
    let realm_remarks_for_sidebar = state_store.read().realm_remarks();
    let contact_remarks_for_sidebar = state_store.read().contact_remarks();
    let filtered_realm_tree: Vec<_> = realm_tree
        .iter()
        .filter(|item| {
            let display_name = realm_remarks_for_sidebar
                .get(&item.node.id)
                .map(|remark| remark.display_name(&item.node.title).to_owned())
                .unwrap_or_else(|| item.node.title.clone());
            let kind_label = match item.node.kind {
                RealmTreeNodeKind::Realm => "realm",
                RealmTreeNodeKind::Space => "space",
            };
            sidebar_text_matches_query(
                &collaboration_sidebar_query_value,
                &[&item.node.id, &item.node.title, &display_name, kind_label],
            )
        })
        .cloned()
        .collect();
    let manage_realm_rows: Vec<_> = collaboration_realm_tree_nodes
        .iter()
        .filter(|node| node.kind == RealmTreeNodeKind::Realm)
        .map(|node| {
            let display_name = realm_remarks_for_sidebar
                .get(&node.id)
                .map(|remark| remark.display_name(&node.title).to_owned())
                .unwrap_or_else(|| node.title.clone());
            let encrypted = realm_tree_projections
                .get(&node.id)
                .is_some_and(realm_projection_is_encrypted);
            let space_count = descendant_node_ids(&collaboration_realm_tree_nodes, &node.id)
                .len()
                .saturating_sub(1);
            RealmManageRow {
                realm_id: node.id.clone(),
                display_name,
                title: node.title.clone(),
                encrypted,
                space_count,
            }
        })
        .collect::<Vec<_>>();
    let mut filtered_direct_contact_rows: Vec<_> = direct_contact_rows
        .read()
        .iter()
        .filter(|contact| {
            let display_name = display_name_for_did(&state_store.read(), &contact.peer);
            let scopes = contact
                .bidirectional_scopes
                .iter()
                .chain(contact.effective_scopes.iter())
                .chain(contact.granted_by_me.iter())
                .chain(contact.granted_to_me.iter())
                .cloned()
                .collect::<Vec<_>>()
                .join(" ");
            sidebar_text_matches_query(
                &direct_sidebar_query_value,
                &[&contact.peer, &contact.state, &display_name, &scopes],
            )
        })
        .cloned()
        .collect();
    filtered_direct_contact_rows.sort_by(|left, right| {
        let left_remark = contact_remarks_for_sidebar.get(&left.peer);
        let right_remark = contact_remarks_for_sidebar.get(&right.peer);
        let left_pinned = left_remark.is_some_and(|remark| remark.pinned);
        let right_pinned = right_remark.is_some_and(|remark| remark.pinned);
        let left_label = display_name_for_did(&state_store.read(), &left.peer).to_ascii_lowercase();
        let right_label =
            display_name_for_did(&state_store.read(), &right.peer).to_ascii_lowercase();
        right_pinned
            .cmp(&left_pinned)
            .then_with(|| left_label.cmp(&right_label))
            .then_with(|| left.peer.cmp(&right.peer))
    });
    let active_security_scope_id = if active_projection_realm_id.trim().is_empty() {
        active_realm_id.as_str()
    } else {
        active_projection_realm_id.as_str()
    };
    let active_realm_security_encrypted = crate::security_state::security_projection_for_scope_id(
        &realm_tree_projections,
        active_security_scope_id,
    )
    .or_else(|| {
        crate::security_state::security_projection_for_scope_id(
            &realm_tree_projections,
            &active_realm_id,
        )
    })
    .map(crate::security_state::realm_projection_is_encrypted)
    .unwrap_or(false);
    let active_locale = locale();
    let active_direction = active_locale.direction();
    let direction_attr = active_direction.as_str();
    let locale_attr = active_locale.code();
    let active_theme = theme();
    let sidebar_is_collapsed = sidebar_collapsed();
    let sidebar_is_resizing = sidebar_resizing();
    let server_menu_is_open = server_menu_open();
    let configured_principal_servers = config_store.read().load().principal_servers;
    let server_options = server_options_for(&base_url(), &configured_principal_servers);
    let sidebar_style = format!("--sidebar-w: {:.0}px;", sidebar_width());
    let theme_is_night = theme_renders_as_night(&active_theme, system_theme_is_night());
    // The shell's `data-theme` carries the *raw* chosen mode
    // (`light` | `night` | `system`) as an app/diagnostic signal (the e2e theme
    // assertions read it). All *styling* is driven off the *effective* canonical
    // `light`/`dark` value that `apply_document_root_theme` mirrors onto `<html>`:
    // design.css / app_overrides tokens and the vendored dxc palette key on
    // `:root` / `html[data-theme]`, and app.css's `--ck-*` + auth surfaces key on
    // `[data-theme="dark"]` (the `<html>` ancestor). Nothing styling-related
    // depends on this attribute, so it stays the raw mode.
    let theme_attr = active_theme.as_str();
    let theme_toggle_icon = if theme_is_night { "sun" } else { "moon" };
    let theme_toggle_title = if theme_is_night {
        "Switch to light theme"
    } else {
        "Switch to night theme"
    };
    let route_title = resolved_realm_surface
        .map(RealmSurface::title)
        .unwrap_or_else(|| route_label(&route));
    let topbar_context_title = selected_preview
        .as_ref()
        .map(|space| space.title.clone())
        .unwrap_or_else(|| {
            if route_uses_realm_context {
                "Space".to_owned()
            } else {
                route_title.to_owned()
            }
        });
    let topbar_search_is_open =
        palette_open() || topbar_search_expanded() || !global_query().is_empty();
    let topbar_unread_notifications = unread_notification_count(&state_store.read().load());
    let has_topbar_unread_notifications = topbar_unread_notifications > 0;
    let document_title = if matches!(&route, Route::Dashboard) {
        "Inkson | Cokret".to_owned()
    } else {
        format!("{route_title} | Inkson | Cokret")
    };
    let shell_class = format!(
        "shell app{}{}{}",
        if active_direction == TextDirection::Rtl {
            " rtl"
        } else {
            ""
        },
        if sidebar_is_collapsed {
            " sidebar-collapsed"
        } else {
            ""
        },
        if sidebar_is_resizing {
            " sidebar-resizing"
        } else {
            ""
        }
    );
    // Unified single-root render: the auth surface (Restoring / Login /
    // Callback) and the full app shell are rendered from ONE `rsx!` template
    // below, branched by an inner `if/else`. Returning two *different* root
    // templates from separate `return rsx!{…}` sites made Dioxus skip the
    // root-template swap (the freshly-rendered AppShell tree was computed but
    // never committed, leaving the stale auth-card DOM on screen — the
    // invitee "stuck on Restoring session" bug). A single template with a
    // dynamic if/else node reconciles reliably.
    let auth_class = format!(
        "auth-shell{}",
        if active_direction == TextDirection::Rtl {
            " rtl"
        } else {
            ""
        }
    );
    let login_navigator = navigator;
    let callback_navigator = navigator;
    let mut login_bootstrap_pending = bootstrap_pending;
    let mut callback_bootstrap_pending = bootstrap_pending;
    let mut login_session_boot_state = session_boot_state;
    let mut callback_session_boot_state = session_boot_state;
    let auth_shell_node = rsx! {
            main {
                class: auth_class,
                "dir": direction_attr,
                "lang": locale_attr,
                "data-direction": direction_attr,
                "data-locale": locale_attr,
                "data-theme": theme_attr,
                "data-testid": "auth-shell",
                div { class: "auth-card",
                    match auth_surface {
                        AuthSurface::Callback => rsx! {
                            crate::views::login::LoginPanel {
                                base_url,
                                account_did,
                                device_id,
                                token,
                                connection_status,
                                config_store,
                                state_store,
                                account_primary_handle,
                                personal_handles,
                                personal_handles_status,
                                auto_capture_callback: true,
                                on_login: move |_| {
                                    callback_bootstrap_pending.set(true);
                                    callback_session_boot_state.set(SessionBootState::Checking);
                                    let _ = callback_navigator.push(Route::Dashboard);
                                },
                            }
                        },
                        AuthSurface::Restoring => rsx! {
                            section {
                                class: "auth-panel auth-restore",
                                "data-testid": "session-restore-panel",
                                role: "status",
                                "aria-live": "polite",
                                div { class: "auth-brand",
                                    div { class: "auth-logo", "C" }
                                    div {
                                        h1 { "Restoring session" }
                                        p { "Cokret" }
                                    }
                                }
                                div { class: "auth-restore-indicator", "aria-hidden": "true" }
                                div {
                                    class: "auth-status",
                                    "data-testid": "session-restore-status",
                                    "{connection_status()}"
                                }
                            }
                        },
                        AuthSurface::Login | AuthSurface::AppShell => rsx! {
                            crate::views::login::LoginPanel {
                                base_url,
                                account_did,
                                device_id,
                                token,
                                connection_status,
                                config_store,
                                state_store,
                                account_primary_handle,
                                personal_handles,
                                personal_handles_status,
                                auto_capture_callback: false,
                                on_login: move |_| {
                                    login_bootstrap_pending.set(true);
                                    login_session_boot_state.set(SessionBootState::Checking);
                                    let _ = login_navigator.push(Route::Dashboard);
                                },
                            }
                        },
                    }
                }
                Outlet::<Route> {}
            }
    };

    let content_route = if matches!(&route, Route::Login) && has_session {
        Route::Dashboard
    } else {
        route.clone()
    };
    // Single source of truth for the post-boot account-health prompt chain.
    // Each prompt below renders iff it is the resolved highest-priority one,
    // replacing the per-prompt inline suppression that used to drift apart.
    // See `account_health` and `docs/user-strands-key-lifecycle.md` §3.
    let active_prompt = {
        let store = state_store.read();
        let actor = account_did();
        let local_recovery_configured =
            crate::views::recovery::recovery_options_configured(&store, &actor);
        let account_recovery_configured = account_recovery_configured();
        crate::account_health::AccountHealthInputs {
            has_session,
            sync_bootstrap_complete: sync_bootstrap_complete(),
            device_check_complete: device_authorization_check_complete(),
            on_recovery_route: matches!(
                &content_route,
                Route::Recovery | Route::SettingsRecovery
            ),
            recovery_check_complete: account_recovery_configured.is_some(),
            needs_device_authorization: needs_device_authorization(),
            needs_mls_unlock: needs_mls_unlock(),
            needs_mls_backup: needs_mls_backup(),
            needs_mls_recovery_setup: needs_mls_recovery_setup(),
            floor_low:
                crate::components::encryption_floor_prompt::account_needs_recommended_encryption_prompt(
                    &store, &actor,
                ),
            recovery_unconfigured: recovery_setup_prompt_required_for_account_state(
                account_recovery_configured,
                local_recovery_configured,
                account_has_other_devices(),
            ),
        }
        .resolve()
    };
    use crate::account_health::AccountHealthPrompt;
    let show_recovery_setup_prompt =
        active_prompt == AccountHealthPrompt::RecoverySetupReminder && !recovery_key_setup_prompt();
    // Per-account durable suppression for the advisory encryption-floor check:
    // once auto-acknowledged it stays quiet across navigations and sessions (the
    // in-session `encryption_floor_prompt_dismissed` signal covers the same
    // frame before the persisted flag is read back).
    let encryption_floor_prompt_acknowledged =
        crate::app::encryption_floor_prompt_acknowledged(&state_store.read(), &account_did());

    rsx! {
        style { "{DXC_THEME}" }
        style { "{STYLE}" }
        style { "{DESIGN_STYLE}" }
        style { "{APP_OVERRIDES}" }
        document::Title { "{document_title}" }
        if matches!(auth_surface, AuthSurface::AppShell) {
        style { "html, body, #main {{ height: 100%; overflow: hidden; }}" }
        div {
            class: shell_class,
            style: "{sidebar_style}",
            "dir": direction_attr,
            "lang": locale_attr,
            "data-direction": direction_attr,
            "data-locale": locale_attr,
            "data-theme": theme_attr,
            "data-testid": "client-shell",
            tabindex: "-1",
            // A6.4 — global key handler. `?` (Shift+/) opens the
            // shortcut-help overlay unless the event originated from a
            // text input / textarea / contenteditable surface. `Esc`
            // dismisses transient overlays.
            // A6.1 — `Cmd+F` (Ctrl+F on non-Mac) opens the global
            // cross-Space message search panel; we intercept the
            // browser's native find-in-page because the in-app panel
            // covers all Realms and Spaces the user has access to.
            onkeydown: move |event| {
                let key = event.key().to_string();
                let modifiers = event.modifiers();
                let ctrl = modifiers.ctrl();
                let meta = modifiers.meta();
                if (ctrl || meta) && key.eq_ignore_ascii_case("k") {
                    event.prevent_default();
                    event.stop_propagation();
                    topbar_search_expanded.set(true);
                    palette_open.set(true);
                    return;
                }
                if crate::views::global_search::key_event_is_search_trigger(&key, ctrl, meta) {
                    event.prevent_default();
                    event.stop_propagation();
                    let _ = navigator.push(Route::Search);
                    return;
                }
                if key == "Escape" {
                    if notifications_drawer_open() {
                        notifications_drawer_open.set(false);
                        event.prevent_default();
                        event.stop_propagation();
                        return;
                    }
                    if shortcut_help_open() {
                        shortcut_help_open.set(false);
                        event.prevent_default();
                        event.stop_propagation();
                        return;
                    }
                    if palette_open() || topbar_search_expanded() || !global_query().trim().is_empty() {
                        palette_open.set(false);
                        topbar_search_expanded.set(false);
                        global_query.set(String::new());
                        event.prevent_default();
                        event.stop_propagation();
                    }
                    return;
                }
                if crate::components::shortcut_help::key_event_is_help_trigger(&key) {
                    // We can't reliably inspect event.target() in
                    // dioxus 0.7 (the target type is opaque); however
                    // text inputs already swallow the key event before
                    // it reaches the shell when they're focused — so
                    // this handler is only reached for "global" key
                    // presses. Toggle the overlay.
                    shortcut_help_open.set(true);
                    event.stop_propagation();
                }
            },
            onclick: move |_| {
                if palette_open() || topbar_search_expanded() || !global_query().trim().is_empty() {
                    palette_open.set(false);
                    topbar_search_expanded.set(false);
                    global_query.set(String::new());
                }
            },
            onmousemove: move |event| {
                if sidebar_resizing() && !sidebar_collapsed() {
                    let next_width = clamp_sidebar_width(event.client_coordinates().x);
                    sidebar_width.set(next_width);
                }
            },
            onmouseup: move |_| {
                if sidebar_resizing() {
                    let mut store = state_store.write();
                    save_sidebar_width_preference(&mut store, sidebar_width());
                }
                sidebar_resizing.set(false);
            },
            onmouseleave: move |_| {
                if sidebar_resizing() {
                    let mut store = state_store.write();
                    save_sidebar_width_preference(&mut store, sidebar_width());
                }
                sidebar_resizing.set(false);
            },
            // Unified feedback (docs/design/unified-feedback-system.md
            // Wave 0). AppBanner: single-slot persistent banner; the
            // offline condition is derived from the sync engine's
            // network state ("offline"/"reconnecting"/"online") and
            // gated on an active session so the pre-connect boot frame
            // does not flash the banner.
            crate::components::AppBanner {
                offline: !token().is_empty() && network_state() == "offline",
            }
            // ToastHost: stacked transient toasts. Drains the generic
            // toast queue plus the policy-deny queue (fed by
            // `api_error::decode_cokret_error`'s policy-deny dispatch,
            // G3.Y3) and the CKP-0007 circle-error queue (fed by
            // `maybe_dispatch_circle_error`), so any 403 / Circle error
            // is surfaced without each call site wiring its own UI.
            crate::components::ToastHost {}
            crate::components::DidResolutionHealthBanner { health: did_resolution_health }
            Outlet::<Route> {}
            crate::components::DeviceAuthorizationPrompt {
                needs_device_authorization,
            }
            // device-lifecycle.md §2.1/§7 — surface an incoming same-principal
            // pairing request on this (authorized) device so the user can
            // compare the pairing code and approve/reject without navigating to
            // the devices settings page.
            crate::components::DevicePairApprovalPrompt {
                base_url,
                token,
                device_id,
                state_store,
            }
            crate::components::AgentRuntimeApprovalPrompt {
                base_url,
                token,
                account_did,
            }
            if active_prompt == AccountHealthPrompt::RecommendedEncryptionFloor
                && !recovery_key_setup_prompt()
                && !encryption_floor_prompt_dismissed()
                && !encryption_floor_prompt_acknowledged
            {
                crate::components::EncryptionFloorPrompt {
                    token,
                    account_did,
                    state_store,
                    sync_bootstrap_complete,
                    device_authorization_check_complete,
                    needs_device_authorization,
                    needs_mls_unlock,
                    needs_mls_backup,
                    recovery_key_setup_prompt,
                    account_recovery_configured,
                    dismissed: encryption_floor_prompt_dismissed,
                }
            }
            crate::components::RecoveryKeySetupPrompt {
                base_url,
                token,
                account_did,
                device_id,
                state_store,
                open: recovery_key_setup_prompt,
                account_primary_handle,
                on_server_configured: move |_| account_recovery_configured.set(Some(true)),
            }
            if show_recovery_setup_prompt {
                div {
                    class: "event recovery-setup-banner",
                    "data-testid": "recovery-setup-banner",
                    role: "region",
                    "aria-label": "Recovery setup is incomplete",
                    div { class: "event-head",
                        strong { "Recovery setup is incomplete" }
                        span { class: "muted", "first-time setup" }
                    }
                    div { class: "muted",
                        "Generate your Recovery Key (24 words) before relying on this account. Backups are stored server-side as ciphertext only; Cokret cannot recover the 24 words for you."
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "recovery-setup-open-recovery",
                            onclick: move |_| recovery_key_setup_prompt.set(true),
                            UiIcon { name: "key" }
                            "Configure recovery"
                        }
                        Link {
                            class: "secondary",
                            "data-testid": "recovery-setup-open-encryption",
                            to: Route::SettingsSection { section: "encryption".to_owned() },
                            UiIcon { name: "lock" }
                            "Encrypted history status"
                        }
                    }
                    div { class: "muted",
                        "Encrypted-history recovery needs an account MLS secret; if this is a brand-new account, the app will prompt again after your first encrypted write creates material that can be backed up."
                    }
                }
            }
            // Fresh-device diagnostic: encrypted history exists, but no
            // passphrase-backed account-secret backup is available to unlock
            // on this browser.
            if active_prompt == AccountHealthPrompt::RecoverySetupMissing {
                crate::components::MlsRecoverySetupMissingBanner {
                    needs_mls_recovery_setup,
                    actor_id: account_did,
                }
            }
            // Step 3 of the account-MLS-secret auto-unlock strand: a
            // recovery-passphrase banner that restores encrypted history on
            // a fresh device. Renders nothing unless boot detection flagged
            // `needs_mls_unlock`.
            if active_prompt == AccountHealthPrompt::MlsUnlock {
                crate::components::MlsUnlockPrompt {
                    base_url,
                    token,
                    actor_id: account_did,
                    device_id,
                    state_store,
                    needs_mls_unlock,
                    restore_payload_cache: mls_restore_payload_cache,
                }
            }
            // Task X3 — one-time account-secret BACKUP prompt (mirror of the
            // unlock banner). Renders nothing unless detection flagged
            // `needs_mls_backup` (local secret exists, no server backup yet).
            if active_prompt == AccountHealthPrompt::MlsBackup {
                crate::components::MlsBackupPrompt {
                    base_url,
                    token,
                    actor_id: account_did,
                    device_id,
                    state_store,
                    needs_mls_backup,
                    account_recovery_configured,
                    account_primary_handle,
                }
            }
            div { class: "mobile-shellbar", "data-testid": "mobile-shellbar",
                Button {
                    variant: ButtonVariant::Ghost,
                    size: ButtonSize::Sm,
                    class: "btn icon",
                    "data-testid": "mobile-nav-toggle",
                    title: if mobile_nav_open() { "Close menu" } else { "Open menu" },
                    "aria-label": if mobile_nav_open() { "Close menu" } else { "Open menu" },
                    "aria-controls": "mobile-navigation-drawer",
                    "aria-expanded": "{mobile_nav_open()}",
                    onclick: move |_| mobile_nav_open.toggle(),
                    if mobile_nav_open() {
                        UiIcon { name: "x" }
                    } else {
                        UiIcon { name: "menu" }
                    }
                }
                div { class: "brand", "Cokret" }
                Button {
                    variant: ButtonVariant::Ghost,
                    size: ButtonSize::Sm,
                    class: "btn icon",
                    "data-testid": "mobile-theme-toggle",
                    title: "{theme_toggle_title}",
                    "aria-label": "{theme_toggle_title}",
                    onclick: move |_| {
                        let current_theme = theme();
                        let next = next_manual_theme(&current_theme);
                        theme.set(next.clone());
                        state_store.write().save_private_data(&account_did(), "theme", next.clone());
                        // A4a — best-effort cross-device sync via
                        // `ck.account_data.set(client.ui)`.
                        crate::views::settings::push_client_ui_account_data(
                            base_url(),
                            token(),
                            next,
                        );
                    },
                    UiIcon { name: theme_toggle_icon }
                }
                Button {
                    variant: ButtonVariant::Ghost,
                    size: ButtonSize::Sm,
                    r#type: "button",
                    class: "btn icon",
                    "data-testid": "mobile-shortcuts-button",
                    title: crate::i18n::tr("shortcuts.title"),
                    "aria-label": crate::i18n::tr("shortcuts.title"),
                    onclick: move |event: dioxus::events::MouseEvent| {
                        event.stop_propagation();
                        mobile_nav_open.set(false);
                        shortcut_help_open.set(true);
                    },
                    UiIcon { name: "keyboard" }
                }
                Button {
                    variant: ButtonVariant::Ghost,
                    size: ButtonSize::Sm,
                    r#type: "button",
                    class: if notifications_drawer_open() { "btn icon topbar-notifications-link is-active" } else { "btn icon topbar-notifications-link" },
                    "data-testid": "mobile-topbar-notifications-button",
                    title: "Notifications",
                    "aria-label": "Notifications",
                    "aria-expanded": "{notifications_drawer_open()}",
                    onclick: move |event: dioxus::events::MouseEvent| {
                        event.stop_propagation();
                        mobile_nav_open.set(false);
                        account_menu_open.set(false);
                        server_menu_open.set(false);
                        if palette_open() || topbar_search_expanded() || !global_query().trim().is_empty() {
                            palette_open.set(false);
                            topbar_search_expanded.set(false);
                            global_query.set(String::new());
                        }
                        notifications_drawer_open.toggle();
                    },
                    UiIcon { name: "bell" }
                    if has_topbar_unread_notifications {
                        span { class: "topbar-notifications-badge", "aria-hidden": "true" }
                    }
                }
            }
            nav {
                id: "mobile-navigation-drawer",
                class: if mobile_nav_open() { "mobile-drawer open" } else { "mobile-drawer" },
                "data-testid": "mobile-nav-drawer",
                div { class: "mobile-status", "data-testid": "mobile-connection-status",
                    span { "data-testid": "mobile-status-label", "{connection_status}" }
                    span { class: "muted mono", "data-testid": "mobile-sync-cursor", "cursor {sync_cursor}" }
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "mobile-connect-button",
                        title: "Refresh server metadata and sync state",
                        "aria-label": "Refresh server metadata and sync state",
                        onclick: move |_| {
                            sync_generation.set(sync_generation() + 1);
                            sync_bootstrap_complete.set(false);
                            connect(
                                base_url(),
                                account_did(),
                                device_id(),
                                ConnectContext {
                                    connection_status,
                                    sync_cursor,
                                    token,
                                    account_did,
                                    device_id,
                                    selected_realm_id,
                                    realm_tree_nodes,
                                    projection_events,
                                    device_queue,
                                    frontier_state,
                                    crypto_state,
                                    config_store,
                                    state_store,
                                    network_state,
                                    last_error,
                                    server_description,
                                    server_probe_status,
                                    account_primary_handle,
                                    personal_handles,
                                    personal_handles_status,
                                    theme,
                                    sync_generation,
                                    needs_device_authorization,
                                    device_authorization_check_complete,
                                    account_has_other_devices,
                                    sync_bootstrap_complete,
                                    session_boot_state,
                                    call_signal_hub,
                                    did_cache,
                                    did_resolution_health,
                                },
                            )
                        },
                        "Refresh"
                    }
                }
                Link { class: "secondary", "data-testid": "mobile-dashboard-nav-button", to: Route::Dashboard, onclick: move |_| mobile_nav_open.set(false), {crate::i18n::tr("nav.dashboard")} }
                Link { class: "secondary", "data-testid": "mobile-file-transfer-nav-button", to: Route::FileTransfer, onclick: move |_| mobile_nav_open.set(false), "Files" }
                Link { class: "secondary", "data-testid": "mobile-directory-nav-button", to: Route::Directory, onclick: move |_| mobile_nav_open.set(false), {crate::i18n::tr("nav.directory")} }
                Link { class: "secondary", "data-testid": "mobile-settings-nav-button", to: Route::Settings, onclick: move |_| mobile_nav_open.set(false), {crate::i18n::tr("nav.settings")} }
                if !loaded_realm_tree_nodes.is_empty() {
                    div { class: "muted", "{crate::i18n::tr(\"command_palette.realms\")} ({realm_tree.len()})" }
                    Input {
                        class: "mobile-realm-tree-filter",
                        "data-testid": "mobile-realm-tree-filter",
                        value: "{mobile_space_query}",
                        placeholder: crate::i18n::tr("mobile.filter_realms"),
                        oninput: move |event: FormEvent| mobile_space_query.set(event.value()),
                    }
                    div { class: "mobile-realm-tree-list", "data-testid": "mobile-realm-tree-list",
                        {
                            let q = mobile_space_query();
                            let q_lc = q.trim().to_lowercase();
                            let filtered: Vec<_> = realm_tree
                                .iter()
                                .filter(|item| {
                                    q_lc.is_empty()
                                        || item.node.title.to_lowercase().contains(&q_lc)
                                        || item.node.id.to_lowercase().contains(&q_lc)
                                })
                                .collect();
                            if filtered.is_empty() {
                                rsx! {
                                    div { class: "muted", "data-testid": "mobile-realm-tree-empty", {crate::i18n::tr("mobile.no_match")} }
                                }
                            } else {
                                rsx! {
                                    for item in filtered.iter() {
                                        Link {
                                            class: "secondary",
                                            "data-testid": "mobile-realm-tree-nav-button",
                                            to: Route::Realm {
                                                realm_id: item.node.projection_realm_id().to_owned()
                                            },
                                            onclick: {
                                                let id = item.node.projection_realm_id().to_owned();
                                                move |_| {
                                                    selected_realm_id.set(id.clone());
                                                    mobile_nav_open.set(false);
                                                    mobile_space_query.set(String::new());
                                                }
                                            },
                                            "{item.node.title}"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            aside { class: "sidebar", "data-testid": "sidebar", role: "navigation", "aria-label": "Main navigation",
                div {
                    class: "sidebar-resize-handle",
                    "data-testid": "sidebar-resize-handle",
                    title: "Drag to resize menu",
                    "aria-hidden": "true",
                    onmousedown: move |event| {
                        event.prevent_default();
                        sidebar_resizing.set(true);
                    },
                }
                div { class: "sidebar-header",
                    Link { class: "brand", to: Route::Dashboard, "aria-label": "Inkson | Cokret Home",
                        span { class: "logo", "⌘" }
                        span { class: "product-meta",
                            span { class: "product-name", "Inkson | Cokret" }
                        }
                    }
                }

                div { class: "server-switch", "data-testid": "principal-context", "aria-label": "Current server context",
                    Button {
                        variant: ButtonVariant::Secondary,
                        class: "server-switch-button",
                        "data-testid": "server-switch-button",
                        title: "Switch server",
                        "aria-label": "Switch server",
                        "aria-expanded": if server_menu_is_open { "true" } else { "false" },
                        onclick: move |_| {
                            server_menu_open.toggle();
                            account_menu_open.set(false);
                        },
                        span { class: "server-switch-icon",
                            UiIcon { name: "server" }
                        }
                        span { class: "server-switch-title",
                            span { class: "v", "{active_server_label}" }
                        }
                        span { class: "server-switch-state",
                            if server_menu_is_open {
                                UiIcon { name: "chevron-up" }
                            } else {
                                UiIcon { name: "chevron-down" }
                            }
                        }
                    }

                    if server_menu_is_open && !sidebar_is_collapsed {
                        div { class: "server-switch-menu", "data-testid": "server-switch-menu",
                            div { class: "server-option-list", "aria-label": "Server choices",
                                for option_url in server_options.clone() {
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        class: if same_server_url(&option_url, &base_url()) { "server-option active" } else { "server-option" },
                                        "data-testid": "server-option",
                                        title: "Switch to {option_url}",
                                        "aria-label": "Switch to {option_url}",
                                        onclick: {
                                            let option_url = option_url.clone();
                                            move |_| {
                                                let next_url = normalize_server_url(&option_url);
                                                select_server(next_url.clone(), ServerSelectionContext {
                                                    base_url,
                                                    token,
                                                    sync_cursor,
                                                    selected_realm_id,
                                                    realm_tree_nodes,
                                                    projection_events,
                                                    device_queue,
                                                    frontier_state,
                                                    crypto_state,
                                                    config_store,
                                                    state_store,
                                                    network_state,
                                                    last_error,
                                                    server_description,
                                                    server_probe_status,
                                                    connection_status,
                                                    account_did,
                                                    device_id,
                                                    account_primary_handle,
                                                    personal_handles,
                                                    personal_handles_status,
                                                    personal_handles_lookup_key,
                                                    sync_generation,
                                                });
                                                server_menu_open.set(false);
                                                sync_bootstrap_complete.set(false);
                                                connect(
                                                    next_url,
                                                    account_did(),
                                                    device_id(),
                                                    ConnectContext {
                                                        connection_status,
                                                        sync_cursor,
                                                        token,
                                                        account_did,
                                                        device_id,
                                                        selected_realm_id,
                                                        realm_tree_nodes,
                                                        projection_events,
                                                        device_queue,
                                                        frontier_state,
                                                        crypto_state,
                                                        config_store,
                                                        state_store,
                                                        network_state,
                                                        last_error,
                                                        server_description,
                                                        server_probe_status,
                                                        account_primary_handle,
                                                        personal_handles,
                                                        personal_handles_status,
                                                        theme,
                                                        sync_generation,
                                                        needs_device_authorization,
                                                        device_authorization_check_complete,
                                                        account_has_other_devices,
                                                        sync_bootstrap_complete,
                                                        session_boot_state,
                                                        call_signal_hub,
                                                        did_cache,
                                                        did_resolution_health,
                                                    },
                                                );
                                            }
                                        },
                                        span { class: "server-option-text",
                                            span { class: "server-option-main mono", "{option_url}" }
                                        }
                                        if same_server_url(&option_url, &base_url()) {
                                            span { class: "pill muted xs", "current" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                div { class: "sidebar-nav-group",
                    Link { class: "sidebar-nav-item", to: Route::Dashboard,
                        span { class: "sidebar-nav-icon", UiIcon { name: "home" } }
                        span { class: "grow", "Home" }
                    }
                    Link { class: "sidebar-nav-item", to: Route::FileTransfer,
                        span { class: "sidebar-nav-icon", UiIcon { name: "file" } }
                        span { class: "grow", "Files" }
                    }
                }

                div { class: "sidebar-nav-group workspace-tab-group", "data-testid": "realm-tree-list",
                    if !sidebar_is_collapsed {
                        div { class: "sidebar-scope-toggle workspace-tabs", "data-testid": "realm-sidebar-mode-toggle", role: "tablist", "aria-label": "Collaboration and contacts",
                            Button {
                                variant: ButtonVariant::Secondary,
                                class: if realm_sidebar_tab() == "collaboration" { "scope-chip active" } else { "scope-chip" },
                                "data-testid": "realm-sidebar-tab-collaboration",
                                role: "tab",
                                "aria-selected": if realm_sidebar_tab() == "collaboration" { "true" } else { "false" },
                                onclick: move |_| realm_sidebar_tab.set("collaboration".to_owned()),
                                {crate::i18n::tr("nav.collaboration")}
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                class: if realm_sidebar_tab() == "direct" { "scope-chip active" } else { "scope-chip" },
                                "data-testid": "realm-sidebar-tab-direct",
                                role: "tab",
                                "aria-selected": if realm_sidebar_tab() == "direct" { "true" } else { "false" },
                                onclick: {
                                    let base = base_url();
                                    move |_| {
                                        realm_sidebar_tab.set("direct".to_owned());
                                        if direct_contacts_loaded() || token().trim().is_empty() {
                                            return;
                                        }
                                        load_direct_contacts_for_sidebar(
                                            base.clone(),
                                            token(),
                                            direct_contact_rows,
                                            direct_contacts_loaded,
                                        );
                                    }
                                },
                                {crate::i18n::tr("nav.contacts")}
                            }
                        }
                        div { class: "sidebar-tab-toolbar", "data-testid": "realm-sidebar-toolbar",
                            div { class: "sidebar-tab-search",
                                if realm_sidebar_tab() == "collaboration" {
                                    Input {
                                        "data-testid": "realm-sidebar-search-input",
                                        value: "{collaboration_sidebar_query}",
                                        placeholder: "Search Realms",
                                        oninput: move |event: FormEvent| collaboration_sidebar_query.set(event.value()),
                                    }
                                } else {
                                    Input {
                                        "data-testid": "contacts-sidebar-search-input",
                                        value: "{direct_sidebar_query}",
                                        placeholder: "Search Contacts",
                                        oninput: move |event: FormEvent| direct_sidebar_query.set(event.value()),
                                    }
                                }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    size: ButtonSize::IconXs,
                                    class: "sidebar-toolbar-action sidebar-tab-search-submit",
                                    r#type: "button",
                                    "data-testid": "realm-sidebar-search-button",
                                    title: "Search",
                                    "aria-label": "Search",
                                    onclick: {
                                        let base = base_url();
                                        move |_| {
                                            if realm_sidebar_tab() == "direct" && !direct_contacts_loaded() {
                                                load_direct_contacts_for_sidebar(
                                                    base.clone(),
                                                    token(),
                                                    direct_contact_rows,
                                                    direct_contacts_loaded,
                                                );
                                            }
                                        }
                                    },
                                    UiIcon { name: "search" }
                                }
                            }
                            if realm_sidebar_tab() == "collaboration" {
                                Link {
                                    class: "sidebar-toolbar-action sidebar-toolbar-link add-realm-cta",
                                    "data-testid": "sidebar-new-realm-cta",
                                    title: "Create a new Realm",
                                    "aria-label": "Create a new Realm",
                                    to: Route::SetupSection { section: "realms".to_owned() },
                                    UiIcon { name: "plus" }
                                }
                            } else {
                                Link {
                                    class: "sidebar-toolbar-action sidebar-toolbar-link add-contact-cta",
                                    "data-testid": "sidebar-new-contact-cta",
                                    title: "Add a contact",
                                    "aria-label": "Add a contact",
                                    to: Route::Contacts,
                                    UiIcon { name: "user-plus" }
                                }
                            }
                            if realm_sidebar_tab() == "collaboration" {
                                Link {
                                    class: if matches!(content_route, Route::RealmsManage) { "sidebar-toolbar-action sidebar-toolbar-link is-active" } else { "sidebar-toolbar-action sidebar-toolbar-link" },
                                    "data-testid": "realm-sidebar-manage-home-button",
                                    title: "Manage Realms",
                                    "aria-label": "Manage Realms",
                                    to: Route::RealmsManage,
                                    UiIcon { name: "home" }
                                }
                            } else {
                                Link {
                                    class: if matches!(content_route, Route::ContactsManage) { "sidebar-toolbar-action sidebar-toolbar-link is-active" } else { "sidebar-toolbar-action sidebar-toolbar-link" },
                                    "data-testid": "realm-sidebar-manage-home-button",
                                    title: "Manage Contacts",
                                    "aria-label": "Manage Contacts",
                                    to: Route::ContactsManage,
                                    onclick: {
                                        let base = base_url();
                                        move |_| {
                                            if direct_contacts_loaded() || token().trim().is_empty() {
                                                return;
                                            }
                                            load_direct_contacts_for_sidebar(
                                                base.clone(),
                                                token(),
                                                direct_contact_rows,
                                                direct_contacts_loaded,
                                            );
                                        }
                                    },
                                    UiIcon { name: "home" }
                                }
                            }
                        }
                    }
                    if realm_sidebar_tab() == "direct" {
                        if !sidebar_is_collapsed {
                            Link {
                                class: "sidebar-nav-item contact-sidebar-summary",
                                "data-testid": "contacts-sidebar-summary",
                                title: "Open the full Contacts list",
                                to: Route::Contacts,
                                span { class: "sidebar-nav-icon", UiIcon { name: "users" } }
                                span { class: "grow truncate", {crate::i18n::tr("nav.contacts")} }
                                span { class: "pill muted xs", "{direct_contact_count}" }
                            }
                        }
                        if direct_contact_rows.read().is_empty() {
                            div { class: "sidebar-nav-item is-dim", "data-testid": "direct-conversation-empty-state",
                                span { class: "sidebar-nav-icon", UiIcon { name: "users" } }
                                span { class: "grow truncate",
                                    {if has_session { crate::i18n::tr("contacts.empty") } else { crate::i18n::tr("contacts.sign_in") }}
                                }
                            }
                        } else if filtered_direct_contact_rows.is_empty() {
                            div { class: "sidebar-nav-item is-dim", "data-testid": "direct-conversation-no-results",
                                span { class: "sidebar-nav-icon", UiIcon { name: "search" } }
                                span { class: "grow truncate", "No matching contacts" }
                            }
                        } else {
                            for contact in filtered_direct_contact_rows.iter() {
                                {
                                    let peer = contact.peer.clone();
                                    let state_label = contact.state.clone();
                                    let scopes_label = contact.bidirectional_scopes.join(", ");
                                    let direct = contact.direct_conversation.clone();
                                    let has_direct_scope = contact
                                        .bidirectional_scopes
                                        .iter()
                                        .chain(contact.effective_scopes.iter())
                                        .any(|scope| scope == "direct_message");
                                    let has_active_direct = direct
                                        .as_ref()
                                        .is_some_and(|summary| summary.state == "active");
                                    let can_resolve =
                                        contact.state == "accepted" && (has_direct_scope || has_active_direct);
                                    let icon_name = if has_active_direct {
                                        "message"
                                    } else {
                                        "user"
                                    };
                                    let row_title = if can_resolve {
                                        crate::i18n::tr("direct.open")
                                    } else {
                                        crate::i18n::tr("direct.unavailable")
                                    };
                                    let contact_remark =
                                        contact_remarks_for_sidebar.get(&peer).cloned();
                                    let display_name = display_name_for_did(&state_store.read(), &peer);
                                                                        let has_contact_remark = contact_remark
                                        .as_ref()
                                        .is_some_and(|remark| !remark.local_name.trim().is_empty());
                                    let is_pinned_contact =
                                        contact_remark.as_ref().is_some_and(|remark| remark.pinned);
                                    let pin_contact_label = if is_pinned_contact {
                                        crate::i18n::tr("contact.unpin")
                                    } else {
                                        crate::i18n::tr("contact.pin")
                                    };
                                    let pinned_contact_badge_label =
                                        crate::i18n::tr("contact.pinned");
                                    let contact_menu_key = format!("contact:{peer}");
                                    let contact_menu_is_open =
                                        sidebar_row_menu_open().as_deref()
                                            == Some(contact_menu_key.as_str());
                                    rsx! {
                                        div { class: "sidebar-row contact-sidebar-action-row",
                                            key: "{peer}",
                                            button {
                                                class: if can_resolve { "sidebar-nav-item contact-sidebar-row sidebar-row-main" } else { "sidebar-nav-item contact-sidebar-row sidebar-row-main is-dim" },
                                                r#type: "button",
                                                "data-testid": "direct-conversation-row",
                                                "data-peer": "{peer}",
                                                "data-state": "{state_label}",
                                                title: "{row_title}",
                                                onclick: {
                                                    let peer = peer.clone();
                                                    let direct = direct.clone();
                                                    let base = base_url();
                                                    move |event: dioxus::events::MouseEvent| {
                                                        event.prevent_default();
                                                        event.stop_propagation();
                                                        if !can_resolve {
                                                            crate::components::feedback::toast_info("direct.unavailable", vec![]);
                                                            return;
                                                        }
                                                        if let Some(summary) = direct.clone()
                                                            && summary.state == "active"
                                                        {
                                                            let _ = navigator.push(Route::DirectConversation {
                                                                realm_id: summary.realm_id,
                                                                strand_id: summary.main_strand_id,
                                                            });
                                                            return;
                                                        }
                                                        let api_token = token();
                                                        let base = base.clone();
                                                        let peer_for_task = peer.clone();
                                                        spawn(async move {
                                                            let result = crate::views::helpers::with_authed_api(
                                                                &base,
                                                                api_token,
                                                                |api| async move {
                                                                    api.direct_conversation_resolve(&peer_for_task, true).await
                                                                },
                                                            ).await;
                                                            match result {
                                                                Ok(response) => {
                                                                    if matches!(
                                                                        response.state,
                                                                        cokret_sdk::DirectConversationResolveState::Found
                                                                            | cokret_sdk::DirectConversationResolveState::Created
                                                                    )
                                                                        && let (Some(realm_id), Some(strand_id)) = (response.realm_id, response.main_strand_id)
                                                                    {
                                                                        let _ = navigator.push(Route::DirectConversation {
                                                                            realm_id: realm_id.to_string(),
                                                                            strand_id: strand_id.to_string(),
                                                                        });
                                                                    } else {
                                                                        crate::components::feedback::toast_error(
                                                                            "feedback.direct_open_failed",
                                                                            vec![],
                                                                            Some(format!("state: {:?}", response.state)),
                                                                        );
                                                                    }
                                                                }
                                                                Err(err) => crate::components::feedback::toast_error(
                                                                    "feedback.direct_open_failed",
                                                                    vec![],
                                                                    Some(err.display()),
                                                                ),
                                                            }
                                                        });
                                                    }
                                                },
                                                span { class: "sidebar-nav-icon", UiIcon { name: icon_name.to_owned() } }
                                                span { class: "grow truncate", "{display_name}" }
                                                if has_contact_remark {
                                                    span {
                                                        class: "pill muted xs",
                                                        "data-testid": "contact-sidebar-remark-badge",
                                                        title: "Local remark (private to this account)",
                                                        "Remark"
                                                    }
                                                }
                                                if is_pinned_contact {
                                                    span {
                                                        class: "pill muted xs realm-pin-badge",
                                                        "data-testid": "contact-sidebar-pinned-badge",
                                                        title: "{pinned_contact_badge_label}",
                                                        UiIcon { name: "pin" }
                                                    }
                                                }
                                                span { class: "pill muted xs", "{state_label}" }
                                                if has_direct_scope {
                                                    span { class: "pill muted xs", title: "{scopes_label}", "DM" }
                                                }
                                            }
                                            div {
                                                class: if contact_menu_is_open { "sidebar-row-menu-host is-open" } else { "sidebar-row-menu-host" },
                                                button {
                                                    class: "sidebar-row-menu-button",
                                                    r#type: "button",
                                                    "data-testid": "direct-conversation-row-menu-button",
                                                    title: "Contact actions",
                                                    "aria-label": "Contact actions",
                                                    "aria-haspopup": "menu",
                                                    "aria-expanded": if contact_menu_is_open { "true" } else { "false" },
                                                    onclick: {
                                                        let key = contact_menu_key.clone();
                                                        move |event: dioxus::events::MouseEvent| {
                                                            event.prevent_default();
                                                            event.stop_propagation();
                                                            if sidebar_row_menu_open().as_deref() == Some(key.as_str()) {
                                                                sidebar_row_menu_open.set(None);
                                                            } else {
                                                                sidebar_row_menu_open.set(Some(key.clone()));
                                                            }
                                                        }
                                                    },
                                                    UiIcon { name: "more-horizontal" }
                                                }
                                                if contact_menu_is_open {
                                                    div {
                                                        class: "sidebar-row-menu-scrim",
                                                        "aria-label": "Close row actions",
                                                        onclick: move |_| sidebar_row_menu_open.set(None),
                                                    }
                                                    div {
                                                        class: "sidebar-row-menu-panel",
                                                        role: "menu",
                                                        "aria-label": "Contact actions",
                                                        button {
                                                            class: "sidebar-row-menu-item",
                                                            r#type: "button",
                                                            role: "menuitem",
                                                            "data-testid": "direct-conversation-row-pin-action",
                                                            title: "{pin_contact_label}",
                                                            "aria-label": "{pin_contact_label}",
                                                            onclick: {
                                                                let peer = peer.clone();
                                                                let existing = contact_remark.clone();
                                                                let next_pinned = !is_pinned_contact;
                                                                move |event: dioxus::events::MouseEvent| {
                                                                    event.prevent_default();
                                                                    event.stop_propagation();
                                                                    toggle_sidebar_contact_pin(
                                                                        peer.clone(),
                                                                        existing.clone(),
                                                                        next_pinned,
                                                                        state_store,
                                                                        base_url(),
                                                                        token(),
                                                                    );
                                                                    sidebar_row_menu_open.set(None);
                                                                }
                                                            },
                                                            UiIcon { name: "pin" }
                                                            span { "{pin_contact_label}" }
                                                        }
                                                        button {
                                                            class: "sidebar-row-menu-item danger",
                                                            r#type: "button",
                                                            role: "menuitem",
                                                            "data-testid": "direct-conversation-row-delete-action",
                                                            title: "Delete Contact",
                                                            "aria-label": "Delete Contact",
                                                            disabled: !has_session,
                                                            onclick: {
                                                                let peer = peer.clone();
                                                                move |event: dioxus::events::MouseEvent| {
                                                                    event.prevent_default();
                                                                    event.stop_propagation();
                                                                    delete_sidebar_contact(
                                                                        base_url(),
                                                                        token(),
                                                                        peer.clone(),
                                                                        state_store,
                                                                        direct_contact_rows,
                                                                        direct_contacts_loaded,
                                                                    );
                                                                    sidebar_row_menu_open.set(None);
                                                                }
                                                            },
                                                            UiIcon { name: "x" }
                                                            span { "Delete" }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else if collaboration_realm_tree_nodes.is_empty() {
                        div { class: "sidebar-nav-item is-dim", "data-testid": "realm-tree-empty-state",
                            span { class: "sidebar-nav-icon", UiIcon { name: "folder" } }
                            span { class: "grow truncate", if has_session { "No Realm tree loaded" } else { "Sign in to load Realms" } }
                        }
                        // Diagnostic line: when an authenticated user sees an
                        // empty sidebar, surface the latest connect status and
                        // (if any) last_error directly so QA / users can tell
                        // "sync failed" from "no Realms yet" without opening
                        // devtools. Truncated to keep the sidebar tidy.
                        if has_session && !sidebar_is_collapsed {
                            div { class: "sidebar-nav-meta",
                                "data-testid": "realm-tree-empty-state-status",
                                style: "padding: 4px 12px; font-size: 11px; line-height: 1.4; opacity: 0.7;",
                                {
                                    let status_text = connection_status();
                                    let error_text = last_error();
                                    let trimmed_status = if status_text.len() > 96 {
                                        format!("{}…", &status_text[..96])
                                    } else {
                                        status_text
                                    };
                                    let trimmed_error = error_text
                                        .as_ref()
                                        .map(|err| if err.len() > 96 {
                                            format!("{}…", &err[..96])
                                        } else {
                                            err.clone()
                                        });
                                    rsx! {
                                        div { "data-testid": "realm-tree-empty-state-status-line",
                                            "{trimmed_status}"
                                        }
                                        if let Some(err) = trimmed_error {
                                            div {
                                                "data-testid": "realm-tree-empty-state-error-line",
                                                style: "color: var(--danger, #d33);",
                                                "{err}"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else if filtered_realm_tree.is_empty() {
                        div { class: "sidebar-nav-item is-dim", "data-testid": "realm-tree-no-results",
                            span { class: "sidebar-nav-icon", UiIcon { name: "search" } }
                            span { class: "grow truncate", "No matching Realms" }
                        }
                    } else {
                        for item in filtered_realm_tree.iter() {
                            {
                                let item_node = item.node.clone();
                                let depth_px = item.depth * 14;
                                let target_realm_id = item_node.projection_realm_id().to_owned();
                                let is_active = item_node.kind == RealmTreeNodeKind::Realm
                                    && effective_realm_id.as_deref() == Some(item_node.id.as_str());
                                let item_class = if is_active {
                                    "sidebar-nav-item realm-tree-item is-active"
                                } else {
                                    "sidebar-nav-item realm-tree-item"
                                };
                                // Spec client-preferences.md §3.7: when the
                                // user has a private Realm remark, prefer its
                                // local_name; fall back to the public title.
                                // Use a "(remark)" badge so duplicate-titled
                                // Realms can be distinguished without leaking
                                // the remark beyond this device.
                                let remark = if item_node.kind == RealmTreeNodeKind::Realm {
                                    state_store.read().realm_remark(&item_node.id)
                                } else {
                                    None
                                };
                                let display_name = remark
                                    .as_ref()
                                    .map(|r| r.display_name(&item_node.title).to_owned())
                                    .unwrap_or_else(|| item_node.title.clone());
                                let has_remark = remark
                                    .as_ref()
                                    .is_some_and(|r| !r.local_name.trim().is_empty());
                                let is_pinned_realm = remark.as_ref().is_some_and(|r| r.pinned);
                                let can_pin_realm = item_node.kind == RealmTreeNodeKind::Realm
                                    && !realm_tree_node_looks_like_direct_conversation(&item_node);
                                let pin_action_label = if is_pinned_realm {
                                    crate::i18n::tr("realm.unpin")
                                } else {
                                    crate::i18n::tr("realm.pin")
                                };
                                let pinned_badge_label = crate::i18n::tr("realm.pinned");
                                let add_child_title = match item_node.kind {
                                    RealmTreeNodeKind::Realm => "Create a new Space at the root of this Realm",
                                    RealmTreeNodeKind::Space => "Create a new Space under this one (this Space becomes the parent)",
                                };
                                let menu_key = format!("realm:{}", item_node.id);
                                let menu_is_open =
                                    sidebar_row_menu_open().as_deref() == Some(menu_key.as_str());
                                // Add Member / Settings are Realm-scoped write
                                // actions: only surface them once the lazy authz
                                // probe (fired on menu open) has confirmed the
                                // actor may perform them. Absent / pending / denied
                                // all read as hidden (fail-closed).
                                let row_perms = if item_node.kind == RealmTreeNodeKind::Realm {
                                    sidebar_row_perms.read().get(&item_node.id).copied()
                                } else {
                                    None
                                };
                                let can_add_member =
                                    row_perms.map(|p| p.can_add_member).unwrap_or(false);
                                let can_open_settings =
                                    row_perms.map(|p| p.can_settings).unwrap_or(false);
                                let add_member_label = crate::i18n::tr("realm.add_member");
                                let settings_label = crate::i18n::tr("realm.settings");
                                let actions_title = match item_node.kind {
                                    RealmTreeNodeKind::Realm => "Realm actions",
                                    RealmTreeNodeKind::Space => "Space actions",
                                };
                                let (icon_name, icon_class, icon_title) = match item_node.kind {
                                    RealmTreeNodeKind::Realm => {
                                        let is_encrypted = realm_tree_projections
                                            .get(&item_node.id)
                                            .is_some_and(realm_projection_is_encrypted);
                                        if is_encrypted {
                                            (
                                                "lock",
                                                "sidebar-nav-icon realm-security-secure",
                                                "Encrypted Realm",
                                            )
                                        } else {
                                            (
                                                "unlock",
                                                "sidebar-nav-icon realm-security-unsafe",
                                                "Unencrypted Realm",
                                            )
                                        }
                                    }
                                    RealmTreeNodeKind::Space => (
                                        "folder",
                                        "sidebar-nav-icon",
                                        "Space",
                                    ),
                                };
                                rsx! {
                            div { class: "sidebar-row",
                            key: "{item_node.id}",
                            Link {
                                class: "{item_class} sidebar-row-main",
                                "data-testid": "realm-tree-node-button",
                                title: "{item_node.title}",
                                style: "padding-left: calc(10px + {depth_px}px);",
                                to: Route::Realm { realm_id: target_realm_id.clone() },
                                onclick: {
                                    let id = target_realm_id.clone();
                                    move |_| selected_realm_id.set(id.clone())
                                },
                                span {
                                    class: "{icon_class}",
                                    title: "{icon_title}",
                                    UiIcon { name: icon_name.to_owned() }
                                }
                                span { class: "grow truncate", "{display_name}" }
                                if has_remark {
                                    span {
                                        class: "pill muted xs",
                                        "data-testid": "realm-tree-realm-remark-badge",
                                        title: "Local remark (private to this account)",
                                        "Remark"
                                    }
                                }
                                if is_pinned_realm {
                                    span {
                                        class: "pill muted xs realm-pin-badge",
                                        "data-testid": "realm-tree-pinned-badge",
                                        title: "{pinned_badge_label}",
                                        UiIcon { name: "pin" }
                                    }
                                }
                                // Two-tier classification badge: Realm
                                // (security boundary) vs Space (nav
                                // container inside a Realm). When a
                                // Realm has descendants, show the count
                                // instead of the kind tag so the user
                                // sees the tree structure at a glance.
                                if item.descendant_count > 0 && item_node.kind == RealmTreeNodeKind::Realm {
                                    span { class: "pill muted xs", "{item.descendant_count}" }
                                } else {
                                    match item_node.kind {
                                        RealmTreeNodeKind::Realm => rsx! {
                                            span {
                                                class: "pill muted xs",
                                                "data-testid": "realm-tree-kind-realm",
                                                title: "Realm — security / sync / E2EE boundary (spec realm-and-space.md §2)",
                                                "Realm"
                                            }
                                        },
                                        RealmTreeNodeKind::Space => rsx! {
                                            span {
                                                class: "pill muted xs",
                                                "data-testid": "realm-tree-kind-space",
                                                title: "Space — navigation container inside a Realm (spec realm-and-space.md §3)",
                                                "Space"
                                            }
                                        },
                                    }
                                }
                            }
                            div {
                                class: if menu_is_open { "sidebar-row-menu-host is-open" } else { "sidebar-row-menu-host" },
                                button {
                                    class: "sidebar-row-menu-button",
                                    r#type: "button",
                                    "data-testid": "realm-tree-row-menu-button",
                                    title: "{actions_title}",
                                    "aria-label": "{actions_title}",
                                    "aria-haspopup": "menu",
                                    "aria-expanded": if menu_is_open { "true" } else { "false" },
                                    onclick: {
                                        let key = menu_key.clone();
                                        let perms_realm_id = item_node.id.clone();
                                        let probe_perms = item_node.kind == RealmTreeNodeKind::Realm;
                                        move |event: dioxus::events::MouseEvent| {
                                            event.prevent_default();
                                            event.stop_propagation();
                                            if sidebar_row_menu_open().as_deref() == Some(key.as_str()) {
                                                sidebar_row_menu_open.set(None);
                                            } else {
                                                sidebar_row_menu_open.set(Some(key.clone()));
                                                // Lazily resolve Add Member / Settings
                                                // visibility for just this Realm the
                                                // moment its menu opens.
                                                if probe_perms {
                                                    ensure_sidebar_row_perms(
                                                        base_url(),
                                                        token(),
                                                        account_did(),
                                                        perms_realm_id.clone(),
                                                        sidebar_row_perms,
                                                    );
                                                }
                                            }
                                        }
                                    },
                                    UiIcon { name: "more-horizontal" }
                                }
                                if menu_is_open {
                                    div {
                                        class: "sidebar-row-menu-scrim",
                                        "aria-label": "Close row actions",
                                        onclick: move |_| sidebar_row_menu_open.set(None),
                                    }
                                    div {
                                        class: "sidebar-row-menu-panel",
                                        role: "menu",
                                        "aria-label": "{actions_title}",
                                        if can_pin_realm {
                                            button {
                                                class: "sidebar-row-menu-item",
                                                r#type: "button",
                                                role: "menuitem",
                                                "data-testid": "realm-tree-row-pin-action",
                                                title: "{pin_action_label}",
                                                "aria-label": "{pin_action_label}",
                                                onclick: {
                                                    let id = item_node.id.clone();
                                                    let existing = remark.clone();
                                                    let next_pinned = !is_pinned_realm;
                                                    move |event: dioxus::events::MouseEvent| {
                                                        event.prevent_default();
                                                        event.stop_propagation();
                                                        toggle_sidebar_realm_pin(
                                                            id.clone(),
                                                            existing.clone(),
                                                            next_pinned,
                                                            state_store,
                                                            base_url(),
                                                            token(),
                                                        );
                                                        sidebar_row_menu_open.set(None);
                                                    }
                                                },
                                                UiIcon { name: "pin" }
                                                span { "{pin_action_label}" }
                                            }
                                        }
                                        Link {
                                            class: "sidebar-row-menu-item",
                                            role: "menuitem",
                                            "data-testid": "realm-tree-row-add-action",
                                            title: "{add_child_title}",
                                            "aria-label": "{add_child_title}",
                                            to: Route::SetupSection { section: "new-space".to_owned() },
                                            onclick: {
                                                let id = item_node.id.clone();
                                                let home_realm_id = target_realm_id.clone();
                                                move |_| {
                                                    selected_realm_id.set(home_realm_id.clone());
                                                    new_space_context_node.set(id.clone());
                                                    sidebar_row_menu_open.set(None);
                                                }
                                            },
                                            UiIcon { name: "plus" }
                                            span { "New Space" }
                                        }
                                        if can_add_member {
                                            Link {
                                                class: "sidebar-row-menu-item",
                                                role: "menuitem",
                                                "data-testid": "realm-tree-row-add-member-action",
                                                title: "{add_member_label}",
                                                "aria-label": "{add_member_label}",
                                                to: Route::RealmMembers { realm_id: target_realm_id.clone() },
                                                onclick: {
                                                    let home_realm_id = target_realm_id.clone();
                                                    move |_| {
                                                        selected_realm_id.set(home_realm_id.clone());
                                                        sidebar_row_menu_open.set(None);
                                                    }
                                                },
                                                UiIcon { name: "user-plus" }
                                                span { "{add_member_label}" }
                                            }
                                        }
                                        if can_open_settings {
                                            Link {
                                                class: "sidebar-row-menu-item",
                                                role: "menuitem",
                                                "data-testid": "realm-tree-row-settings-action",
                                                title: "{settings_label}",
                                                "aria-label": "{settings_label}",
                                                to: Route::RealmAdmin { realm_id: target_realm_id.clone() },
                                                onclick: {
                                                    let home_realm_id = target_realm_id.clone();
                                                    move |_| {
                                                        selected_realm_id.set(home_realm_id.clone());
                                                        sidebar_row_menu_open.set(None);
                                                    }
                                                },
                                                UiIcon { name: "settings" }
                                                span { "{settings_label}" }
                                            }
                                        }
                                        if item_node.kind == RealmTreeNodeKind::Realm {
                                            button {
                                                class: "sidebar-row-menu-item danger",
                                                r#type: "button",
                                                role: "menuitem",
                                                "data-testid": "realm-tree-row-leave-action",
                                                title: "Leave Realm",
                                                "aria-label": "Leave Realm",
                                                disabled: !has_session,
                                                onclick: {
                                                    let id = item_node.id.clone();
                                                    move |event: dioxus::events::MouseEvent| {
                                                        event.prevent_default();
                                                        event.stop_propagation();
                                                        leave_sidebar_realm(
                                                            base_url(),
                                                            token(),
                                                            id.clone(),
                                                            account_did(),
                                                            state_store,
                                                            realm_tree_nodes,
                                                            selected_realm_id,
                                                            sync_cursor,
                                                        );
                                                        sidebar_row_menu_open.set(None);
                                                    }
                                                },
                                                UiIcon { name: "x" }
                                                span { "Leave" }
                                            }
                                        }
                                    }
                                }
                            }
                            }
                                }
                            }
                        }
                    }
                }

            }

            if sidebar_is_resizing {
                div {
                    class: "sidebar-resize-shield",
                    "data-testid": "sidebar-resize-shield",
                    onmousemove: move |event| {
                        if !sidebar_collapsed() {
                            let next_width = clamp_sidebar_width(event.client_coordinates().x);
                            sidebar_width.set(next_width);
                        }
                    },
                    onmouseup: move |_| {
                        let mut store = state_store.write();
                        save_sidebar_width_preference(&mut store, sidebar_width());
                        sidebar_resizing.set(false);
                    },
                }
                }

            main { class: "main workspace", "data-testid": "main-view", role: "main", "aria-label": "Main content",
                div { class: "topbar workspace-header",
                    div { class: "topbar-left",
                        Button {
                            variant: ButtonVariant::Ghost,
                            size: ButtonSize::Sm,
                            class: "btn icon sidebar-collapse-toggle",
                            "data-testid": "sidebar-collapse-toggle",
                            title: if sidebar_is_collapsed { "Show navigation" } else { "Hide navigation" },
                            "aria-label": if sidebar_is_collapsed { "Show navigation" } else { "Hide navigation" },
                            onclick: move |_| sidebar_collapsed.toggle(),
                            if sidebar_is_collapsed {
                                UiIcon { name: "panel-left-open" }
                            } else {
                                UiIcon { name: "panel-left-close" }
                            }
                        }
                        div { class: "topbar-context", "data-testid": "topbar-crumbs",
                            if route_uses_realm_context && !active_realm_id.is_empty() {
                                SecurityStateBadge {
                                    encrypted: active_realm_security_encrypted,
                                    compact: false,
                                    test_id: Some("realm-security-state".to_owned()),
                                }
                            }
                            span { class: "topbar-context-title", "data-testid": "realm-title", "{topbar_context_title}" }
                            if route_uses_realm_context && !active_realm_id.is_empty() {
                                {
                                    let (current_surface_label, current_surface_icon) = match resolved_realm_surface {
                                        Some(surface) => (surface.short_label(), surface.icon_name()),
                                        None if realm_members_active => ("Members", "users"),
                                        None => ("Settings", "settings"),
                                    };
                                    rsx! {
                                        span {
                                            class: "topbar-current-surface",
                                            "data-testid": "current-realm-surface",
                                            title: "Current view: {current_surface_label}",
                                            UiIcon { name: current_surface_icon }
                                            span { class: "topbar-current-surface-label", "{current_surface_label}" }
                                        }
                                    }
                                }
                            }
                            if !active_realm_id.is_empty() {
                                span { class: "sr-only mono", "data-testid": "selected-realm-id", "{active_realm_id}" }
                            }
                        }
                    }
                    if route_uses_realm_context && !active_realm_id.is_empty() {
                        RealmContextBar {
                            realm_id: active_realm_id.clone(),
                            current_surface: resolved_realm_surface,
                            account_did: account_did(),
                            state_store,
                            members_active: realm_members_active,
                            minimal_ready,
                            kanban_ready,
                            full_ready,
                        }
                    }
                    div { class: "actions",
                        button {
                            class: "sr-only",
                            r#type: "button",
                            tabindex: "-1",
                            "aria-hidden": "true",
                            "data-testid": "global-search-shortcut-target",
                            onclick: move |_| {
                                let _ = navigator.push(Route::Search);
                            },
                            "Open global search"
                        }
                        div {
                            class: if topbar_search_is_open {
                                "topbar-command-search is-open"
                            } else {
                                "topbar-command-search"
                            },
                            onclick: move |event: dioxus::events::MouseEvent| event.stop_propagation(),
                            onkeydown: move |event| {
                                if event.key().to_string() == "Escape" {
                                    palette_open.set(false);
                                    topbar_search_expanded.set(false);
                                    global_query.set(String::new());
                                    event.prevent_default();
                                    event.stop_propagation();
                                }
                            },
                            if !topbar_search_is_open {
                                Button {
                                    variant: ButtonVariant::Ghost,
                                    size: ButtonSize::Sm,
                                    r#type: "button",
                                    class: "btn icon",
                                    "data-testid": "topbar-search-button",
                                    title: crate::i18n::tr("topbar.search_placeholder"),
                                    "aria-label": crate::i18n::tr("topbar.search_placeholder"),
                                    onclick: move |_| {
                                        topbar_search_expanded.set(true);
                                        palette_open.set(true);
                                    },
                                    UiIcon { name: "search" }
                                }
                            } else {
                                div { class: "topbar-command-search-field",
                                    UiIcon { name: "search" }
                                    input {
                                        "data-testid": "global-search-input",
                                        value: "{global_query}",
                                        placeholder: crate::i18n::tr("topbar.search_placeholder"),
                                        autofocus: true,
                                        onmounted: move |event| async move {
                                            let _ = event.set_focus(true).await;
                                        },
                                        onfocusin: move |_| palette_open.set(true),
                                        oninput: move |event| {
                                            global_query.set(event.value());
                                            palette_open.set(true);
                                        },
                                        onkeydown: move |event| {
                                            let key = event.key().to_string();
                                            if key == "Escape" {
                                                palette_open.set(false);
                                                topbar_search_expanded.set(false);
                                                global_query.set(String::new());
                                                event.prevent_default();
                                                event.stop_propagation();
                                            } else if key == "Enter"
                                                && !global_query().trim().is_empty()
                                            {
                                                view.set(Route::to_view(&Route::Directory));
                                                let _ = navigator.push(Route::Directory);
                                                palette_open.set(false);
                                                topbar_search_expanded.set(false);
                                            }
                                        },
                                    }
                                    kbd { "⌘K" }
                                }
                                if palette_open() {
                                    CommandPalette {
                                        query: global_query(),
                                        nodes: realm_tree_nodes(),
                                        on_navigate: move |route: Route| {
                                            view.set(Route::to_view(&route));
                                            let _ = navigator.push(route);
                                            palette_open.set(false);
                                            topbar_search_expanded.set(false);
                                            global_query.set(String::new());
                                        },
                                        on_pick_realm: move |realm_id: String| {
                                            selected_realm_id.set(realm_id.clone());
                                            view.set(crate::views::AppView::Kanban);
                                            let _ = navigator.push(Route::Realm { realm_id });
                                            palette_open.set(false);
                                            topbar_search_expanded.set(false);
                                            global_query.set(String::new());
                                        },
                                        on_close: move |_: ()| {
                                            palette_open.set(false);
                                            topbar_search_expanded.set(false);
                                            global_query.set(String::new());
                                        },
                                    }
                                }
                            }
                        }
                        Button {
                            variant: ButtonVariant::Ghost,
                            size: ButtonSize::Sm,
                            class: "btn icon theme-toggle-button",
                            "data-testid": "theme-toggle",
                            title: "{theme_toggle_title}",
                            "aria-label": "{theme_toggle_title}",
                            onclick: move |_| {
                                let current_theme = theme();
                                let next = next_manual_theme(&current_theme);
                                theme.set(next.clone());
                                state_store.write().save_private_data(&account_did(), "theme", next.clone());
                                // A4a — best-effort cross-device sync
                                // via `ck.account_data.set(client.ui)`.
                                crate::views::settings::push_client_ui_account_data(
                                    base_url(),
                                    token(),
                                    next,
                                );
                            },
                            UiIcon { name: theme_toggle_icon }
                        }
                        Button {
                            variant: ButtonVariant::Ghost,
                            size: ButtonSize::Sm,
                            r#type: "button",
                            class: "btn icon",
                            "data-testid": "topbar-shortcuts-button",
                            title: crate::i18n::tr("shortcuts.title"),
                            "aria-label": crate::i18n::tr("shortcuts.title"),
                            onclick: move |event: dioxus::events::MouseEvent| {
                                event.stop_propagation();
                                shortcut_help_open.set(true);
                            },
                            UiIcon { name: "keyboard" }
                        }
                        div { class: "sr-only", "data-testid": "connection-status", role: "status", "aria-live": "polite",
                            span { "data-testid": "status-label", "{connection_status}" }
                            span { "data-testid": "network-state-badge", "{network_state}" }
                            span { class: "mono", "data-testid": "sync-cursor", "cursor {sync_cursor}" }
                            if let Some(ref err) = last_error() {
                                span { "data-testid": "last-error", "{err}" }
                            }
                        }
                        Button {
                            variant: ButtonVariant::Ghost,
                            size: ButtonSize::Sm,
                            r#type: "button",
                            class: if notifications_drawer_open() { "btn icon topbar-notifications-link is-active" } else { "btn icon topbar-notifications-link" },
                            "data-testid": "topbar-notifications-button",
                            title: crate::i18n::tr("nav.notifications"),
                            "aria-label": crate::i18n::tr("nav.notifications"),
                            "aria-expanded": "{notifications_drawer_open()}",
                            onclick: move |event: dioxus::events::MouseEvent| {
                                event.stop_propagation();
                                mobile_nav_open.set(false);
                                account_menu_open.set(false);
                                server_menu_open.set(false);
                                if palette_open() || topbar_search_expanded() || !global_query().trim().is_empty() {
                                    palette_open.set(false);
                                    topbar_search_expanded.set(false);
                                    global_query.set(String::new());
                                }
                                notifications_drawer_open.toggle();
                            },
                            UiIcon { name: "bell" }
                            if has_topbar_unread_notifications {
                                span { class: "topbar-notifications-badge", "aria-hidden": "true" }
                            }
                        }
                        // M-UX-CONTEXT-1: the old "+ New Space"
                        // topbar shortcut is gone. Realm + Space
                        // creation now live in the sidebar where the
                        // tree hierarchy makes the parent explicit:
                        // a `+R` button at the section header for a
                        // new Realm, and a per-row `+` (on every Realm
                        // / Space) that scopes the new Space to that
                        // parent. A floating "+ New Space" with no
                        // parent context was confusing — it actually
                        // opened the Realm bootstrap strand.
                        div { class: "account-menu-wrap",
                            Button {
                                variant: ButtonVariant::Ghost,
                                size: ButtonSize::Sm,
                                class: "btn icon account-menu-button",
                                "data-testid": "account-menu-button",
                                title: crate::i18n::tr("topbar.account_menu"),
                                "aria-label": crate::i18n::tr("topbar.account_menu"),
                                onclick: move |event: dioxus::events::MouseEvent| {
                                    event.stop_propagation();
                                    if palette_open() || topbar_search_expanded() || !global_query().trim().is_empty() {
                                        palette_open.set(false);
                                        topbar_search_expanded.set(false);
                                        global_query.set(String::new());
                                    }
                                    server_menu_open.set(false);
                                    account_menu_open.toggle();
                                },
                                if !topbar_avatar_blob_ref.trim().is_empty() {
                                    span {
                                        class: "avatar-img topbar-account-avatar",
                                        key: "{topbar_avatar_blob_ref}",
                                        crate::content::renderer::AuthenticatedBlobImage {
                                            blob_ref: topbar_avatar_blob_ref.trim().to_owned(),
                                            alt_text: crate::i18n::tr("topbar.account_menu"),
                                        }
                                    }
                                } else {
                                    span {
                                        class: "avatar-img default-avatar topbar-account-avatar tone-{topbar_avatar_tone}",
                                        "aria-hidden": "true",
                                        span { "{topbar_avatar_initial}" }
                                    }
                                }
                                if has_session {
                                    span { class: "dot-online", title: "online" }
                                }
                            }
                            if account_menu_open() {
                                div {
                                    class: "account-menu-scrim",
                                    "aria-hidden": "true",
                                    onclick: move |_| account_menu_open.set(false),
                                }
                                div { class: "account-menu", "data-testid": "account-menu", role: "menu",
                                    div { class: "account-menu__head",
                                        if !topbar_avatar_blob_ref.trim().is_empty() {
                                            span {
                                                class: "avatar-img account-menu__avatar",
                                                key: "{topbar_avatar_blob_ref}",
                                                crate::content::renderer::AuthenticatedBlobImage {
                                                    blob_ref: topbar_avatar_blob_ref.trim().to_owned(),
                                                    alt_text: account_label.clone(),
                                                }
                                            }
                                        } else {
                                            span {
                                                class: "avatar-img default-avatar account-menu__avatar tone-{topbar_avatar_tone}",
                                                "aria-hidden": "true",
                                                span { "{topbar_avatar_initial}" }
                                            }
                                        }
                                        span { class: "grow",
                                            span { class: "who", "{account_label}" }
                                            span { class: "handle", "{account_detail}" }
                                        }
                                        Link {
                                            class: "btn icon sm ghost account-menu__qr",
                                            "data-testid": "account-menu-settings-qr",
                                            title: "Settings",
                                            "aria-label": "Open settings",
                                            to: Route::Settings,
                                            onclick: move |_| account_menu_open.set(false),
                                            UiIcon { name: "qr-code" }
                                        }
                                    }
                                    div { class: "account-menu__rows",
                                        div { class: "account-menu__row",
                                            strong { "DID" }
                                            div { class: "account-menu__value",
                                                span { class: "mono", "data-testid": "account-menu-did", title: "{account_did_value}", "{account_did_label}" }
                                                Button {
                                                    variant: ButtonVariant::Ghost,
                                                    size: ButtonSize::Sm,
                                                    class: "btn icon account-menu__copy",
                                                    "data-testid": "account-menu-copy-did",
                                                    title: "Copy DID",
                                                    "aria-label": "Copy DID",
                                                    onclick: {
                                                        let value = account_did_value.clone();
                                                        move |_| {
                                                            copy_text_to_clipboard(&value);
                                                            account_session_state.set("DID copied".to_owned());
                                                        }
                                                    },
                                                    UiIcon { name: "copy" }
                                                }
                                            }
                                        }
                                        div { class: "account-menu__row",
                                            strong { "Handles" }
                                            div { class: "account-menu__value",
                                                span {
                                                    class: "mono",
                                                    "data-testid": "account-menu-handles",
                                                    title: "{account_handles_title}",
                                                    "{account_handles_label}"
                                                }
                                                Button {
                                                    variant: ButtonVariant::Ghost,
                                                    size: ButtonSize::Sm,
                                                    class: "btn icon account-menu__copy",
                                                    "data-testid": "account-menu-copy-handles",
                                                    title: "Copy handles",
                                                    "aria-label": "Copy handles",
                                                    onclick: {
                                                        let value = account_handles_title.clone();
                                                        move |_| {
                                                            copy_text_to_clipboard(&value);
                                                            account_session_state.set("Handles copied".to_owned());
                                                        }
                                                    },
                                                    UiIcon { name: "copy" }
                                                }
                                            }
                                        }
                                        div { class: "account-menu__row",
                                            strong { "Device" }
                                            div { class: "account-menu__value",
                                                span { class: "mono", "data-testid": "account-menu-device", title: "{device_id_value}", "{device_id_label}" }
                                                Button {
                                                    variant: ButtonVariant::Ghost,
                                                    size: ButtonSize::Sm,
                                                    class: "btn icon account-menu__copy",
                                                    "data-testid": "account-menu-copy-device",
                                                    title: "Copy device ID",
                                                    "aria-label": "Copy device ID",
                                                    onclick: {
                                                        let value = device_id_value.clone();
                                                        move |_| {
                                                            copy_text_to_clipboard(&value);
                                                            account_session_state.set("Device ID copied".to_owned());
                                                        }
                                                    },
                                                    UiIcon { name: "copy" }
                                                }
                                            }
                                        }
                                        div { class: "account-menu__row",
                                            strong { "Server" }
                                            span { "{active_server_label}" }
                                        }
                                        div { class: "account-menu__row",
                                            strong { "Frontier" }
                                            span { class: "mono", "data-testid": "account-menu-frontier", title: "{frontier_label}", "{frontier_label_display}" }
                                        }
                                        div { class: "account-menu__row",
                                            strong { "Push" }
                                            span { class: "mono", "data-testid": "account-menu-push", "{push_label}" }
                                        }
                                        div { class: "account-menu__row",
                                            strong { "Queue" }
                                            span { class: "mono", "data-testid": "account-menu-queue", "{queue_label}" }
                                        }
                                        div { class: "account-menu__row",
                                            strong { "Crypto" }
                                            span { class: "mono", "data-testid": "account-menu-crypto", "{crypto_label}" }
                                        }
                                    }
                                    div { class: "account-menu__section",
                                        div { class: "account-menu__section-head",
                                            span { "Session" }
                                            span { "credential" }
                                        }
                                        div { class: "account-menu__rows",
                                            div { class: "account-menu__row",
                                                strong { "Credential" }
                                                span { class: "mono", "data-testid": "account-menu-session-token", if has_session { "Credential loaded" } else { "No authenticated session" } }
                                            }
                                            div { class: "account-menu__row",
                                                strong { "Crypto" }
                                                span { class: "mono", "data-testid": "account-menu-session-crypto", "{crypto_label}" }
                                            }
                                            div { class: "account-menu__row",
                                                strong { "State" }
                                                span { class: "mono", "data-testid": "account-menu-session-state", "{account_session_label}" }
                                            }
                                        }
                                    }
                                    div { class: "account-menu__actions",
                                        Button {
                                            variant: ButtonVariant::Ghost,
                                            size: ButtonSize::Sm,
                                            class: "btn",
                                            "data-testid": "account-menu-session-refresh",
                                            "aria-label": "Refresh session",
                                            disabled: !has_session,
                                            onclick: {
                                                let base = base_url();
                                                move |_| {
                                                    let base = base.clone();
                                                    let api_token = token();
                                                    let actor = account_did();
                                                    let device = device_id();
                                                    account_session_state.set("Refreshing session".to_owned());
                                                    spawn(async move {
                                                        match self_authed_api(&base, api_token.clone()) {
                                                            Ok(api) => match api.account_me().await {
                                                                Ok(account) => {
                                                                    let canonical_actor = account.did;
                                                                    if let Some(personal_handle) =
                                                                        personal_handle_from_account_handle(&account.handle)
                                                                    {
                                                                        account_primary_handle
                                                                            .set(personal_handle.clone());
                                                                        let handles = merge_personal_handles(
                                                                            &personal_handles(),
                                                                            [personal_handle],
                                                                        );
                                                                        personal_handles_status
                                                                            .set(personal_handles_status_for(&handles));
                                                                        personal_handles.set(handles);
                                                                    } else {
                                                                        account_primary_handle.set(String::new());
                                                                        if personal_handles().is_empty() {
                                                                            personal_handles_status.set("Not published".to_owned());
                                                                        }
                                                                    }
                                                                    account_did.set(canonical_actor.clone());
                                                                    persist_config(
                                                                        config_store,
                                                                        base.clone(),
                                                                        canonical_actor.clone(),
                                                                        device.clone(),
                                                                        api_token,
                                                                    );
                                                                    account_session_state.set(format!(
                                                                        "Session refresh ok: {}",
                                                                        canonical_actor
                                                                    ));
                                                                }
                                                                Err(error) => {
                                                                    if is_auth_expired_error(&error) {
                                                                        // The credential expired between background
                                                                        // refresh ticks. Try the session-grant
                                                                        // refresh path before declaring the session
                                                                        // dead — clicking "Refresh session" must
                                                                        // keep the user signed in, not bounce them to
                                                                        // login on a routine credential rotation.
                                                                        match crate::session::refresh_current_session().await {
                                                                            crate::session::CurrentSessionRefresh::Credential(fresh) => {
                                                                                let canonical_actor = match self_authed_api(&base, fresh) {
                                                                                    Ok(api) => api
                                                                                        .account_me()
                                                                                        .await
                                                                                        .ok()
                                                                                        .and_then(|account| {
                                                                                            let canonical_actor = account.did;
                                                                                            if let Some(personal_handle) =
                                                                                                personal_handle_from_account_handle(&account.handle)
                                                                                            {
                                                                                                account_primary_handle
                                                                                                    .set(personal_handle.clone());
                                                                                                let handles = merge_personal_handles(
                                                                                                    &personal_handles(),
                                                                                                    [personal_handle],
                                                                                                );
                                                                                                personal_handles_status
                                                                                                    .set(personal_handles_status_for(&handles));
                                                                                                personal_handles.set(handles);
                                                                                            } else {
                                                                                                account_primary_handle
                                                                                                    .set(String::new());
                                                                                                if personal_handles().is_empty() {
                                                                                                    personal_handles_status
                                                                                                        .set("Not published".to_owned());
                                                                                                }
                                                                                            }
                                                                                            (!canonical_actor.trim().is_empty())
                                                                                                .then_some(canonical_actor)
                                                                                        }),
                                                                                    Err(_) => None,
                                                                                }
                                                                                .unwrap_or_else(|| actor.clone());
                                                                                account_did.set(canonical_actor.clone());
                                                                                account_session_state.set(format!(
                                                                                    "Session refresh ok: {canonical_actor}"
                                                                                ));
                                                                            }
                                                                            crate::session::CurrentSessionRefresh::SignInRequired { reason } => {
                                                                                last_error.set(Some(reason));
                                                                                account_session_state.set(
                                                                                    "Sign in again to refresh this session.".to_owned()
                                                                                );
                                                                            }
                                                                            crate::session::CurrentSessionRefresh::LoginRequired { reason } => {
                                                                                last_error.set(Some(reason));
                                                                                account_session_state.set(
                                                                                    "Session expired. Sign in again.".to_owned()
                                                                                );
                                                                            }
                                                                            crate::session::CurrentSessionRefresh::RetryLater { reason } => {
                                                                                account_session_state.set(format!(
                                                                                    "Session refresh pending: {reason}"
                                                                                ));
                                                                            }
                                                                        }
                                                                    } else {
                                                                        account_session_state.set(format!(
                                                                            "Session refresh failed: {error}"
                                                                        ));
                                                                    }
                                                                }
                                                            },
                                                            Err(error) => account_session_state
                                                                .set(format!("Invalid server URL: {error}")),
                                                        }
                                                    });
                                                }
                                            },
                                            "Refresh"
                                        }
                                        Button {
                                            variant: ButtonVariant::Ghost,
                                            size: ButtonSize::Sm,
                                            class: "btn",
                                            "data-testid": "account-menu-session-logout",
                                            "aria-label": "Log out",
                                            disabled: !has_session,
                                            onclick: move |_| {
                                                let base = base_url();
                                                let actor = account_did();
                                                let device = device_id();
                                                let api_token = token();
                                                // Capture the grant + grant-binding key BEFORE the
                                                // local wipe below: hard logout MUST also terminate
                                                // the Auth Server session (revoke grant + finish
                                                // browser session) so the rotation chain can't be
                                                // resumed (account-lifecycle §4.1), and that needs
                                                // the grant JWT + a grant-binding DPoP proof.
                                                let logout_grant =
                                                    state_store.read().session_grant();
                                                let logout_device_handle = {
                                                    let mut store = state_store.write();
                                                    crate::account_auth::grant_dpop::ensure_device_key(&mut store).ok()
                                                };
                                                // F7 — journal the logout intent durably BEFORE the
                                                // local wipe. If the tab closes mid-flight or coauth is
                                                // briefly unreachable, the next boot
                                                // (`run_pending_logout_if_any`) retries the server-side
                                                // termination so the rotation chain can't outlive the
                                                // "logout". The record stashes the device seed (the live
                                                // key is wiped below) purely to mint the revoke DPoP
                                                // proof; it is cleared once coauth confirms the grant is
                                                // gone (account-lifecycle §4.1).
                                                let pending_logout =
                                                    crate::pending_logout::PendingLogout {
                                                        grant_jwt: logout_grant
                                                            .as_ref()
                                                            .map(|grant| grant.grant_jwt.clone()),
                                                        device_seed_b64: logout_device_handle
                                                            .as_ref()
                                                            .map(|handle| handle.seed_b64().to_string()),
                                                        device_jkt: logout_device_handle
                                                            .as_ref()
                                                            .map(|handle| handle.jkt().to_owned()),
                                                        principal_server_url: logout_grant
                                                            .as_ref()
                                                            .map(|grant| {
                                                                grant.principal_server_url.clone()
                                                            }),
                                                        // T1.Y4 — re-resolved at
                                                        // logout time from the
                                                        // principal server's
                                                        // describe.auth_metadata.
                                                        gate_account_base: None,
                                                        base_url: base.clone(),
                                                        session_credential: api_token.clone(),
                                                        account_did: actor.clone(),
                                                        created_at: chrono::Utc::now(),
                                                    };
                                                let logout_secure_store =
                                                    crate::secure_key_store::default_secure_key_store(
                                                        "inkson",
                                                    );
                                                if let Err(error) =
                                                    crate::pending_logout::persist_pending_logout(
                                                        &pending_logout,
                                                        logout_secure_store.as_ref(),
                                                    )
                                                {
                                                    tracing::warn!(
                                                        ?error,
                                                        "failed to journal pending logout"
                                                    );
                                                }
                                                let logout_generation = session_generation() + 1;
                                                account_session_state.set("Logging out".to_owned());
                                                session_generation.set(logout_generation);
                                                // Clear browser-session credentials up front so a
                                                // local retry cannot resurrect the session if the
                                                // server-side logout call later fails or is
                                                // cancelled. Keep the account entry itself:
                                                // projections, MLS snapshots, plaintext sidecars,
                                                // and the durable device identity are account
                                                // state, not grant-binding state. The next
                                                // interactive sign-in rotates the grant-binding
                                                // seed before issuing the new session grant.
                                                state_store
                                                    .write()
                                                    .clear_session_scoped_for_logout();
                                                // Wiping the durable E2EE device identity (true
                                                // "remove this device") is reserved for a separate
                                                // explicit action; logout only terminates the
                                                // browser session.
                                                let _ = crate::account_auth::clear_persisted_oidc_scaffold();
                                                // Wipe the in-memory UI signals too so the
                                                // sidebar can't paint a frame of stale
                                                // Realm tree updates between this click and the
                                                // navigator.push(Login).
                                                realm_tree_nodes.set(Vec::new());
                                                projection_events.set(Vec::new());
                                                sync_cursor.set("-".to_owned());
                                                selected_realm_id.set(String::new());
                                                device_queue.set(0);
                                                // Y2 - logout is a full trust-bundle reset:
                                                // clear the entire session-scoped DID
                                                // resolution cache so the next user in this
                                                // browser cannot hit the previous session's
                                                // resolution results (stale documents / old key
                                                // sets).
                                                did_cache.write().clear();
                                                account_primary_handle.set(String::new());
                                                personal_handles.set(Vec::new());
                                                personal_handles_status.set("Not published".to_owned());
                                                personal_handles_lookup_key.set(String::new());
                                                last_error.set(None);
                                                token.set(String::new());
                                                crate::config::clear_session_credential_secret(&actor);
                                                persist_config(
                                                    config_store,
                                                    base.clone(),
                                                    actor.clone(),
                                                    device.clone(),
                                                    String::new(),
                                                );
                                                session_boot_state.set(SessionBootState::Unauthenticated);
                                                // Bump the SyncEngine generation so any
                                                // in-flight long-poll exits on its next
                                                // iteration check instead of applying a
                                                // response after the wipe.
                                                sync_generation.set(sync_generation() + 1);
                                                account_menu_open.set(false);
                                                redirect_to_login(navigator);
                                                spawn(async move {
                                                    // Drive the journalled logout: revoke the grant at
                                                    // coauth (terminating the rotation chain) then run
                                                    // the soland courtesy logout. On success the journal
                                                    // entry is cleared; a transient coauth failure leaves
                                                    // it for the next boot to retry. Local credentials are
                                                    // already wiped, so a failure here never keeps THIS
                                                    // client signed in.
                                                    let outcome =
                                                        crate::pending_logout::execute_pending_logout(
                                                            &pending_logout,
                                                            logout_secure_store.as_ref(),
                                                        )
                                                        .await;
                                                    let logout_message = match outcome {
                                                        crate::pending_logout::LogoutRunOutcome::Completed => {
                                                            "Logout ok: session revoked".to_owned()
                                                        }
                                                        crate::pending_logout::LogoutRunOutcome::Retain => {
                                                            "Logged out locally; server revoke will retry"
                                                                .to_owned()
                                                        }
                                                    };
                                                    if session_generation() == logout_generation {
                                                        account_session_state.set(logout_message);
                                                    }
                                                });
                                            },
                                            "Log out"
                                        }
                                        Link {
                                            class: "btn sm",
                                            "data-testid": "account-menu-settings",
                                            to: Route::Settings,
                                            onclick: move |_| account_menu_open.set(false),
                                            UiIcon { name: "settings" }
                                            "Settings"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                div { class: "workspace-body",
                match content_route {
                    Route::Login => rsx! {
                        crate::views::login::LoginPanel {
                            base_url,
                            account_did,
                            device_id,
                            token,
                            connection_status,
                            config_store,
                            state_store,
                            account_primary_handle,
                            personal_handles,
                            personal_handles_status,
                            auto_capture_callback: false,
                            on_login: move |_| { let _ = navigator.push(Route::Dashboard); },
                        }
                    },
                    Route::AuthCallback => rsx! {
                        crate::views::login::LoginPanel {
                            base_url,
                            account_did,
                            device_id,
                            token,
                            connection_status,
                            config_store,
                            state_store,
                            account_primary_handle,
                            personal_handles,
                            personal_handles_status,
                            auto_capture_callback: true,
                            on_login: move |_| { let _ = navigator.push(Route::Dashboard); },
                        }
                    },
                    Route::Dashboard => rsx! {
                        crate::views::dashboard::DashboardPanel {
                            base_url: base_url(),
                            token,
                            realm_tree_nodes,
                            selected_realm_id,
                            view,
                            state_store,
                            device_queue: device_queue(),
                            frontier_state: frontier_state(),
                            sync_cursor: sync_cursor(),
                        }
                    },
                    Route::FileTransfer => rsx! {
                        crate::views::file_transfer::FileTransferPanel {
                            base_url: base_url(),
                            token,
                            account_did: account_did(),
                            device_id: device_id(),
                        }
                    },
                    Route::Realm { .. } => {
                        match resolved_realm_surface.unwrap_or(RealmSurface::Board) {
                            RealmSurface::Board => {
                                if kanban_ready {
                                    rsx! {
                                        crate::views::kanban::KanbanPanel {
                                            base_url: base_url(),
                                            plaintext_service_did: active_service_did.clone(),
                                            token,
                                            account_did: account_did(),
                                            device_id: device_id(),
                                            selected_realm_id: active_realm_id.clone(),
                                            projection_realm_id: active_projection_realm_id.clone(),
                                            sync_cursor,
                                            realm_live_epoch,
                                            frontier_state,
                                            state_store,
                                            event_write_ready,
                                        }
                                    }
                                } else {
                                    rsx! { ProfileGateNotice { profile: "kanban_mvp" } }
                                }
                            }
                        }
                    },
                    Route::DirectConversation { realm_id, strand_id } => {
                        if selected_realm_id() != *realm_id {
                            selected_realm_id.set(realm_id.clone());
                        }
                        if minimal_ready {
                            rsx! {
                                crate::views::chat::ChatPanel {
                                    base_url: base_url(),
                                    plaintext_service_did: active_service_did.clone(),
                                    account_did: account_did(),
                                    device_id: device_id(),
                                    token,
                                    selected_realm_id: realm_id.clone(),
                                    sync_cursor,
                                    realm_live_epoch,
                                    frontier_state,
                                    state_store,
                                    initial_strand_id: strand_id.clone(),
                                    embedded: false,
                                    direct_mode: true,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "minimal_client" } }
                        }
                    },
                    Route::Chat { message, .. } => {
                        if let Some(sid) = route.realm_id()
                            && selected_realm_id() != sid
                        {
                            selected_realm_id.set(sid.to_owned());
                        }
                        if minimal_ready {
                            rsx! {
                                crate::views::chat::ChatPanel {
                                    base_url: base_url(),
                                    plaintext_service_did: active_service_did.clone(),
                                    account_did: account_did(),
                                    device_id: device_id(),
                                    token,
                                    selected_realm_id: active_realm_id.clone(),
                                    sync_cursor,
                                    realm_live_epoch,
                                    frontier_state,
                                    state_store,
                                    initial_strand_id: default_strand_id_for_realm(&active_realm_id),
                                    embedded: false,
                                    direct_mode: false,
                                    focus_message_id: message.clone(),
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "minimal_client" } }
                        }
                    },
                    Route::Directory => rsx! {
                        crate::views::directory::DirectoryPanel {
                            base_url: base_url(),
                            selected_realm_id,
                            token,
                            view,
                            state_store,
                        }
                    },
                    Route::RealmsManage => rsx! {
                        RealmsManagePage {
                            base_url: base_url(),
                            account_did: account_did(),
                            token,
                            has_session,
                            realm_rows: manage_realm_rows.clone(),
                            realm_tree_nodes,
                            selected_realm_id,
                            sync_cursor,
                            state_store,
                            query: realm_manage_query,
                            selection: manage_realm_selection,
                            busy: manage_bulk_busy,
                        }
                    },
                    Route::ContactsManage => rsx! {
                        ContactsManagePage {
                            base_url: base_url(),
                            token,
                            has_session,
                            contact_rows: direct_contact_rows,
                            contacts_loaded: direct_contacts_loaded,
                            state_store,
                            query: contact_manage_query,
                            selection: manage_contact_selection,
                            busy: manage_bulk_busy,
                        }
                    },
                    Route::Contacts => rsx! {
                        crate::views::contacts::ContactsPanel {
                            base_url: base_url(),
                            token,
                            state_store,
                        }
                    },
                    Route::Setup | Route::SetupSection { .. } => {
                        if full_ready {
                            rsx! {
                                crate::views::setup::SetupPanel {
                                    base_url: base_url(),
                                    plaintext_service_did: active_service_did.clone(),
                                    secure_store_ready: secure_store_bootstrap_ready(),
                                    token,
                                    account_did,
                                    device_id,
                                    config_store,
                                    state_store,
                                    realm_tree_nodes,
                                    selected_realm_id,
                                    new_space_context_node,
                                    section: route.setup_section().map(str::to_owned),
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "full_client" } }
                        }
                    },
                    Route::Settings
                    | Route::SettingsSection { .. }
                    | Route::NotificationsSettings
                    | Route::SettingsDevices
                    | Route::SettingsDevicesPair
                    | Route::SettingsRecovery
                    | Route::Recovery
                    | Route::Audit
                    | Route::Developer => rsx! {
                        crate::views::settings::SettingsPanel {
                            base_url,
                            account_did,
                            device_id,
                            token,
                            account_primary_handle: account_primary_handle(),
                            personal_handles: personal_handles(),
                            personal_handles_status: personal_handles_status(),
                            can_list_handles_for_subject,
                            config_store,
                            state_store,
                            push_state,
                            locale,
                            theme,
                        }
                    },
                    Route::VerifyDevice => {
                        if e2ee_ready {
                            rsx! {
                                crate::views::verify_device::VerifyDevicePanel {
                                    base_url: base_url(),
                                    token,
                                    device_id: device_id(),
                                    account_did: account_did(),
                                    selected_realm_id: selected_realm_id(),
                                    state_store,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "e2ee_client" } }
                        }
                    },
                    Route::RealmMembers { .. } => {
                        if let Some(sid) = route.realm_id()
                            && selected_realm_id() != sid
                        {
                            selected_realm_id.set(sid.to_owned());
                        }
                        if full_ready {
                            rsx! {
                                crate::views::realm_admin::RealmMembersPanel {
                                    base_url: base_url(),
                                    active_service_did: active_service_did.clone(),
                                    account_did: account_did(),
                                    device_id: device_id(),
                                    token,
                                    selected_realm_id: active_realm_id.clone(),
                                    sync_cursor,
                                    frontier_state,
                                    state_store,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "full_client" } }
                        }
                    },
                    Route::RealmAdmin { .. } | Route::RealmAdminSection { .. } => {
                        if let Some(sid) = route.realm_id()
                            && selected_realm_id() != sid
                        {
                            selected_realm_id.set(sid.to_owned());
                        }
                        if full_ready {
                            rsx! {
                                crate::views::realm_admin::RealmAdminPanel {
                                    base_url: base_url(),
                                    account_did: account_did(),
                                    device_id: device_id(),
                                    token,
                                    selected_realm_id: active_realm_id.clone(),
                                    sync_cursor,
                                    frontier_state,
                                    state_store,
                                    active_section: route.realm_admin_section().map(str::to_owned),
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "full_client" } }
                        }
                    },
                    Route::Kanban
                    | Route::KanbanRealm { .. }
                    | Route::KanbanBoard { .. }
                    | Route::KanbanBoardTask { .. }
                    | Route::KanbanTask { .. } => {
                        if let Some(sid) = route.realm_id()
                            && selected_realm_id() != sid
                        {
                            selected_realm_id.set(sid.to_owned());
                        }
                        if kanban_ready {
                            rsx! {
                                crate::views::kanban::KanbanPanel {
                                    base_url: base_url(),
                                    plaintext_service_did: active_service_did.clone(),
                                    token,
                                    account_did: account_did(),
                                    device_id: device_id(),
                                    selected_realm_id: active_realm_id.clone(),
                                    projection_realm_id: active_projection_realm_id.clone(),
                                    sync_cursor,
                                    realm_live_epoch,
                                    frontier_state,
                                    state_store,
                                    event_write_ready,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "kanban_mvp" } }
                        }
                    },
                    Route::Notifications => rsx! {
                        crate::views::notifications::NotificationsPanel {
                            base_url: base_url(),
                            account_did: account_did(),
                            device_id: device_id(),
                            token,
                            state_store,
                        }
                    },
                    Route::Call {
                        call_id,
                        peer,
                        realm_id,
                        video,
                        incoming,
                    } => {
                        let call_realm_id = if realm_id.trim().is_empty() {
                            active_realm_id.clone()
                        } else {
                            realm_id.clone()
                        };
                        rsx! {
                            crate::views::call::CallPanel {
                                base_url: base_url(),
                                token,
                                state_store,
                                selected_realm_id: call_realm_id,
                                account_did: account_did(),
                                device_id: device_id(),
                                call_id: call_id.clone(),
                                peer: peer.clone(),
                                want_video: video == "1",
                                incoming: incoming == "1",
                            }
                        }
                    },
                    Route::Onboarding => rsx! {
                        crate::views::onboarding::OnboardingPanel {
                            base_url: base_url(),
                            token,
                            account_did,
                            device_id,
                            state_store,
                        }
                    },
                    Route::Quarantine => rsx! {
                        crate::views::quarantine::QuarantinePanel {
                            // Coauth and soland may share a host in
                            // single-server dev deployments - fall back to
                            // `base_url` until the topology probe surfaces a
                            // separate coauth URL.
                            coauth_url: base_url(),
                            // Admin scope is currently inferred from the
                            // login profile; until profile claims surface
                            // here we treat any signed-in user as admin so
                            // they can exercise the approve / reject path
                            // in dev. Production will gate this on the
                            // `coauth.admin` scope from the session grant.
                            is_admin: true,
                        }
                    },
                    Route::Applets => rsx! {
                        if crate::views::applets::applets_enabled() {
                            crate::views::applets::AppletsPanel {
                                base_url: base_url(),
                                account_did,
                                token,
                                selected_realm_id: selected_realm_id(),
                                state_store,
                            }
                        } else {
                            DeferredFeatureGate { feature: "experimental-applets" }
                        }
                    },
                    Route::Agents => rsx! {
                        if crate::views::agents::agents_enabled() {
                            crate::views::agents::AgentsPanel {
                                base_url: base_url(),
                                account_did,
                                token,
                                selected_realm_id: selected_realm_id(),
                                state_store,
                            }
                        } else {
                            DeferredFeatureGate { feature: "experimental-agents" }
                        }
                    },
                    // A6.1 — global cross-Space message search panel.
                    Route::Search => rsx! {
                        crate::views::global_search::GlobalSearchPanel {
                            state_store,
                            account_did,
                            device_id,
                            initial_query: String::new(),
                        }
                    },
                }
            }
            }
            if notifications_drawer_open() {
                div {
                    class: "notifications-drawer-layer",
                    "data-testid": "notifications-drawer",
                    aside {
                        class: "notifications-drawer-panel",
                        "data-testid": "notifications-drawer-panel",
                        "aria-label": crate::i18n::tr("nav.notifications"),
                        onclick: move |event: dioxus::events::MouseEvent| event.stop_propagation(),
                        div { class: "notifications-drawer-header",
                            div { class: "notifications-drawer-title",
                                UiIcon { name: "bell" }
                                span { {crate::i18n::tr("nav.notifications")} }
                            }
                            div { class: "notifications-drawer-actions",
                                Link {
                                    class: "btn icon sm ghost",
                                    "data-testid": "notifications-drawer-settings",
                                    title: crate::i18n::tr("notifications.tooltip.settings"),
                                    "aria-label": crate::i18n::tr("notifications.tooltip.settings"),
                                    to: Route::SettingsSection { section: "notifications".to_owned() },
                                    onclick: move |_| notifications_drawer_open.set(false),
                                    UiIcon { name: "settings" }
                                }
                                Button {
                                    variant: ButtonVariant::Ghost,
                                    size: ButtonSize::Sm,
                                    r#type: "button",
                                    class: "btn icon",
                                    "data-testid": "notifications-drawer-close",
                                    title: crate::i18n::tr("common.close"),
                                    "aria-label": crate::i18n::tr("common.close"),
                                    onclick: move |_| notifications_drawer_open.set(false),
                                    UiIcon { name: "x" }
                                }
                            }
                        }
                        crate::views::notifications::NotificationsPanel {
                            base_url: base_url(),
                            account_did: account_did(),
                            device_id: device_id(),
                            token,
                            state_store,
                        }
                    }
                }
            }
            // A6.4 — shortcut help overlay; toggled by the `?` global
            // key handler on the shell div above.
            crate::components::shortcut_help::ShortcutHelpOverlay {
                visible: shortcut_help_open,
            }
        }
        } else {
            {auth_shell_node}
        }
    }
}

#[cfg(test)]
#[path = "../app_tests.rs"]
mod tests;
