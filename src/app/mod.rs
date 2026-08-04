use std::collections::{BTreeMap, BTreeSet};

use arkret_sdk::protocol_journey::ContactScope;
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use dioxus_router::hooks::*;
use dioxus_router::{Link, Navigator, Outlet};
use serde_json::Value;

use crate::api_error::is_auth_expired_error;
use crate::components::{SecurityStateBadge, SelfAttributionBadge, UiIcon};
use crate::config::{ClientConfig, LocalConfigStore, normalize_device_id, normalize_server_url};
use crate::conformance::profile_ready;
use crate::i18n::{Locale, TextDirection};
use crate::models::{
    RealmTreeNode, RealmTreeNodeKind, ServiceDescribe, missing_v1_principal_server_requirements,
    projection_realm_id_for_known_node, service_supports_event_envelope_write_plane,
    service_supports_operation,
};
// R28-B — realm-tree / projection / field-extraction helpers moved to
// `crate::realm_tree`. Re-export the two `pub` entry points used by
// `crate::sync_engine` so the existing `crate::app::…` call sites keep
// resolving without a sync_engine edit.
pub(crate) use crate::realm_tree::{
    descendant_node_ids, full_sync_projection_keep_set, realm_tree_items_with_pinned_realms,
    realm_tree_node_is_direct_conversation, realm_tree_nodes_from_sync_realms_with_roles,
};
use crate::routes::Route;
use crate::state::projection::ProjectionEvent;
use crate::state::{
    ClientLocalState, LocalStateStore, PersistedSessionGrant, default_strand_id_for_realm,
};
use crate::transport::TransportClient;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::input::Input;
use crate::views::ConnectionState;
use crate::views::helpers::{actor_display_label, persist_config, short_protocol_id};

const REALM_KEY_SHARE_ANSWER_RETRY_BACKOFF_MS: u64 = 60_000;

/// Entry cap for the realm-key answer retry cooldown table. A single device only
/// tracks the handful of unanswered `ak.realm_key.request` dedup keys currently
/// backing off; the cap bounds a pathological key space.
const REALM_KEY_ANSWER_BACKOFF_MAX_ENTRIES: usize = 64;

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
mod web_leader;
// YOU-07-001: per-realm surface selection (RealmSurface enum + preference
// load/persist + route→surface resolution) lives in `app/realm_surface.rs`
// (move only). The glob re-export keeps inline call sites and `app_tests.rs`
// `use super::*` resolution unchanged.
mod realm_surface;
pub(crate) mod runtime_adapter;
pub(crate) use realm_surface::*;

// Structural split: non-component helpers, data-assembly routines, the
// session-boot state machine, and the secondary `#[component]` pages
// (`RealmsManagePage`, `ContactsManagePage`, `RealmContextBar`,
// `CommandPalette`, ...) moved out of this file into sibling `app/*.rs`
// modules (move only). `RouterView` now only assembles `AppBootstrap`; further
// session-shell/effect extraction continues behind that boundary. Each glob
// re-export keeps the inline call sites and `app_tests.rs` `use super::*`
// resolution unchanged.
mod clipboard;
mod command_palette;
mod connect;
mod connection_effects;
mod context_bar;
mod feature_gate;
mod fold_evidence_effects;
mod global_effects;
mod handles;
mod manage_pages;
mod mls_recovery_effects;
mod mls_runtime_effects;
mod navigation_state;
mod notifications_drawer;
mod projection_adapter;
mod recovery_effects;
mod recovery_reminder_effects;
mod route_surface;
mod secure_store_effects;
mod session_boot;
mod session_context;
mod session_shell;
mod shell_effects;
mod sidebar;
mod sidebar_width;
mod signal_products;
mod sync_effects;
use arkret_wire::ProfileId;
pub(crate) use clipboard::*;
pub(crate) use command_palette::*;
use connect::*;
use connection_effects::{ConnectionEffectState, ConnectionEffects};
pub(crate) use context_bar::*;
pub(crate) use feature_gate::*;
use fold_evidence_effects::{SidecarFoldEvidenceEffectState, SidecarFoldEvidenceEffects};
use global_effects::GlobalEffects;
pub(crate) use handles::*;
pub(crate) use manage_pages::*;
use mls_recovery_effects::{MlsRecoveryEffectState, MlsRecoveryEffects};
use mls_runtime_effects::{MlsRuntimeEffectState, MlsRuntimeEffects};
use navigation_state::NavigationState;
use notifications_drawer::NotificationsDrawer;
use recovery_effects::AccountRecoveryEffects;
use recovery_reminder_effects::{RecoveryReminderEffectState, RecoveryReminderEffects};
use route_surface::{RouteSurface, RouteSurfaceState};
use secure_store_effects::{SecureStoreEffectState, SecureStoreEffects};
use session_boot::*;
pub(crate) use session_context::SessionContext;
use session_shell::SessionShell;
use shell_effects::{ShellEffectState, ShellEffects};
use sidebar::*;
use sidebar_width::*;
use sync_effects::SyncEffects;

const UI_PREFERENCES_SCOPE: &str = "ui.browser";
const SIDEBAR_WIDTH_PREFERENCE_KEY: &str = "layout.sidebar.width";
const DEFAULT_SIDEBAR_WIDTH: f64 = 320.0;
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
    include_str!("../styles/app_overrides/sidecar-shell.css"),
    include_str!("../styles/app_overrides/circle-workspace.css"),
);

/// C3: yoface shared-component design tokens. The first layer is shadcn
/// semantic tokens (`--primary/--background/--foreground/...`); the second
/// layer is dioxus-components compatibility aliases
/// (`--primary-color-N/--focused-border-color/...`) used by `yoface::ui::*`
/// `#[css_module]` styles. Values come from the inkson green palette (yoface
/// tokens.css matches inkson design.css), so this keeps the existing
/// `var(--dark,...)` / `var(--light,...)` and `[data-theme]` switches and the
/// current inkson green appearance. Injection order stays before the three
/// existing style blocks so later design.css/app_overrides can override these
/// tokens.
const DXC_THEME: &str = yoface::TOKENS_CSS;
// CSS-module class hashes include the component source path. Keep the shared
// button stylesheet available through yoface's stable `dx-button` class so a
// relocated workspace or stale Dioxus asset directory cannot strip every
// button down to the browser default while the wasm and CSS hashes disagree.
const DXC_BUTTON_STYLE: &str = yoface::ui::button::BUTTON_CSS;

#[component]
pub fn App() -> Element {
    ensure_default_push_token_provider();
    use_hook(crate::notification_sound::initialize_notification_audio);
    rsx! {
        web_leader::WebLeaderGate {}
    }
}

#[component]
pub fn RouterView() -> Element {
    rsx! { AppBootstrap {} }
}

/// Owns one-time persisted-state hydration and constructs the session-scoped
/// runtime context. `RouterView` intentionally remains assembly-only.
#[component]
fn AppBootstrap() -> Element {
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
    let initial_realm_tree_nodes = realm_tree_nodes_from_sync_realms_with_roles(
        &initial_local_state.realm_tree_projections,
        &initial_local_state.realm_collaboration_roles,
    );
    let initial_realm_tree_owner_did = initial_state_store.active_account_did().unwrap_or_default();
    let initial_sidebar_width = load_sidebar_width_preference(&initial_state_store);
    // Boot locale: the device cache plus the platform default, through the
    // shared resolver. The account tier is deliberately absent here — the
    // signed-in account's `preferred_locale` arrives with the session, which
    // is not restored yet at this point in boot. `AccountLocaleSync` applies
    // it as soon as it lands, so a stale device cache is corrected within the
    // first session refresh rather than persisting for the whole session.
    let initial_locale =
        crate::i18n::resolve_locale(None, initial_state_store.device_pref("locale").as_deref());
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
        .unwrap_or_default();
    let config_store = use_signal(LocalConfigStore::default);
    let mut state_store = use_signal_sync(LocalStateStore::default);
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
    // Bumped by Settings → My Agents on every owned-agent mutation so the
    // Contacts sidebar can re-pull `agent_list`. See `SessionContext`.
    let owned_agents_rev = use_signal(|| 0_u64);

    // A4 — provide the session-scoped shared handles (`state_store`, `base_url`)
    // via context so descendant components read them through
    // `use_context::<SessionContext>()` instead of threading them down as props.
    // Same signal handles `RouterView` already owns; single source of truth.
    use_context_provider(|| SessionContext {
        state_store,
        base_url,
        owned_agents_rev,
    });
    let sidecar_session = use_signal(|| None::<crate::sidecar::HostedSidecarState>);
    use_context_provider(|| crate::sidecar::HostedSidecarStateContext(sidecar_session));
    // Construct the typed session coordinator once. Runtime and UI effects
    // share this owner instead of registering unrelated thread-local callbacks.
    let session_coordinator = use_hook(move || {
        crate::runtime::session::SessionCoordinator::new(move || {
            Box::pin(refresh_session_credential_for_active_context(
                base_url,
                account_did,
                device_id,
                state_store,
                token,
                config_store,
                session_generation,
            )) as crate::runtime::session::LocalRefreshFuture
        })
    });
    let runtime_services = use_context_provider(|| {
        let state_adapter = crate::client_core::InksonLocalStateStoreAdapter::from_backend(
            runtime_adapter::SignalLocalStateBackend::new(state_store),
        );
        crate::runtime::services::RuntimeServices::new(state_adapter, session_coordinator.clone())
    });

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
    let initial_realm_tree_owner_did_for_signal = initial_realm_tree_owner_did.clone();
    let mut sync_cursor = use_signal(move || initial_sync_cursor);
    // Liveness counter for the per-realm `events/subscribe` engine
    // (`crate::realm_events_engine`). Bumped when that engine folds fresh realm
    // events the account stream never delivered (cross-member case); the kanban
    // panel reads it as a second freshness axis besides `sync_cursor`.
    let realm_live_epoch = use_signal(|| 0u64);
    let mut selected_realm_id = use_signal(move || initial_selected_realm_id);
    let mut new_space_context_node = use_signal(String::new);
    let mut realm_tree_nodes = use_signal(move || initial_realm_tree_nodes_for_signal);
    let mut realm_tree_owner_did = use_signal(move || initial_realm_tree_owner_did_for_signal);
    let mut projection_events = use_signal(Vec::<ProjectionEvent>::new);
    let mut device_queue = use_signal(|| 0usize);
    let push_state = use_signal(move || initial_push_state);
    let frontier_state = use_signal(|| "Not loaded".to_owned());
    let crypto_state = use_signal(|| "No authenticated session".to_owned());
    let network_state = use_signal(|| "offline".to_owned());

    // Realm-tree nodes are an in-memory account projection. Invalidate them as
    // soon as the account signal changes; connect() will repopulate them from
    // the new account. Keeping the owner separately also prevents the render
    // between the DID change and this effect from exposing the old account.
    use_effect(move || {
        let current_account = account_did().trim().to_owned();
        if realm_tree_owner_did.peek().as_str() != current_account {
            realm_tree_nodes.set(Vec::new());
            projection_events.set(Vec::new());
            sync_cursor.set(String::new());
            selected_realm_id.set(String::new());
            device_queue.set(0);
            realm_tree_owner_did.set(current_account);
        }
    });
    let mut last_error = use_signal(|| Option::<String>::None);
    let server_description = use_signal(|| Option::<ServiceDescribe>::None);
    let server_probe_status = use_signal(|| "server not probed".to_owned());
    let locale = use_signal(move || initial_locale);
    let secure_store_bootstrap_ready = use_signal(move || initial_secure_store_bootstrap_ready);
    // Provide i18n context for views that call `crate::i18n::tr(key)`.
    // `GlobalEffects` keeps the locale field synchronized; dictionary tables
    // are baked once at boot.
    let i18n_signal = use_context_provider::<crate::i18n::I18nSignal>(|| {
        crate::i18n::init_i18n_with_locale(initial_locale)
    });
    // D0 — server-administrator signal sourced from
    // `AccountView.is_server_admin` (the server's configured admin principal
    // set), provided via context so operator-only surfaces (organization
    // create / bind) can gate their UI without prop drilling. This is the real
    // operator signal — distinct from any Realm-role `is_admin` placeholder.
    let is_server_admin =
        use_context_provider(|| crate::views::realm_admin::ServerAdminSignal(Signal::new(false))).0;
    // Y1 - session-scoped DID resolution cache handle.
    //
    // Mount point note: inkson app state is a set of scattered `use_signal`
    // handles rather than one aggregate struct, so this follows the same
    // minimal-intrusion pattern: provide a shared
    // `Signal<DidResolutionCache>` with `use_context_provider`.
    //   * Authority resolution sites can fetch it via `use_context::<Signal<DidResolutionCache>>()`
    //     and use `did_resolver::resolve_with_cache` for cache-first resolution.
    //   * `SyncEffects` copies the same handle into `SyncEngineContext.did_cache` so the Y2
    //     invalidation hook can invalidate/clear while ingesting projections.
    // The cache is pure in-memory state, is not persisted, and only lives for a
    // single login session, matching the `DidResolutionCache` docs.
    let mut did_cache =
        use_context_provider(|| Signal::new(arkret_sdk::identity::DidResolutionCache::default()));
    let did_resolution_health = use_signal(crate::components::DidResolutionHealth::healthy);
    let mut theme = use_signal(move || initial_theme);
    {
        let projection_router = runtime_services.projection_sink.clone();
        use_hook(move || {
            projection_router.install(std::rc::Rc::new(
                projection_adapter::ProjectionAdapter::new(
                    projection_events,
                    sync_cursor,
                    connection_status,
                    network_state,
                    last_error,
                    device_queue,
                    theme,
                    selected_realm_id,
                ),
            ));
        });
    }
    let system_theme_is_night = use_signal(browser_prefers_dark_theme);
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
    let current_account_display_name = use_signal(String::new);
    let current_account_avatar_blob_ref = use_signal(String::new);
    let current_device_display_name = use_signal(String::new);
    let mut account_identity_lookup_key = use_signal(String::new);
    let contact_handles_lookup_key = use_signal(String::new);
    let contact_handles_fetching = use_signal(BTreeSet::<String>::new);
    let mut global_query = use_signal(String::new);
    let mut palette_open = use_signal(|| false);
    let mut topbar_search_expanded = use_signal(|| false);
    let mut notifications_drawer_open = use_signal(|| false);
    let mut sync_bootstrap_complete = use_signal(|| false);
    // A6.4 — `?` keyboard shortcut help overlay state.
    let mut shortcut_help_open = use_signal(|| false);
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
    let own_agent_rows = use_signal(Vec::<arkret_sdk::AgentProjection>::new);
    let own_agents_loaded = use_signal(|| false);
    // Keep the Contacts sidebar's owned-agent list in sync with Settings → My
    // Agents. That panel bumps `owned_agents_rev` after provisioning, pausing,
    // resuming, or deactivating an agent; re-pull `agent_list` here so the
    // change is reflected without a manual reload. Only reload once the sidebar
    // has already loaded its agents — before that the lazy first load fetches
    // fresh state anyway, so there is nothing to keep in sync yet.
    use_effect(move || {
        let _ = owned_agents_rev();
        if !*own_agents_loaded.peek() {
            return;
        }
        let api_token = token.peek().clone();
        if api_token.trim().is_empty() {
            return;
        }
        load_own_agents_for_sidebar(
            base_url.peek().clone(),
            api_token,
            own_agent_rows,
            own_agents_loaded,
        );
    });
    let mut own_agents_expanded = use_signal(|| true);
    let mut expanded_contact_agents = use_signal(BTreeSet::<String>::new);
    // One shared in-flight key keeps every direct-chat entry (human contacts,
    // owned Agents, and a contact's Agents) single-flight and gives the row a
    // visible/accessible "Opening" state while the server resolves or ensures
    // the conversation. Without this, a real Sidecar ensure can take long
    // enough that the click appears to do nothing and repeated clicks create
    // duplicate requests.
    let mut direct_chat_opening = use_signal(|| Option::<String>::None);
    let mut sidebar_row_menu_open = use_signal(|| Option::<String>::None);
    // UI pre-gate cache for the row menu's Add Member / Settings entries,
    // keyed by realm_id. Filled lazily when a row kebab opens (see
    // `ensure_sidebar_row_perms`) so we never probe authz for Realms whose
    // menu the user never touches.
    let sidebar_row_perms = use_signal(BTreeMap::<String, SidebarRowRealmPerms>::new);
    let mls_key_package_publish_key_seen = use_signal(|| Option::<String>::None);
    let mls_welcome_bootstrap_key_seen = use_signal(|| Option::<String>::None);
    // Admin-side counterpart of the Welcome bootstrap: serialize admission
    // reconciliation so durable-change and backoff retries cannot overlap.
    let mls_admission_reconcile_in_flight = use_signal(|| false);
    let mls_admission_reconcile_pending = use_signal(|| false);
    // Throttle key for the admission pre-filter diagnostic: only emit a WARN
    // when the (realm, blocking-reason) pair changes, so a genuinely stuck
    // admin gets one visible line per cause.
    let mls_admission_diag_last = use_signal(String::new);
    // History sharing (encryption-and-audit.md): single-flight guard for the
    // to-device `ak.realm_key.share` ingest + `ak.realm_key.request` provider
    // response pass, so inbox changes and explicit retries cannot overlap.
    let realm_key_sharing_in_flight = use_signal(|| false);
    // History sharing (receiver-initiated pull): dedup key of the last
    // `ak.realm_key.request` this device emitted, as
    // `"{realm}|{from}|{to}|{installed_signature}"`. The installed-secret
    // signature is folded in so that once a `ak.realm_key.share` lands and
    // installs a `history_secret`, the key changes and a still-open gap can be
    // re-requested — but an unchanged state never re-emits the same request.
    let realm_key_request_dedup = use_signal(|| Option::<String>::None);
    let realm_key_answer_backoff_until = use_signal(|| {
        crate::keyed_cooldown::KeyedCooldown::new(REALM_KEY_ANSWER_BACKOFF_MAX_ENTRIES)
    });
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
    // detection effect (X11). See `maybe_auto_backup_mls_after_encrypted_write`.
    use_context_provider(|| crate::components::MlsBackupSignal(needs_mls_backup));
    // Signal product hubs are populated only by the encrypted Signal receive
    // path after envelope proof, MLS AEAD and product authorization succeed.
    // `crate::signal_receive_engine` drives that path and reaches these hubs
    // through the router installed below, so the engine itself stays free of
    // UI types.
    let call_signal_hub = use_context_provider(crate::views::call_signals::CallSignalHub::new);
    let message_stream_hub =
        use_context_provider(crate::views::message_streams::MessageStreamHub::new);
    let read_receipt_hub = use_context_provider(crate::views::read_receipts::ReadReceiptHub::new);
    {
        let signal_product_router = runtime_services.signal_product_sink.clone();
        use_hook(move || {
            signal_product_router.install(std::rc::Rc::new(
                signal_products::AppSignalProductSink::new(
                    call_signal_hub,
                    message_stream_hub,
                    read_receipt_hub,
                    base_url,
                    token,
                    account_did,
                    did_cache,
                    runtime_adapter::state_store_handle(state_store),
                ),
            ));
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
    // SyncEngine generation counter. Declared up front so bootstrap connect()
    // and the session-owned `SyncEffects` component share one liveness axis.
    let mut sync_generation = use_signal(|| 0u64);
    let sync_engine_active_generation = use_signal(|| Option::<u64>::None);
    // Dedup key (`<generation>|<realm_id>`) for the per-realm events engine, so
    // a base_url/token re-render doesn't stack a second loop on the same realm.
    let realm_events_engine_active_key = use_signal(|| Option::<String>::None);
    // The Signal receive rail takes no selector, so one loop per generation is
    // the whole lifecycle.
    let signal_receive_engine_active_generation = use_signal(|| Option::<u64>::None);
    let websocket_rail_active_generation = use_signal(|| Option::<u64>::None);
    let bootstrap_pending = use_signal(|| true);

    // AKP-0007 P3B.4.3 — active multi-profile snapshot, threaded into
    // the sync engine context so the loop can detect a profile rotation
    // and exit cleanly. The shell is currently single-profile; the
    // signal stays default-empty until the account switcher writes to
    // it on the first user-driven add-account / switch action.
    let profiles_signal = use_signal(crate::config::MultiProfileConfig::default);

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
    let active_service_id = active_server_description
        .as_ref()
        .map(|description| description.service_id.as_str().to_owned())
        .unwrap_or_default();
    let can_list_handles_for_subject =
        active_server_description
            .as_ref()
            .is_some_and(|description| {
                service_supports_operation(
                    description,
                    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_QUERY_LIST_HANDLES_FOR_SUBJECT,
                )
            });
    let has_session = !token().trim().is_empty();
    let boot_state = session_boot_state();
    let auth_surface = auth_surface_for_route(&route, has_session, boot_state);
    let authenticated_login_navigator = navigator;
    let authenticated_login_token = token;
    let route_is_login = matches!(&route, Route::Login);
    use_effect(move || {
        if route_is_login && !authenticated_login_token().trim().is_empty() {
            let _ = authenticated_login_navigator.replace(Route::Dashboard);
        }
    });
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
    let account_display_name = current_account_display_name();
    let device_display_name = current_device_display_name();
    let account_label = if has_session {
        if !account_display_name.trim().is_empty() {
            account_display_name.clone()
        } else {
            personal_handles_value
                .first()
                .map(|handle| format!("@{handle}"))
                .unwrap_or_else(|| actor_display_label(&state_store.read(), &account_did_value))
        }
    } else {
        "Not signed in".to_owned()
    };
    let account_detail = if has_session {
        let device = if device_display_name.trim().is_empty() {
            device_id_label.clone()
        } else {
            device_display_name.clone()
        };
        personal_handles_value
            .first()
            .map(|handle| format!("@{handle} · {device}"))
            .unwrap_or(device)
    } else {
        "Refresh server metadata, then sign in".to_owned()
    };
    // The actor-private mirror is authoritative when present (including an
    // explicit empty tombstone after clearing an avatar). Otherwise use the
    // public Actor Profile projection loaded from account/viewer.
    let topbar_avatar_blob_ref = use_memo(move || {
        if token().trim().is_empty() {
            String::new()
        } else {
            state_store
                .read()
                .load_private_data(&account_did(), "avatar_blob_ref")
                .unwrap_or_else(&*current_account_avatar_blob_ref)
        }
    })();
    let minimal_ready = profile_ready(
        active_server_description.as_ref(),
        ProfileId::MINIMAL_CLIENT_V1,
    );
    let kanban_ready = profile_ready(active_server_description.as_ref(), ProfileId::KANBAN_MVP_V1);
    let full_ready = profile_ready(
        active_server_description.as_ref(),
        ProfileId::FULL_CLIENT_V1,
    );
    let e2ee_ready = profile_ready(
        active_server_description.as_ref(),
        ProfileId::E2EE_CLIENT_V1,
    );
    let event_write_ready = active_server_description
        .as_ref()
        .map(service_supports_event_envelope_write_plane)
        .unwrap_or(false);
    let route_uses_realm_context = route_uses_realm_context(&route);
    let context_realm_id = if route_uses_realm_context {
        effective_realm_id.clone()
    } else {
        None
    };
    let resolved_realm_surface = resolve_realm_surface(
        &route,
        &state_store.read(),
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
            load_realm_surface_preference(&state_store.read(), &account_did(), realm_id);
        if stored_surface != surface {
            persist_realm_surface_preference(
                &mut state_store.write(),
                &account_did(),
                realm_id,
                surface,
            );
        }
    }

    let loaded_realm_tree_nodes = if session_boot::account_projections_visible(
        &route,
        has_session,
        &account_did(),
        &realm_tree_owner_did(),
    ) {
        realm_tree_nodes()
    } else {
        Vec::new()
    };
    // The principal control / self Realm (device ledger, key log, and the
    // holder's own private uploads — see key-management.md §4.1) is account
    // infrastructure, not a collaboration workspace, so it MUST NOT show up in
    // the sidebar realm list. Derive its canonical id from the account DID and
    // hide that node plus its descendants, mirroring the direct-conversation
    // filter below.
    let self_realm_id: Option<String> = arkret_sdk::Did::new(account_did())
        .ok()
        .map(|did| arkret_sdk::principal_control_realm_id(&did));
    let hidden_realm_tree_node_ids: BTreeSet<String> = loaded_realm_tree_nodes
        .iter()
        .filter(|node| {
            node.kind == RealmTreeNodeKind::Realm
                && (realm_tree_node_is_direct_conversation(node)
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
    let pinned_realm_ids = {
        let store = state_store.read();
        pinned_realm_ids_from_store(&store)
    };
    let realm_tree =
        realm_tree_items_with_pinned_realms(&collaboration_realm_tree_nodes, &pinned_realm_ids);
    let realm_tree_projections = state_store.read().load().realm_tree_projections;
    // A persisted Realm-default MLS snapshot is authoritative local evidence
    // for previously created/joined encrypted Realms. It also repairs clients
    // whose cached account projection was already downgraded by the old
    // `e2ee_epoch: null => plaintext` parser before this build starts.
    let realm_ids_with_local_mls: BTreeSet<String> = state_store
        .read()
        .mls_snapshots()
        .into_keys()
        .filter(|scope_id| scope_id.starts_with("ak:realm:"))
        .collect();
    let collaboration_sidebar_query_value =
        collaboration_sidebar_query().trim().to_ascii_lowercase();
    let direct_sidebar_query_value = direct_sidebar_query().trim().to_ascii_lowercase();
    // Render from an owned snapshot. Keeping a Signal read guard alive inside
    // the RSX iterator lets an async Direct Conversation open complete while
    // Dioxus is still reconciling that borrowed hook storage, which panics in
    // generational-box when the opening state is cleared.
    let own_agent_rows_for_sidebar = own_agent_rows.read().clone();
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
                .and_then(crate::security_state::realm_projection_security_state)
                .unwrap_or_else(|| realm_ids_with_local_mls.contains(&node.id));
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
            let peer_id = crate::models::contact_peer_id(contact);
            let display_name = actor_display_label(&state_store.read(), peer_id.as_str());
            let scopes = contact
                .bidirectional_scopes
                .iter()
                .chain(contact.effective_scopes.iter().flatten())
                .chain(contact.granted_to_peer_scopes.iter())
                .chain(contact.granted_by_peer_scopes.iter())
                .map(|scope| crate::models::contact_scope_wire(*scope))
                .collect::<Vec<_>>()
                .join(" ");
            let agent_match = contact.agents.iter().any(|agent| {
                sidebar_text_matches_query(
                    &direct_sidebar_query_value,
                    &[
                        agent.agent_id.as_str(),
                        agent.display_name.as_deref().unwrap_or_default(),
                        agent.agent_slug.as_deref().unwrap_or_default(),
                    ],
                )
            });
            agent_match
                || sidebar_text_matches_query(
                    &direct_sidebar_query_value,
                    &[
                        peer_id.as_str(),
                        crate::models::contact_state_wire(contact.state),
                        &display_name,
                        &scopes,
                    ],
                )
        })
        .cloned()
        .collect();
    filtered_direct_contact_rows.sort_by(|left, right| {
        let left_peer = crate::models::contact_peer_id(left);
        let right_peer = crate::models::contact_peer_id(right);
        let left_remark = contact_remarks_for_sidebar.get(left_peer.as_str());
        let right_remark = contact_remarks_for_sidebar.get(right_peer.as_str());
        let left_pinned = left_remark.is_some_and(|remark| remark.pinned);
        let right_pinned = right_remark.is_some_and(|remark| remark.pinned);
        let left_label =
            actor_display_label(&state_store.read(), left_peer.as_str()).to_ascii_lowercase();
        let right_label =
            actor_display_label(&state_store.read(), right_peer.as_str()).to_ascii_lowercase();
        right_pinned
            .cmp(&left_pinned)
            .then_with(|| left_label.cmp(&right_label))
            .then_with(|| left_peer.cmp(right_peer))
    });
    let active_security_scope_id = if active_projection_realm_id.trim().is_empty() {
        active_realm_id.as_str()
    } else {
        active_projection_realm_id.as_str()
    };
    // The Realm row and topbar must never disagree about the same Realm. Use
    // the row's already-resolved Realm projection first; only fall back to a
    // Space/Strand scope lookup while the Realm tree itself is still hydrating.
    // Scope-first lookup allowed a partial board projection to turn an
    // encrypted Realm into the topbar's `Unencrypted` false default.
    let active_realm_security_encrypted = manage_realm_rows
        .iter()
        .find(|row| row.realm_id == active_realm_id)
        .map(|row| row.encrypted)
        .or_else(|| {
            crate::security_state::security_projection_for_scope_id(
                &realm_tree_projections,
                active_security_scope_id,
            )
            .map(crate::security_state::realm_projection_is_encrypted)
        })
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
    // `:root` / `html[data-theme]`, and app.css's `--ak-*` + auth surfaces key on
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
        .map(|surface| surface.title().to_owned())
        .unwrap_or_else(|| match &route {
            Route::Dashboard => crate::i18n::tr("nav.dashboard"),
            Route::FileTransfer => crate::i18n::tr("nav.files"),
            Route::Settings | Route::SettingsSection { .. } => crate::i18n::tr("nav.settings"),
            _ => crate::i18n::tr(route_label_key(&route)),
        });
    let topbar_context_title = selected_preview
        .as_ref()
        .map(|space| space.title.clone())
        .unwrap_or_else(|| {
            if route_uses_realm_context {
                "Space".to_owned()
            } else {
                route_title.clone()
            }
        });
    let topbar_search_is_open =
        palette_open() || topbar_search_expanded() || !global_query().is_empty();
    let topbar_unread_notifications = unread_notification_count(&state_store.read().load());
    let has_topbar_unread_notifications = topbar_unread_notifications > 0;
    let document_title = if matches!(&route, Route::Dashboard) {
        "Inkson | Arkret".to_owned()
    } else {
        format!("{route_title} | Inkson | Arkret")
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
    let login_onboarding_navigator = navigator;
    let callback_onboarding_navigator = navigator;
    let mut login_bootstrap_pending = bootstrap_pending;
    let mut callback_bootstrap_pending = bootstrap_pending;
    let mut login_session_boot_state = session_boot_state;
    let mut callback_session_boot_state = session_boot_state;
    let login_redirect_to_dashboard = should_redirect_to_dashboard_after_login(&route);
    let callback_redirect_to_dashboard = login_redirect_to_dashboard;
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
                                account_did,
                                device_id,
                                token,
                                connection_status,
                                config_store,
                                account_primary_handle,
                                personal_handles,
                                personal_handles_status,
                                locale,
                                auto_capture_callback: true,
                                on_login: move |_| {
                                    callback_bootstrap_pending.set(true);
                                    callback_session_boot_state.set(SessionBootState::Checking);
                                    if callback_redirect_to_dashboard {
                                        let destination = if state_store
                                            .read()
                                            .pending_principal_registration()
                                            .is_some()
                                        {
                                            Route::Onboarding
                                        } else {
                                            Route::Dashboard
                                        };
                                        let _ = callback_navigator.push(destination);
                                    }
                                },
                                on_onboarding: move |_| {
                                    let _ = callback_onboarding_navigator.push(Route::Onboarding);
                                },
                            }
                        },
                        AuthSurface::Register => rsx! {
                            crate::views::register::RegistrationPanel { device_id }
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
                                        p { "Arkret" }
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
                                account_did,
                                device_id,
                                token,
                                connection_status,
                                config_store,
                                account_primary_handle,
                                personal_handles,
                                personal_handles_status,
                                locale,
                                auto_capture_callback: false,
                                on_login: move |_| {
                                    login_bootstrap_pending.set(true);
                                    login_session_boot_state.set(SessionBootState::Checking);
                                    if login_redirect_to_dashboard {
                                        let _ = login_navigator.push(Route::Dashboard);
                                    }
                                },
                                on_onboarding: move |_| {
                                    let _ = login_onboarding_navigator.push(Route::Onboarding);
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
            on_onboarding_route: matches!(&content_route, Route::Onboarding),
            recovery_check_complete: account_recovery_configured.is_some(),
            needs_device_authorization: needs_device_authorization(),
            account_has_other_devices: account_has_other_devices(),
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
    let mobile_connect_session = runtime_services.session.clone();
    let server_connect_session = runtime_services.session.clone();
    let manual_refresh_session = runtime_services.session.clone();

    rsx! {
        SessionShell {
            locale,
            i18n_signal,
            base_url,
            token,
            state_store,
            connection_status,
            last_error,
            session_boot_state,
            is_server_admin,
            theme,
            system_theme_is_night,
            ConnectionEffects {
                state: ConnectionEffectState {
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
                    secure_store_bootstrap_ready,
                    session_generation,
                    did_resolution_health,
                    bootstrap_pending,
                }
            }
            AccountRecoveryEffects {
                account_recovery_configured,
                account_recovery_detection_key_seen,
                last_error,
                token,
                account_did,
                device_id,
                sync_generation,
                session_boot_state,
                on_onboarding_route: matches!(&content_route, Route::Onboarding),
            }
            MlsRecoveryEffects {
                state: MlsRecoveryEffectState {
                    mls_unlock_detection_key_seen,
                    needs_mls_unlock,
                    needs_mls_backup,
                    needs_mls_recovery_setup,
                    mls_restore_payload_cache,
                    secure_store_bootstrap_ready,
                    account_recovery_configured,
                    token,
                    account_did,
                    device_id,
                    sync_generation,
                    session_boot_state,
                    on_onboarding_route: matches!(&content_route, Route::Onboarding),
                }
            }
            RecoveryReminderEffects {
                state: RecoveryReminderEffectState {
                    recovery_key_setup_prompt,
                    recovery_auto_prompt_fired,
                    token,
                    account_did,
                    sync_bootstrap_complete,
                    secure_store_bootstrap_ready,
                    on_onboarding_route: matches!(&content_route, Route::Onboarding),
                    device_authorization_check_complete,
                    account_recovery_configured,
                    needs_device_authorization,
                    needs_mls_unlock,
                    needs_mls_backup,
                    needs_mls_recovery_setup,
                    account_has_other_devices,
                }
            }
            MlsRuntimeEffects {
                state: MlsRuntimeEffectState {
                    route_uses_realm_context,
                    context_realm_id: context_realm_id.clone(),
                    mls_key_package_publish_key_seen,
                    secure_store_bootstrap_ready,
                    device_authorization_check_complete,
                    needs_device_authorization,
                    token,
                    account_did,
                    device_id,
                    server_description,
                    sync_bootstrap_complete,
                    sync_cursor,
                    realm_live_epoch,
                    mls_admission_reconcile_in_flight,
                    mls_admission_reconcile_pending,
                    last_error,
                    mls_admission_diag_last,
                    realm_events_route_enabled,
                    selected_realm_id,
                    device_queue,
                    realm_key_sharing_in_flight,
                    realm_key_request_dedup,
                    realm_key_answer_backoff_until,
                    mls_welcome_bootstrap_key_seen,
                    crypto_state,
                    needs_mls_backup,
                }
            }
            ShellEffects {
                state: ShellEffectState {
                    account_primary_handle,
                    account_did,
                    token,
                    server_description,
                    personal_handles,
                    personal_handles_status,
                    personal_handles_lookup_key,
                    device_id,
                    current_account_display_name,
                    current_account_avatar_blob_ref,
                    current_device_display_name,
                    account_identity_lookup_key,
                    contact_handles_lookup_key,
                    contact_handles_fetching,
                    direct_contact_rows,
                }
            }
            SecureStoreEffects {
                state: SecureStoreEffectState {
                    config_store,
                    account_did,
                    device_id,
                    secure_store_bootstrap_ready,
                    token,
                }
            }
            SidecarFoldEvidenceEffects {
                state: SidecarFoldEvidenceEffectState { account_did }
            }
            SyncEffects {
                sync_generation,
                sync_engine_active_generation,
                realm_events_engine_active_key,
                signal_receive_engine_active_generation,
                websocket_rail_active_generation,
                sync_bootstrap_complete,
                token,
                account_did,
                device_id,
                selected_realm_id,
                realm_events_route_enabled,
                realm_live_epoch,
                profiles: profiles_signal,
            }
            style { "{DXC_THEME}" }
            style { "{DXC_BUTTON_STYLE}" }
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
            // `api_error::decode_arkret_error`'s policy-deny dispatch,
            // G3.Y3) and the AKP-0007 circle-error queue (fed by
            // `maybe_dispatch_circle_error`), so any 403 / Circle error
            // is surfaced without each call site wiring its own UI.
            crate::components::ToastHost {}
            crate::components::DidResolutionHealthBanner { health: did_resolution_health }
            Outlet::<Route> {}
            if active_prompt == AccountHealthPrompt::DeviceAuthorization {
                crate::components::DeviceAuthorizationPrompt {
                    needs_device_authorization,
                }
            }
            // device-lifecycle.md §2.1/§7 — surface an incoming same-principal
            // pairing request on this (authorized) device so the user can
            // compare the pairing code and approve/reject without navigating to
            // the devices settings page.
            crate::components::DevicePairApprovalPrompt {
                token,
                device_id,
            }
            crate::components::AgentRuntimeApprovalPrompt {
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
                token,
                account_did,
                device_id,
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
                        "Generate your Recovery Key (24 words) before relying on this account. Backups are stored server-side as ciphertext only; Arkret cannot recover the 24 words for you."
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
                            to: Route::SettingsSection {
                                section: "encryption".to_owned(),
                                filter: String::new(),
                            },
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
            if active_prompt == AccountHealthPrompt::RecoverySetupMissing
                && !recovery_key_setup_prompt()
            {
                crate::components::MlsRecoverySetupMissingBanner {
                    needs_mls_recovery_setup,
                    actor_id: account_did,
                }
            }
            // Step 3 of the account-MLS-secret auto-unlock strand: a
            // recovery-passphrase banner that restores encrypted history on
            // a fresh device. Renders nothing unless boot detection flagged
            // `needs_mls_unlock`.
            if active_prompt == AccountHealthPrompt::MlsUnlock
                && !recovery_key_setup_prompt()
            {
                crate::components::MlsUnlockPrompt {
                    token,
                    actor_id: account_did,
                    device_id,
                    needs_mls_unlock,
                    restore_payload_cache: mls_restore_payload_cache,
                }
            }
            // Task X3 — one-time account-secret BACKUP prompt (mirror of the
            // unlock banner). Renders nothing unless detection flagged
            // `needs_mls_backup` (local secret exists, no server backup yet).
            if active_prompt == AccountHealthPrompt::MlsBackup
                && !recovery_key_setup_prompt()
            {
                crate::components::MlsBackupPrompt {
                    token,
                    actor_id: account_did,
                    device_id,
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
                div { class: "brand", "Arkret" }
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
                        // `ak.account_data.set(ak.client.ui_state)`.
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
                    session: mobile_connect_session.clone(),
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
                                    did_cache,
                                    did_resolution_health,
                                },
                            )
                        },
                        "Refresh"
                    }
                }
                Link { class: "secondary", "data-testid": "mobile-dashboard-nav-button", to: Route::Dashboard, onclick: move |_| mobile_nav_open.set(false), {crate::i18n::tr("nav.dashboard")} }
                Link { class: "secondary", "data-testid": "mobile-file-transfer-nav-button", to: Route::FileTransfer, onclick: move |_| mobile_nav_open.set(false), {crate::i18n::tr("nav.files")} }
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
                    Link { class: "brand", to: Route::Dashboard, "aria-label": "Inkson | Arkret Home",
                        span { class: "logo", "⌘" }
                        span { class: "product-meta",
                            span { class: "product-name", "Inkson | Arkret" }
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
                                            let server_connect_session =
                                                server_connect_session.clone();
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
                    session: server_connect_session.clone(),
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
                        span { class: "grow", {crate::i18n::tr("nav.dashboard")} }
                    }
                    Link { class: "sidebar-nav-item", to: Route::FileTransfer,
                        span { class: "sidebar-nav-icon", UiIcon { name: "file" } }
                        span { class: "grow", {crate::i18n::tr("nav.files")} }
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
                                        load_direct_contacts_and_agents_for_sidebar(
                                            base.clone(),
                                            token(),
                                            direct_contact_rows,
                                            direct_contacts_loaded,
                                            own_agent_rows,
                                            own_agents_loaded,
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
                                        placeholder: crate::i18n::tr("sidebar.search_realms"),
                                        oninput: move |event: FormEvent| collaboration_sidebar_query.set(event.value()),
                                    }
                                } else {
                                    Input {
                                        "data-testid": "contacts-sidebar-search-input",
                                        value: "{direct_sidebar_query}",
                                        placeholder: crate::i18n::tr("sidebar.search_contacts"),
                                        oninput: move |event: FormEvent| direct_sidebar_query.set(event.value()),
                                    }
                                }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    size: ButtonSize::IconXs,
                                    class: "sidebar-toolbar-action sidebar-tab-search-submit",
                                    r#type: "button",
                                    "data-testid": "realm-sidebar-search-button",
                                    title: crate::i18n::tr("sidebar.search"),
                                    "aria-label": crate::i18n::tr("sidebar.search"),
                                    onclick: {
                                        let base = base_url();
                                        move |_| {
                                            if realm_sidebar_tab() == "direct" && !direct_contacts_loaded() {
                                                load_direct_contacts_and_agents_for_sidebar(
                                                    base.clone(),
                                                    token(),
                                                    direct_contact_rows,
                                                    direct_contacts_loaded,
                                                    own_agent_rows,
                                                    own_agents_loaded,
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
                                            load_direct_contacts_and_agents_for_sidebar(
                                                base.clone(),
                                                token(),
                                                direct_contact_rows,
                                                direct_contacts_loaded,
                                                own_agent_rows,
                                                own_agents_loaded,
                                            );
                                        }
                                    },
                                    UiIcon { name: "home" }
                                }
                            }
                        }
                    }
                    if realm_sidebar_tab() == "direct" {
                        if has_session && (direct_sidebar_query_value.is_empty()
                            || own_agent_rows_for_sidebar.iter().any(|agent| {
                                sidebar_text_matches_query(
                                    &direct_sidebar_query_value,
                                    &[
                                        agent.agent_id.as_str(),
                                        agent.display_name.as_deref().unwrap_or_default(),
                                                &agent.slug,
                                    ],
                                )
                            })
                            || sidebar_text_matches_query(
                                &direct_sidebar_query_value,
                                &[&account_did(), &actor_display_label(&state_store.read(), &account_did()), &account_primary_handle()],
                            ))
                        {
                            {
                                let active_account_did = account_did();
                                let self_did = if active_account_did.trim().is_empty() {
                                    let configured = config_store.read().load().account_did;
                                    if configured.trim().is_empty() {
                                        state_store
                                            .read()
                                            .session_grant()
                                            .map(|grant| grant.principal_id)
                                            .unwrap_or_default()
                                    } else {
                                        configured
                                    }
                                } else {
                                    active_account_did
                                };
                                let primary_handle = account_primary_handle();
                                let self_label = if primary_handle.trim().is_empty() {
                                    actor_display_label(&state_store.read(), &self_did)
                                } else {
                                    primary_handle
                                };
                                let self_agents_button_label = if own_agents_expanded() {
                                    "Hide your AI agents"
                                } else {
                                    "Show your AI agents"
                                };
                                rsx! {
                                    div {
                                        class: "contact-sidebar-group is-self",
                                        "data-testid": "contact-sidebar-self-group",
                                        button {
                                            class: "sidebar-nav-item contact-sidebar-row contact-sidebar-user-row",
                                            r#type: "button",
                                            "data-testid": "contact-sidebar-self-row",
                                            "data-peer": "{self_did}",
                                            "aria-expanded": if own_agents_expanded() { "true" } else { "false" },
                                            "aria-label": "{self_agents_button_label}",
                                            title: "{self_agents_button_label}",
                                            onclick: move |_| own_agents_expanded.toggle(),
                                            span { class: "sidebar-nav-icon contact-sidebar-user-avatar",
                                                crate::components::IdentityAvatar {
                                                    seed: self_did.clone(),
                                                    alt_text: self_label.clone(),
                                                    blob_ref: Some(topbar_avatar_blob_ref.clone()),
                                                    class: "avatar-img".to_owned(),
                                                }
                                            }
                                            span { class: "grow truncate", "{self_label}" }
                                            SelfAttributionBadge {
                                                test_id: Some("contact-sidebar-self-badge".to_owned()),
                                            }
                                            span {
                                                class: "contact-agent-chevron",
                                                "data-testid": "contact-sidebar-self-agent-toggle",
                                                UiIcon { name: if own_agents_expanded() { "chevron-down" } else { "chevron-right" } }
                                            }
                                        }
                                        if own_agents_expanded() {
                                            div { class: "contact-agent-list", "data-testid": "contact-sidebar-self-agents",
                                                for agent in own_agent_rows_for_sidebar.iter() {
                                                    {
                                                        let agent_id = agent.agent_id.to_string();
                                                        let agent_label = agent
                                                            .display_name
                                                            .clone()
                                                            .unwrap_or_else(|| agent.slug.clone());
                                                        let avatar_blob_ref = agent
                                                            .avatar_blob_ref
                                                            .as_ref()
                                                            .map(ToString::to_string)
                                                            .unwrap_or_default();
                                                        let controller_id = self_did.clone();
                                                        let opening_key = format!("owned-agent:{agent_id}");
                                                        let opening_target = direct_chat_opening();
                                                        let chat_open_blocked = opening_target.is_some();
                                                        let is_opening = opening_target.as_deref()
                                                            == Some(opening_key.as_str());
                                                        let agent_button_label = if is_opening {
                                                            format!("Opening chat with {agent_label}")
                                                        } else {
                                                            format!("Chat with {agent_label}")
                                                        };
                                                        rsx! {
                                                            button {
                                                                key: "{agent_id}",
                                                                class: "sidebar-nav-item contact-sidebar-agent-row",
                                                                r#type: "button",
                                                                "data-testid": "contact-sidebar-agent-row",
                                                                "data-agent": "{agent_id}",
                                                                "data-controller": "{controller_id}",
                                                                "data-opening": if is_opening { "true" } else { "false" },
                                                                "aria-busy": if is_opening { "true" } else { "false" },
                                                                "aria-label": "{agent_button_label}",
                                                                title: "{agent_button_label}",
                                                                disabled: chat_open_blocked,
                                                                onclick: {
                                                                    let base = base_url();
                                                                    let agent_id = agent_id.clone();
                                                                    let opening_key = opening_key.clone();
                                                                    move |event: dioxus::events::MouseEvent| {
                                                                        event.prevent_default();
                                                                        event.stop_propagation();
                                                                        if direct_chat_opening.read().is_some() {
                                                                            return;
                                                                        }
                                                                        direct_chat_opening.set(Some(opening_key.clone()));
                                                                        let api_token = token();
                                                                        let base = base.clone();
                                                                        let agent_id = agent_id.clone();
                                                                        spawn(async move {
                                                                            let agent_id_for_log = agent_id.clone();
                                                                            let route = match crate::transport::auth::with_authed_api(
                                                                                &base,
                                                                                api_token,
                                                                                |api| async move {
                                                                                    crate::transport::account::direct_conversation_resolve(
                                                                                        &api,
                                                                                        state_store,
                                                                                        &agent_id,
                                                                                        true,
                                                                                        true,
                                                                                    ).await
                                                                                },
                                                                            ).await {
                                                                                Ok(response) if crate::transport::account::direct_conversation_coordinates(&response).is_some() => {
                                                                                    let coordinates = crate::transport::account::direct_conversation_coordinates(&response).expect("guarded coordinates");
                                                                                    Some(Route::DirectConversation {
                                                                                        realm_id: coordinates.realm_id.to_string(),
                                                                                        strand_id: coordinates.main_strand_id.to_string(),
                                                                                    })
                                                                                },
                                                                                Ok(response) => {
                                                                                    crate::components::feedback::toast_error(
                                                                                        "feedback.direct_open_failed",
                                                                                        vec![],
                                                                                        Some(format!("outcome: {response:?}")),
                                                                                    );
                                                                                    None
                                                                                }
                                                                                Err(err) => {
                                                                                    tracing::error!(
                                                                                        error = %err.display(),
                                                                                        agent_id = %agent_id_for_log,
                                                                                        "owned agent direct conversation open failed"
                                                                                    );
                                                                                    crate::components::feedback::toast_error(
                                                                                        "feedback.direct_open_failed", vec![], Some(err.display()),
                                                                                    );
                                                                                    None
                                                                                }
                                                                            };
                                                                            direct_chat_opening.set(None);
                                                                            if let Some(route) = route {
                                                                                let _ = navigator.push(route);
                                                                            }
                                                                        });
                                                                    }
                                                                },
                                                                span { class: "sidebar-nav-icon contact-sidebar-agent-avatar",
                                                                    crate::components::IdentityAvatar {
                                                                        seed: agent_id.clone(),
                                                                        alt_text: agent_label.clone(),
                                                                        blob_ref: Some(avatar_blob_ref),
                                                                        class: "avatar-img".to_owned(),
                                                                    }
                                                                }
                                                                span { class: "grow truncate", "{agent_label}" }
                                                                span { class: "pill muted xs", if is_opening { "Opening..." } else { "AI agent" } }
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
                        if !has_session {
                            div { class: "sidebar-nav-item is-dim", "data-testid": "direct-conversation-empty-state",
                                span { class: "sidebar-nav-icon", UiIcon { name: "users" } }
                                span { class: "grow truncate", {crate::i18n::tr("contacts.sign_in")} }
                            }
                        } else if filtered_direct_contact_rows.is_empty() && !direct_sidebar_query_value.is_empty() {
                            div { class: "sidebar-nav-item is-dim", "data-testid": "direct-conversation-no-results",
                                span { class: "sidebar-nav-icon", UiIcon { name: "search" } }
                                span { class: "grow truncate", "No matching contacts" }
                            }
                        } else {
                            for contact in filtered_direct_contact_rows.iter() {
                                {
                                    let peer = crate::models::contact_peer_id(&contact).to_string();
                                    let state_label =
                                        crate::models::contact_state_wire(contact.state).to_owned();
                                    let scopes_label = contact
                                        .bidirectional_scopes
                                        .iter()
                                        .map(|scope| crate::models::contact_scope_wire(*scope))
                                        .collect::<Vec<_>>()
                                        .join(", ");
                                    let direct = contact.direct_conversation.clone();
                                    let has_direct_scope = contact
                                        .bidirectional_scopes
                                        .iter()
                                        .chain(contact.effective_scopes.iter().flatten())
                                        .any(|scope| *scope == ContactScope::DirectMessage);
                                    let has_active_direct = direct
                                        .as_ref()
                                        .is_some_and(|summary| {
                                            summary.state
                                                == arkret_sdk::DirectConversationSummaryState::Found
                                        });
                                    let can_resolve =
                                        contact.state == arkret_sdk::ContactState::Accepted
                                            && (has_direct_scope || has_active_direct);
                                    let contact_remark =
                                        contact_remarks_for_sidebar.get(&peer).cloned();
                                    let display_name = actor_display_label(&state_store.read(), &peer);
                                    let opening_key = format!("contact:{peer}");
                                    let opening_target = direct_chat_opening();
                                    let chat_open_blocked = opening_target.is_some();
                                    let is_opening = opening_target.as_deref()
                                        == Some(opening_key.as_str());
                                    let row_title = if is_opening {
                                        format!("Opening chat with {display_name}")
                                    } else if can_resolve {
                                        format!("Chat with {display_name}")
                                    } else {
                                        crate::i18n::tr("direct.unavailable")
                                    };
                                    let state_badge_label = if is_opening {
                                        "Opening...".to_owned()
                                    } else {
                                        state_label.clone()
                                    };
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
                                    let contact_agent_count = contact.agents.len();
                                    let contact_agents_expanded = expanded_contact_agents.read().contains(&peer);
                                    let show_contact_agents = contact_agents_expanded
                                        || (!direct_sidebar_query_value.is_empty()
                                            && contact.agents.iter().any(|agent| {
                                                sidebar_text_matches_query(
                                                    &direct_sidebar_query_value,
                                                    &[
                                                        agent.agent_id.as_str(),
                                                        agent.display_name.as_deref().unwrap_or_default(),
                                                        agent.agent_slug.as_deref().unwrap_or_default(),
                                                    ],
                                                )
                                            }));
                                    rsx! {
                                        div { class: "contact-sidebar-group", key: "{peer}", "data-controller": "{peer}",
                                          div { class: "sidebar-row contact-sidebar-action-row",
                                            button {
                                                class: if can_resolve { "sidebar-nav-item contact-sidebar-row sidebar-row-main" } else { "sidebar-nav-item contact-sidebar-row sidebar-row-main is-dim" },
                                                r#type: "button",
                                                "data-testid": "direct-conversation-row",
                                                "data-peer": "{peer}",
                                                "data-state": "{state_label}",
                                                "data-opening": if is_opening { "true" } else { "false" },
                                                "aria-busy": if is_opening { "true" } else { "false" },
                                                "aria-label": "{row_title}",
                                                title: "{row_title}",
                                                disabled: chat_open_blocked,
                                                onclick: {
                                                    let peer = peer.clone();
                                                    let direct = direct.clone();
                                                    let base = base_url();
                                                    let opening_key = opening_key.clone();
                                                    move |event: dioxus::events::MouseEvent| {
                                                        event.prevent_default();
                                                        event.stop_propagation();
                                                        if direct_chat_opening.read().is_some() {
                                                            return;
                                                        }
                                                        if !can_resolve {
                                                            crate::components::feedback::toast_info("direct.unavailable", vec![]);
                                                            return;
                                                        }
                                                        if let Some(summary) = direct.clone()
                                                            && summary.state
                                                                == arkret_sdk::DirectConversationSummaryState::Found
                                                        {
                                                            let _ = navigator.push(Route::DirectConversation {
                                                                realm_id: summary.realm_id.to_string(),
                                                                strand_id: summary.main_strand_id.to_string(),
                                                            });
                                                            return;
                                                        }
                                                        direct_chat_opening.set(Some(opening_key.clone()));
                                                        let api_token = token();
                                                        let base = base.clone();
                                                        let peer_for_task = peer.clone();
                                                        let peer_for_log = peer_for_task.clone();
                                                        spawn(async move {
                                                            let result = crate::transport::auth::with_authed_api(
                                                                &base,
                                                                api_token,
                                                                |api| async move {
                                                                    crate::transport::account::direct_conversation_resolve(
                                                                        &api,
                                                                        state_store,
                                                                        &peer_for_task,
                                                                        true,
                                                                        false,
                                                                    ).await
                                                                },
                                                            ).await;
                                                            let route = match result {
                                                                Ok(response) => {
                                                                    if let Some(coordinates) = crate::transport::account::direct_conversation_coordinates(&response) {
                                                                        Some(Route::DirectConversation {
                                                                            realm_id: coordinates.realm_id.to_string(),
                                                                            strand_id: coordinates.main_strand_id.to_string(),
                                                                        })
                                                                    } else {
                                                                        crate::components::feedback::toast_error(
                                                                            "feedback.direct_open_failed",
                                                                            vec![],
                                                                            Some(format!("outcome: {response:?}")),
                                                                        );
                                                                        None
                                                                    }
                                                                }
                                                                Err(err) => {
                                                                    tracing::error!(
                                                                        error = %err.display(),
                                                                        peer = %peer_for_log,
                                                                        "direct conversation open failed"
                                                                    );
                                                                    crate::components::feedback::toast_error(
                                                                        "feedback.direct_open_failed",
                                                                        vec![],
                                                                        Some(err.display()),
                                                                    );
                                                                    None
                                                                }
                                                            };
                                                            direct_chat_opening.set(None);
                                                            if let Some(route) = route {
                                                                let _ = navigator.push(route);
                                                            }
                                                        });
                                                    }
                                                },
                                                span { class: "sidebar-nav-icon contact-sidebar-user-avatar",
                                                    crate::components::IdentityAvatar {
                                                        seed: peer.clone(),
                                                        alt_text: display_name.clone(),
                                                        class: "avatar-img".to_owned(),
                                                    }
                                                }
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
                                                span { class: "pill muted xs", "{state_badge_label}" }
                                                if has_direct_scope {
                                                    span { class: "pill muted xs", title: "{scopes_label}", "DM" }
                                                }
                                                if contact_agent_count > 0 {
                                                    span {
                                                        class: "pill muted xs contact-agent-count",
                                                        role: "button",
                                                        tabindex: "0",
                                                        "data-testid": "contact-sidebar-agent-toggle",
                                                        "aria-expanded": if contact_agents_expanded { "true" } else { "false" },
                                                        onclick: {
                                                            let peer = peer.clone();
                                                            move |event: dioxus::events::MouseEvent| {
                                                                event.prevent_default();
                                                                event.stop_propagation();
                                                                if expanded_contact_agents.read().contains(&peer) {
                                                                    expanded_contact_agents.write().remove(&peer);
                                                                } else {
                                                                    expanded_contact_agents.write().insert(peer.clone());
                                                                }
                                                            }
                                                        },
                                                        "Agents {contact_agent_count}"
                                                    }
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
                                                            disabled: true,
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
                                          if show_contact_agents {
                                            div { class: "contact-agent-list", "data-testid": "contact-sidebar-contact-agents",
                                              for agent in contact.agents.iter() {
                                                {
                                                    let agent_id = agent.agent_id.to_string();
                                                    let agent_label = agent.display_name.clone()
                                                        .or_else(|| agent.agent_slug.clone())
                                                        .unwrap_or_else(|| short_protocol_id(&agent_id));
                                                    let agent_direct = agent.direct_conversation.clone();
                                                    let avatar_blob_ref = agent
                                                        .avatar_blob_ref
                                                        .as_ref()
                                                        .map(ToString::to_string)
                                                        .unwrap_or_default();
                                                    let controller = peer.clone();
                                                    let opening_key = format!("contact-agent:{agent_id}");
                                                    let opening_target = direct_chat_opening();
                                                    let chat_open_blocked = opening_target.is_some();
                                                    let is_opening = opening_target.as_deref()
                                                        == Some(opening_key.as_str());
                                                    let agent_button_label = if is_opening {
                                                        format!("Opening chat with {agent_label}")
                                                    } else {
                                                        format!("Chat with {agent_label}")
                                                    };
                                                    rsx! {
                                                        button {
                                                            key: "{agent_id}",
                                                            class: "sidebar-nav-item contact-sidebar-agent-row",
                                                            r#type: "button",
                                                            "data-testid": "contact-sidebar-agent-row",
                                                            "data-agent": "{agent_id}",
                                                            "data-controller": "{controller}",
                                                            "data-opening": if is_opening { "true" } else { "false" },
                                                            "aria-busy": if is_opening { "true" } else { "false" },
                                                            "aria-label": "{agent_button_label}",
                                                            title: "{agent_button_label}",
                                                            disabled: chat_open_blocked,
                                                            onclick: {
                                                                let base = base_url();
                                                                let agent_id = agent_id.clone();
                                                                let agent_direct = agent_direct.clone();
                                                                let opening_key = opening_key.clone();
                                                                move |event: dioxus::events::MouseEvent| {
                                                                    event.prevent_default();
                                                                    event.stop_propagation();
                                                                    if direct_chat_opening.read().is_some() {
                                                                        return;
                                                                    }
                                                                    if let Some(summary) = agent_direct.clone()
                                                                        && summary.state
                                                                            == arkret_sdk::DirectConversationSummaryState::Found
                                                                    {
                                                                        let _ = navigator.push(Route::DirectConversation {
                                                                            realm_id: summary.realm_id.to_string(),
                                                                            strand_id: summary.main_strand_id.to_string(),
                                                                        });
                                                                        return;
                                                                    }
                                                                    direct_chat_opening.set(Some(opening_key.clone()));
                                                                    let api_token = token();
                                                                    let base = base.clone();
                                                                    let agent_id = agent_id.clone();
                                                                    spawn(async move {
                                                                        let agent_id_for_log = agent_id.clone();
                                                                        let route = match crate::transport::auth::with_authed_api(
                                                                            &base,
                                                                            api_token,
                                                                            |api| async move {
                                                                                crate::transport::account::direct_conversation_resolve(
                                                                                    &api,
                                                                                    state_store,
                                                                                    &agent_id,
                                                                                    true,
                                                                                    false,
                                                                                ).await
                                                                            },
                                                                        ).await {
                                                                            Ok(response) if crate::transport::account::direct_conversation_coordinates(&response).is_some() => {
                                                                                let coordinates = crate::transport::account::direct_conversation_coordinates(&response).expect("guarded coordinates");
                                                                                Some(Route::DirectConversation {
                                                                                    realm_id: coordinates.realm_id.to_string(),
                                                                                    strand_id: coordinates.main_strand_id.to_string(),
                                                                                })
                                                                            },
                                                                            Ok(response) => {
                                                                                crate::components::feedback::toast_error(
                                                                                    "feedback.direct_open_failed",
                                                                                    vec![],
                                                                                    Some(format!("outcome: {response:?}")),
                                                                                );
                                                                                None
                                                                            }
                                                                            Err(err) => {
                                                                                tracing::error!(
                                                                                    error = %err.display(),
                                                                                    agent_id = %agent_id_for_log,
                                                                                    "contact agent direct conversation open failed"
                                                                                );
                                                                                crate::components::feedback::toast_error(
                                                                                    "feedback.direct_open_failed", vec![], Some(err.display()),
                                                                                );
                                                                                None
                                                                            }
                                                                        };
                                                                        direct_chat_opening.set(None);
                                                                        if let Some(route) = route {
                                                                            let _ = navigator.push(route);
                                                                        }
                                                                    });
                                                                }
                                                            },
                                                            span { class: "sidebar-nav-icon contact-sidebar-agent-avatar",
                                                                crate::components::IdentityAvatar {
                                                                    seed: agent_id.clone(),
                                                                    alt_text: agent_label.clone(),
                                                                    blob_ref: Some(avatar_blob_ref),
                                                                    class: "avatar-img".to_owned(),
                                                                }
                                                            }
                                                            span { class: "grow truncate", "{agent_label}" }
                                                            span { class: "pill muted xs", if is_opening { "Opening..." } else { "AI agent" } }
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
                    } else if collaboration_realm_tree_nodes.is_empty() {
                        div { class: "sidebar-nav-item is-dim", "data-testid": "realm-tree-empty-state",
                            span { class: "sidebar-nav-icon", UiIcon { name: "folder" } }
                            span { class: "grow truncate",
                                {
                                    if has_session {
                                        crate::i18n::tr("sidebar.realms_empty")
                                    } else {
                                        crate::i18n::tr("sidebar.realms_sign_in")
                                    }
                                }
                            }
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
                                    let raw_status = connection_status();
                                    let status_text = match raw_status.as_str() {
                                        "Online" => crate::i18n::tr("common.online"),
                                        "Offline" => crate::i18n::tr("common.offline"),
                                        _ => raw_status,
                                    };
                                    let error_text = last_error();
                                    // Truncate by characters, not bytes: these
                                    // strings carry server `reason` / error text
                                    // that can contain non-ASCII (CJK / emoji),
                                    // and a byte slice mid-character would panic
                                    // the whole shell to a white screen.
                                    let trimmed_status = if status_text.chars().count() > 96 {
                                        format!("{}…", status_text.chars().take(96).collect::<String>())
                                    } else {
                                        status_text
                                    };
                                    let trimmed_error = error_text
                                        .as_ref()
                                        .map(|err| if err.chars().count() > 96 {
                                            format!("{}…", err.chars().take(96).collect::<String>())
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
                            span { class: "grow truncate", {crate::i18n::tr("sidebar.realms_no_results")} }
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
                                    && !realm_tree_node_is_direct_conversation(&item_node);
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
                                            .and_then(crate::security_state::realm_projection_security_state)
                                            .unwrap_or_else(|| realm_ids_with_local_mls.contains(&item_node.id));
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
                                            Link {
                                                class: "sidebar-row-menu-item",
                                                role: "menuitem",
                                                "data-testid": "realm-tree-row-circles-action",
                                                title: "Circles",
                                                "aria-label": "Circles",
                                                to: Route::Circles { realm_id: target_realm_id.clone() },
                                                onclick: {
                                                    let home_realm_id = target_realm_id.clone();
                                                    move |_| {
                                                        selected_realm_id.set(home_realm_id.clone());
                                                        sidebar_row_menu_open.set(None);
                                                    }
                                                },
                                                UiIcon { name: "users" }
                                                span { "Circles" }
                                            }
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
                                // via `ak.account_data.set(ak.client.ui_state)`.
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
                                crate::components::IdentityAvatar {
                                    seed: account_did_value.clone(),
                                    alt_text: crate::i18n::tr("topbar.account_menu"),
                                    blob_ref: Some(topbar_avatar_blob_ref.clone()),
                                    class: "avatar-img topbar-account-avatar".to_owned(),
                                    test_id: Some("topbar-account-avatar".to_owned()),
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
                                        crate::components::IdentityAvatar {
                                            seed: account_did_value.clone(),
                                            alt_text: account_label.clone(),
                                            blob_ref: Some(topbar_avatar_blob_ref.clone()),
                                            class: "avatar-img account-menu__avatar".to_owned(),
                                            test_id: Some("account-menu-avatar".to_owned()),
                                        }
                                        span { class: "grow",
                                            span { class: "who", "data-testid": "account-menu-display-name", "{account_label}" }
                                            span { class: "handle", "data-testid": "account-menu-account-detail", "{account_detail}" }
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
                                                            crate::components::feedback::toast_success("feedback.copied_did", vec![]);
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
                                                            crate::components::feedback::toast_success("feedback.copied_handles", vec![]);
                                                        }
                                                    },
                                                    UiIcon { name: "copy" }
                                                }
                                            }
                                        }
                                        div { class: "account-menu__row",
                                            strong { "Device" }
                                            div { class: "account-menu__value",
                                                div { class: "account-menu__device-text",
                                                    span {
                                                        class: "account-menu__device-name",
                                                        "data-testid": "account-menu-device-name",
                                                        if device_display_name.trim().is_empty() { "This device" } else { "{device_display_name}" }
                                                    }
                                                    span {
                                                        class: "mono account-menu__device-id",
                                                        "data-testid": "account-menu-device",
                                                        title: "{device_id_value}",
                                                        "{device_id_label}"
                                                    }
                                                }
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
                                                            crate::components::feedback::toast_success("feedback.copied_device_id", vec![]);
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
                                                let session = manual_refresh_session.clone();
                                                move |_| {
                                                    let base = base.clone();
                                                    let session = session.clone();
                                                    let api_token = token();
                                                    let actor = account_did();
                                                    let device = device_id();
                                                    personal_handles_lookup_key.set(String::new());
                                                    account_identity_lookup_key.set(String::new());
                                                    account_session_state.set("Refreshing session".to_owned());
                                                    spawn(async move {
                                                        match self_authed_api(&base, api_token.clone()) {
                                                            Ok(api) => match async {
                                                                crate::transport::account::account_me(&api.sdk_http_client()?).await
                                                            }
                                                            .await
                                                            {
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
                                                                        match session.refresh().await {
                                                                            crate::runtime::session::CurrentSessionRefresh::Credential(fresh) => {
                                                                                let canonical_actor = match self_authed_api(&base, fresh) {
                                                                                    Ok(api) => async {
                                                                                        crate::transport::account::account_me(&api.sdk_http_client()?).await
                                                                                    }
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
                                                                            crate::runtime::session::CurrentSessionRefresh::SignInRequired { reason } => {
                                                                                last_error.set(Some(reason));
                                                                                account_session_state.set(
                                                                                    "Sign in again to refresh this session.".to_owned()
                                                                                );
                                                                            }
                                                                            crate::runtime::session::CurrentSessionRefresh::LoginRequired { reason } => {
                                                                                last_error.set(Some(reason));
                                                                                account_session_state.set(
                                                                                    "Session expired. Sign in again.".to_owned()
                                                                                );
                                                                            }
                                                                            crate::runtime::session::CurrentSessionRefresh::RetryLater { reason } => {
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
                                                    crate::identity::account_auth::grant_dpop::ensure_device_key(&mut store).ok()
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
                                                runtime_services.effects.request_cancel_all();
                                                // Clear browser-session credentials up front so a
                                                // local retry cannot resurrect the session if the
                                                // server-side logout call later fails or is
                                                // cancelled. Keep the account entry itself:
                                                // projections, encrypted MLS checkpoints, and the
                                                // durable device identity are account state, not
                                                // grant-binding state. In-memory plaintext sidecars
                                                // are cleared here and can only be restored from the
                                                // encrypted checkpoint after the next sign-in. The
                                                // next interactive sign-in rotates the grant-binding
                                                // seed before issuing the new session grant.
                                                state_store
                                                    .write()
                                                    .clear_session_scoped_for_logout();
                                                // Wiping the durable E2EE device identity (true
                                                // "remove this device") is reserved for a separate
                                                // explicit action; logout only terminates the
                                                // browser session.
                                                let _ = crate::identity::account_auth::clear_persisted_oidc_scaffold();
                                                // Wipe the in-memory UI signals too so the
                                                // sidebar can't paint a frame of stale
                                                // Realm tree updates between this click and the
                                                // navigator.push(Login).
                                                realm_tree_nodes.set(Vec::new());
                                                projection_events.set(Vec::new());
                                                sync_cursor.set(String::new());
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
                                                let logout_effects =
                                                    runtime_services.effects.clone();
                                                spawn(async move {
                                                    logout_effects.cancel_all().await;
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
                RouteSurface {
                    state: RouteSurfaceState {
                        content_route: content_route.clone(),
                        navigation: NavigationState::new(
                            route.clone(),
                            view,
                            selected_realm_id,
                            new_space_context_node,
                        ),
                        account_did,
                        device_id,
                        token,
                        connection_status,
                        config_store,
                        account_primary_handle,
                        personal_handles,
                        personal_handles_status,
                        realm_tree_nodes,
                        device_queue,
                        frontier_state,
                        sync_cursor,
                        resolved_realm_surface,
                        minimal_ready,
                        kanban_ready,
                        full_ready,
                        e2ee_ready,
                        event_write_ready,
                        active_service_id: active_service_id.clone(),
                        active_realm_id: active_realm_id.clone(),
                        active_projection_realm_id: active_projection_realm_id.clone(),
                        realm_live_epoch,
                        has_session,
                        manage_realm_rows: manage_realm_rows.clone(),
                        realm_manage_query,
                        manage_realm_selection,
                        manage_bulk_busy,
                        direct_contact_rows,
                        direct_contacts_loaded,
                        contact_manage_query,
                        manage_contact_selection,
                        secure_store_bootstrap_ready,
                        needs_device_authorization,
                        device_authorization_check_complete,
                        can_list_handles_for_subject,
                        push_state,
                        locale,
                        theme,
                        base_url,
                    }
                }
            }
            NotificationsDrawer {
                open: notifications_drawer_open,
                account_did: account_did(),
                device_id: device_id(),
                token,
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
}

#[cfg(test)]
#[path = "../app_tests.rs"]
mod tests;
