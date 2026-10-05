use std::collections::{BTreeMap, BTreeSet};

use arkret_sdk::contact_operations::ContactScope;
use dioxus::prelude::*;
use dioxus_router::hooks::*;
use dioxus_router::{Link, Navigator, Outlet};
use serde_json::Value;

use crate::components::{SecurityStateBadge, SelfAttributionBadge, UiIcon};
use crate::config::{ClientConfig, LocalConfigStore, normalize_server_url};
use crate::conformance::StationFeature;
use crate::i18n::UiLocale;
use crate::models::{
    RealmTreeNode, RealmTreeNodeKind, ServiceDescribe, missing_v1_station_requirements,
    projection_realm_id_for_known_node, service_supports_event_envelope_write_plane,
};
// R28-B — realm-tree / projection / field-extraction helpers moved to
// `crate::realm_tree`. Re-export the two `pub` entry points used by
// `crate::sync_engine` so the existing `crate::app::…` call sites keep
// resolving without a sync_engine edit.
pub(crate) use crate::realm_tree::{
    descendant_node_ids, realm_tree_node_is_direct_conversation,
    realm_tree_nodes_from_sync_realms_with_roles,
};
use crate::routes::Route;
use crate::state::projection::ProjectionEvent;
use crate::state::{ClientLocalState, LocalStateStore, PersistedSessionGrant};
use crate::transport::TransportClient;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::input::Input;
use crate::ui_signal::try_set_signal;
use crate::views::ConnectionState;
use crate::views::helpers::{actor_display_label, persist_config, short_protocol_id};

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

// post-login / startup-check effects and small types moved to
// `crate::app::bootstrap` (move-only; logic, signatures, and bytes unchanged).
// The re-export keeps existing app.rs call sites and `app_tests.rs`
// `use super::*` resolution paths unchanged.
#[path = "../bootstrap.rs"]
mod bootstrap;
pub(crate) use bootstrap::*;
// theme-resolution helpers (system/shell dark-mode detection, the
// `<html>` data-theme mirror, manual toggle) live in `app/theme.rs` (move only).
// The glob re-export keeps the inline call sites and `app_tests.rs` `use super::*`
// resolution unchanged.
mod theme;
pub(crate) use theme::*;
mod web_leader;
// per-realm surface selection (RealmSurface enum + preference
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
mod connection_handlers;
mod context_bar;
pub(crate) mod direct_open;
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
mod security_signals;
mod session_boot;
mod session_context;
mod session_shell;
mod shell_effects;
mod shell_model;
mod sidebar;
mod sidebar_width;
mod signal_products;
mod sync_effects;
pub(crate) use clipboard::*;
pub(crate) use command_palette::*;
use connect::*;
use connection_effects::{ConnectionEffectState, ConnectionEffects};
use connection_handlers::{
    ConnectionRuntimeSignals, ManualSessionRefreshContext, ServerSwitchHandlerContext,
    refresh_connection, refresh_current_session, switch_server_and_connect,
};
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
use security_signals::{SecurityRuntimeSignals, use_security_runtime_signals};
pub(crate) use session_boot::*;
use session_context::AppStateStore;
pub(crate) use session_context::{ContactInbox, SessionContext};
use session_shell::{
    MobileConnectionStatus, MobileNavDrawer, MobileRealmTree, SessionShell, SessionSurface,
};
use shell_effects::{ShellEffectState, ShellEffects};
use sidebar::*;
use sidebar_width::*;
use sync_effects::SyncEffects;

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

// The stylesheets are four ordered layers, and the order below IS the
// contract; nothing is encoded in file-name prefixes.
//
//   `base/`       tokens first, then the element reset. `tokens.css` carries
//                 custom-property declarations and nothing else, so there is
//                 exactly one place a theme value can come from.
//   `components/` product-neutral primitives (button, field, badge, surface,
//                 modal, ...). A class defined here is defined once across the
//                 whole layer.
//   `features/`   one product surface per file, named after that surface. A
//                 feature may scope a component (`.settings .btn`) or add a
//                 modifier, but must not restate a component's own rule.
//   `adaptive/`   cross-feature viewport, print, contrast and reduced-motion
//                 overrides. It is last because a media query adds no
//                 specificity: anywhere earlier and a plain rule after it wins,
//                 which is how the tablet/mobile layer used to lose silently.
//                 Media queries that only concern one feature stay in that
//                 feature's file.
const BASE_STYLE: &str = concat!(
    include_str!("../styles/base/tokens.css"),
    include_str!("../styles/base/reset.css"),
);

const COMPONENT_STYLE: &str = concat!(
    include_str!("../styles/components/surfaces.css"),
    include_str!("../styles/components/controls.css"),
    include_str!("../styles/components/forms.css"),
    include_str!("../styles/components/badges.css"),
    include_str!("../styles/components/avatar.css"),
    include_str!("../styles/components/tables.css"),
    include_str!("../styles/components/overlays.css"),
    include_str!("../styles/components/feedback.css"),
    include_str!("../styles/components/qr-share.css"),
    include_str!("../styles/components/content-blocks.css"),
    include_str!("../styles/components/rich-text-editor.css"),
    include_str!("../styles/components/utilities.css"),
);

const FEATURE_STYLE: &str = concat!(
    include_str!("../styles/features/app-shell.css"),
    include_str!("../styles/features/sidebar-nav.css"),
    include_str!("../styles/features/topbar.css"),
    include_str!("../styles/features/account-menu.css"),
    include_str!("../styles/features/command-palette.css"),
    include_str!("../styles/features/auth.css"),
    include_str!("../styles/features/onboarding.css"),
    include_str!("../styles/features/chat-shell.css"),
    include_str!("../styles/features/chat-message.css"),
    include_str!("../styles/features/chat-composer.css"),
    include_str!("../styles/features/chat-sidecar.css"),
    include_str!("../styles/features/circle.css"),
    include_str!("../styles/features/kanban-board.css"),
    include_str!("../styles/features/kanban-card-detail.css"),
    include_str!("../styles/features/kanban-card-fields.css"),
    include_str!("../styles/features/settings.css"),
    include_str!("../styles/features/settings-security.css"),
    include_str!("../styles/features/settings-devices.css"),
    include_str!("../styles/features/setup.css"),
    include_str!("../styles/features/contacts.css"),
    include_str!("../styles/features/members-admin.css"),
    include_str!("../styles/features/agents-admin.css"),
    include_str!("../styles/features/realm-manage.css"),
    include_str!("../styles/features/directory.css"),
    include_str!("../styles/features/recovery.css"),
    include_str!("../styles/features/call.css"),
);

const ADAPTIVE_STYLE: &str = concat!(
    include_str!("../styles/adaptive/viewport.css"),
    include_str!("../styles/adaptive/accessibility-print.css"),
);

/// C3: yoface shared-component design tokens. The first layer is shadcn
/// semantic tokens (`--primary/--background/--foreground/...`); the second
/// layer is the dioxus-components token aliases
/// (`--primary-color-N/--focused-border-color/...`) used by `yoface::ui::*`
/// `#[css_module]` styles. Values come from the inkson green palette (yoface
/// tokens.css matches `styles/base/tokens.css`), so this keeps the existing
/// `var(--dark,...)` / `var(--light,...)` and `[data-theme]` switches and the
/// current inkson green appearance. Injection order stays before the four
/// style layers so `base/tokens.css` can override these tokens.
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
    // Detached submission tasks run in Dioxus' runtime root (`ScopeId::ROOT`),
    // which is the parent of this component's hook scope. A normal
    // `use_signal_sync` would therefore be owned by a child scope while those
    // longer-lived tasks read and write it, triggering CopyValue lifetime
    // warnings and making hot-reload/remount writes unsafe. Keep hook-stable
    // construction, but assign the Signal itself to the runtime root so every
    // component and detached task is its descendant.
    let state_store =
        use_hook(|| SyncSignal::new_maybe_sync_in_scope(LocalStateStore::default(), ScopeId::ROOT));
    use_context_provider(|| AppStateStore(state_store));
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
    if let (Some(account), Some(persisted)) = (
        initial_config.active_account.as_ref(),
        initial_local_state.device_authoring_authority.as_ref(),
    ) {
        let cache_epoch = crate::identity::device_directory::cache_epoch();
        crate::identity::device_directory::restore_persisted_device_authoring_authority(
            cache_epoch,
            &account.authority,
            &account.device_id,
            persisted,
        );
    }
    let initial_session_credential = initial_session_credential_from_state(
        &initial_local_state,
        &initial_config,
        chrono::Utc::now().timestamp(),
    );
    let initial_active_account = initial_config.active_account.clone();
    let initial_server_url = initial_active_account
        .as_ref()
        .map(|account| account.server_url.to_string())
        .or_else(|| initial_config.stations.first().map(ToString::to_string))
        .unwrap_or_else(|| "https://local.host".to_owned());
    let initial_principal_id = initial_active_account
        .as_ref()
        .map(|account| account.principal_id().clone());
    let initial_device_id = initial_active_account
        .as_ref()
        .map(|account| account.device_id.to_string())
        .unwrap_or_else(crate::config::new_device_id);
    let initial_can_restore_session =
        has_bootstrap_refresh_material(&initial_state_store, initial_active_account.as_ref());
    let initial_secure_store_bootstrap_ready = !cfg!(target_arch = "wasm32");
    let initial_session_boot_state = session_boot_state_from_bootstrap_material(
        &initial_session_credential,
        initial_can_restore_session,
        crate::app::principal_id_text(&initial_principal_id),
        initial_secure_store_bootstrap_ready,
    );
    let initial_control_realm_ids = principal_control_realm_ids(&initial_local_state);
    let initial_realm_tree_nodes = realm_tree_nodes_from_sync_realms_with_roles(
        &initial_local_state.realm_tree_projections,
        &initial_local_state.realm_collaboration_roles,
    )
    .into_iter()
    .filter(|node| !initial_control_realm_ids.contains(&node.id))
    .collect::<Vec<_>>();
    let initial_realm_tree_owner_id = initial_state_store
        .active_principal_id()
        .unwrap_or_default();
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
        .load_plain_local_data("theme")
        .filter(|theme| matches!(theme.as_str(), "light" | "night" | "system"))
        .unwrap_or_else(|| "night".to_owned());
    // Rehydrate the persisted primary handle for the booted account so any
    // signed-out diagnostics can identify the account by handle on a fresh
    // load, instead of falling back to the raw principal ID. Reads the per-account entry
    // by DID (not the active account), so it works regardless of which account
    // is currently active.
    let initial_account_primary_handle = initial_state_store
        .primary_handle_for_principal_id(crate::app::principal_id_text(&initial_principal_id))
        .unwrap_or_default();
    let config_store = use_signal(LocalConfigStore::default);
    let mut state_store = use_context::<AppStateStore>().0;
    // Move-into-signal initialisers. Each `use_signal(...)` runs once on
    // first render, so we pre-extract the fields and hand each closure a
    // ready-to-move `String` instead of repeatedly cloning the whole
    // `initial_config` struct.
    // Pin the active typed user store to the persisted server-authored
    // principal before async signer bootstrap begins.
    {
        let boot_account = initial_active_account.clone();
        use_hook(move || {
            let Some(account) = boot_account.clone() else {
                crate::secure_key_store::set_active_device_seed_scope(None);
                return;
            };
            match crate::secure_key_store::UserLocalStore::new(account.authority, account.device_id)
            {
                Ok(store) => store.activate(),
                Err(error) => {
                    tracing::error!(%error, "persisted active account secure scope is invalid");
                    crate::secure_key_store::set_active_device_seed_scope(None);
                }
            }
        });
    }
    let base_url = use_signal(move || initial_server_url);
    let active_account = use_signal(move || initial_active_account);
    let principal_id = use_signal(move || initial_principal_id);
    let device_id = use_signal(move || initial_device_id);
    let mut token = use_signal(move || initial_session_credential);
    let session_boot_state = use_signal(move || initial_session_boot_state);
    let mut session_generation = use_signal(|| 0_u64);
    // Bumped by Settings → My Agents on every owned-agent mutation so the
    // Contacts sidebar can re-pull `agent_list`. See `SessionContext`.
    let owned_agents_rev = use_signal(|| 0_u64);

    // A4 — provide the session-scoped shared handles (`state_store`, `base_url`)
    // via context so descendant components read them through
    // `use_context::<SessionContext>()` instead of threading them down as props.
    // Same signal handles `RouterView` already owns; single source of truth.
    use_context_provider(|| SessionContext {
        active_account,
        state_store,
        base_url,
        session_generation,
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
    let navigation_state_snapshot = state_store.read().load();
    let principal_control_realm_ids = principal_control_realm_ids(&navigation_state_snapshot);
    let personal_control_realm_id = personal_control_realm_id(&navigation_state_snapshot);
    let routed_realm_id = route.realm_id().map(str::to_owned);
    let routed_control_realm_id = routed_realm_id
        .as_ref()
        .filter(|realm_id| principal_control_realm_ids.contains(realm_id.as_str()))
        .cloned();
    let current_route_uses_realm_context =
        route_uses_realm_context(&route) && routed_control_realm_id.is_none();
    let mut realm_events_route_enabled = use_signal(move || current_route_uses_realm_context);
    if *realm_events_route_enabled.peek() != current_route_uses_realm_context {
        realm_events_route_enabled.set(current_route_uses_realm_context);
    }
    // Connection-lifecycle status only (offline / restoring / online / session
    // expired). Operation feedback now goes through the toast queue in
    // `crate::components::feedback` — never through this signal.
    let connection_status = use_signal(|| ConnectionState::Offline.label().to_owned());
    let initial_sync_cursor = initial_sync_cursor(initial_local_state.sync_cursor.clone());
    let initial_selected_realm_id = initial_realm_tree_nodes
        .iter()
        .find(|node| node.kind == RealmTreeNodeKind::Realm)
        .map(|node| node.id.clone())
        .unwrap_or_default();
    let initial_push_state =
        crate::push::push_status_label(initial_local_state.push_registration.as_ref());
    let initial_realm_tree_nodes_for_signal = initial_realm_tree_nodes.clone();
    let initial_realm_tree_owner_id_for_signal = initial_realm_tree_owner_id.clone();
    let mut sync_cursor = use_signal(move || initial_sync_cursor);
    // Liveness counter for the per-realm `events/subscribe` engine
    // (`crate::realm_events_engine`). Bumped when that engine folds fresh realm
    // events the account stream never delivered (cross-member case); the kanban
    // panel reads it as a second freshness axis besides `sync_cursor`.
    let realm_live_epoch = use_signal(|| 0u64);
    let mut selected_realm_id = use_signal(move || initial_selected_realm_id);
    let mut new_space_context_node = use_signal(String::new);
    let mut realm_tree_nodes = use_signal(move || initial_realm_tree_nodes_for_signal);
    if realm_tree_nodes
        .peek()
        .iter()
        .any(|node| principal_control_realm_ids.contains(&node.id))
    {
        realm_tree_nodes.set(
            realm_tree_nodes()
                .into_iter()
                .filter(|node| !principal_control_realm_ids.contains(&node.id))
                .collect(),
        );
    }
    let mut realm_tree_owner_id = use_signal(move || initial_realm_tree_owner_id_for_signal);
    let mut projection_events = use_signal(Vec::<ProjectionEvent>::new);
    let mut device_queue = use_signal(|| 0usize);
    let push_state = use_signal(move || initial_push_state);
    let frontier_state = use_signal(|| "Not loaded".to_owned());
    let crypto_state = use_signal(|| "No authenticated session".to_owned());
    let network_state = use_signal(|| "offline".to_owned());

    // Realm-tree nodes are an in-memory account projection. Invalidate them as
    // soon as the account signal changes; connect() will repopulate them from
    // the new account. Keeping the owner separately also prevents the render
    // between the principal change and this effect from exposing the old account.
    use_effect(move || {
        let current_account = crate::app::principal_id_owned(principal_id());
        if realm_tree_owner_id.peek().as_str() != current_account {
            realm_tree_nodes.set(Vec::new());
            projection_events.set(Vec::new());
            sync_cursor.set(String::new());
            selected_realm_id.set(String::new());
            device_queue.set(0);
            realm_tree_owner_id.set(current_account);
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
    let mobile_space_query = use_signal(String::new);
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
    let account_identity_lookup_key = use_signal(String::new);
    let contact_handles_lookup_key = use_signal(String::new);
    let contact_handles_fetching = use_signal(BTreeSet::<String>::new);
    let mut global_query = use_signal(String::new);
    let mut palette_open = use_signal(|| false);
    let mut topbar_search_expanded = use_signal(|| false);
    let mut notifications_drawer_open = use_signal(|| false);
    let sync_bootstrap_complete = use_signal(|| false);
    // A6.4 — `?` keyboard shortcut help overlay state.
    let mut shortcut_help_open = use_signal(|| false);
    let mut realm_sidebar_tab = use_signal(|| "collaboration".to_owned());
    let mut collaboration_sidebar_query = use_signal(String::new);
    let mut direct_sidebar_query = use_signal(String::new);
    let realm_manage_query = use_signal(String::new);
    let contact_manage_query = use_signal(String::new);
    let direct_contact_rows = use_signal(Vec::<crate::models::ContactListRow>::new);
    use_context_provider(|| ContactInbox(direct_contact_rows));
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
    let SecurityRuntimeSignals {
        mls_key_package_publish_key_seen,
        mls_welcome_bootstrap_key_seen,
        mls_admission_reconcile_in_flight,
        mls_admission_reconcile_pending,
        mls_admission_diag_last,
        needs_mls_unlock,
        needs_mls_backup,
        needs_mls_recovery_setup,
        needs_device_authorization,
        device_authorization_check_complete,
        account_has_other_devices,
        mut recovery_key_setup_prompt,
        recovery_auto_prompt_fired,
        mut account_recovery_configured,
        mut account_recovery_detection_key_seen,
        account_recovery_retry_attempt,
    } = use_security_runtime_signals();
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
                    principal_id,
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
    let sync_engine_active_generation = use_signal(|| Option::<String>::None);
    // Dedup key (`<generation>|<realm_id>`) for the per-realm events engine, so
    // a base_url/token re-render doesn't stack a second loop on the same realm.
    let realm_events_engine_active_key = use_signal(|| Option::<String>::None);
    // The Signal receive rail takes no selector, so one loop per generation is
    // the whole lifecycle.
    let signal_receive_engine_active_generation = use_signal(|| Option::<u64>::None);
    let websocket_rail_active_generation = use_signal(|| Option::<u64>::None);
    let bootstrap_pending = use_signal(|| true);

    // P3B.4.3 — active multi-profile snapshot, threaded into
    // the sync engine context so the loop can detect a profile rotation
    // and exit cleanly. The shell is currently single-profile; the
    // signal stays default-empty until the account switcher writes to
    // it on the first user-driven add-account / switch action.
    let profiles_signal = use_signal(crate::config::MultiProfileConfig::default);

    let shell_model::RealmSelection {
        effective_realm_id,
        remember: remember_routed_realm_id,
    } = shell_model::resolve_realm_selection(
        routed_realm_id.as_deref(),
        &selected_realm_id(),
        &principal_control_realm_ids,
    );
    let active_realm_id = effective_realm_id.clone().unwrap_or_default();
    if let Some(route_realm_id) = remember_routed_realm_id {
        selected_realm_id.set(route_realm_id);
    }

    let active_server_description = server_description();
    let active_service_id = active_server_description
        .as_ref()
        .map(|description| description.service_id.as_str().to_owned())
        .unwrap_or_default();
    let has_session = !token().trim().is_empty();
    let auth_surface = auth_surface_for_route(
        &route,
        has_session,
        session_boot_state(),
        secure_store_bootstrap_ready(),
    );
    #[cfg(all(target_arch = "wasm32", debug_assertions))]
    {
        let auth_surface_route = route.clone();
        use_effect(move || {
            let secure_store_ready = secure_store_bootstrap_ready();
            let boot_state = session_boot_state();
            let has_session = !token().trim().is_empty();
            let surface = auth_surface_for_route(
                &auth_surface_route,
                has_session,
                boot_state,
                secure_store_ready,
            );
            tracing::warn!(
                target: "session_state",
                route = ?auth_surface_route,
                secure_store_ready,
                has_session,
                boot_state = ?boot_state,
                surface = ?surface,
                "auth surface classified"
            );
        });
    }
    let active_server_label = normalize_server_url(&base_url());
    let principal_id_value = crate::app::principal_id_owned(principal_id());
    let device_id_value = device_id();
    let principal_id_label = short_protocol_id(&principal_id_value);
    let device_id_label = short_protocol_id(&device_id_value);
    let personal_handles_value = personal_handles();
    let account_display_name = current_account_display_name();
    let device_display_name = current_device_display_name();
    let shell_model::AccountIdentityLabels {
        handles_label: account_handles_label,
        handles_title: account_handles_title,
        label: account_label,
        detail: account_detail,
    } = shell_model::account_identity_labels(shell_model::AccountIdentityInput {
        has_session,
        personal_handles: &personal_handles_value,
        personal_handles_status: &personal_handles_status(),
        account_display_name: &account_display_name,
        device_display_name: &device_display_name,
        device_id_label: &device_id_label,
        principal_id_value: &principal_id_value,
        store: &state_store.read(),
    });
    // The actor-private mirror is authoritative when present (including an
    // explicit empty tombstone after clearing an avatar). Otherwise use the
    // public Actor Profile projection loaded from account/viewer.
    let topbar_avatar_blob_ref = use_memo(move || {
        if token().trim().is_empty() {
            String::new()
        } else {
            state_store
                .read()
                .load_plain_local_data("avatar_blob_ref")
                .unwrap_or_else(&*current_account_avatar_blob_ref)
        }
    })();
    let board_ready = StationFeature::Board.ready(active_server_description.as_ref());
    let event_write_ready = active_server_description
        .as_ref()
        .map(service_supports_event_envelope_write_plane)
        .unwrap_or(false);
    let route_uses_realm_context =
        route_uses_realm_context(&route) && routed_control_realm_id.is_none();
    let context_realm_id = if route_uses_realm_context {
        effective_realm_id.clone()
    } else {
        None
    };
    let resolved_realm_surface = if routed_control_realm_id.is_some() {
        None
    } else {
        resolve_realm_surface(
            &route,
            &state_store.read(),
            crate::app::principal_id_text(&principal_id()),
            context_realm_id.as_deref(),
        )
    };
    let realm_members_active = matches!(&route, Route::RealmMembers { .. });
    if let (Some(realm_id), Some(surface)) = (routed_realm_id.as_deref(), resolved_realm_surface)
        && matches!(
            &route,
            Route::KanbanRealm { .. } | Route::KanbanBoard { .. } | Route::KanbanBoardTask { .. }
        )
    {
        let stored_surface = load_realm_surface_preference(
            &state_store.read(),
            crate::app::principal_id_text(&principal_id()),
            realm_id,
        );
        if stored_surface != surface {
            persist_realm_surface_preference(
                &mut state_store.write(),
                crate::app::principal_id_text(&principal_id()),
                realm_id,
                surface,
            );
        }
    }

    let loaded_realm_tree_nodes = if session_boot::account_projections_visible(
        &route,
        has_session,
        crate::app::principal_id_text(&principal_id()),
        &realm_tree_owner_id(),
    ) {
        realm_tree_nodes()
    } else {
        Vec::new()
    };
    let pinned_realm_ids = {
        let store = state_store.read();
        pinned_realm_ids_from_store(&store)
    };
    let realm_tree_projections = state_store.read().load().realm_tree_projections;
    let current_product_view = state_store.read().current_product_view();
    // A persisted Realm-default MLS snapshot is authoritative local evidence
    // for previously created/joined encrypted Realms. It also repairs clients
    // whose cached account projection was already downgraded by the old
    // `e2ee_epoch: null => plaintext` parser before this build starts.
    let realm_ids_with_local_mls: BTreeSet<String> = state_store
        .read()
        .mls_local_checkpoints()
        .into_keys()
        .filter(|scope_id| scope_id.starts_with("ak:realm:"))
        .collect();
    let collaboration_sidebar_query_value =
        collaboration_sidebar_query().trim().to_ascii_lowercase();
    let direct_sidebar_query_value = direct_sidebar_query().trim().to_ascii_lowercase();
    let realm_remarks_for_sidebar = state_store.read().realm_remarks();
    let shell_model::RealmNavigationModel {
        collaboration_nodes: collaboration_realm_tree_nodes,
        selected_preview,
        active_projection_realm_id,
        realm_tree,
        filtered_realm_tree,
        manage_realm_rows,
        active_realm_security_encrypted,
    } = shell_model::build_realm_navigation(shell_model::RealmNavigationInput {
        loaded_nodes: &loaded_realm_tree_nodes,
        principal_control_realm_ids: &principal_control_realm_ids,
        context_realm_id: context_realm_id.as_deref(),
        active_realm_id: &active_realm_id,
        pinned_realm_ids: &pinned_realm_ids,
        realm_tree_projections: &realm_tree_projections,
        current_product_view: current_product_view.as_ref(),
        realm_ids_with_local_mls: &realm_ids_with_local_mls,
        realm_remarks: &realm_remarks_for_sidebar,
        collaboration_query: &collaboration_sidebar_query_value,
    });
    // Render from an owned snapshot. Keeping a Signal read guard alive inside
    // the RSX iterator lets an async Direct Conversation open complete while
    // Dioxus is still reconciling that borrowed hook storage, which panics in
    // generational-box when the opening state is cleared.
    let own_agent_rows_for_sidebar = own_agent_rows.read().clone();
    let contact_remarks_for_sidebar = state_store.read().active_contact_remarks();
    let filtered_direct_contact_rows = shell_model::filter_and_sort_direct_contacts(
        &direct_contact_rows.read(),
        &direct_sidebar_query_value,
        &state_store.read(),
        &contact_remarks_for_sidebar,
    );
    let active_locale = locale();
    let active_direction = active_locale.direction();
    let direction_attr = active_direction.as_str();
    let locale_attr = active_locale.code();
    let active_theme = theme();
    let sidebar_is_collapsed = sidebar_collapsed();
    let sidebar_is_resizing = sidebar_resizing();
    let server_menu_is_open = server_menu_open();
    let configured_stations = config_store.read().load().stations;
    let server_options = server_options_for(&base_url(), &configured_stations);
    let sidebar_style = format!("--sidebar-w: {:.0}px;", sidebar_width());
    let shell_model::ShellChrome {
        theme_toggle_icon,
        theme_toggle_title,
        shell_class,
        auth_class,
    } = shell_model::shell_chrome(
        &active_theme,
        system_theme_is_night(),
        active_direction,
        sidebar_is_collapsed,
        sidebar_is_resizing,
    );
    // The shell's `data-theme` carries the *raw* chosen mode
    // (`light` | `night` | `system`) as an app/diagnostic signal (the e2e theme
    // assertions read it). All *styling* is driven off the *effective* canonical
    // `light`/`dark` value that `apply_document_root_theme` mirrors onto `<html>`:
    // `styles/base/tokens.css` and the vendored dxc palette key on `:root` /
    // `html[data-theme]`, and the `--ak-*` aliases plus the auth surfaces key
    // on `[data-theme="dark"]` (the `<html>` ancestor). Nothing styling-related
    // depends on this attribute, so it stays the raw mode.
    let theme_attr = active_theme.as_str();
    let route_title = if routed_control_realm_id.is_some() {
        crate::i18n::tr("route.principal_control")
    } else {
        resolved_realm_surface
            .map(|surface| surface.title().to_owned())
            .unwrap_or_else(|| match &route {
                Route::Dashboard => crate::i18n::tr("nav.dashboard"),
                Route::Settings | Route::SettingsSection { .. } => crate::i18n::tr("nav.settings"),
                _ => crate::i18n::tr(route_label_key(&route)),
            })
    };
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
    let topbar_unread_notifications = {
        let snapshot = state_store.read().load();
        unread_notification_count(&snapshot)
            + ContactInbox(direct_contact_rows).pending_count(&snapshot)
    };
    let has_topbar_unread_notifications = topbar_unread_notifications > 0;
    let document_title = if matches!(&route, Route::Dashboard) {
        "Inkson | Arkret".to_owned()
    } else {
        format!("{route_title} | Inkson | Arkret")
    };
    // The auth surface and app shell are mounted through one stable component
    // boundary below. SessionSurface owns the small conditional template, so
    // neither surface's internal RSX can alter this parent template's shape.
    let mut login_bootstrap_pending = bootstrap_pending;
    let mut callback_bootstrap_pending = bootstrap_pending;
    let login_session_boot_state = session_boot_state;
    let callback_session_boot_state = session_boot_state;
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
                                principal_id,
                                device_id,
                                token,
                                config_store,
                                locale,
                                auto_capture_callback: true,
                                on_login: move |_| {
                                    callback_bootstrap_pending.set(true);
                                    transition_session_boot_state(
                                        callback_session_boot_state,
                                        SessionBootState::Checking,
                                        "OIDC callback accepted; bootstrap requested",
                                    );
                                    navigator.replace(Route::Dashboard);
                                },
                            }
                        },
                        AuthSurface::Onboarding => rsx! {
                            crate::views::onboarding::OnboardingPanel {
                                secure_store_ready: secure_store_bootstrap_ready(),
                                token,
                                principal_id,
                                device_id,
                                config_store,
                                account_primary_handle,
                                needs_device_authorization,
                                device_authorization_check_complete,
                            }
                        },
                        AuthSurface::Register => rsx! {
                            crate::views::register::RegistrationPanel {}
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
                                        h1 { {crate::i18n::tr("app.boot.opening_secure_storage")} }
                                        p { "Arkret" }
                                    }
                                }
                                div { class: "auth-restore-indicator", "aria-hidden": "true" }
                                div {
                                    class: "auth-status",
                                    "data-testid": "session-restore-status",
                                    {crate::i18n::tr("app.boot.loading_keys")}
                                }
                            }
                        },
                        AuthSurface::Login | AuthSurface::AppShell => rsx! {
                            crate::views::login::LoginPanel {
                                principal_id,
                                device_id,
                                token,
                                config_store,
                                locale,
                                auto_capture_callback: false,
                                session_error: last_error(),
                                on_login: move |_| {
                                    login_bootstrap_pending.set(true);
                                    transition_session_boot_state(
                                        login_session_boot_state,
                                        SessionBootState::Checking,
                                        "interactive session accepted; bootstrap requested",
                                    );
                                    navigator.replace(Route::Dashboard);
                                },
                            }
                        },
                    }
                }
                Outlet::<Route> {}
            }
    };

    let content_route = route.clone();
    // Single source of truth for the post-boot account-health prompt chain.
    // Each prompt below renders iff it is the resolved highest-priority one,
    // replacing the per-prompt inline suppression that used to drift apart.
    // See `account_health` and `docs/user-flows-key-lifecycle.md` §3.
    let active_prompt = {
        let store = state_store.read();
        let actor = principal_id();
        let local_recovery_configured =
            actor.is_some() && crate::views::recovery::recovery_options_configured(&store);
        let account_recovery_configured = account_recovery_configured();
        crate::account_health::AccountHealthInputs {
            has_session,
            sync_bootstrap_complete: sync_bootstrap_complete(),
            device_check_complete: device_authorization_check_complete(),
            on_recovery_route: matches!(&content_route, Route::Recovery | Route::SettingsRecovery),
            on_onboarding_route: matches!(&content_route, Route::Onboarding),
            recovery_check_complete: account_recovery_configured.is_some(),
            needs_device_authorization: needs_device_authorization(),
            account_has_other_devices: account_has_other_devices(),
            needs_mls_unlock: needs_mls_unlock(),
            needs_mls_backup: needs_mls_backup(),
            needs_mls_recovery_setup: needs_mls_recovery_setup(),
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
    let connection_runtime = ConnectionRuntimeSignals {
        connection_status,
        sync_cursor,
        token,
        principal_id,
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
        bootstrap_pending,
        did_resolution_health,
    };
    let mobile_connect_session = runtime_services.session.clone();
    let server_switch_context = ServerSwitchHandlerContext {
        runtime: connection_runtime,
        base_url,
        state_store,
        personal_handles_lookup_key,
        server_menu_open,
        session: runtime_services.session.clone(),
    };
    let manual_refresh_context = ManualSessionRefreshContext {
        session: runtime_services.session.clone(),
        token,
        principal_id,
        active_account,
        account_session_state,
        personal_handles_lookup_key,
        account_identity_lookup_key,
        account_primary_handle,
        personal_handles,
        personal_handles_status,
        last_error,
        config_store,
    };
    let mobile_status = rsx! {
        MobileConnectionStatus {
            connection_status,
            sync_cursor,
            on_refresh: move |_| refresh_connection(
                base_url(),
                connection_runtime,
                mobile_connect_session.clone(),
                state_store,
            ),
        }
    };
    let mobile_realm_tree = rsx! {
        MobileRealmTree {
            has_realms: !loaded_realm_tree_nodes.is_empty(),
            realm_tree: realm_tree.clone(),
            mobile_space_query,
            selected_realm_id,
            mobile_nav_open,
        }
    };

    rsx! {
            SessionShell {
                locale,
                i18n_signal,
                base_url,
                token,
                state_store,
                last_error,
                secure_store_bootstrap_ready,
                is_server_admin,
                theme,
                system_theme_is_night,
                ConnectionEffects {
                    state: ConnectionEffectState {
                        runtime: connection_runtime,
                        secure_store_bootstrap_ready,
                        session_generation,
                        authentication_active: route_owns_authentication(&route),
                    }
                }
                if matches!(auth_surface, AuthSurface::AppShell) {
                AccountRecoveryEffects {
                    account_recovery_configured,
                    account_recovery_detection_key_seen,
                    account_recovery_retry_attempt,
                    last_error,
                    token,
                    principal_id,
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
                        principal_id,
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
                        principal_id,
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
                        principal_id,
                        device_id,
                        server_description,
                        sync_bootstrap_complete,
                        sync_cursor,
                        realm_live_epoch,
                        mls_admission_reconcile_in_flight,
                        mls_admission_reconcile_pending,
                        last_error,
                        mls_admission_diag_last,
                        selected_realm_id,
                        device_queue,
                        mls_welcome_bootstrap_key_seen,
                        crypto_state,
                        needs_mls_backup,
                    }
                }
                ShellEffects {
                    state: ShellEffectState {
                        account_primary_handle,
                        principal_id,
                        token,
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
                        did_resolution_health,
                    }
                }
                SidecarFoldEvidenceEffects {
                    state: SidecarFoldEvidenceEffectState { principal_id }
                }
                SyncEffects {
                    sync_generation,
                    sync_engine_active_generation,
                    realm_events_engine_active_key,
                    signal_receive_engine_active_generation,
                    websocket_rail_active_generation,
                    sync_bootstrap_complete,
                    token,
                    principal_id,
                    device_id,
                    selected_realm_id,
                    realm_events_route_enabled,
                    realm_live_epoch,
                    profiles: profiles_signal,
                }
                }
                SecureStoreEffects {
                    state: SecureStoreEffectState {
                        config_store,
                        principal_id,
                        device_id,
                        secure_store_bootstrap_ready,
                        token,
                    }
                }
                style { "{DXC_THEME}" }
                style { "{DXC_BUTTON_STYLE}" }
                style { "{BASE_STYLE}" }
                style { "{COMPONENT_STYLE}" }
                style { "{FEATURE_STYLE}" }
                style { "{ADAPTIVE_STYLE}" }
                document::Title { "{document_title}" }
                SessionSurface {
                    is_app_shell: matches!(auth_surface, AuthSurface::AppShell),
                    auth_shell: auth_shell_node,
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
                // G3.Y3) and the circle-error queue (fed by
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
                crate::components::AgentRuntimeApprovalPrompt {
                    token,
                    principal_id,
                    server_description,
                }
                crate::components::RecoveryKeySetupPrompt {
                    token,
                    principal_id,
                    device_id,
                    open: recovery_key_setup_prompt,
                    account_primary_handle,
                    on_server_configured: move |_| {
                        account_recovery_configured.set(Some(true));
                        // Invalidate any pre-publication policy read. Its
                        // completion is generation-fenced in recovery_effects,
                        // and this schedules a fresh authoritative read.
                        account_recovery_detection_key_seen.set(None);
                    },
                }
                if show_recovery_setup_prompt {
                    div {
                        class: "event recovery-setup-banner",
                        "data-testid": "recovery-setup-banner",
                        role: "region",
                        "aria-label": crate::i18n::tr("app.recovery.incomplete_title"),
                        div { class: "event-head",
                            strong { {crate::i18n::tr("app.recovery.incomplete_title")} }
                            span { class: "muted", "first-time setup" }
                        }
                        div { class: "muted",
                            {crate::i18n::tr("app.recovery.incomplete_body")}
                        }
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "recovery-setup-open-recovery",
                                onclick: move |_| recovery_key_setup_prompt.set(true),
                                UiIcon { name: "key" }
                                {crate::i18n::tr("app.recovery.configure")}
                            }
                            Link {
                                class: "secondary",
                                "data-testid": "recovery-setup-open-encryption",
                                to: Route::SettingsSection {
                                    section: "encryption".to_owned(),
                                    filter: String::new(),
                                },
                                UiIcon { name: "lock" }
                                {crate::i18n::tr("app.recovery.history_status")}
                            }
                        }
                        div { class: "muted",
                            {crate::i18n::tr("app.recovery.history_status_body")}
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
                        actor_id: principal_id,
                    }
                }
                // Step 3 of the account-MLS-secret auto-unlock flow: a
                // recovery-passphrase banner that restores encrypted history on
                // a fresh device. Renders nothing unless boot detection flagged
                // `needs_mls_unlock`.
                if active_prompt == AccountHealthPrompt::MlsUnlock
                    && !recovery_key_setup_prompt()
                {
                    crate::components::MlsUnlockPrompt {
                        token,
                        actor_id: principal_id,
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
                        title: if mobile_nav_open() { crate::i18n::tr("app.nav.close_menu") } else { crate::i18n::tr("app.nav.open_menu") },
                        "aria-label": if mobile_nav_open() { crate::i18n::tr("app.nav.close_menu") } else { crate::i18n::tr("app.nav.open_menu") },
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
                            state_store.write().save_plain_local_data("theme", next.clone());
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
                }
                MobileNavDrawer {
                    mobile_nav_open,
                    status: mobile_status,
                    realm_tree: mobile_realm_tree,
                }
                aside { class: "sidebar", "data-testid": "sidebar", role: "navigation", "aria-label": crate::i18n::tr("app.nav.main_navigation"),
                    div {
                        class: "sidebar-resize-handle",
                        "data-testid": "sidebar-resize-handle",
                        title: crate::i18n::tr("app.nav.resize_menu"),
                        "aria-hidden": "true",
                        onmousedown: move |event| {
                            event.prevent_default();
                            sidebar_resizing.set(true);
                        },
                    }
                    div { class: "sidebar-header",
                        Link { class: "brand", to: Route::Dashboard, "aria-label": crate::i18n::tr("app.brand.home"),
                            span { class: "logo", "⌘" }
                            span { class: "product-meta",
                                span { class: "product-name", "Inkson | Arkret" }
                            }
                        }
                    }

                    ServerSwitcher {
                        server_menu_open,
                        server_menu_is_open,
                        account_menu_open,
                        sidebar_collapsed: sidebar_is_collapsed,
                        active_server_label: active_server_label.clone(),
                        server_options: server_options.clone(),
                        base_url,
                        on_select: move |option_url| switch_server_and_connect(
                            option_url,
                            server_switch_context.clone(),
                        ),
                    }

                    div { class: "sidebar-nav-group",
                        Link { class: "sidebar-nav-item", to: Route::Dashboard,
                            span { class: "sidebar-nav-icon", UiIcon { name: "home" } }
                            span { class: "grow", {crate::i18n::tr("nav.dashboard")} }
                        }
                    }

                    div { class: "sidebar-nav-group realm-tab-group", "data-testid": "realm-tree-list",
                        if has_session && state_store.read().sync_realm_list_after().is_some() {
                            button {
                                class: "sidebar-toolbar-action",
                                "data-testid": "realm-list-load-more",
                                onclick: move |_| state_store.write().request_next_sync_realm_list_page(),
                                {crate::i18n::tr("directory.load_more_realms")}
                            }
                        }
                        if !sidebar_is_collapsed {
                            div { class: "sidebar-scope-toggle realm-tabs", "data-testid": "realm-sidebar-mode-toggle", role: "tablist", "aria-label": crate::i18n::tr("app.nav.scope_toggle"),
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
                                                state_store,
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
                                                        state_store,
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
                                        title: crate::i18n::tr("setup.new_realm"),
                                        "aria-label": crate::i18n::tr("setup.new_realm"),
                                        to: Route::SetupSection { section: "realms".to_owned() },
                                        UiIcon { name: "plus" }
                                    }
                                } else {
                                    Link {
                                        class: "sidebar-toolbar-action sidebar-toolbar-link add-contact-cta",
                                        "data-testid": "sidebar-new-contact-cta",
                                        title: crate::i18n::tr("contacts.empty_add"),
                                        "aria-label": crate::i18n::tr("contacts.empty_add"),
                                        to: Route::Contacts,
                                        UiIcon { name: "user-plus" }
                                    }
                                }
                                SidebarManageHomeLink {
                                    direct: realm_sidebar_tab() == "direct",
                                    active: if realm_sidebar_tab() == "direct" {
                                        matches!(content_route, Route::ContactsManage)
                                    } else {
                                        matches!(content_route, Route::RealmsManage | Route::PrincipalControl)
                                    },
                                    on_open_contacts: {
                                        let base = base_url();
                                        move |_| {
                                            if direct_contacts_loaded() || token().trim().is_empty() {
                                                return;
                                            }
                                            load_direct_contacts_and_agents_for_sidebar(
                                                base.clone(),
                                                token(),
                                                state_store,
                                                direct_contact_rows,
                                                direct_contacts_loaded,
                                                own_agent_rows,
                                                own_agents_loaded,
                                            );
                                        }
                                    },
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
                                    &[
                                        crate::app::principal_id_text(&principal_id()),
                                        &actor_display_label(
                                            &state_store.read(),
                                            crate::app::principal_id_text(&principal_id()),
                                        ),
                                        &account_primary_handle(),
                                    ],
                                ))
                            {
                                {
                                    let active_principal_id = crate::app::principal_id_owned(principal_id());
                                    let self_principal_id = if active_principal_id.trim().is_empty() {
                                        let configured = config_store
                                            .read()
                                            .load()
                                            .active_account
                                            .map(|account| account.principal_id().to_string())
                                            .unwrap_or_default();
                                        if configured.trim().is_empty() {
                                            state_store
                                                .read()
                                                .session_grant()
                                                .map(|grant| grant.account_id.principal_id.to_string())
                                                .unwrap_or_default()
                                        } else {
                                            configured
                                        }
                                    } else {
                                        active_principal_id
                                    };
                                    let primary_handle = account_primary_handle();
                                    let self_label = if primary_handle.trim().is_empty() {
                                        actor_display_label(&state_store.read(), &self_principal_id)
                                    } else {
                                        primary_handle
                                    };
                                    let self_agents_button_label = if own_agents_expanded() {
                                        crate::i18n::tr("app.sidebar.hide_own_agents")
                                    } else {
                                        crate::i18n::tr("app.sidebar.show_own_agents")
                                    };
                                    rsx! {
                                        div {
                                            class: "contact-sidebar-group is-self",
                                            "data-testid": "contact-sidebar-self-group",
                                            button {
                                                class: "sidebar-nav-item contact-sidebar-row contact-sidebar-user-row",
                                                r#type: "button",
                                                "data-testid": "contact-sidebar-self-row",
                                                "data-peer": "{self_principal_id}",
                                                "aria-expanded": if own_agents_expanded() { "true" } else { "false" },
                                                "aria-label": "{self_agents_button_label}",
                                                title: "{self_agents_button_label}",
                                                onclick: move |_| own_agents_expanded.toggle(),
                                                span { class: "sidebar-nav-icon contact-sidebar-user-avatar",
                                                    crate::components::IdentityAvatar {
                                                        seed: self_principal_id.clone(),
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
                                                            let controller_principal_id = self_principal_id.clone();
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
                                                                    "data-controller": "{controller_principal_id}",
                                                                    "data-opening": if is_opening { "true" } else { "false" },
                                                                    "aria-busy": if is_opening { "true" } else { "false" },
                                                                    "aria-label": "{agent_button_label}",
                                                                    title: "{agent_button_label}",
                                                                    disabled: chat_open_blocked,
                                                                    onclick: {
                                                                        let base = base_url();
                                                                        let agent_id = agent_id.clone();
                                                                        let controller_principal_id = controller_principal_id.clone();
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
                                                                            let controller_principal_id = controller_principal_id.clone();
                                                                            direct_open::open_direct_conversation(
                                                                                base,
                                                                                api_token,
                                                                                state_store,
                                                                                navigator,
                                                                                direct_chat_opening,
                                                                                direct_open::DirectConversationTarget::OwnedAgent {
                                                                                    agent_id,
                                                                                    controller_principal_id,
                                                                                },
                                                                            );
                                                                        }
                                                                    },
                                                                    crate::components::AgentIdentity { agent_id: agent_id.clone(), label: agent_label.clone(), avatar_blob_ref: Some(avatar_blob_ref), is_opening }
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
                                    span { class: "grow truncate", {crate::i18n::tr("manage.contacts_no_results")} }
                                }
                            } else {
                                for contact in filtered_direct_contact_rows.iter() {
                                    {
                                        let peer_principal = crate::models::contact_peer_id(contact).to_string();
                                        let peer = contact.peer.contact_actor_id().to_string();
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
                                        let can_edit_contact_remark =
                                            contact.state == arkret_sdk::ContactState::Accepted
                                                && matches!(
                                                    &contact.peer,
                                                    arkret_sdk::contact_operations::ContactPeer::Human { .. }
                                                );
                                        let contact_remark =
                                            contact_remarks_for_sidebar.get(&peer_principal).cloned();
                                        let display_name = crate::views::helpers::contact_peer_label(&state_store.read(), contact);
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
                                            crate::i18n::tr("app.sidebar.opening")
                                        } else {
                                            state_label.clone()
                                        };
                                                                            let has_contact_remark = contact_remark
                                            .as_ref()
                                            .is_some_and(|remark| !remark.petname.trim().is_empty());
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
                                        let contact_agent_count = contact.contact_agent_projections.len();
                                        let contact_agents_expanded = expanded_contact_agents.read().contains(&peer);
                                        let show_contact_agents = contact_agents_expanded
                                            || (!direct_sidebar_query_value.is_empty()
                                            && contact.contact_agent_projections.iter().any(|agent| {
                                                    sidebar_text_matches_query(
                                                        &direct_sidebar_query_value,
                                                        &[
                                                            agent.actor_id.signing_principal_id().as_str(),
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
                                                            direct_open::open_direct_conversation(
                                                                base,
                                                                api_token,
                                                                state_store,
                                                                navigator,
                                                                direct_chat_opening,
                                                                direct_open::DirectConversationTarget::Peer { peer_id: peer_for_task },
                                                            );
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
                                                            title: crate::i18n::tr("app.sidebar.remark_title"),
                                                            {crate::i18n::tr("app.sidebar.remark")}
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
                                                        span { class: "pill muted xs", title: "{scopes_label}", {crate::i18n::tr("app.sidebar.direct_badge")} }
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
                                                            {crate::i18n::tr_args(
                                                                "app.sidebar.agent_count",
                                                                &[("count", contact_agent_count.to_string())],
                                                            )}
                                                        }
                                                    }
                                                }
                                                div {
                                                    class: if contact_menu_is_open { "sidebar-row-menu-host is-open" } else { "sidebar-row-menu-host" },
                                                    button {
                                                        class: "sidebar-row-menu-button",
                                                        r#type: "button",
                                                        "data-testid": "direct-conversation-row-menu-button",
                                                        title: crate::i18n::tr("app.sidebar.contact_actions"),
                                                        "aria-label": crate::i18n::tr("app.sidebar.contact_actions"),
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
                                                            "aria-label": crate::i18n::tr("app.sidebar.close_row_actions"),
                                                            onclick: move |_| sidebar_row_menu_open.set(None),
                                                        }
                                                        div {
                                                            class: "sidebar-row-menu-panel",
                                                            role: "menu",
                                                            "aria-label": crate::i18n::tr("app.sidebar.contact_actions"),
                                                            if can_edit_contact_remark {
                                                            button {
                                                                class: "sidebar-row-menu-item",
                                                                r#type: "button",
                                                                role: "menuitem",
                                                                "data-testid": "direct-conversation-row-pin-action",
                                                                title: "{pin_contact_label}",
                                                                "aria-label": "{pin_contact_label}",
                                                                onclick: {
                                                                    let peer = peer_principal.clone();
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
                                                            }
                                                            button {
                                                                class: "sidebar-row-menu-item danger",
                                                                r#type: "button",
                                                                role: "menuitem",
                                                                "data-testid": "direct-conversation-row-delete-action",
                                                                title: crate::i18n::tr("app.sidebar.delete_contact"),
                                                                "aria-label": crate::i18n::tr("app.sidebar.delete_contact"),
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
                                                                span { {crate::i18n::tr("common.delete")} }
                                                            }
                                                        }
                                                    }
                                                }
                                              }
                                              if show_contact_agents {
                                                div { class: "contact-agent-list", "data-testid": "contact-sidebar-contact-agents",
                                        for agent in contact.contact_agent_projections.iter() {
                                                    {
                                                        let agent_id = agent.actor_id.to_string();
                                                        let agent_label = agent.display_name.clone()
                                                            .or_else(|| agent.agent_slug.clone())
                                                            .unwrap_or_else(|| short_protocol_id(&agent_id));
                                                        let agent_direct = agent.direct_conversation.clone();
                                                        let avatar_blob_ref = agent
                                                            .avatar_blob_ref
                                                            .as_ref()
                                                            .map(ToString::to_string)
                                                            .unwrap_or_default();
                                                        let controller = match &contact.peer {
                                                            arkret_sdk::contact_operations::ContactPeer::Human { account_id } => serde_json::to_string(account_id),
                                                            arkret_sdk::contact_operations::ContactPeer::Agent { controller_account_id, .. } => serde_json::to_string(controller_account_id),
                                                        }.unwrap_or_default();
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
                                                                    let controller = controller.clone();
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
                                                                        let controller = controller.clone();
                                                                        direct_open::open_direct_conversation(
                                                                            base,
                                                                            api_token,
                                                                            state_store,
                                                                            navigator,
                                                                            direct_chat_opening,
                                                                            direct_open::DirectConversationTarget::ContactAgent { agent_id, controller },
                                                                        );
                                                                    }
                                                                },
                                                                crate::components::AgentIdentity { agent_id: agent_id.clone(), label: agent_label.clone(), avatar_blob_ref: Some(avatar_blob_ref), is_opening }
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
                                            let is_encrypted = crate::views::helpers::realm_mls_activation(
                                                    current_product_view.as_ref(),
                                                    &item_node.id,
                                                )
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
                                            title: crate::i18n::tr("app.sidebar.remark_title"),
                                            {crate::i18n::tr("app.sidebar.remark")}
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
                                                    title: crate::i18n::tr("friendly.realm.description"),
                                                    {crate::i18n::tr("friendly.realm")}
                                                }
                                            },
                                            RealmTreeNodeKind::Space => rsx! {
                                                span {
                                                    class: "pill muted xs",
                                                    "data-testid": "realm-tree-kind-space",
                                                    title: crate::i18n::tr("friendly.space.description"),
                                                    {crate::i18n::tr("friendly.space")}
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
                                                            crate::app::principal_id_owned(principal_id()),
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
                                            "aria-label": crate::i18n::tr("app.sidebar.close_row_actions"),
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
                                                span { {crate::i18n::tr("setup.space.new_space")} }
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
                                                    title: crate::i18n::tr("route.circles"),
                                                    "aria-label": crate::i18n::tr("route.circles"),
                                                    to: Route::Circles { realm_id: target_realm_id.clone() },
                                                    onclick: {
                                                        let home_realm_id = target_realm_id.clone();
                                                        move |_| {
                                                            selected_realm_id.set(home_realm_id.clone());
                                                            sidebar_row_menu_open.set(None);
                                                        }
                                                    },
                                                    UiIcon { name: "users" }
                                                    span { {crate::i18n::tr("route.circles")} }
                                                }
                                                button {
                                                    class: "sidebar-row-menu-item danger",
                                                    r#type: "button",
                                                    role: "menuitem",
                                                    "data-testid": "realm-tree-row-leave-action",
                                                    title: crate::i18n::tr("realm_admin.leave_confirm_button"),
                                                    "aria-label": crate::i18n::tr("realm_admin.leave_confirm_button"),
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
                                                                crate::app::principal_id_owned(principal_id()),
                                                                state_store,
                                                                realm_tree_nodes,
                                                                selected_realm_id,
                                                                sync_cursor,
                                                            );
                                                            sidebar_row_menu_open.set(None);
                                                        }
                                                    },
                                                    UiIcon { name: "x" }
                                                    span { {crate::i18n::tr("realm_admin.leave_realm")} }
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

                main { class: "main realm", "data-testid": "main-view", role: "main", "aria-label": crate::i18n::tr("app.main_content"),
                    div { class: "topbar realm-header",
                        div { class: "topbar-left",
                            Button {
                                variant: ButtonVariant::Ghost,
                                size: ButtonSize::Sm,
                                class: "btn icon sidebar-collapse-toggle",
                                "data-testid": "sidebar-collapse-toggle",
                                title: if sidebar_is_collapsed { crate::i18n::tr("app.nav.show_navigation") } else { crate::i18n::tr("app.nav.hide_navigation") },
                                "aria-label": if sidebar_is_collapsed { crate::i18n::tr("app.nav.show_navigation") } else { crate::i18n::tr("app.nav.hide_navigation") },
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
                                    crate::components::mls_creator_retry::CreatorMlsRetry {
                                        realm_id: active_realm_id.clone(),
                                        refresh_hint: last_error().unwrap_or_default(),
                                        token,
                                    }
                                }
                                if route_uses_realm_context && !active_realm_id.is_empty() {
                                    {
                                        let (current_surface_label, current_surface_icon) = match resolved_realm_surface {
                                            Some(surface) => {
                                                (surface.short_label().to_owned(), surface.icon_name())
                                            }
                                            None if realm_members_active => {
                                                (crate::i18n::tr("realm_admin.members"), "users")
                                            }
                                            None => (crate::i18n::tr("nav.settings"), "settings"),
                                        };
                                        rsx! {
                                            span {
                                                class: "topbar-current-surface",
                                                "data-testid": "current-realm-surface",
                                                title: crate::i18n::tr_args(
                                                    "app.topbar.current_view",
                                                    &[("surface", current_surface_label.clone())],
                                                ),
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
                                principal_id: crate::app::principal_id_owned(principal_id()),
                                members_active: realm_members_active,
                                board_ready,
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
                                {crate::i18n::tr("app.topbar.open_global_search")}
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
                                    state_store.write().save_plain_local_data(
                                        "theme",
                                        next.clone(),
                                    );
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
                            // opened the Realm bootstrap flow.
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
                                        seed: principal_id_value.clone(),
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
                                                seed: principal_id_value.clone(),
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
                                                title: crate::i18n::tr("nav.settings"),
                                                "aria-label": crate::i18n::tr("app.account.open_settings"),
                                                to: Route::Settings,
                                                onclick: move |_| account_menu_open.set(false),
                                                UiIcon { name: "qr-code" }
                                            }
                                        }
                                        div { class: "account-menu__rows",
                                            div { class: "account-menu__row",
                                                strong { {crate::i18n::tr("app.account.did")} }
                                                div { class: "account-menu__value",
                                                    span { class: "mono", "data-testid": "account-menu-did", title: "{principal_id_value}", "{principal_id_label}" }
                                                    Button {
                                                        variant: ButtonVariant::Ghost,
                                                        size: ButtonSize::Sm,
                                                        class: "btn icon account-menu__copy",
                                                        "data-testid": "account-menu-copy-did",
                                                        title: crate::i18n::tr("settings.account.copy_did"),
                                                        "aria-label": crate::i18n::tr("settings.account.copy_did"),
                                                        onclick: {
                                                            let value = principal_id_value.clone();
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
                                                strong { {crate::i18n::tr("settings.account.handles")} }
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
                                                        title: crate::i18n::tr("settings.account.copy_handles"),
                                                        "aria-label": crate::i18n::tr("settings.account.copy_handles"),
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
                                                strong { {crate::i18n::tr("settings.devices.column_device")} }
                                                div { class: "account-menu__value",
                                                    div { class: "account-menu__device-text",
                                                        span {
                                                            class: "account-menu__device-name",
                                                            "data-testid": "account-menu-device-name",
                                                            if device_display_name.trim().is_empty() { {crate::i18n::tr("settings.devices.this_device")} } else { "{device_display_name}" }
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
                                                        title: crate::i18n::tr("settings.account.copy_device_id"),
                                                        "aria-label": crate::i18n::tr("settings.account.copy_device_id"),
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
                                                strong { {crate::i18n::tr("app.account.server")} }
                                                span { "{active_server_label}" }
                                            }
                                        }
                                        div { class: "account-menu__actions",
                                            Button {
                                                variant: ButtonVariant::Ghost,
                                                size: ButtonSize::Sm,
                                                class: "btn",
                                                "data-testid": "account-menu-session-refresh",
                                                "aria-label": crate::i18n::tr("app.account.refresh_session"),
                                                disabled: !has_session,
                                                onclick: {
                                                    let base = base_url();
                                                    let refresh_context = manual_refresh_context.clone();
                                                    move |_| refresh_current_session(
                                                        base.clone(),
                                                        refresh_context.clone(),
                                                    )
                                                },
                                                {crate::i18n::tr("common.refresh")}
                                            }
                                            Button {
                                                variant: ButtonVariant::Ghost,
                                                size: ButtonSize::Sm,
                                                class: "btn",
                                                "data-testid": "account-menu-session-logout",
                                                "aria-label": crate::i18n::tr("app.account.log_out"),
                                                disabled: !has_session,
                                                onclick: move |_| {
                                                    let base = base_url();
                                                    let Some(active) = active_account.peek().clone() else {
                                                        last_error.set(Some(
                                                            "active account context is unavailable"
                                                                .to_owned(),
                                                        ));
                                                        return;
                                                    };
                                                    // ActiveAccountContext is the authenticated identity
                                                    // aggregate. The derived display signals can lag one
                                                    // render behind a restored session, but logout must not
                                                    // turn into a no-op when the authoritative account is
                                                    // already present.
                                                    let actor = active.principal_id().clone();
                                                    let device = active.device_id.to_string();
                                                    let api_token = token();
                                                    // Capture the grant + grant-binding key BEFORE the
                                                    // local wipe below: hard logout MUST also terminate
                                                    // the private authentication session (revoke grant + finish
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
                                                    // (`pending_logout::execute_pending_logout`) retries the server-side
                                                    // termination so the rotation chain can't outlive the
                                                    // "logout". The record stashes the device seed (the live
                                                    // key is wiped below) purely to mint the revoke DPoP
                                                    // proof; it is cleared once coauth confirms the grant is
                                                    // gone (account-lifecycle §4.1).
                                                    let pending_logout =
                                                        crate::pending_logout::PendingLogout {
                                                            authority: active.authority.clone(),
                                                            device_id: active.device_id.clone(),
                                                            grant_jwt: logout_grant
                                                                .as_ref()
                                                                .map(|grant| grant.grant_jwt.clone()),
                                                            device_seed_b64: logout_device_handle
                                                                .as_ref()
                                                                .map(|handle| handle.seed_b64().to_string()),
                                                            device_jkt: logout_device_handle
                                                                .as_ref()
                                                                .map(|handle| handle.jkt().to_owned()),
                                                            station_url: logout_grant
                                                                .as_ref()
                                                                .map(|grant| grant.station_url.clone()),
                                                            // T1.Y4 — re-resolved at
                                                            // logout time from the
                                                            // Station's
                                                            // describe.auth_metadata.
                                                            gate_account_base_url: None,
                                                            base_url: active.server_url.clone(),
                                                            session_credential: api_token.clone(),
                                                            principal_id: actor.clone(),
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
                                                    let _ = crate::identity::account_auth::clear_all_persisted_oidc_scaffolds();
                                                    // Wipe the in-memory UI signals too so the
                                                    // sidebar can't paint a frame of stale
                                                    // Realm tree updates between this click and the
                                                    // navigator.push(Login).
                                                    realm_tree_nodes.set(Vec::new());
                                                    projection_events.set(Vec::new());
                                                    sync_cursor.set(String::new());
                                                    selected_realm_id.set(String::new());
                                                    device_queue.set(0);
                                                    account_primary_handle.set(String::new());
                                                    personal_handles.set(Vec::new());
                                                    personal_handles_status.set("Not published".to_owned());
                                                    personal_handles_lookup_key.set(String::new());
                                                    last_error.set(None);
                                                    token.set(String::new());
                                                    if let Some(account) = SessionContext::get().active_account.peek().as_ref() {
                                                        crate::config::clear_session_credential_secret(account);
                                                    }
                                                    persist_config(
                                                        config_store,
                                                        base.clone(),
                                                        Some(actor.clone()),
                                                        device.clone(),
                                                        String::new(),
                                                    );
                                                    transition_session_boot_state(
                                                        session_boot_state,
                                                        SessionBootState::Unauthenticated,
                                                        "user logged out",
                                                    );
                                                    // Bump the SyncEngine generation so any
                                                    // in-flight long-poll exits on its next
                                                    // iteration check instead of applying a
                                                    // response after the wipe.
                                                    // Read before taking the mutable signal borrow.
                                                    // `set(sync_generation() + 1)` evaluates the
                                                    // mutable receiver first and traps in wasm when
                                                    // the nested read tries to borrow the same
                                                    // Dioxus signal.
                                                    let next_sync_generation = sync_generation() + 1;
                                                    sync_generation.set(next_sync_generation);
                                                    account_menu_open.set(false);
                                                    redirect_to_login(navigator);
                                                    let logout_effects =
                                                        runtime_services.effects.clone();
                                                    // The session effects may still hold a read
                                                    // borrow on the shared DID cache when the click
                                                    // arrives, and a root task cannot safely retain
                                                    // that component Signal after navigation. The
                                                    // next authenticated bootstrap clears the cache
                                                    // before resolving any DID (connect.rs); the
                                                    // unauthenticated surface cannot consume it.
                                                    // Keep the detached task signal-free and use it
                                                    // only to finish the durable server logout.
                                                    dioxus::core::spawn_forever(async move {
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
                                                        let _ = outcome;
                                                    });
                                                },
                                                {crate::i18n::tr("app.account.log_out")}
                                            }
                                            Link {
                                                class: "btn sm",
                                                "data-testid": "account-menu-settings",
                                                to: Route::Settings,
                                                onclick: move |_| account_menu_open.set(false),
                                                UiIcon { name: "settings" }
                                                {crate::i18n::tr("nav.settings")}
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
                            principal_id,
                            device_id,
                            token,
                            account_recovery_configured,
                            config_store,
                            account_primary_handle,
                            personal_handles,
                            personal_handles_status,
                            realm_tree_nodes,
                            device_queue,
                            frontier_state,
                            sync_cursor,
                            resolved_realm_surface,
                            server_description,
                            event_write_ready,
                            active_service_id: active_service_id.clone(),
                            active_realm_id: active_realm_id.clone(),
                            active_projection_realm_id: active_projection_realm_id.clone(),
                            realm_live_epoch,
                            has_session,
                            personal_control_realm_id: personal_control_realm_id.clone(),
                            routed_control_realm_id: routed_control_realm_id.clone(),
                            manage_realm_rows: manage_realm_rows.clone(),
                            realm_manage_query,
                            direct_contact_rows,
                            direct_contacts_loaded,
                            contact_manage_query,
                            secure_store_bootstrap_ready,
                            needs_device_authorization,
                            device_authorization_check_complete,
                            push_state,
                            locale,
                            theme,
                            base_url,
                        }
                    }
                }
                NotificationsDrawer {
                    open: notifications_drawer_open,
                    principal_id: active_account()
                        .map(|account| account.principal_id().to_string())
                        .unwrap_or_default(),
                    device_id: device_id(),
                    token,
                }
                // A6.4 — shortcut help overlay; toggled by the `?` global
                // key handler on the shell div above.
                crate::components::shortcut_help::ShortcutHelpOverlay {
                    visible: shortcut_help_open,
                }
            }
                }
        }
    }
}

#[cfg(test)]
#[path = "../app_tests.rs"]
mod tests;
