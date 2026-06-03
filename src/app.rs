use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};

use dioxus::prelude::*;
use dioxus_router::hooks::*;
use dioxus_router::{Link, Navigator, Router};
use serde_json::Value;

use crate::api::{CokretApi, is_auth_expired_error};
use crate::components::{SecurityStateBadge, UiIcon};
use crate::config::{
    ClientConfig, LocalConfigStore, is_valid_device_id, normalize_device_id, normalize_server_url,
};
use crate::conformance::{
    PROFILE_E2EE_CLIENT, PROFILE_FULL_CLIENT, PROFILE_KANBAN_MVP, PROFILE_MINIMAL_CLIENT,
    PROFILE_PUSH_GATEWAY, profile_ready,
};
use crate::i18n::{Locale, TextDirection};
use crate::local_state::{
    ClientLocalState, LocalStateStore, OidcTokenBundle, PersistedSessionGrant,
};
use crate::models::{
    ServerDescription, ServerDescriptionExt, SpacePreview, SpacePreviewKind,
    projection_realm_id_for_known_space,
};
use crate::routes::Route;
// R28-B — space-tree / projection / field-extraction helpers moved to
// `crate::space_tree`. Re-export the two `pub` entry points used by
// `crate::sync_engine` so the existing `crate::app::…` call sites keep
// resolving without a sync_engine edit.
pub(crate) use crate::space_tree::{
    descendant_space_ids, full_sync_projection_keep_set, realm_projection_is_encrypted,
    space_previews_from_sync_spaces, space_tree_items,
};
use crate::views::ConnectionState;
use crate::views::helpers::{persist_config, short_protocol_id};
use crate::views::timeline::TimelineEvent;

const UI_PREFERENCES_SCOPE: &str = "ui.browser";
const SIDEBAR_WIDTH_PREFERENCE_KEY: &str = "layout.sidebar.width";
const SPACE_SCOPE_PREFERENCE_KEY: &str = "layout.space.scope";
const BOOT_ACCESS_TOKEN_SKEW_SECS: i64 = 30;
const DEFAULT_SIDEBAR_WIDTH: f64 = 272.0;
const MIN_SIDEBAR_WIDTH: f64 = 220.0;
const MAX_SIDEBAR_WIDTH: f64 = 420.0;

const STYLE: &str = include_str!("styles/app.css");

const CLAUDE_STYLE: &str = include_str!("styles/claude_design.css");

const CLAUDE_APP_OVERRIDES: &str = include_str!("styles/claude_app_overrides.css");

/// One-shot push-token provider bootstrap.
///
/// Runs once on first App render. On wasm32 we install
/// `WebPushTokenProvider::new()` (drives the service-worker +
/// `pushManager.subscribe` path described in `push.rs::WebPushTokenProvider`).
/// On native builds we install `FcmPushTokenProvider` / `ApnsPushTokenProvider`.
/// The host adapter supplies the actual OS token through
/// `set_fcm_push_token` / `set_apns_push_token` after Firebase/APNs returns
/// it; local dev can inject the same token via env vars. Subsequent renders
/// short-circuit via `OnceLock` semantics inside `set_push_token_provider`.
fn ensure_default_push_token_provider() {
    if crate::push::push_token_provider().is_some() {
        return;
    }
    #[cfg(target_arch = "wasm32")]
    {
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::WebPushTokenProvider::new(),
        ));
    }
    #[cfg(all(not(target_arch = "wasm32"), target_os = "android"))]
    {
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::FcmPushTokenProvider,
        ));
    }
    #[cfg(all(not(target_arch = "wasm32"), target_os = "ios"))]
    {
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::ApnsPushTokenProvider,
        ));
    }
    #[cfg(all(
        not(target_arch = "wasm32"),
        not(target_os = "android"),
        not(target_os = "ios")
    ))]
    {
        // Desktop / server builds: install the FCM provider as the
        // safe default. It reads `YOUGEN_FCM_PUSH_TOKEN`,
        // `FCM_PUSH_TOKEN`, or `CHASK_PUSH_KEY` for local bridge
        // testing, and otherwise reports "no token" without emitting a
        // placeholder to the gateway.
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::FcmPushTokenProvider,
        ));
    }
}

#[component]
pub fn App() -> Element {
    ensure_default_push_token_provider();
    rsx! {
        Router::<Route> {}
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpaceScopeMode {
    Exact,
    IncludeDescendants,
}

impl SpaceScopeMode {
    fn includes_descendants(self) -> bool {
        matches!(self, Self::IncludeDescendants)
    }

    fn label(self) -> &'static str {
        match self {
            Self::Exact => "Current Space only",
            Self::IncludeDescendants => "Current + descendants",
        }
    }

    fn preference_value(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::IncludeDescendants => "descendants",
        }
    }

    fn from_preference(value: &str) -> Self {
        match value {
            "descendants" => Self::IncludeDescendants,
            _ => Self::Exact,
        }
    }
}

fn scoped_space_ids(
    spaces: &[SpacePreview],
    root_space_id: &str,
    scope_mode: SpaceScopeMode,
) -> Vec<String> {
    if root_space_id.trim().is_empty() {
        Vec::new()
    } else if scope_mode.includes_descendants() {
        descendant_space_ids(spaces, root_space_id)
    } else {
        vec![root_space_id.to_owned()]
    }
}

fn browser_prefers_dark_theme() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window()
            .and_then(|window| {
                window
                    .match_media("(prefers-color-scheme: dark)")
                    .ok()
                    .flatten()
            })
            .map(|query| query.matches())
            .unwrap_or(false)
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        false
    }
}

fn browser_shell_color_scheme_is_dark() -> Option<bool> {
    #[cfg(target_arch = "wasm32")]
    {
        let window = web_sys::window()?;
        let document = window.document()?;
        let shell = document
            .query_selector("[data-testid=\"client-shell\"]")
            .ok()
            .flatten()?;
        let styles = window.get_computed_style(&shell).ok().flatten()?;
        let color_scheme = styles
            .get_property_value("color-scheme")
            .ok()?
            .to_ascii_lowercase();
        let has_dark = color_scheme.split_whitespace().any(|token| token == "dark");
        let has_light = color_scheme
            .split_whitespace()
            .any(|token| token == "light");
        if has_dark && !has_light {
            Some(true)
        } else if has_light && !has_dark {
            Some(false)
        } else {
            None
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        None
    }
}

fn theme_renders_as_night(theme: &str, system_theme_is_night: bool) -> bool {
    theme == "night" || (theme == "system" && system_theme_is_night)
}

fn next_manual_theme(theme: &str) -> String {
    let is_night = if theme == "system" {
        browser_shell_color_scheme_is_dark().unwrap_or_else(browser_prefers_dark_theme)
    } else {
        theme == "night"
    };
    if is_night { "light" } else { "night" }.to_owned()
}

fn oidc_access_token_boot_usable(bundle: &OidcTokenBundle, now_unix: i64) -> bool {
    if bundle.access_token.trim().is_empty() {
        return false;
    }
    match bundle.expires_at_unix {
        Some(expires_at) => now_unix + BOOT_ACCESS_TOKEN_SKEW_SECS < expires_at,
        None => true,
    }
}

fn session_grant_access_token_boot_usable(
    grant: &PersistedSessionGrant,
    access_token: &str,
    now_unix: i64,
) -> bool {
    if access_token.trim().is_empty() {
        return false;
    }
    if grant
        .grant_expires_at
        .is_some_and(|expires_at| expires_at.timestamp() <= now_unix)
    {
        return false;
    }
    grant
        .session_expires_at
        .is_some_and(|expires_at| now_unix + BOOT_ACCESS_TOKEN_SKEW_SECS < expires_at.timestamp())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionBootState {
    Checking,
    Restoring,
    Authenticated,
    Unauthenticated,
}

impl SessionBootState {
    fn from_boot_material(session_token: &str, can_restore_session: bool) -> Self {
        if !session_token.trim().is_empty() {
            Self::Checking
        } else if can_restore_session {
            Self::Restoring
        } else {
            Self::Unauthenticated
        }
    }

    fn is_pending(self) -> bool {
        matches!(self, Self::Checking | Self::Restoring)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthSurface {
    AppShell,
    Login,
    Callback,
    Restoring,
}

fn auth_surface_for_route(
    route: &Route,
    has_session: bool,
    boot_state: SessionBootState,
) -> AuthSurface {
    if matches!(route, Route::AuthCallback) {
        AuthSurface::Callback
    } else if has_session {
        AuthSurface::AppShell
    } else if boot_state.is_pending() {
        AuthSurface::Restoring
    } else {
        AuthSurface::Login
    }
}

fn initial_session_token_from_state(
    local_state: &ClientLocalState,
    config: &ClientConfig,
    now_unix: i64,
) -> String {
    if let Some(bundle) = local_state.oidc_tokens.as_ref() {
        // Access tokens are short-lived cache material. On a hard page
        // reload, let the refresh-token/session-grant poller mint a fresh
        // bearer instead of racing boot API calls with an expired one.
        if oidc_access_token_boot_usable(bundle, now_unix) {
            return bundle.access_token.clone();
        }
    }
    if let Some(grant) = local_state.session_grant.as_ref() {
        return if session_grant_access_token_boot_usable(grant, &config.session_token, now_unix) {
            config.session_token.clone()
        } else {
            String::new()
        };
    }
    if local_state.oidc_tokens.is_some() {
        return String::new();
    }
    config.session_token.clone()
}

fn has_bootstrap_refresh_material(
    store: &LocalStateStore,
    principal_server_url: &str,
    actor_did: &str,
) -> bool {
    let state = store.load();
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    if store
        .load_oidc_tokens_with_secure_store(actor_did, secure_store.as_ref())
        .as_ref()
        .is_some_and(crate::oidc::lifecycle::has_refresh_token)
    {
        return true;
    }
    state.session_grant.as_ref().is_some_and(|grant| {
        crate::session_refresh::grant_matches_principal_server(grant, principal_server_url)
            && !crate::session_refresh::grant_is_dead(grant)
    })
}

fn is_local_development_server_url(principal_server_url: &str) -> bool {
    let normalized = normalize_server_url(principal_server_url);
    let Ok(url) = url::Url::parse(&normalized) else {
        return false;
    };
    url.host_str()
        .is_some_and(|host| matches!(host, "local.host" | "localhost" | "127.0.0.1" | "::1"))
}

fn can_attempt_development_session_reissue(
    principal_server_url: &str,
    actor_did: &str,
    device_id: &str,
) -> bool {
    let actor = actor_did.trim();
    let device = device_id.trim();
    !actor.is_empty()
        && actor.starts_with("did:")
        && is_valid_device_id(device)
        && is_local_development_server_url(principal_server_url)
}

fn can_bootstrap_with_development_session_reissue(
    local_state: &ClientLocalState,
    principal_server_url: &str,
    actor_did: &str,
    device_id: &str,
) -> bool {
    let actor = actor_did.trim();
    local_state
        .account_scope_owner
        .as_deref()
        .map(str::trim)
        .is_some_and(|owner| owner == actor)
        && can_attempt_development_session_reissue(principal_server_url, actor, device_id)
}

#[component]
pub fn RouterView() -> Element {
    let initial_config = LocalConfigStore::default().load();
    let initial_state_store = LocalStateStore::default();
    let initial_local_state = initial_state_store.load();
    let initial_session_token = initial_session_token_from_state(
        &initial_local_state,
        &initial_config,
        chrono::Utc::now().timestamp(),
    );
    let initial_can_restore_session = has_bootstrap_refresh_material(
        &initial_state_store,
        &initial_config.server_url,
        &initial_config.account_did,
    );
    let initial_can_reissue_development_session = can_bootstrap_with_development_session_reissue(
        &initial_local_state,
        &initial_config.server_url,
        &initial_config.account_did,
        &initial_config.device_id,
    );
    let initial_session_boot_state = SessionBootState::from_boot_material(
        &initial_session_token,
        initial_can_restore_session || initial_can_reissue_development_session,
    );
    let initial_spaces = space_previews_from_sync_spaces(&initial_local_state.space_projections);
    let initial_sidebar_width = load_sidebar_width_preference(&initial_state_store);
    let initial_space_scope_mode = load_space_scope_preference(&initial_state_store);
    let initial_locale = initial_state_store
        .load_private_data(&initial_config.account_did, "locale")
        .map(|code| Locale::from_code(&code))
        .unwrap_or_default();
    let initial_theme = initial_state_store
        .load_private_data(&initial_config.account_did, "theme")
        .filter(|theme| matches!(theme.as_str(), "light" | "night" | "system"))
        .unwrap_or_else(|| "system".to_owned());
    let config_store = use_signal(LocalConfigStore::default);
    let mut state_store = use_signal(LocalStateStore::default);
    // Move-into-signal initialisers. Each `use_signal(...)` runs once on
    // first render, so we pre-extract the fields and hand each closure a
    // ready-to-move `String` instead of repeatedly cloning the whole
    // `initial_config` struct.
    let initial_server_url = initial_config.server_url.clone();
    let initial_account_did = initial_config.account_did.clone();
    let initial_device_id = initial_config.device_id.clone();
    let base_url = use_signal(move || initial_server_url);
    let mut account_did = use_signal(move || initial_account_did);
    let device_id = use_signal(move || initial_device_id);
    let mut token = use_signal(move || initial_session_token);
    let mut session_boot_state = use_signal(move || initial_session_boot_state);

    // Install the app-wide, single-flight bearer refresher exactly once.
    // Every auth-expired handler (connect, sync, chat send, Realm create,
    // the account-menu button, the background poller) re-mints through
    // this one closure via `crate::session::refresh_current_bearer()`, so
    // refresh policy lives in a single place and concurrent rollovers
    // coalesce instead of racing.
    use_hook(move || {
        crate::session::register_session_refresher(std::rc::Rc::new(move || {
            Box::pin(remint_principal_bearer(
                base_url,
                account_did,
                device_id,
                state_store,
                token,
                config_store,
            )) as crate::session::LocalRefreshFuture
        }));
    });

    let navigator = use_navigator();
    let route = use_route::<Route>();
    let mut view = use_signal(|| route.to_view());
    let mut status = use_signal(|| ConnectionState::Offline.label().to_owned());
    let initial_sync_cursor = initial_local_state
        .sync_cursor
        .clone()
        .unwrap_or_else(|| "-".to_owned());
    let initial_selected_space = initial_spaces
        .first()
        .map(|space| space.space_id.clone())
        .unwrap_or_default();
    let initial_draft = initial_spaces
        .first()
        .and_then(|space| initial_local_state.drafts.get(&space.space_id))
        .cloned()
        .unwrap_or_default();
    let initial_push_state =
        crate::push::push_status_label(initial_local_state.push_registration.as_ref());
    let initial_spaces_for_signal = initial_spaces.clone();
    let mut sync_cursor = use_signal(move || initial_sync_cursor);
    let mut selected_space = use_signal(move || initial_selected_space);
    let mut spaces = use_signal(move || initial_spaces_for_signal);
    let mut timeline = use_signal(Vec::<TimelineEvent>::new);
    let draft = use_signal(move || initial_draft);
    let mut device_queue = use_signal(|| 0usize);
    let push_state = use_signal(move || initial_push_state);
    let frontier_state = use_signal(|| "Not loaded".to_owned());
    let crypto_state = use_signal(|| "No authenticated session".to_owned());
    let network_state = use_signal(|| "offline".to_owned());
    let mut last_error = use_signal(|| Option::<String>::None);
    let server_description = use_signal(|| Option::<ServerDescription>::None);
    let server_probe_status = use_signal(|| "server not probed".to_owned());
    let locale = use_signal(move || initial_locale);
    #[cfg(target_arch = "wasm32")]
    {
        let mut state_store_for_secure_upgrade = state_store;
        use_future(move || async move {
            match crate::secure_key_store::upgrade_wasm_secure_key_store_async("yougen").await {
                Ok(Some(secure_store)) => {
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
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(?error, "IndexedDB secure-key-store upgrade failed");
                }
            }
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
    // `ck.capability.grant` projection events ship, the post-login flow
    // will `engine.write().add_grant(...)` and the kanban Archive /
    // Restore buttons will start gating themselves.
    use_context_provider::<Signal<crate::capability::CapabilityEngine>>(|| {
        Signal::new(crate::capability::CapabilityEngine::new())
    });
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
    let mut mobile_nav_open = use_signal(|| false);
    let mut mobile_space_query = use_signal(String::new);
    let mut sidebar_collapsed = use_signal(|| false);
    let mut sidebar_width = use_signal(move || initial_sidebar_width);
    let mut sidebar_resizing = use_signal(|| false);
    let mut server_menu_open = use_signal(|| false);
    let mut account_menu_open = use_signal(|| false);
    let mut account_session_state = use_signal(|| "Session idle".to_owned());
    let mut global_query = use_signal(String::new);
    let mut palette_open = use_signal(|| false);
    let mut topbar_search_expanded = use_signal(|| false);
    let mut sync_bootstrap_complete = use_signal(|| false);
    // A6.4 — `?` keyboard shortcut help overlay state.
    let mut shortcut_help_open = use_signal(|| false);
    let mut space_scope_mode = use_signal(move || initial_space_scope_mode);
    let mls_welcome_bootstrap_key_seen = use_signal(|| Option::<String>::None);
    // Step 3 of the account-MLS-secret auto-unlock flow: set by the bootstrap
    // effect when this device has no local account secret yet but the server
    // holds an `mls_account_secret` backup; consumed by `MlsUnlockPrompt`.
    let needs_mls_unlock = use_signal(|| false);
    // Mirror of `needs_mls_unlock` (task X3): set by the detection effects when
    // this account has used encryption (a local account MLS secret exists) but
    // the server holds NO `mls_account_secret` backup yet — so a fresh browser
    // would lose history. Consumed by `MlsBackupPrompt`. Mutually exclusive
    // with `needs_mls_unlock`: restore (unlock) always wins.
    let needs_mls_backup = use_signal(|| false);
    // X11.2 — expose `needs_mls_backup` via context so deep encrypted-write
    // success paths (kanban card detail update, chat secure send) can flip the
    // backup prompt on directly, WITHOUT relying on the fragile boot-time
    // detection effect (X11). See `maybe_flag_mls_backup_after_encrypted_write`.
    use_context_provider(|| crate::components::MlsBackupSignal(needs_mls_backup));
    let mls_restore_payload_cache = use_signal(|| Option::<Value>::None);
    let mls_unlock_detection_key_seen = use_signal(|| Option::<String>::None);

    // On first render with a live session, fetch the directory + sync so
    // the sidebar's Space list shows up after a page reload. The list
    // intentionally isn't persisted in localStorage — directory search
    // results live only in the in-memory `spaces` signal, so without
    // this kick we'd render "No spaces loaded" until the user clicks
    // Refresh.
    //
    // The flag is consumed only after we confirm base+session are both
    // populated. Otherwise a fresh user who lands without a session and
    // then signs in (on the same mount) would never auto-connect, since
    // the one-shot would have already been spent during the empty-session
    // first render.
    // Background session-refresh poller. Proactively re-mints the bearer
    // a little before it expires so requests rarely hit a cold 401. The
    // re-mint itself goes through the shared single-flight refresher
    // (`crate::session`), so this poller and any reactive 401-retry can
    // never fire two competing refreshes for the same rollover.
    use_future({
        let mut status = status;
        let mut last_error = last_error;
        let state_store = state_store;
        let account_did = account_did;
        let token = token;
        let mut session_boot_state = session_boot_state;
        move || async move {
            let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
            loop {
                // Freshness gate — only re-mint when the active credential
                // is actually near expiry. We key off *both* signals and
                // refresh if either is due:
                //   * the OIDC access token's own `expires_at` (when the IdP advertised
                //     `expires_in`), and
                //   * the session grant's `session_expires_at`, which tracks the short-lived
                //     principal bearer itself.
                // The grant signal is what saves IdPs that omit
                // `expires_in` (where `due_for_refresh` can never fire) —
                // we still proactively refresh before the principal bearer
                // dies instead of waiting for a cold 401. (Read-only
                // borrow, dropped before any await, so concurrent
                // `state_store.write()` callers never hit
                // `AlreadyBorrowedMut`.)
                let due = {
                    let store = state_store.read();
                    let oidc_due = store
                        .load_oidc_tokens_with_secure_store(&account_did(), secure_store.as_ref())
                        .map(|bundle| crate::oidc::lifecycle::due_for_refresh(&bundle))
                        .unwrap_or(false);
                    let grant_due = matches!(
                        crate::session_refresh::refresh_decision(&store),
                        crate::session_refresh::RefreshDecision::Due
                    );
                    oidc_due || grant_due
                };
                if due {
                    if token().trim().is_empty() {
                        status.set("Restoring session...".to_owned());
                        session_boot_state.set(SessionBootState::Restoring);
                    }
                    match crate::session::refresh_current_bearer().await {
                        Some(_) => {
                            status.set("Online".to_owned());
                            session_boot_state.set(SessionBootState::Authenticated);
                            last_error.set(None);
                        }
                        None => {
                            // Keep the current bearer alive; a reactive 401
                            // (or the login flow) handles a genuinely dead
                            // session. Surface the last issue for dev tools.
                            last_error.set(Some(
                                "background session refresh produced no new bearer".to_owned(),
                            ));
                        }
                    }
                }
                crate::api::sleep_for(std::time::Duration::from_secs(
                    crate::session_refresh::POLL_INTERVAL_SECS,
                ))
                .await;
            }
        }
    });

    // SyncEngine generation counter. Declared up front so the
    // bootstrap connect() can pass it via `ConnectContext`. The engine
    // itself is spawned by the `use_effect` further down.
    let mut sync_generation = use_signal(|| 0u64);

    // CXP-0007 P3B.4.3 — active multi-profile snapshot, threaded into
    // the sync engine context so the loop can detect a profile rotation
    // and exit cleanly. The shell is currently single-profile; the
    // signal stays default-empty until the account switcher writes to
    // it on the first user-driven add-account / switch action.
    let profiles_signal = use_signal(crate::config::MultiProfileConfig::default);

    // Lower-level API helpers cannot directly mutate app signals, but they
    // can receive terminal auth errors (notably `session grant is not
    // active: revoked`) from background pollers. Register one soft-logout
    // hook so those paths can clear the live bearer and stop retry loops.
    {
        let mut invalidator_token = token;
        let mut invalidator_sync_cursor = sync_cursor;
        let mut invalidator_selected_space = selected_space;
        let mut invalidator_spaces = spaces;
        let mut invalidator_timeline = timeline;
        let mut invalidator_device_queue = device_queue;
        let mut invalidator_crypto_state = crypto_state;
        let mut invalidator_status = status;
        let mut invalidator_network_state = network_state;
        let mut invalidator_last_error = last_error;
        let mut invalidator_state_store = state_store;
        let invalidator_config_store = config_store;
        let invalidator_base_url = base_url;
        let invalidator_account_did = account_did;
        let invalidator_device_id = device_id;
        let mut invalidator_sync_generation = sync_generation;
        let invalidator_navigator = navigator;
        use_hook(move || {
            crate::session::register_session_invalidator(move |reason| {
                invalidator_state_store.write().set_session_grant(None);
                invalidator_token.set(String::new());
                persist_config(
                    invalidator_config_store,
                    invalidator_base_url(),
                    invalidator_account_did(),
                    invalidator_device_id(),
                    String::new(),
                );
                invalidator_sync_cursor.set("-".to_owned());
                invalidator_selected_space.set(String::new());
                invalidator_spaces.set(Vec::new());
                invalidator_timeline.set(Vec::new());
                invalidator_device_queue.set(0);
                invalidator_crypto_state.set("Session expired".to_owned());
                invalidator_status.set("Session expired; sign in again".to_owned());
                invalidator_network_state.set("online".to_owned());
                invalidator_last_error.set(Some(reason));
                invalidator_sync_generation.set(invalidator_sync_generation() + 1);
                let _ = invalidator_navigator.push(Route::Login);
            });
        });
    }

    // Single-source-of-truth for the sidebar. Anything that wants to
    // change the visible Space list writes to
    // `state_store.space_projections` (sync engine, connect()'s initial
    // bootstrap, setup's optimistic post-create insert, future
    // push-notification ingestion). This effect derives the `spaces`
    // Signal from those projections so consumers can keep reading
    // `spaces()` as before — but the only path into the data is
    // through the store. Avoids the "stale ghost space" class of bugs
    // where signal writers forgot to also update the projection (or
    // vice versa) and the two slid out of sync.
    use_effect(move || {
        let projections = state_store.read().load().space_projections;
        let next = space_previews_from_sync_spaces(&projections);
        // Perf (P1): this effect re-runs on *any* `state_store` write (drafts,
        // theme, notifications, read receipts, …), not just projection changes.
        // Skip the `set` when the derived list is unchanged so unrelated writes
        // don't cascade a re-render through every `spaces()` consumer (sidebar,
        // command palette, root shell).
        if *spaces.peek() != next {
            spaces.set(next);
        }
    });

    // Bootstrap handshake: on first render with a valid session, run
    // `connect()` exactly once to do the `/server/describe` +
    // `/account/me` probes and the initial server-authoritative full
    // sync. After that, the SyncEngine (below) owns continuous sync.
    let mut bootstrap_pending = use_signal(|| true);
    if bootstrap_pending() {
        let base = base_url();
        let mut session = token();
        if !session.trim().is_empty() {
            let (has_oidc_bundle, stale_for_selected_server) = {
                let store = state_store.read();
                let has_oidc_bundle = store.oidc_tokens().is_some();
                let stale_grant = store
                    .session_grant()
                    .as_ref()
                    .map(|grant| {
                        !crate::session_refresh::grant_matches_principal_server(grant, &base)
                    })
                    .unwrap_or(false);
                (has_oidc_bundle, stale_grant)
            };
            let stale_for_selected_server = !has_oidc_bundle && stale_for_selected_server;
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
        let (can_restore_session, can_reissue_development_session) = {
            let store = state_store.read();
            let state = store.load();
            (
                has_bootstrap_refresh_material(&store, &base, &account_did()),
                can_bootstrap_with_development_session_reissue(
                    &state,
                    &base,
                    &account_did(),
                    &device_id(),
                ),
            )
        };
        if !base.trim().is_empty()
            && (!session.trim().is_empty()
                || can_restore_session
                || can_reissue_development_session)
        {
            bootstrap_pending.set(false);
            sync_bootstrap_complete.set(false);
            session_boot_state.set(SessionBootState::from_boot_material(
                &session,
                can_restore_session || can_reissue_development_session,
            ));
            connect(
                base,
                account_did(),
                device_id(),
                ConnectContext {
                    status,
                    sync_cursor,
                    token,
                    account_did,
                    selected_space,
                    spaces,
                    timeline,
                    device_queue,
                    frontier_state,
                    crypto_state,
                    config_store,
                    state_store,
                    network_state,
                    last_error,
                    server_description,
                    server_probe_status,
                    theme,
                    sync_generation,
                    sync_bootstrap_complete,
                    session_boot_state,
                    navigator,
                },
            );
        } else if !base.trim().is_empty() {
            session_boot_state.set(SessionBootState::Unauthenticated);
        }
    }

    // SyncEngine — long-poll loop that keeps `space_projections` +
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
        let ctx = crate::sync_engine::SyncEngineContext {
            base_url,
            token,
            state_store,
            spaces,
            timeline,
            sync_cursor,
            status,
            network_state,
            last_error,
            device_queue,
            theme,
            account_did,
            selected_space,
            profiles: profiles_signal,
        };
        spawn(async move {
            crate::sync_engine::run_sync_engine(current_gen, sync_generation, ctx).await;
        });
    });

    // D1: detect the account-MLS unlock requirement as soon as a logged-in
    // session finishes bootstrap, without waiting for the user to enter a
    // Space/Board/Document route that runs the per-space Welcome bootstrap.
    {
        let mut seen_detection_key = mls_unlock_detection_key_seen;
        let mut needs_mls_unlock = needs_mls_unlock;
        let mut needs_mls_backup = needs_mls_backup;
        let mut restore_payload_cache = mls_restore_payload_cache;
        let state_store_for_detection = state_store;
        use_effect(move || {
            let base = base_url();
            let session = token();
            let actor = account_did();
            let device = device_id();
            let generation = sync_generation();
            if session.trim().is_empty() {
                needs_mls_unlock.set(false);
                needs_mls_backup.set(false);
                restore_payload_cache.set(None);
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
            let has_local_mls_snapshot =
                !state_store_for_detection.read().mls_snapshots().is_empty();
            let has_local_account_secret = crate::mls::runtime::load_account_mls_secret(
                crate::secure_key_store::default_secure_key_store("yougen").as_ref(),
                &actor,
            )
            .map(|secret| secret.is_some())
            .unwrap_or(false);
            let detection_key = format!(
                "{generation}|{base}|{actor}|{device}|sec={has_local_account_secret}|snap={has_local_mls_snapshot}"
            );
            if seen_detection_key().as_deref() == Some(detection_key.as_str()) {
                return;
            }
            seen_detection_key.set(Some(detection_key));

            spawn(async move {
                match crate::views::helpers::with_authed_api(&base, session, |api| async move {
                    crate::mls::account_recovery::fetch_mls_restore_payload(&api).await
                })
                .await
                {
                    Ok(payload) => {
                        let secure_store =
                            crate::secure_key_store::default_secure_key_store("yougen");
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
                            restore_payload_cache.set(Some(payload));
                            needs_mls_unlock.set(true);
                            needs_mls_backup.set(false);
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
                            needs_mls_backup.set(should_backup);
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

    let routed_space_id = route.space_id().map(str::to_owned);
    let remembered_space_id = selected_space();
    let effective_space_id = routed_space_id.clone().or_else(|| {
        if remembered_space_id.trim().is_empty() {
            None
        } else {
            Some(remembered_space_id.clone())
        }
    });
    let active_space_id = effective_space_id.clone().unwrap_or_default();
    if let Some(route_space_id) = routed_space_id.as_deref()
        && remembered_space_id != route_space_id
    {
        selected_space.set(route_space_id.to_owned());
    }

    let active_server_description = server_description();
    let active_service_did = active_server_description
        .as_ref()
        .map(|description| description.service_did.as_str().to_owned())
        .unwrap_or_default();
    let has_session = !token().trim().is_empty();
    let boot_state = session_boot_state();
    let auth_surface = auth_surface_for_route(&route, has_session, boot_state);
    {
        let redirect_route = route.clone();
        let redirect_navigator = navigator;
        use_effect(move || {
            if matches!(redirect_route, Route::Login) && !token().trim().is_empty() {
                let _ = redirect_navigator.push(Route::Dashboard);
            }
        });
    }
    let active_server_label = normalize_server_url(&base_url());
    let account_did_value = account_did();
    let device_id_value = device_id();
    let account_did_label = short_protocol_id(&account_did_value);
    let device_id_label = short_protocol_id(&device_id_value);
    let account_label = if has_session {
        account_did_label.clone()
    } else {
        "Not signed in".to_owned()
    };
    let account_detail = if has_session {
        format!("device {device_id_label}")
    } else {
        "Refresh server metadata, then sign in".to_owned()
    };
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
    let push_ready = profile_ready(active_server_description.as_ref(), PROFILE_PUSH_GATEWAY);
    let event_write_ready = active_server_description
        .as_ref()
        .map(|description| description.supports_event_envelope_write_plane())
        .unwrap_or(false);
    let route_uses_space_context = route_uses_space_context(&route);
    let context_space_id = if route_uses_space_context {
        effective_space_id.clone()
    } else {
        None
    };
    {
        let bootstrap_route_uses_space_context = route_uses_space_context;
        let bootstrap_context_space_id = context_space_id.clone();
        let mut seen_bootstrap_key = mls_welcome_bootstrap_key_seen;
        let state_store_for_bootstrap = state_store;
        let crypto_state_for_bootstrap = crypto_state;
        let last_error_for_bootstrap = last_error;
        let mut needs_mls_unlock_for_bootstrap = needs_mls_unlock;
        let mut needs_mls_backup_for_bootstrap = needs_mls_backup;
        let mut restore_payload_cache_for_bootstrap = mls_restore_payload_cache;
        use_effect(move || {
            let selected = selected_space();
            if !bootstrap_route_uses_space_context {
                return;
            }
            let bootstrap_space_id = bootstrap_context_space_id
                .clone()
                .filter(|space| !space.trim().is_empty())
                .unwrap_or(selected);
            let base = base_url();
            let session = token();
            let actor = account_did();
            let device = device_id();
            let description = server_description();
            let Some(bootstrap_key) = mls_welcome_bootstrap_key(
                &base,
                &session,
                &actor,
                &device,
                &bootstrap_space_id,
                profile_ready(description.as_ref(), PROFILE_E2EE_CLIENT),
                sync_bootstrap_complete(),
            ) else {
                return;
            };
            // BUG X4: the per-space bootstrap caches its `seen` key, so after
            // the user's first encrypted write *creates* the account MLS
            // secret (and this space's MLS snapshot) the detection would
            // never re-run and the backup prompt would never appear. Read a
            // `state_store` signal in the synchronous body (`has_local_mls_snapshot`)
            // so Dioxus re-fires this effect when the write saves the snapshot,
            // and fold both the local account-secret presence (`sec=`) and the
            // snapshot presence (`snap=`) into the key so the `seen` guard no
            // longer matches once they flip false→true.
            let has_local_mls_snapshot = state_store_for_bootstrap
                .read()
                .mls_snapshot_for(&bootstrap_space_id)
                .is_some();
            let has_local_account_secret = crate::mls::runtime::load_account_mls_secret(
                crate::secure_key_store::default_secure_key_store("yougen").as_ref(),
                &actor,
            )
            .map(|secret| secret.is_some())
            .unwrap_or(false);
            let bootstrap_key = format!(
                "{bootstrap_key}|sec={has_local_account_secret}|snap={has_local_mls_snapshot}"
            );
            if seen_bootstrap_key().as_deref() == Some(bootstrap_key.as_str()) {
                return;
            }
            seen_bootstrap_key.set(Some(bootstrap_key));

            let state_store_task = state_store_for_bootstrap;
            let mut crypto_state_task = crypto_state_for_bootstrap;
            let mut last_error_task = last_error_for_bootstrap;
            let space_label = short_protocol_id(&bootstrap_space_id);
            // Detection-step clones: the originals are moved into the Welcome
            // bootstrap call below; we reuse these for the account-secret
            // unlock probe afterwards.
            let detect_base = base.clone();
            let detect_session = session.clone();
            let detect_actor = actor.clone();
            let detect_device = device.clone();
            let state_store_for_probe = state_store_for_bootstrap;
            spawn(async move {
                match bootstrap_mls_welcome_for_space(
                    base,
                    session,
                    actor,
                    device,
                    bootstrap_space_id,
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
                            "MLS Welcome applied for {space_label}: {} group(s); history backup {backup_label}",
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
                match crate::views::helpers::with_authed_api(
                    &detect_base,
                    detect_session,
                    |api| async move {
                        crate::mls::account_recovery::fetch_mls_restore_payload(&api).await
                    },
                )
                .await
                {
                    Ok(payload) => {
                        let secure_store =
                            crate::secure_key_store::default_secure_key_store("yougen");
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
                            restore_payload_cache_for_bootstrap.set(Some(payload));
                            needs_mls_unlock_for_bootstrap.set(true);
                            needs_mls_backup_for_bootstrap.set(false);
                        } else {
                            let should_backup =
                                crate::mls::account_recovery::mls_backup_prompt_required(
                                    &payload,
                                    secure_store.as_ref(),
                                    &detect_actor,
                                    &detect_device,
                                );
                            needs_mls_backup_for_bootstrap.set(should_backup);
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
    let resolved_space_surface = resolve_space_surface(
        &route,
        &state_store(),
        &account_did(),
        context_space_id.as_deref(),
    );
    if let (Some(space_id), Some(surface)) = (routed_space_id.as_deref(), resolved_space_surface)
        && matches!(
            &route,
            Route::TimelineSpace { .. }
                | Route::KanbanSpace { .. }
                | Route::KanbanBoard { .. }
                | Route::KanbanBoardTask { .. }
                | Route::DocumentSpace { .. }
        )
    {
        let stored_surface =
            load_space_surface_preference(&state_store(), &account_did(), space_id);
        if stored_surface != surface {
            persist_space_surface_preference(
                &mut state_store.write(),
                &account_did(),
                space_id,
                surface,
            );
        }
    }

    let loaded_spaces = spaces();
    let selected_preview = loaded_spaces
        .iter()
        .find(|space| context_space_id.as_deref() == Some(space.space_id.as_str()))
        .cloned();
    let active_scope_mode = space_scope_mode();
    let active_space_scope_ids =
        scoped_space_ids(&loaded_spaces, &active_space_id, active_scope_mode);
    let active_projection_realm_id =
        projection_realm_id_for_known_space(&loaded_spaces, &active_space_id).unwrap_or_default();
    let active_space_scope_set: BTreeSet<String> = active_space_scope_ids.iter().cloned().collect();
    let active_space_scope_count = active_space_scope_ids.len();
    let active_space_scope_label = if active_space_scope_count <= 1 {
        active_scope_mode.label().to_owned()
    } else {
        format!(
            "{} · {} Spaces",
            active_scope_mode.label(),
            active_space_scope_count
        )
    };
    let space_tree = space_tree_items(&loaded_spaces);
    let space_projections = state_store.read().load().space_projections;
    let active_security_scope_id = if active_projection_realm_id.trim().is_empty() {
        active_space_id.as_str()
    } else {
        active_projection_realm_id.as_str()
    };
    let active_space_security_encrypted = crate::security_state::security_projection_for_scope_id(
        &space_projections,
        active_security_scope_id,
    )
    .or_else(|| {
        crate::security_state::security_projection_for_scope_id(
            &space_projections,
            &active_space_id,
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
    let server_options = server_options_for(&base_url());
    let sidebar_style = format!("--sidebar-w: {:.0}px;", sidebar_width());
    let theme_attr = active_theme.as_str();
    let theme_is_night = theme_renders_as_night(&active_theme, system_theme_is_night());
    let theme_toggle_icon = if theme_is_night { "sun" } else { "moon" };
    let theme_toggle_title = if theme_is_night {
        "Switch to light theme"
    } else {
        "Switch to night theme"
    };
    let route_title = resolved_space_surface
        .map(SpaceSurface::title)
        .unwrap_or_else(|| route_label(&route));
    let topbar_context_title = selected_preview
        .as_ref()
        .map(|space| space.title.clone())
        .unwrap_or_else(|| {
            if route_uses_space_context {
                "Space".to_owned()
            } else {
                route_title.to_owned()
            }
        });
    let topbar_search_is_open =
        palette_open() || topbar_search_expanded() || !global_query().is_empty();
    let document_title = if matches!(&route, Route::Dashboard) {
        "Yougen | Cokret".to_owned()
    } else {
        format!("{route_title} | Yougen | Cokret")
    };
    let shell_class = format!(
        "shell app {}{}{}{}",
        match active_theme.as_str() {
            "night" => "theme-night",
            "light" => "theme-light",
            _ => "theme-system",
        },
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
    if !matches!(auth_surface, AuthSurface::AppShell) {
        let auth_class = format!(
            "auth-shell {}{}",
            match active_theme.as_str() {
                "night" => "theme-night",
                "light" => "theme-light",
                _ => "theme-system",
            },
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

        return rsx! {
            style { "{STYLE}" }
            style { "{CLAUDE_STYLE}" }
            style { "{CLAUDE_APP_OVERRIDES}" }
            document::Title { "{document_title}" }
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
                                status,
                                config_store,
                                state_store,
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
                                    "{status()}"
                                }
                            }
                        },
                        AuthSurface::Login | AuthSurface::AppShell => rsx! {
                            crate::views::login::LoginPanel {
                                base_url,
                                account_did,
                                device_id,
                                token,
                                status,
                                config_store,
                                state_store,
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
            }
        };
    }

    let content_route = if matches!(&route, Route::Login) && has_session {
        Route::Dashboard
    } else {
        route.clone()
    };

    rsx! {
        style { "{STYLE}" }
        style { "{CLAUDE_STYLE}" }
        style { "{CLAUDE_APP_OVERRIDES}" }
        document::Title { "{document_title}" }
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
            // covers all spaces the user has access to.
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
            // G3.Y3 — global policy-deny banner. Floats above the shell
            // so any 403 with a policy-shaped envelope is surfaced
            // without each call site wiring its own error UI. The
            // banner is pulled from a process-wide queue populated by
            // `api::decode_cokret_error`'s `maybe_dispatch_policy_deny`.
            crate::components::PolicyDenyBanner {}
            // CXP-0007 P3B.3 — global Circle-error toast, fed by the
            // HTTP layer's `maybe_dispatch_circle_error` next to the
            // policy-deny dispatcher. Renders nothing when no error
            // is queued.
            crate::components::CircleErrorToast { i18n: i18n_signal }
            // Step 3 of the account-MLS-secret auto-unlock flow: a
            // recovery-passphrase banner that restores encrypted history on
            // a fresh device. Renders nothing unless boot detection flagged
            // `needs_mls_unlock`.
            crate::components::MlsUnlockPrompt {
                base_url,
                token,
                actor_did: account_did,
                device_id,
                state_store,
                needs_mls_unlock,
                restore_payload_cache: mls_restore_payload_cache,
            }
            // Task X3 — one-time account-secret BACKUP prompt (mirror of the
            // unlock banner). Renders nothing unless detection flagged
            // `needs_mls_backup` (local secret exists, no server backup yet).
            crate::components::MlsBackupPrompt {
                base_url,
                token,
                actor_did: account_did,
                device_id,
                state_store,
                needs_mls_backup,
            }
            div { class: "mobile-shellbar", "data-testid": "mobile-shellbar",
                button {
                    class: "btn icon sm ghost",
                    "data-testid": "mobile-nav-toggle",
                    title: if mobile_nav_open() { "Close menu" } else { "Open menu" },
                    "aria-label": if mobile_nav_open() { "Close menu" } else { "Open menu" },
                    onclick: move |_| mobile_nav_open.toggle(),
                    if mobile_nav_open() {
                        UiIcon { name: "x" }
                    } else {
                        UiIcon { name: "menu" }
                    }
                }
                div { class: "brand", "Cokret" }
                button {
                    class: "btn icon sm ghost",
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
                Link {
                    class: "btn icon sm ghost topbar-notifications-link",
                    "data-testid": "mobile-topbar-notifications-button",
                    to: Route::Notifications,
                    title: "Notifications",
                    "aria-label": "Notifications",
                    UiIcon { name: "inbox" }
                    span { class: "topbar-notifications-badge", "aria-hidden": "true" }
                }
            }
            nav {
                class: if mobile_nav_open() { "mobile-drawer open" } else { "mobile-drawer" },
                "data-testid": "mobile-nav-drawer",
                div { class: "mobile-status", "data-testid": "mobile-connection-status",
                    span { "data-testid": "mobile-status-label", "{status}" }
                    span { class: "muted mono", "data-testid": "mobile-sync-cursor", "cursor {sync_cursor}" }
                    button {
                        class: "primary",
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
                                    status,
                                    sync_cursor,
                                    token,
                                    account_did,
                                    selected_space,
                                    spaces,
                                    timeline,
                                    device_queue,
                                    frontier_state,
                                    crypto_state,
                                    config_store,
                                    state_store,
                                    network_state,
                                    last_error,
                                    server_description,
                                    server_probe_status,
                                    theme,
                                    sync_generation,
                                    sync_bootstrap_complete,
                                    session_boot_state,
                                    navigator,
                                },
                            )
                        },
                        "Refresh"
                    }
                }
                Link { class: "secondary", "data-testid": "mobile-dashboard-nav-button", to: Route::Dashboard, onclick: move |_| mobile_nav_open.set(false), {crate::i18n::tr("nav.dashboard")} }
                Link { class: "secondary", "data-testid": "mobile-directory-nav-button", to: Route::Directory, onclick: move |_| mobile_nav_open.set(false), {crate::i18n::tr("nav.directory")} }
                Link { class: "secondary", "data-testid": "mobile-settings-nav-button", to: Route::Settings, onclick: move |_| mobile_nav_open.set(false), {crate::i18n::tr("nav.settings")} }
                if !loaded_spaces.is_empty() {
                    div { class: "muted", "{crate::i18n::tr(\"command_palette.spaces\")} ({space_tree.len()})" }
                    input {
                        class: "mobile-space-filter",
                        "data-testid": "mobile-space-filter",
                        value: "{mobile_space_query}",
                        placeholder: crate::i18n::tr("mobile.filter_spaces"),
                        oninput: move |event| mobile_space_query.set(event.value()),
                    }
                    div { class: "mobile-space-list", "data-testid": "mobile-space-list",
                        {
                            let q = mobile_space_query();
                            let q_lc = q.trim().to_lowercase();
                            let filtered: Vec<_> = space_tree
                                .iter()
                                .filter(|item| {
                                    q_lc.is_empty()
                                        || item.space.title.to_lowercase().contains(&q_lc)
                                        || item.space.space_id.to_lowercase().contains(&q_lc)
                                })
                                .collect();
                            if filtered.is_empty() {
                                rsx! {
                                    div { class: "muted", "data-testid": "mobile-space-empty", {crate::i18n::tr("mobile.no_match")} }
                                }
                            } else {
                                rsx! {
                                    for item in filtered.iter() {
                                        Link {
                                            class: "secondary",
                                            "data-testid": "mobile-space-nav-button",
                                            to: Route::Space { space_id: item.space.space_id.clone() },
                                            onclick: {
                                                let id = item.space.space_id.clone();
                                                move |_| {
                                                    selected_space.set(id.clone());
                                                    mobile_nav_open.set(false);
                                                    mobile_space_query.set(String::new());
                                                }
                                            },
                                            "{item.space.title}"
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
                    Link { class: "brand", to: Route::Dashboard, "aria-label": "Yougen | Cokret Home",
                        span { class: "logo", "⌘" }
                        span { class: "product-meta",
                            span { class: "product-name", "Yougen | Cokret" }
                        }
                    }
                }

                div { class: "server-switch", "data-testid": "principal-context", "aria-label": "Current server context",
                    button {
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
                                    button {
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
                                                    selected_space,
                                                    spaces,
                                                    timeline,
                                                    device_queue,
                                                    frontier_state,
                                                    crypto_state,
                                                    config_store,
                                                    state_store,
                                                    network_state,
                                                    last_error,
                                                    server_description,
                                                    server_probe_status,
                                                    status,
                                                    account_did,
                                                    device_id,
                                                    sync_generation,
                                                });
                                                server_menu_open.set(false);
                                                sync_bootstrap_complete.set(false);
                                                connect(
                                                    next_url,
                                                    account_did(),
                                                    device_id(),
                                                    ConnectContext {
                                                        status,
                                                        sync_cursor,
                                                        token,
                                                        account_did,
                                                        selected_space,
                                                        spaces,
                                                        timeline,
                                                        device_queue,
                                                        frontier_state,
                                                        crypto_state,
                                                        config_store,
                                                        state_store,
                                                        network_state,
                                                        last_error,
                                                        server_description,
                                                        server_probe_status,
                                                        theme,
                                                        sync_generation,
                                                        sync_bootstrap_complete,
                                                        session_boot_state,
                                                        navigator,
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
                }

                div { class: "sidebar-nav-group", "data-testid": "space-list",
                    h4 { class: "sidebar-nav-group-title",
                        span {
                            title: "Realms (security boundaries) and the Spaces nested inside them — spec realm-and-space.md.",
                            "Realms & Spaces"
                        }
                        // Header "+" creates a new Realm (no scope
                        // needed). For new Spaces use the per-row
                        // "+" hover action on a Realm or Space —
                        // that surfaces the parent context inline
                        // instead of dumping the user on a form with
                        // no idea where the Space will land.
                        Link {
                            class: "add-realm-cta",
                            "data-testid": "sidebar-new-realm-cta",
                            title: "Create a new Realm (security boundary). For a new Space, hover a Realm or Space row and click the + on that row.",
                            "aria-label": "Create a new Realm",
                            to: Route::SetupSection { section: "realms".to_owned() },
                            UiIcon { name: "plus" }
                        }
                    }
                    if !loaded_spaces.is_empty() && !sidebar_is_collapsed {
                        div { class: "sidebar-scope-toggle", "data-testid": "space-scope-toggle", role: "group", "aria-label": "Space selection scope",
                            button {
                                class: if active_scope_mode == SpaceScopeMode::Exact { "scope-chip active" } else { "scope-chip" },
                                "data-testid": "space-scope-exact",
                                title: "Select only the current Space",
                                "aria-pressed": if active_scope_mode == SpaceScopeMode::Exact { "true" } else { "false" },
                                onclick: move |_| {
                                    space_scope_mode.set(SpaceScopeMode::Exact);
                                    save_space_scope_preference(&mut state_store.write(), SpaceScopeMode::Exact);
                                },
                                "Only"
                            }
                            button {
                                class: if active_scope_mode == SpaceScopeMode::IncludeDescendants { "scope-chip active" } else { "scope-chip" },
                                "data-testid": "space-scope-descendants",
                                title: "Select the current Space and all descendant Spaces",
                                "aria-pressed": if active_scope_mode == SpaceScopeMode::IncludeDescendants { "true" } else { "false" },
                                onclick: move |_| {
                                    space_scope_mode.set(SpaceScopeMode::IncludeDescendants);
                                    save_space_scope_preference(&mut state_store.write(), SpaceScopeMode::IncludeDescendants);
                                },
                                "Tree"
                            }
                        }
                    }
                    if loaded_spaces.is_empty() {
                        div { class: "sidebar-nav-item is-dim", "data-testid": "space-empty-state",
                            span { class: "sidebar-nav-icon", UiIcon { name: "folder" } }
                            span { class: "grow truncate", if has_session { "No spaces loaded" } else { "Sign in to load spaces" } }
                        }
                        // Diagnostic line: when an authenticated user sees an
                        // empty sidebar, surface the latest connect status and
                        // (if any) last_error directly so QA / users can tell
                        // "sync failed" from "no spaces yet" without opening
                        // devtools. Truncated to keep the sidebar tidy.
                        if has_session && !sidebar_is_collapsed {
                            div { class: "sidebar-nav-meta",
                                "data-testid": "space-empty-state-status",
                                style: "padding: 4px 12px; font-size: 11px; line-height: 1.4; opacity: 0.7;",
                                {
                                    let status_text = status();
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
                                        div { "data-testid": "space-empty-state-status-line",
                                            "{trimmed_status}"
                                        }
                                        if let Some(err) = trimmed_error {
                                            div {
                                                "data-testid": "space-empty-state-error-line",
                                                style: "color: var(--danger, #d33);",
                                                "{err}"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        for item in space_tree.iter() {
                            {
                                let item_space = item.space.clone();
                                let depth_px = item.depth * 14;
                                let in_scope = active_space_scope_set.contains(&item_space.space_id);
                                let is_active = effective_space_id.as_deref() == Some(item_space.space_id.as_str());
                                let item_class = if is_active {
                                    "sidebar-nav-item space-tree-item is-active"
                                } else if in_scope {
                                    "sidebar-nav-item space-tree-item is-scope-member"
                                } else {
                                    "sidebar-nav-item space-tree-item"
                                };
                                // Spec client-preferences.md §3.7: when the
                                // user has a private Space remark, prefer its
                                // local_name; fall back to the public title.
                                // Use a "(remark)" badge so duplicate-titled
                                // Spaces can be distinguished without leaking
                                // the remark beyond this device.
                                let remark = state_store
                                    .read()
                                    .space_remark(&item_space.space_id);
                                let display_name = remark
                                    .as_ref()
                                    .map(|r| r.display_name(&item_space.title).to_owned())
                                    .unwrap_or_else(|| item_space.title.clone());
                                let has_remark = remark
                                    .as_ref()
                                    .is_some_and(|r| !r.local_name.trim().is_empty());
                                let add_child_title = match item_space.kind {
                                    SpacePreviewKind::Realm => "Create a new Space at the root of this Realm",
                                    SpacePreviewKind::Space => "Create a new Space under this one (this Space becomes the parent)",
                                };
                                let (icon_name, icon_class, icon_title) = match item_space.kind {
                                    SpacePreviewKind::Realm => {
                                        let is_encrypted = space_projections
                                            .get(&item_space.space_id)
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
                                    SpacePreviewKind::Space => (
                                        "folder",
                                        "sidebar-nav-icon",
                                        "Space",
                                    ),
                                };
                                rsx! {
                            div { class: "sidebar-row",
                            Link {
                                class: "{item_class} sidebar-row-main",
                                "data-testid": "space-button",
                                title: "{item_space.title}",
                                style: "padding-left: calc(10px + {depth_px}px);",
                                to: Route::Space { space_id: item_space.space_id.clone() },
                                onclick: {
                                    let id = item_space.space_id.clone();
                                    move |_| selected_space.set(id.clone())
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
                                        "data-testid": "space-remark-badge",
                                        title: "Local remark (private to this account)",
                                        "备注"
                                    }
                                }
                                // Two-tier classification badge: Realm
                                // (security boundary) vs Space (nav
                                // container inside a Realm). When a
                                // Realm has descendants, show the count
                                // instead of the kind tag so the user
                                // sees the tree structure at a glance.
                                if item.descendant_count > 0 && item_space.kind == SpacePreviewKind::Realm {
                                    span { class: "pill muted xs", "{item.descendant_count}" }
                                } else {
                                    match item_space.kind {
                                        SpacePreviewKind::Realm => rsx! {
                                            span {
                                                class: "pill muted xs",
                                                "data-testid": "space-kind-realm",
                                                title: "Realm — security / sync / E2EE boundary (spec realm-and-space.md §2)",
                                                "Realm"
                                            }
                                        },
                                        SpacePreviewKind::Space => rsx! {
                                            span {
                                                class: "pill muted xs",
                                                "data-testid": "space-kind-space",
                                                title: "Space — navigation container inside a Realm (spec realm-and-space.md §3)",
                                                "Space"
                                            }
                                        },
                                    }
                                }
                            }
                            // Contextual "+" — creates a new Space
                            // scoped to this row. For Realms this is
                            // "Space at the Realm root"; for Spaces
                            // this is "child Space under this one".
                            // Sets `selected_space` first so the
                            // NewSpace form can derive the prefilled
                            // realm_id + parent_space_id from it.
                            Link {
                                class: "sidebar-row-add-action",
                                "data-testid": "space-row-add-action",
                                title: "{add_child_title}",
                                "aria-label": "{add_child_title}",
                                to: Route::SetupSection { section: "new-space".to_owned() },
                                onclick: {
                                    let id = item_space.space_id.clone();
                                    move |_| selected_space.set(id.clone())
                                },
                                UiIcon { name: "plus" }
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
                        button {
                            class: "btn icon sm ghost sidebar-collapse-toggle",
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
                            if route_uses_space_context && !active_space_id.is_empty() {
                                SecurityStateBadge {
                                    encrypted: active_space_security_encrypted,
                                    compact: false,
                                    test_id: Some("space-security-state".to_owned()),
                                }
                            }
                            span { class: "topbar-context-title", "data-testid": "space-title", "{topbar_context_title}" }
                            if route_uses_space_context && !active_space_id.is_empty() {
                                {
                                    let (current_surface_label, current_surface_icon) = match resolved_space_surface {
                                        Some(surface) => (surface.short_label(), surface.icon_name()),
                                        None => ("Settings", "settings"),
                                    };
                                    rsx! {
                                        span {
                                            class: "topbar-current-surface",
                                            "data-testid": "current-space-surface",
                                            title: "Current view: {current_surface_label}",
                                            UiIcon { name: current_surface_icon }
                                            span { class: "topbar-current-surface-label", "{current_surface_label}" }
                                        }
                                    }
                                }
                            }
                            if route_uses_space_context && active_space_scope_count > 1 {
                                span { class: "topbar-context-pill muted", "{active_space_scope_label}" }
                            }
                            if !active_space_id.is_empty() {
                                span { class: "sr-only mono", "data-testid": "selected-space-id", "{active_space_id}" }
                            }
                        }
                    }
                    if route_uses_space_context && !active_space_id.is_empty() {
                        SpaceContextBar {
                            space_id: active_space_id.clone(),
                            scope_label: active_space_scope_label.clone(),
                            scope_count: active_space_scope_count,
                            current_surface: resolved_space_surface,
                            account_did: account_did(),
                            state_store,
                            minimal_ready,
                            kanban_ready,
                            full_ready,
                        }
                    }
                    div { class: "actions",
                        button {
                            class: "btn icon sm ghost theme-toggle-button",
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
                                button {
                                    r#type: "button",
                                    class: "btn icon sm ghost",
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
                                    button {
                                        r#type: "button",
                                        class: "btn icon sm ghost topbar-command-search-close",
                                        title: crate::i18n::tr("common.close"),
                                        "aria-label": crate::i18n::tr("common.close"),
                                        onclick: move |_| {
                                            palette_open.set(false);
                                            topbar_search_expanded.set(false);
                                            global_query.set(String::new());
                                        },
                                        UiIcon { name: "x" }
                                    }
                                }
                                if palette_open() {
                                    CommandPalette {
                                        query: global_query(),
                                        spaces: spaces(),
                                        on_navigate: move |route: Route| {
                                            view.set(Route::to_view(&route));
                                            let _ = navigator.push(route);
                                            palette_open.set(false);
                                            topbar_search_expanded.set(false);
                                            global_query.set(String::new());
                                        },
                                        on_pick_space: move |space_id: String| {
                                            selected_space.set(space_id.clone());
                                            view.set(crate::views::View::Timeline);
                                            let _ = navigator.push(Route::Space { space_id });
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
                        div { class: "sr-only", "data-testid": "connection-status", role: "status", "aria-live": "polite",
                            span { "data-testid": "status-label", "{status}" }
                            span { "data-testid": "network-state-badge", "{network_state}" }
                            span { class: "mono", "data-testid": "sync-cursor", "cursor {sync_cursor}" }
                            if let Some(ref err) = last_error() {
                                span { "data-testid": "last-error", "{err}" }
                            }
                        }
                        Link {
                            class: "btn icon sm ghost topbar-notifications-link",
                            "data-testid": "topbar-notifications-button",
                            to: Route::Notifications,
                            title: crate::i18n::tr("nav.notifications"),
                            "aria-label": crate::i18n::tr("nav.notifications"),
                            UiIcon { name: "inbox" }
                            span { class: "topbar-notifications-badge", "aria-hidden": "true" }
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
                            button {
                                class: "btn icon sm ghost account-menu-button",
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
                                UiIcon { name: "user" }
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
                                        span { class: "avatar", if has_session { "P" } else { "?" } }
                                        span { class: "grow",
                                            span { class: "who", "{account_label}" }
                                            span { class: "handle", "{account_detail}" }
                                        }
                                    }
                                    div { class: "account-menu__rows",
                                        div { class: "account-menu__row",
                                            strong { "DID" }
                                            div { class: "account-menu__value",
                                                span { class: "mono", "data-testid": "account-menu-did", title: "{account_did_value}", "{account_did_label}" }
                                                button {
                                                    class: "btn icon sm ghost account-menu__copy",
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
                                            strong { "Device" }
                                            div { class: "account-menu__value",
                                                span { class: "mono", "data-testid": "account-menu-device", title: "{device_id_value}", "{device_id_label}" }
                                                button {
                                                    class: "btn icon sm ghost account-menu__copy",
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
                                            span { "bearer" }
                                        }
                                        div { class: "account-menu__rows",
                                            div { class: "account-menu__row",
                                                strong { "Token" }
                                                span { class: "mono", "data-testid": "account-menu-session-token", if has_session { "Token loaded" } else { "No authenticated session" } }
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
                                        button {
                                            class: "btn sm ghost",
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
                                                        match CokretApi::new(&base) {
                                                            Ok(api) => match api.with_bearer(api_token.clone()).account_me().await {
                                                                Ok(account) => {
                                                                    let canonical_actor = account.did;
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
                                                                        // The bearer expired between background
                                                                        // refresh ticks. Try a silent re-mint
                                                                        // (OIDC refresh_token / session-grant
                                                                        // exchange) before declaring the session
                                                                        // dead — clicking "Refresh session" must
                                                                        // *keep* the user signed in, not bounce
                                                                        // them to login on a routine token rollover.
                                                                        if let Some(fresh) = crate::session::refresh_current_bearer().await {
                                                                            let canonical_actor = match CokretApi::new(&base) {
                                                                                Ok(api) => api
                                                                                    .with_bearer(fresh)
                                                                                    .account_me()
                                                                                    .await
                                                                                    .ok()
                                                                                    .map(|account| account.did)
                                                                                    .filter(|did| !did.trim().is_empty()),
                                                                                Err(_) => None,
                                                                            }
                                                                            .unwrap_or_else(|| actor.clone());
                                                                            account_did.set(canonical_actor.clone());
                                                                            account_session_state.set(format!(
                                                                                "Session refresh ok: {canonical_actor}"
                                                                            ));
                                                                        } else {
                                                                            token.set(String::new());
                                                                            persist_config(
                                                                                config_store,
                                                                                base.clone(),
                                                                                actor.clone(),
                                                                                device.clone(),
                                                                                String::new(),
                                                                            );
                                                                            status.set("Session expired; sign in again".to_owned());
                                                                            last_error.set(Some("auth_expired: session expired".to_owned()));
                                                                            account_session_state.set(
                                                                                "Session expired. Sign in again.".to_owned()
                                                                            );
                                                                            session_boot_state.set(SessionBootState::Unauthenticated);
                                                                            redirect_to_login(navigator);
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
                                        button {
                                            class: "btn sm ghost",
                                            "data-testid": "account-menu-session-logout",
                                            "aria-label": "Log out",
                                            disabled: !has_session,
                                            onclick: move |_| {
                                                let base = base_url();
                                                let actor = account_did();
                                                let device = device_id();
                                                let api_token = token();
                                                account_session_state.set("Logging out".to_owned());
                                                // Clear OIDC + session-grant state up
                                                // front so a refresh-token-based silent
                                                // re-auth cannot resurrect the session
                                                // if the server-side logout call later
                                                // fails or is cancelled.
                                                state_store.write().set_oidc_tokens(None);
                                                state_store.write().set_session_grant(None);
                                                // Then wipe every account-scoped local
                                                // projection cache (spaces, drafts,
                                                // anchors, read markers, remarks…) so
                                                // whoever signs in next on this browser
                                                // can't see the previous session's data.
                                                // Device-level state (local_identity,
                                                // push_registration) is preserved.
                                                state_store.write().clear_account_scoped();
                                                // G3.Y0 — this is the *hard* logout path
                                                // (user clicked "Log out"). Wipe the
                                                // device DPoP key so the next sign-in
                                                // rotates `cnf.jkt`. The soft path
                                                // (`session_refresh`'s LoginRequired
                                                // outcome) deliberately keeps the key.
                                                state_store.write().set_dpop_device_key(None);
                                                let _ = crate::coauth::clear_persisted_oidc_scaffold();
                                                // Wipe the in-memory UI signals too so the
                                                // sidebar can't paint a frame of stale
                                                // spaces between this click and the
                                                // navigator.push(Login).
                                                spaces.set(Vec::new());
                                                timeline.set(Vec::new());
                                                sync_cursor.set("-".to_owned());
                                                selected_space.set(String::new());
                                                device_queue.set(0);
                                                last_error.set(None);
                                                session_boot_state.set(SessionBootState::Unauthenticated);
                                                // Bump the SyncEngine generation so any
                                                // in-flight long-poll exits on its next
                                                // iteration check instead of applying a
                                                // response after the wipe.
                                                sync_generation.set(sync_generation() + 1);
                                                spawn(async move {
                                                    let api_result = CokretApi::new(&base)
                                                        .map(|api| api.with_bearer(api_token));
                                                    let logout_message = match api_result {
                                                        Ok(api) => match api.logout().await {
                                                            Ok(response) => format!(
                                                                "Logout ok: revoked {}",
                                                                response.revoked
                                                            ),
                                                            Err(error) => {
                                                                format!("Logout failed: {error}")
                                                            }
                                                        },
                                                        Err(error) => {
                                                            format!("Invalid server URL: {error}")
                                                        }
                                                    };
                                                    token.set(String::new());
                                                    persist_config(
                                                        config_store,
                                                        base,
                                                        actor,
                                                        device,
                                                        String::new(),
                                                    );
                                                    account_session_state.set(logout_message);
                                                    account_menu_open.set(false);
                                                    redirect_to_login(navigator);
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
                            status,
                            config_store,
                            state_store,
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
                            status,
                            config_store,
                            state_store,
                            auto_capture_callback: true,
                            on_login: move |_| { let _ = navigator.push(Route::Dashboard); },
                        }
                    },
                    Route::Dashboard => rsx! {
                        crate::views::dashboard::DashboardPanel {
                            base_url: base_url(),
                            token,
                            spaces,
                            selected_space,
                            view,
                            state_store,
                            device_queue: device_queue(),
                            frontier_state: frontier_state(),
                            sync_cursor: sync_cursor(),
                        }
                    },
                    Route::Space { .. } => {
                        match resolved_space_surface.unwrap_or(SpaceSurface::Timeline) {
                            SpaceSurface::Timeline => {
                                if minimal_ready {
                                    rsx! {
                                        crate::views::timeline::TimelinePanel {
                                            base_url: base_url(),
                                            account_did: account_did(),
                                            device_id: device_id(),
                                            token,
                                            selected_space: active_space_id.clone(),
                                            selected_space_scope: active_space_scope_ids.clone(),
                                            timeline,
                                            draft,
                                            state_store,
                                            crypto_state,
                                            sync_cursor,
                                            frontier_state,
                                            base_url_sig: base_url,
                                        }
                                    }
                                } else {
                                    rsx! { ProfileGateNotice { profile: "minimal_client" } }
                                }
                            }
                            SpaceSurface::Board => {
                                if kanban_ready {
                                    rsx! {
                                        crate::views::kanban::KanbanPanel {
                                            base_url: base_url(),
                                            plaintext_service_did: active_service_did.clone(),
                                            token,
                                            account_did: account_did(),
                                            device_id: device_id(),
                                            selected_space: active_space_id.clone(),
                                            projection_realm_id: active_projection_realm_id.clone(),
                                            selected_space_scope: active_space_scope_ids.clone(),
                                            sync_cursor,
                                            frontier_state,
                                            state_store,
                                            event_write_ready,
                                        }
                                    }
                                } else {
                                    rsx! { ProfileGateNotice { profile: "kanban_mvp" } }
                                }
                            }
                            SpaceSurface::Document => {
                                if full_ready {
                                    rsx! {
                                        crate::views::document::DocumentPanel {
                                            base_url: base_url(),
                                            token,
                                            selected_space: active_space_id.clone(),
                                            document_ref: None,
                                            state_store,
                                            account_did: account_did(),
                                        }
                                    }
                                } else {
                                    rsx! { ProfileGateNotice { profile: "full_client" } }
                                }
                            }
                        }
                    },
                    Route::Timeline | Route::TimelineSpace { .. } | Route::TimelineMessage { .. } => {
                        if let Some(sid) = route.space_id()
                            && selected_space() != sid
                        {
                            selected_space.set(sid.to_owned());
                        }
                        if minimal_ready {
                            rsx! {
                                crate::views::timeline::TimelinePanel {
                                    base_url: base_url(),
                                    account_did: account_did(),
                                    device_id: device_id(),
                                    token,
                                    selected_space: active_space_id.clone(),
                                    selected_space_scope: active_space_scope_ids.clone(),
                                    timeline,
                                    draft,
                                    state_store,
                                    crypto_state,
                                    sync_cursor,
                                    frontier_state,
                                    base_url_sig: base_url,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "minimal_client" } }
                        }
                    },
                    Route::Chat { .. } => {
                        if let Some(sid) = route.space_id()
                            && selected_space() != sid
                        {
                            selected_space.set(sid.to_owned());
                        }
                        if minimal_ready {
                            rsx! {
                                crate::views::chat::ChatPanel {
                                    base_url: base_url(),
                                    plaintext_service_did: active_service_did.clone(),
                                    account_did: account_did(),
                                    device_id: device_id(),
                                    token,
                                    selected_space: active_space_id.clone(),
                                    selected_space_scope: active_space_scope_ids.clone(),
                                    sync_cursor,
                                    frontier_state,
                                    state_store,
                                    initial_flow_id: default_flow_id_for_scope(&active_space_id),
                                    embedded: false,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "minimal_client" } }
                        }
                    },
                    Route::Directory => rsx! {
                        crate::views::directory::DirectoryPanel {
                            base_url: base_url(),
                            selected_space,
                            status,
                            token,
                            view,
                            state_store,
                        }
                    },
                    Route::Contacts => rsx! {
                        crate::views::contacts::ContactsPanel {
                            base_url: base_url(),
                            token,
                        }
                    },
                    Route::ContactsNew => rsx! {
                        crate::views::contacts::ContactNewPanel {
                            base_url: base_url(),
                            token,
                        }
                    },
                    Route::Setup | Route::SetupSection { .. } => {
                        if full_ready {
                            rsx! {
                                crate::views::setup::SetupPanel {
                                    base_url: base_url(),
                                    plaintext_service_did: active_service_did.clone(),
                                    token,
                                    account_did,
                                    device_id,
                                    config_store,
                                    state_store,
                                    selected_space,
                                    status,
                                    section: route.setup_section().map(str::to_owned),
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "full_client" } }
                        }
                    },
                    Route::Settings | Route::SettingsSection { .. } | Route::NotificationsSettings => rsx! {
                        crate::views::settings::SettingsPanel {
                            base_url,
                            account_did,
                            device_id,
                            token,
                            crypto_state: crypto_state(),
                            config_store,
                            state_store,
                            push_state,
                            locale,
                            theme,
                            status,
                            push_ready,
                        }
                    },
                    // G3.Y1 — device management + QR pairing live on
                    // their own routes so the e2e harness can deep-link
                    // into them without scrolling past unrelated
                    // settings sections.
                    Route::SettingsDevices | Route::SettingsDevicesPair => rsx! {
                        crate::views::settings::devices::SettingsDevicesPanel {
                            base_url,
                            account_did,
                            device_id,
                            token,
                            state_store,
                        }
                    },
                    Route::SettingsRecovery => rsx! {
                        crate::views::settings::recovery::SettingsRecoveryPanel {
                            base_url,
                            token,
                            account_did,
                            state_store,
                        }
                    },
                    Route::SettingsSecurity => rsx! {
                        crate::views::settings::security::SettingsSecurityPanel {
                            base_url,
                            account_did,
                            device_id,
                            token,
                            state_store,
                        }
                    },
                    Route::Recover => rsx! {
                        crate::views::settings::recover_restore::RecoverPanel {
                            base_url,
                            token,
                            account_did: account_did(),
                            device_id: device_id(),
                            state_store,
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
                                    selected_space: selected_space(),
                                    state_store,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "e2ee_client" } }
                        }
                    },
                    Route::SpaceAdmin { .. } | Route::SpaceAdminSection { .. } => {
                        if let Some(sid) = route.space_id()
                            && selected_space() != sid
                        {
                            selected_space.set(sid.to_owned());
                        }
                        if full_ready {
                            rsx! {
                                crate::views::space_admin::SpaceAdminPanel {
                                    base_url: base_url(),
                                    account_did: account_did(),
                                    device_id: device_id(),
                                    token,
                                    selected_space: active_space_id.clone(),
                                    sync_cursor,
                                    frontier_state,
                                    state_store,
                                    active_section: route.space_admin_section().map(str::to_owned),
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "full_client" } }
                        }
                    },
                    Route::Audit => rsx! {
                        crate::views::audit::AuditPanel { state_store }
                    },
                    Route::Developer => rsx! {
                        crate::views::developer::DeveloperToolsPanel { state_store }
                    },
                    Route::Kanban
                    | Route::KanbanSpace { .. }
                    | Route::KanbanBoard { .. }
                    | Route::KanbanBoardTask { .. }
                    | Route::KanbanTask { .. } => {
                        if let Some(sid) = route.space_id()
                            && selected_space() != sid
                        {
                            selected_space.set(sid.to_owned());
                        }
                        if kanban_ready {
                            rsx! {
                                crate::views::kanban::KanbanPanel {
                                    base_url: base_url(),
                                    plaintext_service_did: active_service_did.clone(),
                                    token,
                                    account_did: account_did(),
                                    device_id: device_id(),
                                    selected_space: active_space_id.clone(),
                                    projection_realm_id: active_projection_realm_id.clone(),
                                    selected_space_scope: active_space_scope_ids.clone(),
                                    sync_cursor,
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
                            token,
                            state_store,
                        }
                    },
                    Route::Document | Route::DocumentNew | Route::DocumentSpace { .. } => {
                        if let Some(sid) = route.space_id()
                            && selected_space() != sid
                        {
                            selected_space.set(sid.to_owned());
                        }
                        let document_ref = match &route {
                            Route::DocumentSpace { space_id } if space_id.starts_with("ck:morph:") => {
                                Some(space_id.clone())
                            }
                            _ => None,
                        };
                        rsx! {
                            if full_ready {
                                crate::views::document::DocumentPanel {
                                    base_url: base_url(),
                                    token,
                                    selected_space: active_space_id.clone(),
                                    document_ref,
                                    state_store,
                                    account_did: account_did(),
                                }
                            } else {
                                ProfileGateNotice { profile: "full_client" }
                            }
                        }
                    },
                    Route::Call => rsx! {
                        crate::views::call::CallPanel { state_store }
                        if crate::views::webrtc::live_media_enabled() {
                            crate::views::webrtc::WebRtcCallPanel {
                                base_url: base_url(),
                                token,
                                state_store,
                                selected_space: active_space_id.clone(),
                                account_did: account_did(),
                                device_id: device_id(),
                            }
                        } else {
                            DeferredFeatureGate { feature: "experimental-webrtc" }
                        }
                    },
                    Route::Recovery => rsx! {
                        crate::views::recovery::RecoveryPanel {
                            base_url: base_url(),
                            token,
                            state_store,
                            account_did,
                            device_id,
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
                                selected_space: selected_space(),
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
                                selected_space: selected_space(),
                                state_store,
                            }
                        } else {
                            DeferredFeatureGate { feature: "experimental-agents" }
                        }
                    },
                    // A6.1 — global cross-Space message search panel.
                    Route::Search => rsx! {
                        crate::views::global_search::GlobalSearchPanel {
                            base_url,
                            token,
                            initial_query: String::new(),
                        }
                    },
                }
            }
            }
            // A6.4 — shortcut help overlay; toggled by the `?` global
            // key handler on the shell div above.
            crate::components::shortcut_help::ShortcutHelpOverlay {
                visible: shortcut_help_open,
            }
        }
    }
}

#[component]
fn SpaceContextBar(
    space_id: String,
    scope_label: String,
    scope_count: usize,
    current_surface: Option<SpaceSurface>,
    account_did: String,
    state_store: Signal<LocalStateStore>,
    minimal_ready: bool,
    kanban_ready: bool,
    full_ready: bool,
) -> Element {
    let _ = (&scope_label, scope_count);
    let mut menu_open = use_signal(|| false);
    let (current_nav_label, current_nav_icon) = match current_surface {
        Some(surface) => (surface.short_label(), surface.icon_name()),
        None => ("Settings", "settings"),
    };
    rsx! {
        div { class: "space-context-bar", "data-testid": "space-context-bar",
            div { class: "actions space-nav-inline", "data-testid": "space-context-inline",
                for surface in SpaceSurface::top_nav() {
                    if surface.is_available(minimal_ready, kanban_ready, full_ready) {
                        Link {
                            class: if current_surface == Some(surface) { "primary" } else { "secondary" },
                            to: surface.route(space_id.clone()),
                            onclick: {
                                let account_did = account_did.clone();
                                let space_id = space_id.clone();
                                move |_| {
                                    persist_space_surface_preference(
                                        &mut state_store.write(),
                                        &account_did,
                                        &space_id,
                                        surface,
                                    );
                                }
                            },
                            UiIcon { name: surface.icon_name() }
                            "{surface.short_label()}"
                        }
                    } else {
                        button {
                            class: "secondary",
                            disabled: true,
                            UiIcon { name: surface.icon_name() }
                            "{surface.short_label()}"
                        }
                    }
                }
                Link {
                    class: if current_surface.is_none() { "primary" } else { "secondary" },
                    to: Route::SpaceAdmin { space_id: space_id.clone() },
                    UiIcon { name: "settings" }
                    "Settings"
                }
            }
            div {
                class: if menu_open() { "space-nav-menu-host is-open" } else { "space-nav-menu-host" },
                "data-testid": "space-context-menu",
                button {
                    class: "btn icon sm secondary space-nav-menu-button",
                    "data-testid": "space-context-menu-button",
                    title: "Switch view: {current_nav_label}",
                    "aria-label": "Switch Space view",
                    "aria-expanded": "{menu_open()}",
                    onclick: move |_| menu_open.toggle(),
                    UiIcon { name: current_nav_icon }
                }
                if menu_open() {
                    button {
                        class: "space-nav-menu-scrim",
                        "aria-label": "Close Space view menu",
                        onclick: move |_| menu_open.set(false),
                    }
                    div {
                        class: "space-nav-menu-panel",
                        role: "menu",
                        "aria-label": "Space views",
                        for surface in SpaceSurface::top_nav() {
                            if surface.is_available(minimal_ready, kanban_ready, full_ready) {
                                Link {
                                    class: if current_surface == Some(surface) { "space-nav-menu-item is-active" } else { "space-nav-menu-item" },
                                    role: "menuitem",
                                    to: surface.route(space_id.clone()),
                                    onclick: {
                                        let account_did = account_did.clone();
                                        let space_id = space_id.clone();
                                        move |_| {
                                            persist_space_surface_preference(
                                                &mut state_store.write(),
                                                &account_did,
                                                &space_id,
                                                surface,
                                            );
                                            menu_open.set(false);
                                        }
                                    },
                                    UiIcon { name: surface.icon_name() }
                                    "{surface.short_label()}"
                                }
                            } else {
                                button {
                                    class: "space-nav-menu-item",
                                    role: "menuitem",
                                    disabled: true,
                                    UiIcon { name: surface.icon_name() }
                                    "{surface.short_label()}"
                                }
                            }
                        }
                        Link {
                            class: if current_surface.is_none() { "space-nav-menu-item is-active" } else { "space-nav-menu-item" },
                            role: "menuitem",
                            to: Route::SpaceAdmin { space_id: space_id.clone() },
                            onclick: move |_| menu_open.set(false),
                            UiIcon { name: "settings" }
                            "Settings"
                        }
                    }
                }
            }
        }
    }
}

/// Static list of jumpable destinations surfaced in the command palette.
/// Keep in sync with `routes::Route` — only views the user can act on are
/// listed.
fn palette_destinations() -> Vec<(&'static str, &'static str, Route)> {
    vec![
        ("Home", "dashboard, recent activity", Route::Dashboard),
        (
            "Notifications",
            "inbox, mentions, approvals",
            Route::Notifications,
        ),
        ("Search", "messages across spaces", Route::Search),
        ("Directory", "search realms, orgs, actors", Route::Directory),
        (
            "Onboarding",
            "DID, handle, device, recovery",
            Route::Onboarding,
        ),
        (
            "Settings",
            "account, encryption, push, server",
            Route::Settings,
        ),
        (
            "Recovery",
            "vault, social, recovery key (preview)",
            Route::Recovery,
        ),
        (
            "Verify device",
            "QR / SAS device verification",
            Route::VerifyDevice,
        ),
        (
            "Quarantine",
            "review held invites (admin)",
            Route::Quarantine,
        ),
        (
            "New Realm",
            "create security boundary",
            Route::SetupSection {
                section: "realms".to_owned(),
            },
        ),
    ]
}

fn palette_filter(query: &str, haystack: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let needle = query.trim().to_lowercase();
    let hay = haystack.to_lowercase();
    needle.split_whitespace().all(|token| hay.contains(token))
}

#[component]
fn CommandPalette(
    query: String,
    spaces: Vec<SpacePreview>,
    on_navigate: EventHandler<Route>,
    on_pick_space: EventHandler<String>,
    on_close: EventHandler<()>,
) -> Element {
    let dest_list = palette_destinations();
    let matched_dests: Vec<_> = dest_list
        .iter()
        .filter(|(label, hint, _)| palette_filter(&query, &format!("{label} {hint}")))
        .cloned()
        .collect();
    let matched_spaces: Vec<SpacePreview> = spaces
        .iter()
        .filter(|space| palette_filter(&query, &format!("{} {}", space.title, space.space_id)))
        .take(10)
        .cloned()
        .collect();

    rsx! {
        div {
            class: "command-palette",
            "data-testid": "command-palette",
            role: "listbox",
            "aria-label": "Command palette",
            if matched_spaces.is_empty() && matched_dests.is_empty() {
                div { class: "command-palette-empty", "data-testid": "command-palette-empty",
                    {crate::i18n::tr("command_palette.empty")}
                }
            }
            if !matched_spaces.is_empty() {
                div { class: "command-palette-group",
                    div { class: "command-palette-label", {crate::i18n::tr("command_palette.spaces")} }
                    for space in matched_spaces.iter() {
                        {
                            let space_id_label = short_protocol_id(&space.space_id);
                            rsx! {
                                button {
                                    class: "command-palette-item",
                                    "data-testid": "command-palette-space",
                                    role: "option",
                                    "aria-label": "Open space {space.title}",
                                    onclick: {
                                        let id = space.space_id.clone();
                                        move |_| on_pick_space.call(id.clone())
                                    },
                                    span { class: "command-palette-item-title", "{space.title}" }
                                    span { class: "command-palette-item-hint", title: "{space.space_id}", "{space_id_label}" }
                                }
                            }
                        }
                    }
                }
            }
            if !matched_dests.is_empty() {
                div { class: "command-palette-group",
                    div { class: "command-palette-label", {crate::i18n::tr("command_palette.jump_to")} }
                    for (label, hint, route) in matched_dests.iter() {
                        button {
                            class: "command-palette-item",
                            "data-testid": "command-palette-dest",
                            role: "option",
                            "aria-label": "Navigate to {label}",
                            onclick: {
                                let route = route.clone();
                                move |_| on_navigate.call(route.clone())
                            },
                            span { class: "command-palette-item-title", "{label}" }
                            span { class: "command-palette-item-hint", "{hint}" }
                        }
                    }
                }
            }
            div { class: "command-palette-footer",
                button {
                    class: "btn sm ghost",
                    "data-testid": "command-palette-close",
                    "aria-label": "Close command palette",
                    onclick: move |_| on_close.call(()),
                    {crate::i18n::tr("command_palette.close")}
                }
            }
        }
    }
}

/// Translate a protocol-level profile id into the friendly product name
/// that end users see. The raw id remains available in the developer
/// details panel.
fn friendly_profile_label(profile: &str) -> String {
    let key = match profile {
        "minimal_client" => "profile_gate.friendly.minimal_client",
        "kanban_mvp" => "profile_gate.friendly.kanban_mvp",
        "chat_mvp" => "profile_gate.friendly.chat_mvp",
        "full_client" => "profile_gate.friendly.full_client",
        "e2ee_client" => "profile_gate.friendly.e2ee_client",
        _ => "profile_gate.friendly.unknown",
    };
    crate::i18n::tr(key)
}

#[component]
fn ProfileGateNotice(profile: &'static str) -> Element {
    let show_details = use_signal(|| false);
    let title = crate::i18n::tr("profile_gate.title");
    let body = crate::i18n::tr("profile_gate.body");
    let toggle_label = if *show_details.read() {
        crate::i18n::tr("friendly.identifier.hide_technical")
    } else {
        crate::i18n::tr("friendly.identifier.show_technical")
    };
    let friendly = friendly_profile_label(profile);
    let dev_label = crate::i18n::tr("developer.profile.required");
    let mut show_details = show_details;
    rsx! {
        div { class: "timeline", "data-testid": "profile-gate-notice",
            div { class: "event error-banner",
                div { class: "event-head",
                    span { "{title}" }
                    span { "{friendly}" }
                }
                div { class: "space-title", "{body}" }
                div { class: "profile-gate-details",
                    button {
                        r#type: "button",
                        class: "link-button",
                        "data-testid": "profile-gate-toggle-technical",
                        onclick: move |_| {
                            let current = *show_details.read();
                            show_details.set(!current);
                        },
                        "{toggle_label}"
                    }
                    if *show_details.read() {
                        div { class: "muted profile-gate-technical", "data-testid": "profile-gate-technical",
                            div { strong { "{dev_label}: " } code { "{profile}" } }
                            div { "Write controls for this surface are hidden until /server/describe advertises the matching profile requirements." }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn DeferredFeatureGate(feature: &'static str) -> Element {
    rsx! {
        div {
            class: "timeline",
            "data-testid": "deferred-feature-gate",
            "data-feature": "{feature}",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpaceSurface {
    Timeline,
    Board,
    Document,
}

impl SpaceSurface {
    fn top_nav() -> [Self; 3] {
        [Self::Timeline, Self::Board, Self::Document]
    }

    fn short_label(self) -> &'static str {
        match self {
            Self::Timeline => "Timeline",
            Self::Board => "Board",
            Self::Document => "Document",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::Timeline => "Timeline View",
            Self::Board => "Board View",
            Self::Document => "Document View",
        }
    }

    fn icon_name(self) -> &'static str {
        match self {
            Self::Timeline => "timeline",
            Self::Board => "board",
            Self::Document => "file",
        }
    }

    fn preference_value(self) -> &'static str {
        match self {
            Self::Timeline => "timeline",
            Self::Board => "board",
            Self::Document => "document",
        }
    }

    fn from_preference(value: &str) -> Option<Self> {
        match value {
            "timeline" => Some(Self::Timeline),
            "board" => Some(Self::Board),
            "discussion" => Some(Self::Board),
            "document" => Some(Self::Document),
            _ => None,
        }
    }

    fn route(self, space_id: String) -> Route {
        match self {
            Self::Timeline => Route::TimelineSpace { space_id },
            Self::Board => Route::KanbanSpace { space_id },
            Self::Document => Route::DocumentSpace { space_id },
        }
    }

    fn is_available(self, minimal_ready: bool, kanban_ready: bool, full_ready: bool) -> bool {
        match self {
            Self::Timeline => minimal_ready,
            Self::Board => kanban_ready,
            Self::Document => full_ready,
        }
    }
}

fn space_surface_preference_key(space_id: &str) -> String {
    format!("space_surface:{space_id}")
}

fn load_space_surface_preference(
    state_store: &LocalStateStore,
    account_key: &str,
    space_id: &str,
) -> SpaceSurface {
    if account_key.trim().is_empty() {
        return SpaceSurface::Timeline;
    }

    state_store
        .load_private_data(account_key, &space_surface_preference_key(space_id))
        .as_deref()
        .and_then(SpaceSurface::from_preference)
        .unwrap_or(SpaceSurface::Timeline)
}

fn persist_space_surface_preference(
    state_store: &mut LocalStateStore,
    account_key: &str,
    space_id: &str,
    surface: SpaceSurface,
) {
    if account_key.trim().is_empty() {
        return;
    }

    state_store.save_private_data(
        account_key,
        space_surface_preference_key(space_id),
        surface.preference_value(),
    );
}

fn default_flow_id_for_scope(scope_id: &str) -> String {
    scope_id
        .strip_prefix("ck:realm:")
        .or_else(|| scope_id.strip_prefix("ck:space:"))
        .map(|suffix| format!("ck:flow:{suffix}"))
        .unwrap_or_else(|| scope_id.to_owned())
}

fn resolve_space_surface(
    route: &Route,
    state_store: &LocalStateStore,
    account_key: &str,
    _effective_space_id: Option<&str>,
) -> Option<SpaceSurface> {
    match route {
        Route::Space { space_id } => Some(load_space_surface_preference(
            state_store,
            account_key,
            space_id,
        )),
        Route::Timeline | Route::TimelineSpace { .. } | Route::TimelineMessage { .. } => {
            Some(SpaceSurface::Timeline)
        }
        Route::Chat { .. } => None,
        Route::Kanban
        | Route::KanbanSpace { .. }
        | Route::KanbanBoard { .. }
        | Route::KanbanBoardTask { .. }
        | Route::KanbanTask { .. } => Some(SpaceSurface::Board),
        Route::Document | Route::DocumentNew | Route::DocumentSpace { .. } => {
            Some(SpaceSurface::Document)
        }
        Route::SpaceAdmin { .. } | Route::SpaceAdminSection { .. } => None,
        _ => None,
    }
}

fn route_uses_space_context(route: &Route) -> bool {
    matches!(
        route,
        Route::Space { .. }
            | Route::Timeline
            | Route::TimelineSpace { .. }
            | Route::TimelineMessage { .. }
            | Route::Chat { .. }
            | Route::Kanban
            | Route::KanbanSpace { .. }
            | Route::KanbanBoard { .. }
            | Route::KanbanBoardTask { .. }
            | Route::KanbanTask { .. }
            | Route::Document
            | Route::DocumentNew
            | Route::DocumentSpace { .. }
            | Route::SpaceAdmin { .. }
            | Route::SpaceAdminSection { .. }
    )
}

fn route_label(route: &Route) -> &'static str {
    match route {
        Route::Dashboard => "Home",
        Route::Login | Route::AuthCallback => "Login",
        // Route::Space resolves either a Realm or a Space projection
        // depending on the id prefix — see the sidebar two-tier
        // classification. Keep both protocol terms visible until a
        // separate Realm view splits off.
        Route::Space { .. } => "Realm / Space",
        Route::Timeline | Route::TimelineSpace { .. } | Route::TimelineMessage { .. } => {
            "Timeline View"
        }
        Route::Chat { .. } => "Discussion",
        Route::Contacts | Route::ContactsNew => "Contacts",
        Route::Directory => "Search",
        Route::Setup => "New Realm",
        Route::SetupSection { section } => match section.as_str() {
            "realms" | "spaces" => "New Realm",
            "new-space" => "New Space",
            _ => "Setup",
        },
        Route::Settings | Route::SettingsSection { .. } | Route::NotificationsSettings => {
            "Settings"
        }
        Route::VerifyDevice => "Verify Device",
        Route::SpaceAdmin { .. } => "Space Settings",
        Route::SpaceAdminSection { section, .. } => match section.as_str() {
            "members" => "Members Settings",
            "access" => "Access Policy",
            "security" => "Security & MLS",
            "governance" => "Governance",
            "federation" => "Federation Trust",
            "repair" => "Repair & Danger",
            _ => "Space Settings",
        },
        Route::Audit => "Audit",
        Route::Developer => "Developer Tools",
        Route::Kanban
        | Route::KanbanSpace { .. }
        | Route::KanbanBoard { .. }
        | Route::KanbanBoardTask { .. }
        | Route::KanbanTask { .. } => "Board View",
        Route::Notifications => "Notifications",
        Route::Document | Route::DocumentNew | Route::DocumentSpace { .. } => "Document View",
        Route::Call => "Call",
        Route::Recovery => "Recovery",
        Route::Recover => "Restore from backup",
        Route::SettingsDevices => "Devices",
        Route::SettingsDevicesPair => "Pair new device",
        Route::SettingsRecovery => "Recovery passphrase",
        Route::SettingsSecurity => "Key backup",
        Route::Onboarding => "Onboarding",
        Route::Quarantine => "Invite Quarantine",
        Route::Applets => "Applets",
        Route::Agents => "Agents",
        Route::Search => "Search",
    }
}

fn server_key(server_url: &str) -> String {
    normalize_server_url(server_url)
        .trim()
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

fn same_server_url(left: &str, right: &str) -> bool {
    server_key(left) == server_key(right)
}

fn mls_welcome_bootstrap_key(
    base_url: &str,
    session_token: &str,
    account_did: &str,
    device_id: &str,
    space_id: &str,
    e2ee_ready: bool,
    sync_bootstrap_complete: bool,
) -> Option<String> {
    if !e2ee_ready || !sync_bootstrap_complete {
        return None;
    }
    let base = server_key(base_url);
    let session = session_token.trim();
    let actor = account_did.trim();
    let device = device_id.trim();
    let space = space_id.trim();
    if base.is_empty()
        || session.is_empty()
        || actor.is_empty()
        || device.is_empty()
        || space.is_empty()
    {
        return None;
    }

    let mut token_hash = DefaultHasher::new();
    session.hash(&mut token_hash);
    Some(format!(
        "{base}|{actor}|{device}|{space}|{:016x}",
        token_hash.finish()
    ))
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct MlsWelcomeBootstrapOutcome {
    applied: usize,
    backup_id: Option<String>,
}

async fn bootstrap_mls_welcome_for_space(
    base_url: String,
    session_token: String,
    actor_did: String,
    device_id: String,
    space_id: String,
    mut state_store: Signal<LocalStateStore>,
    needs_mls_backup: Signal<bool>,
) -> Result<MlsWelcomeBootstrapOutcome, String> {
    if session_token.trim().is_empty() || space_id.trim().is_empty() {
        return Ok(MlsWelcomeBootstrapOutcome::default());
    }

    let messages = crate::views::helpers::with_authed_api(
        &base_url,
        session_token.clone(),
        |api| async move { api.receive_device_messages().await },
    )
    .await
    .map_err(|error| error.display())?;

    // Runs on every target now that OpenMLS builds + runs under wasm32
    // (the browser uses the in-tree OpenMLS via the `js` feature). Previously
    // the wasm branch discarded the device messages and returned the default
    // outcome, which is why a fresh browser never applied a pending Welcome
    // and showed empty/locked encrypted spaces.
    let messages_value =
        serde_json::to_value(&messages).map_err(|error| format!("device messages: {error}"))?;
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let welcome_outcome = {
        let mut store = state_store.write();
        crate::mls::runtime::apply_welcome_messages_with_device_snapshot(
            &mut store,
            secure_store.as_ref(),
            &space_id,
            &actor_did,
            &device_id,
            &messages_value,
        )
    }
    .map_err(|error| error.user_message())?;

    // Welcomes were present but some/all failed to apply: report (do not fail
    // the boot when others succeeded). A totally-empty welcome set has
    // `failed == 0` and is silent.
    if welcome_outcome.failed > 0 {
        tracing::warn!(
            space = %space_id,
            applied = welcome_outcome.applied,
            failed = welcome_outcome.failed,
            first_error = welcome_outcome.first_error.as_deref().unwrap_or(""),
            "some MLS welcome(s) failed to apply"
        );
    }

    let applied = welcome_outcome.applied;
    if applied == 0 {
        return Ok(MlsWelcomeBootstrapOutcome::default());
    }

    // Applying a Welcome creates/imports the local account MLS secret before
    // the user necessarily sends an encrypted message. Prompt for the recovery
    // passphrase now if the account secret still lacks a server backup.
    crate::components::maybe_flag_mls_backup_after_encrypted_write(
        base_url.clone(),
        session_token.clone(),
        actor_did.clone(),
        needs_mls_backup,
    )
    .await;

    let Some(snapshot) = state_store.read().mls_snapshot_for(&space_id) else {
        return Ok(MlsWelcomeBootstrapOutcome {
            applied,
            backup_id: None,
        });
    };
    let actor_for_backup = actor_did.clone();
    let device_for_backup = device_id.clone();
    let backup_id =
        crate::views::helpers::with_authed_api(&base_url, session_token, |api| async move {
            crate::mls::runtime::upload_mls_snapshot_backup(
                &api,
                &snapshot,
                &actor_for_backup,
                &device_for_backup,
            )
            .await
            .map_err(|err| anyhow::anyhow!(err.user_message()))
        })
        .await
        .map_err(|error| error.display())?;

    Ok(MlsWelcomeBootstrapOutcome {
        applied,
        backup_id: Some(backup_id),
    })
}

fn server_options_for(current_server_url: &str) -> Vec<String> {
    let mut options: Vec<String> = Vec::new();
    for url in [
        normalize_server_url(current_server_url),
        normalize_server_url("https://local.host/"),
    ] {
        if url.is_empty()
            || options
                .iter()
                .any(|existing| same_server_url(existing, &url))
        {
            continue;
        }
        options.push(url);
    }
    options
}

#[derive(Clone, Copy)]
struct ServerSelectionContext {
    base_url: Signal<String>,
    token: Signal<String>,
    sync_cursor: Signal<String>,
    selected_space: Signal<String>,
    spaces: Signal<Vec<SpacePreview>>,
    timeline: Signal<Vec<TimelineEvent>>,
    device_queue: Signal<usize>,
    frontier_state: Signal<String>,
    crypto_state: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    state_store: Signal<LocalStateStore>,
    network_state: Signal<String>,
    last_error: Signal<Option<String>>,
    server_description: Signal<Option<ServerDescription>>,
    server_probe_status: Signal<String>,
    status: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    /// SyncEngine generation counter — bumped to retire the
    /// previous-server engine after the cache wipe + URL repoint.
    sync_generation: Signal<u64>,
}

fn select_server(server_url: String, ctx: ServerSelectionContext) {
    let server_url = normalize_server_url(&server_url);
    let mut base_url = ctx.base_url;
    let mut token = ctx.token;
    let mut sync_cursor = ctx.sync_cursor;
    let mut selected_space = ctx.selected_space;
    let mut spaces = ctx.spaces;
    let mut timeline = ctx.timeline;
    let mut device_queue = ctx.device_queue;
    let mut frontier_state = ctx.frontier_state;
    let mut crypto_state = ctx.crypto_state;
    let mut network_state = ctx.network_state;
    let mut last_error = ctx.last_error;
    let mut server_description = ctx.server_description;
    let mut server_probe_status = ctx.server_probe_status;
    let mut status = ctx.status;
    let mut state_store = ctx.state_store;
    let mut sync_generation = ctx.sync_generation;
    let server_changed = !same_server_url(&base_url(), &server_url);

    // A space cached against the previous server's view is meaningless
    // on the new server (different service DID, different membership,
    // potentially overlapping ck:space ids that point at unrelated
    // rooms). Wipe the account-scoped cache before re-pointing the URL
    // so the next sync starts from a clean slate. Device-level state
    // (local_identity, push_registration) is preserved.
    {
        let mut store = state_store.write();
        store.clear_account_scoped();
        if server_changed {
            store.set_session_grant(None);
            store.set_oidc_tokens(None);
        }
    }
    // Retire the previous server's SyncEngine. The use_effect's
    // base_url tracking would re-spawn anyway, but bumping here ensures
    // the in-flight long-poll exits before the new URL takes over.
    sync_generation.set(sync_generation() + 1);

    if server_changed {
        token.set(String::new());
    }
    let next_token = if server_changed {
        String::new()
    } else {
        token()
    };
    base_url.set(server_url.clone());
    sync_cursor.set("-".to_owned());
    selected_space.set(String::new());
    spaces.set(Vec::new());
    timeline.set(Vec::new());
    device_queue.set(0);
    frontier_state.set("Not loaded".to_owned());
    crypto_state.set("Refresh session for selected server".to_owned());
    server_description.set(None);
    server_probe_status.set("server not probed".to_owned());
    status.set(ConnectionState::Offline.label().to_owned());
    network_state.set("offline".to_owned());
    last_error.set(None);
    persist_config(
        ctx.config_store,
        server_url,
        (ctx.account_did)(),
        (ctx.device_id)(),
        next_token,
    );
}

fn clamp_sidebar_width(width: f64) -> f64 {
    width.clamp(MIN_SIDEBAR_WIDTH, MAX_SIDEBAR_WIDTH)
}

fn load_sidebar_width_preference(state_store: &LocalStateStore) -> f64 {
    state_store
        .load_private_data(UI_PREFERENCES_SCOPE, SIDEBAR_WIDTH_PREFERENCE_KEY)
        .and_then(|value| value.parse::<f64>().ok())
        .map(clamp_sidebar_width)
        .unwrap_or(DEFAULT_SIDEBAR_WIDTH)
}

fn save_sidebar_width_preference(state_store: &mut LocalStateStore, width: f64) {
    state_store.save_private_data(
        UI_PREFERENCES_SCOPE,
        SIDEBAR_WIDTH_PREFERENCE_KEY,
        format!("{:.0}", clamp_sidebar_width(width)),
    );
}

fn load_space_scope_preference(state_store: &LocalStateStore) -> SpaceScopeMode {
    state_store
        .load_private_data(UI_PREFERENCES_SCOPE, SPACE_SCOPE_PREFERENCE_KEY)
        .as_deref()
        .map(SpaceScopeMode::from_preference)
        .unwrap_or(SpaceScopeMode::Exact)
}

fn save_space_scope_preference(state_store: &mut LocalStateStore, mode: SpaceScopeMode) {
    state_store.save_private_data(
        UI_PREFERENCES_SCOPE,
        SPACE_SCOPE_PREFERENCE_KEY,
        mode.preference_value(),
    );
}

async fn refresh_oidc_bearer_for_server(
    principal_server_url: &str,
    actor_did: &str,
    device_id: &str,
    previous: &crate::local_state::OidcTokenBundle,
) -> anyhow::Result<crate::local_state::OidcTokenBundle> {
    let refresh_token = previous
        .refresh_token
        .as_deref()
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("OIDC bundle has no refresh_token"))?;
    let auth_server_url = crate::coauth::resolve_principal_auth_server_url(principal_server_url)
        .await
        .map_err(|error| anyhow::anyhow!("resolve auth server: {error}"))?;
    let coauth = crate::coauth::CoauthApi::new(&auth_server_url)?;
    let topology = coauth.inspect_topology().await?;
    let plan = crate::coauth::build_oidc_code_exchange_plan(
        &topology,
        principal_server_url,
        actor_did,
        device_id,
    )?;
    let response = coauth
        .refresh_oidc_tokens(&plan.token_endpoint, &plan.client_id, refresh_token)
        .await?;
    Ok(crate::oidc::lifecycle::apply_refresh_response(
        previous, &response,
    ))
}

async fn reissue_development_session(
    principal_server_url: &str,
    actor_did: &str,
    device_id: &str,
) -> Option<crate::models::DevLoginResponse> {
    if !can_attempt_development_session_reissue(principal_server_url, actor_did, device_id) {
        return None;
    }
    let api = CokretApi::new(principal_server_url).ok()?;
    let description = api.describe().await.ok()?;
    if !description.development_mode {
        return None;
    }
    api.dev_login(actor_did.trim(), device_id.trim()).await.ok()
}

/// The single source of truth for re-minting the principal bearer.
///
/// Registered once at the app root and reached everywhere through
/// [`crate::session::refresh_current_bearer`]. Reads the live
/// base/actor/device from their signals (so it always targets the active
/// session), tries the OIDC `refresh_token` path first, then the
/// session-grant exchange. On success it writes the fresh bearer into the
/// `token` signal and persisted config and returns it; on definitive
/// failure it returns `None` and the caller routes to login.
///
/// Concurrency is handled by `crate::session`: callers coalesce onto one
/// in-flight invocation, so this never runs twice in parallel for a single
/// rollover.
async fn remint_principal_bearer(
    base_url: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    mut state_store: Signal<LocalStateStore>,
    mut token: Signal<String>,
    config_store: Signal<LocalConfigStore>,
) -> Option<String> {
    let base = base_url();
    let actor = account_did();
    let device = device_id();

    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let oidc_bundle = {
        let store = state_store.read();
        store.load_oidc_tokens_with_secure_store(&actor, secure_store.as_ref())
    };
    if let Some(bundle) = oidc_bundle
        && crate::oidc::lifecycle::has_refresh_token(&bundle)
        && let Ok(next) = refresh_oidc_bearer_for_server(&base, &actor, &device, &bundle).await
    {
        // Abandon if the user switched servers while the refresh was in
        // flight — committing here would resurrect the old server's
        // credentials over the freshly selected session.
        if !same_server_url(&base, &base_url()) {
            return None;
        }
        let access_token = next.access_token.clone();
        state_store.write().set_oidc_tokens_with_secure_store(
            Some(next),
            &actor,
            secure_store.as_ref(),
        );
        token.set(access_token.clone());
        persist_config(
            config_store,
            base.clone(),
            actor.clone(),
            device.clone(),
            access_token.clone(),
        );
        return Some(access_token);
    }

    let prepared = {
        let mut store = state_store.write();
        crate::session_refresh::prepare_refresh_for_server_after_unauthorized(&mut store, &base)
    };
    let outcome = match prepared {
        crate::session_refresh::RefreshPrepared::Done(outcome) => outcome,
        crate::session_refresh::RefreshPrepared::Ready { grant, proof } => {
            let result = crate::session_refresh::exchange_refresh(&grant, &proof).await;
            // Same server-switch guard as the OIDC path: don't write the
            // old server's grant outcome onto a session that just moved.
            if !same_server_url(&base, &base_url()) {
                return None;
            }
            let mut store = state_store.write();
            crate::session_refresh::commit_refresh(&mut store, result)
        }
    };
    match outcome {
        crate::session_refresh::RefreshOutcome::Refreshed { access_token, .. } => {
            token.set(access_token.clone());
            persist_config(
                config_store,
                base.clone(),
                actor.clone(),
                device.clone(),
                access_token.clone(),
            );
            Some(access_token)
        }
        crate::session_refresh::RefreshOutcome::LoginRequired { reason } => {
            crate::session::invalidate_current_session(reason);
            None
        }
        _ => {
            if let Some(session) = reissue_development_session(&base, &actor, &device).await {
                if !same_server_url(&base, &base_url()) {
                    return None;
                }
                let access_token = session.access_token.clone();
                let actor = if session.actor.trim().is_empty() {
                    actor
                } else {
                    session.actor.clone()
                };
                let device = if session.device_id.trim().is_empty() {
                    device
                } else {
                    session.device_id.clone()
                };
                token.set(access_token.clone());
                persist_config(config_store, base, actor, device, access_token.clone());
                return Some(access_token);
            }
            None
        }
    }
}

#[derive(Clone, Copy)]
struct ConnectContext {
    status: Signal<String>,
    sync_cursor: Signal<String>,
    token: Signal<String>,
    account_did: Signal<String>,
    selected_space: Signal<String>,
    spaces: Signal<Vec<SpacePreview>>,
    timeline: Signal<Vec<TimelineEvent>>,
    device_queue: Signal<usize>,
    frontier_state: Signal<String>,
    crypto_state: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    state_store: Signal<LocalStateStore>,
    network_state: Signal<String>,
    last_error: Signal<Option<String>>,
    server_description: Signal<Option<ServerDescription>>,
    server_probe_status: Signal<String>,
    /// A4a: shared UI theme signal so `/sync` can hydrate the theme
    /// from the remote `client.ui` account-data payload right after
    /// session bootstrap. Stub field — wire-up is tracked under A4a.
    theme: Signal<String>,
    /// SyncEngine generation counter. Bumped when `connect()` detects
    /// the canonical actor has changed since the last persisted run
    /// (account swap on the same device) so any in-flight engine for
    /// the previous account exits before applying its response.
    sync_generation: Signal<u64>,
    /// Set when the explicit bootstrap/manual connect attempt has completed.
    /// The background SyncEngine waits for this so it does not race the
    /// first full account-subscribe snapshot on the same render.
    sync_bootstrap_complete: Signal<bool>,
    session_boot_state: Signal<SessionBootState>,
    navigator: Navigator,
}

fn redirect_to_login(navigator: Navigator) {
    let _ = navigator.push(Route::Login);
}

fn connect(base: String, actor: String, device: String, ctx: ConnectContext) {
    let device = normalize_device_id(&device);
    spawn(async move {
        let mut sync_bootstrap_complete = ctx.sync_bootstrap_complete;
        let mut status = ctx.status;
        let mut sync_cursor = ctx.sync_cursor;
        let mut token = ctx.token;
        let mut account_did = ctx.account_did;
        let mut selected_space = ctx.selected_space;
        let mut spaces = ctx.spaces;
        let mut timeline = ctx.timeline;
        let mut device_queue = ctx.device_queue;
        let mut frontier_state = ctx.frontier_state;
        let mut crypto_state = ctx.crypto_state;
        let config_store = ctx.config_store;
        let mut state_store = ctx.state_store;
        let mut network_state = ctx.network_state;
        let mut last_error = ctx.last_error;
        let mut server_description = ctx.server_description;
        let mut server_probe_status = ctx.server_probe_status;
        let mut theme = ctx.theme;
        let navigator = ctx.navigator;
        let mut session_boot_state = ctx.session_boot_state;

        session_boot_state.set(if token().trim().is_empty() {
            SessionBootState::Restoring
        } else {
            SessionBootState::Checking
        });
        status.set(ConnectionState::Loading.label().to_owned());
        network_state.set("reconnecting".to_owned());
        last_error.set(None);
        match CokretApi::new(&base) {
            Ok(api) => {
                // Probe `/server/describe` for status text, but treat failure
                // as non-fatal: a transient describe error (CORS preflight,
                // server warming up, brief 5xx) must not block the sync below
                // — otherwise an existing session with cached/server-side
                // spaces silently renders "No spaces loaded" until the user
                // manually retries.
                let description = match api.describe().await {
                    Ok(description) => {
                        let missing = description.missing_v1_principal_server_requirements();
                        if !missing.is_empty() {
                            let message =
                                format!("server describe rejected: missing {}", missing.join(", "));
                            status.set(format!("{}: {message}", ConnectionState::Error.label()));
                            network_state.set("offline".to_owned());
                            last_error.set(Some(message.clone()));
                            server_probe_status.set(message);
                            server_description.set(None);
                            session_boot_state.set(if token().trim().is_empty() {
                                SessionBootState::Unauthenticated
                            } else {
                                SessionBootState::Authenticated
                            });
                            sync_bootstrap_complete.set(true);
                            return;
                        }
                        status.set(format!(
                            "{}: {} / {}",
                            ConnectionState::Online.label(),
                            description.service_type,
                            description.protocol_version
                        ));
                        network_state.set("online".to_owned());
                        server_probe_status.set(format!(
                            "server describe loaded: {} / {}",
                            description.service_type, description.protocol_version
                        ));
                        // Round 4 — cache the advertised trust_domain so
                        // downstream signing flows (cross_signing.publish,
                        // S2S transcripts) can pull a canonical
                        // value off local state without an extra round
                        // trip. Cleared when describe fails so a stale
                        // domain can't leak into the next flow.
                        {
                            let mut store = state_store.write();
                            let mut snapshot = store.load();
                            // `TypedTrustDomainId` enforces a non-empty
                            // `ck:trust_domain:<scope>` shape at deserialize
                            // time, so the previous "is_empty" guard is
                            // structurally impossible. Always cache.
                            snapshot.server_trust_domain =
                                Some(description.trust_domain.as_str().to_owned());
                            store.save(snapshot);
                        }
                        server_description.set(Some(description.clone()));
                        Some(description)
                    }
                    Err(error) => {
                        status.set(format!(
                            "{}: describe failed: {error}; trying sync",
                            ConnectionState::Reconnecting.label()
                        ));
                        network_state.set("reconnecting".to_owned());
                        last_error.set(Some(format!("describe: {error}")));
                        server_probe_status.set(format!("server describe failed: {error}"));
                        server_description.set(None);
                        None
                    }
                };

                let mut session_token = token();
                if session_token.trim().is_empty() {
                    if let Some(refreshed) = crate::session::refresh_current_bearer().await {
                        session_token = refreshed;
                        session_boot_state.set(SessionBootState::Checking);
                    } else {
                        let probe_label = description
                            .as_ref()
                            .map(|d| format!("{} / {}", d.service_type, d.protocol_version))
                            .unwrap_or_else(|| "server probe unavailable".to_owned());
                        status.set(format!("Refreshed: {probe_label}; sign-in required"));
                        network_state.set("online".to_owned());
                        sync_cursor.set("-".to_owned());
                        spaces.set(Vec::new());
                        timeline.set(Vec::new());
                        device_queue.set(0);
                        crypto_state.set("No authenticated session".to_owned());
                        persist_config(
                            config_store,
                            base.clone(),
                            actor.clone(),
                            device.clone(),
                            String::new(),
                        );
                        session_boot_state.set(SessionBootState::Unauthenticated);
                        sync_bootstrap_complete.set(true);
                        return;
                    }
                }

                let mut authed = api.clone().with_bearer(session_token.clone());
                // Resolve the canonical actor DID from `/account/me`. Three
                // outcomes:
                //   1. Ok with non-empty DID -> use it as canonical_actor.
                //   2. Err that looks like auth expiry -> wipe session, bounce to login. The
                //      session is provably dead.
                //   3. Anything else (Ok with empty DID, transient 5xx, parse error, network
                //      failure) -> fall back to the locally stored actor, log a diagnostic to
                //      last_error so the sidebar/status surface can show it, and keep going so sync
                //      still has a chance to populate spaces.
                let canonical_actor = match authed.account_me().await {
                    Ok(account) if !account.did.trim().is_empty() => account.did,
                    Ok(_) => {
                        last_error.set(Some(
                            "account_me: server returned empty actor DID; reusing local actor"
                                .to_owned(),
                        ));
                        actor.clone()
                    }
                    Err(error) if is_auth_expired_error(&error) => {
                        if let Some(refreshed) = crate::session::refresh_current_bearer().await {
                            session_token = refreshed;
                            authed = api.clone().with_bearer(session_token.clone());
                            match authed.account_me().await {
                                Ok(account) if !account.did.trim().is_empty() => account.did,
                                Ok(_) => {
                                    last_error.set(Some(
                                        "account_me: refreshed session returned empty actor DID; reusing local actor"
                                            .to_owned(),
                                    ));
                                    actor.clone()
                                }
                                Err(retry_error) if !is_auth_expired_error(&retry_error) => {
                                    last_error.set(Some(format!("account_me: {retry_error}")));
                                    actor.clone()
                                }
                                Err(_) => {
                                    token.set(String::new());
                                    persist_config(
                                        config_store,
                                        base.clone(),
                                        actor.clone(),
                                        device.clone(),
                                        String::new(),
                                    );
                                    sync_cursor.set("-".to_owned());
                                    selected_space.set(String::new());
                                    spaces.set(Vec::new());
                                    timeline.set(Vec::new());
                                    device_queue.set(0);
                                    crypto_state.set("Session expired".to_owned());
                                    status.set("Session expired; sign in again".to_owned());
                                    network_state.set("online".to_owned());
                                    last_error
                                        .set(Some("auth_expired: session expired".to_owned()));
                                    session_boot_state.set(SessionBootState::Unauthenticated);
                                    redirect_to_login(navigator);
                                    sync_bootstrap_complete.set(true);
                                    return;
                                }
                            }
                        } else {
                            token.set(String::new());
                            persist_config(
                                config_store,
                                base.clone(),
                                actor.clone(),
                                device.clone(),
                                String::new(),
                            );
                            sync_cursor.set("-".to_owned());
                            selected_space.set(String::new());
                            spaces.set(Vec::new());
                            timeline.set(Vec::new());
                            device_queue.set(0);
                            crypto_state.set("Session expired".to_owned());
                            status.set("Session expired; sign in again".to_owned());
                            network_state.set("online".to_owned());
                            last_error.set(Some("auth_expired: session expired".to_owned()));
                            session_boot_state.set(SessionBootState::Unauthenticated);
                            redirect_to_login(navigator);
                            sync_bootstrap_complete.set(true);
                            return;
                        }
                    }
                    Err(error) => {
                        last_error.set(Some(format!("account_me: {error}")));
                        actor.clone()
                    }
                };
                if canonical_actor != actor {
                    // Account changed since the last persisted run (the
                    // server's `/account/me` disagrees with our cached
                    // actor). When the previous actor was non-empty this
                    // means a different human is signing in on the same
                    // device — every account-scoped record (projections,
                    // drafts, anchor views, read markers, remarks, and the
                    // previous identity's session grant + OIDC bundle) is
                    // someone else's data and must be wiped before the sync
                    // below repopulates the store. `adopt_account_scope`
                    // performs the wipe and stamps the new owner so a later
                    // login recognises the scope. Device-level state
                    // (local_identity, push_registration, DPoP key) is
                    // preserved.
                    if !actor.trim().is_empty() {
                        let mut store = state_store.write();
                        store.adopt_account_scope(&canonical_actor);
                        // Also wipe the in-memory UI signals so the
                        // sidebar can't paint the previous actor's
                        // spaces between this point and the sync that's
                        // about to run.
                        drop(store);
                        spaces.set(Vec::new());
                        timeline.set(Vec::new());
                        selected_space.set(String::new());
                        sync_cursor.set("-".to_owned());
                        device_queue.set(0);
                        // Retire the previous-account SyncEngine so its
                        // in-flight long-poll doesn't write back into
                        // the freshly-wiped state.
                        let mut sync_generation = ctx.sync_generation;
                        sync_generation.set(sync_generation() + 1);
                    } else {
                        // No previous identity to displace — just record
                        // who the scope now belongs to (don't wipe: a
                        // just-established grant could be dropped).
                        state_store
                            .write()
                            .stamp_account_scope_owner(&canonical_actor);
                    }
                    account_did.set(canonical_actor.clone());
                } else {
                    // Actor unchanged — record the scope owner so a later
                    // login for a different identity is recognised and the
                    // stale scope is reset.
                    state_store
                        .write()
                        .stamp_account_scope_owner(&canonical_actor);
                }
                persist_config(
                    config_store,
                    base.clone(),
                    canonical_actor.clone(),
                    device.clone(),
                    session_token,
                );
                crypto_state.set(format!("session token loaded for {device}"));

                // `connect()` always issues a full sync (`since=None`) —
                // it's invoked on app boot, the mobile Refresh button,
                // and server switches, all of which represent
                // "re-establish the world from scratch". The SyncEngine
                // (see crate::sync_engine) owns the long-poll loop that
                // threads the cursor for incremental deltas.
                let sync_result = match authed.account_subscribe_snapshot(None).await {
                    Ok(sync) => Ok(sync),
                    Err(error) if is_auth_expired_error(&error) => {
                        if let Some(refreshed) = crate::session::refresh_current_bearer().await {
                            session_token = refreshed;
                            authed = api.clone().with_bearer(session_token.clone());
                            authed.account_subscribe_snapshot(None).await
                        } else {
                            Err(error)
                        }
                    }
                    Err(error) => Err(error),
                };
                match sync_result {
                    Ok(sync) => {
                        {
                            let mut store = state_store.write();
                            store.save_sync_cursor(sync.cursor.clone());
                            // Server-authoritative reconcile for top-level
                            // Realm membership. Nested Space containers are
                            // not always returned as top-level sync entries,
                            // so keep local container projections while their
                            // home Realm is still present.
                            let server_set: BTreeSet<String> =
                                sync.spaces.keys().cloned().collect();
                            let keep_set = full_sync_projection_keep_set(
                                &server_set,
                                &store.load().space_projections,
                            );
                            let pruned = store.retain_space_projections(|id| keep_set.contains(id));
                            if !pruned.is_empty() {
                                tracing::info!(
                                    pruned_count = pruned.len(),
                                    "full sync pruned stale space projections",
                                );
                            }
                            // Explicit `left_spaces` deltas — soland emits
                            // these on incremental syncs too; for full sync
                            // they're redundant with `retain_space_projections`
                            // above but cheap to apply when soland evolves
                            // to send them on full sync.
                            for left_id in &sync.left_spaces {
                                store.forget_space(left_id);
                            }
                            for (id, body) in &sync.spaces {
                                store.save_space_projection(id.clone(), body.clone());
                                // Thread the per-Space Anchor view (frontier /
                                // leaves / state_root / bottom cells) into the
                                // local store so Move builders + UI can read
                                // it. Bodies without an `anchor_view` field
                                // produce a Default view (empty frontier =
                                // sentinel) so we still record presence.
                                let view =
                                    crate::local_state::LocalAnchorView::from_sync_body(body);
                                store.set_anchor_view(id.clone(), view);
                                store.ingest_move_event_states(id, body);
                            }
                            // Hydrate Space remarks from the actor-private
                            // account_data projection (spec
                            // client-preferences.md §3.7). soland keys these
                            // entries by `ck.contacts.space.<space_id>` and
                            // returns the canonical SpaceRemark JSON in
                            // `content`. Entries for other namespaces are
                            // ignored here.
                            let notification_projection = sync
                                .account_data
                                .iter()
                                .filter(|entry| {
                                    crate::views::notifications::is_notification_account_data(entry)
                                })
                                .cloned()
                                .collect::<Vec<_>>();
                            if !notification_projection.is_empty() {
                                store.save_notification_projection(notification_projection);
                            }
                            for entry in &sync.account_data {
                                let Some(data_type) =
                                    entry.get("data_type").and_then(serde_json::Value::as_str)
                                else {
                                    continue;
                                };
                                // A4a — hydrate `client.ui` theme from
                                // the remote payload. Cross-device wins:
                                // when remote carries a valid theme that
                                // differs from the local cached value
                                // we update the UI Signal +
                                // LocalConfigStore synchronously.
                                if data_type == "client.ui" {
                                    if let Some(content) = entry.get("content") {
                                        let local_theme = theme();
                                        if let Some(remote_theme) =
                                            crate::account_data::merge_client_ui_theme(
                                                &local_theme,
                                                content,
                                            )
                                        {
                                            theme.set(remote_theme.clone());
                                            store.save_private_data(
                                                &account_did(),
                                                "theme",
                                                remote_theme,
                                            );
                                        }
                                        if let Some(avatar_blob_ref) =
                                            crate::account_data::avatar_blob_ref_from_client_ui(
                                                content,
                                            )
                                        {
                                            store.save_private_data(
                                                &account_did(),
                                                "avatar_blob_ref",
                                                avatar_blob_ref,
                                            );
                                        } else if crate::account_data::avatar_blob_ref_tombstoned_from_client_ui(content) {
                                            store.save_private_data(
                                                &account_did(),
                                                "avatar_blob_ref",
                                                "",
                                            );
                                        }
                                    }
                                    continue;
                                }
                                if data_type == "ck.account.blocklist" {
                                    let Some(content) = entry.get("content") else {
                                        continue;
                                    };
                                    match crate::account_data::blocklist_entries_from_account_data(
                                        content,
                                    ) {
                                        Ok(entries) => {
                                            store.set_client_blocklist(entries);
                                        }
                                        Err(error) => {
                                            tracing::warn!(
                                                "ignoring malformed ck.account.blocklist account_data: {error}"
                                            );
                                        }
                                    }
                                    continue;
                                }
                                if let Some(actor_did) =
                                    crate::account_data::actor_did_from_contact_remark_key(
                                        data_type,
                                    )
                                {
                                    let Some(content) = entry.get("content") else {
                                        continue;
                                    };
                                    match serde_json::from_value::<crate::account_data::ContactRemark>(
                                        content.clone(),
                                    ) {
                                        Ok(remark) => {
                                            store.set_contact_remark(actor_did.to_owned(), remark);
                                        }
                                        Err(error) => {
                                            tracing::warn!(
                                                "ignoring malformed Contact remark for {actor_did}: {error}"
                                            );
                                        }
                                    }
                                    continue;
                                }
                                let Some(space_id) =
                                    crate::account_data::space_id_from_space_remark_key(data_type)
                                else {
                                    continue;
                                };
                                let Some(content) = entry.get("content") else {
                                    continue;
                                };
                                match serde_json::from_value::<crate::account_data::SpaceRemark>(
                                    content.clone(),
                                ) {
                                    Ok(remark) => {
                                        store.set_space_remark(space_id.to_owned(), remark);
                                    }
                                    Err(error) => {
                                        tracing::warn!(
                                            "ignoring malformed Space remark for {space_id}: {error}"
                                        );
                                    }
                                }
                            }
                            // Force a synchronous flush so that if the user
                            // refreshes the tab immediately after a successful
                            // sync the next mount's `initial_state_store.load()`
                            // sees the new projections + cursor. Without this
                            // we rely on the per-call `flush()` inside each
                            // setter (which is best-effort on wasm) and on the
                            // WriteGuard's Drop, neither of which is guaranteed
                            // before the browser tears down the page.
                            if let Err(error) = store.flush() {
                                last_error.set(Some(format!("state_store flush failed: {error}")));
                            }
                        }
                        let synced_timeline = timeline_events_from_sync_spaces(&sync.spaces);
                        // `spaces` is derived from `state_store.space_projections`
                        // by a use_effect in `RouterView` — we don't set it
                        // here. Read a reconciled snapshot for status text
                        // and selected_space bookkeeping only.
                        let reconciled = space_previews_from_sync_spaces(
                            &state_store.read().load().space_projections,
                        );
                        if reconciled.is_empty() {
                            status.set(ConnectionState::Empty.label().to_owned());
                        } else {
                            status.set(format!(
                                "{}: synced {} space(s)",
                                ConnectionState::Online.label(),
                                reconciled.len()
                            ));
                        }
                        let first_space = reconciled.first().map(|space| space.space_id.clone());
                        let current = selected_space();
                        let trimmed = current.trim();
                        let needs_reset =
                            trimmed.is_empty() || !reconciled.iter().any(|s| s.space_id == trimmed);
                        if needs_reset {
                            selected_space.set(first_space.unwrap_or_default());
                        }
                        timeline.set(synced_timeline);
                        device_queue.set(sync.to_device.len());
                        sync_cursor.set(sync.cursor);
                    }
                    Err(error) if is_auth_expired_error(&error) => {
                        token.set(String::new());
                        persist_config(
                            config_store,
                            base.clone(),
                            canonical_actor.clone(),
                            device.clone(),
                            String::new(),
                        );
                        sync_cursor.set("-".to_owned());
                        selected_space.set(String::new());
                        spaces.set(Vec::new());
                        timeline.set(Vec::new());
                        device_queue.set(0);
                        crypto_state.set("Session expired".to_owned());
                        status.set("Session expired; sign in again".to_owned());
                        network_state.set("online".to_owned());
                        last_error.set(Some("auth_expired: session expired".to_owned()));
                        session_boot_state.set(SessionBootState::Unauthenticated);
                        redirect_to_login(navigator);
                        sync_bootstrap_complete.set(true);
                        return;
                    }
                    Err(error) => {
                        // Sync failed — the `spaces` Signal already
                        // reflects what's in the local store via the
                        // derive effect; just refresh status text and
                        // make sure selected_space points at something
                        // still in scope.
                        let fallback = space_previews_from_sync_spaces(
                            &state_store.read().load().space_projections,
                        );
                        if fallback.is_empty() {
                            status.set(format!(
                                "{}: sync failed: {error}",
                                ConnectionState::Reconnecting.label()
                            ));
                        } else {
                            status.set(
                                "Refreshed: sync unavailable, showing cached/local Space list"
                                    .to_owned(),
                            );
                        }
                        let first_space = fallback.first().map(|space| space.space_id.clone());
                        let current = selected_space();
                        let trimmed = current.trim();
                        let needs_reset =
                            trimmed.is_empty() || !fallback.iter().any(|s| s.space_id == trimmed);
                        if needs_reset {
                            selected_space.set(first_space.unwrap_or_default());
                        }
                        last_error.set(Some(format!("sync: {error}")));
                    }
                }
                let events_result = match authed.events_describe().await {
                    Ok(events) => Ok(events),
                    Err(error) if is_auth_expired_error(&error) => {
                        if let Some(refreshed) = crate::session::refresh_current_bearer().await {
                            session_token = refreshed;
                            authed = api.clone().with_bearer(session_token.clone());
                            authed.events_describe().await
                        } else {
                            Err(error)
                        }
                    }
                    Err(error) => Err(error),
                };
                match events_result {
                    Ok(events) => {
                        if let Some(frontier) = frontier_label(&events.frontier) {
                            frontier_state.set(frontier);
                        }
                    }
                    Err(error) if is_auth_expired_error(&error) => {
                        // Same definitive-session-loss handling as the sync 401
                        // branch above. Without this, an expired token that
                        // passed sync (because sync was served from a cache or
                        // a misrouted path) could silently leave the user with
                        // a stale frontier and no session-expiry redirect.
                        token.set(String::new());
                        persist_config(
                            config_store,
                            base.clone(),
                            canonical_actor.clone(),
                            device.clone(),
                            String::new(),
                        );
                        sync_cursor.set("-".to_owned());
                        selected_space.set(String::new());
                        spaces.set(Vec::new());
                        timeline.set(Vec::new());
                        device_queue.set(0);
                        crypto_state.set("Session expired".to_owned());
                        status.set("Session expired; sign in again".to_owned());
                        network_state.set("online".to_owned());
                        last_error.set(Some("auth_expired: session expired".to_owned()));
                        session_boot_state.set(SessionBootState::Unauthenticated);
                        redirect_to_login(navigator);
                        sync_bootstrap_complete.set(true);
                        return;
                    }
                    Err(error) => {
                        last_error.set(Some(format!("events_describe: {error}")));
                    }
                }
            }
            Err(error) => {
                status.set(format!(
                    "{}: invalid URL: {error}",
                    ConnectionState::Error.label()
                ));
                network_state.set("offline".to_owned());
                last_error.set(Some(format!("invalid URL: {error}")));
                server_probe_status.set(format!("server describe skipped: invalid URL: {error}"));
                server_description.set(None);
            }
        }
        session_boot_state.set(if token().trim().is_empty() {
            SessionBootState::Unauthenticated
        } else {
            SessionBootState::Authenticated
        });
        sync_bootstrap_complete.set(true);
    });
}

fn copy_text_to_clipboard(text: &str) {
    let Ok(encoded) = serde_json::to_string(text) else {
        return;
    };
    let script = format!(
        r#"(async () => {{
    const text = {encoded};
    if (navigator.clipboard && window.isSecureContext) {{
        await navigator.clipboard.writeText(text);
        return true;
    }}
    const node = document.createElement("textarea");
    node.value = text;
    node.setAttribute("readonly", "");
    node.style.position = "fixed";
    node.style.left = "-9999px";
    document.body.appendChild(node);
    node.select();
    const copied = document.execCommand("copy");
    document.body.removeChild(node);
    return copied;
}})()"#
    );
    let _ = document::eval(&script);
}

pub fn timeline_events_from_sync_spaces(spaces: &BTreeMap<String, Value>) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    for (id, body) in spaces {
        let id_label = short_protocol_id(id);
        let mut summary_event = TimelineEvent::system_notice(
            format!("summary-{id}"),
            "server",
            format!(
                "{id_label}: {}",
                body["summary"]["summary"]
                    .as_str()
                    .unwrap_or("No summary available")
            ),
        );
        summary_event.space_id = Some(id.clone());
        events.push(summary_event);

        let Some(timeline_events) = body
            .get("timeline")
            .and_then(|timeline| timeline.get("events"))
            .and_then(Value::as_array)
        else {
            continue;
        };

        for event in timeline_events {
            if event.get("kind").and_then(Value::as_str) != Some("ck.message.create") {
                continue;
            }
            let event_id = event
                .get("event_id")
                .and_then(Value::as_str)
                .unwrap_or("event:unknown")
                .to_owned();
            let content = event.get("content").unwrap_or(&Value::Null);
            let body = content
                .get("body")
                .and_then(Value::as_str)
                .or_else(|| event.get("body").and_then(Value::as_str))
                .or_else(|| {
                    content
                        .get("blocks")
                        .and_then(Value::as_array)
                        .and_then(|blocks| blocks.first())
                        .and_then(|block| block.get("text"))
                        .and_then(Value::as_str)
                })
                .unwrap_or("[message]")
                .to_owned();
            events.push(TimelineEvent {
                space_id: Some(id.clone()),
                id: event_id.clone(),
                sender: event
                    .get("sender")
                    .and_then(Value::as_str)
                    .unwrap_or("did:web:unknown")
                    .to_owned(),
                sender_display: event
                    .get("sender")
                    .and_then(Value::as_str)
                    .unwrap_or("server")
                    .to_owned(),
                body,
                timestamp: event
                    .get("created_at")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                thread_id: event
                    .get("thread_id")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                event_id: Some(event_id),
                ..TimelineEvent::default()
            });
        }
    }
    events
}

pub fn merge_timeline_events(
    current: &[TimelineEvent],
    incoming: Vec<TimelineEvent>,
) -> Vec<TimelineEvent> {
    let mut merged = current.to_vec();
    for event in incoming {
        if let Some(existing) = merged.iter_mut().find(|existing| existing.id == event.id) {
            *existing = event;
        } else {
            merged.push(event);
        }
    }
    merged
}

fn frontier_label(frontier: &serde_json::Value) -> Option<String> {
    if let Some(items) = frontier.as_array() {
        return items
            .iter()
            .filter_map(|item| item.as_str())
            .next()
            .map(ToOwned::to_owned);
    }
    frontier
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// The App component installs a default push-token provider on
    /// first render so `device-summary` never
    /// shows the `"no PushTokenProvider installed"` warning in
    /// production. The helper is idempotent (`OnceLock` inside
    /// `set_push_token_provider`) — calling it twice in the same
    /// process is safe.
    #[test]
    fn ensure_default_push_token_provider_installs_a_provider_and_is_idempotent() {
        // Provider state is process-wide via `OnceLock`. We don't
        // assert which concrete provider was installed (varies by
        // target_arch / target_os); we only assert the slot becomes
        // populated and stays populated across a second call.
        super::ensure_default_push_token_provider();
        let after_first = crate::push::push_token_provider();
        assert!(
            after_first.is_some(),
            "first ensure call must install a provider"
        );
        super::ensure_default_push_token_provider();
        assert!(
            crate::push::push_token_provider().is_some(),
            "second ensure call must keep the provider installed"
        );
    }

    fn oidc_bundle(access_token: &str, expires_at_unix: Option<i64>) -> OidcTokenBundle {
        OidcTokenBundle {
            access_token: access_token.to_owned(),
            refresh_token: Some("rt-test".to_owned()),
            token_type: "Bearer".to_owned(),
            expires_at_unix,
            id_token: None,
            scope: None,
            audience: Some("https://local.host".to_owned()),
            stored_at: chrono::Utc::now(),
        }
    }

    fn session_grant(session_expires_in: i64, grant_expires_in: i64) -> PersistedSessionGrant {
        let now = chrono::Utc::now();
        PersistedSessionGrant {
            grant_jwt: "grant.jwt".to_owned(),
            session_private_key_pem: "PEM".to_owned(),
            grant_id: "grant-1".to_owned(),
            audience: "https://local.host/api".to_owned(),
            principal_id: "did:web:alice.example".to_owned(),
            device_id: "ck:device:01964137-0000-7000-8000-000000000001".to_owned(),
            principal_server_url: "https://local.host".to_owned(),
            session_grant_exchange_path: "_cokret/gate/auth/session-grant/exchange".to_owned(),
            grant_expires_at: Some(now + chrono::Duration::seconds(grant_expires_in)),
            session_expires_at: Some(now + chrono::Duration::seconds(session_expires_in)),
            stored_at: now,
        }
    }

    #[test]
    fn development_session_reissue_is_local_did_and_protocol_device_only() {
        let actor = "did:web:alice.example";
        let device = "ck:device:01964137-0000-7000-8000-000000000001";

        assert!(can_attempt_development_session_reissue(
            "https://local.host",
            actor,
            device
        ));
        assert!(can_attempt_development_session_reissue(
            "http://127.0.0.1:8787",
            actor,
            device
        ));
        assert!(!can_attempt_development_session_reissue(
            "https://principal.example",
            actor,
            device
        ));
        assert!(!can_attempt_development_session_reissue(
            "https://local.host",
            "alice",
            device
        ));
        assert!(!can_attempt_development_session_reissue(
            "https://local.host",
            actor,
            "dev_yougen"
        ));
    }

    #[test]
    fn bootstrap_development_reissue_requires_matching_account_scope_owner() {
        let actor = "did:web:alice.example";
        let device = "ck:device:01964137-0000-7000-8000-000000000001";
        let mut state = ClientLocalState::default();

        assert!(!can_bootstrap_with_development_session_reissue(
            &state,
            "https://local.host",
            actor,
            device
        ));

        state.account_scope_owner = Some(actor.to_owned());
        assert!(can_bootstrap_with_development_session_reissue(
            &state,
            "https://local.host",
            actor,
            device
        ));

        state.account_scope_owner = Some("did:web:bob.example".to_owned());
        assert!(!can_bootstrap_with_development_session_reissue(
            &state,
            "https://local.host",
            actor,
            device
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn isolated_store(tag: &str) -> LocalStateStore {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("yougen-app-{tag}-{stamp}.json"));
        LocalStateStore::with_path(path)
    }

    #[test]
    fn boot_session_token_uses_fresh_oidc_access_token() {
        let now = 1_000;
        let state = ClientLocalState {
            oidc_tokens: Some(oidc_bundle("sx-fresh", Some(now + 120))),
            ..Default::default()
        };
        let config = ClientConfig::from_fields(
            "https://local.host",
            "did:web:alice.example",
            "ck:device:01964137-0000-7000-8000-000000000001",
            "legacy-token",
        );

        assert_eq!(
            initial_session_token_from_state(&state, &config, now),
            "sx-fresh"
        );
    }

    #[test]
    fn boot_session_token_ignores_expired_oidc_access_token() {
        let now = 1_000;
        let state = ClientLocalState {
            oidc_tokens: Some(oidc_bundle("sx-expired", Some(now - 1))),
            ..Default::default()
        };
        let config = ClientConfig::from_fields(
            "https://local.host",
            "did:web:alice.example",
            "ck:device:01964137-0000-7000-8000-000000000001",
            "legacy-token",
        );

        assert_eq!(initial_session_token_from_state(&state, &config, now), "");
    }

    #[test]
    fn boot_session_token_ignores_nearly_expired_oidc_access_token() {
        let now = 1_000;
        let state = ClientLocalState {
            oidc_tokens: Some(oidc_bundle(
                "sx-nearly-expired",
                Some(now + BOOT_ACCESS_TOKEN_SKEW_SECS),
            )),
            ..Default::default()
        };
        let config = ClientConfig::from_fields(
            "https://local.host",
            "did:web:alice.example",
            "ck:device:01964137-0000-7000-8000-000000000001",
            "legacy-token",
        );

        assert_eq!(initial_session_token_from_state(&state, &config, now), "");
    }

    #[test]
    fn boot_session_token_falls_back_to_legacy_config_without_oidc_bundle() {
        let state = ClientLocalState::default();
        let config = ClientConfig::from_fields(
            "https://local.host",
            "did:web:alice.example",
            "ck:device:01964137-0000-7000-8000-000000000001",
            "legacy-token",
        );

        assert_eq!(
            initial_session_token_from_state(&state, &config, 1_000),
            "legacy-token"
        );
    }

    #[test]
    fn boot_session_token_uses_fresh_session_grant_bearer() {
        let now = chrono::Utc::now().timestamp();
        let state = ClientLocalState {
            session_grant: Some(session_grant(120, 3600)),
            ..Default::default()
        };
        let config = ClientConfig::from_fields(
            "https://local.host",
            "did:web:alice.example",
            "ck:device:01964137-0000-7000-8000-000000000001",
            "bridge-token",
        );

        assert_eq!(
            initial_session_token_from_state(&state, &config, now),
            "bridge-token"
        );
    }

    #[test]
    fn boot_session_token_falls_back_to_session_grant_when_oidc_is_expired() {
        let now = chrono::Utc::now().timestamp();
        let state = ClientLocalState {
            oidc_tokens: Some(oidc_bundle("sx-expired-oidc", Some(now - 1))),
            session_grant: Some(session_grant(120, 3600)),
            ..Default::default()
        };
        let config = ClientConfig::from_fields(
            "https://local.host",
            "did:web:alice.example",
            "ck:device:01964137-0000-7000-8000-000000000001",
            "bridge-token",
        );

        assert_eq!(
            initial_session_token_from_state(&state, &config, now),
            "bridge-token"
        );
    }

    #[test]
    fn boot_session_token_ignores_expired_session_grant_bearer() {
        let now = chrono::Utc::now().timestamp();
        let state = ClientLocalState {
            session_grant: Some(session_grant(-1, 3600)),
            ..Default::default()
        };
        let config = ClientConfig::from_fields(
            "https://local.host",
            "did:web:alice.example",
            "ck:device:01964137-0000-7000-8000-000000000001",
            "bridge-token",
        );

        assert_eq!(initial_session_token_from_state(&state, &config, now), "");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn bootstrap_can_start_with_oidc_refresh_material_without_bearer() {
        let mut store = isolated_store("bootstrap-oidc");
        let state = ClientLocalState {
            oidc_tokens: Some(oidc_bundle("sx-expired", Some(1))),
            ..Default::default()
        };
        store.save(state);

        assert!(has_bootstrap_refresh_material(
            &store,
            "https://local.host",
            "did:web:alice.example"
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn bootstrap_can_start_with_session_grant_without_bearer() {
        let mut store = isolated_store("bootstrap-grant");
        store.set_session_grant(Some(session_grant(-1, 3600)));

        assert!(has_bootstrap_refresh_material(
            &store,
            "https://local.host",
            "did:web:alice.example"
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn bootstrap_ignores_session_grant_for_other_server() {
        let mut store = isolated_store("bootstrap-other-server");
        let mut grant = session_grant(-1, 3600);
        grant.principal_server_url = "https://other.local.host".to_owned();
        store.set_session_grant(Some(grant));

        assert!(!has_bootstrap_refresh_material(
            &store,
            "https://local.host",
            "did:web:alice.example"
        ));
    }

    #[test]
    fn boot_state_restores_when_refresh_material_exists_without_token() {
        assert_eq!(
            SessionBootState::from_boot_material("", true),
            SessionBootState::Restoring
        );
        assert_eq!(
            SessionBootState::from_boot_material("sx-live", true),
            SessionBootState::Checking
        );
        assert_eq!(
            SessionBootState::from_boot_material("", false),
            SessionBootState::Unauthenticated
        );
    }

    #[test]
    fn auth_surface_hides_login_while_session_is_restoring() {
        assert_eq!(
            auth_surface_for_route(&Route::Dashboard, false, SessionBootState::Restoring),
            AuthSurface::Restoring
        );
        assert_eq!(
            auth_surface_for_route(&Route::Login, false, SessionBootState::Restoring),
            AuthSurface::Restoring
        );
        assert_eq!(
            auth_surface_for_route(&Route::Login, false, SessionBootState::Unauthenticated),
            AuthSurface::Login
        );
    }

    #[test]
    fn auth_surface_routes_authenticated_login_to_app_shell() {
        assert_eq!(
            auth_surface_for_route(&Route::Login, true, SessionBootState::Authenticated),
            AuthSurface::AppShell
        );
        assert_eq!(
            auth_surface_for_route(&Route::AuthCallback, true, SessionBootState::Authenticated),
            AuthSurface::Callback
        );
    }

    #[test]
    fn space_top_nav_excludes_discussion_surface() {
        let surfaces = SpaceSurface::top_nav();

        assert_eq!(
            surfaces,
            [
                SpaceSurface::Timeline,
                SpaceSurface::Board,
                SpaceSurface::Document
            ]
        );
        assert_eq!(
            SpaceSurface::from_preference("discussion"),
            Some(SpaceSurface::Board)
        );
    }

    #[test]
    fn setup_section_route_labels_match_realm_and_space_forms() {
        assert_eq!(route_label(&Route::Setup), "New Realm");
        assert_eq!(
            route_label(&Route::SetupSection {
                section: "realms".to_owned()
            }),
            "New Realm"
        );
        assert_eq!(
            route_label(&Route::SetupSection {
                section: "spaces".to_owned()
            }),
            "New Realm"
        );
        assert_eq!(
            route_label(&Route::SetupSection {
                section: "new-space".to_owned()
            }),
            "New Space"
        );
    }

    #[test]
    fn kanban_board_route_uses_space_context_for_mls_bootstrap() {
        let route = Route::KanbanBoard {
            space_id: "ck:realm:019e67a5-8edc-7347-9ca1-a0b880987bdc".to_owned(),
            board_id: "ck:space:019e67ae-e633-7ef4-8a64-1f736d75d8ad".to_owned(),
        };

        assert!(route_uses_space_context(&route));
        assert_eq!(
            route.space_id(),
            Some("ck:realm:019e67a5-8edc-7347-9ca1-a0b880987bdc")
        );
    }

    #[test]
    fn board_first_mls_bootstrap_key_never_prompts_for_passphrase() {
        let route = Route::KanbanBoard {
            space_id: "ck:realm:019e67a5-8edc-7347-9ca1-a0b880987bdc".to_owned(),
            board_id: "ck:space:019e67ae-e633-7ef4-8a64-1f736d75d8ad".to_owned(),
        };
        let space_id = route.space_id().expect("board route carries a realm id");

        let key = mls_welcome_bootstrap_key(
            "http://localhost:8080",
            "secret-session-token",
            "did:web:yougen.example",
            "ck:device:01964137-0000-7000-8000-000000000001",
            space_id,
            true,
            true,
        )
        .expect("board route should be eligible for App-owned MLS Welcome bootstrap");
        let missing_welcome = crate::mls::runtime::MlsRuntimeStatus::MissingWelcome.user_message();

        assert!(!key.contains("secret-session-token"));
        assert!(!missing_welcome.to_ascii_lowercase().contains("passphrase"));
        assert!(missing_welcome.contains("MLS Welcome"));
        assert!(missing_welcome.contains("encrypted MLS history backup"));
    }

    #[test]
    fn mls_welcome_bootstrap_key_waits_for_e2ee_profile_and_sync() {
        let base = "https://local.host/";
        let session = "session-token";
        let actor = "did:web:yougen.example";
        let device = "ck:device:01964137-0000-7000-8000-000000000001";
        let space = "ck:realm:019e67a5-8edc-7347-9ca1-a0b880987bdc";

        assert_eq!(
            mls_welcome_bootstrap_key(base, session, actor, device, space, false, true),
            None
        );
        assert_eq!(
            mls_welcome_bootstrap_key(base, session, actor, device, space, true, false),
            None
        );
        assert_eq!(
            mls_welcome_bootstrap_key(base, "", actor, device, space, true, true),
            None
        );
        assert!(
            mls_welcome_bootstrap_key(base, session, actor, device, space, true, true).is_some()
        );
    }

    fn preview(id: &str, name: &str, parent: Option<&str>) -> SpacePreview {
        SpacePreview {
            space_id: id.to_owned(),
            title: name.to_owned(),
            description: None,
            tags: Default::default(),
            public: true,
            category: None,
            parent_space_id: parent.map(ToOwned::to_owned),
            child_space_ids: Vec::new(),
            kind: SpacePreviewKind::Realm,
            realm_id: String::new(),
        }
    }
    #[test]
    fn scoped_space_ids_support_exact_and_descendants() {
        let spaces = vec![
            preview("ck:space:root", "Root", None),
            preview("ck:space:child", "Child", Some("ck:space:root")),
            preview("ck:space:deep", "Deep", Some("ck:space:child")),
        ];

        assert_eq!(
            scoped_space_ids(&spaces, "ck:space:root", SpaceScopeMode::Exact),
            vec!["ck:space:root".to_owned()]
        );
        assert_eq!(
            scoped_space_ids(&spaces, "ck:space:root", SpaceScopeMode::IncludeDescendants),
            vec![
                "ck:space:root".to_owned(),
                "ck:space:child".to_owned(),
                "ck:space:deep".to_owned()
            ]
        );
    }
    #[test]
    fn merge_timeline_events_keeps_existing_messages_on_summary_only_delta() {
        let mut summary = TimelineEvent::system_notice("summary-ck:realm:test", "server", "old");
        summary.space_id = Some("ck:realm:test".to_owned());
        let message = TimelineEvent {
            id: "ck:event:message".to_owned(),
            space_id: Some("ck:realm:test".to_owned()),
            body: "welcome".to_owned(),
            ..TimelineEvent::default()
        };
        let mut updated_summary =
            TimelineEvent::system_notice("summary-ck:realm:test", "server", "new");
        updated_summary.space_id = Some("ck:realm:test".to_owned());

        let merged = merge_timeline_events(&[summary, message], vec![updated_summary]);

        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].body, "new");
        assert_eq!(merged[1].body, "welcome");
    }
}
