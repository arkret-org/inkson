use std::collections::{BTreeMap, BTreeSet};

use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use dioxus_router::hooks::*;
use dioxus_router::{Link, Navigator, Router};
use serde_json::Value;

use crate::api::{CokretApi, is_auth_expired_error};
use crate::components::{SecurityStateBadge, UiIcon};
use crate::config::{ClientConfig, LocalConfigStore, normalize_device_id, normalize_server_url};
use crate::conformance::{
    PROFILE_E2EE_CLIENT, PROFILE_FULL_CLIENT, PROFILE_KANBAN_MVP, PROFILE_MINIMAL_CLIENT,
    profile_ready,
};
use crate::i18n::{Locale, TextDirection};
use crate::local_state::{
    ClientLocalState, LocalStateStore, OidcTokenBundle, PersistedSessionGrant,
};
use crate::models::{
    RealmTreeNode, RealmTreeNodeKind, ServerDescription, ServerDescriptionExt,
    projection_realm_id_for_known_node,
};
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
use crate::views::helpers::{persist_config, short_protocol_id};
use crate::views::timeline::TimelineEvent;

// YOU-07-001:登录后 / 启动检测 effects 的纯函数与小型类型外迁到
// `crate::app::bootstrap`(仅移动,逻辑/签名/字节不变)。重导出使 app.rs
// 内既有调用点与 `app_tests.rs` 的 `use super::*` 解析路径均不变。
#[path = "bootstrap.rs"]
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

const UI_PREFERENCES_SCOPE: &str = "ui.browser";
const SIDEBAR_WIDTH_PREFERENCE_KEY: &str = "layout.sidebar.width";
const BOOT_ACCESS_TOKEN_SKEW_SECS: i64 = 30;
const DEFAULT_SIDEBAR_WIDTH: f64 = 320.0;
const OP_LIST_HANDLES_FOR_SUBJECT: &str = "ck.find.directory.query.list_handles_for_subject";
const MIN_SIDEBAR_WIDTH: f64 = 280.0;
const MAX_SIDEBAR_WIDTH: f64 = 420.0;

const STYLE: &str = include_str!("styles/app.css");

const DESIGN_STYLE: &str = include_str!("styles/design.css");

const APP_OVERRIDES: &str = include_str!("styles/app_overrides.css");

/// C3:yoface 共享组件的设计令牌(第一层 shadcn 语义令牌
/// `--primary/--background/--foreground/...` + 第二层 dioxus-components 兼容
/// 别名 `--primary-color-N/--focused-border-color/...`),供 `yoface::ui::*`
/// 的 `#[css_module]` 样式引用。色值即 yougen 绿色调色板(yoface tokens.css
/// 取值「参照 yougen design.css」),故沿用 `var(--dark,…) var(--light,…)`
/// 与 `[data-theme]` 开关,直接保留 yougen 现有绿色观感。替换了原 vendored
/// `assets/dx-components-theme.css`(黑白默认色)。注入顺序排在三段现有样式
/// 之前,令牌可被后续 design.css/app_overrides 覆盖。
const DXC_THEME: &str = yoface::TOKENS_CSS;

fn pinned_realm_ids_from_store(store: &LocalStateStore) -> BTreeSet<String> {
    store
        .realm_remarks()
        .into_iter()
        .filter_map(|(realm_id, remark)| remark.pinned.then_some(realm_id))
        .collect()
}

fn notification_projection_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn notification_projection_bool(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn unread_notification_count(snapshot: &ClientLocalState) -> usize {
    snapshot
        .notification_projection
        .iter()
        .enumerate()
        .filter(|(index, value)| {
            let id = notification_projection_string(value, &["notification_id", "id"])
                .unwrap_or_else(|| format!("notification-{index}"));
            let client_state = snapshot.notification_client_state.get(&id);
            let client_read = client_state.map(|state| state.read).unwrap_or(false);
            let client_archived = client_state.map(|state| state.archived).unwrap_or(false);
            let archived =
                notification_projection_bool(value, "archived").unwrap_or(client_archived);
            let read = notification_projection_bool(value, "read").unwrap_or(client_read);
            !archived && !read
        })
        .count()
}

#[derive(Clone, Debug, PartialEq)]
struct RealmManageRow {
    realm_id: String,
    display_name: String,
    title: String,
    encrypted: bool,
    space_count: usize,
}

fn sidebar_text_matches_query(normalized_query: &str, values: &[&str]) -> bool {
    normalized_query.is_empty()
        || values
            .iter()
            .any(|value| value.to_ascii_lowercase().contains(normalized_query))
}

fn load_direct_contacts_for_sidebar(
    base: String,
    api_token: String,
    mut direct_contact_rows: Signal<Vec<crate::models::ContactListRow>>,
    mut direct_contacts_loaded: Signal<bool>,
    mut status: Signal<String>,
) {
    if api_token.trim().is_empty() {
        direct_contact_rows.set(Vec::new());
        direct_contacts_loaded.set(false);
        return;
    }

    direct_contacts_loaded.set(true);
    spawn(async move {
        match crate::views::helpers::with_authed_api(&base, api_token, |api| async move {
            api.contacts().await
        })
        .await
        {
            Ok(response) => direct_contact_rows.set(response.contacts),
            Err(err) => {
                direct_contacts_loaded.set(false);
                status.set(format!("direct conversations: {}", err.display()));
            }
        }
    });
}

fn toggle_sidebar_realm_pin(
    realm_id: String,
    existing: Option<crate::account_data::RealmRemark>,
    next_pinned: bool,
    mut state_store: Signal<LocalStateStore>,
    base_url: String,
    api_token: String,
    mut status: Signal<String>,
) {
    let now_rfc3339 = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let next = crate::account_data::RealmRemark::with_pinned_preserving_fields(
        realm_id.clone(),
        existing.as_ref(),
        next_pinned,
        Some(now_rfc3339),
    );
    state_store
        .write()
        .set_realm_remark(realm_id.clone(), next.clone());
    let action_status = if next_pinned {
        crate::i18n::tr("realm.pinned")
    } else {
        crate::i18n::tr("realm.unpin")
    };
    status.set(format!("{action_status}: {}", short_protocol_id(&realm_id)));
    crate::views::settings::push_realm_remark_account_data_with_failure_status(
        base_url, api_token, realm_id, next, status,
    );
}

fn toggle_sidebar_contact_pin(
    actor_id: String,
    existing: Option<crate::account_data::ContactRemark>,
    next_pinned: bool,
    mut state_store: Signal<LocalStateStore>,
    base_url: String,
    api_token: String,
    mut status: Signal<String>,
) {
    let now_rfc3339 = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let next = crate::account_data::ContactRemark::with_pinned_preserving_fields(
        actor_id.clone(),
        existing.as_ref(),
        next_pinned,
        Some(now_rfc3339),
    );
    state_store
        .write()
        .set_contact_remark(actor_id.clone(), next.clone());
    let action_status = if next_pinned {
        "Pinned Contact"
    } else {
        "Unpinned Contact"
    };
    status.set(format!("{action_status}: {}", short_protocol_id(&actor_id)));
    crate::views::settings::push_contact_remark_account_data(base_url, api_token, actor_id, next);
}

fn leave_sidebar_realm(
    base_url: String,
    api_token: String,
    realm_id: String,
    account_did: String,
    mut state_store: Signal<LocalStateStore>,
    mut realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    mut selected_realm_id: Signal<String>,
    mut sync_cursor: Signal<String>,
    mut status: Signal<String>,
) {
    // Realm membership events are authored by the account/principal DID — the
    // server rejects any event whose `actor_id` differs from the bearer
    // session actor (`actor_session_mismatch`). The local device DID is not the
    // session actor, so it must not be used here.
    let actor_id = account_did.trim().to_owned();
    if actor_id.is_empty() {
        status.set("Leave Realm failed: account is not connected".to_owned());
        return;
    }
    let current_nodes = realm_tree_nodes();
    let mut ids_to_forget = descendant_node_ids(&current_nodes, &realm_id);
    if ids_to_forget.is_empty() {
        ids_to_forget.push(realm_id.clone());
    }
    let realm_label = short_protocol_id(&realm_id);
    status.set(format!("Leaving Realm: {realm_label}"));
    spawn(async move {
        let realm_for_api = realm_id.clone();
        match crate::views::helpers::with_authed_api(&base_url, api_token, |api| async move {
            api.leave_realm(&realm_for_api, &actor_id).await
        })
        .await
        {
            Ok(_) => {
                let forgotten_ids = ids_to_forget.into_iter().collect::<BTreeSet<_>>();
                for id in &forgotten_ids {
                    state_store.write().forget_realm_tree_projection(id);
                }
                realm_tree_nodes.set(
                    realm_tree_nodes()
                        .into_iter()
                        .filter(|node| !forgotten_ids.contains(&node.id))
                        .collect(),
                );
                if forgotten_ids.contains(&selected_realm_id()) {
                    selected_realm_id.set(String::new());
                }
                sync_cursor.set("-".to_owned());
                status.set(format!("Left Realm: {realm_label}"));
            }
            Err(err) => status.set(format!(
                "Leave Realm failed for {realm_label}: {}",
                err.display()
            )),
        }
    });
}

/// Per-Realm UI pre-gate for the sidebar row menu's write actions
/// (Add Member / Settings). Presence of a `realm_id` key in the cache means
/// the authz probe has completed; the booleans mirror the server's
/// authoritative decision so the row menu can hide entries the actor cannot
/// use. This is advisory only — the server still makes the real call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SidebarRowRealmPerms {
    can_add_member: bool,
    can_settings: bool,
}

/// Parse a `_cokret/self/authz/check` body into a simple allow boolean.
/// Mirrors `realm_admin::authz_json_allowed`. Fail-closed: any shape we do
/// not recognise reads as denied.
fn sidebar_authz_allowed(value: &Value) -> bool {
    value
        .get("allowed")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| {
            value
                .get("decision")
                .and_then(Value::as_str)
                .map(|decision| matches!(decision, "allow" | "allowed"))
                .unwrap_or(false)
        })
}

/// Lazily probe whether `actor` may add members (`ck.invite.create`) or edit
/// settings (`ck.realm.update`) on `realm_id`, caching the verdict in
/// `perms_cache`.
///
/// Triggered when a sidebar row's kebab menu opens, so at most two authz
/// requests are issued for the single Realm whose menu is open — never the
/// `2·N` that eager per-row probing on every sidebar render would cost.
/// Fail-closed: a transport error or a non-allow body both leave the write
/// actions hidden, and we still cache that verdict so we don't re-probe a
/// Realm the actor plainly cannot manage on every menu open.
fn ensure_sidebar_row_perms(
    base_url: String,
    api_token: String,
    actor: String,
    realm_id: String,
    mut perms_cache: Signal<BTreeMap<String, SidebarRowRealmPerms>>,
) {
    if api_token.trim().is_empty() || actor.trim().is_empty() || realm_id.trim().is_empty() {
        return;
    }
    if perms_cache.read().contains_key(&realm_id) {
        return;
    }
    spawn(async move {
        let perms = match crate::views::helpers::authed_api_with_sync(&base_url, api_token, None) {
            Ok(api) => {
                let invite = api
                    .authz_check_raw(&actor, "ck.invite.create", &realm_id)
                    .await;
                let settings = api
                    .authz_check_raw(&actor, "ck.realm.update", &realm_id)
                    .await;
                SidebarRowRealmPerms {
                    can_add_member: invite.as_ref().map(sidebar_authz_allowed).unwrap_or(false),
                    can_settings: settings
                        .as_ref()
                        .map(sidebar_authz_allowed)
                        .unwrap_or(false),
                }
            }
            Err(_) => SidebarRowRealmPerms::default(),
        };
        perms_cache.write().insert(realm_id, perms);
    });
}

fn delete_sidebar_contact(
    base_url: String,
    api_token: String,
    peer: String,
    mut direct_contact_rows: Signal<Vec<crate::models::ContactListRow>>,
    mut direct_contacts_loaded: Signal<bool>,
    mut status: Signal<String>,
) {
    let peer_label = short_protocol_id(&peer);
    status.set(format!("Deleting contact: {peer_label}"));
    spawn(async move {
        let peer_for_api = peer.clone();
        match crate::views::helpers::with_authed_api(&base_url, api_token, |api| async move {
            api.tombstone_contact(&peer_for_api, false).await
        })
        .await
        {
            Ok(_) => {
                direct_contact_rows.set(
                    direct_contact_rows()
                        .into_iter()
                        .filter(|row| row.peer != peer)
                        .collect(),
                );
                direct_contacts_loaded.set(true);
                status.set(format!("Deleted contact: {peer_label}"));
            }
            Err(err) => status.set(format!(
                "Delete contact failed for {peer_label}: {}",
                err.display()
            )),
        }
    });
}

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

fn should_wait_for_secure_store_session_restore(
    session_token: &str,
    can_restore_session: bool,
    account_did: &str,
    secure_store_ready: bool,
) -> bool {
    session_token.trim().is_empty()
        && !can_restore_session
        && !account_did.trim().is_empty()
        && !secure_store_ready
}

fn session_boot_state_from_bootstrap_material(
    session_token: &str,
    can_restore_session: bool,
    can_reissue_development_session: bool,
    account_did: &str,
    secure_store_ready: bool,
) -> SessionBootState {
    let can_restore_now = can_restore_session || can_reissue_development_session;
    if should_wait_for_secure_store_session_restore(
        session_token,
        can_restore_now,
        account_did,
        secure_store_ready,
    ) {
        SessionBootState::Restoring
    } else {
        SessionBootState::from_boot_material(session_token, can_restore_now)
    }
}

fn rehydrated_session_token_for_active_config(
    config: &ClientConfig,
    base_url: &str,
    account_did: &str,
    device_id: &str,
) -> Option<String> {
    if config.session_token.trim().is_empty()
        || normalize_server_url(&config.server_url) != normalize_server_url(base_url)
        || config.account_did.trim() != account_did.trim()
        || config.device_id.trim() != device_id.trim()
    {
        None
    } else {
        Some(config.session_token.clone())
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
    } else if boot_state.is_pending() {
        AuthSurface::Restoring
    } else if has_session {
        AuthSurface::AppShell
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
    String::new()
}

/// localStorage key the cotest joint-e2e harness uses to hand yougen a real
/// `ck.session.grant` + the DPoP device seed it is bound to. Read ONCE at boot,
/// only on wasm and only when `wasm_allow_localstorage_secrets()` is set — the
/// same dev-only opt-in the harness already toggles. Production never sets
/// either key, so this path is fully inert there.
#[cfg(target_arch = "wasm32")]
const TEST_SESSION_INJECTION_KEY: &str = "yougen.test.session_injection.v1";

/// Dev-only boot injection of a real grant + DPoP key (cotest joint e2e,
/// ②(A+②) model). Returns the injected grant JWT so the caller can seed the
/// in-memory `token` signal before the bootstrap `connect()` reads it.
///
/// Timing: this MUST run before the bootstrap `connect()` block reads `token`
/// and `state_store` (the DPoP key + persisted grant) so the very first
/// `/_cokret/self/*` request carries a valid grant + DPoP + holder proof. It is
/// driven from a `use_hook` placed ahead of that block so it executes once,
/// synchronously, on first render.
///
/// On success it (1) writes the DPoP device key to the secure store via the
/// localStorage tier (the harness sets `allow_localstorage_secrets`), with a
/// thumbprint that equals the grant's `cnf.jkt` because both derive from the
/// same seed, and (2) persists a `PersistedSessionGrant` whose
/// `principal_server_url` is the active server so the bootstrap does not treat
/// it as stale.
#[cfg(target_arch = "wasm32")]
fn inject_test_session_grant(
    state_store: &mut Signal<LocalStateStore>,
    config_store: Signal<LocalConfigStore>,
    server_url: &str,
    account_did: &str,
    device_id: &str,
) -> Option<String> {
    if !crate::secure_key_store::wasm_allow_localstorage_secrets() {
        return None;
    }
    let raw = web_sys::window()
        .and_then(|window| window.local_storage().ok().flatten())
        .and_then(|storage| storage.get_item(TEST_SESSION_INJECTION_KEY).ok().flatten())?;
    let parsed: Value = serde_json::from_str(&raw).ok()?;
    let grant_jwt = parsed.get("grant_jwt")?.as_str()?.to_owned();
    let dpop_seed_b64url = parsed.get("dpop_seed_b64url")?.as_str()?.to_owned();
    if grant_jwt.trim().is_empty() || dpop_seed_b64url.trim().is_empty() {
        return None;
    }
    let grant_id = parsed
        .get("grant_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let audience = parsed
        .get("audience")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();

    let record = match crate::auth_dpop::dpop_device_key_record_from_seed(&dpop_seed_b64url) {
        Ok(record) => record,
        Err(error) => {
            tracing::warn!(?error, "test session injection: invalid DPoP seed");
            return None;
        }
    };
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    if let Err(error) = state_store
        .write()
        .set_dpop_device_key_with_secure_store(Some(record), secure_store.as_ref())
    {
        tracing::warn!(?error, "test session injection: DPoP key persist failed");
        return None;
    }

    let now = chrono::Utc::now();
    let grant = PersistedSessionGrant {
        grant_jwt: grant_jwt.clone(),
        // ②(A+②): the grant rotation/holder proof is signed by the device DPoP
        // key, not a separate session key, so no PEM is needed; e2e never
        // refreshes the injected grant.
        session_private_key_pem: String::new(),
        grant_id,
        audience,
        principal_id: account_did.to_owned(),
        device_id: device_id.to_owned(),
        // MUST match the active server so the bootstrap does not discard the
        // grant as stale (see `grant_matches_principal_server`).
        principal_server_url: server_url.to_owned(),
        session_grant_exchange_path: "_cokret/gate/account/session-grants".to_owned(),
        grant_expires_at: Some(now + chrono::Duration::hours(8)),
        session_expires_at: Some(now + chrono::Duration::hours(8)),
        stored_at: now,
    };
    state_store.write().set_session_grant(Some(grant));
    // Mirror the grant into the persisted config bearer slot so a re-render /
    // reload rehydrates the same session instead of bouncing to /login.
    persist_config(
        config_store,
        server_url.to_owned(),
        account_did.to_owned(),
        device_id.to_owned(),
        grant_jwt.clone(),
    );
    Some(grant_jwt)
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
    let initial_secure_store_bootstrap_ready = !cfg!(target_arch = "wasm32");
    let initial_session_boot_state = session_boot_state_from_bootstrap_material(
        &initial_session_token,
        initial_can_restore_session,
        initial_can_reissue_development_session,
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
    let mut session_generation = use_signal(|| 0_u64);

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
                session_generation,
            )) as crate::session::LocalRefreshFuture
        }));
    });

    // Dev-only (wasm + `allow_localstorage_secrets`) real-grant injection for the
    // cotest joint e2e harness. Runs once, synchronously, ahead of the bootstrap
    // `connect()` below so the first `/_cokret/self/*` request already carries a
    // valid grant + DPoP holder proof. Inert in production (neither localStorage
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
    let mut status = use_signal(|| ConnectionState::Offline.label().to_owned());
    let initial_sync_cursor = initial_local_state
        .sync_cursor
        .clone()
        .unwrap_or_else(|| "-".to_owned());
    let initial_selected_realm_id = initial_realm_tree_nodes
        .iter()
        .find(|node| node.kind == RealmTreeNodeKind::Realm)
        .map(|node| node.id.clone())
        .unwrap_or_default();
    let initial_draft = initial_realm_tree_nodes
        .first()
        .and_then(|space| initial_local_state.drafts.get(&space.id))
        .cloned()
        .unwrap_or_default();
    let initial_push_state =
        crate::push::push_status_label(initial_local_state.push_registration.as_ref());
    let initial_realm_tree_nodes_for_signal = initial_realm_tree_nodes.clone();
    let mut sync_cursor = use_signal(move || initial_sync_cursor);
    let mut selected_realm_id = use_signal(move || initial_selected_realm_id);
    let mut new_space_context_node = use_signal(String::new);
    let mut realm_tree_nodes = use_signal(move || initial_realm_tree_nodes_for_signal);
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
    let secure_store_bootstrap_ready = use_signal(move || initial_secure_store_bootstrap_ready);
    #[cfg(target_arch = "wasm32")]
    {
        let config_store_for_secure_upgrade = config_store;
        let base_url_for_secure_upgrade = base_url;
        let account_did_for_secure_upgrade = account_did;
        let device_id_for_secure_upgrade = device_id;
        let mut state_store_for_secure_upgrade = state_store;
        let mut secure_store_ready_for_upgrade = secure_store_bootstrap_ready;
        let mut token_for_secure_upgrade = token;
        use_future(move || async move {
            match crate::secure_key_store::upgrade_wasm_secure_key_store_async("yougen").await {
                Ok(Some(secure_store)) => {
                    let loaded_config = config_store_for_secure_upgrade
                        .read()
                        .load_with_secure_store(secure_store.as_ref());
                    let held_token = token_for_secure_upgrade.peek().trim().to_owned();
                    if held_token.is_empty() {
                        if let Some(rehydrated) = rehydrated_session_token_for_active_config(
                            &loaded_config,
                            &base_url_for_secure_upgrade(),
                            &account_did_for_secure_upgrade(),
                            &device_id_for_secure_upgrade(),
                        ) {
                            token_for_secure_upgrade.set(rehydrated);
                        }
                    } else {
                        // A bearer is already held in memory: sign-in completed
                        // BEFORE this IndexedDB secure-store upgrade was ready, so
                        // `config.rs` could only reach the localStorage tier — which
                        // refuses bearer tokens — and the bearer was never persisted
                        // (`config persisted without bearer`). Now that the upgraded
                        // store is installed, re-persist it so the session survives a
                        // reload / re-render instead of bouncing back to /login.
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
                    match crate::event_signer::bootstrap_default_signer("yougen") {
                        Ok(_) => {
                            tracing::info!("IndexedDB signer bootstrap succeeded");
                        }
                        Err(error) => {
                            tracing::warn!(?error, "IndexedDB signer bootstrap failed");
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(?error, "IndexedDB secure-key-store upgrade failed");
                }
            }
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
    // Y1 —— 会话级 DID 解析缓存句柄。
    //
    // 挂载点说明:yougen 的 app 态是一堆分散的 `use_signal`,没有单一
    // 聚合 struct,因此选择与上面的 `CapabilityEngine` 完全相同的最小
    // 侵入模式 —— 用 `use_context_provider` 提供一个共享
    // `Signal<DidResolutionCache>`。这样:
    //   * authority 解析点可经 `use_context::<Signal<DidResolutionCache>>()` 取用,配合
    //     `did_resolver::resolve_with_cache` 走缓存优先解析;
    //   * 同一句柄被复制进下面的 `SyncEngineContext.did_cache`,让 Y2 失效钩子在摄入投影时能
    //     `invalidate` / `clear`。
    // 缓存是纯内存态(非持久化),只活在单个登录会话里,语义与
    // `DidResolutionCache` 的文档一致。
    let mut did_cache =
        use_context_provider(|| Signal::new(crate::did_resolver::DidResolutionCache::default()));
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
    let mut personal_handles = use_signal(Vec::<String>::new);
    let mut personal_handles_status = use_signal(|| "Not published".to_owned());
    let mut personal_handles_lookup_key = use_signal(String::new);
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
    let manage_bulk_status = use_signal(String::new);
    let direct_contact_rows = use_signal(Vec::<crate::models::ContactListRow>::new);
    let direct_contacts_loaded = use_signal(|| false);
    let mut sidebar_row_menu_open = use_signal(|| Option::<String>::None);
    // UI pre-gate cache for the row menu's Add Member / Settings entries,
    // keyed by realm_id. Filled lazily when a row kebab opens (see
    // `ensure_sidebar_row_perms`) so we never probe authz for Realms whose
    // menu the user never touches.
    let sidebar_row_perms = use_signal(BTreeMap::<String, SidebarRowRealmPerms>::new);
    let mls_welcome_bootstrap_key_seen = use_signal(|| Option::<String>::None);
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
        let navigator = navigator;
        let mut last_incoming_nav = use_signal(|| Option::<String>::None);
        use_effect(move || {
            let pending = call_signal_hub.incoming_call.read().clone();
            match pending {
                Some(info) => {
                    if last_incoming_nav.read().as_deref() != Some(info.call_id.as_str()) {
                        last_incoming_nav.set(Some(info.call_id.clone()));
                        navigator.push(Route::Call {
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
                            // (or the login strand) handles a genuinely dead
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

    // F7 — durable hard-logout retry. A logout journals its server-side
    // termination intent to localStorage before wiping local creds; if the
    // tab closed before the revoke completed (or coauth was unreachable),
    // finish it on the next boot so the rotation chain can never outlive a
    // "Log out" click. One-shot: reads no signals, so it runs once on mount.
    use_future(move || async move {
        crate::pending_logout::run_pending_logout_if_any(chrono::Utc::now()).await;
    });

    // SyncEngine generation counter. Declared up front so the
    // bootstrap connect() can pass it via `ConnectContext`. The engine
    // itself is spawned by the `use_effect` further down.
    let mut sync_generation = use_signal(|| 0u64);
    let mut sync_engine_active_generation = use_signal(|| Option::<u64>::None);

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
            if base.trim().is_empty() || session.trim().is_empty() || actor.trim().is_empty() {
                account_recovery_configured.set(None);
                account_recovery_detection_key_seen.set(None);
                return;
            }
            let detection_key = format!("{generation}|{base}|{actor}");
            if account_recovery_detection_key_seen().as_deref() == Some(detection_key.as_str()) {
                return;
            }
            account_recovery_detection_key_seen.set(Some(detection_key));
            let local_fingerprint = {
                let store = state_store_for_recovery_state.read();
                crate::views::recovery::local_recovery_key_fingerprint(&store, &actor)
            };
            spawn(async move {
                match crate::views::helpers::with_authed_api(&base, session, |api| async move {
                    let policy = api.get_recovery_policy().await?;
                    let backups = api.list_key_backups().await?;
                    Ok((policy, backups))
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
    // hook so those paths can clear the live bearer and stop retry loops.
    {
        let mut invalidator_token = token;
        let mut invalidator_sync_cursor = sync_cursor;
        let mut invalidator_selected_realm_id = selected_realm_id;
        let mut invalidator_realm_tree_nodes = realm_tree_nodes;
        let mut invalidator_timeline = timeline;
        let mut invalidator_device_queue = device_queue;
        let mut invalidator_crypto_state = crypto_state;
        let mut invalidator_status = status;
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
                crate::config::clear_session_token_secret(&invalidator_account_did());
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
                invalidator_timeline.set(Vec::new());
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
                rehydrated_session_token_for_active_config(
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
            session_boot_state.set(session_boot_state_from_bootstrap_material(
                &session,
                can_restore_session,
                can_reissue_development_session,
                &account_did(),
                secure_store_ready,
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
                    selected_realm_id,
                    realm_tree_nodes,
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
                    personal_handles,
                    personal_handles_status,
                    theme,
                    sync_generation,
                    needs_device_authorization,
                    device_authorization_check_complete,
                    account_has_other_devices,
                    sync_bootstrap_complete,
                    session_boot_state,
                    navigator,
                    call_signal_hub,
                    did_cache,
                },
            );
        } else if !base.trim().is_empty() {
            session_boot_state.set(session_boot_state_from_bootstrap_material(
                &session,
                can_restore_session,
                can_reissue_development_session,
                &account_did(),
                secure_store_ready,
            ));
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
            timeline,
            sync_cursor,
            status,
            network_state,
            last_error,
            device_queue,
            theme,
            account_did,
            device_id,
            selected_realm_id,
            profiles: profiles_signal,
            // Y1/Y2 —— 把上面 provide 的会话级缓存句柄交给同步引擎,
            // 供 Y2 失效钩子在摄入投影时 invalidate/clear。
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
        use_effect(move || {
            if !secure_store_ready_for_detection() {
                return;
            }
            let base = base_url();
            let session = token();
            let actor = account_did();
            let device = device_id();
            let generation = sync_generation();
            if session.trim().is_empty() {
                needs_mls_unlock.set(false);
                needs_mls_backup.set(false);
                needs_mls_recovery_setup.set(false);
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
            let state_for_detection_key = state_store_for_detection.read();
            let has_local_mls_snapshot = !state_for_detection_key.mls_snapshots().is_empty();
            let has_encrypted_realm_projection =
                local_state_has_encrypted_realm(&state_for_detection_key);
            let local_mls_epoch_floor = local_mls_epoch_floor_all(&state_for_detection_key);
            drop(state_for_detection_key);
            let has_local_account_secret = crate::mls::runtime::load_account_mls_secret(
                crate::secure_key_store::default_secure_key_store("yougen").as_ref(),
                &actor,
            )
            .map(|secret| secret.is_some())
            .unwrap_or(false);
            let detection_key = format!(
                "{generation}|{base}|{actor}|{device}|sec={has_local_account_secret}|snap={has_local_mls_snapshot}|enc={has_encrypted_realm_projection}|epoch={local_mls_epoch_floor}"
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
                            let _ =
                                crate::mls::account_recovery::restore_mls_history_with_local_secret_from_payload(
                                    &payload,
                                    &mut store,
                                    secure_store.as_ref(),
                                    &actor,
                                    &device,
                                );
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
                            restore_payload_cache.set(Some(payload));
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
                            needs_mls_backup.set(should_backup);
                            let should_recovery_setup = {
                                let store = state_store_for_detection.read();
                                mls_recovery_setup_missing(
                                    &payload,
                                    &store,
                                    secure_store.as_ref(),
                                    &actor,
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
        // configured (the lowest-priority RecoverySetupReminder state), open the
        // setup modal once and persist a flag so it never auto-pops again — the
        // passive dashboard banner remains as the steady-state reminder. The
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
            // grant-less session (e.g. a dev-login bearer) can never pass that
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
            spawn(async move {
                match CokretApi::new(&base) {
                    Ok(api) => match api
                        .with_bearer(api_token)
                        .list_handles_for_subject(&actor, None, Some("display"))
                        .await
                    {
                        Ok(res) => {
                            let handles = display_handles_from_directory_response(&res);
                            if handles.is_empty() {
                                personal_handles_status.set("No handles published".to_owned());
                            } else {
                                personal_handles_status.set(format!("{} handle(s)", handles.len()));
                            }
                            personal_handles.set(handles);
                        }
                        Err(err) => {
                            tracing::warn!(
                                ?err,
                                "directory list_handles_for_subject failed; keeping account localpart fallback"
                            );
                            if personal_handles().is_empty() {
                                personal_handles_status.set("Not published".to_owned());
                            }
                        }
                    },
                    Err(err) => {
                        tracing::warn!(
                            ?err,
                            "directory list_handles_for_subject skipped for invalid server URL"
                        );
                        if personal_handles().is_empty() {
                            personal_handles_status.set("Not published".to_owned());
                        }
                    }
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
        account_did_label.clone()
    } else {
        "Not signed in".to_owned()
    };
    let account_detail = if has_session {
        personal_handles_value
            .first()
            .map(|handle| format!("@{handle}"))
            .unwrap_or_else(|| format!("device {device_id_label}"))
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
            // longer matches once they flip false→true.
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
            drop(state_for_bootstrap_key);
            let has_local_account_secret = crate::mls::runtime::load_account_mls_secret(
                crate::secure_key_store::default_secure_key_store("yougen").as_ref(),
                &actor,
            )
            .map(|secret| secret.is_some())
            .unwrap_or(false);
            let bootstrap_key = format!(
                "{bootstrap_key}|sec={has_local_account_secret}|snap={has_local_mls_snapshot}|enc={has_encrypted_realm_projection}|epoch={local_mls_epoch_floor}"
            );
            if seen_bootstrap_key().as_deref() == Some(bootstrap_key.as_str()) {
                return;
            }
            seen_bootstrap_key.set(Some(bootstrap_key));

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
                            let _ =
                                crate::mls::account_recovery::restore_mls_history_with_local_secret_from_payload(
                                    &payload,
                                    &mut store,
                                    secure_store.as_ref(),
                                    &detect_actor,
                                    &detect_device,
                                );
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
                            restore_payload_cache_for_bootstrap.set(Some(payload));
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
                            needs_mls_backup_for_bootstrap.set(should_backup);
                            let should_recovery_setup = {
                                let store = state_store_for_probe.read();
                                mls_recovery_setup_missing(
                                    &payload,
                                    &store,
                                    secure_store.as_ref(),
                                    &detect_actor,
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
            Route::TimelineRealm { .. }
                | Route::KanbanRealm { .. }
                | Route::KanbanBoard { .. }
                | Route::KanbanBoardTask { .. }
                | Route::DocumentRealm { .. }
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
            let fallback_name = short_protocol_id(&contact.peer);
            let display_name = contact_remarks_for_sidebar
                .get(&contact.peer)
                .map(|remark| remark.display_name(&fallback_name).to_owned())
                .unwrap_or(fallback_name);
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
        let left_fallback = short_protocol_id(&left.peer);
        let right_fallback = short_protocol_id(&right.peer);
        let left_label = left_remark
            .map(|remark| remark.display_name(&left_fallback).to_ascii_lowercase())
            .unwrap_or_else(|| left_fallback.to_ascii_lowercase());
        let right_label = right_remark
            .map(|remark| remark.display_name(&right_fallback).to_ascii_lowercase())
            .unwrap_or_else(|| right_fallback.to_ascii_lowercase());
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
    let server_options = server_options_for(&base_url());
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
        "Yougen | Cokret".to_owned()
    } else {
        format!("{route_title} | Yougen | Cokret")
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
    if !matches!(auth_surface, AuthSurface::AppShell) {
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

        return rsx! {
            style { "{DXC_THEME}" }
            style { "{STYLE}" }
            style { "{DESIGN_STYLE}" }
            style { "{APP_OVERRIDES}" }
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
    // Single source of truth for the post-boot account-health prompt chain.
    // Each prompt below renders iff it is the resolved highest-priority one,
    // replacing the per-prompt inline suppression that used to drift apart.
    // See `account_health` and `docs/user-strands-key-lifecycle.md` §3.
    let active_prompt = {
        let store = state_store.read();
        let actor = account_did();
        let local_recovery_configured =
            crate::views::recovery::recovery_options_configured(&store, &actor);
        crate::account_health::AccountHealthInputs {
            has_session,
            sync_bootstrap_complete: sync_bootstrap_complete(),
            device_check_complete: device_authorization_check_complete(),
            on_recovery_route: matches!(
                &content_route,
                Route::Recovery | Route::SettingsRecovery
            ),
            needs_device_authorization: needs_device_authorization(),
            needs_mls_unlock: needs_mls_unlock(),
            needs_mls_backup: needs_mls_backup(),
            needs_mls_recovery_setup: needs_mls_recovery_setup(),
            floor_low:
                crate::components::encryption_floor_prompt::account_needs_recommended_encryption_prompt(
                    &store, &actor,
                ),
            recovery_unconfigured: recovery_setup_prompt_required_for_account_state(
                account_recovery_configured(),
                local_recovery_configured,
                account_has_other_devices(),
            ),
        }
        .resolve()
    };
    use crate::account_health::AccountHealthPrompt;
    let show_recovery_setup_prompt =
        active_prompt == AccountHealthPrompt::RecoverySetupReminder && !recovery_key_setup_prompt();

    rsx! {
        style { "{DXC_THEME}" }
        style { "{STYLE}" }
        style { "{DESIGN_STYLE}" }
        style { "{APP_OVERRIDES}" }
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
            // G3.Y3 — global policy-deny banner. Floats above the shell
            // so any 403 with a policy-shaped envelope is surfaced
            // without each call site wiring its own error UI. The
            // banner is pulled from a process-wide queue populated by
            // `api::decode_cokret_error`'s `maybe_dispatch_policy_deny`.
            crate::components::PolicyDenyBanner {}
            // CKP-0007 P3B.3 — global Circle-error toast, fed by the
            // HTTP layer's `maybe_dispatch_circle_error` next to the
            // policy-deny dispatcher. Renders nothing when no error
            // is queued.
            crate::components::CircleErrorToast { i18n: i18n_signal }
            crate::components::DeviceAuthorizationPrompt {
                needs_device_authorization,
            }
            if active_prompt == AccountHealthPrompt::RecommendedEncryptionFloor {
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
                }
            }
            crate::components::RecoveryKeySetupPrompt {
                base_url,
                token,
                account_did,
                device_id,
                state_store,
                open: recovery_key_setup_prompt,
                personal_handles,
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
                    personal_handles,
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
                    span { "data-testid": "mobile-status-label", "{status}" }
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
                                    status,
                                    sync_cursor,
                                    token,
                                    account_did,
                                    selected_realm_id,
                                    realm_tree_nodes,
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
                                    personal_handles,
                                    personal_handles_status,
                                    theme,
                                    sync_generation,
                                    needs_device_authorization,
                                    device_authorization_check_complete,
                                    account_has_other_devices,
                                    sync_bootstrap_complete,
                                    session_boot_state,
                                    navigator,
                                    call_signal_hub,
                                    did_cache,
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
                    Link { class: "brand", to: Route::Dashboard, "aria-label": "Yougen | Cokret Home",
                        span { class: "logo", "⌘" }
                        span { class: "product-meta",
                            span { class: "product-name", "Yougen | Cokret" }
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
                                                        status,
                                                        sync_cursor,
                                                        token,
                                                        account_did,
                                                        selected_realm_id,
                                                        realm_tree_nodes,
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
                                                        personal_handles,
                                                        personal_handles_status,
                                                        theme,
                                                        sync_generation,
                                                        needs_device_authorization,
                                                        device_authorization_check_complete,
                                                        account_has_other_devices,
                                                        sync_bootstrap_complete,
                                                        session_boot_state,
                                                        navigator,
                                                        call_signal_hub,
                                                        did_cache,
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
                                            status,
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
                                                    status,
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
                                                status,
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
                                    let fallback_name = short_protocol_id(&peer);
                                    let display_name = contact_remark
                                        .as_ref()
                                        .map(|remark| remark.display_name(&fallback_name).to_owned())
                                        .unwrap_or(fallback_name);
                                    let has_contact_remark = contact_remark
                                        .as_ref()
                                        .is_some_and(|remark| !remark.local_name.trim().is_empty());
                                    let is_pinned_contact =
                                        contact_remark.as_ref().is_some_and(|remark| remark.pinned);
                                    let pin_contact_label = if is_pinned_contact {
                                        "Unpin Contact"
                                    } else {
                                        "Pin Contact"
                                    };
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
                                                            status.set(format!("{}: {}", crate::i18n::tr("direct.unavailable"), peer));
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
                                                                        status.set(format!("direct conversation: {:?}", response.state));
                                                                    }
                                                                }
                                                                Err(err) => status.set(format!("direct conversation: {}", err.display())),
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
                                                        title: "Pinned Contact",
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
                                                                        status,
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
                                                                        direct_contact_rows,
                                                                        direct_contacts_loaded,
                                                                        status,
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
                                                            status,
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
                                                            status,
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
                                    Button {
                                        variant: ButtonVariant::Ghost,
                                        size: ButtonSize::Sm,
                                        r#type: "button",
                                        class: "btn icon topbar-command-search-close",
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
                                            view.set(crate::views::View::Timeline);
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
                        div { class: "sr-only", "data-testid": "connection-status", role: "status", "aria-live": "polite",
                            span { "data-testid": "status-label", "{status}" }
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
                                                                        personal_handle_from_account_localpart(&account.handle, &base)
                                                                    {
                                                                        personal_handles.set(vec![personal_handle]);
                                                                        personal_handles_status.set("1 handle".to_owned());
                                                                    } else {
                                                                        personal_handles.set(Vec::new());
                                                                        personal_handles_status.set("Not published".to_owned());
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
                                                                        // The bearer expired between background
                                                                        // refresh ticks. Try a silent re-mint
                                                                        // (OIDC refresh_token / session-grant
                                                                        // exchange) before declaring the session
                                                                        // dead — clicking "Refresh session" must
                                                                        // *keep* the user signed in, not bounce
                                                                        // them to login on a routine token rollover.
                                                                        if let Some(fresh) = crate::session::refresh_current_bearer().await {
                                                                            let canonical_actor = match self_authed_api(&base, fresh) {
                                                                                Ok(api) => api
                                                                                    .account_me()
                                                                                    .await
                                                                                    .ok()
                                                                                    .and_then(|account| {
                                                                                        if let Some(personal_handle) =
                                                                                            personal_handle_from_account_localpart(&account.handle, &base)
                                                                                        {
                                                                                            personal_handles.set(vec![personal_handle]);
                                                                                            personal_handles_status
                                                                                                .set("1 handle".to_owned());
                                                                                        } else {
                                                                                            personal_handles.set(Vec::new());
                                                                                            personal_handles_status
                                                                                                .set("Not published".to_owned());
                                                                                        }
                                                                                        (!account.did.trim().is_empty())
                                                                                            .then_some(account.did)
                                                                                    }),
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
                                                // Capture the grant + device holder key BEFORE the
                                                // local wipe below: hard logout MUST also terminate
                                                // the Auth Server session (revoke grant + finish
                                                // browser session) so the rotation chain can't be
                                                // resumed (account-lifecycle §4.1), and that needs
                                                // the grant JWT + a device holder proof.
                                                let logout_grant =
                                                    state_store.read().session_grant();
                                                let logout_device_handle = {
                                                    let mut store = state_store.write();
                                                    crate::auth_dpop::ensure_device_key(&mut store).ok()
                                                };
                                                // F7 — journal the logout intent durably BEFORE the
                                                // local wipe. If the tab closes mid-flight or coauth is
                                                // briefly unreachable, the next boot
                                                // (`run_pending_logout_if_any`) retries the server-side
                                                // termination so the rotation chain can't outlive the
                                                // "logout". The record stashes the device seed (the live
                                                // key is wiped below) purely to mint the revoke holder
                                                // proof; it is cleared once coauth confirms the grant is
                                                // gone (account-lifecycle §4.1).
                                                let pending_logout =
                                                    crate::pending_logout::PendingLogout {
                                                        grant_jwt: logout_grant
                                                            .as_ref()
                                                            .map(|grant| grant.grant_jwt.clone()),
                                                        device_seed_b64: logout_device_handle
                                                            .as_ref()
                                                            .map(|handle| handle.seed_b64()),
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
                                                        bearer: api_token.clone(),
                                                        account_did: actor.clone(),
                                                        created_at: chrono::Utc::now(),
                                                    };
                                                let logout_secure_store =
                                                    crate::secure_key_store::default_secure_key_store(
                                                        "yougen",
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
                                                // Clear OIDC + session-grant state up
                                                // front so a refresh-token-based silent
                                                // re-auth cannot resurrect the session
                                                // if the server-side logout call later
                                                // fails or is cancelled.
                                                state_store.write().set_oidc_tokens(None);
                                                state_store.write().set_session_grant(None);
                                                // Then wipe every account-scoped local
                                                // projection cache (Realm tree, drafts,
                                                // seals, read markers, remarks…) so
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
                                                // Realm tree updates between this click and the
                                                // navigator.push(Login).
                                                realm_tree_nodes.set(Vec::new());
                                                timeline.set(Vec::new());
                                                sync_cursor.set("-".to_owned());
                                                selected_realm_id.set(String::new());
                                                device_queue.set(0);
                                                // Y2 —— logout 属于 trust-bundle 全清场景:
                                                // 整盘清空会话级 DID 解析缓存,确保下一位
                                                // 在本浏览器登录的用户不会命中上一会话的
                                                // 解析结果(陈旧文档 / 旧密钥集)。
                                                did_cache.write().clear();
                                                personal_handles.set(Vec::new());
                                                personal_handles_status.set("Not published".to_owned());
                                                personal_handles_lookup_key.set(String::new());
                                                last_error.set(None);
                                                token.set(String::new());
                                                crate::config::clear_session_token_secret(&actor);
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
                        match resolved_realm_surface.unwrap_or(RealmSurface::Timeline) {
                            RealmSurface::Timeline => {
                                if minimal_ready {
                                    rsx! {
                                        crate::views::timeline::TimelinePanel {
                                            base_url: base_url(),
                                            account_did: account_did(),
                                            device_id: device_id(),
                                            token,
                                            selected_realm_id: active_realm_id.clone(),
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
                                            frontier_state,
                                            state_store,
                                            event_write_ready,
                                        }
                                    }
                                } else {
                                    rsx! { ProfileGateNotice { profile: "kanban_mvp" } }
                                }
                            }
                            RealmSurface::Document => {
                                if full_ready {
                                    rsx! {
                                        crate::views::document::DocumentPanel {
                                            base_url: base_url(),
                                            token,
                                            selected_realm_id: active_realm_id.clone(),
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
                    Route::Timeline | Route::TimelineRealm { .. } | Route::TimelineMessage { .. } => {
                        if let Some(sid) = route.realm_id()
                            && selected_realm_id() != sid
                        {
                            selected_realm_id.set(sid.to_owned());
                        }
                        if minimal_ready {
                            rsx! {
                                crate::views::timeline::TimelinePanel {
                                    base_url: base_url(),
                                    account_did: account_did(),
                                    device_id: device_id(),
                                    token,
                                    selected_realm_id: active_realm_id.clone(),
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
                    Route::Chat { .. } => {
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
                                    frontier_state,
                                    state_store,
                                    initial_strand_id: default_strand_id_for_realm(&active_realm_id),
                                    embedded: false,
                                    direct_mode: false,
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
                            status,
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
                            status: manage_bulk_status,
                        }
                    },
                    Route::ContactsManage => rsx! {
                        ContactsManagePage {
                            base_url: base_url(),
                            token,
                            has_session,
                            contact_rows: direct_contact_rows,
                            contacts_loaded: direct_contacts_loaded,
                            app_status: status,
                            query: contact_manage_query,
                            selection: manage_contact_selection,
                            busy: manage_bulk_busy,
                            status: manage_bulk_status,
                        }
                    },
                    Route::Contacts => rsx! {
                        crate::views::contacts::ContactsPanel {
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
                                    secure_store_ready: secure_store_bootstrap_ready(),
                                    token,
                                    account_did,
                                    device_id,
                                    config_store,
                                    state_store,
                                    realm_tree_nodes,
                                    selected_realm_id,
                                    new_space_context_node,
                                    status,
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
                            personal_handles: personal_handles(),
                            personal_handles_status: personal_handles_status(),
                            can_list_handles_for_subject,
                            config_store,
                            state_store,
                            push_state,
                            locale,
                            theme,
                            status,
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
                                    account_did: account_did(),
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
                    Route::Document | Route::DocumentNew | Route::DocumentRealm { .. } => {
                        if let Some(sid) = route.realm_id()
                            && selected_realm_id() != sid
                        {
                            selected_realm_id.set(sid.to_owned());
                        }
                        let document_ref = match &route {
                            Route::DocumentRealm { realm_id }
                                if realm_id.starts_with("ck:morph:") =>
                            {
                                Some(realm_id.clone())
                            }
                            _ => None,
                        };
                        rsx! {
                            if full_ready {
                                crate::views::document::DocumentPanel {
                                    base_url: base_url(),
                                    token,
                                    selected_realm_id: active_realm_id.clone(),
                                    document_ref,
                                    state_store,
                                    account_did: account_did(),
                                }
                            } else {
                                ProfileGateNotice { profile: "full_client" }
                            }
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
                            base_url,
                            token,
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
                    Button {
                        variant: ButtonVariant::Secondary,
                        r#type: "button",
                        class: "notifications-drawer-scrim",
                        "data-testid": "notifications-drawer-scrim",
                        "aria-label": "Close notifications",
                        onclick: move |_| notifications_drawer_open.set(false),
                    }
                    aside {
                        class: "notifications-drawer-panel",
                        "data-testid": "notifications-drawer-panel",
                        role: "dialog",
                        "aria-modal": "true",
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
    }
}

fn contact_manage_scope_summary(contact: &crate::models::ContactListRow) -> String {
    let mut seen = BTreeSet::<String>::new();
    for scope in contact
        .bidirectional_scopes
        .iter()
        .chain(contact.effective_scopes.iter())
        .chain(contact.granted_by_me.iter())
        .chain(contact.granted_to_me.iter())
    {
        if !scope.trim().is_empty() {
            seen.insert(scope.clone());
        }
    }
    if seen.is_empty() {
        "No shared scopes".to_owned()
    } else {
        seen.into_iter().collect::<Vec<_>>().join(", ")
    }
}

#[component]
fn RealmsManagePage(
    base_url: String,
    account_did: String,
    token: Signal<String>,
    has_session: bool,
    realm_rows: Vec<RealmManageRow>,
    mut realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    mut selected_realm_id: Signal<String>,
    mut sync_cursor: Signal<String>,
    mut state_store: Signal<LocalStateStore>,
    mut query: Signal<String>,
    mut selection: Signal<BTreeSet<String>>,
    mut busy: Signal<bool>,
    mut status: Signal<String>,
) -> Element {
    let normalized_query = query().trim().to_ascii_lowercase();
    let filtered_rows = realm_rows
        .iter()
        .filter(|row| {
            sidebar_text_matches_query(
                &normalized_query,
                &[&row.realm_id, &row.title, &row.display_name],
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    let selected_ids = selection.read().clone();
    let selection_count = selected_ids.len();

    rsx! {
        div { class: "settings workspace-manage-page", "data-testid": "realms-manage-page",
            div { class: "settings-shell workspace-manage-shell",
                section { class: "settings-content-stack workspace-manage-main",
                    div { class: "event workspace-manage-hero",
                        div { class: "workspace-manage-title-block",
                            span { class: "workspace-manage-icon", UiIcon { name: "home" } }
                            div {
                                h2 { class: "settings-content-title", "Manage Realms" }
                                div { class: "muted", "Bulk leave Realms and remove their local tree projections after the server confirms." }
                            }
                        }
                        div { class: "workspace-manage-stats",
                            span { class: "pill muted xs", "{filtered_rows.len()} shown" }
                            span { class: "pill muted xs", "{realm_rows.len()} total" }
                            span { class: "pill muted xs", "{selection_count} selected" }
                        }
                    }

                    div { class: "event workspace-manage-toolbar", "data-testid": "realms-manage-toolbar",
                        div { class: "workspace-manage-search",
                            span { class: "workspace-manage-search-icon", UiIcon { name: "search" } }
                            Input {
                                "data-testid": "realms-manage-search-input",
                                value: "{query}",
                                placeholder: "Search Realms",
                                oninput: move |event: FormEvent| query.set(event.value()),
                            }
                        }
                        div { class: "actions workspace-manage-actions",
                            Button {
                                variant: ButtonVariant::Secondary,
                                size: ButtonSize::Sm,
                                r#type: "button",
                                "data-testid": "realms-manage-select-all",
                                disabled: filtered_rows.is_empty() || busy(),
                                onclick: {
                                    let realm_ids = filtered_rows
                                        .iter()
                                        .map(|row| row.realm_id.clone())
                                        .collect::<BTreeSet<_>>();
                                    move |_| selection.set(realm_ids.clone())
                                },
                                "Select shown"
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                size: ButtonSize::Sm,
                                r#type: "button",
                                "data-testid": "realms-manage-clear",
                                disabled: selection_count == 0 || busy(),
                                onclick: move |_| selection.set(BTreeSet::new()),
                                "Clear"
                            }
                            Button {
                                variant: ButtonVariant::Destructive,
                                size: ButtonSize::Sm,
                                r#type: "button",
                                "data-testid": "realms-manage-leave-selected",
                                disabled: selection_count == 0 || busy() || !has_session,
                                onclick: {
                                    let base = base_url.clone();
                                    let actor_account_did = account_did.clone();
                                    move |_| {
                                        if busy() {
                                            return;
                                        }
                                        let selected = selection
                                            .read()
                                            .iter()
                                            .cloned()
                                            .collect::<Vec<_>>();
                                        if selected.is_empty() {
                                            return;
                                        }
                                        // Membership events are authored by the account/principal
                                        // DID (the bearer session actor), not the local device DID,
                                        // or the server rejects them with `actor_session_mismatch`.
                                        let actor_id = actor_account_did.clone();
                                        if actor_id.trim().is_empty() {
                                            status.set("Leave selected failed: account is not connected".to_owned());
                                            return;
                                        }
                                        let current_nodes = realm_tree_nodes();
                                        let ids_to_forget_by_realm = selected
                                            .iter()
                                            .map(|realm_id| {
                                                let mut ids = descendant_node_ids(&current_nodes, realm_id);
                                                if ids.is_empty() {
                                                    ids.push(realm_id.clone());
                                                }
                                                (realm_id.clone(), ids)
                                            })
                                            .collect::<BTreeMap<_, _>>();
                                        let total = selected.len();
                                        let api_token = token();
                                        let base = base.clone();
                                        busy.set(true);
                                        status.set(format!("Leaving {total} Realm(s)..."));
                                        spawn(async move {
                                            let mut succeeded = BTreeSet::<String>::new();
                                            let mut forgotten_ids = BTreeSet::<String>::new();
                                            let mut failed = Vec::<String>::new();
                                            for realm_id in selected {
                                                let realm_for_api = realm_id.clone();
                                                let actor_for_api = actor_id.clone();
                                                match crate::views::helpers::with_authed_api(
                                                    &base,
                                                    api_token.clone(),
                                                    |api| async move {
                                                        api.leave_realm(&realm_for_api, &actor_for_api).await
                                                    },
                                                )
                                                .await
                                                {
                                                    Ok(_) => {
                                                        succeeded.insert(realm_id.clone());
                                                        if let Some(ids) = ids_to_forget_by_realm.get(&realm_id) {
                                                            for id in ids {
                                                                state_store.write().forget_realm_tree_projection(id);
                                                                forgotten_ids.insert(id.clone());
                                                            }
                                                        }
                                                    }
                                                    Err(err) => failed.push(format!(
                                                        "{} ({})",
                                                        short_protocol_id(&realm_id),
                                                        err.display()
                                                    )),
                                                }
                                            }

                                            if !forgotten_ids.is_empty() {
                                                realm_tree_nodes.set(
                                                    realm_tree_nodes()
                                                        .into_iter()
                                                        .filter(|node| !forgotten_ids.contains(&node.id))
                                                        .collect(),
                                                );
                                                if forgotten_ids.contains(&selected_realm_id()) {
                                                    selected_realm_id.set(String::new());
                                                }
                                                sync_cursor.set("-".to_owned());
                                            }
                                            if !succeeded.is_empty() {
                                                let mut next_selection = selection();
                                                for realm_id in &succeeded {
                                                    next_selection.remove(realm_id);
                                                }
                                                selection.set(next_selection);
                                            }

                                            busy.set(false);
                                            if failed.is_empty() {
                                                status.set(format!(
                                                    "Left {} of {total} Realm(s).",
                                                    succeeded.len()
                                                ));
                                            } else {
                                                status.set(format!(
                                                    "Left {} of {total}; failed: {}",
                                                    succeeded.len(),
                                                    failed.join(", ")
                                                ));
                                            }
                                        });
                                    }
                                },
                                if busy() { "Leaving..." } else { "Leave selected" }
                            }
                        }
                    }

                    if !status.read().is_empty() {
                        div { class: "event workspace-manage-status", "data-testid": "realms-manage-status",
                            "{status}"
                        }
                    }

                    div { class: "event workspace-manage-list-card",
                        div { class: "event-head",
                            span { "Realms" }
                            span { "{filtered_rows.len()} rows" }
                        }
                        if realm_rows.is_empty() {
                            div { class: "members-empty", "data-testid": "realms-manage-empty",
                                div { class: "members-empty-title", if has_session { "No Realm tree loaded" } else { "Sign in to load Realms" } }
                                div { class: "muted members-empty-hint", "Realms will appear here after sync loads the collaboration tree." }
                            }
                        } else if filtered_rows.is_empty() {
                            div { class: "members-empty", "data-testid": "realms-manage-no-results",
                                div { class: "members-empty-title", "No matching Realms" }
                                div { class: "muted members-empty-hint", "Adjust the search query to show more rows." }
                            }
                        } else {
                            div { class: "workspace-manage-list", "data-testid": "realms-manage-list",
                                for row in filtered_rows {
                                    {
                                        let realm_id = row.realm_id.clone();
                                        let checked = selected_ids.contains(&realm_id);
                                        let security_label = if row.encrypted { "Encrypted" } else { "Unencrypted" };
                                        let security_icon = if row.encrypted { "lock" } else { "unlock" };
                                        rsx! {
                                            label {
                                                class: "workspace-manage-row",
                                                "data-testid": "realms-manage-row",
                                                "data-realm-id": "{realm_id}",
                                                Checkbox {
                                                    checked: if checked { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                                    on_checked_change: {
                                                        let realm_id = realm_id.clone();
                                                        move |state: CheckboxState| {
                                                            let mut next = selection();
                                                            if bool::from(state) {
                                                                next.insert(realm_id.clone());
                                                            } else {
                                                                next.remove(&realm_id);
                                                            }
                                                            selection.set(next);
                                                        }
                                                    },
                                                }
                                                div { class: "workspace-manage-row-main",
                                                    strong { title: "{row.title}", "{row.display_name}" }
                                                    span { class: "muted mono", title: "{realm_id}", "{realm_id}" }
                                                }
                                                div { class: "workspace-manage-row-meta",
                                                    span { class: "pill muted xs", title: "{security_label}",
                                                        UiIcon { name: security_icon }
                                                        "{security_label}"
                                                    }
                                                    span { class: "pill muted xs", "{row.space_count} spaces" }
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
}

#[component]
fn ContactsManagePage(
    base_url: String,
    token: Signal<String>,
    has_session: bool,
    mut contact_rows: Signal<Vec<crate::models::ContactListRow>>,
    mut contacts_loaded: Signal<bool>,
    mut app_status: Signal<String>,
    mut query: Signal<String>,
    mut selection: Signal<BTreeSet<String>>,
    mut busy: Signal<bool>,
    mut status: Signal<String>,
) -> Element {
    {
        let base = base_url.clone();
        use_effect(move || {
            if contacts_loaded() || token().trim().is_empty() {
                return;
            }
            load_direct_contacts_for_sidebar(
                base.clone(),
                token(),
                contact_rows,
                contacts_loaded,
                app_status,
            );
        });
    }

    let rows = contact_rows.read().clone();
    let normalized_query = query().trim().to_ascii_lowercase();
    let filtered_rows = rows
        .iter()
        .filter(|contact| {
            let scopes = contact_manage_scope_summary(contact);
            sidebar_text_matches_query(&normalized_query, &[&contact.peer, &contact.state, &scopes])
        })
        .cloned()
        .collect::<Vec<_>>();
    let selected_ids = selection.read().clone();
    let selection_count = selected_ids.len();

    rsx! {
        div { class: "settings workspace-manage-page", "data-testid": "contacts-manage-page",
            div { class: "settings-shell workspace-manage-shell",
                section { class: "settings-content-stack workspace-manage-main",
                    div { class: "event workspace-manage-hero",
                        div { class: "workspace-manage-title-block",
                            span { class: "workspace-manage-icon", UiIcon { name: "users" } }
                            div {
                                h2 { class: "settings-content-title", "Manage Contacts" }
                                div { class: "muted", "Bulk delete contacts and keep successful rows out of the current contact list." }
                            }
                        }
                        div { class: "workspace-manage-stats",
                            span { class: "pill muted xs", "{filtered_rows.len()} shown" }
                            span { class: "pill muted xs", "{rows.len()} total" }
                            span { class: "pill muted xs", "{selection_count} selected" }
                        }
                    }

                    div { class: "event workspace-manage-toolbar", "data-testid": "contacts-manage-toolbar",
                        div { class: "workspace-manage-search",
                            span { class: "workspace-manage-search-icon", UiIcon { name: "search" } }
                            Input {
                                "data-testid": "contacts-manage-search-input",
                                value: "{query}",
                                placeholder: "Search Contacts",
                                oninput: move |event: FormEvent| query.set(event.value()),
                            }
                        }
                        div { class: "actions workspace-manage-actions",
                            Button {
                                variant: ButtonVariant::Secondary,
                                size: ButtonSize::Sm,
                                r#type: "button",
                                "data-testid": "contacts-manage-select-all",
                                disabled: filtered_rows.is_empty() || busy(),
                                onclick: {
                                    let peers = filtered_rows
                                        .iter()
                                        .map(|contact| contact.peer.clone())
                                        .collect::<BTreeSet<_>>();
                                    move |_| selection.set(peers.clone())
                                },
                                "Select shown"
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                size: ButtonSize::Sm,
                                r#type: "button",
                                "data-testid": "contacts-manage-clear",
                                disabled: selection_count == 0 || busy(),
                                onclick: move |_| selection.set(BTreeSet::new()),
                                "Clear"
                            }
                            Button {
                                variant: ButtonVariant::Destructive,
                                size: ButtonSize::Sm,
                                r#type: "button",
                                "data-testid": "contacts-manage-delete-selected",
                                disabled: selection_count == 0 || busy() || !has_session,
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
                                        if busy() {
                                            return;
                                        }
                                        let selected = selection
                                            .read()
                                            .iter()
                                            .cloned()
                                            .collect::<Vec<_>>();
                                        if selected.is_empty() {
                                            return;
                                        }
                                        let total = selected.len();
                                        let api_token = token();
                                        let base = base.clone();
                                        busy.set(true);
                                        status.set(format!("Deleting {total} contact(s)..."));
                                        spawn(async move {
                                            let mut succeeded = BTreeSet::<String>::new();
                                            let mut failed = Vec::<String>::new();
                                            for peer in selected {
                                                let peer_for_api = peer.clone();
                                                match crate::views::helpers::with_authed_api(
                                                    &base,
                                                    api_token.clone(),
                                                    |api| async move {
                                                        api.tombstone_contact(&peer_for_api, false).await
                                                    },
                                                )
                                                .await
                                                {
                                                    Ok(_) => {
                                                        succeeded.insert(peer);
                                                    }
                                                    Err(err) => failed.push(format!(
                                                        "{} ({})",
                                                        short_protocol_id(&peer),
                                                        err.display()
                                                    )),
                                                }
                                            }

                                            if !succeeded.is_empty() {
                                                let mut next_selection = selection();
                                                for peer in &succeeded {
                                                    next_selection.remove(peer);
                                                }
                                                selection.set(next_selection);
                                                match crate::views::helpers::with_authed_api(
                                                    &base,
                                                    api_token.clone(),
                                                    |api| async move { api.contacts().await },
                                                )
                                                .await
                                                {
                                                    Ok(response) => {
                                                        contact_rows.set(response.contacts);
                                                        contacts_loaded.set(true);
                                                    }
                                                    Err(err) => app_status.set(format!(
                                                        "contacts refresh: {}",
                                                        err.display()
                                                    )),
                                                }
                                            }

                                            busy.set(false);
                                            if failed.is_empty() {
                                                status.set(format!(
                                                    "Deleted {} of {total} contact(s).",
                                                    succeeded.len()
                                                ));
                                            } else {
                                                status.set(format!(
                                                    "Deleted {} of {total}; failed: {}",
                                                    succeeded.len(),
                                                    failed.join(", ")
                                                ));
                                            }
                                        });
                                    }
                                },
                                if busy() { "Deleting..." } else { "Delete selected" }
                            }
                        }
                    }

                    if !status.read().is_empty() {
                        div { class: "event workspace-manage-status", "data-testid": "contacts-manage-status",
                            "{status}"
                        }
                    }

                    div { class: "event workspace-manage-list-card",
                        div { class: "event-head",
                            span { "Contacts" }
                            span { "{filtered_rows.len()} rows" }
                        }
                        if rows.is_empty() {
                            div { class: "members-empty", "data-testid": "contacts-manage-empty",
                                div { class: "members-empty-title",
                                    {if has_session { crate::i18n::tr("contacts.empty") } else { crate::i18n::tr("contacts.sign_in") }}
                                }
                                div { class: "muted members-empty-hint", "Accepted, pending, and tombstoned contact rows appear here after loading." }
                            }
                        } else if filtered_rows.is_empty() {
                            div { class: "members-empty", "data-testid": "contacts-manage-no-results",
                                div { class: "members-empty-title", "No matching contacts" }
                                div { class: "muted members-empty-hint", "Adjust the search query to show more rows." }
                            }
                        } else {
                            div { class: "workspace-manage-list", "data-testid": "contacts-manage-list",
                                for contact in filtered_rows {
                                    {
                                        let peer = contact.peer.clone();
                                        let checked = selected_ids.contains(&peer);
                                        let scopes_label = contact_manage_scope_summary(&contact);
                                        let direct_label = contact
                                            .direct_conversation
                                            .as_ref()
                                            .map(|summary| format!("DM {}", summary.state))
                                            .unwrap_or_else(|| "No DM".to_owned());
                                        rsx! {
                                            label {
                                                class: "workspace-manage-row",
                                                "data-testid": "contacts-manage-row",
                                                "data-peer": "{peer}",
                                                Checkbox {
                                                    checked: if checked { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                                    on_checked_change: {
                                                        let peer = peer.clone();
                                                        move |state: CheckboxState| {
                                                            let mut next = selection();
                                                            if bool::from(state) {
                                                                next.insert(peer.clone());
                                                            } else {
                                                                next.remove(&peer);
                                                            }
                                                            selection.set(next);
                                                        }
                                                    },
                                                }
                                                div { class: "workspace-manage-row-main",
                                                    strong { title: "{peer}", "{peer}" }
                                                    span { class: "muted", title: "{scopes_label}", "{scopes_label}" }
                                                }
                                                div { class: "workspace-manage-row-meta",
                                                    span { class: "pill muted xs", "{contact.state}" }
                                                    span { class: "pill muted xs", "{direct_label}" }
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
}

#[component]
fn RealmContextBar(
    realm_id: String,
    current_surface: Option<RealmSurface>,
    account_did: String,
    state_store: Signal<LocalStateStore>,
    members_active: bool,
    minimal_ready: bool,
    kanban_ready: bool,
    full_ready: bool,
) -> Element {
    let mut menu_open = use_signal(|| false);
    let (current_nav_label, current_nav_icon) = match current_surface {
        Some(surface) => (surface.short_label(), surface.icon_name()),
        None if members_active => ("Members", "users"),
        None => ("Settings", "settings"),
    };
    rsx! {
        div { class: "realm-context-bar", "data-testid": "realm-context-bar",
            div { class: "actions realm-nav-inline", "data-testid": "realm-context-inline",
                for surface in RealmSurface::top_nav() {
                    if surface.is_available(minimal_ready, kanban_ready, full_ready) {
                        Link {
                            class: if current_surface == Some(surface) { "primary" } else { "secondary" },
                            to: surface.route(realm_id.clone()),
                            onclick: {
                                let account_did = account_did.clone();
                                let realm_id = realm_id.clone();
                                move |_| {
                                    persist_realm_surface_preference(
                                        &mut state_store.write(),
                                        &account_did,
                                        &realm_id,
                                        surface,
                                    );
                                }
                            },
                            UiIcon { name: surface.icon_name() }
                            "{surface.short_label()}"
                        }
                    } else {
                        Button {
                            variant: ButtonVariant::Secondary,
                            disabled: true,
                            UiIcon { name: surface.icon_name() }
                            "{surface.short_label()}"
                        }
                    }
                }
                Link {
                    class: if members_active { "primary" } else { "secondary" },
                    to: Route::RealmMembers { realm_id: realm_id.clone() },
                    UiIcon { name: "users" }
                    "Members"
                }
                Link {
                    class: if current_surface.is_none() && !members_active { "primary" } else { "secondary" },
                    to: Route::RealmAdmin { realm_id: realm_id.clone() },
                    UiIcon { name: "settings" }
                    "Settings"
                }
            }
            div {
                class: if menu_open() { "realm-nav-menu-host is-open" } else { "realm-nav-menu-host" },
                "data-testid": "realm-context-menu",
                Button {
                    variant: ButtonVariant::Secondary,
                    size: ButtonSize::Sm,
                    class: "btn icon realm-nav-menu-button",
                    "data-testid": "realm-context-menu-button",
                    title: "Switch view: {current_nav_label}",
                    "aria-label": "Switch Realm view",
                    "aria-expanded": "{menu_open()}",
                    onclick: move |_| menu_open.toggle(),
                    UiIcon { name: current_nav_icon }
                }
                if menu_open() {
                    Button {
                        variant: ButtonVariant::Secondary,
                        class: "realm-nav-menu-scrim",
                        "aria-label": "Close Realm view menu",
                        onclick: move |_| menu_open.set(false),
                    }
                    div {
                        class: "realm-nav-menu-panel",
                        role: "menu",
                        "aria-label": "Realm views",
                        for surface in RealmSurface::top_nav() {
                            if surface.is_available(minimal_ready, kanban_ready, full_ready) {
                                Link {
                                    class: if current_surface == Some(surface) { "realm-nav-menu-item is-active" } else { "realm-nav-menu-item" },
                                    role: "menuitem",
                                    to: surface.route(realm_id.clone()),
                                    onclick: {
                                        let account_did = account_did.clone();
                                        let realm_id = realm_id.clone();
                                        move |_| {
                                            persist_realm_surface_preference(
                                                &mut state_store.write(),
                                                &account_did,
                                                &realm_id,
                                                surface,
                                            );
                                            menu_open.set(false);
                                        }
                                    },
                                    UiIcon { name: surface.icon_name() }
                                    "{surface.short_label()}"
                                }
                            } else {
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    class: "realm-nav-menu-item",
                                    role: "menuitem",
                                    disabled: true,
                                    UiIcon { name: surface.icon_name() }
                                    "{surface.short_label()}"
                                }
                            }
                        }
                        Link {
                            class: if members_active { "realm-nav-menu-item is-active" } else { "realm-nav-menu-item" },
                            role: "menuitem",
                            to: Route::RealmMembers { realm_id: realm_id.clone() },
                            onclick: move |_| menu_open.set(false),
                            UiIcon { name: "users" }
                            "Members"
                        }
                        Link {
                            class: if current_surface.is_none() && !members_active { "realm-nav-menu-item is-active" } else { "realm-nav-menu-item" },
                            role: "menuitem",
                            to: Route::RealmAdmin { realm_id: realm_id.clone() },
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
        ("Home", "overview, recent activity", Route::Dashboard),
        ("Files", "private file transfer", Route::FileTransfer),
        (
            "Notifications",
            "inbox, mentions, approvals",
            Route::Notifications,
        ),
        ("Search", "messages across realms", Route::Search),
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
            "Recovery Key (24 words)",
            Route::SettingsRecovery,
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
    nodes: Vec<RealmTreeNode>,
    on_navigate: EventHandler<Route>,
    on_pick_realm: EventHandler<String>,
    on_close: EventHandler<()>,
) -> Element {
    let dest_list = palette_destinations();
    let matched_dests: Vec<_> = dest_list
        .iter()
        .filter(|(label, hint, _)| palette_filter(&query, &format!("{label} {hint}")))
        .cloned()
        .collect();
    let matched_nodes: Vec<RealmTreeNode> = nodes
        .iter()
        .filter(|node| palette_filter(&query, &format!("{} {}", node.title, node.id)))
        .take(10)
        .cloned()
        .collect();

    rsx! {
        div {
            class: "command-palette",
            "data-testid": "command-palette",
            role: "listbox",
            "aria-label": "Command palette",
            if matched_nodes.is_empty() && matched_dests.is_empty() {
                div { class: "command-palette-empty", "data-testid": "command-palette-empty",
                    {crate::i18n::tr("command_palette.empty")}
                }
            }
            if !matched_nodes.is_empty() {
                div { class: "command-palette-group",
                    div { class: "command-palette-label", {crate::i18n::tr("command_palette.realms")} }
                    for node in matched_nodes.iter() {
                        {
                            let node_id_label = short_protocol_id(&node.id);
                            let target_realm_id = node.projection_realm_id().to_owned();
                            let node_kind_label = match node.kind {
                                RealmTreeNodeKind::Realm => "Realm",
                                RealmTreeNodeKind::Space => "Space",
                            };
                            rsx! {
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    class: "command-palette-item",
                                    "data-testid": "command-palette-realm-tree-node",
                                    role: "option",
                                    "aria-label": "Open {node_kind_label} {node.title}",
                                    onclick: {
                                        let realm_id = target_realm_id.clone();
                                        move |_| on_pick_realm.call(realm_id.clone())
                                    },
                                    span { class: "command-palette-item-title", "{node.title}" }
                                    span { class: "command-palette-item-hint", title: "{node.id}", "{node_id_label}" }
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
                        Button {
                            variant: ButtonVariant::Secondary,
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
                Button {
                    variant: ButtonVariant::Ghost,
                    size: ButtonSize::Sm,
                    class: "btn",
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
                div { class: "entity-title", "{body}" }
                div { class: "profile-gate-details",
                    Button {
                        variant: ButtonVariant::Secondary,
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

// YOU-05-009: the main-strand id derivation is a protocol mapping rule; the
// single authoritative copy lives in `crate::local_state`.
use crate::local_state::default_strand_id_for_realm;

fn route_label(route: &Route) -> &'static str {
    match route {
        Route::Dashboard => "Home",
        Route::Login | Route::AuthCallback => "Login",
        Route::RealmsManage => "Manage Realms",
        Route::Realm { .. } => "Realm",
        Route::Timeline | Route::TimelineRealm { .. } | Route::TimelineMessage { .. } => {
            "Timeline View"
        }
        Route::Chat { .. } => "Discussion",
        Route::DirectConversation { .. } => "Direct",
        Route::ContactsManage => "Manage Contacts",
        Route::Contacts => "Contacts",
        Route::FileTransfer => "Files",
        Route::Directory => "Search",
        Route::Setup => "New Realm",
        Route::SetupSection { section } => match section.as_str() {
            "realms" => "New Realm",
            "new-space" => "New Space",
            _ => "Setup",
        },
        Route::Settings => "Settings",
        Route::SettingsSection { section } => settings_route_label(section),
        Route::NotificationsSettings => "Notifications",
        Route::VerifyDevice => "Verify Device",
        Route::RealmMembers { .. } => "Members",
        Route::RealmAdmin { .. } => "Realm Settings",
        Route::RealmAdminSection { section, .. } => match section.as_str() {
            "profile" => "Profile",
            "access" => "Access Policy",
            "security" => "Security & MLS",
            "federation" => "Federation Trust",
            "repair" => "Repair & Danger",
            _ => "Realm Settings",
        },
        Route::Audit | Route::Developer => "Diagnostics",
        Route::Kanban
        | Route::KanbanRealm { .. }
        | Route::KanbanBoard { .. }
        | Route::KanbanBoardTask { .. }
        | Route::KanbanTask { .. } => "Board View",
        Route::Notifications => "Notifications",
        Route::Document | Route::DocumentNew | Route::DocumentRealm { .. } => "Document View",
        Route::Call { .. } => "Call",
        Route::Recovery => "Recovery",
        Route::SettingsDevices => "Devices",
        Route::SettingsDevicesPair => "Pair new device",
        Route::SettingsRecovery => "Recovery",
        Route::Onboarding => "Onboarding",
        Route::Quarantine => "Invite Quarantine",
        Route::Applets => "Applets",
        Route::Agents => "Agents",
        Route::Search => "Search",
    }
}

fn settings_route_label(section: &str) -> &'static str {
    match section {
        "server" => "Account & server",
        "devices" => "Devices",
        "storage" => "Data & sync",
        "encryption" => "Security",
        "security" | "key-backup" | "recovery" => "Recovery",
        "mimi" => "Integrations",
        "push" | "notifications" => "Notifications",
        "privacy" => "Privacy & sharing",
        "invite-policy" | "invite_policy" => "Who can invite me",
        "blocklist" | "blocked-users" => "Blocked actors",
        "capabilities" => "Capabilities",
        "timeline" | "composer" => "Timeline & composer",
        "audit" | "audit-log" | "developer" | "developer-tools" => "Diagnostics",
        "theme" => "Appearance & locale",
        "release" => "Diagnostics",
        _ => "Settings",
    }
}

fn display_handles_from_directory_response(
    res: &cokret_sdk::models::DirectorySubjectHandleList,
) -> Vec<String> {
    let mut seen = BTreeSet::<String>::new();
    let mut handles = Vec::<String>::new();
    let mut push_handle = |handle: String| {
        if !handle.trim().is_empty() && seen.insert(handle.clone()) {
            handles.push(handle);
        }
    };
    if let Some(primary) = res.primary_handle.as_ref() {
        push_handle(primary.canonical().to_owned());
    }
    for claim in &res.claims {
        if let Some(handle) = claim.handle.as_ref() {
            push_handle(handle.canonical().to_owned());
        }
    }
    handles
}

fn personal_handle_from_account_localpart(
    account_localpart: &str,
    server_url: &str,
) -> Option<String> {
    let normalized_localpart = account_localpart.trim().trim_start_matches('@').trim();
    if normalized_localpart.is_empty() {
        return None;
    }
    let server_host = handle_domain_from_server_url(server_url)?;
    Some(format!("{normalized_localpart}:{server_host}"))
}

fn handle_domain_from_server_url(server_url: &str) -> Option<String> {
    let normalized = normalize_server_url(server_url);
    url::Url::parse(&normalized)
        .ok()?
        .host_str()
        .map(str::to_owned)
}

fn account_handles_display(handles: &[String], fallback: &str) -> String {
    if handles.is_empty() {
        fallback.to_owned()
    } else {
        handles
            .iter()
            .map(|handle| format!("@{handle}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

pub(crate) fn server_key(server_url: &str) -> String {
    normalize_server_url(server_url)
        .trim()
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

fn same_server_url(left: &str, right: &str) -> bool {
    server_key(left) == server_key(right)
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
    selected_realm_id: Signal<String>,
    realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
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
    personal_handles: Signal<Vec<String>>,
    personal_handles_status: Signal<String>,
    personal_handles_lookup_key: Signal<String>,
    /// SyncEngine generation counter — bumped to retire the
    /// previous-server engine after the cache wipe + URL repoint.
    sync_generation: Signal<u64>,
}

fn select_server(server_url: String, ctx: ServerSelectionContext) {
    let server_url = normalize_server_url(&server_url);
    let mut base_url = ctx.base_url;
    let mut token = ctx.token;
    let mut sync_cursor = ctx.sync_cursor;
    let mut selected_realm_id = ctx.selected_realm_id;
    let mut realm_tree_nodes = ctx.realm_tree_nodes;
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
    let mut personal_handles = ctx.personal_handles;
    let mut personal_handles_status = ctx.personal_handles_status;
    let mut personal_handles_lookup_key = ctx.personal_handles_lookup_key;
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
    selected_realm_id.set(String::new());
    realm_tree_nodes.set(Vec::new());
    timeline.set(Vec::new());
    device_queue.set(0);
    frontier_state.set("Not loaded".to_owned());
    crypto_state.set("Refresh session for selected server".to_owned());
    personal_handles.set(Vec::new());
    personal_handles_status.set("Not published".to_owned());
    personal_handles_lookup_key.set(String::new());
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

async fn refresh_oidc_bearer_for_server(
    principal_server_url: &str,
    actor_id: &str,
    device_id: &str,
    previous: &crate::local_state::OidcTokenBundle,
) -> anyhow::Result<crate::local_state::OidcTokenBundle> {
    let refresh_token = previous
        .refresh_token
        .as_deref()
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("OIDC bundle has no refresh_token"))?;
    let _ = (actor_id, device_id);
    // T1.Y1/T1.Y4 — resolve the OIDC method via describe.auth_metadata, then do
    // standard OIDC discovery to find the token_endpoint + client_id for the
    // refresh_token grant. No Cokret-private bridge / topology snapshot.
    let resolver = crate::coauth::AuthorityResolver::discover(principal_server_url)
        .await
        .map_err(|error| anyhow::anyhow!("resolve account authority: {error}"))?;
    let method = resolver
        .oidc_method(None)
        .map_err(|error| anyhow::anyhow!("no oidc method: {error}"))?;
    let discovery_url = method
        .openid_configuration
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            method
                .issuer
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|issuer| {
                    format!(
                        "{}/.well-known/openid-configuration",
                        issuer.trim_end_matches('/')
                    )
                })
        })
        .ok_or_else(|| anyhow::anyhow!("oidc method published no discovery url"))?;
    let discovery = crate::coauth::CoauthApi::fetch_oidc_discovery(&discovery_url).await?;
    let token_endpoint = discovery
        .token_endpoint
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("oidc discovery published no token_endpoint"))?;
    let client_id = method
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("yougen");
    let coauth = crate::coauth::CoauthApi::new(&resolver.gate_account_base)?;
    let response = coauth
        .refresh_oidc_tokens(token_endpoint, client_id, refresh_token)
        .await?;
    Ok(crate::oidc::lifecycle::apply_refresh_response(
        previous, &response,
    ))
}

fn oidc_refresh_error_invalidates_grant(error: &anyhow::Error) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("invalid_grant")
        || (message.contains("refresh endpoint returned 400")
            && (message.contains("expired")
                || message.contains("revoked")
                || message.contains("provided access grant is invalid")
                || (message.contains("refresh") && message.contains("invalid"))))
}

async fn reissue_development_session(
    principal_server_url: &str,
    actor_id: &str,
    device_id: &str,
) -> Option<crate::models::SessionLoginOutcome> {
    if !can_attempt_development_session_reissue(principal_server_url, actor_id, device_id) {
        return None;
    }
    let api = CokretApi::new(principal_server_url).ok()?;
    let description = api.describe().await.ok()?;
    if !description.development_mode {
        return None;
    }
    api.dev_login(actor_id.trim(), device_id.trim()).await.ok()
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
    session_generation: Signal<u64>,
) -> Option<String> {
    let base = base_url();
    let actor = account_did();
    let device = device_id();
    let generation = session_generation();

    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let oidc_bundle = {
        let store = state_store.read();
        store.load_oidc_tokens_with_secure_store(&actor, secure_store.as_ref())
    };
    if let Some(bundle) = oidc_bundle
        && crate::oidc::lifecycle::has_refresh_token(&bundle)
    {
        match refresh_oidc_bearer_for_server(&base, &actor, &device, &bundle).await {
            Ok(next) => {
                // Abandon if the user switched servers while the refresh was in
                // flight, or if a logout invalidated this refresh generation.
                // Committing here would resurrect stale credentials over the
                // freshly selected or logged-out session.
                if !same_server_url(&base, &base_url()) || session_generation() != generation {
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
            Err(error) if oidc_refresh_error_invalidates_grant(&error) => {
                if !same_server_url(&base, &base_url()) || session_generation() != generation {
                    return None;
                }
                tracing::warn!(
                    ?error,
                    actor = %actor,
                    "OIDC refresh_token was rejected permanently; clearing persisted OIDC bundle before fallback",
                );
                state_store.write().set_oidc_tokens_with_secure_store(
                    None,
                    &actor,
                    secure_store.as_ref(),
                );
            }
            Err(error) => {
                tracing::warn!(
                    ?error,
                    actor = %actor,
                    "OIDC refresh attempt failed without invalidating the stored refresh_token",
                );
            }
        }
    }

    // ②(A+②): multi-day sliding session. The held credential is the grant
    // itself; when it is near its own expiry the refresh path rotates it (DPoP
    // holder proof signed by the durable device key bound into `cnf.jkt`) onto a
    // fresh grant, and the rotated grant JWT becomes the live credential. There
    // is no longer a grant→bearer exchange. `prepare_refresh_for_server_after_unauthorized`
    // forces a rotation attempt even when the local expiry metadata looks fresh
    // (the server may have rotated/revoked the grant early).
    let prepared = {
        let mut store = state_store.write();
        crate::session_refresh::prepare_refresh_for_server_after_unauthorized(&mut store, &base)
    };
    let outcome = match prepared {
        crate::session_refresh::RefreshPrepared::Done(outcome) => outcome,
        crate::session_refresh::RefreshPrepared::Ready {
            grant,
            device_handle,
        } => {
            let result = crate::session_refresh::exchange_refresh(&grant, &device_handle).await;
            // Same server-switch guard as the OIDC path: don't write the
            // old server's grant outcome onto a session that just moved or
            // logged out.
            if !same_server_url(&base, &base_url()) || session_generation() != generation {
                return None;
            }
            let mut store = state_store.write();
            crate::session_refresh::commit_refresh(&mut store, result)
        }
    };
    match outcome {
        crate::session_refresh::RefreshOutcome::Refreshed { access_token, .. } => {
            if session_generation() != generation {
                return None;
            }
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
            let can_reissue_development_session = {
                let store = state_store.read();
                let state = store.load();
                can_bootstrap_with_development_session_reissue(&state, &base, &actor, &device)
            };
            if !can_reissue_development_session {
                return None;
            }
            if let Some(session) = reissue_development_session(&base, &actor, &device).await {
                if !same_server_url(&base, &base_url()) || session_generation() != generation {
                    return None;
                }
                let access_token = session.access_token.clone();
                let actor = if session.actor.as_str().trim().is_empty() {
                    actor
                } else {
                    session.actor.as_str().to_owned()
                };
                let device = if session.device_id.as_str().trim().is_empty() {
                    device
                } else {
                    session.device_id.as_str().to_owned()
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
    selected_realm_id: Signal<String>,
    realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
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
    personal_handles: Signal<Vec<String>>,
    personal_handles_status: Signal<String>,
    /// A4a: shared UI theme signal so `/sync` can hydrate the theme
    /// from the remote `client.ui` account-data payload right after
    /// session bootstrap. Stub field — wire-up is tracked under A4a.
    theme: Signal<String>,
    /// SyncEngine generation counter. Bumped when `connect()` detects
    /// the canonical actor has changed since the last persisted run
    /// (account swap on the same device) so any in-flight engine for
    /// the previous account exits before applying its response.
    sync_generation: Signal<u64>,
    needs_device_authorization: Signal<bool>,
    device_authorization_check_complete: Signal<bool>,
    account_has_other_devices: Signal<bool>,
    /// Set when the explicit bootstrap/manual connect attempt has completed.
    /// The background SyncEngine waits for this so it does not race the
    /// first full account-subscribe snapshot on the same render.
    sync_bootstrap_complete: Signal<bool>,
    session_boot_state: Signal<SessionBootState>,
    navigator: Navigator,
    /// Receive-side call-signaling hub. The full boot sync routes inbound
    /// `ck.call.signal` envelopes into it (dedup → incoming ring / per-call
    /// inbox); `CallPanel` drains it. See `crate::views::call_signals`.
    call_signal_hub: crate::views::call_signals::CallSignalHub,
    /// Session DID-resolution cache handle. The boot sync's Tier-2 device-key
    /// chain verification (`device-lifecycle.md` §8.3) anchors the published
    /// PSK against the actor's DID document through a resolver backed by a
    /// snapshot of this cache; back-fills are written back. Shared with the
    /// SyncEngine's `did_cache` so both receive paths reuse resolved documents.
    did_cache: Signal<crate::did_resolver::DidResolutionCache>,
}

fn redirect_to_login(navigator: Navigator) {
    let _ = navigator.push(Route::Login);
}

/// ②(A+②) — build a `/_cokret/self/*`-ready client: the credential
/// (`ck.session.grant` JWT) as the bearer plus the device DPoP holder key so
/// each request carries a per-request `DPoP` proof (api-conventions.md §3.3).
/// Used by standalone (non-`connect`) self-path call sites that build their own
/// `CokretApi`. Best-effort on the DPoP key: if it cannot be loaded the bearer
/// is still attached (dev-login / OAuth-introspection inbound paths).
fn self_authed_api(base: &str, grant_or_bearer: impl Into<String>) -> anyhow::Result<CokretApi> {
    let api = CokretApi::new(base)?.with_bearer(grant_or_bearer);
    Ok(crate::views::helpers::attach_device_dpop(api))
}

fn adopt_live_token_for_api(
    api: &CokretApi,
    live_token: Signal<String>,
    session_token: &mut String,
    authed: &mut CokretApi,
) {
    let latest = live_token();
    if !latest.trim().is_empty() && latest != *session_token {
        *session_token = latest;
        *authed = api.clone().with_bearer(session_token.clone());
    }
}

/// Enroll the current session `device` through the delegated account authority
/// (decision 0002 §5.4). Resolves the gate base from the Principal Server's
/// describe, derives this device's `device_public_key` from the persisted
/// signing seed, reads the next `actor_seq` from the principal control stream,
/// asks coauth to mint a signed `service_attested` `ck.device.authorize`, and
/// submits it via `principal_api` (`POST /_cokret/self/events`).
async fn enroll_current_session_device(
    base: &str,
    actor: &str,
    device: &str,
    principal_api: &CokretApi,
    mut state_store: Signal<crate::local_state::LocalStateStore>,
) -> anyhow::Result<()> {
    let actor = actor.trim();
    if actor.is_empty() {
        anyhow::bail!("device enrollment requires a known account DID");
    }
    let grant = state_store
        .read()
        .session_grant()
        .ok_or_else(|| anyhow::anyhow!("device enrollment requires an active session grant"))?;

    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let material = crate::secure_key_store::ensure_signing_seed(secure_store.as_ref())
        .map_err(|error| anyhow::anyhow!("ensure device signing seed: {error}"))?;
    let device_public_key = crate::device_enrollment::device_public_key_multibase(&material);

    let gate_account_base = crate::coauth::resolve_principal_auth_server_url(base)
        .await
        .map_err(|error| anyhow::anyhow!("resolve account authority: {error}"))?;
    let coauth = crate::coauth::CoauthApi::new(&gate_account_base)?;

    let device_key = {
        let mut store = state_store.write();
        crate::auth_dpop::ensure_device_key(&mut store)
            .map_err(|error| anyhow::anyhow!("load device holder key: {error}"))?
    };
    let htu = coauth.endpoint_url("device-authorize")?;
    let dpop_proof = device_key
        .mint_proof("POST", &htu, Some(&grant.grant_jwt))
        .map_err(|error| anyhow::anyhow!("mint device-authorize DPoP proof: {error}"))?;

    // Next control-stream sequence for this principal = highest accepted + 1.
    // `actor_seq` is 1-indexed on the Principal Server (soland rejects 0 with
    // `actor_seq must be greater than zero`), so an empty stream (no frontier
    // yet) enrolls at seq 1, not 0.
    let actor_seq = match principal_api.events_frontier_actor(actor).await {
        Ok(view) => view.actor_seq.saturating_add(1),
        Err(error) => {
            tracing::debug!(?error, "no actor frontier yet; enrolling at seq 1");
            1
        }
    };

    let request = crate::device_enrollment::DeviceEnrollmentRequest {
        grant_jwt: grant.grant_jwt,
        dpop_proof,
        device_id: device.to_owned(),
        device_public_key,
        actor_seq,
        not_before: None,
    };
    crate::device_enrollment::enroll_current_device(&coauth, principal_api, &request, device).await
}

fn connect(base: String, actor: String, device: String, ctx: ConnectContext) {
    let device = normalize_device_id(&device);
    spawn(async move {
        let mut sync_bootstrap_complete = ctx.sync_bootstrap_complete;
        let mut status = ctx.status;
        let mut sync_cursor = ctx.sync_cursor;
        let mut token = ctx.token;
        let mut account_did = ctx.account_did;
        let mut selected_realm_id = ctx.selected_realm_id;
        let mut realm_tree_nodes = ctx.realm_tree_nodes;
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
        let mut personal_handles = ctx.personal_handles;
        let mut personal_handles_status = ctx.personal_handles_status;
        let mut theme = ctx.theme;
        let navigator = ctx.navigator;
        let mut session_boot_state = ctx.session_boot_state;
        let mut needs_device_authorization = ctx.needs_device_authorization;
        let mut device_authorization_check_complete = ctx.device_authorization_check_complete;
        let mut account_has_other_devices = ctx.account_has_other_devices;

        needs_device_authorization.set(false);
        device_authorization_check_complete.set(false);
        account_has_other_devices.set(false);
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
                // ②(A+②) — bind the device DPoP holder key so every clone of
                // this base client attaches a per-request `DPoP` proof to
                // `/_cokret/self/*` requests (api-conventions.md §3.3). The grant
                // (set later via `with_bearer`) is the credential; the DPoP key
                // sender-constrains it. `with_bearer` preserves this field, so all
                // `api.clone().with_bearer(grant)` sites below inherit the DPoP
                // device. Falls back to bearer-only if no device key is available.
                let device_handle = crate::auth_dpop::load_device_key(&state_store.read())
                    .ok()
                    .flatten();
                let persisted_grant = state_store.read().session_grant();
                let api = match device_handle {
                    Some(handle) => {
                        let mut api = api.with_dpop_device(handle.clone());
                        // Attach the session-grant holder proof (minted from the
                        // persisted grant + device key) so the Principal Server's
                        // grant introspection passes on cache-miss / restore, not
                        // just within the ≤120s introspection cache window seeded
                        // by the initial login.
                        if let Some(grant) = persisted_grant
                            && let Ok(proof) = handle.mint_session_grant_introspection_proof(
                                &grant.grant_id,
                                &grant.grant_jwt,
                                &grant.audience,
                            )
                        {
                            api = api.with_session_grant_proof(proof);
                        }
                        api
                    }
                    None => api,
                };
                // Probe `/server/describe` for status text, but treat failure
                // as non-fatal: a transient describe error (CORS preflight,
                // server warming up, brief 5xx) must not block the sync below
                // — otherwise an existing session with cached/server-side
                // the Realm tree silently renders "No Realm tree loaded" until the user
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
                        // downstream signing strands (cross_signing.publish,
                        // S2S transcripts) can pull a canonical
                        // value off local state without an extra round
                        // trip. Cleared when describe fails so a stale
                        // domain can't leak into the next strand.
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
                if !session_token.trim().is_empty()
                    && let Some(refreshed) = crate::session::refresh_current_bearer().await
                {
                    session_token = refreshed;
                    session_boot_state.set(SessionBootState::Checking);
                }
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
                        realm_tree_nodes.set(Vec::new());
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
                        needs_device_authorization.set(false);
                        device_authorization_check_complete.set(true);
                        session_boot_state.set(SessionBootState::Unauthenticated);
                        sync_bootstrap_complete.set(true);
                        return;
                    }
                }

                let mut authed = api.clone().with_bearer(session_token.clone());
                adopt_live_token_for_api(&api, token, &mut session_token, &mut authed);
                // Resolve the canonical actor DID from the account viewer. Three
                // outcomes:
                //   1. Ok with non-empty DID -> use it as canonical_actor.
                //   2. Err that looks like auth expiry -> wipe session, bounce to login. The
                //      session is provably dead.
                //   3. Anything else (Ok with empty DID, transient 5xx, parse error, network
                //      failure) -> fall back to the locally stored actor, log a diagnostic to
                //      last_error so the sidebar/status surface can show it, and keep going so sync
                //      still has a chance to populate realm_tree_nodes.
                let mut account_personal_handle = None::<String>;
                let canonical_actor = match authed.account_me().await {
                    Ok(account) if !account.did.trim().is_empty() => {
                        account_personal_handle =
                            personal_handle_from_account_localpart(&account.handle, &base);
                        account.did
                    }
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
                                Ok(account) if !account.did.trim().is_empty() => {
                                    account_personal_handle =
                                        personal_handle_from_account_localpart(
                                            &account.handle,
                                            &base,
                                        );
                                    account.did
                                }
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
                                    selected_realm_id.set(String::new());
                                    realm_tree_nodes.set(Vec::new());
                                    timeline.set(Vec::new());
                                    device_queue.set(0);
                                    crypto_state.set("Session expired".to_owned());
                                    status.set("Session expired; sign in again".to_owned());
                                    network_state.set("online".to_owned());
                                    last_error
                                        .set(Some("auth_expired: session expired".to_owned()));
                                    needs_device_authorization.set(false);
                                    device_authorization_check_complete.set(true);
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
                            selected_realm_id.set(String::new());
                            realm_tree_nodes.set(Vec::new());
                            timeline.set(Vec::new());
                            device_queue.set(0);
                            crypto_state.set("Session expired".to_owned());
                            status.set("Session expired; sign in again".to_owned());
                            network_state.set("online".to_owned());
                            last_error.set(Some("auth_expired: session expired".to_owned()));
                            needs_device_authorization.set(false);
                            device_authorization_check_complete.set(true);
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
                if let Some(personal_handle) = account_personal_handle {
                    personal_handles.set(vec![personal_handle]);
                    personal_handles_status.set("1 handle".to_owned());
                } else if personal_handles().is_empty() {
                    personal_handles_status.set("Not published".to_owned());
                }
                if canonical_actor != actor {
                    // Account changed since the last persisted run (the
                    // server's account viewer disagrees with our cached
                    // actor). When the previous actor was non-empty this
                    // means a different human is signing in on the same
                    // device — every account-scoped record (projections,
                    // drafts, seal views, read markers, remarks, and the
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
                        // Realm tree updates between this point and the sync that's
                        // about to run.
                        drop(store);
                        realm_tree_nodes.set(Vec::new());
                        timeline.set(Vec::new());
                        selected_realm_id.set(String::new());
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
                adopt_live_token_for_api(&api, token, &mut session_token, &mut authed);
                match authed.list_devices().await {
                    Ok(viewer) => {
                        account_has_other_devices.set(
                            account_has_other_active_devices_from_account_viewer(&viewer, &device),
                        );
                        needs_device_authorization.set(
                            device_authorization_required_from_account_viewer(&viewer, &device),
                        );
                        device_authorization_check_complete.set(true);
                    }
                    Err(error) if is_auth_expired_error(&error) => {
                        if let Some(refreshed) = crate::session::refresh_current_bearer().await {
                            session_token = refreshed;
                            authed = api.clone().with_bearer(session_token.clone());
                            match authed.list_devices().await {
                                Ok(viewer) => {
                                    account_has_other_devices.set(
                                        account_has_other_active_devices_from_account_viewer(
                                            &viewer, &device,
                                        ),
                                    );
                                    needs_device_authorization.set(
                                        device_authorization_required_from_account_viewer(
                                            &viewer, &device,
                                        ),
                                    );
                                }
                                Err(retry_error) => {
                                    tracing::warn!(
                                        ?retry_error,
                                        "device authorization check failed after refresh"
                                    );
                                    needs_device_authorization.set(true);
                                }
                            }
                        } else {
                            needs_device_authorization.set(true);
                        }
                        device_authorization_check_complete.set(true);
                    }
                    Err(error) => {
                        tracing::warn!(?error, "device authorization check failed");
                        needs_device_authorization.set(true);
                        device_authorization_check_complete.set(true);
                    }
                }
                // Decision 0002 §5.4 — when the Principal Server reports this
                // session device is not yet authorized, enroll it through the
                // delegated account authority: coauth signs a `service_attested`
                // `ck.device.authorize` and we submit it to `/_cokret/self/events`,
                // which gives the device row a `device_public_key` so recovery
                // genesis stops failing with `recovery_policy_device_not_authorized`.
                // Idempotent: skipped when already authorized, and a no-op-on-retry
                // because the submit is a CAS on `actor_seq`.
                if needs_device_authorization() {
                    adopt_live_token_for_api(&api, token, &mut session_token, &mut authed);
                    match enroll_current_session_device(
                        &base,
                        &canonical_actor,
                        &device,
                        &authed,
                        state_store,
                    )
                    .await
                    {
                        Ok(()) => {
                            if let Ok(viewer) = authed.list_devices().await {
                                needs_device_authorization.set(
                                    device_authorization_required_from_account_viewer(
                                        &viewer, &device,
                                    ),
                                );
                            } else {
                                needs_device_authorization.set(false);
                            }
                        }
                        Err(error) => {
                            tracing::warn!(?error, "device enrollment failed");
                        }
                    }
                }
                persist_config(
                    config_store,
                    base.clone(),
                    canonical_actor.clone(),
                    device.clone(),
                    session_token.clone(),
                );
                crypto_state.set("Session active".to_owned());

                // `connect()` always issues a full sync (`since=None`) —
                // it's invoked on app boot, the mobile Refresh button,
                // and server switches, all of which represent
                // "re-establish the world from scratch". The SyncEngine
                // (see crate::sync_engine) owns the long-poll loop that
                // threads the cursor for incremental deltas.
                adopt_live_token_for_api(&api, token, &mut session_token, &mut authed);
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
                        adopt_live_token_for_api(&api, token, &mut session_token, &mut authed);
                        let invite_notifications = match authed.invites().await {
                            Ok(response) => Some(response.invites),
                            Err(error) if is_auth_expired_error(&error) => {
                                if let Some(refreshed) =
                                    crate::session::refresh_current_bearer().await
                                {
                                    session_token = refreshed;
                                    authed = api.clone().with_bearer(session_token.clone());
                                    authed.invites().await.ok().map(|response| response.invites)
                                } else {
                                    None
                                }
                            }
                            Err(error) => {
                                tracing::debug!(
                                    ?error,
                                    "background sync could not refresh invite notifications"
                                );
                                None
                            }
                        };
                        {
                            let mut store = state_store.write();
                            store.save_sync_cursor(sync.cursor.clone());
                            // Server-authoritative reconcile for top-level
                            // Realm membership. Nested Space containers are
                            // not always returned as top-level sync entries,
                            // so keep local container projections while their
                            // home Realm is still present.
                            let server_set: BTreeSet<String> =
                                sync.realms.keys().cloned().collect();
                            let keep_set = full_sync_projection_keep_set(
                                &server_set,
                                &store.load().realm_tree_projections,
                            );
                            let pruned =
                                store.retain_realm_tree_projections(|id| keep_set.contains(id));
                            if !pruned.is_empty() {
                                tracing::info!(
                                    pruned_count = pruned.len(),
                                    "full sync pruned stale realm-tree projections",
                                );
                            }
                            // Explicit `left_realms` deltas — soland emits
                            // these on incremental syncs too; for full sync
                            // they're redundant with `retain_realm_tree_projections`
                            // above but cheap to apply when soland evolves
                            // to send them on full sync.
                            for left_id in &sync.left_realms {
                                store.forget_realm_tree_projection(left_id);
                            }
                            let realm_title_hints = invite_notifications
                                .as_deref()
                                .map(crate::views::notifications::realm_title_hints_from_values)
                                .unwrap_or_default();
                            for (id, body) in &sync.realms {
                                let projection = crate::realm_tree::projection_with_title_hint(
                                    id,
                                    body,
                                    realm_title_hints.get(id).map(String::as_str),
                                );
                                store.save_realm_tree_projection(id.clone(), projection);
                                // Thread the per-Realm Seal view (frontier /
                                // leaves / state_root / bottom cells) into the
                                // local store so Move builders + UI can read
                                // it. Bodies without an `seal_view` field
                                // produce a Default view (empty frontier =
                                // sentinel) so we still record presence.
                                let view = crate::local_state::LocalSealView::from_sync_body(body);
                                store.set_realm_seal_view(id.clone(), view);
                                store.ingest_move_event_states(id, body);
                            }
                            // Keep notification projection current even when
                            // invites live on `authz/invites` rather than the
                            // normal account subscribe notification stream.
                            let projection_from_sync =
                                crate::views::notifications::notification_items_from_value(
                                    &sync.notifications,
                                );
                            let account_notification_projection = sync
                                .account_data
                                .iter()
                                .filter(|entry| {
                                    crate::views::notifications::is_notification_account_data(entry)
                                })
                                .cloned()
                                .collect::<Vec<_>>();
                            let should_save_notification_projection = projection_from_sync
                                .is_some()
                                || !account_notification_projection.is_empty()
                                || invite_notifications.is_some();
                            let mut notification_projection =
                                projection_from_sync.unwrap_or_else(|| {
                                    if account_notification_projection.is_empty() {
                                        store.notification_projection()
                                    } else {
                                        account_notification_projection
                                    }
                                });
                            if let Some(invites) = invite_notifications {
                                crate::views::notifications::merge_invite_notifications(
                                    &mut notification_projection,
                                    invites,
                                    &server_set,
                                );
                            }
                            if should_save_notification_projection {
                                store.save_notification_projection(notification_projection);
                            }
                            store.save_presence_projection(sync.presence.clone());
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
                                if let Some(actor_id) =
                                    crate::account_data::actor_id_from_contact_remark_key(data_type)
                                {
                                    let Some(content) = entry.get("content") else {
                                        continue;
                                    };
                                    match serde_json::from_value::<crate::account_data::ContactRemark>(
                                        content.clone(),
                                    ) {
                                        Ok(remark) => {
                                            store.set_contact_remark(actor_id.to_owned(), remark);
                                        }
                                        Err(error) => {
                                            tracing::warn!(
                                                "ignoring malformed Contact remark for {actor_id}: {error}"
                                            );
                                        }
                                    }
                                    continue;
                                }
                                let Some(realm_id) =
                                    crate::account_data::realm_id_from_realm_remark_key(data_type)
                                else {
                                    continue;
                                };
                                let Some(content) = entry.get("content") else {
                                    continue;
                                };
                                match serde_json::from_value::<crate::account_data::RealmRemark>(
                                    content.clone(),
                                ) {
                                    Ok(remark) => {
                                        store.set_realm_remark(realm_id.to_owned(), remark);
                                    }
                                    Err(error) => {
                                        tracing::warn!(
                                            "ignoring malformed Realm remark for {realm_id}: {error}"
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
                            // YOU-02-002/003: surface a latched persistence
                            // failure from the fire-and-forget setters (quota
                            // exceeded, atomic write error, corrupt boot read)
                            // so the user learns their changes are not being
                            // saved instead of silently diverging from disk.
                            if let Some(message) = store.persist_error() {
                                last_error.set(Some(format!("local state not saved: {message}")));
                            }
                        }
                        // Receive side of `ck.call.signal`: route every realm
                        // body's inbound call-signal envelopes into the hub
                        // (dedup → incoming ring / per-call inbox). Done after
                        // the `store` write guard above is dropped so the hub
                        // Signal writes don't nest inside the store borrow.
                        //
                        // Receiver proof verification (`webrtc-signaling.md`
                        // §5.1, fail-closed): each inbound envelope's `proof` is
                        // verified against the sender's authoritative directory
                        // verify key (resolved via `device_directory`) before any
                        // ring / inbox side effect. The routing is async because
                        // a directory cache miss resolves through `keys/query`.
                        {
                            let mut hub = ctx.call_signal_hub;
                            // Tier-2 (device-lifecycle.md §8.3): resolver-backed
                            // DID anchor over a snapshot of the session DID
                            // cache, so the receiver verifies the sender device
                            // key's full cross-signing chain (not just soland's
                            // assertion). Cache back-fills are written back.
                            let mut did_cache = ctx.did_cache;
                            let anchor = crate::did_resolver::ResolverDidAnchor::from_profile(
                                crate::did_resolver::DeploymentProfile::PersonalNode,
                                did_cache.read().clone(),
                            );
                            for (id, body) in &sync.realms {
                                crate::views::call_signals::route_realm_call_signals(
                                    &mut hub,
                                    id,
                                    body,
                                    &canonical_actor,
                                    Some(&api),
                                    &anchor,
                                )
                                .await;
                            }
                            *did_cache.write() = anchor.into_cache();
                        }
                        let synced_timeline = {
                            // Merge encrypted bodies on read (author sidecar →
                            // remote decrypt-on-read). The `store` write guard
                            // above is out of scope here; take a fresh read
                            // guard scoped to this call.
                            let store_guard = state_store.read();
                            crate::views::timeline::timeline_events_from_sync_realms(
                                &sync.realms,
                                Some(&store_guard),
                                Some((&canonical_actor, &device)),
                            )
                        };
                        // `realm_tree_nodes` is derived from `state_store.realm_tree_projections`
                        // by a use_effect in `RouterView` — we don't set it
                        // here. Read a reconciled snapshot for status text
                        // and selected_realm_id bookkeeping only.
                        let reconciled = realm_tree_nodes_from_sync_realms(
                            &state_store.read().load().realm_tree_projections,
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
                        let first_realm = reconciled
                            .iter()
                            .find(|node| node.kind == RealmTreeNodeKind::Realm)
                            .map(|node| node.id.clone());
                        let current = selected_realm_id();
                        let trimmed = current.trim();
                        let needs_reset =
                            trimmed.is_empty() || !reconciled.iter().any(|s| s.id == trimmed);
                        if needs_reset {
                            selected_realm_id.set(first_realm.unwrap_or_default());
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
                        selected_realm_id.set(String::new());
                        realm_tree_nodes.set(Vec::new());
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
                        // Sync failed — the `realm_tree_nodes` Signal already
                        // reflects what's in the local store via the
                        // derive effect; just refresh status text and
                        // make sure selected_realm_id points at something
                        // still in scope.
                        let fallback = realm_tree_nodes_from_sync_realms(
                            &state_store.read().load().realm_tree_projections,
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
                        let first_realm = fallback
                            .iter()
                            .find(|node| node.kind == RealmTreeNodeKind::Realm)
                            .map(|node| node.id.clone());
                        let current = selected_realm_id();
                        let trimmed = current.trim();
                        let needs_reset =
                            trimmed.is_empty() || !fallback.iter().any(|s| s.id == trimmed);
                        if needs_reset {
                            selected_realm_id.set(first_realm.unwrap_or_default());
                        }
                        last_error.set(Some(format!("sync: {error}")));
                    }
                }
                adopt_live_token_for_api(&api, token, &mut session_token, &mut authed);
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
                        // Spec `ServiceDescribe.frontier` is a typed
                        // EventId list; surface the first head.
                        if let Some(frontier) = events.frontier.first() {
                            frontier_state.set(frontier.to_string());
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
                        selected_realm_id.set(String::new());
                        realm_tree_nodes.set(Vec::new());
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

#[cfg(test)]
#[path = "app_tests.rs"]
mod tests;
