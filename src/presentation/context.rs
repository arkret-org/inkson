//! Explicit application state passed to semantic product surfaces.
use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::rc::{Rc, Weak};

use glory::prelude::*;

use super::state_store::{SharedLocalStateBackend, SharedStateStore};
use crate::config::{ActiveAccountContext, ClientConfig, LocalConfigStore};
use crate::i18n::{TranslationDict, UiLocale};
use crate::models::{ContactView, RealmTreeNode, ServiceDescribe};
use crate::routes::Route;
use crate::runtime::services::RuntimeServices;
use crate::runtime::session::{CurrentSessionRefresh, LocalRefreshFuture, SessionCoordinator};
use crate::state::projection::ProjectionEvent;
use crate::sync_engine::ConnectionState;

pub struct BootState {
    pub config_store: LocalConfigStore,
    pub config: ClientConfig,
    pub state_store: SharedStateStore,
    pub initial_credential: String,
    pub realm_tree_nodes: Vec<RealmTreeNode>,
}

pub struct InksonContext {
    pub active_account: Cage<Option<ActiveAccountContext>>,
    pub principal_id: Cage<Option<arkret_sdk::DidCoreId>>,
    pub device_id: Cage<String>,
    pub token: Cage<String>,
    pub base_url: Cage<String>,
    pub config_store: Cage<LocalConfigStore>,
    pub session_generation: Cage<u64>,
    pub owned_agents_rev: Cage<u64>,
    pub state_store: SharedStateStore,
    pub state_revision: Cage<u64>,
    pub services: RuntimeServices,
    pub call_signal_hub: crate::views::call_signals::CallSignalHub,
    pub message_stream_hub: crate::views::message_streams::MessageStreamHub,
    pub read_receipt_hub: crate::views::read_receipts::ReadReceiptHub,
    pub hosted_sidecar: Cage<Option<crate::sidecar::HostedSidecarState>>,
    pub chat_state: crate::views::chat::ChatStatePool,
    pub kanban_state: crate::views::kanban::KanbanStatePool,
    pub route: Cage<Route>,
    pub locale: Cage<UiLocale>,
    pub theme: Cage<String>,
    pub system_theme_is_night: Cage<bool>,
    pub realm_live_epoch: Cage<u64>,
    pub sync_cursor: Cage<String>,
    pub projection_events: Cage<Vec<ProjectionEvent>>,
    pub realm_tree_nodes: Cage<Vec<RealmTreeNode>>,
    pub contact_rows: Cage<Vec<ContactView>>,
    pub selected_realm_id: Cage<String>,
    pub new_space_context_node: Cage<String>,
    pub server_description: Cage<Option<ServiceDescribe>>,
    pub connection_state: Cage<ConnectionState>,
    pub connection_status: Cage<String>,
    pub network_state: Cage<String>,
    pub crypto_state: Cage<String>,
    pub server_probe_status: Cage<String>,
    pub sync_generation: Cage<u64>,
    pub sync_bootstrap_complete: Cage<bool>,
    pub bootstrap_pending: Cage<bool>,
    pub session_boot_state: Cage<crate::app::SessionBootState>,
    pub account_has_other_devices: Cage<bool>,
    pub did_resolution_health: Cage<crate::components::DidResolutionHealth>,
    pub realm_events_route_enabled: Cage<bool>,
    pub device_queue: Cage<usize>,
    pub last_error: Cage<Option<String>>,
    pub is_server_admin: Cage<bool>,
    pub needs_device_authorization: Cage<bool>,
    pub device_authorization_check_complete: Cage<bool>,
    pub secure_store_bootstrap_ready: Cage<bool>,
    pub account_recovery_configured: Cage<Option<bool>>,
    pub needs_mls_backup: Cage<bool>,
    pub needs_mls_unlock: Cage<bool>,
    pub needs_mls_recovery_setup: Cage<bool>,
    pub restore_payload_cache: Cage<Option<serde_json::Value>>,
    pub recovery_key_setup_open: Cage<bool>,
    pub account_primary_handle: Cage<String>,
    pub personal_handles: Cage<Vec<String>>,
    pub personal_handles_status: Cage<String>,
    pub push_state: Cage<String>,
    pub frontier_state: Cage<String>,
    pub profiles: Cage<crate::config::MultiProfileConfig>,
    pub account_revision: Cage<u64>,
    pub account_busy: Cage<bool>,
    pub account_view_retired: Cage<bool>,
    pub account_blocked: Cage<bool>,
    pub account_error: Cage<Option<String>>,
    dictionaries: Rc<HashMap<String, TranslationDict>>,
    root: glory::ui::WeakScope,
    #[cfg(all(not(target_arch = "wasm32"), feature = "desktop"))]
    native_images: RefCell<Option<std::sync::Arc<super::native_images::ScopedImageRegistry>>>,
}

impl InksonContext {
    pub fn new(
        scope: &Scope,
        boot: BootState,
        route: Route,
        refresh: impl Fn(Rc<Self>) -> LocalRefreshFuture + 'static,
    ) -> Rc<Self> {
        let BootState {
            config_store,
            config,
            state_store,
            initial_credential,
            realm_tree_nodes,
        } = boot;
        let initial_snapshot = state_store.read(crate::state::LocalStateStore::load);
        let locale = crate::i18n::resolve_locale(
            None,
            state_store
                .read(|store| store.device_pref("locale"))
                .as_deref(),
        );
        let theme = state_store
            .read(|store| store.load_plain_local_data("theme"))
            .filter(|value| matches!(value.as_str(), "light" | "night" | "system"))
            .unwrap_or_else(|| "night".into());
        let active_account = config.active_account.clone();
        let principal = active_account
            .as_ref()
            .map(|account| account.principal_id().clone());
        let device = config
            .device_id()
            .map(ToString::to_string)
            .unwrap_or_else(crate::config::new_device_id);
        let base_url = config
            .server_url()
            .or_else(|| config.stations.first())
            .map(ToString::to_string)
            .unwrap_or_else(|| "https://local.host".into());
        let selected_realm_id = realm_tree_nodes
            .iter()
            .find(|node| node.kind == crate::models::RealmTreeNodeKind::Realm)
            .map(|node| node.id.clone())
            .unwrap_or_default();
        let initial_handle = state_store
            .read(|store| {
                store.primary_handle_for_principal_id(
                    principal
                        .as_ref()
                        .map(arkret_sdk::DidCoreId::as_str)
                        .unwrap_or_default(),
                )
            })
            .unwrap_or_default();
        let context_slot: Rc<RefCell<Weak<Self>>> = Rc::new(RefCell::new(Weak::new()));
        let refresh_slot = context_slot.clone();
        let coordinator = SessionCoordinator::new(move || match refresh_slot.borrow().upgrade() {
            Some(context) => refresh(context),
            None => {
                Box::pin(async { CurrentSessionRefresh::retry_later("application owner retired") })
            }
        });
        let adapter = crate::client_core::InksonLocalStateStoreAdapter::from_backend(
            SharedLocalStateBackend(state_store.clone()),
        );
        let services = RuntimeServices::new(adapter, coordinator);
        let initial_boot_state = if initial_credential.trim().is_empty() {
            crate::app::SessionBootState::Restoring
        } else {
            crate::app::SessionBootState::Checking
        };
        let dictionaries = Rc::new(HashMap::from([
            (
                UiLocale::En.code().to_owned(),
                crate::i18n::english_translations(),
            ),
            (
                UiLocale::Zh.code().to_owned(),
                crate::i18n::chinese_translations(),
            ),
        ]));
        let context = Rc::new(Self {
            active_account: scope.cage(active_account),
            principal_id: scope.cage(principal),
            device_id: scope.cage(device),
            token: scope.cage(initial_credential),
            base_url: scope.cage(base_url),
            config_store: scope.cage(config_store.clone()),
            session_generation: scope.cage(0),
            owned_agents_rev: scope.cage(0),
            state_revision: scope.cage(state_store.revision()),
            state_store,
            services,
            call_signal_hub: crate::views::call_signals::CallSignalHub::new(scope),
            message_stream_hub: crate::views::message_streams::MessageStreamHub::new(scope),
            read_receipt_hub: crate::views::read_receipts::ReadReceiptHub::new(scope),
            hosted_sidecar: scope.cage(None),
            chat_state: crate::views::chat::ChatStatePool::new(scope),
            kanban_state: crate::views::kanban::KanbanStatePool::new(scope),
            route: scope.cage(route),
            locale: scope.cage(locale),
            theme: scope.cage(theme),
            system_theme_is_night: scope.cage(crate::app::browser_prefers_dark_theme()),
            realm_live_epoch: scope.cage(0),
            sync_cursor: scope.cage(crate::app::initial_sync_cursor(
                initial_snapshot.sync_cursor.clone(),
            )),
            projection_events: scope.cage(Vec::new()),
            realm_tree_nodes: scope.cage(realm_tree_nodes),
            contact_rows: scope.cage(Vec::new()),
            selected_realm_id: scope.cage(selected_realm_id),
            new_space_context_node: scope.cage(String::new()),
            server_description: scope.cage(None),
            connection_state: scope.cage(ConnectionState::Loading),
            connection_status: scope.cage(ConnectionState::Loading.label().to_owned()),
            network_state: scope.cage("online".to_owned()),
            crypto_state: scope.cage("Not initialized".to_owned()),
            server_probe_status: scope.cage("Not probed".to_owned()),
            sync_generation: scope.cage(0),
            sync_bootstrap_complete: scope.cage(false),
            bootstrap_pending: scope.cage(true),
            session_boot_state: scope.cage(initial_boot_state),
            account_has_other_devices: scope.cage(false),
            did_resolution_health: scope.cage(crate::components::DidResolutionHealth::healthy()),
            realm_events_route_enabled: scope.cage(false),
            device_queue: scope.cage(0),
            last_error: scope.cage(None),
            is_server_admin: scope.cage(false),
            needs_device_authorization: scope.cage(false),
            device_authorization_check_complete: scope.cage(false),
            secure_store_bootstrap_ready: scope.cage(!cfg!(target_arch = "wasm32")),
            account_recovery_configured: scope.cage(None),
            needs_mls_backup: scope.cage(false),
            needs_mls_unlock: scope.cage(false),
            needs_mls_recovery_setup: scope.cage(false),
            restore_payload_cache: scope.cage(None),
            recovery_key_setup_open: scope.cage(false),
            account_primary_handle: scope.cage(initial_handle),
            personal_handles: scope.cage(Vec::new()),
            personal_handles_status: scope.cage("Not published".into()),
            push_state: scope.cage(crate::push::push_status_label(
                initial_snapshot.push_registration.as_ref(),
            )),
            frontier_state: scope.cage("Not loaded".into()),
            profiles: scope.cage(config_store.load_profiles()),
            account_revision: scope.cage(0),
            account_busy: scope.cage(false),
            account_view_retired: scope.cage(false),
            account_blocked: scope.cage(false),
            account_error: scope.cage(None),
            dictionaries,
            root: scope.downgrade(),
            #[cfg(all(not(target_arch = "wasm32"), feature = "desktop"))]
            native_images: RefCell::new(None),
        });
        *context_slot.borrow_mut() = Rc::downgrade(&context);
        crate::i18n::bind_application_locale(context.locale);
        super::bind_current_host(&context);
        let mut revisions = context.state_store.subscribe();
        let revision = context.state_revision;
        if let Err(error) = scope.spawn(async move {
            while revisions.changed().await.is_ok() {
                let next = *revisions.borrow_and_update();
                if revision.try_revise(|revision| *revision = next).is_err() {
                    break;
                }
            }
        }) {
            tracing::error!(%error, "could not observe the application store");
        }
        context
    }

    pub fn snapshot(&self) -> crate::state::ClientLocalState {
        let _ = self.state_revision.get();
        self.state_store.read(crate::state::LocalStateStore::load)
    }

    pub fn state_scope(&self) -> Option<Scope> {
        self.root.upgrade()
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "desktop"))]
    pub(crate) fn install_native_images(
        &self,
        images: std::sync::Arc<super::native_images::ScopedImageRegistry>,
    ) {
        *self.native_images.borrow_mut() = Some(images);
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn register_native_image(
        &self,
        scope: &Scope,
        mime: &str,
        bytes: Vec<u8>,
    ) -> std::result::Result<String, String> {
        #[cfg(feature = "desktop")]
        {
            self.native_images
                .borrow()
                .as_ref()
                .ok_or("The native image host is unavailable.")?
                .register(scope, mime, bytes)
        }
        #[cfg(not(feature = "desktop"))]
        {
            let _ = (scope, mime, bytes);
            Err("The native image host is unavailable in this build.".into())
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn revoke_native_image(&self, url: &str) {
        #[cfg(feature = "desktop")]
        if let Some(images) = self.native_images.borrow().as_ref() {
            images.revoke(url);
        }
        #[cfg(not(feature = "desktop"))]
        let _ = url;
    }

    pub(crate) fn clear_account_projections(&self) {
        #[cfg(all(not(target_arch = "wasm32"), feature = "desktop"))]
        if let Some(images) = self.native_images.borrow().as_ref() {
            images.retire();
        }
        self.chat_state.retire_session();
        self.kanban_state.retire_session();
        self.call_signal_hub.reset();
        self.message_stream_hub.reset();
        self.read_receipt_hub.reset();
        self.hosted_sidecar.revise(|value| *value = None);
        self.sync_cursor.revise(String::clear);
        self.realm_tree_nodes.revise(Vec::clear);
        self.contact_rows.revise(Vec::clear);
        self.projection_events.revise(Vec::clear);
        self.selected_realm_id.revise(String::clear);
        self.new_space_context_node.revise(String::clear);
        self.account_primary_handle.revise(String::clear);
        self.personal_handles.revise(Vec::clear);
        self.personal_handles_status
            .revise(|value| *value = "Not published".into());
        self.device_queue.revise(|value| *value = 0);
        self.is_server_admin.revise(|value| *value = false);
        self.needs_device_authorization
            .revise(|value| *value = false);
        self.device_authorization_check_complete
            .revise(|value| *value = false);
        self.account_has_other_devices
            .revise(|value| *value = false);
        self.account_recovery_configured
            .revise(|value| *value = None);
        self.needs_mls_backup.revise(|value| *value = false);
        self.needs_mls_unlock.revise(|value| *value = false);
        self.needs_mls_recovery_setup.revise(|value| *value = false);
        self.restore_payload_cache.revise(|value| *value = None);
        self.recovery_key_setup_open.revise(|value| *value = false);
        self.sync_bootstrap_complete.revise(|value| *value = false);
        self.session_boot_state
            .revise(|value| *value = crate::app::SessionBootState::Restoring);
        self.bootstrap_pending.revise(|value| *value = true);
    }

    pub fn tr(&self, key: &str) -> String {
        crate::i18n::translate(self.locale.get(), &self.dictionaries, key)
    }

    pub fn translated(&self, scope: &Scope, key: impl Into<String>) -> Bond<String> {
        let key = key.into();
        let dictionaries = self.dictionaries.clone();
        let locale = self.locale;
        scope.bond(move || crate::i18n::translate(locale.get(), &dictionaries, &key))
    }

    pub fn translated_args(
        &self,
        scope: &Scope,
        key: impl Into<String>,
        arguments: impl Fn() -> Vec<(&'static str, String)> + 'static,
    ) -> Bond<String> {
        let message = self.translated(scope, key);
        scope.bond(move || crate::i18n::substitute_args(message.get(), &arguments()))
    }

    pub fn navigate(&self, route: Route) {
        #[cfg(target_arch = "wasm32")]
        if let Some(window) = web_sys::window() {
            match window.history().and_then(|history| {
                history.push_state_with_url(
                    &wasm_bindgen::JsValue::NULL,
                    "",
                    Some(&route.to_string()),
                )
            }) {
                Ok(()) => {}
                Err(error) => {
                    tracing::error!(?error, "could not publish navigation");
                    return;
                }
            }
        }
        self.route.revise(|current| *current = route);
    }

    pub fn replace_route(&self, route: Route) {
        #[cfg(target_arch = "wasm32")]
        if let Some(window) = web_sys::window() {
            match window.history().and_then(|history| {
                history.replace_state_with_url(
                    &wasm_bindgen::JsValue::NULL,
                    "",
                    Some(&route.to_string()),
                )
            }) {
                Ok(()) => {}
                Err(error) => {
                    tracing::error!(?error, "could not replace navigation");
                    return;
                }
            }
        }
        if self.route.with_untracked(|current| current != &route) {
            self.route.revise(|current| *current = route);
        }
    }

    /// All detached session work is still bounded by the root window owner.
    pub fn spawn(
        &self,
        future: impl Future<Output = ()> + 'static,
    ) -> std::result::Result<(), glory::core::AccessError> {
        if let Some(root) = self.root.upgrade() {
            root.spawn(future).map(|_| ())
        } else {
            Err(glory::core::AccessError::Disposed)
        }
    }

    pub fn session_matches(&self, generation: u64, account: &Option<ActiveAccountContext>) -> bool {
        self.session_generation.is_alive()
            && self.session_generation.get_untracked() == generation
            && self
                .active_account
                .get_untracked()
                .as_ref()
                .map(|value| (&value.authority, &value.device_id))
                == account
                    .as_ref()
                    .map(|value| (&value.authority, &value.device_id))
    }

    pub fn value_reader<T: Clone + 'static>(
        value: Cage<T>,
    ) -> crate::runtime::input::ValueReader<T> {
        crate::runtime::input::ValueReader::new(move || value.get())
    }

    pub fn value_cell<T: Clone + 'static>(value: Cage<T>) -> crate::runtime::input::ValueCell<T> {
        crate::runtime::input::ValueCell::new(
            move || value.get(),
            move |next| value.revise(|value| *value = next),
            move |update| value.revise(update),
        )
    }

    #[allow(clippy::expect_used)]
    pub fn theme_tokens(&self) -> sapid::Theme {
        let preference = self.theme.get();
        let dark = preference == "night"
            || preference == "system" && crate::app::browser_prefers_dark_theme();
        let color = |value: u32| Color((value >> 16) as u8, (value >> 8) as u8, value as u8, 255);
        let palette = if dark {
            sapid::Palette {
                canvas: color(0x101722),
                surface: color(0x1b2430),
                input: color(0x1b2430),
                foreground: color(0xf8f2ee),
                muted: color(0xcbbab1),
                border: color(0x3a4454),
                accent: color(0xf59e0b),
                accent_hover: color(0xf7ae3a),
                accent_soft: color(0x392c1e),
                accent_text: color(0xfde7ba),
                on_accent: color(0x2c170b),
                success: color(0x7bc9b5),
                danger: color(0xff7a59),
                warning: color(0xf0be78),
                ..sapid::BLUE.base
            }
        } else {
            sapid::Palette {
                canvas: color(0xf6eee7),
                surface: color(0xfffaf5),
                input: color(0xfffaf5),
                foreground: color(0x2f2723),
                muted: color(0x6f625a),
                border: color(0xe6d9cf),
                accent: color(0xd97706),
                accent_hover: color(0xb96505),
                accent_soft: color(0xfff4e6),
                accent_text: color(0x7f3f02),
                on_accent: color(0xfffaf6),
                success: color(0x317d6a),
                danger: color(0xc44c2d),
                warning: color(0xb97824),
                ..sapid::BLUE.base
            }
        };
        // Finite constants above satisfy the palette's construction invariants.
        let mut theme = sapid::Theme::from_palette(
            "inkson",
            if dark {
                sapid::ColorScheme::Dark
            } else {
                sapid::ColorScheme::Light
            },
            palette,
        )
        .expect("the static Inkson palette is valid");
        theme.radius = 8.0;
        theme
    }
}
