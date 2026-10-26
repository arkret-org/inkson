//! Application ownership, account boundaries, and route lifetimes.
use std::rc::Rc;

use glory::Scope;
use glory::ui::view;

use crate::config::LocalConfigStore;
use crate::presentation::widgets::{heading, paragraph, reactive_distinct, stack};
use crate::presentation::{BootState, InksonContext, SharedStateStore, View};
use crate::routes::Route;
use crate::state::LocalStateStore;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "glory_root/selection_tests.rs"]
mod selection_tests;

pub fn root(scope: &Scope) -> View {
    super::web_leader::gate(scope)
}

pub(super) fn bootstrap(scope: &Scope) -> View {
    bootstrap_with_context(scope, |_| {})
}

#[cfg(all(not(target_arch = "wasm32"), feature = "desktop"))]
pub(crate) fn native_root(
    scope: &Scope,
    images: std::sync::Arc<crate::presentation::native_images::ScopedImageRegistry>,
) -> View {
    bootstrap_with_context(scope, |context| context.install_native_images(images))
}

fn bootstrap_with_context(scope: &Scope, configure: impl FnOnce(&Rc<InksonContext>)) -> View {
    super::ensure_default_push_token_provider();
    crate::notification_sound::initialize_notification_audio();
    let config_store = LocalConfigStore::default();
    let (config, store, snapshot) =
        super::read_bootstrap_snapshot(config_store.clone(), LocalStateStore::default());
    if let (Some(account), Some(authority)) = (
        config.active_account.as_ref(),
        snapshot.device_authoring_authority.as_ref(),
    ) {
        crate::identity::device_directory::restore_persisted_device_authoring_authority(
            crate::identity::device_directory::cache_epoch(),
            &account.authority,
            &account.device_id,
            authority,
        );
    }
    match config.active_account.as_ref() {
        Some(account) => match crate::secure_key_store::UserLocalStore::new(
            account.authority.clone(),
            account.device_id.clone(),
        ) {
            Ok(user) => user.activate(),
            Err(error) => {
                tracing::error!(%error, "persisted active account key scope is invalid");
                crate::secure_key_store::set_active_device_seed_scope(None);
            }
        },
        None => crate::secure_key_store::set_active_device_seed_scope(None),
    }
    let initial_credential = super::initial_session_credential_from_state(
        &snapshot,
        &config,
        chrono::Utc::now().timestamp(),
    );
    let can_restore = super::has_bootstrap_refresh_material(&store, config.active_account.as_ref());
    let boot_state = super::session_boot_state_from_bootstrap_material(
        &initial_credential,
        can_restore,
        super::principal_id_text(&config.principal_id().cloned()),
        !cfg!(target_arch = "wasm32"),
    );
    let controls = super::principal_control_realm_ids(&snapshot);
    let realms = crate::realm_tree::realm_tree_nodes_from_sync_realms_with_roles(
        &snapshot.realm_tree_projections,
        &snapshot.realm_collaboration_roles,
    )
    .into_iter()
    .filter(|node| !controls.contains(&node.id))
    .collect();
    let context = InksonContext::new(
        scope,
        BootState {
            config_store,
            config,
            state_store: SharedStateStore::new(store),
            initial_credential,
            realm_tree_nodes: realms,
        },
        current_route(),
        |context| {
            Box::pin(async move {
                super::connect::refresh_session_credential_for_active_context(
                    context.base_url,
                    &context.state_store,
                    context.token,
                    context.config_store,
                    context.session_generation,
                    context.active_account,
                )
                .await
            })
        },
    );
    configure(&context);
    context
        .session_boot_state
        .revise(|state| *state = boot_state);
    if let Err(error) = scope.retain(context.clone()) {
        scope.report_error(error);
    }
    install_browser_navigation(scope, &context);
    install_realm_selection(scope, context.clone());
    let appearance = scope.bond({
        let context = context.clone();
        move || {
            let night = super::theme_renders_as_night(
                &context.theme.get(),
                context.system_theme_is_night.get(),
            );
            if night {
                "inkson-root inkson-theme-dark"
            } else {
                "inkson-root inkson-theme-light"
            }
            .to_owned()
        }
    });
    let boundary = scope.bond({
        let context = context.clone();
        move || {
            (
                context.account_revision.get(),
                context.account_view_retired.get(),
            )
        }
    });
    Box::new(view().class(appearance).fill(reactive_distinct(
        boundary,
        move |scope, (_, retired)| {
            if retired {
                return stack(
                    "auth-shell",
                    vec![paragraph(
                        "",
                        context.translated(scope, "app.account.switching"),
                    )],
                );
            }
            account_owner(scope, context.clone())
        },
    )))
}

#[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
#[derive(Clone, PartialEq)]
struct RealmSelectionDiagnostic {
    route: Route,
    selected: String,
    enabled: bool,
    account: bool,
    retired: bool,
    switching: bool,
    private: bool,
}

fn install_realm_selection(scope: &Scope, context: Rc<InksonContext>) {
    #[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
    let diagnostic = scope.cage(None::<RealmSelectionDiagnostic>);
    scope.effect(move || {
        let route = context.route.get();
        let remembered = context.selected_realm_id.get();
        let _ = context.state_revision.get();
        let account = context.active_account.get();
        let retired = context.account_view_retired.get();
        let switching = context.account_busy.get();
        let controls = context
            .state_store
            .read(|store| super::principal_control_realm_ids(&store.load()));
        let route_enabled = account.is_some()
            && !retired
            && !switching
            && super::route_uses_realm_context(&route)
            && !route
                .realm_id()
                .is_some_and(|realm| controls.contains(realm));
        if context.realm_events_route_enabled.get_untracked() != route_enabled {
            context
                .realm_events_route_enabled
                .revise(|enabled| *enabled = route_enabled);
        }
        #[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
        {
            let next = RealmSelectionDiagnostic {
                route: route.clone(),
                selected: remembered.clone(),
                enabled: route_enabled,
                account: account.is_some(),
                retired,
                switching,
                private: route
                    .realm_id()
                    .is_some_and(|realm| controls.contains(realm)),
            };
            let previous = diagnostic.get_untracked();
            if previous.as_ref() != Some(&next) {
                let route_kind = match &route {
                    Route::RealmMembers { .. } => "realm_members",
                    Route::RealmAdmin { .. } | Route::RealmAdminSection { .. } => "realm_admin",
                    Route::Realm { .. } => "realm",
                    Route::Chat { .. } | Route::DirectConversation { .. } => "chat",
                    Route::Kanban
                    | Route::KanbanRealm { .. }
                    | Route::KanbanBoard { .. }
                    | Route::KanbanBoardTask { .. }
                    | Route::KanbanTask { .. } => "kanban",
                    _ => "outside_realm",
                };
                tracing::warn!(
                    route_kind,
                    route_changed = previous.as_ref().is_none_or(|old| old.route != next.route),
                    selected_changed = previous
                        .as_ref()
                        .is_none_or(|old| old.selected != next.selected),
                    selected_empty = remembered.is_empty(),
                    selected_typed_valid = arkret_sdk::RealmId::new(remembered.clone()).is_ok(),
                    routed_realm_present = route.realm_id().is_some(),
                    routed_typed_valid = route
                        .realm_id()
                        .is_some_and(|realm| arkret_sdk::RealmId::new(realm.to_owned()).is_ok()),
                    selected_matches_route = route.realm_id() == Some(remembered.as_str()),
                    account_present = next.account,
                    retired,
                    switching,
                    private_realm = next.private,
                    route_enabled,
                    "Realm selection dependencies changed"
                );
                diagnostic.revise(|value| *value = Some(next));
            }
        }
        if account.is_none() || retired || switching {
            return;
        }
        let selection =
            super::shell_model::resolve_realm_selection(route.realm_id(), &remembered, &controls);
        if let Some(realm) = selection.remember {
            context
                .selected_realm_id
                .revise(|selected| *selected = realm);
        }
    });
}

fn account_owner(scope: &Scope, context: Rc<InksonContext>) -> View {
    super::secure_store_effects::install(scope, context.clone());
    super::connection_effects::install(scope, context.clone());
    let projection_context = context.clone();
    scope.effect(move || {
        let _ = projection_context.session_generation.get();
        let _ = projection_context.active_account.get();
        let context = projection_context.clone();
        context.services.projection_sink.install(Rc::new(
            super::projection_adapter::ProjectionAdapter::new(
                context.clone(),
                context.projection_events,
                context.sync_cursor,
                context.connection_status,
                context.network_state,
                context.last_error,
                context.device_queue,
                context.theme,
                context.selected_realm_id,
            ),
        ));
        context.services.signal_product_sink.install(Rc::new(
            super::signal_products::AppSignalProductSink::new(
                context.call_signal_hub,
                context.message_stream_hub,
                context.read_receipt_hub,
                context.clone(),
            ),
        ));
    });
    super::sync_effects::install(scope, context.clone());
    super::mls_runtime_effects::install(scope, context.clone());
    super::mls_recovery_effects::install(scope, context.clone());
    super::recovery_effects::install(scope, context.clone());
    super::recovery_reminder_effects::install(scope, context.clone());
    super::fold_evidence_effects::install(scope, context.clone());

    let global = super::global_effects::install(scope, context.clone());
    let surface = scope.bond({
        let context = context.clone();
        move || {
            super::auth_surface_for_route(
                &context.route.get(),
                !context.token.get().trim().is_empty(),
                context.session_boot_state.get(),
                context.secure_store_bootstrap_ready.get(),
            )
        }
    });
    #[cfg(target_arch = "wasm32")]
    if let Some(root) = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.document_element())
    {
        let owner = format!("{:?}", scope.id());
        let update_root = root.clone();
        let update_owner = owner.clone();
        scope.effect(move || {
            if matches!(surface.get(), super::AuthSurface::AppShell) {
                let _ = update_root.set_attribute("data-inkson-app-shell", &update_owner);
            } else if update_root
                .get_attribute("data-inkson-app-shell")
                .as_deref()
                == Some(update_owner.as_str())
            {
                let _ = update_root.remove_attribute("data-inkson-app-shell");
            }
        });
        if let Err(error) = scope.on_cleanup(move || {
            if root.get_attribute("data-inkson-app-shell").as_deref() == Some(owner.as_str()) {
                let _ = root.remove_attribute("data-inkson-app-shell");
            }
        }) {
            scope.report_error(error);
        }
    }
    let content = reactive_distinct(surface, move |scope, surface| match surface {
        super::AuthSurface::AppShell => super::session_shell::shell(scope, context.clone()),
        super::AuthSurface::Restoring => auth_card(
            scope,
            context.clone(),
            Box::new(
                view()
                    .class("auth-panel auth-restore")
                    .role(glory::render::Role::Status)
                    .fill((
                        view().class("auth-brand").fill((
                            view()
                                .class("auth-logo")
                                .fill(glory::ui::text().content("C")),
                            stack(
                                "",
                                vec![
                                    heading(
                                        1,
                                        "",
                                        context
                                            .translated(scope, "app.boot.opening_secure_storage"),
                                    ),
                                    paragraph("", "Arkret"),
                                ],
                            ),
                        )),
                        view().class("auth-restore-indicator"),
                        paragraph(
                            "auth-status",
                            context.translated(scope, "app.boot.loading_keys"),
                        ),
                    )),
            ),
        ),
        _ => {
            let routed = scope.bond({
                let context = context.clone();
                move || context.route.get()
            });
            let context = context.clone();
            auth_card(
                scope,
                context.clone(),
                reactive_distinct(routed, move |scope, route| match route {
                    Route::Register => crate::views::register::page(scope, context.clone(), route),
                    Route::Onboarding => {
                        crate::views::onboarding::page(scope, context.clone(), route)
                    }
                    _ => crate::views::login::page(scope, context.clone(), route),
                }),
            )
        }
    });
    Box::new(view().class("inkson-account-owner").fill((global, content)))
}

fn auth_card(scope: &Scope, context: Rc<InksonContext>, content: View) -> View {
    let class = scope.bond(move || {
        super::shell_model::shell_chrome(
            &context.theme.get(),
            context.system_theme_is_night.get(),
            context.locale.get().direction(),
            false,
            false,
        )
        .auth_class
    });
    Box::new(
        view()
            .class(class)
            .fill(view().class("auth-card").fill(content)),
    )
}

fn current_route() -> Route {
    #[cfg(target_arch = "wasm32")]
    if let Some(window) = web_sys::window() {
        let location = window.location();
        if let (Ok(path), Ok(query)) = (location.pathname(), location.search()) {
            return format!("{path}{query}").parse().unwrap_or(Route::Dashboard);
        }
    }
    Route::Dashboard
}

#[cfg(not(target_arch = "wasm32"))]
fn install_browser_navigation(_scope: &Scope, _context: &Rc<InksonContext>) {}

#[cfg(target_arch = "wasm32")]
fn install_browser_navigation(scope: &Scope, context: &Rc<InksonContext>) {
    use wasm_bindgen::JsCast;
    use wasm_bindgen::closure::Closure;
    struct Listener {
        event: &'static str,
        target: web_sys::EventTarget,
        callback: Closure<dyn FnMut(web_sys::Event)>,
    }
    impl Drop for Listener {
        fn drop(&mut self) {
            let _ = self.target.remove_event_listener_with_callback(
                self.event,
                self.callback.as_ref().unchecked_ref(),
            );
        }
    }
    let Some(window) = web_sys::window() else {
        return;
    };
    let title_context = context.clone();
    scope.effect(move || {
        let route = title_context.route.get();
        let _ = title_context.locale.get();
        let _ = title_context.state_revision.get();
        let selected = title_context.selected_realm_id.get();
        let account = super::principal_id_owned(title_context.principal_id.get());
        let title = title_context.state_store.read(|store| {
            let controls = super::principal_control_realm_ids(&store.load());
            let routed_control = route
                .realm_id()
                .is_some_and(|realm| controls.contains(realm));
            let surface = super::resolve_realm_surface(&route, store, &account, Some(&selected));
            if matches!(route, Route::Dashboard) {
                "Inkson | Arkret".to_owned()
            } else {
                let route_title = if routed_control {
                    title_context.tr("route.principal_control")
                } else {
                    surface
                        .map(|surface| surface.title().to_owned())
                        .unwrap_or_else(|| {
                            title_context.tr(match &route {
                                Route::Settings | Route::SettingsSection { .. } => "nav.settings",
                                _ => super::route_label_key(&route),
                            })
                        })
                };
                format!("{route_title} | Inkson | Arkret")
            }
        });
        if let Some(document) = web_sys::window().and_then(|window| window.document()) {
            document.set_title(&title);
        }
    });
    let weak = Rc::downgrade(context);
    let callback = Closure::new(move |_: web_sys::Event| {
        if let Some(context) = weak.upgrade().filter(|context| context.route.is_alive()) {
            context.route.revise(|route| *route = current_route());
        }
    });
    let target: web_sys::EventTarget = window.clone().into();
    match target.add_event_listener_with_callback("popstate", callback.as_ref().unchecked_ref()) {
        Ok(()) => {
            if let Err(error) = scope.retain(Listener {
                event: "popstate",
                target,
                callback,
            }) {
                scope.report_error(error);
            }
        }
        Err(error) => tracing::error!(?error, "could not observe browser history"),
    }
    if let Ok(Some(media)) = window.match_media("(prefers-color-scheme: dark)") {
        let read = media.clone();
        let weak = Rc::downgrade(context);
        let callback = Closure::new(move |_: web_sys::Event| {
            if let Some(context) = weak
                .upgrade()
                .filter(|context| context.system_theme_is_night.is_alive())
            {
                context
                    .system_theme_is_night
                    .revise(|night| *night = read.matches());
            }
        });
        let target: web_sys::EventTarget = media.into();
        match target.add_event_listener_with_callback("change", callback.as_ref().unchecked_ref()) {
            Ok(()) => {
                if let Err(error) = scope.retain(Listener {
                    event: "change",
                    target,
                    callback,
                }) {
                    scope.report_error(error);
                }
            }
            Err(error) => tracing::warn!(?error, "could not observe system theme"),
        }
    }
}
