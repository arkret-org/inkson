use std::rc::Rc;

use glory::prelude::*;
use glory::render::EventKind;

use super::session_shell::block;
use super::*;
use crate::presentation::widgets::*;
use crate::presentation::{InksonContext, View};

pub(super) fn context_bar(
    scope: &Scope,
    context: Rc<InksonContext>,
    realm_id: String,
    route: Route,
    board_ready: bool,
) -> View {
    let menu = scope.cage(false);
    let account = principal_id_owned(context.principal_id.get());
    let (allows, current) = context.state_store.read(|store| {
        (
            store.realm_allows_spaces(&realm_id),
            resolve_realm_surface(&route, store, &account, Some(&realm_id)),
        )
    });
    let members = matches!(route, Route::RealmMembers { .. });
    let links = {
        let context = context.clone();
        move |popup: bool| {
            let mut children = Vec::<View>::new();
            let class = |active: bool| {
                if popup {
                    if active {
                        "realm-nav-menu-item is-active"
                    } else {
                        "realm-nav-menu-item"
                    }
                } else if active {
                    "primary"
                } else {
                    "secondary"
                }
            };
            let make_link = |target: Route,
                             label: String,
                             icon: &str,
                             active: bool,
                             surface: Option<RealmSurface>|
             -> View {
                let context = context.clone();
                let realm_id = realm_id.clone();
                let account = account.clone();
                Box::new(
                    internal_link()
                        .target(target.to_string())
                        .class(class(active))
                        .name(label.clone())
                        .fill(vec![crate::components::ui_icon(icon), plain(label)])
                        .on(EventKind::Activate, move |_| {
                            if let Some(surface) = surface {
                                context.state_store.write(|store| {
                                    persist_realm_surface_preference(
                                        store, &account, &realm_id, surface,
                                    )
                                });
                            }
                            menu.revise(|value| *value = false);
                            context.navigate(target.clone());
                        }),
                )
            };
            for surface in RealmSurface::top_nav().into_iter().filter(|_| allows) {
                if surface.is_available(board_ready) {
                    children.push(make_link(
                        surface.route(realm_id.clone()),
                        surface.short_label().into(),
                        surface.icon_name(),
                        current == Some(surface),
                        Some(surface),
                    ));
                } else {
                    children.push(Box::new(
                        sapid::button()
                            .unstyled()
                            .class(class(false))
                            .enabled(false)
                            .label(surface.short_label())
                            .left_section(crate::components::ui_icon(surface.icon_name())),
                    ));
                }
            }
            children.push(make_link(
                Route::RealmMembers {
                    realm_id: realm_id.clone(),
                },
                context.tr("realm_admin.members"),
                "users",
                members,
                None,
            ));
            children.push(make_link(
                Route::RealmAdmin {
                    realm_id: realm_id.clone(),
                },
                context.tr("nav.settings"),
                "settings",
                current.is_none() && !members,
                None,
            ));
            children
        }
    };
    let normal = block("actions realm-nav-inline", links(false));
    let (label, icon) = current
        .map(|surface| (surface.short_label(), surface.icon_name()))
        .unwrap_or(if members {
            ("Members", "users")
        } else {
            ("Settings", "settings")
        });
    let popup = reactive(menu, move |_, open| {
        if !open {
            return empty();
        }
        block(
            "realm-nav-menu-overlay",
            vec![
                super::session_shell::action(
                    "realm-nav-menu-scrim",
                    "Close Realm view menu",
                    move || menu.revise(|value| *value = false),
                ),
                block("realm-nav-menu-panel", links(true)),
            ],
        )
    });
    block(
        "realm-context-bar",
        vec![
            normal,
            Box::new(
                view()
                    .class(scope.bond(move || {
                        if menu.get() {
                            "realm-nav-menu-host is-open".to_owned()
                        } else {
                            "realm-nav-menu-host".to_owned()
                        }
                    }))
                    .fill(vec![
                        super::session_shell::icon_action(
                            "btn icon realm-nav-menu-button",
                            format!(
                                "Switch view: {}",
                                current.map(RealmSurface::title).unwrap_or(label)
                            ),
                            icon,
                            move || menu.revise(|value| *value = !*value),
                        ),
                        popup,
                    ]),
            ),
        ],
    )
}
