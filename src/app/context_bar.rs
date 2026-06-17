use super::*;

#[component]
pub(super) fn RealmContextBar(
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
