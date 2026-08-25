//! Setup overview / surface-map section component.

use dioxus::prelude::*;
use dioxus_router::Link;

use super::model::SetupSection;
use crate::i18n::tr;
use crate::routes::Route;

#[component]
pub(super) fn OverviewSection(selected_realm_id: Signal<String>) -> Element {
    let selected_realm_value = selected_realm_id();
    let has_selected_realm = !selected_realm_value.trim().is_empty();

    rsx! {
        div { class: "event", "data-testid": "realm-setup-map",
            div { class: "event-head",
                span { {tr("setup.overview.surfaces")} }
                span { {tr("setup.overview.surfaces.hint")} }
            }
            div { class: "metric-grid",
                div { class: "metric",
                    strong { {tr("setup.new_realm")} }
                    span { {tr("setup.overview.realm.hint")} }
                    Link {
                        class: "secondary",
                        to: Route::SetupSection { section: SetupSection::Realms.slug().to_owned() },
                        {tr("setup.overview.realm.open")}
                    }
                }
                div { class: "metric",
                    strong { {tr("setup.space.new_space")} }
                    span { {tr("setup.overview.space.hint")} }
                    div { class: "muted",
                        {tr("setup.overview.space.body")}
                    }
                    Link {
                        class: "secondary",
                        to: Route::SetupSection { section: SetupSection::NewSpace.slug().to_owned() },
                        {tr("setup.overview.space.open")}
                    }
                }
                div { class: "metric",
                    strong { {tr("setup.overview.onboarding")} }
                    span { {tr("setup.overview.onboarding.hint")} }
                    Link {
                        class: "secondary",
                        to: Route::Onboarding,
                        {tr("setup.overview.onboarding.open")}
                    }
                }
                div { class: "metric",
                    strong { {tr("setup.overview.search")} }
                    span { {tr("setup.overview.search.hint")} }
                    Link {
                        class: "secondary",
                        to: Route::Directory,
                        {tr("setup.overview.search.open")}
                    }
                }
                div { class: "metric",
                    strong { {tr("setup.overview.board")} }
                    span { {tr("setup.overview.board.hint")} }
                    if has_selected_realm {
                        Link {
                            class: "secondary",
                            to: Route::Realm { realm_id: selected_realm_value.clone() },
                            {tr("setup.overview.board.open_current")}
                        }
                    } else {
                        Link { class: "secondary", to: Route::Kanban, {tr("setup.overview.board.open")} }
                    }
                }
            }
        }

        div { class: "event", "data-testid": "realm-setup-checklist",
            div { class: "event-head",
                span { {tr("setup.overview.moved")} }
                span { {tr("setup.overview.moved.hint")} }
            }
            div { class: "actions",
                span { class: "badge", {tr("setup.overview.badge.onboarding")} }
                span { class: "badge", {tr("setup.overview.badge.search")} }
                span { class: "badge", {tr("setup.overview.badge.realm")} }
                span { class: "badge", {tr("setup.overview.badge.settings")} }
            }
        }
    }
}
