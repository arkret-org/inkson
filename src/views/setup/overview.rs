//! Setup overview / surface-map section component.

use dioxus::prelude::*;
use dioxus_router::Link;

use super::model::SetupSection;
use crate::routes::Route;

#[component]
pub(super) fn OverviewSection(selected_realm_id: Signal<String>) -> Element {
    let selected_realm_value = selected_realm_id();
    let has_selected_realm = !selected_realm_value.trim().is_empty();

    rsx! {
        div { class: "event", "data-testid": "workspace-setup-map",
            div { class: "event-head",
                span { "Setup Surfaces" }
                span { "single-purpose entrypoints" }
            }
            div { class: "metric-grid",
                div { class: "metric",
                    strong { "New Realm" }
                    span { "security-boundary bootstrap" }
                    Link {
                        class: "secondary",
                        to: Route::SetupSection { section: SetupSection::Realms.slug().to_owned() },
                        "Open New Realm"
                    }
                }
                div { class: "metric",
                    strong { "New Space" }
                    span { "navigation container inside a Realm" }
                    div { class: "muted",
                        "Hover a Realm or Space in the left sidebar and click the inline + — that's the canonical entry, because it pre-fills the parent context for you. The link below opens the form blank (you'll have to pick a Realm manually)."
                    }
                    Link {
                        class: "secondary",
                        to: Route::SetupSection { section: SetupSection::NewSpace.slug().to_owned() },
                        "Open blank form"
                    }
                }
                div { class: "metric",
                    strong { "Onboarding" }
                    span { "identity bootstrap" }
                    Link { class: "secondary", to: Route::Onboarding, "Open Onboarding" }
                }
                div { class: "metric",
                    strong { "Search" }
                    span { "actors / handles / realms" }
                    Link { class: "secondary", to: Route::Directory, "Open Search" }
                }
                div { class: "metric",
                    strong { "Realm timeline" }
                    span { "after bootstrap" }
                    if has_selected_realm {
                        Link {
                            class: "secondary",
                            to: Route::Realm { realm_id: selected_realm_value.clone() },
                            "Open Current Realm"
                        }
                    } else {
                        Link { class: "secondary", to: Route::Timeline, "Open Timeline" }
                    }
                }
            }
        }

        div { class: "event", "data-testid": "workspace-setup-checklist",
            div { class: "event-head",
                span { "What Moved" }
                span { "IA cleanup" }
            }
            div { class: "actions",
                span { class: "badge", "Onboarding = identity bootstrap" }
                span { class: "badge", "Search = discovery and people" }
                span { class: "badge", "New Realm = security-boundary bootstrap" }
                span { class: "badge", "Settings = recovery and operations" }
            }
        }
    }
}
