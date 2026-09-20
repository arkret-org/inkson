//! Realm-only public Directory surface.

use dioxus::prelude::*;
use dioxus_router::hooks::use_navigator;

use crate::routes::Route;
use crate::transport::auth::with_directory_sdk_client;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;

#[component]
pub fn DirectoryPanel(
    selected_realm_id: Signal<String>,
    token: Signal<String>,
    view: Signal<super::AppView>,
) -> Element {
    let base_url = crate::app::SessionContext::base_url_string();
    let mut query = use_signal(String::new);
    let mut results = use_signal(Vec::<arkret_models_discovery::PublicRealmDirectoryEntry>::new);
    let mut next_cursor = use_signal(|| Option::<String>::None);
    let navigator = use_navigator();

    rsx! {
        div { class: "timeline", "data-testid": "directory-panel", role: "region", "aria-label": "Search public Realms",
            h2 { "Public Realm Directory" }
            p { "Search public Realm metadata. Accounts, handles, organizations, and object targets are not Directory resources." }
            div { class: "actions",
                Input {
                    "data-testid": "directory-search-input",
                    value: "{query}",
                    "aria-label": "Search public Realms",
                    placeholder: "Search public Realms",
                    oninput: move |event: FormEvent| query.set(event.value()),
                }
                Button {
                    variant: ButtonVariant::Primary,
                    "data-testid": "directory-search-button",
                    onclick: {
                        let base_url = base_url.clone();
                        move |_| {
                            let base_url = base_url.clone();
                            let query = query();
                            let credential = token();
                            spawn(async move {
                                match with_directory_sdk_client(&base_url, credential, |http| async move {
                                    crate::transport::directory::search_realms(&http, &query, None).await
                                }).await {
                                    Ok(page) => {
                                        next_cursor.set(page.next_cursor);
                                        results.set(page.realms);
                                    }
                                    Err(error) => crate::components::feedback::toast_error(
                                        "feedback.directory_search_failed",
                                        vec![],
                                        Some(error.to_string()),
                                    ),
                                }
                            });
                        }
                    },
                    "Search"
                }
            }
            for entry in results() {
                {
                    let realm_id = entry.realm_id.as_str().to_owned();
                    let open_realm_id = realm_id.clone();
                    rsx! {
                        article { class: "card", "data-testid": "directory-realm-result",
                            h3 { "{entry.public_metadata.display_name}" }
                            if let Some(summary) = entry.public_metadata.summary.as_deref() {
                                p { "{summary}" }
                            }
                            code { "{realm_id}" }
                            Button {
                                variant: ButtonVariant::Secondary,
                                onclick: move |_| {
                                    selected_realm_id.set(open_realm_id.clone());
                                    view.set(super::AppView::Kanban);
                                    let _ = navigator.push(Route::Realm { realm_id: open_realm_id.clone() });
                                },
                                "Open Realm"
                            }
                        }
                    }
                }
            }
            if next_cursor().is_some() {
                p { "More public Realms are available; refine the search to narrow the result set." }
            }
        }
    }
}
