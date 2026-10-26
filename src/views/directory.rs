use std::rc::Rc;

use glory::Scope;

use crate::presentation::{InksonContext, View};
use crate::routes::Route;
use crate::transport::auth::with_directory_sdk_client;
use crate::views::settings::widgets::*;

pub fn page(scope: &Scope, context: Rc<InksonContext>, _route: Route) -> View {
    let address = scope.cage(String::new());
    let query = scope.cage(String::new());
    let generation = scope.cage(0_u64);
    let next_cursor = scope.cage(None::<String>);
    let results = scope.cage(Vec::<arkret_models_discovery::PublicRealmDirectoryEntry>::new());
    let busy = scope.cage(false);
    let weak = scope.downgrade();
    let search_context = context.clone();
    let rows_context = context.clone();
    let rows = reactive(results, move |scope, rows| {
        let context = rows_context.clone();
        let mut children = Vec::new();
        for entry in rows {
            let realm = entry.realm_id.to_string();
            let navigate = context.clone();
            let target = realm.clone();
            let mut details = vec![
                heading(3, "", entry.public_metadata.display_name),
                paragraph("mono", realm),
            ];
            if let Some(summary) = entry.public_metadata.summary {
                details.push(paragraph("", summary));
            }
            details.push(action(
                scope,
                context.clone(),
                "directory-open-realm",
                "Open Realm",
                "secondary",
                true,
                move || {
                    navigate
                        .selected_realm_id
                        .revise(|value| *value = target.clone());
                    navigate.navigate(Route::Realm {
                        realm_id: target.clone(),
                    });
                },
            ));
            children.push(stack("card directory-realm-result", details));
        }
        stack("directory-results", children)
    });
    stack(
        "timeline directory-panel",
        vec![
            heading(2, "directory-title", "Public Realm Directory"),
            paragraph(
                "directory-description",
                "Search public Realm metadata. Accounts, handles, organizations, and object targets are not Directory resources.",
            ),
            paragraph(
                "directory-description",
                "Enter a Directory HTTPS address for this search. This address is not saved and does not change your Account Station.",
            ),
            line(
                "actions",
                vec![
                    input_prompt(
                        scope,
                        "https://directory.example".into(),
                        address,
                        Box::new(
                            sapid::text_field()
                                .unstyled()
                                .class("input directory-address-input")
                                .name("Directory HTTPS address")
                                .value(address)
                                .on_value_change(move |next| {
                                    address.revise(|value| *value = next);
                                    generation.revise(|value| *value = value.wrapping_add(1));
                                    results.revise(|value| value.clear());
                                    next_cursor.revise(|value| *value = None);
                                }),
                        ),
                    ),
                    input_prompt(
                        scope,
                        "Search public Realms".into(),
                        query,
                        Box::new(
                            sapid::text_field()
                                .unstyled()
                                .class("input directory-search-input")
                                .name("Search public Realms")
                                .value(query)
                                .on_value_change(move |next| query.revise(|value| *value = next)),
                        ),
                    ),
                    action(
                        scope,
                        context.clone(),
                        "directory-search-button",
                        "Search",
                        "primary",
                        scope.bond(move || !busy.get() && !address.get().trim().is_empty()),
                        move || {
                            if busy.get_untracked() {
                                return;
                            }
                            let Some(scope) = weak.upgrade() else { return };
                            let base = search_context.base_url.get();
                            let token = search_context.token.get();
                            let query = query.get();
                            let directory = address.get();
                            let serial = generation.get();
                            busy.revise(|value| *value = true);
                            spawn(&scope, async move {
                                let outcome = with_directory_sdk_client(
                                    &base,
                                    &directory,
                                    token,
                                    |http| async move {
                                        crate::transport::directory::search_realms(
                                            &http, &query, None,
                                        )
                                        .await
                                    },
                                )
                                .await;
                                busy.revise(|value| *value = false);
                                if generation.get() != serial {
                                    return;
                                }
                                match outcome {
                                    Ok(page) => {
                                        next_cursor.revise(|value| *value = page.next_cursor);
                                        results.revise(|value| *value = page.realms);
                                    }
                                    Err(error) => crate::components::feedback::toast_error(
                                        "feedback.directory_search_failed",
                                        vec![],
                                        Some(error.display()),
                                    ),
                                }
                            });
                        },
                    ),
                ],
            ),
            rows,
            reactive(next_cursor, |_, cursor| {
                if cursor.is_some() {
                    paragraph(
                        "muted",
                        "More public Realms are available; refine the search to narrow the result set.",
                    )
                } else {
                    empty()
                }
            }),
        ],
    )
}
