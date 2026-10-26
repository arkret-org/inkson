use std::rc::Rc;

use glory::Scope;

use crate::presentation::{InksonContext, View};
use crate::routes::Route;
use crate::views::settings::widgets::*;
pub(super) fn page(scope: &Scope, context: Rc<InksonContext>) -> View {
    let mut metrics = vec![];
    for (title, hint, body, label, route) in [
        (
            "setup.new_realm",
            "setup.overview.realm.hint",
            "",
            "setup.overview.realm.open",
            Route::SetupSection {
                section: super::model::SetupSection::Realms.slug().into(),
            },
        ),
        (
            "setup.space.new_space",
            "setup.overview.space.hint",
            "setup.overview.space.body",
            "setup.overview.space.open",
            Route::SetupSection {
                section: super::model::SetupSection::NewSpace.slug().into(),
            },
        ),
        (
            "setup.overview.onboarding",
            "setup.overview.onboarding.hint",
            "",
            "setup.overview.onboarding.open",
            Route::Onboarding,
        ),
        (
            "setup.overview.search",
            "setup.overview.search.hint",
            "",
            "setup.overview.search.open",
            Route::Directory,
        ),
        (
            "setup.overview.board",
            "setup.overview.board.hint",
            "",
            "setup.overview.board.open_current",
            if context.selected_realm_id.get_untracked().is_empty() {
                Route::Kanban
            } else {
                Route::Realm {
                    realm_id: context.selected_realm_id.get_untracked(),
                }
            },
        ),
    ] {
        let ctx = context.clone();
        let mut children = vec![
            plain(context.translated(scope, title)),
            plain(context.translated(scope, hint)),
        ];
        if !body.is_empty() {
            children.push(paragraph("muted", context.translated(scope, body)));
        }
        children.push(action(
            scope,
            context.clone(),
            "setup-overview-open",
            label,
            "secondary",
            true,
            move || ctx.navigate(route.clone()),
        ));
        metrics.push(stack("metric", children));
    }
    stack(
        "setup-overview",
        vec![
            stack(
                "event realm-setup-map",
                vec![
                    line(
                        "event-head",
                        vec![
                            plain(context.translated(scope, "setup.overview.surfaces")),
                            plain(context.translated(scope, "setup.overview.surfaces.hint")),
                        ],
                    ),
                    stack("metric-grid", metrics),
                ],
            ),
            stack(
                "event realm-setup-checklist",
                vec![
                    line(
                        "event-head",
                        vec![
                            plain(context.translated(scope, "setup.overview.moved")),
                            plain(context.translated(scope, "setup.overview.moved.hint")),
                        ],
                    ),
                    line(
                        "actions",
                        ["onboarding", "search", "realm", "settings"]
                            .into_iter()
                            .map(|name| {
                                paragraph(
                                    "badge",
                                    context
                                        .translated(scope, format!("setup.overview.badge.{name}")),
                                )
                            })
                            .collect(),
                    ),
                ],
            ),
        ],
    )
}
