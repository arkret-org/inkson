//! Version information from the release inputs of the running client.

use glory::Scope;

use super::widgets::{heading, line, paragraph, plain, stack};
use crate::presentation::{InksonContext, View};

pub(super) fn page(scope: &Scope, context: &InksonContext) -> View {
    let row = |label: &str, value: View| {
        line(
            "settings-about-row",
            vec![paragraph("muted", context.translated(scope, label)), value],
        )
    };
    let release_date = option_env!("INKSON_PACKAGE_RELEASE_DATE").map_or_else(
        || plain(context.translated(scope, "settings.about.no_release_date")),
        plain,
    );
    stack(
        "event settings-about",
        vec![
            heading(2, "settings-content-title", "Inkson"),
            row(
                "settings.about.client_version",
                plain(env!("CARGO_PKG_VERSION")),
            ),
            row(
                "settings.about.spec_version",
                plain(env!("INKSON_SPEC_RELEASE_TAG")),
            ),
            row(
                "developer.section.protocol_version",
                plain(arkret_sdk::PROTOCOL_VERSION),
            ),
            row("settings.about.release_date", release_date),
            row("settings.about.build", plain(crate::build_info::build_id())),
        ],
    )
}
