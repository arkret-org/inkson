//! Realm Circle directory, independent membership, and creator workflows.
use std::rc::Rc;

use glory::prelude::*;

use crate::presentation::widgets::*;
use crate::presentation::{InksonContext, View};
use crate::routes::Route;
use crate::transport::auth::with_authed_api;
use crate::views::settings::widgets::{action, choice, field, input, toggle};
mod commands;
mod controls;
#[cfg(test)]
mod locale_tests;
/// Keep action results in their original form so a locale change can re-render
/// retained feedback without repeating the request.
#[derive(Clone, Default)]
pub(super) struct CircleFeedback {
    key: &'static str,
    error: Option<std::rc::Rc<crate::transport::auth::ApiCallError>>,
}

impl CircleFeedback {
    fn new(key: &'static str) -> Self {
        Self { key, error: None }
    }

    fn with_api_error(mut self, error: crate::transport::auth::ApiCallError) -> Self {
        self.error = Some(std::rc::Rc::new(error));
        self
    }

    fn is_empty(&self) -> bool {
        self.key.is_empty()
    }

    fn render(&self) -> String {
        if self.is_empty() {
            return String::new();
        }
        if let Some(error) = &self.error {
            crate::i18n::tr_args(self.key, &[("error", error.display())])
        } else {
            crate::i18n::tr(self.key)
        }
    }
}

fn valid_short_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=24).contains(&bytes.len())
        && bytes[0].is_ascii_uppercase()
        && bytes
            .iter()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b' ' | b'_' | b'-'))
}

fn lifecycle_label(state: arkret_sdk::CircleState) -> String {
    match state {
        arkret_sdk::CircleState::Active => crate::i18n::tr("circles.page.state_active"),
        arkret_sdk::CircleState::Archived => crate::i18n::tr("circles.page.state_archived"),
        arkret_sdk::CircleState::Tombstoned => crate::i18n::tr("circles.page.state_tombstoned"),
    }
}

fn membership_label(state: Option<arkret_sdk::CircleMembership>) -> String {
    match state {
        Some(arkret_sdk::CircleMembership::Join) => crate::i18n::tr("circles.page.membership_join"),
        Some(arkret_sdk::CircleMembership::Knock) => {
            crate::i18n::tr("circles.page.membership_knock")
        }
        Some(arkret_sdk::CircleMembership::Leave) => {
            crate::i18n::tr("circles.page.membership_leave")
        }
        Some(arkret_sdk::CircleMembership::Ban) => crate::i18n::tr("circles.page.membership_ban"),
        None => crate::i18n::tr("circles.page.membership_viewer"),
    }
}

fn encryption_label(mls_group_id: Option<&str>) -> String {
    if mls_group_id.is_some() {
        crate::i18n::tr("circles.page.encrypted")
    } else {
        crate::i18n::tr("circles.page.unencrypted")
    }
}

fn initial_member_label(principal: &str) -> String {
    crate::i18n::tr_args(
        "circles.page.initial_member",
        &[("member", principal.to_owned())],
    )
}

fn preview_member_count(bucket: arkret_sdk::CircleMemberCountBucket) -> &'static str {
    use arkret_sdk::CircleMemberCountBucket::*;
    match bucket {
        Zero => "0",
        One => "1",
        TwoToThree => "2–3",
        FourToSeven => "4–7",
        EightToFifteen => "8–15",
        SixteenToThirtyOne => "16–31",
        ThirtyTwoToSixtyThree => "32–63",
        SixtyFourToOneHundredTwentySeven => "64–127",
        OneHundredTwentyEightPlus => "128+",
    }
}

#[derive(Clone)]
struct CircleUi {
    busy: Cage<bool>,
    refresh: Cage<u64>,
    status: Cage<CircleFeedback>,
    create_open: Cage<bool>,
}
impl CircleUi {
    fn new(scope: &Scope) -> Rc<Self> {
        Rc::new(Self {
            busy: scope.cage(false),
            refresh: scope.cage(0),
            status: scope.cage(CircleFeedback::default()),
            create_open: scope.cage(false),
        })
    }
}
fn block(class: &str, children: Vec<View>) -> View {
    Box::new(view().class(class.to_owned()).fill(children))
}
fn command_button(
    scope: &Scope,
    context: Rc<InksonContext>,
    ui: Rc<CircleUi>,
    label: &str,
    class: &str,
    command: commands::Change,
) -> View {
    let weak = scope.downgrade();
    let busy = ui.busy;
    action(
        scope,
        context.clone(),
        label,
        label,
        class,
        scope.bond(move || !busy.get()),
        move || {
            if let Some(scope) = weak.upgrade() {
                commands::run(&scope, context.clone(), ui.clone(), command.clone());
            }
        },
    )
}
pub fn page(scope: &Scope, context: Rc<InksonContext>, route: Route) -> View {
    let realm = route
        .realm_id()
        .unwrap_or(&context.selected_realm_id.get())
        .to_owned();
    let selected = match route {
        Route::CircleDetail { circle_id, .. } => Some(circle_id),
        _ => None,
    };
    let ui = CircleUi::new(scope);
    let response = resource(scope, {
        let context = context.clone();
        let ui = ui.clone();
        let realm = realm.clone();
        move || {
            let _ = ui.refresh.get();
            let base = context.base_url.get();
            let token = context.token.get();
            let realm = realm.clone();
            async move {
                with_authed_api(&base, token, |api| async move {
                    api.http()
                        .circle_list(&realm)
                        .await
                        .map_err(anyhow::Error::from)
                })
                .await
                .map(crate::circle::split_ordinary_circle_reads)
                .map_err(|error| error.display())
            }
        }
    });
    let status = scope.bond({
        let context = context.clone();
        let ui = ui.clone();
        move || {
            let _ = context.locale.get();
            ui.status.get().render()
        }
    });
    let body = resource_content(
        context.clone(),
        "circles-directory",
        response,
        "circles.page.loading",
        {
            let context = context.clone();
            let ui = ui.clone();
            let realm = realm.clone();
            move |scope, (circles, previews)| {
                let mut list = Vec::new();
                for circle in &circles {
                    let route = Route::CircleDetail {
                        realm_id: realm.clone(),
                        circle_id: circle.circle_id.to_string(),
                    };
                    let target = route.to_string();
                    let context = context.clone();
                    let badge = crate::components::circle_identity_badge(
                        scope,
                        context.clone(),
                        crate::components::CircleIdentityBadgeProps {
                            color: circle.display.color_token,
                            symbol: circle.display.symbol.clone(),
                            short_name: Some(circle.display.short_name.clone()),
                        },
                    );
                    list.push(Box::new(
                        internal_link()
                            .class(if selected.as_deref() == Some(circle.circle_id.as_str()) {
                                "circle-list-item is-active"
                            } else {
                                "circle-list-item"
                            })
                            .target(target)
                            .fill(vec![
                                block(
                                    "circle-list-item-head",
                                    vec![
                                        plain(circle.title.clone()),
                                        paragraph("pill", lifecycle_label(circle.state)),
                                    ],
                                ),
                                badge,
                                paragraph(
                                    "muted",
                                    crate::i18n::tr_args(
                                        "circles.page.member_count",
                                        &[("count", circle.member_ids.len().to_string())],
                                    ),
                                ),
                                paragraph(
                                    "muted",
                                    encryption_label(circle.mls_group_id.as_deref()),
                                ),
                            ])
                            .on(glory::render::EventKind::Activate, move |_| {
                                context.navigate(route.clone())
                            }),
                    ) as View);
                }
                for preview in &previews {
                    let route = Route::CircleDetail {
                        realm_id: realm.clone(),
                        circle_id: preview.circle_id.to_string(),
                    };
                    let context = context.clone();
                    list.push(Box::new(
                        internal_link()
                            .class("circle-list-item")
                            .target(route.to_string())
                            .fill(vec![
                                heading(3, "", context.translated(scope, "circles.page.preview")),
                                crate::components::circle_identity_badge(
                                    scope,
                                    context.clone(),
                                    crate::components::CircleIdentityBadgeProps {
                                        color: preview.display.color_token,
                                        symbol: preview.display.symbol.clone(),
                                        short_name: None,
                                    },
                                ),
                                paragraph(
                                    "muted",
                                    crate::i18n::tr_args(
                                        "circles.page.preview_count",
                                        &[
                                            (
                                                "count",
                                                preview_member_count(preview.member_count_bucket)
                                                    .to_owned(),
                                            ),
                                            ("rule", format!("{:?}", preview.join_rule)),
                                        ],
                                    ),
                                ),
                            ])
                            .on(glory::render::EventKind::Activate, move |_| {
                                context.navigate(route.clone())
                            }),
                    ) as View);
                }
                if list.is_empty() {
                    list.push(block(
                        "circle-empty",
                        vec![
                            heading(2, "", context.translated(scope, "circles.page.empty")),
                            paragraph(
                                "muted",
                                context.translated(scope, "circles.page.empty_help"),
                            ),
                        ],
                    ));
                }
                let detail = if let Some(circle) = selected.as_deref().and_then(|id| {
                    circles
                        .iter()
                        .find(|circle| circle.circle_id.as_str() == id)
                }) {
                    detail(scope, context.clone(), ui.clone(), circle.clone())
                } else if let Some(preview) = selected.as_deref().and_then(|id| {
                    previews
                        .iter()
                        .find(|preview| preview.circle_id.as_str() == id)
                }) {
                    block(
                        "circle-detail",
                        vec![
                            heading(2, "", context.translated(scope, "circles.page.preview")),
                            paragraph(
                                "muted",
                                context.translated(scope, "circles.page.preview_private"),
                            ),
                            controls::self_membership(
                                scope,
                                context.clone(),
                                ui.clone(),
                                preview.realm_id.to_string(),
                                preview.circle_id.to_string(),
                                preview.join_rule,
                                None,
                                false,
                            ),
                            paragraph(
                                "circle-boundary-grid",
                                crate::i18n::tr_args(
                                    "circles.page.approximate_count",
                                    &[(
                                        "count",
                                        preview_member_count(preview.member_count_bucket)
                                            .to_owned(),
                                    )],
                                ),
                            ),
                        ],
                    )
                } else {
                    block(
                        "circle-detail circle-empty",
                        vec![
                            heading(2, "", context.translated(scope, "circles.page.select")),
                            paragraph(
                                "muted",
                                context.translated(scope, "circles.page.select_help"),
                            ),
                        ],
                    )
                };
                block(
                    "circle-realm-grid",
                    vec![
                        Box::new(
                            view()
                                .role(glory::render::Role::Navigation)
                                .class("circle-list")
                                .name(context.translated(scope, "circles.page.nav_label"))
                                .fill(list),
                        ),
                        detail,
                    ],
                )
            }
        },
    );
    block(
        "circle-realm",
        vec![
            block(
                "circle-realm-header",
                vec![
                    heading(1, "", context.translated(scope, "circles.page.heading")),
                    crate::components::help_tip(
                        scope,
                        context.clone(),
                        crate::components::HelpTipProps {
                            text: context.tr("circles.page.help"),
                        },
                    ),
                    block(
                        "actions",
                        vec![
                            action(
                                scope,
                                context.clone(),
                                "circles-refresh",
                                "common.refresh",
                                "secondary",
                                true,
                                {
                                    let ui = ui.clone();
                                    move || {
                                        ui.refresh.revise(|value| *value = value.wrapping_add(1))
                                    }
                                },
                            ),
                            action(
                                scope,
                                context.clone(),
                                "circles-new",
                                "circles.page.new",
                                "primary",
                                true,
                                {
                                    let ui = ui.clone();
                                    move || ui.create_open.revise(|value| *value = true)
                                },
                            ),
                        ],
                    ),
                ],
            ),
            Box::new(
                view()
                    .role(glory::render::Role::Status)
                    .class("circle-status")
                    .fill(plain(status)),
            ),
            body,
            controls::create_form(scope, context, ui, realm),
        ],
    )
}
fn detail(
    scope: &Scope,
    context: Rc<InksonContext>,
    ui: Rc<CircleUi>,
    circle: arkret_sdk::CircleView,
) -> View {
    let realm = circle.realm_id.to_string();
    let id = circle.circle_id.to_string();
    let mut children = vec![
        block(
            "circle-detail-heading",
            vec![
                block(
                    "",
                    vec![
                        crate::components::circle_identity_badge(
                            scope,
                            context.clone(),
                            crate::components::CircleIdentityBadgeProps {
                                color: circle.display.color_token,
                                symbol: circle.display.symbol.clone(),
                                short_name: Some(circle.display.short_name.clone()),
                            },
                        ),
                        heading(2, "", circle.title.clone()),
                        paragraph("muted", circle.summary.clone().unwrap_or_default()),
                    ],
                ),
                paragraph("pill", lifecycle_label(circle.state)),
            ],
        ),
        block(
            "circle-boundary-grid",
            vec![
                paragraph(
                    "",
                    format!(
                        "{}: {}",
                        context.tr("circles.page.membership"),
                        circle.member_ids.len()
                    ),
                ),
                paragraph("", membership_label(circle.viewer_membership)),
                paragraph(
                    "",
                    format!(
                        "{}: {:?}",
                        context.tr("circles.page.join_rule"),
                        circle.join_rule
                    ),
                ),
                paragraph(
                    "",
                    format!(
                        "{}: {:?}",
                        context.tr("circles.page.history"),
                        circle.history_access
                    ),
                ),
                paragraph(
                    "",
                    format!(
                        "{}: {:?}",
                        context.tr("circles.page.directory"),
                        circle.directory_visibility
                    ),
                ),
                paragraph("", encryption_label(circle.mls_group_id.as_deref())),
            ],
        ),
    ];
    if circle.mls_group_id.is_none() {
        children.push(block(
            "circle-security-warning",
            vec![
                heading(
                    3,
                    "",
                    context.translated(scope, "circles.page.not_encrypted"),
                ),
                paragraph(
                    "",
                    context.translated(scope, "circles.page.plaintext_warning"),
                ),
            ],
        ));
    }
    children.push(controls::self_membership(
        scope,
        context.clone(),
        ui.clone(),
        realm.clone(),
        id.clone(),
        circle.join_rule,
        circle.viewer_membership,
        circle.state == arkret_sdk::CircleState::Tombstoned,
    ));
    if circle.state == arkret_sdk::CircleState::Active {
        children.push(controls::edit_form(
            scope,
            context.clone(),
            ui.clone(),
            circle.clone(),
        ));
    }
    children.push(controls::terminal_actions(
        scope,
        context.clone(),
        ui.clone(),
        circle.clone(),
    ));
    let mut members = vec![heading(
        3,
        "",
        context.translated(scope, "circles.page.members"),
    )];
    for member in &circle.member_ids {
        members.push(block(
            "circle-member-row",
            vec![
                paragraph("mono", member.to_string()),
                command_button(
                    scope,
                    context.clone(),
                    ui.clone(),
                    "circles.page.remove",
                    "secondary danger",
                    commands::Change::Remove {
                        realm: realm.clone(),
                        circle: id.clone(),
                        member: member.clone(),
                    },
                ),
            ],
        ));
    }
    if circle.member_ids.is_empty() {
        members.push(paragraph(
            "muted",
            context.translated(scope, "circles.page.members_private"),
        ));
    }
    if circle.state != arkret_sdk::CircleState::Tombstoned {
        members.push(controls::member_form(
            scope,
            context.clone(),
            ui.clone(),
            realm.clone(),
            id.clone(),
        ));
    }
    children.push(block("circle-members-section", members));
    if circle.state != arkret_sdk::CircleState::Tombstoned {
        let archived = circle.state == arkret_sdk::CircleState::Archived;
        children.push(command_button(
            scope,
            context.clone(),
            ui.clone(),
            if archived {
                "circles.page.restore"
            } else {
                "circles.page.archive"
            },
            "secondary",
            commands::Change::Archive {
                realm,
                circle: id,
                restore: archived,
            },
        ));
    }
    block("circle-detail", children)
}
#[cfg(test)]
mod tests {
    use super::{encryption_label, valid_short_name};

    #[test]
    fn circle_short_name_validation_matches_registered_ascii_boundary() {
        for value in ["Ops", "A_1-x", "A12345678901234567890123"] {
            assert!(valid_short_name(value));
        }
        for value in ["", "ops", "运维", "A!", "A1234567890123456789012345"] {
            assert!(!valid_short_name(value));
        }
    }

    #[test]
    fn circle_security_label_follows_accepted_mls_binding() {
        assert_eq!(
            encryption_label(Some("ak:mls_group:accepted")),
            "Independent MLS group · E2EE active"
        );
        assert_eq!(encryption_label(None), "Restricted delivery · not E2EE");
    }
}
