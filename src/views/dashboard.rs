use std::rc::Rc;

use arkret_sdk::contact_operations::ContactScope;
use glory::{Cage, Scope};

use crate::i18n::tr;
use crate::models::{RealmTreeNodeKind, projection_realm_id_for_known_node};
use crate::presentation::{InksonContext, View};
use crate::routes::Route;
use crate::state::ClientLocalState;
use crate::views::helpers::short_protocol_id;
use crate::views::settings::widgets::*;
#[derive(Clone, Debug, PartialEq)]
struct DashboardNotificationSummary {
    id: String,
    title: String,
    title_is_key: bool,
    body: String,
    body_translation: Option<(&'static str, Vec<(&'static str, String)>)>,
    kind: String,
    kind_label_key: &'static str,
    timestamp: String,
    read: bool,
}

impl DashboardNotificationSummary {
    fn render_title(&self) -> String {
        if self.title_is_key {
            tr(&self.title)
        } else {
            self.title.clone()
        }
    }

    fn render_body(&self) -> String {
        match &self.body_translation {
            Some((key, args)) => crate::i18n::tr_args(key, args),
            None => self.body.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
struct DashboardContactsSummary {
    accepted: usize,
    pending_incoming: usize,
    pending_outgoing: usize,
    direct_ready: usize,
}

impl DashboardContactsSummary {
    fn pending(&self) -> usize {
        self.pending_incoming + self.pending_outgoing
    }
}

fn projection_object_state_label(state: &arkret_sdk::ObjectState) -> &'static str {
    match state {
        arkret_sdk::ObjectState::Active => "dashboard.object_state.active",
        arkret_sdk::ObjectState::Archived => "dashboard.object_state.archived",
        arkret_sdk::ObjectState::Redacted => "dashboard.object_state.redacted",
    }
}

fn dashboard_realm_description(description: Option<&str>) -> String {
    description
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| tr("dashboard.open_board"))
}

#[derive(Clone)]
enum DashboardHealthValue {
    Service {
        service: arkret_sdk::ServiceKind,
        version: arkret_sdk::ServiceProtocolVersion,
    },
    Profiles(usize),
    EndpointError(String),
    ApiError(Rc<crate::transport::auth::ApiCallError>),
}

impl DashboardHealthValue {
    fn render(&self) -> String {
        match self {
            Self::Service { service, version } => crate::i18n::tr_args(
                "dashboard.health.service",
                &[
                    ("service", service.to_string()),
                    ("version", version.to_string()),
                ],
            ),
            Self::Profiles(count) => {
                crate::i18n::tr_args("dashboard.health.profiles", &[("count", count.to_string())])
            }
            Self::EndpointError(error) => {
                crate::i18n::tr_args("dashboard.health.error", &[("error", error.clone())])
            }
            Self::ApiError(error) => {
                crate::i18n::tr_args("dashboard.health.error", &[("error", error.display())])
            }
        }
    }
}

#[derive(Clone)]
struct DashboardHealthCheck {
    name_key: &'static str,
    value: DashboardHealthValue,
}

impl DashboardHealthCheck {
    fn new(name_key: &'static str, value: DashboardHealthValue) -> Self {
        Self { name_key, value }
    }
}

fn dashboard_notification_kind_key(kind: &arkret_sdk::NotificationKind) -> &'static str {
    match kind {
        arkret_sdk::NotificationKind::Message => "dashboard.notification_kind.message",
        arkret_sdk::NotificationKind::Mention => "dashboard.notification_kind.mention",
        arkret_sdk::NotificationKind::Reply => "dashboard.notification_kind.reply",
        arkret_sdk::NotificationKind::Assignment => "dashboard.notification_kind.assignment",
        arkret_sdk::NotificationKind::Schedule => "dashboard.notification_kind.schedule",
        arkret_sdk::NotificationKind::Invite => "dashboard.notification_kind.invite",
        arkret_sdk::NotificationKind::Reaction => "dashboard.notification_kind.reaction",
        arkret_sdk::NotificationKind::Policy => "dashboard.notification_kind.policy",
        arkret_sdk::NotificationKind::Call => "dashboard.notification_kind.call",
        arkret_sdk::NotificationKind::Applet => "dashboard.notification_kind.applet",
        arkret_sdk::NotificationKind::Agent => "dashboard.notification_kind.agent",
        arkret_sdk::NotificationKind::Moderation => "dashboard.notification_kind.moderation",
        arkret_sdk::NotificationKind::System => "dashboard.notification_kind.system",
    }
}

fn nav_view(context: Rc<InksonContext>, route: Route, class: &str, children: Vec<View>) -> View {
    Box::new(
        crate::presentation::widgets::internal_link()
            .class(class)
            .target(route.to_string())
            .fill(children)
            .on(glory::render::EventKind::Activate, move |_| {
                if let Route::Realm { realm_id } | Route::KanbanRealm { realm_id } = &route {
                    context
                        .selected_realm_id
                        .revise(|value| *value = realm_id.clone());
                }
                context.navigate(route.clone());
            }),
    )
}

fn surface_title(value: impl Into<glory::Lotus<String>>) -> View {
    Box::new(
        glory::ui::text()
            .class("dashboard-section-title")
            .style(glory::style::Style::new().font_weight(700.0))
            .content(value),
    )
}

fn notification_source_id(scope: &Scope, identity: &str) -> Option<glory::render::SemanticId> {
    use sha2::Digest;
    match glory::render::SemanticId::new(format!(
        "dashboard-notification-{}",
        hex::encode(sha2::Sha256::digest(identity.as_bytes()))
    )) {
        Ok(id) => Some(id),
        Err(error) => {
            scope.report_error(error);
            None
        }
    }
}

fn frontier_card(scope: &Scope, context: &InksonContext) -> View {
    let id = match glory::render::SemanticId::new("dashboard-event-frontier-source") {
        Ok(id) => id,
        Err(error) => {
            scope.report_error(error);
            return empty();
        }
    };
    let frontier = context.frontier_state;
    Box::new(
        glory::ui::view()
            .class("mono f-11 event-frontier-card")
            .role(glory::render::Role::Group)
            .name(context.translated(scope, "dashboard.event_frontier"))
            .semantics(Some(Box::new(glory::render::Semantics {
                described_by: Some(id.clone()),
                ..Default::default()
            })))
            .fill(vec![
                plain(scope.bond(move || short_protocol_id(frontier.get()))),
                Box::new(
                    glory::ui::text()
                        .class("sr-only dashboard-frontier-provenance")
                        .content(frontier)
                        .semantics(Some(Box::new(glory::render::Semantics {
                            id: Some(id),
                            ..Default::default()
                        }))),
                ) as View,
            ]),
    )
}

fn notifications_open(scope: &Scope, context: Rc<InksonContext>) -> View {
    let label = context.translated(scope, "dashboard.notifications_open");
    let make_link = move || {
        let context = context.clone();
        crate::presentation::widgets::internal_link()
            .class("btn icon sm ghost ml-auto pinned-notifications-open")
            .target(Route::Notifications.to_string())
            .name(label)
            .fill(crate::components::ui_icon("inbox"))
            .on(glory::render::EventKind::Activate, move |_| {
                context.navigate(Route::Notifications)
            })
    };
    #[cfg(target_arch = "wasm32")]
    {
        Box::new(
            sapid::tooltip("dashboard-notifications-hint")
                .label(label)
                .text(label)
                .target(move |target| target.link(make_link())),
        )
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Box::new(make_link())
    }
}
fn dashboard_health(
    scope: &Scope,
    context: Rc<InksonContext>,
    protocol_health: Cage<Vec<DashboardHealthCheck>>,
    health_loading: Cage<bool>,
) -> View {
    let health_handler = {
        let context = context.clone();
        let token = context.token;
        let base_url = context.base_url.get_untracked();
        {
            let base = base_url.clone();
            move |_| {
                let base = base.clone();
                let api_token = token.get();
                health_loading.revise(|value| {
                    *value = true;
                });
                {
                    let task_owner = context.clone();
                    let _ = task_owner.spawn(async move {
                        // Fold the four sequential checks into a
                        // single `with_authed_api` so an Unavailable or
                        // AuthExpired error tags every row at once
                        // instead of silently returning an empty Vec.
                        let result = crate::transport::auth::with_authed_api(
                            &base,
                            api_token,
                            |api| async move {
                                let mut rows = Vec::new();
                                match api.describe().await {
                                    Ok(d) => rows.push(DashboardHealthCheck::new(
                                        "dashboard.health.describe",
                                        DashboardHealthValue::Service {
                                            service: d.service_kind,
                                            version: d.protocol_version,
                                        },
                                    )),
                                    Err(e) => rows.push(DashboardHealthCheck::new(
                                        "dashboard.health.describe",
                                        DashboardHealthValue::EndpointError(e.to_string()),
                                    )),
                                }
                                match async {
                                    crate::transport::account::sync_describe(
                                        &api.sdk_http_client()?,
                                    )
                                    .await
                                }
                                .await
                                {
                                    Ok(s) => rows.push(DashboardHealthCheck::new(
                                        "dashboard.health.sync",
                                        DashboardHealthValue::Profiles(s.supported_profiles.len()),
                                    )),
                                    Err(e) => rows.push(DashboardHealthCheck::new(
                                        "dashboard.health.sync",
                                        DashboardHealthValue::EndpointError(e.to_string()),
                                    )),
                                }
                                match async {
                                    crate::transport::account::identity_describe(
                                        &api.sdk_http_client()?,
                                    )
                                    .await
                                }
                                .await
                                {
                                    Ok(i) => rows.push(DashboardHealthCheck::new(
                                        "dashboard.health.identity",
                                        DashboardHealthValue::Service {
                                            service: i.service_kind,
                                            version: i.protocol_version,
                                        },
                                    )),
                                    Err(e) => rows.push(DashboardHealthCheck::new(
                                        "dashboard.health.identity",
                                        DashboardHealthValue::EndpointError(e.to_string()),
                                    )),
                                }
                                Ok::<_, anyhow::Error>(rows)
                            },
                        )
                        .await;
                        let checks = match result {
                            Ok(rows) => rows,
                            Err(err) => vec![DashboardHealthCheck::new(
                                "dashboard.health.api",
                                DashboardHealthValue::ApiError(Rc::new(err)),
                            )],
                        };
                        protocol_health.revise(|value| {
                            *value = checks;
                        });
                        health_loading.revise(|value| {
                            *value = false;
                        });
                    });
                };
            }
        }
    };
    let health = reactive(protocol_health, {
        let ctx = context.clone();
        move |scope, checks| {
            if checks.is_empty() {
                paragraph("muted f-12", ctx.translated(scope, "dashboard.health_help"))
            } else {
                stack(
                    "stack-sm",
                    checks
                        .into_iter()
                        .map(|check| {
                            line(
                                "settings-row dashboard-health-row",
                                vec![
                                    paragraph(
                                        "label f-12 dashboard-health-name",
                                        tr(check.name_key),
                                    ),
                                    paragraph(
                                        "mono f-11 dashboard-health-value",
                                        check.value.render(),
                                    ),
                                ],
                            )
                        })
                        .collect(),
                )
            }
        }
    });
    let health_name = {
        let context = context.clone();
        scope.bond(move || {
            context.tr(if health_loading.get() {
                "dashboard.checking_health"
            } else {
                "dashboard.run_health_checks"
            })
        })
    };
    let health_handler: Rc<dyn Fn(())> = Rc::new(health_handler);
    let enabled = scope.bond(move || !health_loading.get());
    let make_button = move || {
        let handler = health_handler.clone();
        glory::prelude::button()
            .class("btn icon sm ghost ml-auto check-health-button")
            .name(health_name)
            .enabled(enabled)
            .fill(crate::components::ui_icon("refresh"))
            .on(glory::render::EventKind::Activate, move |_| handler(()))
    };
    #[cfg(target_arch = "wasm32")]
    let health_button: View = Box::new(
        sapid::tooltip("dashboard-health-hint")
            .label(health_name)
            .text(health_name)
            .target(move |target| target.button(make_button())),
    );
    #[cfg(not(target_arch = "wasm32"))]
    let health_button: View = Box::new(make_button());
    stack(
        "surface operations-surface",
        vec![
            line(
                "row surface-head",
                vec![
                    surface_title(context.translated(scope, "dashboard.client_status")),
                    crate::components::help_tip(
                        scope,
                        context.clone(),
                        crate::components::HelpTipProps {
                            text: tr("dashboard.client_status_help"),
                        },
                    ),
                ],
            ),
            line(
                "settings-row",
                vec![
                    stack(
                        "",
                        vec![
                            paragraph(
                                "label f-12",
                                context.translated(scope, "dashboard.sync_frontier"),
                            ),
                            paragraph("sub mono", {
                                let cage = context.sync_cursor;
                                scope.bond(move || short_protocol_id(cage.get()))
                            }),
                        ],
                    ),
                    paragraph("pill success dot", {
                        let token = context.token;
                        scope.bond(move || {
                            tr(if token.get().is_empty() {
                                "dashboard.not_connected"
                            } else {
                                "dashboard.loaded"
                            })
                        })
                    }),
                ],
            ),
            line(
                "settings-row",
                vec![
                    stack(
                        "",
                        vec![
                            paragraph(
                                "label f-12",
                                context.translated(scope, "dashboard.event_frontier"),
                            ),
                            paragraph(
                                "sub",
                                context.translated(scope, "dashboard.station_reported"),
                            ),
                        ],
                    ),
                    frontier_card(scope, &context),
                ],
            ),
            line(
                "settings-row",
                vec![
                    stack(
                        "",
                        vec![
                            paragraph(
                                "label f-12",
                                context.translated(scope, "dashboard.queued_writes"),
                            ),
                            paragraph(
                                "sub",
                                context.translated(scope, "dashboard.local_replay_queue"),
                            ),
                        ],
                    ),
                    paragraph("mono f-11", {
                        let queue = context.device_queue;
                        scope.bond(move || queue.get().to_string())
                    }),
                ],
            ),
            line(
                "actions",
                vec![
                    nav_view(
                        context.clone(),
                        Route::SettingsSection {
                            section: "release".into(),
                            filter: String::new(),
                        },
                        "secondary",
                        vec![
                            crate::components::ui_icon("settings"),
                            plain(context.translated(scope, "dashboard.advanced_diagnostics")),
                        ],
                    ),
                    health_button,
                ],
            ),
            stack("dashboard-health-results", vec![health]),
        ],
    )
}
fn recent_strands_table(rows: Vec<Vec<View>>, empty_label: String) -> View {
    let head = sapid::table_head().row(
        sapid::table_row("head").cells(
            [
                "",
                "dashboard.strand_title",
                "dashboard.strand_space",
                "dashboard.strand_state",
                "dashboard.strand_updated",
            ]
            .into_iter()
            .enumerate()
            .map(|(index, key)| sapid::table_header_cell(format!("column-{index}")).text(tr(key))),
        ),
    );
    let body = if rows.is_empty() {
        sapid::table_body().row(
            sapid::table_row("empty").cell(
                sapid::table_cell("message")
                    .class("dim")
                    .column_span(5)
                    .text(empty_label),
            ),
        )
    } else {
        sapid::table_body().rows(rows.into_iter().enumerate().map(|(index, cells)| {
            sapid::table_row(format!("row-{index}")).cells(cells.into_iter().enumerate().map(
                |(column, view)| {
                    let mut view = Some(view);
                    sapid::table_cell(format!("column-{column}"))
                        .content(move || view.take().unwrap_or_else(empty))
                },
            ))
        }))
    };
    Box::new(
        sapid::table("dashboard-recent-strands")
            .unstyled()
            .class("tbl compact")
            .head(head)
            .body(body),
    )
}

pub fn page(scope: &Scope, context: Rc<InksonContext>, _route: Route) -> View {
    let protocol_health = scope.cage(Vec::<DashboardHealthCheck>::new());
    let health_loading = scope.cage(false);
    let contacts = {
        let ctx = context.clone();
        crate::presentation::widgets::resource(scope, move || {
            let base = ctx.base_url.get();
            let token = ctx.token.get();
            async move {
                if token.trim().is_empty() {
                    return Ok(None);
                }
                crate::transport::auth::with_endpoint_clients(
                    &base,
                    token,
                    None,
                    |clients| async move { clients.account().contacts().await },
                )
                .await
                .map(|response| Some(dashboard_contacts_summary(&response.contacts)))
                .map_err(|_| tr("dashboard.contacts_unavailable"))
            }
        })
    };
    let source = {
        let ctx = context.clone();
        scope.bond(move || {
            let _ = ctx.state_revision.get();
            let _ = ctx.locale.get();
            let _ = ctx.selected_realm_id.get();
            let _ = ctx.realm_tree_nodes.get();
            let _ = ctx.token.get();
            contacts.data.get()
        })
    };
    let ctx = context.clone();
    let panels = reactive(source, move |scope, contact_status| {
        let snapshot = ctx.snapshot();
        let session = !ctx.token.get_untracked().trim().is_empty();
        let nodes = ctx.realm_tree_nodes.get_untracked();
        let pinned = ctx.state_store.read(|store| {
            store
                .realm_remarks()
                .into_iter()
                .filter_map(|(id, remark)| remark.pinned.then_some(id))
                .collect()
        });
        let nodes = crate::realm_tree::realm_tree_items_with_pinned_realms(&nodes, &pinned)
            .into_iter()
            .map(|item| item.node)
            .collect::<Vec<_>>();
        let has_realms = nodes.iter().any(|n| n.kind == RealmTreeNodeKind::Realm);
        let has_spaces = nodes.iter().any(|n| n.kind == RealmTreeNodeKind::Space);
        let active = nodes
            .iter()
            .find(|n| n.id == ctx.selected_realm_id.get_untracked())
            .or_else(|| nodes.first());
        let active_id = active.map(|n| n.id.clone()).unwrap_or_default();
        let realm = projection_realm_id_for_known_node(&nodes, &active_id).unwrap_or_default();
        let strands = dashboard_recent_strands(&snapshot.raw_operations, &realm)
            .into_iter()
            .filter(|s| s.state == arkret_sdk::ObjectState::Active)
            .take(5)
            .collect::<Vec<_>>();
        let notices = dashboard_notification_summaries(&snapshot);
        let unread = notices.iter().filter(|n| !n.read).count();
        let (contact_count, contact_delta) = match &contact_status {
            Some(Ok(Some(summary))) => {
                (summary.accepted.to_string(), contact_summary_delta(summary))
            }
            Some(Err(error)) => ("0".into(), error.clone()),
            _ if !session => ("0".into(), tr("contacts.sign_in")),
            _ => ("...".into(), tr("dashboard.contacts_loading")),
        };
        let metric = |route, label: String, value: String, delta: String, class: &str| {
            nav_view(
                ctx.clone(),
                route,
                &format!(
                    "metric {}",
                    if class == "dashboard-unread-notifications" {
                        ""
                    } else {
                        class
                    }
                ),
                vec![
                    paragraph("lbl", label),
                    paragraph(
                        if class == "dashboard-unread-notifications" {
                            "val dashboard-unread-notifications"
                        } else if class == "dashboard-contacts-card" {
                            "val dashboard-contacts-count"
                        } else {
                            "val"
                        },
                        value,
                    ),
                    paragraph("delta", delta),
                ],
            )
        };
        let mut metrics = vec![
            metric(
                Route::Notifications,
                tr("dashboard.notifications_label"),
                unread.to_string(),
                tr(if session {
                    "dashboard.notifications_delta_unread"
                } else {
                    "dashboard.notifications_delta_signin"
                }),
                "dashboard-unread-notifications",
            ),
            metric(
                Route::Directory,
                tr(projection_collection_label(has_realms, has_spaces)),
                nodes.len().to_string(),
                tr(if session {
                    projection_collection_browse_label(has_realms, has_spaces)
                } else {
                    projection_collection_signin_label(has_realms, has_spaces)
                }),
                "",
            ),
            metric(
                Route::Contacts,
                tr("nav.contacts"),
                contact_count,
                contact_delta,
                "dashboard-contacts-card",
            ),
        ];
        if let Some(active) = active {
            metrics.push(metric(
                Route::KanbanRealm {
                    realm_id: active.id.clone(),
                },
                tr("dashboard.active_strands"),
                strands.len().to_string(),
                tr("dashboard.open_board_view"),
                "",
            ));
        } else {
            metrics.push(metric(
                Route::Setup,
                tr("dashboard.realm_setup"),
                tr(if session {
                    "dashboard.ready"
                } else {
                    "dashboard.sign_in"
                }),
                tr("dashboard.setup_help"),
                "",
            ));
            metrics.push(metric(
                Route::Onboarding,
                tr("dashboard.onboarding"),
                tr("dashboard.onboarding_steps"),
                tr("dashboard.onboarding_help"),
                "",
            ));
        }
        let mut realm_rows = vec![];
        for node in &nodes {
            let remark = if node.kind == RealmTreeNodeKind::Realm {
                ctx.state_store.read(|s| s.realm_remark(&node.id))
            } else {
                None
            };
            let name = remark
                .as_ref()
                .map(|r| r.display_name(&node.title).to_owned())
                .unwrap_or_else(|| node.title.clone());
            let mut children = vec![
                crate::components::identity_avatar(
                    scope,
                    ctx.clone(),
                    crate::components::IdentityAvatarProps {
                        seed: node.id.clone(),
                        alt_text: name.clone(),
                        blob_ref: None,
                        class: "avatar avatar-img".into(),
                        test_id: None,
                    },
                ),
                stack(
                    "grow",
                    vec![
                        paragraph("title", name),
                        paragraph(
                            "sub",
                            dashboard_realm_description(node.description.as_deref()),
                        ),
                    ],
                ),
            ];
            if remark.is_some_and(|r| !r.local_name.trim().is_empty()) {
                children.push(paragraph(
                    "pill muted xs dashboard-realm-tree-realm-remark-badge",
                    tr("dashboard.realm_remark"),
                ));
            }
            if let Some(status) = ctx
                .state_store
                .read(|s| s.realm_state_snapshot_sync_status(&node.id))
            {
                use crate::realm_state_snapshot::RealmStateSnapshotTrustState;
                let key = match status.trust_state {
                    RealmStateSnapshotTrustState::LowerTrust => {
                        Some("dashboard.snapshot_lower_trust")
                    }
                    RealmStateSnapshotTrustState::Degraded => Some("dashboard.snapshot_degraded"),
                    _ => None,
                };
                if let Some(key) = key {
                    children.push(paragraph(
                        "pill muted xs dashboard-realm-tree-snapshot-badge",
                        tr(key),
                    ));
                }
            }
            children.push(paragraph(
                "pill muted xs",
                tr(projection_kind_label(node.kind)),
            ));
            realm_rows.push(nav_view(
                ctx.clone(),
                Route::Realm {
                    realm_id: node.id.clone(),
                },
                "m-list-item dashboard-realm-tree-card",
                children,
            ));
        }
        if realm_rows.is_empty() {
            realm_rows.push(line(
                "m-list-item dashboard-realm-tree-empty",
                vec![
                    paragraph("avatar", "0"),
                    stack(
                        "grow",
                        vec![
                            paragraph(
                                "title",
                                tr(if session {
                                    projection_collection_empty_label(has_realms, has_spaces)
                                } else {
                                    projection_collection_signin_label(has_realms, has_spaces)
                                }),
                            ),
                            paragraph(
                                "sub",
                                tr(if session {
                                    projection_collection_empty_help_label(has_realms, has_spaces)
                                } else {
                                    "dashboard.no_session_help"
                                }),
                            ),
                        ],
                    ),
                ],
            ));
        }
        let realm_surface = stack(
            "surface realm-tree-summary",
            vec![
                line(
                    "row surface-head",
                    vec![
                        plain(tr(recent_projection_collection_label(
                            has_realms, has_spaces,
                        ))),
                        nav_view(
                            ctx.clone(),
                            Route::Directory,
                            "btn icon sm ghost ml-auto",
                            vec![crate::components::ui_icon("search")],
                        ),
                    ],
                ),
                stack("stack-sm dashboard-realm-list", realm_rows),
            ],
        );
        let strand_rows = strands
            .into_iter()
            .map(|strand| {
                vec![
                    empty(),
                    plain(strand.title),
                    plain(tr("dashboard.current_board")),
                    plain(tr(projection_object_state_label(&strand.state))),
                    plain(
                        strand
                            .fields
                            .get("due_at")
                            .or_else(|| strand.fields.get("due"))
                            .and_then(|value| value.as_str())
                            .unwrap_or("-")
                            .to_owned(),
                    ),
                ]
            })
            .collect::<Vec<_>>();
        let recent = stack(
            "surface recent-boards",
            vec![
                line(
                    "row surface-head",
                    vec![surface_title(tr("dashboard.recent_strands"))],
                ),
                recent_strands_table(
                    strand_rows,
                    tr(if session {
                        "dashboard.strands_empty"
                    } else {
                        "dashboard.strands_signin"
                    }),
                ),
            ],
        );
        let activity = stack(
            "surface pad activity-feed",
            vec![
                paragraph("section-title mb-8", tr("dashboard.recent_activity")),
                line(
                    "m-list-item",
                    vec![
                        paragraph("pill muted xs", tr("dashboard.activity_empty")),
                        stack(
                            "grow",
                            vec![
                                paragraph(
                                    "title",
                                    tr(if session {
                                        "dashboard.no_activity"
                                    } else {
                                        "dashboard.no_session_activity"
                                    }),
                                ),
                                paragraph(
                                    "sub",
                                    tr(if session {
                                        "dashboard.activity_sync_help"
                                    } else {
                                        "dashboard.activity_signin_help"
                                    }),
                                ),
                            ],
                        ),
                    ],
                ),
            ],
        );
        let mut notice_rows = notices
            .into_iter()
            .take(3)
            .map(|notice| -> View {
                let Some(identity) = notification_source_id(scope, &notice.id) else {
                    return empty();
                };
                let navigate = ctx.clone();
                Box::new(
                    crate::presentation::widgets::internal_link()
                        .class("m-list-item dashboard-notification-card")
                        .target(Route::Notifications.to_string())
                        .semantics(Some(Box::new(glory::render::Semantics {
                            described_by: Some(identity.clone()),
                            ..Default::default()
                        })))
                        .fill(vec![
                            Box::new(
                                glory::ui::view()
                                    .class("sr-only dashboard-notification-provenance")
                                    .semantics(Some(Box::new(glory::render::Semantics {
                                        id: Some(identity),
                                        ..Default::default()
                                    })))
                                    .fill((
                                        glory::ui::text()
                                            .class("dashboard-notification-source-id")
                                            .content(notice.id.clone()),
                                        glory::ui::text().content(" · "),
                                        glory::ui::text()
                                            .class("dashboard-notification-source-kind")
                                            .content(notice.kind.clone()),
                                    )),
                            ) as View,
                            paragraph("avatar xs", if notice.read { "✓" } else { "!" }),
                            stack(
                                "grow",
                                vec![
                                    paragraph(
                                        "title f-13 dashboard-notification-title",
                                        notice.render_title(),
                                    ),
                                    paragraph(
                                        "sub dashboard-notification-body",
                                        notice.render_body(),
                                    ),
                                ],
                            ),
                            paragraph(
                                "pill muted xs dashboard-notification-kind",
                                tr(notice.kind_label_key),
                            ),
                        ])
                        .on(glory::render::EventKind::Activate, move |_| {
                            navigate.navigate(Route::Notifications)
                        }),
                )
            })
            .collect::<Vec<_>>();
        if notice_rows.is_empty() {
            notice_rows.push(line(
                "m-list-item",
                vec![
                    paragraph("avatar xs", "0"),
                    stack(
                        "grow",
                        vec![
                            paragraph(
                                "title f-13",
                                tr(if session {
                                    "dashboard.no_notifications"
                                } else {
                                    "dashboard.notifications_signin"
                                }),
                            ),
                            paragraph("sub", tr("dashboard.notifications_empty_sub")),
                        ],
                    ),
                ],
            ));
        }
        let notice_surface = stack(
            "surface pinned-notifications",
            vec![
                line(
                    "row surface-head",
                    vec![
                        surface_title(tr("nav.notifications")),
                        notifications_open(scope, ctx.clone()),
                    ],
                ),
                stack("stack-sm dashboard-notification-list", notice_rows),
            ],
        );
        stack(
            "dashboard-live",
            vec![
                stack("metric-grid dashboard-metrics", metrics),
                stack(
                    "dashboard-two-col",
                    vec![
                        stack("stack", vec![realm_surface, recent, activity]),
                        stack(
                            "stack dashboard-right-column",
                            vec![
                                notice_surface,
                                dashboard_health(
                                    scope,
                                    ctx.clone(),
                                    protocol_health,
                                    health_loading,
                                ),
                            ],
                        ),
                    ],
                ),
            ],
        )
    });
    stack("timeline dashboard-panel", vec![panels])
}
fn dashboard_notification_summaries(
    snapshot: &ClientLocalState,
) -> Vec<DashboardNotificationSummary> {
    let mut notifications = snapshot
        .notification_projection
        .iter()
        .filter_map(|value| {
            let id = value.notification_id();
            let client_state = snapshot
                .notification_client_state
                .get(&id)
                .cloned()
                .unwrap_or_default();
            let archived = client_state.archived;
            if archived {
                return None;
            }
            let kind = crate::state::projection::notifications::notification_kind_wire(
                &value.notification_kind(),
            )
            .to_owned();
            // Keep presentation provenance until rendering. Locale changes must not
            // translate literal previews that happen to match dictionary keys.
            let title = notification_title(value, &kind);
            let title_is_key = notification_title_is_key(value);
            let body = notification_body(value);
            let body_translation = notification_body_translation(value);
            Some(DashboardNotificationSummary {
                id,
                title,
                title_is_key,
                body,
                body_translation,
                kind,
                kind_label_key: dashboard_notification_kind_key(&value.notification_kind()),
                timestamp: arkret_sdk::canonical::format_timestamp_canonical(value.created_at()),
                read: client_state.read,
            })
        })
        .collect::<Vec<_>>();
    notifications.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
    notifications
}

fn dashboard_recent_strands(
    raw_operations: &[crate::state::RawOperationRecord],
    realm_id: &str,
) -> Vec<crate::state::projection_views::StrandProjectionView> {
    if realm_id.trim().is_empty() {
        return Vec::new();
    }
    crate::views::kanban::strand_views_from_ops(raw_operations)
        .into_iter()
        .filter(|strand| strand.realm_id == realm_id)
        .collect()
}

fn dashboard_contacts_summary(contacts: &[crate::models::ContactView]) -> DashboardContactsSummary {
    let mut summary = DashboardContactsSummary::default();
    for contact in contacts {
        match contact.state {
            arkret_sdk::ContactState::Accepted => {
                summary.accepted += 1;
                if contact.direct_conversation.is_some()
                    || contact
                        .bidirectional_scopes
                        .contains(&ContactScope::DirectMessage)
                    || contact
                        .effective_scopes
                        .iter()
                        .flatten()
                        .any(|scope| *scope == ContactScope::DirectMessage)
                {
                    summary.direct_ready += 1;
                }
            }
            arkret_sdk::ContactState::PendingIncoming => summary.pending_incoming += 1,
            arkret_sdk::ContactState::PendingOutgoing => summary.pending_outgoing += 1,
            _ => {}
        }
    }
    summary
}

fn contact_summary_delta(summary: &DashboardContactsSummary) -> String {
    crate::i18n::tr_args(
        "dashboard.contacts_delta",
        &[
            ("pending", summary.pending().to_string()),
            ("direct", summary.direct_ready.to_string()),
        ],
    )
}

// Shared with the notifications model; this dashboard does not hydrate or
// apply the feed's separate delivery filters.
use crate::views::notifications::{
    notification_body, notification_body_translation, notification_title, notification_title_is_key,
};

// The projection label helpers below return i18n KEYS; render sites pass
// them through `tr()` (model helpers stay runtime-free so unit tests can
// assert the key table without a Dioxus runtime).

fn projection_kind_label(kind: RealmTreeNodeKind) -> &'static str {
    match kind {
        RealmTreeNodeKind::Realm => "dashboard.node_kind.realm",
        RealmTreeNodeKind::Space => "dashboard.node_kind.space",
    }
}

fn projection_collection_label(has_realms: bool, has_product_spaces: bool) -> &'static str {
    match (has_realms, has_product_spaces) {
        (true, true) => "dashboard.collection.realms_and_spaces",
        (false, true) => "dashboard.collection.spaces",
        _ => "dashboard.collection.realms",
    }
}

fn recent_projection_collection_label(has_realms: bool, has_product_spaces: bool) -> &'static str {
    match (has_realms, has_product_spaces) {
        (true, true) => "dashboard.collection.recent_realms_and_spaces",
        (false, true) => "dashboard.collection.recent_spaces",
        _ => "dashboard.collection.recent_realms",
    }
}

fn projection_collection_browse_label(has_realms: bool, has_product_spaces: bool) -> &'static str {
    match (has_realms, has_product_spaces) {
        (true, true) => "dashboard.collection.browse_realm_or_space",
        (false, true) => "dashboard.collection.browse_space",
        _ => "dashboard.collection.browse_realm",
    }
}

fn projection_collection_signin_label(has_realms: bool, has_product_spaces: bool) -> &'static str {
    match (has_realms, has_product_spaces) {
        (true, true) => "dashboard.collection.signin_realms_and_spaces",
        (false, true) => "dashboard.collection.signin_spaces",
        _ => "dashboard.collection.signin_realms",
    }
}

fn projection_collection_empty_label(has_realms: bool, has_product_spaces: bool) -> &'static str {
    match (has_realms, has_product_spaces) {
        (true, true) => "dashboard.collection.empty_realms_and_spaces",
        (false, true) => "dashboard.collection.empty_spaces",
        _ => "dashboard.collection.empty_realms",
    }
}

fn projection_collection_empty_help_label(
    has_realms: bool,
    has_product_spaces: bool,
) -> &'static str {
    match (has_realms, has_product_spaces) {
        (true, true) => "dashboard.collection.empty_help_realms_and_spaces",
        (false, true) => "dashboard.collection.empty_help_spaces",
        _ => "dashboard.collection.empty_help_realms",
    }
}

#[cfg(test)]
mod tests {
    use arkret_sdk::contact_operations::ContactScope;
    use serde_json::json;

    use super::{
        contact_summary_delta, dashboard_contacts_summary, dashboard_recent_strands,
        projection_collection_label, projection_kind_label, recent_projection_collection_label,
    };
    use crate::models::{ContactView, RealmTreeNodeKind};
    use crate::state::RawOperationRecord;

    #[test]
    fn empty_recent_strands_keeps_real_headers_and_spanning_message() {
        use glory::render::{DocumentPart, Props, TableMetadata};
        crate::i18n::with_test_locale(crate::i18n::UiLocale::En, || {
            let app = glory::App::memory();
            app.mount(super::recent_strands_table(
                vec![],
                "No loaded strands".into(),
            ))
            .unwrap();
            app.flush().unwrap();
            let tree = app.tree();
            let mut pending = tree.roots().to_vec();
            let mut headers = 0;
            let mut spans = Vec::new();
            let mut messages = Vec::new();
            while let Some(id) = pending.pop() {
                let node = tree.node(id).unwrap();
                pending.extend(node.children.iter().copied());
                if let Some(semantics) = node.descriptor.view().semantics.as_ref() {
                    if semantics.document_part == Some(DocumentPart::ColumnHeader) {
                        headers += 1;
                    }
                    if let Some(TableMetadata::Cell { column_span, .. }) = semantics.table.as_ref()
                        && *column_span > 1
                    {
                        spans.push(*column_span);
                    }
                }
                if let Props::Text(text) = node.descriptor.view().props
                    && text.content == "No loaded strands"
                {
                    messages.push(text.content.clone());
                }
            }
            assert_eq!(headers, 5);
            assert_eq!(spans, vec![5]);
            assert_eq!(messages, vec!["No loaded strands"]);
        });
    }

    #[test]
    fn projection_labels_follow_realm_space_kind() {
        // The helpers return i18n keys (translated at render via tr()).
        assert_eq!(
            projection_kind_label(RealmTreeNodeKind::Realm),
            "dashboard.node_kind.realm"
        );
        assert_eq!(
            projection_kind_label(RealmTreeNodeKind::Space),
            "dashboard.node_kind.space"
        );
        assert_eq!(
            projection_collection_label(true, false),
            "dashboard.collection.realms"
        );
        assert_eq!(
            recent_projection_collection_label(true, false),
            "dashboard.collection.recent_realms"
        );
        assert_eq!(
            recent_projection_collection_label(true, true),
            "dashboard.collection.recent_realms_and_spaces"
        );
    }

    #[test]
    fn contact_summary_counts_actionable_rows() {
        fn contact(peer: &str, state: arkret_sdk::ContactState, direct_ready: bool) -> ContactView {
            ContactView {
                peer: arkret_sdk::contact_operations::ContactPeer::Human {
                    account_id: arkret_sdk::AccountId::new(
                        crate::mls_api_helpers::principal_core_id(peer).unwrap(),
                        arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                    ),
                },
                state,
                request_event_ref: None,
                request_message: None,
                response_event_ref: None,
                tombstone_event_ref: None,
                next_prepare_input: (state == arkret_sdk::ContactState::Accepted).then(|| {
                    arkret_sdk::contact_operations::ContactNextPrepareInput {
                        contact_round_id: arkret_sdk::Hash::new(
                            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        )
                        .unwrap(),
                        version: 2,
                        predecessor_event_ref: arkret_sdk::EventId::new(
                            "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                        )
                        .unwrap(),
                    }
                }),
                granted_to_peer_scopes: Vec::new(),
                granted_by_peer_scopes: Vec::new(),
                bidirectional_scopes: Vec::new(),
                effective_scopes: Some(Vec::new()),
                direct_conversation: direct_ready.then(|| arkret_sdk::DirectConversationSummary {
                    realm_id: arkret_sdk::RealmId::new(
                        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
                    )
                    .unwrap(),
                    main_strand_id: arkret_sdk::StrandId::new(
                        "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1".to_owned(),
                    )
                    .unwrap(),
                    binding_event_ref: arkret_sdk::EventId::new(
                        "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                    )
                    .unwrap(),
                    state: arkret_sdk::DirectConversationSummaryState::Found,
                }),
                contact_agent_projections: Vec::new(),
                peer_endpoint: None,
            }
        }

        let rows = vec![
            {
                let mut row = contact(
                    "did:web:alice.example",
                    arkret_sdk::ContactState::Accepted,
                    false,
                );
                row.bidirectional_scopes = vec![ContactScope::DirectMessage];
                row
            },
            contact(
                "did:web:bob.example",
                arkret_sdk::ContactState::Accepted,
                true,
            ),
            contact(
                "did:web:casey.example",
                arkret_sdk::ContactState::PendingIncoming,
                false,
            ),
            contact(
                "did:web:drew.example",
                arkret_sdk::ContactState::Tombstoned,
                false,
            ),
        ];

        let summary = dashboard_contacts_summary(&rows);

        assert_eq!(summary.accepted, 2);
        assert_eq!(summary.pending(), 1);
        assert_eq!(summary.direct_ready, 2);
        assert_eq!(contact_summary_delta(&summary), "Pending 1 · Direct 2");
    }

    #[test]
    fn recent_strands_use_only_sync_backed_operations_for_active_realm() {
        // Sync-backed record shape: the ingest funnel keys the record by the
        // ACCEPTED Event id, and the Strand is `retype(event_id)` — a create
        // payload names no object id of its own.
        let operation = |event_id: &str, realm_id: &str| RawOperationRecord {
            operation_id: event_id.to_owned(),
            realm_id: Some(realm_id.to_owned()),
            received_at: chrono::DateTime::parse_from_rfc3339("2026-07-13T00:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            payload: json!({
                "kind": "ak.strand.create",
                "operation_id": event_id,
                "realm_id": realm_id,
                "write_state": "synced",
                "body": {
                    "object": {
                        "realm_id": realm_id,
                        "metadata": { "title": event_id }
                    }
                }
            }),
        };
        let realm_a = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let realm_b = "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
        let operations = vec![
            operation(
                "ak:event:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934",
                realm_a,
            ),
            operation(
                "ak:event:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu",
                realm_b,
            ),
        ];

        let strands = dashboard_recent_strands(&operations, realm_a);

        assert_eq!(strands.len(), 1);
        assert_eq!(strands[0].realm_id, realm_a);
    }

    #[test]
    fn dashboard_notification_previews_keep_literal_keys_and_defaults_follow_locale() {
        use super::dashboard_notification_summaries;
        use crate::state::projection::notifications::test_event_notification;
        use crate::state::{ClientLocalState, NotificationClientState};

        let realm = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
        let event = |ordinal, preview| {
            test_event_notification(
                ordinal,
                arkret_sdk::NotificationKind::Message,
                realm,
                None,
                preview,
            )
        };
        let defaults = event(901, json!({}));
        let literal = event(
            902,
            json!({
                "title": "notifications.default_title.message",
                "body": "Original {realm} {error} / 原文"
            }),
        );
        let literal_body_key = event(
            903,
            json!({"title": "Original {title}", "summary": "notifications.default_body"}),
        );
        let explicit_empty = event(904, json!({"title": "", "body": ""}));
        let archived = event(905, json!({"title": "Archived literal preview"}));
        let mut snapshot = ClientLocalState::default();
        snapshot.notification_client_state.insert(
            literal.notification_id(),
            NotificationClientState {
                read: true,
                archived: false,
            },
        );
        snapshot.notification_client_state.insert(
            archived.notification_id(),
            NotificationClientState {
                read: false,
                archived: true,
            },
        );
        snapshot.notification_projection = vec![
            defaults.clone(),
            literal.clone(),
            literal_body_key.clone(),
            explicit_empty.clone(),
            archived,
        ]
        .into();
        let rows = dashboard_notification_summaries(&snapshot);
        assert_eq!(
            rows.iter().map(|row| row.id.clone()).collect::<Vec<_>>(),
            vec![
                explicit_empty.notification_id(),
                literal_body_key.notification_id(),
                literal.notification_id(),
                defaults.notification_id(),
            ]
        );
        let by_id = |id: &str| rows.iter().find(|row| row.id == id).unwrap();
        assert!(by_id(&literal.notification_id()).read);
        let original_snapshot = snapshot.clone();
        for (language, title, body) in [
            (crate::i18n::UiLocale::En, "New message", "Notification"),
            (crate::i18n::UiLocale::Zh, "新消息", "通知"),
            (crate::i18n::UiLocale::En, "New message", "Notification"),
        ] {
            crate::i18n::with_test_locale(language, || {
                assert_eq!(by_id(&defaults.notification_id()).render_title(), title);
                assert_eq!(by_id(&defaults.notification_id()).render_body(), body);
                assert_eq!(
                    by_id(&literal.notification_id()).render_title(),
                    "notifications.default_title.message"
                );
                assert_eq!(
                    by_id(&literal.notification_id()).render_body(),
                    "Original {realm} {error} / 原文"
                );
                assert_eq!(
                    by_id(&literal_body_key.notification_id()).render_title(),
                    "Original {title}"
                );
                assert_eq!(
                    by_id(&literal_body_key.notification_id()).render_body(),
                    "notifications.default_body"
                );
                assert_eq!(by_id(&explicit_empty.notification_id()).render_title(), "");
                assert_eq!(by_id(&explicit_empty.notification_id()).render_body(), "");
                assert_eq!(dashboard_notification_summaries(&snapshot), rows);
                assert_eq!(
                    snapshot.notification_projection,
                    original_snapshot.notification_projection
                );
                assert_eq!(
                    snapshot.notification_client_state,
                    original_snapshot.notification_client_state
                );
            });
        }
    }

    #[test]
    fn dashboard_invite_and_runtime_approval_copy_retranslates_retained_summaries() {
        use super::dashboard_notification_summaries;
        use crate::state::projection::notifications::{
            raw_notifications_from_sources, test_invite,
        };
        use crate::state::{ClientLocalState, StoredInviteNotification, StoredNotification};

        let realm = "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
        let invite = test_invite(1, realm);
        let delta = arkret_sdk::sync::NotificationDelta::try_new(
            arkret_sdk::NotificationIdentity::AgentApproval(
                arkret_sdk::NotificationId::new(
                    "ak:notification:01964137-0000-7000-8000-000000000004",
                )
                .unwrap(),
            ),
            arkret_sdk::sync::NotificationDeltaAction::Upsert,
            Some(arkret_sdk::sync::NotificationData::AgentRuntimeApproval(
                arkret_sdk::sync::AgentRuntimeApprovalNotificationData {
                    approval_request_id: arkret_sdk::sync::AgentRuntimeApprovalRequestId::new(
                        "agent_runtime_approval:01964137-0000-7000-8000-000000000005",
                    )
                    .unwrap(),
                    agent_id: crate::mls_api_helpers::principal_core_id("did:web:agent.example")
                        .unwrap(),
                    requested_at: chrono::DateTime::parse_from_rfc3339("2026-05-29T00:00:00.000Z")
                        .unwrap()
                        .with_timezone(&chrono::Utc),
                    expires_at: chrono::DateTime::parse_from_rfc3339("2026-05-29T00:10:00.000Z")
                        .unwrap()
                        .with_timezone(&chrono::Utc),
                },
            )),
        )
        .unwrap();
        let mut snapshot = ClientLocalState {
            notification_projection: raw_notifications_from_sources(Some(&[delta]), &[]).into(),
            ..Default::default()
        };
        snapshot
            .notification_projection
            .push(StoredNotification::Invite {
                invite: StoredInviteNotification {
                    invite_id: invite.id,
                    realm_id: invite.realm_id,
                    created_at: invite.created_at,
                },
            });
        let rows = dashboard_notification_summaries(&snapshot);
        assert_eq!(rows.len(), 2);
        let invitation = rows.iter().find(|row| row.kind == "invite").unwrap();
        let approval = rows
            .iter()
            .find(|row| row.id.starts_with("ak:notification:"))
            .unwrap();
        let short_realm = crate::views::helpers::short_protocol_id(realm);
        for (language, invite_title, approval_title, approval_body) in [
            (
                crate::i18n::UiLocale::En,
                "Realm invite",
                "Agent runtime approval",
                "Review the pending Agent runtime key request.",
            ),
            (
                crate::i18n::UiLocale::Zh,
                "Realm 邀请",
                "Agent 运行授权审批",
                "审查待处理的 Agent 运行密钥请求。",
            ),
            (
                crate::i18n::UiLocale::En,
                "Realm invite",
                "Agent runtime approval",
                "Review the pending Agent runtime key request.",
            ),
        ] {
            crate::i18n::with_test_locale(language, || {
                assert_eq!(invitation.render_title(), invite_title);
                let invite_body = match language {
                    crate::i18n::UiLocale::En => format!("You were invited to join {short_realm}."),
                    crate::i18n::UiLocale::Zh => format!("你收到了加入 {short_realm} 的邀请。"),
                };
                assert_eq!(invitation.render_body(), invite_body);
                assert_eq!(approval.render_title(), approval_title);
                assert_eq!(approval.render_body(), approval_body);
                assert_eq!(dashboard_notification_summaries(&snapshot), rows);
            });
        }
    }
}

#[cfg(test)]
mod locale_regression_tests {

    use super::*;
    use crate::i18n::UiLocale;
    use crate::transport::auth::ApiCallError;

    fn feedback_values(checks: &[DashboardHealthCheck]) -> Vec<String> {
        let contacts = DashboardContactsSummary {
            accepted: 2,
            pending_incoming: 1,
            pending_outgoing: 2,
            direct_ready: 2,
        };
        let contact_status = [
            "dashboard.contacts_loading",
            "dashboard.contacts_unavailable",
        ];
        let mut values = vec![
            contact_summary_delta(&contacts),
            dashboard_realm_description(None),
            dashboard_realm_description(Some("dashboard.open_board")),
            dashboard_realm_description(Some("Original {error} {version} / 原文")),
            dashboard_realm_description(Some("")),
            tr(dashboard_notification_kind_key(
                &arkret_sdk::NotificationKind::Message,
            )),
        ];
        values.extend(contact_status.iter().map(|key| tr(key)));
        for state in [
            arkret_sdk::ObjectState::Active,
            arkret_sdk::ObjectState::Archived,
            arkret_sdk::ObjectState::Redacted,
        ] {
            values.push(tr(projection_object_state_label(&state)));
        }
        for check in checks.iter() {
            values.push(tr(check.name_key));
            values.push(check.value.render());
        }
        values
    }
    #[test]
    fn cached_dashboard_health_and_contact_status_rerender_without_replacing_results() {
        let problem: arkret_sdk::Problem = serde_json::from_value(serde_json::json!({
            "type": "https://arkret.org/problems/internal_error", "title": "Internal error",
            "status": 500, "detail": "private server detail / 原文", "code": "internal_error"
        }))
        .unwrap();
        let checks = vec![
            DashboardHealthCheck::new(
                "dashboard.health.describe",
                DashboardHealthValue::Service {
                    service: arkret_sdk::ServiceKind::Station,
                    version: arkret_sdk::ServiceProtocolVersion::V1,
                },
            ),
            DashboardHealthCheck::new("dashboard.health.sync", DashboardHealthValue::Profiles(9)),
            DashboardHealthCheck::new(
                "dashboard.health.identity",
                DashboardHealthValue::EndpointError(
                    "Original {error} {count} / dashboard.health.error / 原文".to_owned(),
                ),
            ),
            DashboardHealthCheck::new(
                "dashboard.health.api",
                DashboardHealthValue::ApiError(Rc::new(ApiCallError::Failed(
                    crate::api_error::TransportClientError {
                        status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                        error: problem,
                    }
                    .into(),
                ))),
            ),
            DashboardHealthCheck::new(
                "dashboard.health.api",
                DashboardHealthValue::ApiError(Rc::new(ApiCallError::Unavailable(
                    anyhow::anyhow!("private unavailable diagnostic"),
                ))),
            ),
            DashboardHealthCheck::new(
                "dashboard.health.api",
                DashboardHealthValue::ApiError(Rc::new(ApiCallError::AuthExpired(
                    anyhow::anyhow!("private session diagnostic"),
                ))),
            ),
            DashboardHealthCheck::new(
                "dashboard.health.api",
                DashboardHealthValue::ApiError(Rc::new(ApiCallError::Failed(anyhow::anyhow!(
                    "{}",
                    "Local {error} / 原文"
                )))),
            ),
        ];
        let expected = |language: UiLocale| {
            let mut values = if language == UiLocale::Zh {
                vec![
                    "待处理 3 · 私聊 2",
                    "打开看板",
                    "消息",
                    "正在加载联系人",
                    "联系人暂不可用",
                    "活跃",
                    "已归档",
                    "已删改",
                    "服务说明",
                    "同步",
                    "9 个配置档",
                    "身份",
                    "错误：Original {error} {count} / dashboard.health.error / 原文",
                    "错误：与服务器通信时出现问题。请重试。",
                    "错误：服务器当前不可用。请检查服务器地址,或稍等片刻后重试。",
                    "错误：登录已过期。请重新登录以继续。",
                    "错误：Local {error} / 原文",
                ]
            } else {
                vec![
                    "Pending 3 · Direct 2",
                    "Open Board",
                    "message",
                    "Loading contacts",
                    "Contacts unavailable",
                    "active",
                    "archived",
                    "redacted",
                    "Describe",
                    "Sync",
                    "9 profiles",
                    "Identity",
                    "Error: Original {error} {count} / dashboard.health.error / 原文",
                    "Error: Something went wrong while talking to the server. Try again.",
                    "Error: The server is unavailable right now. Check the server address, or wait a moment and try again.",
                    "Error: Your session has expired. Sign in again to continue.",
                    "Error: Local {error} / 原文",
                ]
            };
            values.extend([
                "dashboard.open_board",
                "Original {error} {version} / 原文",
                "",
                "station v1.0",
                "API",
                "API",
                "API",
                "API",
            ]);
            let mut values = values
                .into_iter()
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            values.sort();
            values
        };
        for language in [UiLocale::En, UiLocale::Zh, UiLocale::En] {
            crate::i18n::with_test_locale(language, || {
                let mut values = feedback_values(&checks);
                values.sort();
                assert_eq!(values, expected(language));
                assert!(values.iter().all(|value| !value.contains("private")));
            });
        }
    }
}
