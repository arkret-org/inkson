//! Agent settings panel.
//!
//! This view is deliberately limited to settings backed by live server
//! calls: the agent directory row, runtime pairing/key state, lifecycle,
//! capability grants, and lifecycle controls. Per-Realm participation is
//! configured from that Realm's Members area.

use std::rc::Rc;
use std::time::Duration;

use arkret_models_collaboration::agent_operations::{
    AgentDeactivateRequestBody, AgentLifecycleState, AgentPauseRequestBody,
    AgentRenewPairingResponseBody, AgentResumeRequestBody, AgentRuntimeState, AgentView, KeyState,
};
use arkret_models_collaboration::events_payloads::agent::AgentKeyScope;
use glory::{Cage, Scope};

use super::model::{
    AgentGrantPreset, AgentServiceScopePreset, agent_lifecycle_wire, agent_runtime_state_wire,
    agent_view_from_directory_row, build_agent_pairing_deep_link,
    build_agent_pairing_handoff_token, is_pairing_request_expired, key_state_runtime_state,
    render_agent_pairing_qr_svg, requested_scope_for_presets,
};
use crate::presentation::{InksonContext, SharedStateStore, View};
use crate::routes::Route;
use crate::transport::auth::{with_authed_sdk_client, with_event_submitter};
use crate::views::helpers::short_protocol_id;
use crate::views::settings::widgets::*;

mod controller;
mod model;

use controller::*;
use model::*;

#[derive(Clone)]
struct AgentPage {
    context: Rc<InksonContext>,
    controller: AgentAdminController,
    slug: Cage<String>,
    presets: Cage<Vec<AgentGrantPreset>>,
    services: Cage<Vec<AgentServiceScopePreset>>,
    replace_open: Cage<bool>,
}
impl AgentPage {
    fn begin_creation(&self) {
        self.context.workspace_navigation.open_detail();
        if self.controller.create_mode.get_untracked()
            || self.controller.provision_in_flight.get_untracked()
        {
            return;
        }
        self.presets
            .revise(|value| *value = vec![AgentGrantPreset::Read, AgentGrantPreset::ReplyAsAgent]);
        self.services
            .revise(|value| *value = AgentServiceScopePreset::DEFAULTS.to_vec());
        self.slug.revise(String::clear);
        self.controller
            .new_agent_avatar_blob_ref
            .revise(String::clear);
        self.controller.last_op_status.revise(String::clear);
        self.controller
            .provision_operation_id
            .revise(|value| *value = None);
        self.controller.create_mode.revise(|value| *value = true);
    }
}
pub fn page(scope: &Scope, context: Rc<InksonContext>, route: Route) -> View {
    page_with_header(scope, context, route, Rc::new(|_| empty()))
}

pub(crate) fn page_with_header(
    scope: &Scope,
    context: Rc<InksonContext>,
    route: Route,
    header: crate::presentation::widgets::WorkspaceHeader,
) -> View {
    let filter = match route {
        Route::SettingsSection { section, filter } if section == "agents" => {
            normalize_agent_filter(&filter).to_owned()
        }
        _ => "all".into(),
    };
    let filter = scope.cage(filter);
    let filter_context = context.clone();
    scope.effect(move || {
        if let Route::SettingsSection {
            section,
            filter: query,
        } = filter_context.route.get()
            && section == "agents"
        {
            let next = normalize_agent_filter(&query);
            if filter.get_untracked() != next {
                filter.revise(|value| *value = next.to_owned());
            }
        }
    });
    let controller = AgentAdminController {
        context: context.clone(),
        owner: scope.downgrade(),
        agents: scope.cage(Vec::new()),
        list_status: scope.cage(String::new()),
        list_phase: scope.cage(if context.token.get_untracked().is_empty() {
            AgentListPhase::SignInRequired
        } else {
            AgentListPhase::Loading
        }),
        last_op_status: scope.cage(String::new()),
        refresh_epoch: scope.cage(0),
        detail_refresh_epoch: scope.cage(0),
        selected_agent_id: scope.cage(String::new()),
        create_mode: scope.cage(false),
        new_agent_avatar_blob_ref: scope.cage(String::new()),
        provision_in_flight: scope.cage(false),
        provision_operation_id: scope.cage(None),
        deactivate_dialog_open: scope.cage(false),
        deactivate_confirm: scope.cage(String::new()),
        pairing_action_agent_id: scope.cage(String::new()),
        pairing_action_phase: scope.cage(PairingActionPhase::default()),
        owned_agents_rev: context.owned_agents_rev,
        state_store: context.state_store.clone(),
    };
    let state = AgentPage {
        context: context.clone(),
        controller: controller.clone(),
        slug: scope.cage(String::new()),
        presets: scope.cage(vec![AgentGrantPreset::Read, AgentGrantPreset::ReplyAsAgent]),
        services: scope.cage(AgentServiceScopePreset::DEFAULTS.to_vec()),
        replace_open: scope.cage(false),
    };
    let refresh = controller.clone();
    let refresh_context = context.clone();
    let previous = Rc::new(std::cell::RefCell::new(None));
    scope.effect(move || {
        let _ = refresh_context.state_revision.get();
        let mut approvals = refresh_context.state_store.read(|store| {
            store
                .notification_projection()
                .into_iter()
                .filter_map(|value| {
                    let (id, data) = value.agent_runtime_approval()?;
                    Some(format!("{}:{}", id.as_str(), data.id))
                })
                .collect::<Vec<_>>()
        });
        approvals.sort();
        let key = (
            refresh_context.token.get(),
            refresh_context.session_generation.get(),
            refresh_context.owned_agents_rev.get(),
            approvals,
        );
        if previous.borrow().as_ref() == Some(&key) {
            return;
        }
        *previous.borrow_mut() = Some(key.clone());
        if !key.0.trim().is_empty() {
            refresh
                .clone()
                .refresh_agents(refresh_context.base_url.get(), key.0);
        }
    });
    let query = scope.cage(String::new());
    let search = scope.bond(move || query.get().trim().to_lowercase());
    mount_agent_selection(
        scope,
        controller.agents,
        controller.selected_agent_id,
        filter,
        search,
    );
    let details = controller.clone();
    let replace_open = state.replace_open;
    let deactivate_open = controller.deactivate_dialog_open;
    let deactivate_confirm = controller.deactivate_confirm;
    let selected_id = controller.selected_agent_id;
    let creation_mode = controller.create_mode;
    scope.effect(move || {
        let _ = (selected_id.get(), creation_mode.get());
        replace_open.revise(|value| *value = false);
        deactivate_open.revise(|value| *value = false);
        deactivate_confirm.revise(String::clear);
    });
    let detail_context = context.clone();
    scope.effect(move || {
        let _ = detail_context.owned_agents_rev.get();
        let id = details.selected_agent_id.get();
        if !id.is_empty() {
            details.clone().load_agent_details(
                detail_context.base_url.get(),
                detail_context.token.get(),
                id,
            );
        }
    });
    let resume = controller.clone();
    let resume_context = context.clone();
    scope.effect(move || {
        let _ = resume_context.owned_agents_rev.get();
        if resume.provision_operation_id.get().is_some()
            && !resume.provision_in_flight.get()
            && resume.create_mode.get()
        {
            resume.clone().reconcile_completed_provision(
                resume_context.base_url.get(),
                resume_context.token.get(),
            );
        }
    });
    let agents = controller.agents;
    let selected = controller.selected_agent_id;
    let create = controller.create_mode;
    let list_phase = controller.list_phase;
    let list_header = {
        let context = context.clone();
        let refresh = state.controller.clone();
        let refresh_context = context.clone();
        let begin = state.clone();
        crate::presentation::widgets::navigation_heading(
            scope,
            context.clone(),
            "agents-navigation-search",
            heading(
                2,
                "workspace-list-title",
                context.translated(scope, "settings.section.agents"),
            ),
            "agents.search",
            query,
            vec![
                agent_icon_action(
                    scope,
                    context.clone(),
                    "agent-admin-refresh-button",
                    "agents.refresh",
                    "refresh",
                    scope.bond(move || {
                        !matches!(
                            list_phase.get(),
                            AgentListPhase::Loading | AgentListPhase::SignInRequired
                        )
                    }),
                    move || {
                        refresh.clone().refresh_agents(
                            refresh_context.base_url.get(),
                            refresh_context.token.get(),
                        )
                    },
                ),
                agent_icon_action(
                    scope,
                    context.clone(),
                    "agent-admin-create-open-button",
                    "agents.create",
                    "plus",
                    scope.bond(move || {
                        list_phase.get() != AgentListPhase::SignInRequired
                            && !controller.provision_in_flight.get()
                    }),
                    move || begin.begin_creation(),
                ),
            ],
        )
    };
    let filter_context = context.clone();
    let filters = Box::new(
        sapid::segmented_control("agent-list-filter")
            .theme(context.theme_tokens())
            .size(sapid::Size::Small)
            .name(context.translated(scope, "agents.lifecycle"))
            .class("agent-admin-filter-bar")
            .with_item_borders(false)
            .value(scope.bond(move || {
                let value = filter.get();
                // The audit route is deliberately absent from the normal filter choices.
                if value == "deactivated" {
                    String::new()
                } else {
                    value
                }
            }))
            .segments(AGENT_LIST_FILTERS.into_iter().map(|(value, label)| {
                sapid::segment(value)
                    .class(format!("agent-admin-filter-{value}"))
                    .label(context.translated(scope, label))
            }))
            .on_value_change(move |value| {
                if filter.get_untracked() != value {
                    filter_context.navigate(Route::SettingsSection {
                        section: "agents".into(),
                        filter: value,
                    });
                }
            }),
    ) as View;
    let list_state = state.clone();
    let list_rows = reactive(
        scope.bond(move || {
            (
                agents.get(),
                selected.get(),
                create.get(),
                filter.get(),
                search.get(),
            )
        }),
        move |scope, (rows, selected_id, is_create, current_filter, search)| {
            let state = list_state.clone();
            let context = state.context.clone();
            let mut agent_rows = Vec::new();
            for agent in rows
                .iter()
                .filter(|agent| agent_visible(agent, &current_filter, &search))
            {
                let id = agent_id(agent);
                let target = id.clone();
                let navigation = context.workspace_navigation.clone();
                let choose = state.controller.selected_agent_id;
                let create = state.controller.create_mode;
                let slug = agent_slug_label(agent);
                let lifecycle = agent_lifecycle_wire(agent.agent.lifecycle);
                let runtime = agent_runtime_state_wire(
                    super::model::agent_projection_runtime_state(&agent.agent),
                );
                let selected = !is_create && id == selected_id;
                let avatar = crate::components::generated_avatar::identity_avatar_inline(
                    scope,
                    context.clone(),
                    crate::components::IdentityAvatarProps {
                        seed: id.clone(),
                        alt_text: slug.clone(),
                        blob_ref: agent
                            .agent
                            .avatar_blob_ref
                            .as_ref()
                            .map(ToString::to_string),
                        class: "avatar-img agent-admin-row-avatar".into(),
                        test_id: Some("agent-admin-avatar".into()),
                    },
                );
                agent_rows.push(Box::new(
                    sapid::button()
                        .unstyled()
                        .class(if selected {
                            "agent-admin-list-row agent-admin-row active"
                        } else {
                            "agent-admin-list-row agent-admin-row"
                        })
                        .name(slug.clone())
                        .pressed(selected)
                        .enabled(scope.bond(move || !state.controller.provision_in_flight.get()))
                        .fill(
                            glory::ui::group().fill((
                                avatar,
                                glory::ui::text()
                                    .class("agent-admin-row-title")
                                    .content(slug),
                                glory::ui::text()
                                    .class(super::model::agent_state_badge_class(lifecycle))
                                    .content(context.translated(scope, agent_state_key(lifecycle))),
                                glory::ui::text()
                                    .class(super::model::agent_state_badge_class(runtime))
                                    .content(context.translated(scope, agent_state_key(runtime))),
                                glory::ui::text()
                                    .class("sr-only agent-actor-identity")
                                    .content(
                                        crate::mls_api_helpers::local_account_actor_id(&id)
                                            .map(|actor| actor.to_string())
                                            .unwrap_or_else(|_| id.clone()),
                                    ),
                            )),
                        )
                        .on_press(move || {
                            create.revise(|value| *value = false);
                            choose.revise(|value| *value = target.clone());
                            navigation.open_detail();
                        }),
                ) as View);
            }
            stack("agent-admin-list-rows", agent_rows)
        },
    );
    let navigation = context.workspace_navigation.clone();
    let placeholder = scope.bond(move || {
        let in_detail = navigation.pane_visible(true);
        if in_detail && create.get() {
            return None;
        }
        let rows = agents.get();
        agent_empty_state(&rows, &filter.get(), &search.get(), list_phase.get())
            .map(|state| (in_detail, state))
    });
    let empty_pane = |in_detail| {
        let state = state.clone();
        crate::presentation::widgets::reactive_distinct(placeholder, move |scope, placement| {
            match placement {
                Some((target, kind)) if target == in_detail => {
                    agent_placeholder(scope, &state, kind, query)
                }
                _ => empty(),
            }
        })
    };
    let list_status = controller.list_status;
    let feedback = scope.bond(move || {
        if list_phase.get() == AgentListPhase::Failed && agents.get().is_empty() {
            String::new()
        } else {
            list_status.get()
        }
    });
    let detail_state = state.clone();
    let detail = reactive(
        agent_detail_source(scope, agents, selected, create, filter),
        move |scope, (rows, id, create, current_filter)| {
            let state = detail_state.clone();
            if create {
                return creation(scope, &state);
            }
            if id.is_empty() {
                return empty();
            }
            let now = crate::clock::now_timestamp();
            let view = build_agent_admin_view(&rows, &id, &current_filter, &now);
            details_view(scope, &state, view, id)
        },
    );
    stack(
        "agent-admin-page agent-admin",
        vec![line(
            "agent-admin-layout",
            vec![
                crate::presentation::widgets::workspace_pane(
                    scope,
                    &context,
                    false,
                    stack(
                        "agent-admin-list-pane agent-admin-list",
                        vec![
                            list_header,
                            filters,
                            stack(
                                "agent-admin-list-content",
                                vec![status(feedback), empty_pane(false), list_rows],
                            ),
                        ],
                    ),
                ),
                crate::presentation::widgets::workspace_detail(
                    scope,
                    &context,
                    &header,
                    "agent-admin-detail-content",
                    stack(
                        "agent-admin-detail-stack",
                        vec![status(controller.last_op_status), empty_pane(true), detail],
                    ),
                ),
            ],
        )],
    )
}
fn agent_placeholder(
    scope: &Scope,
    state: &AgentPage,
    kind: AgentEmptyState,
    query: Cage<String>,
) -> View {
    let context = state.context.clone();
    let (message, icon) = match kind {
        AgentEmptyState::Loading => ("agents.empty.loading", "refresh"),
        AgentEmptyState::Failed => ("agents.empty.failed", "alert"),
        AgentEmptyState::SignIn => ("agents.empty.sign_in", "user"),
        AgentEmptyState::Filtered => ("agents.empty.filtered", "search"),
        AgentEmptyState::FirstUse => ("agents.empty.none", "bot"),
    };
    let placeholder = sapid::empty_state()
        .unstyled()
        .class("agent-placeholder")
        .heading_level(3)
        .title(context.translated(scope, message))
        .illustration(crate::components::icons::ui_icon_with_class(
            icon,
            "agent-placeholder-icon",
        ));
    let state = state.clone();
    let placeholder = match kind {
        AgentEmptyState::FirstUse => placeholder.actions(action(
            scope,
            context.clone(),
            "agent-empty-create",
            "agents.create",
            "primary",
            true,
            move || state.begin_creation(),
        )),
        AgentEmptyState::Filtered => placeholder.actions(action(
            scope,
            context.clone(),
            "agent-empty-clear",
            "agents.clear_filters",
            "secondary",
            true,
            move || {
                query.revise(String::clear);
                context.navigate(Route::SettingsSection {
                    section: "agents".into(),
                    filter: "all".into(),
                });
            },
        )),
        AgentEmptyState::Failed => placeholder.actions(action(
            scope,
            context.clone(),
            "agent-empty-retry",
            "common.retry",
            "secondary",
            true,
            move || {
                state
                    .controller
                    .clone()
                    .refresh_agents(context.base_url.get(), context.token.get())
            },
        )),
        AgentEmptyState::SignIn => placeholder.actions(action(
            scope,
            context.clone(),
            "agent-empty-signin",
            "login.title",
            "secondary",
            true,
            move || context.navigate(Route::Login),
        )),
        AgentEmptyState::Loading => placeholder,
    };
    Box::new(
        glory::ui::view()
            .role(glory::render::Role::Status)
            .class("agent-list-state")
            .fill(placeholder),
    )
}

fn agent_state_key(state: &str) -> &str {
    match state {
        "pending" | "pending_runtime_key" => "realm_admin.roster.agent_awaiting",
        "ready" => "realm_admin.roster.agent_ready",
        "replacing" => "realm_admin.roster.agent_replacing",
        "active" => "realm_admin.roster.agent_active",
        "pairing_expired" => "realm_admin.roster.agent_expired",
        "paused" => "realm_admin.roster.agent_paused",
        "deactivated" => "realm_admin.roster.agent_deactivated",
        other => other,
    }
}

fn agent_detail_source(
    scope: &Scope,
    agents: Cage<Vec<AgentView>>,
    selected: Cage<String>,
    create: Cage<bool>,
    filter: Cage<String>,
) -> glory::Bond<(Vec<AgentView>, String, bool, String)> {
    scope.bond(move || {
        if create.get() {
            return (Vec::new(), String::new(), true, String::new());
        }
        (agents.get(), selected.get(), false, filter.get())
    })
}

fn creation(scope: &Scope, state: &AgentPage) -> View {
    let context = state.context.clone();
    let busy = state.controller.provision_in_flight;
    let enabled = scope.bond(move || !busy.get());
    let presets = state.presets;
    let services = state.services;
    let slug = state.slug;
    let valid_slug =
        scope.bond(move || arkret_models_identity::validate_agent_slug(&slug.get()).is_ok());
    let avatar = state.controller.new_agent_avatar_blob_ref;
    let preview_seed = scope.bond(move || {
        let slug = slug.get();
        if slug.trim().is_empty() {
            "New agent".to_owned()
        } else {
            slug.trim().to_owned()
        }
    });
    let avatar_context = context.clone();
    let avatar_picker = reactive(avatar, move |scope, current| {
        crate::components::avatar_uploader::avatar_uploader_with_seed(
            scope,
            avatar_context.clone(),
            crate::components::AvatarUploaderProps {
                current_blob_ref: current,
                alt_text: "Agent avatar".into(),
                api_token: avatar_context.token.get(),
                upload_realm_id: None,
                test_id_prefix: "agent-admin-avatar".into(),
                on_uploaded: Rc::new(move |next| avatar.revise(|value| *value = next)),
                on_clear: Rc::new(move |()| avatar.revise(|value| value.clear())),
            },
            preview_seed.into(),
        )
    });
    let mut content = Vec::new();
    for preset in AgentGrantPreset::ALL {
        let checked = scope.bond(move || presets.get().contains(&preset));
        content.push(capability_row(
            format!("agent-create-content-{}", preset.preset_name()),
            preset.label(),
            preset.help(),
            checked,
            enabled,
            Some(Rc::new(move |checked| {
                presets.revise(|values| {
                    values.retain(|value| *value != preset);
                    if checked {
                        values.push(preset);
                    }
                })
            })),
        ));
    }
    let mut service = Vec::new();
    for preset in AgentServiceScopePreset::ALL {
        let checked = scope.bond(move || services.get().contains(&preset));
        service.push(capability_row(
            format!("agent-create-service-{}", preset.preset_name()),
            preset.label(),
            preset.help(),
            checked,
            enabled,
            Some(Rc::new(move |checked| {
                services.revise(|values| {
                    values.retain(|value| *value != preset);
                    if checked {
                        values.push(preset);
                    }
                })
            })),
        ));
    }
    let principal = context.principal_id;
    let provision = state.clone();
    let cancel = state.controller.clone();
    stack(
        "event agent-admin-detail-pane",
        vec![
            line(
                "event-head",
                vec![heading(
                    2,
                    "entity-title",
                    context.translated(scope, "agents.create"),
                )],
            ),
            field(
                scope,
                context.clone(),
                "agent-admin-provision-agent-slug",
                "agents.slug",
                slug,
                enabled,
                false,
                move |next| slug.revise(|value| *value = normalize_agent_slug(&next)),
            ),
            reactive(
                scope.bond(move || !slug.get().is_empty() && !valid_slug.get()),
                {
                    let context = context.clone();
                    move |scope, invalid| {
                        if invalid {
                            paragraph(
                                "agent-admin-field-hint",
                                context.translated(scope, "agents.slug_help"),
                            )
                        } else {
                            empty()
                        }
                    }
                },
            ),
            avatar_picker,
            heading(
                3,
                "agent-admin-section-head",
                context.translated(scope, "agents.content_capabilities"),
            ),
            stack("agent-admin-preset-list", content),
            heading(
                3,
                "agent-admin-section-head",
                context.translated(scope, "agents.runtime_services"),
            ),
            stack("agent-admin-preset-list", service),
            reactive(services, {
                let context = context.clone();
                move |scope, selected| {
                    if selected.is_empty() {
                        paragraph(
                            "agent-admin-field-hint",
                            context.translated(scope, "agents.services_required"),
                        )
                    } else {
                        empty()
                    }
                }
            }),
            line(
                "actions",
                vec![
                    action(
                        scope,
                        context.clone(),
                        "agent-admin-provision-button",
                        "agents.create",
                        "primary",
                        scope.bond(move || {
                            !busy.get()
                                && principal.get().is_some()
                                && valid_slug.get()
                                && !services.get().is_empty()
                        }),
                        move || {
                            let Some(principal) = provision.context.principal_id.get() else {
                                return;
                            };
                            provision.controller.clone().provision_agent(
                                provision.context.base_url.get(),
                                provision.context.token.get(),
                                ProvisionAgentRequest {
                                    controller_principal_id: principal,
                                    slug: slug.get(),
                                    avatar_blob_ref: avatar.get(),
                                    content_presets: presets.get(),
                                    service_scopes: services.get(),
                                },
                            );
                        },
                    ),
                    action(
                        scope,
                        context.clone(),
                        "agent-admin-create-cancel-button",
                        "common.cancel",
                        "secondary",
                        enabled,
                        move || {
                            cancel
                                .new_agent_avatar_blob_ref
                                .revise(|value| value.clear());
                            cancel.provision_operation_id.revise(|value| *value = None);
                            cancel.create_mode.revise(|value| *value = false);
                            cancel.context.workspace_navigation.show_list();
                        },
                    ),
                ],
            ),
        ],
    )
}

fn details_view(scope: &Scope, state: &AgentPage, view: AgentAdminView, id: String) -> View {
    let context = state.context.clone();
    let mut children = vec![
        stack(
            "agent-admin-detail-head",
            vec![stack(
                "agent-admin-detail-identity",
                vec![
                    heading(
                        3,
                        "entity-title agent-admin-slug-title",
                        view.selected_title.clone(),
                    ),
                    paragraph("mono muted", id.clone()),
                ],
            )],
        ),
        line(
            "agent-admin-detail-meta",
            vec![
                stack(
                    "agent-admin-detail-meta-item",
                    vec![
                        paragraph("muted", context.translated(scope, "agents.created")),
                        plain(if view.selected_created_at.is_empty() {
                            "-".into()
                        } else {
                            view.selected_created_at.clone()
                        }),
                    ],
                ),
                stack(
                    "agent-admin-detail-meta-item",
                    vec![
                        paragraph(
                            "muted",
                            context.translated(scope, "dashboard.strand_updated"),
                        ),
                        plain(if view.selected_updated_at.is_empty() {
                            "-".into()
                        } else {
                            view.selected_updated_at.clone()
                        }),
                    ],
                ),
            ],
        ),
    ];
    children.push(permission_overview(scope, context.clone(), &view));
    if view.selected_should_show_pairing_card {
        let mut pairing = Vec::new();
        if view.selected_pairing_is_expired {
            pairing.push(paragraph(
                "agent-admin-status error",
                context.translated(scope, "agents.pairing_expired_help"),
            ));
        }
        if view.selected_has_pcr_binding && !view.selected_pairing_is_expired {
            let token = build_agent_pairing_handoff_token(
                &view.selected_pairing_request_id,
                &view.selected_pairing_code,
            );
            let url = build_agent_pairing_deep_link(&context.base_url.get(), &token);
            let qr = render_agent_pairing_qr_svg(&url);
            pairing.push(crate::components::qr_share_panel(
                scope,
                context.clone(),
                crate::components::QrSharePanelProps {
                    qr_svg: qr,
                    url,
                    qr_aria_label: "Agent runtime pairing QR code".into(),
                    url_aria_label: "Agent runtime pairing URL".into(),
                    qr_test_id: "agent-admin-pairing-qr".into(),
                    url_test_id: "agent-admin-pairing-url".into(),
                    copy_test_id: "agent-admin-copy-pairing-link-button".into(),
                    url_rows: 5,
                },
            ));
        }
        if view.selected_can_renew_pairing {
            let renew = state.clone();
            let target = id.clone();
            let slug = view.selected_slug.clone();
            let action_id = state.controller.pairing_action_agent_id;
            pairing.push(action(
                scope,
                context.clone(),
                "agent-admin-renew-pairing-button",
                "Pair again",
                "primary",
                scope.bond(move || action_id.get().is_empty()),
                move || {
                    if !action_id.get_untracked().is_empty() {
                        return;
                    }
                    action_id.revise(|value| *value = target.clone());
                    renew
                        .controller
                        .pairing_action_phase
                        .revise(|value| *value = PairingActionPhase::IssuingPairing);
                    renew.controller.clone().renew_pairing(
                        renew.context.base_url.get(),
                        renew.context.token.get(),
                        target.clone(),
                        slug.clone(),
                    );
                },
            ));
        }
        let pairing_class = if !view.selected_has_pcr_binding {
            "badge amber"
        } else if view.selected_pairing_is_expired {
            "badge red"
        } else {
            "badge amber"
        };
        let pairing_label = if !view.selected_has_pcr_binding {
            "agents.setup_incomplete"
        } else if view.selected_pairing_is_expired {
            "agents.expired"
        } else {
            agent_state_key(&view.selected_runtime_state)
        };
        pairing.insert(
            0,
            line(
                "agent-admin-section-head",
                vec![
                    paragraph(
                        "agent-admin-section-title",
                        if view.selected_is_replacement_pairing {
                            "Connect the replacement runtime"
                        } else {
                            "Connect an agent runtime"
                        },
                    ),
                    paragraph(
                        format!("{pairing_class} agent-runtime-state"),
                        context.translated(scope, pairing_label),
                    ),
                ],
            ),
        );
        children.push(stack(
            "agent-admin-section agent-admin-pairing-card",
            pairing,
        ));
    }
    let mut capabilities = Vec::new();
    for (preset, checked) in view.selected_content_capabilities {
        capabilities.push(capability_row(
            format!("agent-content-{}", preset.preset_name()),
            preset.label(),
            preset.help(),
            checked,
            false,
            None,
        ));
    }
    let mut services = Vec::new();
    for (preset, checked) in view.selected_service_capabilities {
        services.push(capability_row(
            format!("agent-service-{}", preset.preset_name()),
            preset.label(),
            preset.help(),
            checked,
            false,
            None,
        ));
    }
    let mut capability_section = vec![
        line(
            "agent-admin-section-head",
            vec![paragraph(
                "agent-admin-section-title",
                context.translated(scope, "agents.content_capabilities"),
            )],
        ),
        stack(
            "agent-admin-preset-list agent-admin-content-capability-list",
            capabilities,
        ),
        line(
            "agent-admin-section-head",
            vec![paragraph(
                "agent-admin-section-title",
                context.translated(scope, "agents.runtime_services"),
            )],
        ),
        stack(
            "agent-admin-preset-list agent-admin-service-capability-list",
            services,
        ),
    ];
    if view.selected_status == "deactivated" {
        capability_section.push(paragraph(
            "agent-admin-terminal-note agent-admin-deactivated-capabilities-note",
            "Historical grants have been revoked and are no longer usable.",
        ));
    }
    let mut exact = Some(stack(
        "agent-admin-section agent-admin-capabilities",
        capability_section,
    ));
    children.push(Box::new(
        sapid::collapsible(format!("agent-ceiling-{}", scope.id().slot()))
            .unstyled()
            .class("agent-admin-exact-permissions")
            .label(context.translated(scope, "permissions.exact"))
            .default_open(false)
            .content_policy(sapid::ContentPolicy::KeepMounted)
            .content(move || exact.take().unwrap_or_else(empty)),
    ));
    let terminal = view.selected_status == "deactivated";
    let enable = state.clone();
    let key = view.selected_key_state_owned.clone();
    let target = id.clone();
    let mut lifecycle = vec![line(
        "agent-admin-section-head",
        vec![paragraph(
            "agent-admin-section-title",
            context.translated(scope, "agents.lifecycle"),
        )],
    )];
    if !terminal {
        if matches!(view.selected_status.as_str(), "active" | "paused") {
            lifecycle.push(line(
                "agent-admin-lifecycle-toggle-row",
                vec![
                    line(
                        "agent-admin-lifecycle-summary",
                        vec![
                            paragraph(
                                "agent-admin-section-title",
                                context.translated(scope, "agents.enabled"),
                            ),
                            paragraph(
                                if view.selected_status == "active" {
                                    "badge green"
                                } else {
                                    "badge amber"
                                },
                                context.translated(scope, agent_state_key(&view.selected_status)),
                            ),
                            paragraph(
                                format!(
                                    "{} agent-admin-runtime-state-badge",
                                    super::model::agent_state_badge_class(
                                        &view.selected_runtime_state
                                    )
                                ),
                                context.translated(
                                    scope,
                                    agent_state_key(&view.selected_runtime_state),
                                ),
                            ),
                        ],
                    ),
                    Box::new(
                        sapid::switch()
                            .unstyled()
                            .class("agent-admin-enabled-switch")
                            .name(context.translated(scope, "agents.enabled"))
                            .checked(view.selected_status == "active")
                            .enabled(view.selected_has_pcr_binding)
                            .on_checked_change(move |next| {
                                let Some(principal) = enable.context.principal_id.get() else {
                                    return;
                                };
                                enable.controller.clone().set_agent_enabled(
                                    enable.context.base_url.get(),
                                    enable.context.token.get(),
                                    target.clone(),
                                    principal,
                                    key.clone(),
                                    next,
                                );
                            }),
                    ),
                ],
            ));
        }
        if view.selected_can_replace_runtime {
            let open = state.replace_open;
            let replace = state.clone();
            let target = id.clone();
            lifecycle.push(action(
                scope,
                context.clone(),
                "agent-admin-replace-runtime-button",
                "Replace runtime",
                "secondary",
                true,
                move || open.revise(|value| *value = true),
            ));
            let pause_key = view.selected_key_state_owned.clone();
            let can_pause = view.selected_status == "active";
            lifecycle.push(reactive(open,move|scope,show|{if !show{return empty();}let state=replace.clone();let context=state.context.clone();let confirm=state.clone();let target=target.clone();let confirm_target=target.clone();let mut actions=vec![action(scope,context.clone(),"agent-admin-replace-runtime-confirm-button","Confirm replacement","secondary",true,move||{open.revise(|value|*value=false);confirm.controller.clone().replace_runtime(confirm.context.base_url.get(),confirm.context.token.get(),confirm_target.clone());})];if can_pause{let pause=state.clone();let key=pause_key.clone();actions.push(action(scope,context.clone(),"agent-admin-replace-runtime-pause-first-button","Pause first (recommended if the key may be compromised)","secondary",true,move||{let Some(principal)=pause.context.principal_id.get()else{return;};open.revise(|value|*value=false);pause.controller.clone().set_agent_enabled(pause.context.base_url.get(),pause.context.token.get(),target.clone(),principal,key.clone(),false);}));}actions.push(action(scope,context.clone(),"agent-admin-replace-runtime-cancel-button","Cancel","secondary",true,move||open.revise(|value|*value=false)));stack("agent-admin-replace-runtime-confirm",vec![paragraph("muted","Completing this pairing atomically revokes this agent's current runtime key. The existing runtime goes offline immediately and stays offline until the new runtime publishes its KeyPackage pool. The agent's lifecycle intent is preserved — an active agent needs no resume."),line("actions",actions)])}));
        }
        let open = state.controller.deactivate_dialog_open;
        let text = state.controller.deactivate_confirm;
        lifecycle.push(action(
            scope,
            context.clone(),
            "agent-admin-deactivate-button",
            "Deactivate",
            "destructive",
            true,
            move || {
                text.revise(|value| value.clear());
                open.revise(|value| *value = true);
            },
        ));
        let deactivate = state.clone();
        let target = id.clone();
        let key = view.selected_key_state_owned.clone();
        let deactivate_state = view.deactivate_status;
        lifecycle.push(reactive(open,move|scope,show|{
   if !show{return empty()}let state=deactivate.clone();let context=state.context.clone();let confirm=state.clone();let target=target.clone();let key=key.clone();
   confirmation(scope,context.clone(),"agent-admin-deactivate-modal","Deactivate agent",stack("modal-body workflow-form agent-admin-deactivate-modal-body",vec![
    paragraph("muted","This action is terminal. The Agent identity will be deactivated and its runtime key revoked."),
    input(scope,context.clone(),"agent-admin-deactivate-confirm-input","Type DEACTIVATE to confirm.",text,true),
    action(scope,context.clone(),"agent-admin-deactivate-confirm-button","Deactivate agent","destructive",scope.bond(move||text.get()=="DEACTIVATE"),move||{
     if text.get_untracked()!="DEACTIVATE"{return}
     let Some(principal)=confirm.context.principal_id.get()else{return};
     confirm.controller.clone().deactivate_agent(confirm.context.base_url.get(),confirm.context.token.get(),target.clone(),principal,deactivate_state,key.clone());
    }),
   ]),move||{open.revise(|value|*value=false);text.revise(|value|value.clear());})
  }));
    } else {
        lifecycle.push(paragraph(
            "agent-admin-terminal-note",
            "This Agent is deactivated. Lifecycle intent cannot be restored.",
        ));
    }
    children.push(stack(
        "agent-admin-section agent-admin-agent-actions",
        lifecycle,
    ));
    stack("event agent-admin-detail-pane agent-admin-detail", children)
}

fn mount_agent_selection(
    scope: &Scope,
    agents: Cage<Vec<AgentView>>,
    selected: Cage<String>,
    filter: Cage<String>,
    search: glory::Bond<String>,
) {
    scope.effect(move || {
        let rows = agents.get();
        let filter = filter.get();
        let search = search.get();
        let current = selected.get_untracked();
        let next = if rows
            .iter()
            .any(|row| agent_id(row) == current && agent_visible(row, &filter, &search))
        {
            current.clone()
        } else {
            rows.iter()
                .find(|row| agent_visible(row, &filter, &search))
                .map(agent_id)
                .unwrap_or_default()
        };
        if next != current {
            selected.revise(|value| *value = next);
        }
    });
}

fn agent_icon_action(
    scope: &Scope,
    context: Rc<InksonContext>,
    key: &str,
    label: &str,
    icon: &str,
    enabled: impl Into<glory::Vary<bool>>,
    handler: impl FnMut() + 'static,
) -> View {
    Box::new(
        sapid::button()
            .unstyled()
            .class(format!("btn icon secondary {key}"))
            .name(context.translated(scope, label))
            .enabled(enabled)
            .fill(crate::components::ui_icon(icon))
            .on_press(handler),
    )
}

fn capability_row(
    key: String,
    title: &str,
    help: &str,
    checked: impl Into<glory::Vary<bool>>,
    enabled: impl Into<glory::Vary<bool>>,
    changed: Option<Rc<dyn Fn(bool)>>,
) -> View {
    let checked = checked.into();
    let enabled = enabled.into();
    let readonly = changed.is_none();
    Box::new(
        sapid::field(key)
            .unstyled()
            .class(if readonly {
                "agent-admin-preset-row readonly"
            } else {
                "agent-admin-preset-row"
            })
            .label(title.to_owned())
            .description(help.to_owned())
            .enabled(enabled.clone())
            .control(move |field| {
                let input = sapid::checkbox()
                    .unstyled()
                    .field(field)
                    .checked(checked.clone())
                    .enabled(enabled.clone());
                if let Some(changed) = changed.clone() {
                    input.on_checked_change(move |next| changed(next))
                } else {
                    input
                }
            }),
    )
}

fn permission_overview(scope: &Scope, context: Rc<InksonContext>, view: &AgentAdminView) -> View {
    let labels = |presets: &[AgentGrantPreset]| {
        view.selected_content_capabilities
            .iter()
            .filter(|(preset, checked)| *checked && presets.contains(preset))
            .map(|(preset, _)| preset.label())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let read = labels(&[AgentGrantPreset::Read]);
    let write = labels(&[
        AgentGrantPreset::Draft,
        AgentGrantPreset::ReplyAsAgent,
        AgentGrantPreset::ActOnBehalf,
        AgentGrantPreset::Organizer,
    ]);
    let mut rows = vec![
        paragraph(
            "agent-permission-state",
            format!(
                "{} · {}",
                crate::i18n::tr(agent_state_key(&view.selected_runtime_state)),
                crate::i18n::tr(agent_state_key(&view.selected_status))
            ),
        ),
        paragraph(
            "muted",
            context.translated(scope, "permissions.ceiling_note"),
        ),
        paragraph(
            "",
            format!(
                "{}: {}",
                crate::i18n::tr("permissions.read_ceiling"),
                if read.is_empty() {
                    crate::i18n::tr("permissions.none")
                } else {
                    read
                }
            ),
        ),
        paragraph(
            "",
            format!(
                "{}: {}",
                crate::i18n::tr("permissions.write_ceiling"),
                if write.is_empty() {
                    crate::i18n::tr("permissions.none")
                } else {
                    write
                }
            ),
        ),
    ];
    if let Some(key) = &view.selected_key_state_owned {
        rows.push(paragraph(
            "agent-permission-controller",
            format!(
                "{}: {}",
                crate::i18n::tr("permissions.controller"),
                short_protocol_id(key.controller_account_id.principal_id.as_str())
            ),
        ));
        rows.push(paragraph(
            "agent-permission-station",
            format!(
                "{}: {}",
                crate::i18n::tr("permissions.account_station"),
                short_protocol_id(key.controller_account_id.station_id.as_str())
            ),
        ));
        rows.push(paragraph(
            "muted",
            context.translated(scope, "permissions.runtime_location_note"),
        ));
        if key.active_authorizations.is_empty() {
            rows.push(paragraph(
                "muted agent-permission-expiry",
                context.translated(scope, "permissions.no_runtime_key"),
            ));
        } else {
            for authorization in &key.active_authorizations {
                rows.push(paragraph(
                    "agent-permission-expiry",
                    format!(
                        "{} · {}: {}",
                        short_protocol_id(authorization.verification_method.as_str()),
                        crate::i18n::tr("permissions.key_expiry"),
                        authorization
                            .expires_at
                            .map(|date| date.to_rfc3339())
                            .unwrap_or_else(|| crate::i18n::tr("permissions.no_fixed_expiry"))
                    ),
                ));
            }
        }
        let disclosure = serde_json::json!({"controller_account_id":key.controller_account_id,"principal_control_realm_id":key.principal_control_realm_id,
            "controller_authorization_ref":key.controller_authorization_ref,"requested_scope":key.requested_scope,"active_authorizations":key.active_authorizations,"reported_grants":view.selected_grants});
        let mut source = Some(paragraph(
            "mono permission-source-json",
            serde_json::to_string_pretty(&disclosure).unwrap_or_default(),
        ));
        rows.push(Box::new(
            sapid::collapsible(format!("agent-source-{}", scope.id().slot()))
                .unstyled()
                .class("permission-source")
                .label(context.translated(scope, "permissions.sources"))
                .default_open(false)
                .content_policy(sapid::ContentPolicy::KeepMounted)
                .content(move || source.take().unwrap_or_else(empty)),
        ));
    } else {
        rows.push(paragraph(
            "muted",
            context.translated(scope, "permissions.details_unavailable"),
        ));
    }
    stack("agent-admin-section agent-permission-overview", rows)
}

#[cfg(test)]
mod retained_creation_tests {
    use std::cell::RefCell;

    use super::*;

    #[test]
    fn unrelated_agent_refresh_retains_the_live_creation_owner() {
        let app = glory::App::memory();
        let scope = app.scope();
        let agents = scope.cage(Vec::<AgentView>::new());
        let selected = scope.cage(String::new());
        let create = scope.cage(true);
        let filter = scope.cage("all".to_owned());
        let owners = Rc::new(RefCell::new(Vec::new()));
        let rendered = owners.clone();
        app.mount(reactive(
            agent_detail_source(scope, agents, selected, create, filter),
            move |scope, _| {
                rendered.borrow_mut().push(scope.downgrade());
                paragraph("", "retained Agent creation")
            },
        ))
        .unwrap();
        let owner = owners.borrow()[0].clone();
        agents.revise(Vec::clear);
        selected.revise(|value| *value = "another Agent".into());
        filter.revise(|value| *value = "paused".into());
        app.flush().unwrap();
        assert_eq!(owners.borrow().len(), 1);
        assert!(owner.upgrade().is_some());

        create.revise(|value| *value = false);
        app.flush().unwrap();
        assert_eq!(owners.borrow().len(), 2);
        assert!(owner.upgrade().is_none());
    }
}
