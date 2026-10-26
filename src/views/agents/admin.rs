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
pub fn page(scope: &Scope, context: Rc<InksonContext>, route: Route) -> View {
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
    mount_agent_selection(
        scope,
        controller.agents,
        controller.selected_agent_id,
        filter,
    );
    let details = controller.clone();
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
    let list_state = state.clone();
    let list = reactive(
        scope.bond(move || (agents.get(), selected.get(), create.get(), filter.get())),
        move |scope, (rows, selected_id, is_create, current_filter)| {
            let state = list_state.clone();
            let context = state.context.clone();
            let mut children = Vec::new();
            let refresh = state.controller.clone();
            let refresh_context = context.clone();
            let begin = state.clone();
            children.push(line(
                "event-head",
                vec![
                    plain("Agents"),
                    line(
                        "actions agent-admin-list-actions",
                        vec![
                            agent_icon_action(
                                scope,
                                context.clone(),
                                "agent-admin-refresh-button",
                                "Refresh agents",
                                "refresh",
                                "secondary",
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
                                "Create agent",
                                "plus",
                                if is_create { "primary" } else { "secondary" },
                                move || {
                                    begin.slug.revise(|value| value.clear());
                                    begin
                                        .controller
                                        .new_agent_avatar_blob_ref
                                        .revise(|value| value.clear());
                                    begin
                                        .controller
                                        .last_op_status
                                        .revise(|value| value.clear());
                                    begin
                                        .controller
                                        .provision_operation_id
                                        .revise(|value| *value = None);
                                    begin.controller.create_mode.revise(|value| *value = true);
                                },
                            ),
                        ],
                    ),
                ],
            ));
            let mut filters = Vec::new();
            for (filter, label) in AGENT_LIST_FILTERS {
                let navigate = context.clone();
                let filter = filter.to_owned();
                let active = filter == current_filter;
                filters.push(action(
                    scope,
                    context.clone(),
                    &format!("agent-admin-filter-{filter}"),
                    label,
                    if active {
                        "agent-admin-filter-button active"
                    } else {
                        "agent-admin-filter-button"
                    },
                    true,
                    move || {
                        navigate.navigate(Route::SettingsSection {
                            section: "agents".into(),
                            filter: filter.clone(),
                        })
                    },
                ));
            }
            children.push(line("agent-admin-filter-bar", filters));
            children.push(status(state.controller.list_status));
            let view = build_agent_admin_view(
                &rows,
                &selected_id,
                &current_filter,
                &crate::clock::now_timestamp(),
            );
            let mut agent_rows = Vec::new();
            for agent in &view.visible_agents {
                let id = agent_id(agent);
                let target = id.clone();
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
                    glory::ui::button()
                        .class(if selected {
                            "agent-admin-list-row agent-admin-row active"
                        } else {
                            "agent-admin-list-row agent-admin-row"
                        })
                        .name(slug.clone())
                        .semantics(Some(Box::new(glory::render::Semantics {
                            pressed: Some(selected),
                            ..Default::default()
                        })))
                        .fill(
                            glory::ui::group().fill((
                                avatar,
                                glory::ui::text()
                                    .class("agent-admin-row-title")
                                    .content(slug),
                                glory::ui::text()
                                    .class(super::model::agent_state_badge_class(lifecycle))
                                    .content(super::model::agent_state_label(lifecycle)),
                                glory::ui::text()
                                    .class(super::model::agent_state_badge_class(runtime))
                                    .content(super::model::agent_state_label(runtime)),
                                glory::ui::text()
                                    .class("mono muted agent-admin-row-id")
                                    .content(short_protocol_id(&id)),
                            )),
                        )
                        .on(glory::render::EventKind::Activate, move |_| {
                            create.revise(|value| *value = false);
                            choose.revise(|value| *value = target.clone());
                        }),
                ) as View);
            }
            children.push(stack("agent-admin-list-rows", agent_rows));
            if view.visible_agents.is_empty() {
                children.push(paragraph(
                    "members-empty compact",
                    if view.has_any_agents {
                        "No agents match this filter."
                    } else {
                        "No agents yet. Create an Agent to connect its runtime."
                    },
                ));
            }
            stack("event agent-admin-list-pane agent-admin-list", children)
        },
    );
    let detail_state = state.clone();
    let detail = reactive(
        scope.bond(move || {
            let creating = create.get();
            (
                agents.get(),
                selected.get(),
                creating,
                if creating {
                    String::new()
                } else {
                    filter.get()
                },
            )
        }),
        move |scope, (rows, id, create, current_filter)| {
            let state = detail_state.clone();
            if create {
                return creation(scope, &state);
            }
            if id.is_empty() {
                return card(
                    scope,
                    state.context.clone(),
                    "Select an agent",
                    vec![paragraph(
                        "muted",
                        "Choose an agent on the left, or create one first.",
                    )],
                );
            }
            let now = crate::clock::now_timestamp();
            let view = build_agent_admin_view(&rows, &id, &current_filter, &now);
            details_view(scope, &state, view, id)
        },
    );
    stack(
        "agent-admin-page agent-admin",
        vec![
            status(controller.last_op_status),
            line("agent-admin-layout", vec![list, detail]),
        ],
    )
}
fn creation(scope: &Scope, state: &AgentPage) -> View {
    let context = state.context.clone();
    let busy = state.controller.provision_in_flight;
    let enabled = scope.bond(move || !busy.get());
    let presets = state.presets;
    let services = state.services;
    let slug = state.slug;
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
    let provision = state.clone();
    let cancel = state.controller.clone();
    stack(
        "event agent-admin-detail-pane",
        vec![
            line(
                "event-head",
                vec![plain(context.translated(scope, "Create agent"))],
            ),
            field(
                scope,
                context.clone(),
                "agent-admin-provision-agent-slug",
                "Slug",
                slug,
                enabled,
                false,
                move |next| slug.revise(|value| *value = normalize_agent_slug(&next)),
            ),
            avatar_picker,
            heading(3, "agent-admin-section-head", "Content capabilities"),
            stack("agent-admin-preset-list", content),
            heading(3, "agent-admin-section-head", "Runtime service surface"),
            stack("agent-admin-preset-list", service),
            line(
                "actions",
                vec![
                    action(
                        scope,
                        context.clone(),
                        "agent-admin-provision-button",
                        "Create",
                        "primary",
                        scope.bond(move || !busy.get() && !slug.get().trim().is_empty()),
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
                        "Cancel",
                        "secondary",
                        enabled,
                        move || {
                            cancel
                                .new_agent_avatar_blob_ref
                                .revise(|value| value.clear());
                            cancel.provision_operation_id.revise(|value| *value = None);
                            cancel.create_mode.revise(|value| *value = false);
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
                        paragraph("muted", "Created"),
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
                        paragraph("muted", "Updated"),
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
    if view.selected_should_show_pairing_card {
        let mut pairing = Vec::new();
        if view.selected_pairing_is_expired {
            pairing.push(paragraph("agent-admin-status error","This pairing request expired. The expired code and link can never be used again; pair again to issue a fresh code and QR for this agent."));
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
            "Setup incomplete"
        } else if view.selected_pairing_is_expired {
            "Expired"
        } else {
            super::model::agent_state_label(&view.selected_runtime_state)
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
                        pairing_label.to_owned(),
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
            vec![
                paragraph("agent-admin-section-title", "Content capabilities"),
                paragraph("muted", "Configured when this agent was created"),
            ],
        ),
        paragraph(
            "muted",
            "Actual access is the intersection of this ceiling with Realm membership, participation, and effective grants.",
        ),
        stack(
            "agent-admin-preset-list agent-admin-content-capability-list",
            capabilities,
        ),
        line(
            "agent-admin-section-head",
            vec![
                paragraph("agent-admin-section-title", "Runtime service surface"),
                paragraph("muted", "Selected when this agent was created"),
            ],
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
    children.push(stack(
        "agent-admin-section agent-admin-capabilities",
        capability_section,
    ));
    let terminal = view.selected_status == "deactivated";
    let enable = state.clone();
    let key = view.selected_key_state_owned.clone();
    let target = id.clone();
    let mut lifecycle = vec![line(
        "agent-admin-section-head",
        vec![
            paragraph("agent-admin-section-title", "Lifecycle"),
            paragraph("muted", "Loaded from selected agent"),
        ],
    )];
    if !terminal {
        if matches!(view.selected_status.as_str(), "active" | "paused") {
            lifecycle.push(line(
                "agent-admin-lifecycle-toggle-row",
                vec![
                    stack(
                        "agent-admin-lifecycle-copy",
                        vec![
                            paragraph("agent-admin-section-title", "Agent enabled"),
                            paragraph(
                                "muted",
                                if view.selected_status == "active" {
                                    "Active — turn off to pause"
                                } else {
                                    "Paused — turn on to resume"
                                },
                            ),
                        ],
                    ),
                    line(
                        "agent-admin-lifecycle-toggle-control",
                        vec![
                            paragraph(
                                if view.selected_status == "active" {
                                    "badge green"
                                } else {
                                    "badge amber"
                                },
                                if view.selected_status == "active" {
                                    "Active"
                                } else {
                                    "Paused"
                                },
                            ),
                            paragraph(
                                format!(
                                    "{} agent-admin-runtime-state-badge",
                                    super::model::agent_state_badge_class(
                                        &view.selected_runtime_state
                                    )
                                ),
                                super::model::agent_state_label(&view.selected_runtime_state)
                                    .to_owned(),
                            ),
                            Box::new(
                                sapid::switch()
                                    .unstyled()
                                    .class("agent-admin-enabled-switch")
                                    .name("Agent enabled")
                                    .checked(view.selected_status == "active")
                                    .enabled(view.selected_has_pcr_binding)
                                    .on_checked_change(move |next| {
                                        let Some(principal) = enable.context.principal_id.get()
                                        else {
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
) {
    scope.effect(move || {
        let rows = agents.get();
        let filter = filter.get();
        let current = selected.get_untracked();
        let next = if rows.iter().any(|row| {
            agent_id(row) == current
                && agent_matches_filter(agent_lifecycle_wire(row.agent.lifecycle), &filter)
        }) {
            current.clone()
        } else {
            rows.iter()
                .find(|row| {
                    agent_matches_filter(agent_lifecycle_wire(row.agent.lifecycle), &filter)
                })
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
    variant: &str,
    handler: impl FnMut() + 'static,
) -> View {
    Box::new(
        sapid::button()
            .unstyled()
            .class(format!("btn icon {variant} {key}"))
            .name(context.translated(scope, label))
            .fill(crate::components::ui_icon(icon))
            .on_press(handler),
    )
}

fn capability_row(
    key: String,
    title: &str,
    help: &str,
    checked: impl Into<glory::Lotus<bool>>,
    enabled: impl Into<glory::Lotus<bool>>,
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
