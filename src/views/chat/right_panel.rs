use std::rc::Rc;

use super::*;
use crate::presentation::widgets::{empty, paragraph, plain, reactive_distinct};
use crate::presentation::{InksonContext, View};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SidecarDeliveryDiagnostics {
    pub(super) submit: &'static str,
    pub(super) fanout: &'static str,
    pub(super) receipt: &'static str,
    pub(super) last_updated: String,
}

fn tabs(
    scope: &Scope,
    context: Rc<InksonContext>,
    active: DiscussionSidePanel,
    snapshot: Bond<snapshot::ChatSnapshot>,
    right_panel: Cage<Option<DiscussionSidePanel>>,
) -> View {
    let members = scope.bond({
        let context = context.clone();
        move || {
            if snapshot.get().sidecar_session.is_some() {
                "Access".to_owned()
            } else {
                crate::i18n::tr_for_locale(context.locale.get(), "chat.tabs.members")
            }
        }
    });
    let settings = scope.bond(move || {
        if snapshot.get().sidecar_session.is_some() {
            "Connection details".to_owned()
        } else {
            crate::i18n::tr_for_locale(context.locale.get(), "chat.tabs.settings")
        }
    });
    Box::new(
        view().class("discussion-right-tabs").fill((
            sapid::button()
                .unstyled()
                .variant(sapid::ButtonVariant::Secondary)
                .class(if active == DiscussionSidePanel::Users {
                    "btn btn-secondary discussion-right-tab active discussion-right-tab-members"
                } else {
                    "btn btn-secondary discussion-right-tab discussion-right-tab-members"
                })
                .label(members)
                .on_press(move || {
                    right_panel.revise(|value| *value = Some(DiscussionSidePanel::Users))
                }),
            sapid::button()
                .unstyled()
                .variant(sapid::ButtonVariant::Secondary)
                .class(if active == DiscussionSidePanel::Settings {
                    "btn btn-secondary discussion-right-tab active discussion-right-tab-settings"
                } else {
                    "btn btn-secondary discussion-right-tab discussion-right-tab-settings"
                })
                .label(settings)
                .on_press(move || {
                    right_panel.revise(|value| *value = Some(DiscussionSidePanel::Settings))
                }),
        )),
    )
}

fn subhead(label: impl Into<Lotus<String>>) -> View {
    Box::new(
        view()
            .class("discussion-subhead")
            .fill(text().content(label)),
    )
}
fn detail(label: impl Into<Lotus<String>>, value: impl Into<Lotus<String>>, class: &str) -> View {
    Box::new(
        view().class("detail-row").fill((
            text().content(label),
            text()
                .style(Style::new().font_weight(700.0))
                .class(format!("detail-value {class}"))
                .content(value),
        )),
    )
}
fn panel_head(label: impl Into<Lotus<String>>) -> View {
    Box::new(
        view().class("discussion-panel-head").fill(
            view()
                .class("discussion-title-row")
                .fill(text().kind(TextKind::Heading(2)).content(label)),
        ),
    )
}

#[derive(Clone, PartialEq)]
struct PresenceRow {
    actor: String,
    display: String,
    state: String,
    status: Option<String>,
    is_self: bool,
}

fn controller_summary(
    scope: &Scope,
    context: Rc<InksonContext>,
    controller: &SpaceParticipant,
    participants: &[SpaceParticipant],
    display: String,
    count: String,
) -> View {
    let selector = agent_selector_label(controller);
    let slug = controller
        .agent_metadata
        .as_ref()
        .map(|metadata| metadata.agent_slug.clone())
        .filter(|slug| !slug.trim().is_empty());
    let mut children: Vec<View> = vec![
        crate::components::identity_avatar_inline(
            scope,
            context,
            crate::components::IdentityAvatarProps {
                seed: controller.roster_key(),
                alt_text: display.clone(),
                blob_ref: None,
                class: "avatar-img participant-avatar participant-controller-avatar".into(),
                test_id: None,
            },
        ),
        Box::new(
            text()
                .class("mono participant-id participant-controller-name")
                .content(slug.clone().unwrap_or(display)),
        ),
        Box::new(
            text()
                .class("badge participant-badge member participant-controller-role")
                .content(controller.role.label()),
        ),
        Box::new(
            text()
                .class("participant-agent-group-toggle muted participant-controller-count")
                .content(count),
        ),
    ];
    if controller.is_self {
        children.push(Box::new(
            text()
                .class("badge self-attribution-badge participant-controller-self")
                .content("ME"),
        ));
    }
    if controller.is_agent || slug.is_some() {
        children.push(Box::new(
            text()
                .class("badge member-badge member-badge-agent participant-controller-agent")
                .content("Agent"),
        ));
    }
    if let Some(owner) = agent_controller_label(controller, participants) {
        children.push(Box::new(
            text()
                .class("muted participant-agent-subline participant-controller-owner")
                .content(format!("agent of {owner}")),
        ));
    }
    if let Some(selector) = selector {
        children.push(Box::new(
            text()
                .class("mono muted participant-agent-selector participant-controller-selector")
                .content(format!("@{selector}")),
        ));
    }
    Box::new(group().fill(children))
}

pub(super) fn users_panel(
    scope: &Scope,
    context: Rc<InksonContext>,
    controller: ChatController,
    snapshot: Bond<snapshot::ChatSnapshot>,
    right_panel: Cage<Option<DiscussionSidePanel>>,
) -> View {
    let heading = scope.bond({
        let context = context.clone();
        move || {
            if snapshot.get().sidecar_session.is_some() {
                "Access".to_owned()
            } else {
                crate::i18n::tr_for_locale(context.locale.get(), "chat.users_header")
            }
        }
    });
    let access = scope.bond({
        let context = context.clone();
        move || {
            let current = snapshot.get();
            (
                current.sidecar_session,
                context.account_primary_handle.get(),
                current.sidecar_owned_agents,
                current.sidecar_security_label,
            )
        }
    });
    let access = reactive_distinct(access, move |_, (session, handle, agents, security)| {
        let Some(session) = session else {
            return empty();
        };
        let mut children = vec![
            subhead("Sidecar members"),
            Box::new(view().class("sidecar-access-row").fill((
                view().fill((
                    text().style(Style::new().font_weight(700.0)).content(
                        if handle.trim().is_empty() {
                            "You".to_owned()
                        } else {
                            handle
                        },
                    ),
                    text().class("muted").content("Controller"),
                )),
                text().class("badge success").content("Active"),
            ))) as View,
        ];
        for agent in agents {
            let id = agent.principal_id.to_string();
            let slug = agent
                .agent_metadata
                .as_ref()
                .map(|metadata| metadata.agent_slug.trim().to_owned())
                .filter(|slug| !slug.is_empty())
                .unwrap_or_else(|| short_principal_label(&id));
            let addressed = session
                .addressed_agent_ids
                .iter()
                .any(|candidate| candidate == &id);
            let mut identity =
                vec![Box::new(text().style(Style::new().font_weight(700.0)).content(slug)) as View];
            if let Some(selector) = agent_selector_label(&agent) {
                identity.push(paragraph("muted", format!("@{selector}")));
            }
            identity.push(paragraph("muted mono", id));
            children.push(Box::new(
                view().class("sidecar-access-row sidecar-agent-row").fill((
                    view().fill(identity),
                    text()
                        .class(if addressed { "badge accent" } else { "badge" })
                        .content(if addressed {
                            "Addressed now"
                        } else {
                            "Eligible agent"
                        }),
                )),
            ));
        }
        children.extend([
            paragraph("event info","Sidecar access is derived from your eligible Agents. The badge marks the Agent addressed by the current message."),
            subhead("Encryption"),detail("Profile",security.unwrap_or_else(||"Opening".into()),""),
            detail("Membership reconciliation",if session.membership_ready(){"Complete"}else{"Pending"},""),
            detail("Pending members",session.pending_reconciliation_count().to_string(),""),
        ]);
        Box::new(
            view()
                .class("discussion-detail-section sidecar-access-section sidecar-access-panel")
                .fill(children),
        )
    });
    let presence = scope.bond({
        let context = context.clone();
        move || {
            let current = snapshot.get();
            let labels = controller.presence_labels.get();
            let states = controller.presence_states.get();
            let statuses = controller.presence_status_messages.get();
            let _ = context.state_revision.get();
            context.state_store.read(|store| {
                current
                    .presence_participants
                    .iter()
                    .map(|participant| {
                        let actor = participant.roster_key();
                        let display =
                            display_label_for_actor(store, &current.participants, &labels, &actor);
                        let state = states.get(&actor).cloned().unwrap_or_else(|| {
                            if participant.is_self {
                                "online".into()
                            } else {
                                "offline".into()
                            }
                        });
                        PresenceRow {
                            status: statuses.get(&actor).cloned(),
                            actor,
                            display,
                            state,
                            is_self: participant.is_self,
                        }
                    })
                    .collect::<Vec<_>>()
            })
        }
    });
    let presence_context = context.clone();
    let presence = reactive_distinct(presence, move |scope, rows| {
        let children = rows
            .into_iter()
            .map(|row| {
                let mut name = vec![plain(row.display)];
                if row.is_self {
                    name.push(crate::components::self_attribution_badge(
                        scope,
                        presence_context.clone(),
                        crate::components::SelfAttributionBadgeProps {
                            class: Some("participant-inline-self-badge presence-self-badge".into()),
                            test_id: Some("presence-self-badge".into()),
                        },
                    ));
                }
                let mut content = vec![
                    Box::new(
                        text()
                            .class(format!("presence-dot presence-dot-{}", row.state))
                            .content(""),
                    ) as View,
                    Box::new(view().class("presence-name").name(row.actor).fill(name)),
                    Box::new(text().class("muted").content(format!(" ({})", row.state))),
                ];
                if let Some(status) = row.status {
                    content.push(Box::new(
                        text()
                            .class("muted presence-status-message")
                            .content(format!(" — {status}")),
                    ));
                }
                Box::new(
                    view()
                        .class(format!("presence-row presence-row-{}", row.state))
                        .fill(content),
                ) as View
            })
            .collect::<Vec<_>>();
        Box::new(view().class("presence-list").fill(children))
    });
    let expanded = scope.cage(std::collections::BTreeSet::<String>::new());
    let roster = scope.bond({
        let context = context.clone();
        move || {
            let current = snapshot.get();
            let _ = context.state_revision.get();
            let labels = context.state_store.read(|store| {
                current
                    .participants
                    .iter()
                    .map(|participant| {
                        (
                            participant.roster_key(),
                            participant_roster_display_label(store, participant),
                        )
                    })
                    .collect::<std::collections::BTreeMap<_, _>>()
            });
            (
                current.participants,
                current.participants_for_messages,
                current.public_agent_ids,
                labels,
            )
        }
    });
    let roster_context = context.clone();
    let roster = reactive_distinct(
        roster,
        move |scope, (participants, messages, public_agents, labels)| {
            let mut children = vec![subhead("Space users")];
            for row in participant_roster_rows(&participants, &public_agents) {
                match row {
                    ParticipantRosterRow::Participant(participant) => {
                        let display = labels
                            .get(&participant.roster_key())
                            .cloned()
                            .unwrap_or_default();
                        children.push(super::timeline::discussion_participant_row(
                            scope,
                            roster_context.clone(),
                            super::timeline::DiscussionParticipantRowProps {
                                participant,
                                participants: messages.clone(),
                                display_label: display,
                                nested_agent: false,
                                show_binding_details: true,
                            },
                        ));
                    }
                    ParticipantRosterRow::ControllerWithAgents { controller, agents } => {
                        let key = controller.roster_key();
                        let display = labels.get(&key).cloned().unwrap_or_default();
                        let count = agents.len();
                        let count_label = if count == 1 {
                            "1 agent".to_owned()
                        } else {
                            format!("{count} agents")
                        };
                        let aria = format!(
                            "Show {count_label} for {display} ({}), {}{}",
                            controller.roster_key(),
                            controller.role.label(),
                            if controller.is_self {
                                ", This is your account"
                            } else {
                                ""
                            }
                        );
                        let group_class = if controller.is_self {
                            "participant-agent-group self"
                        } else if controller.is_agent {
                            "participant-agent-group agent"
                        } else {
                            "participant-agent-group"
                        };
                        let summary = controller_summary(
                            scope,
                            roster_context.clone(),
                            &controller,
                            &messages,
                            display,
                            count_label,
                        );
                        let mut agent_rows = vec![];
                        for participant in agents {
                            let display = labels
                                .get(&participant.roster_key())
                                .cloned()
                                .unwrap_or_default();
                            agent_rows.push(super::timeline::discussion_participant_row(
                                scope,
                                roster_context.clone(),
                                super::timeline::DiscussionParticipantRowProps {
                                    participant,
                                    participants: messages.clone(),
                                    display_label: display,
                                    nested_agent: true,
                                    show_binding_details: true,
                                },
                            ));
                        }
                        let open = scope.bond({
                            let key = key.clone();
                            move || expanded.get().contains(&key)
                        });
                        let changed_key = key.clone();
                        let mut summary = Some(summary);
                        let mut agent_rows = Some(agent_rows);
                        children.push(Box::new(
                            sapid::collapsible(format!(
                                "participant-{}",
                                &arkret_sdk::canonical::sha256_hex(key.as_bytes())[..16]
                            ))
                            .unstyled()
                            .class(group_class)
                            .label(aria)
                            .open(open)
                            .on_open_change(move |value| {
                                expanded.revise(|expanded| {
                                    if value {
                                        expanded.insert(changed_key.clone());
                                    } else {
                                        expanded.remove(&changed_key);
                                    }
                                })
                            })
                            .trigger_content(move || summary.take().unwrap_or_else(empty))
                            .content_policy(sapid::ContentPolicy::KeepMounted)
                            .content(move || {
                                Box::new(
                                    view()
                                        .class("participant-agent-children")
                                        .fill(agent_rows.take().unwrap_or_default()),
                                )
                            }),
                        ));
                    }
                }
            }
            Box::new(view().class("discussion-detail-section").fill(children))
        },
    );
    Box::new(
        view()
            .role(glory::render::Role::Section)
            .class("discussion-panel discussion-details-panel discussion-users-panel")
            .fill((
                panel_head(heading),
                tabs(
                    scope,
                    context,
                    DiscussionSidePanel::Users,
                    snapshot,
                    right_panel,
                ),
                access,
                view()
                    .class("discussion-detail-section")
                    .fill((subhead("Presence"), presence)),
                roster,
            )),
    )
}

#[derive(Clone, PartialEq)]
struct SettingsModel {
    sidecar: Option<crate::sidecar::HostedSidecarState>,
    diagnostics: Option<SidecarDeliveryDiagnostics>,
    security: Option<String>,
    realm: String,
    strand: String,
    category: String,
    unread: usize,
    messages: usize,
    locale: crate::i18n::UiLocale,
}

pub(super) fn settings_panel(
    scope: &Scope,
    context: Rc<InksonContext>,
    props: ChatPanelProps,
    controller: ChatController,
    snapshot: Bond<snapshot::ChatSnapshot>,
    right_panel: Cage<Option<DiscussionSidePanel>>,
) -> View {
    let heading = scope.bond({
        let context = context.clone();
        move || {
            if snapshot.get().sidecar_session.is_some() {
                "Connection details".to_owned()
            } else {
                crate::i18n::tr_for_locale(context.locale.get(), "chat.settings_header")
            }
        }
    });
    let model = scope.bond({
        let context = context.clone();
        move || {
            let value = snapshot.get();
            SettingsModel {
                sidecar: value.sidecar_session,
                diagnostics: value.sidecar_delivery_diagnostics,
                security: value.sidecar_security_label,
                realm: props.selected_realm_id.clone(),
                strand: controller.selected_channel.get(),
                category: value.selected_channel_category,
                unread: value.selected_channel_unread,
                messages: value.visible_message_count,
                locale: context.locale.get(),
            }
        }
    });
    let command_scope = scope.downgrade();
    let body_context = context.clone();
    let body = reactive_distinct(model, move |scope, model| {
        let context = body_context.clone();
        let mut sections = Vec::<View>::new();
        if let (Some(session), Some(diagnostics)) = (&model.sidecar, &model.diagnostics) {
            let security = model.security.as_deref().unwrap_or("Opening");
            let summary = session.diagnostic_summary(
                security,
                diagnostics.submit,
                diagnostics.fanout,
                diagnostics.receipt,
                &diagnostics.last_updated,
            );
            let weak = command_scope.clone();
            let copy_context = context.clone();
            let open_context = context.clone();
            sections.push(Box::new(view().class("discussion-detail-section sidecar-diagnostics-section sidecar-connection-details").fill((
                detail("Trace ID",session.trace_id.to_string(),"mono"),detail("Ensure","Complete",""),
                detail("Private access",if session.membership_ready(){"Complete"}else{"Reconciling"},""),
                detail("Encryption",security.to_owned(),""),detail("Message submit",diagnostics.submit,""),
                detail("Notification fanout",diagnostics.fanout,""),detail("Agent receipt",diagnostics.receipt,""),detail("Last updated",diagnostics.last_updated.clone(),""),
                view().class("actions").fill((
                    sapid::button().unstyled().variant(sapid::ButtonVariant::Secondary).class("btn btn-secondary sidecar-copy-diagnostics").label("Copy diagnostic summary")
                        .on_press(move || {
                            let Some(scope)=weak.upgrade() else{return;};let summary=summary.clone();let context=copy_context.clone();
                            let generation=context.session_generation.get_untracked();let account=context.active_account.get_untracked();
                            if let Err(error)=scope.spawn(async move {
                                let result=crate::components::platform_io::copy_text(&summary).await;
                                if context.session_matches(generation,&account)&&let Err(error)=result {
                                    context.last_error.revise(|value|*value=Some(format!("Copy diagnostic summary: {error}")));
                                }
                            }){scope.report_error(error);}
                        }),
                    sapid::button().unstyled().variant(sapid::ButtonVariant::Secondary).class("btn btn-secondary").label("Open agent settings")
                        .on_press(move ||open_context.navigate(Route::SettingsSection{section:"agents".into(),filter:String::new()})),
                )),
            ))));
        }
        let muted = scope.bond({
            let context = context.clone();
            let realm = model.realm.clone();
            move || {
                let _ = context.state_revision.get();
                context
                    .state_store
                    .read(|store| store.muted_realms().contains(&realm))
            }
        });
        let sending = scope.bond({
            let context = context.clone();
            let strand = model.strand.clone();
            move || {
                let _ = context.state_revision.get();
                context.state_store.read(|store| {
                    store
                        .read_receipt_strand_override(&strand)
                        .unwrap_or_else(|| store.read_receipt_default_send())
                })
            }
        });
        let displaying = scope.bond({
            let context = context.clone();
            let strand = model.strand.clone();
            move || {
                let _ = context.state_revision.get();
                context.state_store.read(|store| {
                    store
                        .read_receipt_strand_display_override(&strand)
                        .unwrap_or_else(|| store.read_receipt_default_display())
                })
            }
        });
        let mute_context = context.clone();
        let send_context = context.clone();
        let display_context = context.clone();
        let send_strand = model.strand.clone();
        let display_strand = model.strand.clone();
        let realm = model.realm.clone();
        let generation = context.session_generation.get_untracked();
        let account = context.active_account.get_untracked();
        let mute_account = account.clone();
        let send_account = account.clone();
        sections.push(Box::new(view().class("discussion-detail-section").fill((
            subhead("Settings"),
            settings_check("discussion-settings-mute", crate::i18n::tr_for_locale(model.locale,"chat.settings.mute_notifications"), muted, Rc::new(move |value| {if mute_context.session_matches(generation,&mute_account) {
                    mute_context.state_store.write(|store|store.set_realm_muted(realm.clone(),value));
                    let revision=mute_context.state_store.revision();mute_context.state_revision.revise(|value|*value=revision);
                }})),
            settings_check("discussion-settings-read-receipts", crate::i18n::tr_for_locale(model.locale,"chat.settings.read_receipts"), sending, Rc::new(move |value| {if send_context.session_matches(generation,&send_account) {
                    send_context.state_store.write(|store|store.set_read_receipt_strand_override(send_strand.clone(),Some(value)));
                    let revision=send_context.state_store.revision();send_context.state_revision.revise(|value|*value=revision);
                }})),
            settings_check("discussion-settings-read-receipts-display", "Show others' read receipts", displaying, Rc::new(move |value| {if display_context.session_matches(generation,&account) {
                    display_context.state_store.write(|store|store.set_read_receipt_strand_display_override(display_strand.clone(),Some(value)));
                    let revision=display_context.state_store.revision();display_context.state_revision.revise(|value|*value=revision);
                }})),
            view().class("settings-row settings-row-readonly discussion-settings-shared-history-note").fill((
                text().content(crate::i18n::tr_for_locale(model.locale,"chat.settings.shared_history")),
                text().class("muted").content(crate::i18n::tr_for_locale(model.locale,"chat.settings.shared_history_hint")),
            )),
        ))));
        sections.push(Box::new(view().class("discussion-detail-section").fill((
            subhead("Selected"),
            detail("Category", model.category, ""),
            detail("Unread", model.unread.to_string(), ""),
            detail("Messages", model.messages.to_string(), ""),
        ))));
        Box::new(view().class("discussion-settings-sections").fill(sections))
    });
    Box::new(
        view()
            .role(glory::render::Role::Section)
            .class("discussion-panel discussion-details-panel discussion-settings-panel")
            .fill((
                panel_head(heading),
                tabs(
                    scope,
                    context,
                    DiscussionSidePanel::Settings,
                    snapshot,
                    right_panel,
                ),
                body,
            )),
    )
}

fn settings_check(
    key: &str,
    label: impl Into<Lotus<String>>,
    checked: Bond<bool>,
    changed: Rc<dyn Fn(bool)>,
) -> View {
    Box::new(
        sapid::field(key)
            .unstyled()
            .class(format!("settings-row {key}"))
            .label(label)
            .control(move |field| {
                let changed = changed.clone();
                sapid::checkbox()
                    .unstyled()
                    .field(field)
                    .checked(checked)
                    .on_checked_change(move |value| changed(value))
            }),
    )
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod disclosure_tests {
    use super::*;

    #[test]
    fn controller_with_agents_has_one_admitted_retained_disclosure_button() {
        let app = glory::App::memory();
        let directory = tempfile::tempdir().unwrap();
        let context = InksonContext::new(
            app.scope(),
            crate::presentation::BootState {
                config_store: crate::config::LocalConfigStore::with_path(
                    directory.path().join("config.json"),
                ),
                config: crate::config::ClientConfig::default(),
                state_store: crate::presentation::SharedStateStore::new(
                    LocalStateStore::with_path(directory.path().join("state.json")),
                ),
                initial_credential: String::new(),
                realm_tree_nodes: vec![],
            },
            Route::Dashboard,
            |_| Box::pin(std::future::pending()),
        );
        let principal: arkret_sdk::DidCoreId = "ak:did_core:web:alice.example".parse().unwrap();
        let controller = SpaceParticipant {
            actor_id: Some(arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                principal.clone(),
                "ak:did_core:web:station.example".parse().unwrap(),
            ))),
            principal_id: principal,
            display_name: Some("Alice".into()),
            handle_label: None,
            display_name_rank: 0,
            role: SpaceParticipantRole::Member,
            is_self: true,
            is_agent: false,
            agent_metadata: None,
        };
        let content = controller_summary(
            app.scope(),
            context,
            &controller,
            std::slice::from_ref(&controller),
            "Alice".into(),
            "2 agents".into(),
        );
        let mut content = Some(content);
        let open = app.scope().cage(false);
        app.mount(
            sapid::collapsible("participant-contract")
                .label("Show 2 agents for Alice")
                .open(open)
                .on_open_change(move |next| {
                    open.revise(|value| *value = next);
                })
                .trigger_content(move || content.take().unwrap_or_else(empty))
                .content(|| text().content("Agent details")),
        )
        .unwrap();
        fn trigger(
            tree: &glory::render::memory::Memory,
            id: glory::render::NodeId,
        ) -> Option<glory::render::NodeId> {
            let node = tree.node(id).unwrap();
            if matches!(
                node.descriptor.view().props,
                glory::render::Props::Button(_)
            ) {
                return Some(id);
            }
            node.children.iter().find_map(|id| trigger(tree, *id))
        }
        let button = {
            let tree = app.tree();
            tree.roots()
                .iter()
                .find_map(|id| trigger(&tree, *id))
                .unwrap()
        };
        for expected in [true, false, true] {
            assert!(
                app.dispatch(button, glory::render::Event::Activate)
                    .unwrap()
            );
            app.flush().unwrap();
            assert_eq!(open.get_untracked(), expected);
            let tree = app.tree();
            let descriptor = tree.node(button).unwrap().descriptor.view();
            assert_eq!(
                descriptor.semantics.as_ref().unwrap().expanded,
                Some(expected)
            );
        }
    }
}
