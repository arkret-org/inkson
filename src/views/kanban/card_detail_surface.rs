use super::*;

#[derive(Clone)]
pub(super) struct CardDetailContext {
    pub principal_id: arkret_sdk::DidCoreId,
    pub authority: arkret_sdk::AccountId,
    pub device_id: arkret_sdk::DeviceId,
    pub selected_realm_id: String,
    pub projection_realm_id: String,
    pub synthesis_entries: glory::Bond<Vec<CardSynthesisTrackEntry>>,
    pub selected_scope_security_encrypted: glory::Bond<Option<bool>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct CardTrackEditContext {
    pub(super) source_strand_id: String,
}

fn canonicalized_edit_target(
    previous: &str,
    next: &str,
    aliases: &BTreeMap<String, String>,
) -> bool {
    !previous.is_empty()
        && previous != next
        && resolve_event_derived_target_alias(aliases, previous) == next
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SuspendedTrackEdit {
    pub(super) scope: CardEditScope,
    pub(super) synthesis: String,
    pub(super) synthesis_target_id: Option<String>,
}

/// Preserve Synthesis drafts when switching cards. Summary / Calendar edits
/// target `metadata.*` and are unaffected.
pub(super) fn suspend_track_edit(
    scope: CardEditScope,
    synthesis: String,
    synthesis_target_id: Option<String>,
) -> Option<SuspendedTrackEdit> {
    (scope == CardEditScope::Synthesis).then_some(SuspendedTrackEdit {
        scope,
        synthesis,
        synthesis_target_id,
    })
}

/// Keep a content-editing session attached to the visible content tab. Drafts
/// live in separate signals, so moving between Description and Synthesis can
/// reveal the matching editor without discarding either draft. Summary and
/// Calendar forms are independent of the content tabs and remain untouched.
pub(super) fn content_edit_scope_for_tab(
    editing: bool,
    current_scope: CardEditScope,
    tab: CardDetailContentTab,
) -> Option<CardEditScope> {
    if !editing
        || !matches!(
            current_scope,
            CardEditScope::Description | CardEditScope::Synthesis
        )
    {
        return None;
    }

    match tab {
        CardDetailContentTab::Description => Some(CardEditScope::Description),
        CardDetailContentTab::Synthesis => Some(CardEditScope::Synthesis),
        CardDetailContentTab::Discussion => None,
    }
}

fn card_owned_agent_rows(
    joined_members: Option<&BTreeSet<arkret_sdk::ActorId>>,
    inventory: &BTreeMap<String, String>,
    station: &arkret_sdk::DidCoreId,
) -> Vec<(String, String)> {
    // Display roster pages are demand-loaded. Only the complete verified
    // current cut can enumerate joined owned Agents independently of them.
    let Some(joined_members) = joined_members else {
        return Vec::new();
    };
    let mut agents = inventory
        .iter()
        .filter_map(|(principal, slug)| {
            let principal = arkret_sdk::DidCoreId::new(principal.clone()).ok()?;
            let joined_actor = joined_members.iter().find(|actor| {
                actor.as_account_id().is_some_and(|account| {
                    account.principal_id == principal && account.station_id == *station
                })
            })?;
            Some((joined_actor.to_string(), slug.clone()))
        })
        .collect::<Vec<_>>();
    agents.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    agents
}

#[cfg(test)]
mod edit_identity_tests {
    use super::*;

    #[test]
    fn owned_agents_use_complete_joined_current_independently_of_display_roster() {
        let local = arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let remote = arkret_sdk::DidCoreId::new("ak:did_core:web:remote.example").unwrap();
        let inventory = BTreeMap::from([
            (
                "ak:did_core:web:joined.example".to_owned(),
                "alpha".to_owned(),
            ),
            (
                "ak:did_core:web:absent.example".to_owned(),
                "beta".to_owned(),
            ),
            (
                "ak:did_core:web:knocking.example".to_owned(),
                "gamma".to_owned(),
            ),
            ("invalid".to_owned(), "invalid".to_owned()),
        ]);
        let actor = |principal: &str, station: &arkret_sdk::DidCoreId| {
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                arkret_sdk::DidCoreId::new(principal).unwrap(),
                station.clone(),
            ))
        };
        let joined = BTreeSet::from([
            actor("ak:did_core:web:joined.example", &local),
            actor("ak:did_core:web:absent.example", &remote),
            actor("ak:did_core:web:unowned.example", &local),
        ]);
        let rows = card_owned_agent_rows(Some(&joined), &inventory, &local);
        assert_eq!(
            rows,
            vec![(
                actor("ak:did_core:web:joined.example", &local).to_string(),
                "alpha".to_owned(),
            )]
        );
        assert!(card_owned_agent_rows(None, &inventory, &local).is_empty());
        assert!(card_owned_agent_rows(Some(&BTreeSet::new()), &inventory, &local).is_empty());
    }

    #[test]
    fn card_identity_reconciliation_preserves_the_draft_only_for_its_resolved_target() {
        let aliases = BTreeMap::from([
            ("pending-card".to_owned(), "submitted-card".to_owned()),
            ("submitted-card".to_owned(), "accepted-strand".to_owned()),
        ]);
        assert!(canonicalized_edit_target(
            "pending-card",
            "accepted-strand",
            &aliases
        ));
        assert!(!canonicalized_edit_target(
            "pending-card",
            "other-strand",
            &aliases
        ));
        assert!(!canonicalized_edit_target("", "accepted-strand", &aliases));
        assert!(!canonicalized_edit_target(
            "unknown-card",
            "accepted-strand",
            &aliases
        ));
    }
}

#[derive(Clone)]
struct Detail {
    app: Rc<InksonContext>,
    context: CardDetailContext,
    c: KanbanController,
    card: Cage<Option<KanbanCard>>,
    mentions: Cage<Option<crate::views::chat::MentionInsertRequest>>,
    agents: crate::presentation::widgets::Resource<BTreeMap<String, String>>,
    modes: glory::Bond<crate::views::chat::agent_modes::Modes>,
    probe: glory::Bond<crate::views::secure_send::ScopeSendProbe>,
}
impl Detail {
    fn close(&self) {
        let c = self.c;
        c.selected_card.revise(|value| *value = None);
        c.editing_card_detail.revise(|value| *value = false);
        c.card_detail_actions_open.revise(|value| *value = false);
        self.app.replace_route(kanban_card_detail_board_route(
            &self.context.selected_realm_id,
            c.selected_board.get_untracked().as_ref(),
        ));
    }
    fn tab(&self, tab: CardDetailContentTab) {
        let c = self.c;
        if let Some(scope) = content_edit_scope_for_tab(
            c.editing_card_detail.get_untracked(),
            c.card_edit_scope.get_untracked(),
            tab,
        ) {
            c.card_edit_scope.revise(|value| *value = scope);
        }
        c.card_detail_tab.revise(|value| *value = tab);
        if tab == CardDetailContentTab::Discussion
            && let Some(card) = c.selected_card.get_untracked()
        {
            c.card_detail_discussion_mounted_for
                .revise(|value| *value = Some(card.primary_strand_id));
        }
        replace_card_detail_tab_query(self.app.clone(), tab);
    }
    fn begin(&self, scope: CardEditScope, entry: Option<CardSynthesisTrackEntry>) {
        let c = self.c;
        let Some(current) = c.selected_card.get_untracked() else {
            return;
        };
        if !card_detail_edit_ready(&current) {
            return;
        }
        prepare_selected_card_for_edit(c.selected_card);
        let draft = card_detail_draft_from_card(&current);
        c.card_edit_title.revise(|v| *v = draft.title);
        c.card_edit_description.revise(|v| *v = draft.description);
        c.card_edit_body.revise(|v| *v = draft.description_body);
        c.card_edit_labels.revise(|v| *v = draft.labels.join(", "));
        c.card_edit_assignee.revise(|v| *v = draft.assignee);
        c.card_edit_due.revise(|v| *v = draft.due);
        c.card_edit_calendar.revise(|v| *v = draft.calendar);
        if scope == CardEditScope::Synthesis {
            c.card_edit_synthesis.revise(|v| {
                *v = entry
                    .as_ref()
                    .map(|entry| entry.body.clone())
                    .unwrap_or_default()
            });
            c.card_edit_synthesis_target_id
                .revise(|v| *v = entry.map(|entry| entry.id));
        } else {
            c.card_edit_synthesis.revise(|v| *v = draft.synthesis);
            c.card_edit_synthesis_target_id.revise(|v| *v = None);
        }
        c.card_edit_scope.revise(|v| *v = scope);
        c.card_detail_edit_status.revise(|v| v.clear());
        c.editing_card_detail.revise(|v| *v = true);
        c.card_detail_actions_open.revise(|v| *v = false);
    }
    fn cancel(&self) {
        let c = self.c;
        let Some(current) = c.selected_card.get_untracked() else {
            return;
        };
        reset_card_detail_edit(
            &current,
            c.card_edit_title,
            c.card_edit_description,
            c.card_edit_body,
            c.card_edit_synthesis,
            c.card_edit_synthesis_target_id,
            c.card_edit_labels,
            c.card_edit_assignee,
            c.card_edit_due,
            c.editing_card_detail,
            c.card_detail_actions_open,
            c.card_synthesis_history_open_id,
            c.card_synthesis_selected_revision_id,
            c.card_detail_edit_status,
        );
    }
    fn save(&self) {
        let c = self.c;
        let Some(current) = c.selected_card.get_untracked() else {
            return;
        };
        let app = self.app.clone();
        let context = self.context.clone();
        let entries = context.synthesis_entries.get_untracked();
        let secure = context.selected_scope_security_encrypted.get_untracked();
        let window = app.clone();
        spawn_write(window, async move {
            save_card_detail_edit(
                app.clone(),
                app.base_url.get_untracked(),
                app.token,
                context.selected_realm_id,
                context.principal_id.to_string(),
                context.device_id.to_string(),
                current,
                entries,
                secure,
                None,
                c.card_edit_scope,
                c.card_edit_title,
                c.card_edit_description,
                c.card_edit_body,
                c.card_edit_synthesis,
                c.card_edit_synthesis_target_id,
                c.card_edit_labels,
                c.card_edit_assignee,
                c.card_edit_due,
                c.editing_card_detail,
                c.card_detail_actions_open,
                c.card_detail_edit_status,
                c.selected_card,
                app.state_store.clone(),
                c.board_status,
            )
            .await;
        });
    }
    fn due(&self, value: String) {
        let c = self.c;
        let Some(current) = c.selected_card.get_untracked() else {
            return;
        };
        let app = self.app.clone();
        let context = self.context.clone();
        let window = app.clone();
        spawn_write(window, async move {
            let _ = save_card_due_edit(
                app.clone(),
                app.base_url.get_untracked(),
                app.token,
                context.selected_realm_id,
                context.principal_id.to_string(),
                context.device_id.to_string(),
                current,
                value,
                context.selected_scope_security_encrypted.get_untracked(),
                c.due_picker_open,
                c.due_edit_status,
                c.selected_card,
                app.state_store.clone(),
                c.board_status,
            )
            .await;
        });
    }
    fn calendar(&self) {
        let c = self.c;
        let Some(current) = c.selected_card.get_untracked() else {
            return;
        };
        let calendar = c.card_edit_calendar.get_untracked();
        let app = self.app.clone();
        let context = self.context.clone();
        let window = app.clone();
        spawn_write(window, async move {
            let _ = save_card_calendar_edit(
                app.clone(),
                app.base_url.get_untracked(),
                app.token,
                context.selected_realm_id,
                context.principal_id.to_string(),
                context.device_id.to_string(),
                current,
                calendar,
                context.selected_scope_security_encrypted.get_untracked(),
                c.editing_card_detail,
                c.card_detail_actions_open,
                c.card_detail_edit_status,
                c.selected_card,
                app.state_store.clone(),
                c.board_status,
            )
            .await;
        });
    }
    fn assignees(&self) {
        let c = self.c;
        let Some(current) = c.selected_card.get_untracked() else {
            return;
        };
        if dispatch_card_assignees_update(
            self.app.clone(),
            self.app.base_url.get_untracked(),
            self.app.token,
            self.context.selected_realm_id.clone(),
            self.context.principal_id.to_string(),
            current,
            c.assignee_selected_actor_ids.get_untracked(),
            c.selected_card,
            self.app.state_store.clone(),
            c.board_status,
            c.assignee_edit_status,
        ) {
            c.assignee_picker_open.revise(|v| *v = false);
            c.assignee_filter.revise(String::clear);
        }
    }
    fn lifecycle(&self, target: StrandLifecycleState) {
        let Some(card) = self.c.selected_card.get_untracked() else {
            return;
        };
        if !card_detail_edit_ready(&card)
            || !matches!(
                (card.lifecycle, target),
                (StrandLifecycleState::Active, StrandLifecycleState::Archived)
                    | (StrandLifecycleState::Archived, StrandLifecycleState::Active)
            )
        {
            return;
        }
        dispatch_strand_lifecycle(
            self.app.clone(),
            self.app.base_url.get_untracked(),
            self.app.token,
            self.context.selected_realm_id.clone(),
            self.context.principal_id.to_string(),
            card.id,
            target,
            self.app.state_store.clone(),
            self.c.board_status,
        );
        self.close();
    }
    fn mention(&self, actor: arkret_sdk::AccountId, agent: bool) {
        self.tab(CardDetailContentTab::Discussion);
        self.mentions
            .revise(|v| *v = Some(crate::views::chat::MentionInsertRequest::new(actor, agent)));
    }
}
pub(super) fn card_detail(
    scope: &Scope,
    app: Rc<InksonContext>,
    c: KanbanController,
    context: CardDetailContext,
) -> View {
    let agents = {
        let app = app.clone();
        crate::presentation::widgets::resource(scope, move || {
            let base = app.base_url.get();
            let credential = app.token.get();
            let _ = app.owned_agents_rev.get();
            async move {
                if credential.trim().is_empty() {
                    return Err("authenticated Agent inventory is unavailable".into());
                }
                with_authed_sdk_client(&base, credential, |http| async move {
                    let response = http.agent_page().await?;
                    Ok(crate::views::agents::mentionable_owned_agent_slugs(
                        response.agents,
                    ))
                })
                .await
                .map_err(|error| error.display())
            }
        })
    };
    let key = {
        let app = app.clone();
        let context = context.clone();
        let agents = agents.clone();
        scope.bond(move || {
            let inventory = agents
                .data
                .get()
                .and_then(|result| result.ok())
                .unwrap_or_default();
            let credential = app.token.get();
            let _ = app.state_revision.get();
            let sync_ready = crate::app::account_sync_ready(&app.sync_cursor.get());
            app.state_store.read(|store| {
                let joined = store
                    .complete_joined_member_hint_for_realm(&context.selected_realm_id)
                    .ok()
                    .flatten();
                let accounts = crate::operation::authoring_station_id()
                    .ok()
                    .map(|station| {
                        card_owned_agent_rows(joined.as_ref(), &inventory, &station)
                            .into_iter()
                            .filter_map(|(actor, _)| {
                                serde_json::from_str::<arkret_sdk::ActorId>(&actor).ok()
                            })
                            .filter_map(|actor| actor.as_account_id().cloned())
                            .collect()
                    })
                    .unwrap_or_default();
                crate::views::chat::agent_modes::AgentModeReadKey {
                    base: app.base_url.get_untracked(),
                    authority: context.authority.clone(),
                    realm: context.selected_realm_id.clone(),
                    credential: credential.clone(),
                    session_epoch: crate::identity::device_directory::session_cache_epoch(),
                    sync_ready,
                    ready: store.current_product_view_ready(&context.selected_realm_id),
                    complete: store.current_product_view().is_some_and(|view| {
                        view.realm_id == context.selected_realm_id && view.complete_cut
                    }),
                    reset: store.current_reset_required(),
                    head: arkret_sdk::RealmId::new(context.selected_realm_id.clone())
                        .ok()
                        .and_then(|realm_id| {
                            store
                                .verified_commit_stream_cursor(
                                    &arkret_sdk::CommitStreamRef::Realm { realm_id },
                                )
                                .ok()
                                .flatten()
                        }),
                    accounts,
                }
            })
        })
    };
    let modes = crate::views::chat::agent_modes::agent_modes(
        scope,
        app.clone(),
        key.into(),
        "card_members",
    );
    let probe = crate::views::secure_send::scope_send_probe(
        scope,
        app.clone(),
        glory::Lotus::from(
            arkret_sdk::RealmId::new(context.selected_realm_id.clone())
                .ok()
                .map(|realm_id| arkret_sdk::ScopeRef::Realm { realm_id }),
        ),
        glory::Lotus::from(context.device_id.clone()),
    );
    let retained = retained_card(scope, app.clone(), c.selected_card, &context);
    let detail = Detail {
        card: retained,
        app: app.clone(),
        context,
        c,
        mentions: scope.cage(None),
        agents,
        modes,
        probe,
    };
    {
        let app = app.clone();
        scope.effect(move || {
            let next = CardTrackEditContext {
                source_strand_id: retained
                    .get()
                    .map(|card| card.primary_strand_id)
                    .unwrap_or_default(),
            };
            let previous = c.card_edit_context_seen.get_untracked();
            if previous == next {
                return;
            }
            let aliases = app
                .state_store
                .read(|store| event_derived_target_aliases(&store.load().raw_operations));
            if canonicalized_edit_target(
                &previous.source_strand_id,
                &next.source_strand_id,
                &aliases,
            ) {
                c.card_edit_context_seen.revise(|v| *v = next);
                return;
            }
            if c.editing_card_detail.get_untracked() {
                if let Some(edit) = suspend_track_edit(
                    c.card_edit_scope.get_untracked(),
                    c.card_edit_synthesis.get_untracked(),
                    c.card_edit_synthesis_target_id.get_untracked(),
                ) && !previous.source_strand_id.is_empty()
                {
                    c.suspended_shared_track_edits
                        .revise(|edits| edits.insert(previous.source_strand_id, edit));
                }
                c.editing_card_detail.revise(|v| *v = false);
                c.card_detail_actions_open.revise(|v| *v = false);
                c.card_detail_edit_status.revise(|v| v.clear());
                c.card_edit_synthesis_target_id.revise(|v| *v = None);
            }
            let suspended = c
                .suspended_shared_track_edits
                .revise(|edits| edits.remove(&next.source_strand_id));
            c.card_edit_context_seen.revise(|v| *v = next);
            if let Some(edit) = suspended {
                c.card_edit_scope.revise(|v| *v = edit.scope);
                c.card_edit_synthesis.revise(|v| *v = edit.synthesis);
                c.card_edit_synthesis_target_id
                    .revise(|v| *v = edit.synthesis_target_id);
                c.editing_card_detail.revise(|v| *v = true);
            }
        });
    }
    let target = card_detail_target(scope, retained);
    let authority = detail.context.authority.clone();
    let device = detail.context.device_id.clone();
    let realm = detail.context.selected_realm_id.clone();
    let target = scope.bond(move || {
        target
            .get()
            .map(|(id, strand)| (authority.clone(), device.clone(), realm.clone(), id, strand))
    });
    crate::presentation::widgets::reactive_distinct(target, move |scope, target| {
        let Some((_, _, _, id, strand)) = target else {
            return empty();
        };
        match retained
            .get_untracked()
            .filter(|card| card.id == id && card.primary_strand_id == strand)
        {
            Some(card) => detail_surface(scope, detail.clone(), card),
            None => empty(),
        }
    })
}

fn retained_card(
    scope: &Scope,
    app: Rc<InksonContext>,
    selected: Cage<Option<KanbanCard>>,
    context: &CardDetailContext,
) -> Cage<Option<KanbanCard>> {
    let retained = scope.cage(None::<KanbanCard>);
    let authority = context.authority.clone();
    let device = context.device_id.clone();
    let realm = context.selected_realm_id.clone();
    scope.effect(move || {
        let active = app.active_account.get();
        let route = app.route.get();
        let _ = app.state_revision.get();
        let current = selected.get();
        let route_realm = match &route {
            Route::KanbanTask { realm_id, .. } | Route::KanbanBoardTask { realm_id, .. } => {
                Some(realm_id.as_str())
            }
            _ => None,
        };
        let target = route_card_strand_id(&route);
        let same_account = active
            .as_ref()
            .is_some_and(|active| active.authority == authority && active.device_id == device);
        let denied = app
            .state_store
            .read(|store| store.account_scope_read_denied(&realm));
        let next = if same_account && route_realm == Some(realm.as_str()) && !denied {
            target.and_then(|target| {
                let aliases = app
                    .state_store
                    .read(|store| event_derived_target_aliases(&store.load().raw_operations));
                let target = resolve_event_derived_target_alias(&aliases, &target);
                let matches = |card: &KanbanCard| {
                    resolve_event_derived_target_alias(&aliases, &card.id) == target
                        || resolve_event_derived_target_alias(&aliases, &card.primary_strand_id)
                            == target
                };
                current
                    .filter(|card| matches(card))
                    .or_else(|| retained.get_untracked().filter(|card| matches(card)))
            })
        } else {
            None
        };
        if retained.get_untracked() != next {
            retained.revise(|value| *value = next);
        }
    });
    retained
}

fn card_detail_target(
    scope: &Scope,
    selected: Cage<Option<KanbanCard>>,
) -> glory::Bond<Option<(String, String)>> {
    scope.bond(move || selected.get().map(|card| (card.id, card.primary_strand_id)))
}
fn discussion_suspended(
    scope: &Scope,
    selected: Cage<Option<KanbanCard>>,
    strand: String,
) -> glory::Bond<bool> {
    scope.bond(move || {
        selected.get().is_none_or(|card| {
            card.primary_strand_id != strand || !card_discussion_target_ready(&card)
        })
    })
}

fn icon(
    scope: &Scope,
    detail: &Detail,
    key: &str,
    label: &str,
    name: &str,
    handler: impl FnMut() + 'static,
) -> View {
    Box::new(
        sapid::button()
            .unstyled()
            .class(format!(
                "card-detail-header-button card-detail-icon-button {key}"
            ))
            .name(detail.app.translated(scope, label))
            .fill(crate::components::ui_icon(name))
            .on_press(handler),
    )
}
fn detail_surface(scope: &Scope, detail: Detail, card: KanbanCard) -> View {
    let c = detail.c;
    let close = detail.clone();
    let content = detail.clone();
    let current = card.clone();
    let style = scope.bond(move || {
        if c.card_detail_docked.get() {
            glory::style::Style::new()
                .width(glory::style::Length::Px(c.card_detail_dock_width.get()))
        } else {
            glory::style::Style::new()
        }
    });
    let popup = sapid::dialog("kanban-card-detail-dialog")
        .unstyled()
        .class(scope.bond(move || {
            format!(
                "card-detail-popup card-detail-modal{}",
                if c.card_detail_docked.get() {
                    " is-docked"
                } else {
                    ""
                }
            )
        }))
        .name({
            let initial = card.title.clone();
            let displayed = detail.card;
            scope.bond(move || {
                displayed
                    .get()
                    .map(|card| card.title)
                    .unwrap_or_else(|| initial.clone())
            })
        })
        .open(true)
        .show_trigger(false)
        .show_close(false)
        .style(style)
        .on_dismiss(move |_| close.close())
        .content(move || {
            let detail = content.clone();
            let card = current.clone();
            glory::prelude::widget(move |scope| {
                detail_contents(scope, detail.clone(), card.clone()).build(scope)
            })
        });
    Box::new(
        glory::prelude::view()
            .class(scope.bond(move || {
                format!(
                    "card-detail-overlay{}",
                    if c.card_detail_docked.get() {
                        " is-docked"
                    } else {
                        ""
                    }
                )
            }))
            .fill(popup),
    )
}
fn detail_contents(scope: &Scope, detail: Detail, card: KanbanCard) -> View {
    let c = detail.c;
    let displayed = detail.card;
    let app = detail.app.clone();
    let close = detail.clone();
    let share = detail.clone();
    let card_id = card.id.clone();
    let share_button = icon(
        scope,
        &detail,
        "card-detail-share-link-button",
        "kanban.ui.copy_strand_link",
        "share",
        move || {
            share_kanban_strand_link(
                share.app.clone(),
                &strand_detail_deep_link_path_with_tab(
                    &share.context.selected_realm_id,
                    &card_id,
                    c.card_detail_tab.get_untracked(),
                ),
            )
        },
    );
    let sidebar = icon(
        scope,
        &detail,
        "card-detail-sidebar-toggle",
        "kanban.ui.show_details",
        "panel-right-open",
        move || {
            c.card_detail_sidebar_visible
                .revise(|value| *value = !*value)
        },
    );
    let dock = icon(
        scope,
        &detail,
        "card-detail-dock-toggle",
        "kanban.ui.dock_to_side",
        "minimize",
        move || {
            let next = c.card_detail_docked.revise(|value| {
                *value = !*value;
                *value
            });
            persist_card_detail_docked(next);
        },
    );
    let more = icon(
        scope,
        &detail,
        "card-detail-actions-button",
        "kanban.ui.actions",
        "more-horizontal",
        move || c.card_detail_actions_open.revise(|value| *value = !*value),
    );
    let close_button = icon(
        scope,
        &detail,
        "card-detail-close-button",
        "kanban.ui.close_card_detail",
        "x",
        move || close.close(),
    );
    let resize = Box::new(
        glory::prelude::view()
            .class("card-detail-resize-handle")
            .style(scope.bond(move || {
                glory::style::Style::new().display(if c.card_detail_docked.get() {
                    glory::style::Display::Block
                } else {
                    glory::style::Display::None
                })
            }))
            .name("Resize task details")
            .semantics(Some(Box::new(glory::render::Semantics {
                drag_capture: Some(glory::render::DragCapture::Press),
                ..Default::default()
            })))
            .on(glory::render::EventKind::Drag, move |event| {
                let glory::render::Event::Drag { phase, x, .. } = event else {
                    return;
                };
                use glory::render::DragPhase;
                match phase {
                    DragPhase::Start => {
                        c.card_detail_resizing.revise(|v| *v = true);
                        c.card_detail_resize_start_x.revise(|v| *v = x);
                        c.card_detail_resize_start_width
                            .revise(|v| *v = c.card_detail_dock_width.get_untracked());
                    }
                    DragPhase::Move => {
                        if c.card_detail_resizing.get_untracked() {
                            let next = (c.card_detail_resize_start_width.get_untracked()
                                + c.card_detail_resize_start_x.get_untracked()
                                - x)
                                .clamp(CARD_DETAIL_DOCK_WIDTH_MIN, CARD_DETAIL_DOCK_WIDTH_MAX);
                            c.card_detail_dock_width.revise(|v| *v = next);
                        }
                    }
                    DragPhase::Drop => {
                        c.card_detail_resizing.revise(|v| *v = false);
                        persist_card_detail_dock_width(c.card_detail_dock_width.get_untracked());
                    }
                    DragPhase::Cancel => {
                        c.card_detail_resizing.revise(|v| *v = false);
                    }
                }
            })
            .style(scope.bond(move || {
                glory::style::Style::new().display(if c.card_detail_docked.get() {
                    glory::style::Display::Block
                } else {
                    glory::style::Display::None
                })
            })),
    ) as View;
    let menu = {
        let detail = detail.clone();
        reactive(
            scope.bond(move || {
                (
                    c.card_detail_actions_open.get(),
                    c.editing_card_detail.get()
                        && c.card_edit_scope.get() == CardEditScope::Summary,
                )
            }),
            move |scope, (open, editing)| {
                if !open {
                    return empty();
                }
                if editing {
                    return stack(
                        "card-detail-actions-menu card-detail-action-menu is-editing",
                        vec![
                            stack(
                                "card-detail-action-menu-field",
                                vec![input(
                                    scope,
                                    detail.app.clone(),
                                    "card-detail-labels-input",
                                    "kanban.ui.labels",
                                    c.card_edit_labels,
                                    true,
                                )],
                            ),
                            stack(
                                "card-detail-action-menu-field",
                                vec![input(
                                    scope,
                                    detail.app.clone(),
                                    "card-detail-due-input",
                                    "kanban.ui.due",
                                    c.card_edit_due,
                                    true,
                                )],
                            ),
                        ],
                    );
                }
                let edit = detail.clone();
                let ready = scope.bond(move || {
                    c.selected_card
                        .get()
                        .is_some_and(|card| card_detail_edit_ready(&card))
                });
                let mut actions = vec![action(
                    scope,
                    detail.app.clone(),
                    "card-detail-menu-edit-button",
                    "common.edit",
                    "secondary card-detail-action-menu-item",
                    ready,
                    move || edit.begin(CardEditScope::Summary, None),
                )];
                if let Some(card) = c.selected_card.get_untracked()
                    && matches!(
                        card.lifecycle,
                        StrandLifecycleState::Active | StrandLifecycleState::Archived
                    )
                {
                    let restore = card.lifecycle == StrandLifecycleState::Archived;
                    let target = if restore {
                        StrandLifecycleState::Active
                    } else {
                        StrandLifecycleState::Archived
                    };
                    let lifecycle = detail.clone();
                    actions.push(action(
                        scope,
                        detail.app.clone(),
                        if restore {
                            "card-detail-restore-button"
                        } else {
                            "card-detail-archive-button"
                        },
                        if restore {
                            "kanban.restore_action"
                        } else {
                            "kanban.archive_action"
                        },
                        "secondary card-detail-action-menu-item",
                        ready,
                        move || lifecycle.lifecycle(target),
                    ));
                }
                stack("card-detail-actions-menu card-detail-action-menu", actions)
            },
        )
    };
    let summary = {
        let detail = detail.clone();
        let card = card.clone();
        reactive(
            scope.bond(move || {
                let editing = c.editing_card_detail.get();
                let kind = c.card_edit_scope.get();
                let card = if editing && kind == CardEditScope::Summary {
                    None
                } else {
                    displayed.get()
                };
                (editing, kind, card)
            }),
            move |scope, (editing, kind, current)| {
                let card = current.unwrap_or_else(|| card.clone());
                if editing && kind == CardEditScope::Summary {
                    let save = detail.clone();
                    let cancel = detail.clone();
                    stack(
                        "workflow-form card-detail-section card-detail-edit-form",
                        vec![
                            line(
                                "card-detail-section-head",
                                vec![line(
                                    "card-detail-section-title",
                                    vec![crate::components::ui_icon("file"), plain("Summary")],
                                )],
                            ),
                            input(
                                scope,
                                detail.app.clone(),
                                "card-detail-title-input",
                                "kanban.ui.card_title",
                                c.card_edit_title,
                                true,
                            ),
                            field(
                                scope,
                                detail.app.clone(),
                                "card-detail-summary-input",
                                "Summary",
                                c.card_edit_description,
                                true,
                                true,
                                move |next| c.card_edit_description.revise(|v| *v = next),
                            ),
                            input(
                                scope,
                                detail.app.clone(),
                                "card-detail-edit-labels",
                                "kanban.ui.labels",
                                c.card_edit_labels,
                                true,
                            ),
                            edit_actions(
                                scope,
                                detail.app.clone(),
                                c.card_detail_edit_status,
                                {
                                    let probe = detail.probe;
                                    scope.bond(move || probe.get().gate.is_some())
                                },
                                move || save.save(),
                                move || cancel.cancel(),
                            ),
                        ],
                    )
                } else {
                    let edit = detail.clone();
                    stack(
                        "card-detail-section card-detail-summary-section",
                        vec![
                            line(
                                "card-detail-section-head",
                                vec![
                                    line(
                                        "card-detail-section-title",
                                        vec![crate::components::ui_icon("file"), plain("Summary")],
                                    ),
                                    action(
                                        scope,
                                        detail.app.clone(),
                                        "card-detail-edit-button",
                                        "common.edit",
                                        "secondary card-detail-mini-action card-detail-edit-action",
                                        card_detail_edit_ready(&card),
                                        move || edit.begin(CardEditScope::Summary, None),
                                    ),
                                ],
                            ),
                            if card_summary_text(&card.description).is_empty() {
                                paragraph(
                                    "card-detail-empty",
                                    detail.app.translated(scope, "kanban.ui.no_summary"),
                                )
                            } else {
                                paragraph(
                                    "card-detail-summary card-summary",
                                    card_summary_text(&card.description),
                                )
                            },
                        ],
                    )
                }
            },
        )
    };
    let mut tabs = vec![];
    for (tab, key, label) in [
        (
            CardDetailContentTab::Description,
            "card-detail-tab-description",
            "kanban.ui.description",
        ),
        (
            CardDetailContentTab::Synthesis,
            "card-detail-tab-synthesis",
            "kanban.ui.synthesis",
        ),
        (
            CardDetailContentTab::Discussion,
            "card-detail-tab-discussion",
            "kanban.ui.discussion",
        ),
    ] {
        let detail = detail.clone();
        tabs.push(Box::new(
            glory::ui::button()
                .class(scope.bond(move || {
                    format!(
                        "card-detail-tab {key}{}",
                        if c.card_detail_tab.get() == tab {
                            " active"
                        } else {
                            ""
                        }
                    )
                }))
                .label(app.translated(scope, label))
                .semantics(scope.bond(move || {
                    Some(Box::new(glory::render::Semantics {
                        tab: true,
                        selected: Some(c.card_detail_tab.get() == tab),
                        ..Default::default()
                    }))
                }))
                .on(glory::render::EventKind::Activate, move |_| detail.tab(tab)),
        ) as View);
    }
    let narrative = narrative(scope, detail.clone(), card.clone());
    let discussion = {
        let detail = detail.clone();
        let initial_strand_id = card.primary_strand_id.clone();
        let suspended = discussion_suspended(scope, c.selected_card, initial_strand_id.clone());
        let started = scope.cage(false);
        let target = initial_strand_id.clone();
        scope.effect(move || {
            if c.card_detail_discussion_mounted_for.get().as_deref() == Some(target.as_str())
                && !suspended.get()
                && !started.get_untracked()
            {
                started.revise(|value| *value = true);
            }
        });
        let target = initial_strand_id.clone();
        let visible = scope.bond(move || {
            if started.get() {
                (true, false)
            } else {
                (
                    false,
                    c.card_detail_discussion_mounted_for.get().as_deref() == Some(target.as_str()),
                )
            }
        });
        crate::presentation::widgets::reactive_distinct(
            visible,
            move |scope, (started, requested)| {
                if !started {
                    return if requested {
                        paragraph("card-detail-empty card-discussion-pending-target",detail.app.translated(scope,"kanban.ui.discussion_will_be_available_when_this_card_finishes_syncing"))
                    } else {
                        empty()
                    };
                }
                let initial_strand_id = initial_strand_id.clone();
                let chat = crate::views::chat::chat_panel(
                    scope,
                    detail.app.clone(),
                    crate::views::chat::ChatPanelProps {
                        selected_realm_id: detail.context.selected_realm_id.clone(),
                        initial_strand_id,
                        embedded: true,
                        source_suspended: suspended.into(),
                        direct_mode: false,
                        direct_peer_id: String::new(),
                        sidecar_session: None,
                        focus_message_id: String::new(),
                        mention_insert_request: Some(detail.mentions),
                    },
                );
                Box::new(
                    glory::prelude::view()
                        .class(scope.bond(move || {
                            format!(
                                "card-detail-discussion-panel card-discussion-panel{}",
                                if c.card_detail_tab.get() == CardDetailContentTab::Discussion {
                                    ""
                                } else {
                                    " is-hidden"
                                }
                            )
                        }))
                        .style(scope.bond(move || {
                            glory::style::Style::new().display(
                                if c.card_detail_tab.get() == CardDetailContentTab::Discussion {
                                    glory::style::Display::Block
                                } else {
                                    glory::style::Display::None
                                },
                            )
                        }))
                        .fill(chat),
                )
            },
        )
    };
    let right = sidebar_view(scope, detail.clone(), card.clone());
    let title = {
        let detail = detail.clone();
        let initial = card.clone();
        let security = detail.context.selected_scope_security_encrypted;
        reactive(
            scope.bond(move || (displayed.get(), security.get())),
            move |scope, (current, inherited)| {
                let card = current.unwrap_or_else(|| initial.clone());
                let encrypted = card.security_encrypted.or(inherited);
                let mut badges = vec![crate::components::write_state_badge(
                    scope,
                    detail.app.clone(),
                    crate::components::WriteStateBadgeProps {
                        state: card.state.write_state(),
                        icon_only: None,
                    },
                )];
                badges.extend(
                    card.labels
                        .iter()
                        .map(|label| paragraph("badge", label.clone())),
                );
                stack(
                    "card-detail-title-block",
                    vec![line(
                        "card-detail-title-row",
                        vec![
                            crate::components::security_state_badge(
                                scope,
                                detail.app.clone(),
                                crate::components::SecurityStateBadgeProps {
                                    encrypted: encrypted.unwrap_or(true),
                                    compact: true,
                                    test_id: Some("strand-detail-security-state".into()),
                                    unknown: encrypted.is_none(),
                                },
                            ),
                            heading(
                                2,
                                "",
                                kanban_title_label(
                                    &card.title,
                                    &card.id,
                                    &crate::i18n::tr("kanban.title_pending"),
                                ),
                            ),
                            line("card-detail-title-meta", badges),
                        ],
                    )],
                )
            },
        )
    };
    Box::new(glory::prelude::group().fill(vec![
            resize,
            line(
                "card-detail-header",
                vec![
                    title,
                    line(
                        "card-detail-header-actions",
                        vec![
                            share_button,
                            sidebar,
                            dock,
                            stack("card-detail-action-menu-wrap", vec![more, menu]),
                            close_button,
                        ],
                    ),
                ],
            ),
            Box::new(
                glory::prelude::view()
                    .class(scope.bond(move || {
                        if c.card_detail_sidebar_visible.get() {
                            "card-detail-layout"
                        } else {
                            "card-detail-layout no-sidebar"
                        }
                        .to_owned()
                    }))
                    .fill(vec![
                        stack(
                            "card-detail-main",
                            vec![
                                summary,
                                stack(
                                    "card-detail-section card-detail-tabs-section",
                                    vec![
                                        Box::new(
                                            glory::ui::view()
                                                .role(glory::render::Role::TabList)
                                                .class("card-detail-tabs")
                                                .fill(tabs),
                                        ),
                                        narrative,
                                        discussion,
                                    ],
                                ),
                            ],
                        ),
                        right,
                    ]),
            ),
        ]))
}

fn render_body(scope: &Scope, app: Rc<InksonContext>, body: &str) -> View {
    let blocks = crate::content::renderer::parse_message_body(body);
    crate::content::render_blocks(scope, app, &blocks)
}
fn track_editor(scope: &Scope, detail: Detail, synthesis: bool) -> View {
    let c = detail.c;
    let save = detail.clone();
    let cancel = detail.clone();
    let value = if synthesis {
        c.card_edit_synthesis
    } else {
        c.card_edit_body
    };
    let allow_image = detail
        .context
        .selected_scope_security_encrypted
        .get_untracked()
        == Some(false);
    let ready = {
        let probe = detail.probe;
        scope.bond(move || probe.get().gate.is_some())
    };
    stack(
        "workflow-form card-detail-edit-form",
        vec![
            card_markdown_editor(
                scope,
                detail.app.clone(),
                if synthesis {
                    "card-detail-synthesis-input"
                } else {
                    "card-detail-description-input"
                },
                &crate::i18n::tr(if synthesis {
                    "kanban.ui.synthesis"
                } else {
                    "kanban.ui.description"
                }),
                value,
                detail.context.selected_realm_id.clone(),
                allow_image,
            ),
            paragraph("muted", {
                let probe = detail.probe;
                scope.bond(move || {
                    let probe = probe.get();
                    probe.blocked_reason.unwrap_or_else(|| {
                        if probe.checking {
                            "Checking sync and encryption readiness...".into()
                        } else {
                            String::new()
                        }
                    })
                })
            }),
            edit_actions(
                scope,
                detail.app.clone(),
                c.card_detail_edit_status,
                ready,
                move || save.save(),
                move || cancel.cancel(),
            ),
        ],
    )
}
fn synthesis_revision(
    entry: &CardSynthesisTrackEntry,
    selected: Option<&str>,
) -> (CardSynthesisRevision, bool, usize) {
    let latest = entry
        .revisions
        .last()
        .cloned()
        .unwrap_or_else(|| CardSynthesisRevision {
            id: entry.id.clone(),
            body: entry.body.clone(),
            actor_id: entry.actor_id.clone(),
            author_label: entry.author_label.clone(),
            timestamp_label: entry.timestamp_label.clone(),
            sort_key: entry.sort_key.clone(),
        });
    let revision = selected
        .and_then(|id| entry.revisions.iter().find(|revision| revision.id == id))
        .cloned()
        .unwrap_or_else(|| latest.clone());
    let version = entry
        .revisions
        .iter()
        .position(|candidate| candidate.id == revision.id)
        .unwrap_or(entry.revisions.len().saturating_sub(1))
        + 1;
    let is_latest = revision.id == latest.id;
    (revision, is_latest, version)
}

fn synthesis_entry(
    scope: &Scope,
    detail: Detail,
    entry: CardSynthesisTrackEntry,
    editing: bool,
    can_edit: bool,
) -> View {
    let c = detail.c;
    let show_history = c.card_synthesis_history_open_id;
    let show_edit = !c.editing_card_detail.get_untracked();
    let selected_history = c.card_synthesis_selected_revision_id;
    let selected_entry = entry.clone();
    let displayed =
        scope.bond(move || synthesis_revision(&selected_entry, selected_history.get().as_deref()));
    let principal = detail.context.principal_id.to_string();
    let class = scope.bond(move || {
        let (revision, latest, _) = displayed.get();
        format!(
            "card-synthesis-entry {}{}",
            if latest { "is-latest" } else { "is-history" },
            if actor_is_current_account(&revision.actor_id, &principal) {
                " is-own"
            } else {
                ""
            }
        )
    });
    let header_detail = detail.clone();
    let header_entry = entry.clone();
    let header = crate::presentation::widgets::reactive_distinct(
        displayed,
        move |scope, (revision, latest, version)| {
            let own = actor_is_current_account(
                &revision.actor_id,
                header_detail.context.principal_id.as_str(),
            );
            let author = crate::components::actor_identity_label(
                scope,
                header_detail.app.clone(),
                crate::components::ActorIdentityLabelProps {
                    label: revision.author_label,
                    title: Some(if revision.actor_id.trim().is_empty() {
                        crate::i18n::tr("kanban.ui.unknown_author")
                    } else {
                        revision.actor_id
                    }),
                    class: Some("card-synthesis-author".into()),
                    test_id: Some("card-synthesis-author".into()),
                    self_badge_test_id: Some("card-synthesis-self-badge".into()),
                    is_self: own,
                    ..Default::default()
                },
            );
            let mut head = vec![
                author,
                Box::new(
                    glory::ui::text()
                        .content(revision.timestamp_label)
                        .class("card-synthesis-time"),
                ) as View,
                Box::new(
                    glory::ui::text()
                        .content(format!("v{version}"))
                        .class("badge"),
                ),
            ];
            head.push(Box::new(
                glory::ui::text()
                    .content(if latest {
                        "latest".into()
                    } else {
                        crate::i18n::tr("kanban.ui.historical_version")
                    })
                    .class(if latest {
                        "badge badge-success"
                    } else {
                        "badge badge-warning"
                    }),
            ));
            if !latest {
                head.push(action(
                    scope,
                    header_detail.app.clone(),
                    "card-synthesis-latest-button",
                    "kanban.ui.latest",
                    "secondary badge card-synthesis-latest-button",
                    true,
                    move || {
                        selected_history.revise(|value| *value = None);
                        show_history.revise(|value| *value = None);
                    },
                ));
            }
            if header_entry.revisions.len() > 1 {
                let entry_id = header_entry.id.clone();
                let trigger = Box::new(
                    sapid::button()
                        .unstyled()
                        .class("secondary badge card-synthesis-history-trigger")
                        .label("edited")
                        .on_press(move || {
                            show_history.revise(|open| {
                                *open = if open.as_deref() == Some(entry_id.as_str()) {
                                    None
                                } else {
                                    Some(entry_id.clone())
                                }
                            })
                        }),
                ) as View;
                let revisions = header_entry.clone();
                let history_app = header_detail.app.clone();
                let principal = header_detail.context.principal_id.to_string();
                let menu = reactive(show_history, move |scope, open| {
                    if open.as_deref() != Some(revisions.id.as_str()) {
                        return empty();
                    }
                    let selected =
                        synthesis_revision(&revisions, selected_history.get_untracked().as_deref())
                            .0
                            .id;
                    let latest = revisions
                        .revisions
                        .last()
                        .map(|revision| revision.id.as_str());
                    let mut items = vec![paragraph(
                        "card-synthesis-history-title",
                        crate::i18n::tr("kanban.ui.history"),
                    )];
                    for (index, revision) in revisions.revisions.iter().enumerate().rev() {
                        let id = revision.id.clone();
                        let is_latest = Some(id.as_str()) == latest;
                        let summary = card_summary_text(&revision.body);
                        let preview = if summary.chars().count() > 72 {
                            format!("{}...", summary.chars().take(72).collect::<String>())
                        } else {
                            summary
                        };
                        let mut content = vec![inline_label("badge", format!("v{}", index + 1))];
                        if is_latest {
                            content.push(inline_label(
                                "badge badge-success card-synthesis-history-latest",
                                "latest",
                            ));
                        }
                        content.push(inline_label(
                            "card-synthesis-history-author",
                            revision.author_label.clone(),
                        ));
                        if actor_is_current_account(&revision.actor_id, &principal) {
                            content.push(crate::components::self_attribution_badge_inline(
                                scope,
                                history_app.clone(),
                                crate::components::SelfAttributionBadgeProps {
                                    class: Some("card-synthesis-history-self-badge".into()),
                                    test_id: Some("card-synthesis-history-self-badge".into()),
                                },
                            ));
                        }
                        content.push(inline_label(
                            "card-synthesis-history-time",
                            revision.timestamp_label.clone(),
                        ));
                        content.push(inline_label("card-synthesis-history-preview", preview));
                        items.push(Box::new(
                            sapid::button()
                                .unstyled()
                                .class(if id == selected {
                                    "secondary card-synthesis-history-item active"
                                } else {
                                    "secondary card-synthesis-history-item"
                                })
                                .name(format!(
                                    "v{} {} {}",
                                    index + 1,
                                    revision.author_label,
                                    revision.timestamp_label
                                ))
                                .fill(content)
                                .on_press(move || {
                                    selected_history
                                        .revise(|value| *value = (!is_latest).then(|| id.clone()));
                                    show_history.revise(|value| *value = None);
                                }),
                        ));
                    }
                    stack("card-synthesis-history-menu", items)
                });
                head.push(stack("card-synthesis-history-wrap", vec![trigger, menu]));
            }
            if show_edit {
                let edit = header_detail.clone();
                let target = header_entry.clone();
                head.push(action(
                    scope,
                    header_detail.app.clone(),
                    "card-detail-edit-synthesis-button",
                    "common.edit",
                    "secondary card-detail-mini-action card-synthesis-entry-edit",
                    can_edit,
                    move || edit.begin(CardEditScope::Synthesis, Some(target.clone())),
                ));
            }
            line("card-synthesis-entry-head", head)
        },
    );
    let body = if editing {
        track_editor(scope, detail, true)
    } else {
        let app = detail.app;
        crate::presentation::widgets::reactive_distinct(displayed, move |scope, (revision, ..)| {
            render_body(scope, app.clone(), &revision.body)
        })
    };
    Box::new(glory::ui::view().class(class).fill(vec![header, body]))
}

fn narrative(scope: &Scope, detail: Detail, card: KanbanCard) -> View {
    let c = detail.c;
    let displayed = detail.card;
    let source = scope.bond(move || {
        (
            c.card_detail_tab.get(),
            c.editing_card_detail.get(),
            c.card_edit_scope.get(),
            if c.editing_card_detail.get()
                && matches!(
                    c.card_edit_scope.get(),
                    CardEditScope::Description | CardEditScope::Synthesis
                )
            {
                None
            } else {
                displayed.get()
            },
        )
    });
    crate::presentation::widgets::reactive_distinct(
        source,
        move |scope, (tab, editing, kind, current)| {
            let card = current.unwrap_or_else(|| card.clone());
            match tab {
                CardDetailContentTab::Discussion => empty(),
                CardDetailContentTab::Description => {
                    if editing && kind == CardEditScope::Description {
                        return track_editor(scope, detail.clone(), false);
                    }
                    let mut children = vec![];
                    if card.description_locked {
                        children.push(paragraph(
                            "card-detail-empty card-detail-description-locked",
                            MLS_LOCKED_FIELD_PLACEHOLDER,
                        ));
                    } else {
                        children.push(if card.description_body.trim().is_empty() {
                            paragraph(
                                "card-detail-empty",
                                detail.app.translated(scope, "kanban.ui.no_description"),
                            )
                        } else {
                            stack(
                                "card-detail-description card-description-body",
                                vec![render_body(
                                    scope,
                                    detail.app.clone(),
                                    &card.description_body,
                                )],
                            )
                        });
                        let edit = detail.clone();
                        children.push(line(
                            "card-synthesis-footer-action",
                            vec![action(
                                scope,
                                detail.app.clone(),
                                "card-detail-edit-description-button",
                                "common.edit",
                                "secondary card-detail-mini-action",
                                card_detail_edit_ready(&card),
                                move || edit.begin(CardEditScope::Description, None),
                            )],
                        ));
                    }
                    stack(
                        "card-detail-tab-panel card-detail-synthesis-panel card-description-panel",
                        children,
                    )
                }
                CardDetailContentTab::Synthesis => {
                    if card.synthesis_locked {
                        return paragraph(
                            "card-detail-empty card-detail-synthesis-locked",
                            MLS_LOCKED_FIELD_PLACEHOLDER,
                        );
                    }
                    let detail = detail.clone();
                    let can_edit = card_detail_edit_ready(&card);
                    crate::presentation::widgets::reactive_distinct(
                        detail.context.synthesis_entries,
                        move |scope, entries| {
                            let mut children = vec![];
                            if entries.is_empty() {
                                children.push(paragraph(
                                    "card-detail-empty",
                                    detail.app.translated(scope, "kanban.ui.no_synthesis_yet"),
                                ));
                            }
                            for entry in entries {
                                let editing_this = editing
                                    && kind == CardEditScope::Synthesis
                                    && c.card_edit_synthesis_target_id.get_untracked().as_deref()
                                        == Some(entry.id.as_str());
                                children.push(synthesis_entry(
                                    scope,
                                    detail.clone(),
                                    entry,
                                    editing_this,
                                    can_edit,
                                ));
                            }
                            if editing
                                && kind == CardEditScope::Synthesis
                                && c.card_edit_synthesis_target_id.get_untracked().is_none()
                            {
                                children.push(track_editor(scope, detail.clone(), true));
                            } else {
                                let new = detail.clone();
                                children.push(line(
                                    "card-synthesis-footer-action",
                                    vec![action(
                                        scope,
                                        detail.app.clone(),
                                        "card-detail-new-synthesis-button",
                                        "kanban.ui.new",
                                        "secondary card-detail-mini-action",
                                        can_edit,
                                        move || new.begin(CardEditScope::Synthesis, None),
                                    )],
                                ));
                            }
                            stack(
                                "card-detail-tab-panel card-synthesis-panel",
                                vec![stack("card-synthesis-track", children)],
                            )
                        },
                    )
                }
            }
        },
    )
}

fn sidebar_view(scope: &Scope, detail: Detail, card: KanbanCard) -> View {
    let c = detail.c;
    let displayed = detail.card;
    let app = detail.app.clone();
    let panel_detail = detail.clone();
    let content = reactive(
        scope.bond(move || {
            (
                c.card_detail_sidebar_tab.get(),
                app.state_revision.get(),
                app.realm_live_epoch.get(),
                displayed.get(),
            )
        }),
        move |scope, (tab, _, _, current)| {
            let card = current.unwrap_or_else(|| card.clone());
            let (realm, rows) = panel_detail.app.state_store.read(|store| {
                let loaded = store.load();
                let projection = loaded
                    .realm_tree_projections
                    .get(&panel_detail.context.selected_realm_id);
                (
                    member_roster_realm_context(
                        &panel_detail.context.selected_realm_id,
                        &panel_detail.context.projection_realm_id,
                        projection,
                    ),
                    realm_member_roster(projection),
                )
            });
            let mut tabs = vec![];
            for (kind, key, label) in [
                (
                    CardDetailSidebarTab::Details,
                    "card-detail-sidebar-tab-details",
                    crate::i18n::tr("kanban.ui.details"),
                ),
                (
                    CardDetailSidebarTab::Members,
                    "card-detail-sidebar-tab-members",
                    crate::i18n::tr_args(
                        "kanban.ui.member_count",
                        &[("count", rows.len().to_string())],
                    ),
                ),
            ] {
                tabs.push(Box::new(
                    glory::ui::button()
                        .class(format!(
                            "card-detail-tab {key}{}",
                            if kind == tab { " active" } else { "" }
                        ))
                        .label(label)
                        .semantics(Some(Box::new(glory::render::Semantics {
                            tab: true,
                            selected: Some(kind == tab),
                            ..Default::default()
                        })))
                        .on(glory::render::EventKind::Activate, move |_| {
                            c.card_detail_sidebar_tab.revise(|value| *value = kind)
                        }),
                ) as View);
            }
            let body = match tab {
                CardDetailSidebarTab::Details => {
                    details_fields(scope, panel_detail.clone(), card.clone(), realm, rows)
                }
                CardDetailSidebarTab::Members => {
                    member_list(scope, panel_detail.clone(), card.clone(), realm, rows)
                }
            };
            stack(
                "card-detail-sidebar-content",
                vec![
                    Box::new(
                        glory::ui::view()
                            .role(glory::render::Role::TabList)
                            .class("card-detail-tabs card-detail-sidebar-tabs")
                            .fill(tabs),
                    ),
                    body,
                ],
            )
        },
    );
    Box::new(
        glory::prelude::view()
            .class("card-detail-sidebar")
            .style(scope.bond(move || {
                if c.card_detail_sidebar_visible.get() {
                    glory::style::Style::new()
                } else {
                    glory::style::Style::new().display(glory::style::Display::None)
                }
            }))
            .fill(content),
    )
}
fn side_field(label: &str, body: View) -> View {
    Box::new(glory::ui::group().fill(vec![
        Box::new(glory::ui::view().document_part(glory::render::DocumentPart::Term)
            .class("card-detail-field-label").fill(plain(crate::i18n::tr(label)))) as View,
        Box::new(glory::ui::view().document_part(glory::render::DocumentPart::Definition)
            .class("card-detail-field-value").fill(body)) as View,
    ]))
}

fn assignee_avatar(
    scope: &Scope,
    app: Rc<InksonContext>,
    actor: &arkret_sdk::ActorId,
    label: &str,
) -> View {
    crate::components::generated_avatar::identity_avatar_inline(
        scope,
        app,
        crate::components::IdentityAvatarProps {
            seed: actor.to_string(),
            alt_text: label.to_owned(),
            blob_ref: None,
            class: "avatar-img assignee-avatar".into(),
            test_id: None,
        },
    )
}

pub(super) fn inline_label(class: &str, value: impl Into<glory::Lotus<String>>) -> View {
    Box::new(glory::ui::text().class(class.to_owned()).content(value))
}

fn strand_identity(scope: &Scope, strand: &str) -> View {
    let identity =
        match glory::render::SemanticId::new(format!("card-strand-{}", scope.id().slot())) {
            Ok(id) => id,
            Err(error) => {
                scope.report_error(error);
                return empty();
            }
        };
    Box::new(
        glory::ui::view()
            .role(glory::render::Role::Group)
            .class("card-detail-strand-identity")
            .semantics(Some(Box::new(glory::render::Semantics {
                described_by: Some(identity.clone()),
                ..Default::default()
            })))
            .fill((
                glory::ui::text()
                    .kind(glory::render::TextKind::Paragraph)
                    .class("card-detail-field-code")
                    .content(short_protocol_id(strand)),
                glory::ui::text()
                    .class("sr-only")
                    .content(strand.to_owned())
                    .semantics(Some(Box::new(glory::render::Semantics {
                        id: Some(identity),
                        ..Default::default()
                    }))),
            )),
    )
}

fn details_fields(
    scope: &Scope,
    detail: Detail,
    card: KanbanCard,
    realm: String,
    rows: Vec<crate::views::member_display::RealmMemberRow>,
) -> View {
    let c = detail.c;
    let assigned = card_assigned_actor_ids(&card);
    let names = detail.app.state_store.read(|store| {
        assigned
            .iter()
            .map(|actor| {
                (
                    actor.clone(),
                    assignee_label_for_actor(store, &realm, &rows, actor),
                )
            })
            .collect::<Vec<_>>()
    });
    let pick = detail.clone();
    let chosen = assigned.iter().cloned().collect::<BTreeSet<_>>();
    let mut row = vec![line(
        "assignee-chip-list",
        names
            .into_iter()
            .map(|(actor, label)| {
                line(
                    "assignee-chip",
                    vec![
                        assignee_avatar(scope, detail.app.clone(), &actor, &label),
                        inline_label("assignee-chip-label", label),
                    ],
                )
            })
            .collect(),
    )];
    let mut add_children = vec![crate::components::ui_icon("plus")];
    if assigned.is_empty() {
        add_children.push(plain(
            detail.app.translated(scope, "kanban.ui.add_assignees"),
        ));
    }
    row.push(Box::new(
        sapid::button()
            .unstyled()
            .class(if assigned.is_empty() {
                "assignee-add assignee-add-empty card-detail-assignee-add"
            } else {
                "assignee-add card-detail-assignee-add"
            })
            .name(detail.app.translated(scope, "kanban.ui.add_assignees"))
            .enabled(card_detail_edit_ready(&card))
            .fill(add_children)
            .on_press(move || {
                c.assignee_selected_actor_ids
                    .revise(|value| *value = chosen.clone());
                c.assignee_filter.revise(String::clear);
                c.assignee_edit_status.revise(String::clear);
                c.assignee_picker_open.revise(|value| *value = !*value);
            }),
    ));
    if !assigned.is_empty() {
        let clear = detail.clone();
        row.push(Box::new(
            sapid::button()
                .unstyled()
                .class("assignee-add assignee-clear")
                .name(detail.app.translated(scope, "kanban.ui.clear_assignees"))
                .enabled(card_detail_edit_ready(&card))
                .fill(crate::components::ui_icon("x"))
                .on_press(move || {
                    c.assignee_selected_actor_ids.revise(BTreeSet::clear);
                    clear.assignees();
                }),
        ));
    }
    let assignees = stack(
        "assignee-editor card-detail-assignees",
        vec![
            line("assignee-chip-row", row),
            assignee_picker(scope, pick, card.clone(), realm, rows),
        ],
    );
    let due = card.due.clone();
    let due_editor = due_picker(scope, detail.clone());
    let has_due = !due.trim().is_empty();
    let mut due_children = Vec::new();
    if has_due {
        due_children.push(inline_label("due-pill due-date-value", due.clone()));
    }
    let mut trigger_content = vec![crate::components::ui_icon("calendar")];
    if !has_due {
        trigger_content.push(plain(
            detail.app.translated(scope, "kanban.ui.add_due_date"),
        ));
    }
    due_children.push(Box::new(
        sapid::button()
            .unstyled()
            .class(if has_due {
                "due-edit-button card-detail-due-trigger"
            } else {
                "due-add-button card-detail-due-trigger"
            })
            .name(detail.app.translated(
                scope,
                if has_due {
                    "kanban.ui.edit_due_date"
                } else {
                    "kanban.ui.add_due_date"
                },
            ))
            .enabled(card_detail_edit_ready(&card))
            .fill(trigger_content)
            .on_press(move || {
                c.due_edit_value.revise(|v| *v = due.clone());
                c.due_calendar_month
                    .revise(|v| *v = due_calendar_month_for_value(&due));
                c.due_edit_status.revise(String::clear);
                c.due_picker_open.revise(|v| *v = true);
            }),
    ));
    if has_due {
        let clear = detail.clone();
        due_children.push(Box::new(
            sapid::button()
                .unstyled()
                .class("due-edit-button due-clear-button")
                .name(detail.app.translated(scope, "kanban.ui.clear_due_date"))
                .enabled(card_detail_edit_ready(&card))
                .fill(crate::components::ui_icon("x"))
                .on_press(move || clear.due(String::new())),
        ));
    }
    due_children.push(due_editor);
    let due_view = line("due-editor card-detail-due", due_children);
    let mut fields = vec![
        side_field("kanban.ui.strand_id", strand_identity(scope, &card.id)),
        side_field("kanban.ui.assignees", assignees),
        side_field("kanban.ui.due", due_view),
    ];
    fields.push(side_field(
        "kanban.ui.labels",
        line(
            "card-labels",
            card.labels
                .iter()
                .map(|label| paragraph("card-label", label.clone()))
                .collect(),
        ),
    ));
    fields.push(side_field(
        "kanban.ui.calendar",
        calendar_view(scope, detail.clone(), card.clone()),
    ));
    fields.push(side_field(
        "Security",
        crate::components::security_state_badge(
            scope,
            detail.app.clone(),
            crate::components::SecurityStateBadgeProps {
                encrypted: card.security_encrypted.unwrap_or(true),
                compact: false,
                test_id: Some("card-detail-security-badge".into()),
                unknown: card.security_encrypted.is_none(),
            },
        ),
    ));
    fields.push(side_field(
        "Discussion scope",
        paragraph("", card.external_visibility),
    ));
    stack(
        "card-detail-side-fields card-fields",
        vec![Box::new(
            glory::ui::view()
                .document_part(glory::render::DocumentPart::DescriptionList)
                .class("card-detail-field-list semantic-card-fields")
                .fill(fields),
        )],
    )
}
fn assignee_picker(
    _scope: &Scope,
    detail: Detail,
    card: KanbanCard,
    realm: String,
    rows: Vec<crate::views::member_display::RealmMemberRow>,
) -> View {
    let c = detail.c;
    reactive(c.assignee_picker_open, move |scope, open| {
        if !open {
            return empty();
        }
        let options = assignment_picker_roster(&rows, &card);
        let detail_rows = detail.clone();
        let realm = realm.clone();
        let rows = rows.clone();
        let body = reactive(c.assignee_filter, move |scope, filter| {
            let labels = detail_rows.app.state_store.read(|store| {
                options
                    .iter()
                    .filter_map(|row| {
                        let label = assignee_label_for_actor(store, &realm, &rows, &row.actor_id);
                        assignee_filter_matches(&filter, &label, &row.actor_id.to_string())
                            .then(|| (row.actor_id.clone(), label))
                    })
                    .collect::<Vec<_>>()
            });
            if labels.is_empty() {
                return paragraph(
                    "assignee-option-empty",
                    crate::i18n::tr("kanban.ui.no_members_match"),
                );
            }
            stack(
                "assignee-options assignee-picker-list",
                labels
                    .into_iter()
                    .map(|(actor, label)| {
                        let selected_actor = actor.clone();
                        let selected = scope.bond(move || {
                            c.assignee_selected_actor_ids
                                .get()
                                .contains(&selected_actor)
                        });
                        let short_id = short_protocol_id(actor.to_string());
                        let avatar =
                            assignee_avatar(scope, detail_rows.app.clone(), &actor, &label);
                        let semantics = scope.bond(move || {
                            Some(Box::new(glory::render::Semantics {
                                pressed: Some(selected.get()),
                                ..Default::default()
                            }))
                        });
                        Box::new(
                            glory::ui::button()
                                .class(scope.bond(move || {
                                    format!(
                                        "secondary assignee-option assignee-picker-option{}",
                                        if selected.get() { " selected" } else { "" }
                                    )
                                }))
                                .name(label.clone())
                                .semantics(semantics)
                                .fill(vec![
                                    inline_label(
                                        "assignee-option-check",
                                        scope.bond(move || {
                                            if selected.get() {
                                                "✓".into()
                                            } else {
                                                String::new()
                                            }
                                        }),
                                    ),
                                    avatar,
                                    inline_label("assignee-option-label", label),
                                    inline_label("assignee-option-meta", short_id),
                                ])
                                .on(glory::render::EventKind::Activate, move |_| {
                                    c.assignee_selected_actor_ids.revise(|values| {
                                        if !values.insert(actor.clone()) {
                                            values.remove(&actor);
                                        }
                                    })
                                }),
                        ) as View
                    })
                    .collect(),
            )
        });
        let save = detail.clone();
        stack(
            "assignee-popover assignee-picker",
            vec![
                line(
                    "assignee-search",
                    vec![
                        crate::components::ui_icon("search"),
                        crate::views::settings::widgets::input_prompt(
                            scope,
                            detail
                                .app
                                .translated(scope, "kanban.ui.filter_members")
                                .into(),
                            c.assignee_filter,
                            Box::new(
                                sapid::text_field()
                                    .unstyled()
                                    .class("input card-detail-assignee-filter")
                                    .name(detail.app.translated(scope, "kanban.ui.filter_members"))
                                    .value(c.assignee_filter)
                                    .on_value_change(move |value| {
                                        c.assignee_filter.revise(|current| *current = value)
                                    }),
                            ),
                        ),
                    ],
                ),
                body,
                reactive(c.assignee_edit_status, |_scope, status| {
                    if status.trim().is_empty() {
                        empty()
                    } else {
                        paragraph("assignee-edit-status", status)
                    }
                }),
                line(
                    "assignee-popover-actions assignee-picker-actions",
                    vec![
                        action(
                            scope,
                            detail.app.clone(),
                            "card-detail-assignee-clear-draft",
                            "kanban.ui.clear",
                            "secondary",
                            true,
                            move || c.assignee_selected_actor_ids.revise(BTreeSet::clear),
                        ),
                        action(
                            scope,
                            detail.app.clone(),
                            "card-detail-assignee-cancel",
                            "common.cancel",
                            "secondary",
                            true,
                            move || {
                                c.assignee_picker_open.revise(|v| *v = false);
                                c.assignee_filter.revise(String::clear);
                                c.assignee_edit_status.revise(String::clear);
                            },
                        ),
                        action(
                            scope,
                            detail.app.clone(),
                            "card-detail-assignee-save",
                            "common.save",
                            "primary",
                            true,
                            move || save.assignees(),
                        ),
                    ],
                ),
            ],
        )
    })
}
fn due_picker(_scope: &Scope, detail: Detail) -> View {
    let c = detail.c;
    reactive(c.due_picker_open, move |scope, open| {
        if !open {
            return empty();
        }
        let body = detail.clone();
        crate::components::dismissible_popup(
            scope,
            detail.app.clone(),
            crate::components::DismissiblePopupProps {
                overlay_class: "due-date-modal-backdrop".into(),
                surface_class: "due-date-modal".into(),
                aria_label: crate::i18n::tr("kanban.ui.due_date_calendar"),
                on_dismiss: Rc::new(move |()| c.due_picker_open.revise(|value| *value = false)),
                children: Rc::new(move |scope| due_picker_contents(scope, body.clone())),
                overlay_test_id: Some("card-detail-due-editor-backdrop".into()),
                surface_test_id: Some("card-detail-due-editor-dialog".into()),
                overlay_style: None,
                surface_style: None,
            },
        )
    })
}
fn due_picker_contents(scope: &Scope, detail: Detail) -> View {
    let c = detail.c;
    let calendar = reactive(c.due_calendar_month, move |scope, month| {
        let prev = Box::new(
            sapid::button()
                .unstyled()
                .class("secondary due-calendar-nav due-date-month-prev")
                .name(crate::i18n::tr("kanban.ui.previous_month"))
                .label("‹")
                .on_press(move || {
                    c.due_calendar_month
                        .revise(|value| *value = add_due_calendar_months(*value, -1))
                }),
        ) as View;
        let next = Box::new(
            sapid::button()
                .unstyled()
                .class("secondary due-calendar-nav due-date-month-next")
                .name(crate::i18n::tr("kanban.ui.next_month"))
                .label("›")
                .on_press(move || {
                    c.due_calendar_month
                        .revise(|value| *value = add_due_calendar_months(*value, 1))
                }),
        ) as View;
        let weekdays = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"]
            .into_iter()
            .map(|day| plain(crate::i18n::tr(&format!("kanban.ui.{day}"))))
            .collect::<Vec<_>>();
        let mut days = Vec::<View>::new();
        for cell in due_calendar_cells(month) {
            let iso = cell.iso_date.clone();
            let selected = iso.clone();
            let is_today = cell.date == due_calendar_today();
            let class = scope.bond(move || {
                format!(
                    "secondary due-calendar-day{}{}{}",
                    if cell.in_current_month {
                        ""
                    } else {
                        " outside"
                    },
                    if c.due_edit_value.get() == selected {
                        " selected"
                    } else {
                        ""
                    },
                    if is_today { " today" } else { "" }
                )
            });
            let selected = iso.clone();
            let pressed = scope.bond(move || {
                Some(Box::new(glory::render::Semantics {
                    pressed: Some(c.due_edit_value.get() == selected),
                    ..Default::default()
                }))
            });
            days.push(Box::new(
                glory::ui::button()
                    .class(class)
                    .name(iso.clone())
                    .label(cell.day.to_string())
                    .semantics(pressed)
                    .on(glory::render::EventKind::Activate, move |_| {
                        c.due_edit_value.revise(|value| *value = iso.clone());
                        c.due_calendar_month
                            .revise(|value| *value = due_calendar_month_for_value(&iso));
                    }),
            ));
        }
        stack(
            "due-calendar",
            vec![
                line(
                    "due-calendar-header",
                    vec![
                        prev,
                        paragraph("due-calendar-title", due_calendar_month_label(month)),
                        next,
                    ],
                ),
                line("due-calendar-weekdays", weekdays),
                stack("due-calendar-grid", days),
            ],
        )
    });
    let save = detail.clone();
    let heading = stack(
        "due-date-modal-title",
        vec![
            heading(
                3,
                "",
                detail.app.translated(scope, "kanban.ui.set_due_date"),
            ),
            paragraph(
                "muted",
                detail
                    .app
                    .translated(scope, "kanban.ui.choose_a_date_for_this_card"),
            ),
        ],
    );
    let close = Box::new(
        sapid::button()
            .unstyled()
            .class("secondary due-date-modal-close")
            .name(detail.app.translated(scope, "common.close"))
            .fill(crate::components::ui_icon("x"))
            .on_press(move || c.due_picker_open.revise(|open| *open = false)),
    ) as View;
    let status = reactive(c.due_edit_status, |_, status| {
        if status.trim().is_empty() {
            empty()
        } else {
            paragraph("due-edit-status", status)
        }
    });
    Box::new(glory::prelude::group().fill(vec![
        line("due-date-modal-head", vec![heading, close]),
        stack(
            "due-date-modal-body card-detail-due-picker",
            vec![
                stack(
                    "due-date-modal-field",
                    vec![input(
                        scope,
                        detail.app.clone(),
                        "card-detail-due-value",
                        "kanban.ui.due",
                        c.due_edit_value,
                        true,
                    )],
                ),
                calendar,
                status,
            ],
        ),
        line(
            "due-date-modal-actions",
            vec![
                action(
                    scope,
                    detail.app.clone(),
                    "card-detail-due-today",
                    "Today",
                    "secondary",
                    true,
                    move || {
                        let today = due_calendar_today().format("%Y-%m-%d").to_string();
                        c.due_edit_value.revise(|value| *value = today);
                        c.due_calendar_month
                            .revise(|value| *value = default_due_calendar_month());
                    },
                ),
                action(
                    scope,
                    detail.app.clone(),
                    "card-detail-due-clear",
                    "kanban.ui.clear",
                    "secondary due-date-clear-action",
                    true,
                    move || {
                        c.due_edit_value.revise(String::clear);
                        c.due_calendar_month
                            .revise(|value| *value = default_due_calendar_month());
                    },
                ),
                action(
                    scope,
                    detail.app.clone(),
                    "card-detail-due-cancel",
                    "common.cancel",
                    "secondary",
                    true,
                    move || c.due_picker_open.revise(|open| *open = false),
                ),
                action(
                    scope,
                    detail.app.clone(),
                    "card-detail-due-save",
                    "common.save",
                    "primary",
                    {
                        let probe = detail.probe;
                        scope.bond(move || probe.get().gate.is_some())
                    },
                    move || save.due(c.due_edit_value.get_untracked()),
                ),
            ],
        ),
    ]))
}

fn calendar_view(scope: &Scope, detail: Detail, card: KanbanCard) -> View {
    let c = detail.c;
    reactive(
        scope.bond(move || (c.editing_card_detail.get(), c.card_edit_scope.get())),
        move |scope, (editing, kind)| {
            if editing && kind == CardEditScope::Calendar {
                let _save = detail.clone();
                let _cancel = detail.clone();
                let body = detail.clone();
                let cancel_popup = detail.clone();
                let original = card.calendar.clone();
                return crate::components::dismissible_popup(
                    scope,
                    detail.app.clone(),
                    crate::components::DismissiblePopupProps {
                        overlay_class: "due-date-modal-backdrop calendar-schedule-modal-backdrop"
                            .into(),
                        surface_class: "due-date-modal calendar-schedule-modal".into(),
                        aria_label: crate::i18n::tr("kanban.ui.calendar"),
                        on_dismiss: Rc::new(move |()| {
                            c.card_edit_calendar
                                .revise(|value| *value = original.clone());
                            cancel_popup.cancel();
                        }),
                        children: Rc::new(move |scope| {
                            let save = body.clone();
                            let cancel = body.clone();
                            let probe = body.probe;
                            stack("calendar-schedule-modal-content",vec![heading(3,"",body.app.translated(scope,"kanban.ui.edit_schedule")),paragraph("muted",body.app.translated(scope,"kanban.ui.set_the_event_time_recurrence_and_calendar_details")),calendar_schedule_edit_form(scope,body.app.clone(),c.card_edit_calendar,c.card_detail_edit_status,scope.bond(move||probe.get().gate.is_some()).into(),move||save.calendar(),move||cancel.cancel())])
                        }),
                        overlay_test_id: Some("card-detail-calendar-editor-backdrop".into()),
                        surface_test_id: Some("card-detail-calendar-editor-dialog".into()),
                        overlay_style: None,
                        surface_style: None,
                    },
                );
            }
            let schedule = &card.calendar;
            let mut children = vec![];
            if schedule.has_schedule() {
                let mut fields = vec![];
                for (label, value) in [
                    ("kanban.ui.start", schedule.start.clone()),
                    ("kanban.ui.end", schedule.end.clone()),
                    ("kanban.ui.timezone", schedule.timezone.clone()),
                    ("kanban.ui.status", schedule.status.clone()),
                    ("kanban.ui.recurrence", schedule.recurrence_label()),
                    (
                        "kanban.ui.location",
                        if schedule.location_locked {
                            MLS_LOCKED_FIELD_PLACEHOLDER.into()
                        } else {
                            schedule.location.clone()
                        },
                    ),
                ] {
                    if !value.is_empty() {
                        fields.push(line(
                            "calendar-summary-row",
                            vec![
                                paragraph("calendar-summary-label", crate::i18n::tr(label)),
                                paragraph("calendar-summary-value", value),
                            ],
                        ));
                    }
                }
                if schedule.all_day {
                    fields.push(paragraph(
                        "calendar-summary-mode",
                        crate::i18n::tr("kanban.ui.all_day"),
                    ));
                }
                children.push(stack("calendar-summary", fields));
                children.push(
                    match calendar_agenda(
                        schedule,
                        &card.calendar_schedule_basis_refs,
                        chrono::Utc::now(),
                    ) {
                        Ok(items) if !items.is_empty() => stack(
                            "calendar-agenda card-detail-calendar-agenda",
                            items
                                .into_iter()
                                .map(|item| {
                                    line(
                                        "calendar-agenda-item",
                                        vec![
                                            paragraph("calendar-agenda-start", item.local_start),
                                            paragraph("calendar-agenda-end", item.local_end),
                                        ],
                                    )
                                })
                                .collect(),
                        ),
                        Ok(_) => paragraph(
                            "card-detail-calendar-agenda-empty",
                            crate::i18n::tr("kanban.ui.no_occurrences_in_the_next_90_days"),
                        ),
                        Err(error) => paragraph("card-detail-calendar-agenda-unresolved", error),
                    },
                );
                children.push(rsvp_view(scope, detail.clone(), card.clone()));
            } else {
                children.push(paragraph(
                    "calendar-empty",
                    crate::i18n::tr("kanban.ui.no_schedule"),
                ));
            }
            let edit = detail.clone();
            let enabled = card_detail_edit_ready(&card);
            children.push(action(
                scope,
                detail.app.clone(),
                "card-detail-calendar-edit",
                "common.edit",
                "secondary",
                enabled,
                move || {
                    edit.begin(CardEditScope::Calendar, None);
                    c.calendar_rsvp_occurrence.revise(|v| {
                        *v = calendar_occurrence_hint(&c.card_edit_calendar.get_untracked())
                    });
                },
            ));
            stack("calendar-editor card-detail-calendar", children)
        },
    )
}
fn rsvp_view(scope: &Scope, detail: Detail, card: KanbanCard) -> View {
    let c = detail.c;
    let status = card.calendar_rsvp.clone();
    let mut children = vec![];
    if status.has_any() {
        if let Some(own) = status.own_status {
            children.push(paragraph("calendar-rsvp-own card-detail-rsvp-own", own));
        }
        if status.own_needs_reconfirmation {
            children.push(paragraph(
                "calendar-rsvp-reconfirm card-detail-rsvp-reconfirm",
                "Schedule changed. Please confirm your response again.",
            ));
        }
        children.push(paragraph(
            "calendar-rsvp-counts card-detail-rsvp-counts",
            format!(
                "{} yes · {} maybe · {} no",
                status.accepted, status.tentative, status.declined
            ),
        ));
        if status.excluded > 0 {
            children.push(paragraph(
                "calendar-rsvp-excluded card-detail-rsvp-excluded",
                format!("{} response(s) no longer count", status.excluded),
            ));
        }
    }
    children.push(input(
        scope,
        detail.app.clone(),
        "card-detail-calendar-rsvp-occurrence",
        "Occurrence",
        c.calendar_rsvp_occurrence,
        true,
    ));
    let mut buttons = vec![action(
        scope,
        detail.app.clone(),
        "card-detail-rsvp-series",
        "Entire series",
        "secondary",
        true,
        move || c.calendar_rsvp_occurrence.revise(String::clear),
    )];
    for (status, label) in [
        ("accepted", "Yes"),
        ("tentative", "Maybe"),
        ("declined", "No"),
    ] {
        let detail = detail.clone();
        let card = card.clone();
        buttons.push(Box::new(
            sapid::button()
                .unstyled()
                .class(format!("btn secondary card-detail-rsvp-{status}"))
                .label(label)
                .enabled(card.state == CardState::Synced)
                .on_press(move || {
                    dispatch_calendar_rsvp(
                        detail.app.clone(),
                        detail.app.base_url.get_untracked(),
                        detail.app.token,
                        detail.context.selected_realm_id.clone(),
                        detail.context.principal_id.to_string(),
                        card.clone(),
                        status,
                        c.calendar_rsvp_occurrence.get_untracked(),
                        detail.app.state_store.clone(),
                        c.board_status,
                    )
                }),
        ) as View);
    }
    children.push(line("calendar-rsvp-actions", buttons));
    stack("calendar-rsvp card-detail-calendar-rsvp", children)
}
fn member_list(
    scope: &Scope,
    detail: Detail,
    card: KanbanCard,
    realm: String,
    rows: Vec<crate::views::member_display::RealmMemberRow>,
) -> View {
    let agents = detail.agents.clone();
    let modes = detail.modes;
    reactive(
        scope.bond(move || (agents.data.get(), modes.get())),
        move |scope, (inventory, modes)| {
            let Some(inventory) = inventory else {
                return paragraph(
                    "card-detail-empty card-detail-member-identities-pending",
                    crate::i18n::tr("kanban.ui.members_loading"),
                );
            };
            let Ok(inventory) = inventory else {
                return paragraph(
                    "card-detail-empty card-detail-member-identities-error",
                    crate::i18n::tr("kanban.ui.members_unavailable"),
                );
            };
            let (joined, participants) = detail.app.state_store.read(|store| {
                (
                    store
                        .complete_joined_member_hint_for_realm(&detail.context.selected_realm_id)
                        .ok()
                        .flatten(),
                    strand_participant_ids(&store.load().raw_operations, &card.primary_strand_id)
                        .into_iter()
                        .collect::<BTreeSet<_>>(),
                )
            });
            let mut humans = rows
                .iter()
                .filter(|row| {
                    crate::views::member_display::owned_agent_slug(row, &inventory).is_none()
                })
                .collect::<Vec<_>>();
            humans.sort_by_key(|row| {
                !card_member_is_current_account(row, detail.context.principal_id.as_str())
            });
            let owned = crate::operation::authoring_station_id()
                .ok()
                .map(|station| card_owned_agent_rows(joined.as_ref(), &inventory, &station))
                .unwrap_or_default();
            let mut children = vec![];
            for row in humans {
                let is_self =
                    card_member_is_current_account(row, detail.context.principal_id.as_str());
                let label = detail.app.state_store.read(|store| {
                    crate::views::member_display::resolve_member_display(store, &realm, row).label
                });
                children.push(member_row(
                    scope,
                    detail.clone(),
                    row.actor_id.clone(),
                    label,
                    is_self,
                    None,
                    None,
                    participants.contains(&row.actor_id.to_string()),
                ));
                if is_self {
                    for (actor, slug) in &owned {
                        if let Ok(actor) = serde_json::from_str::<arkret_sdk::ActorId>(actor) {
                            let mode = actor
                                .as_account_id()
                                .and_then(|account| modes.get(account))
                                .copied();
                            let in_strand = participants.contains(&actor.to_string());
                            children.push(member_row(
                                scope,
                                detail.clone(),
                                actor,
                                slug.clone(),
                                false,
                                Some(slug.clone()),
                                mode,
                                in_strand,
                            ));
                        }
                    }
                }
            }
            if children.is_empty() {
                children.push(paragraph(
                    "card-detail-empty",
                    "No members yet for this Realm.",
                ));
            }
            stack("card-detail-actor-list card-detail-realm-members", children)
        },
    )
}
fn member_row(
    scope: &Scope,
    detail: Detail,
    actor: arkret_sdk::ActorId,
    label: String,
    is_self: bool,
    agent: Option<String>,
    mode: Option<arkret_sdk::AgentInteractionMode>,
    in_strand: bool,
) -> View {
    let account = actor.as_account_id().cloned();
    let is_agent = agent.is_some();
    let identity = account
        .as_ref()
        .map(|account| {
            let account_identity = format!(
                "Principal: {} · Station: {}",
                account.principal_id, account.station_id
            );
            if is_agent {
                format!("Agent: {} · {account_identity}", account.principal_id)
            } else {
                account_identity
            }
        })
        .unwrap_or_else(|| actor.to_string());
    use sha2::Digest;
    let identity_id = match glory::render::SemanticId::new(format!(
        "card-member-{}",
        hex::encode(sha2::Sha256::digest(actor.to_string().as_bytes()))
    )) {
        Ok(id) => id,
        Err(error) => {
            scope.report_error(error);
            return empty();
        }
    };
    let description_id = identity_id.clone();
    let mention_name = detail
        .app
        .translated_args(scope, "kanban.ui.mention_member", {
            let label = label.clone();
            move || vec![("name", label.clone())]
        });
    let mut children: Vec<View> = vec![];
    if let Some(slug) = agent.as_ref() {
        children.push(crate::components::generated_avatar::identity_avatar_inline(
            scope,
            detail.app.clone(),
            crate::components::IdentityAvatarProps {
                seed: actor.signing_principal_id().to_string(),
                alt_text: slug.clone(),
                blob_ref: None,
                class: "sidebar-nav-icon contact-sidebar-agent-avatar avatar-img".into(),
                test_id: None,
            },
        ));
        children.push(Box::new(
            glory::ui::text()
                .class("grow truncate card-detail-member")
                .content(slug.clone()),
        ));
        let (badge_class, badge_key) = match mode {
            Some(arkret_sdk::AgentInteractionMode::Public) => (
                "pill xs agent-mode-badge is-public",
                "app.sidebar.public_agent_badge",
            ),
            Some(arkret_sdk::AgentInteractionMode::Private) => (
                "pill xs agent-mode-badge is-private",
                "app.sidebar.private_agent_badge",
            ),
            None => ("pill muted xs", "app.sidebar.agent_badge"),
        };
        children.push(Box::new(
            glory::ui::text()
                .class(badge_class)
                .content(detail.app.translated(scope, badge_key)),
        ));
    } else {
        children.push(Box::new(
            glory::ui::text()
                .class(if in_strand {
                    "card-detail-actor-dot participant"
                } else {
                    "card-detail-actor-dot"
                })
                .content(""),
        ));
        children.push(Box::new(
            glory::ui::text()
                .class("card-detail-actor-id card-detail-member")
                .content(label),
        ));
        if is_self {
            children.push(crate::components::self_attribution_badge_inline(
                scope,
                detail.app.clone(),
                crate::components::SelfAttributionBadgeProps::default(),
            ));
        }
    }
    children.push(Box::new(
        glory::ui::text()
            .class("sr-only card-detail-member-identity")
            .content(identity)
            .semantics(Some(Box::new(glory::render::Semantics {
                id: Some(identity_id),
                ..Default::default()
            }))),
    ));
    let mention = Box::new(glory::ui::button()
        .class(if is_agent { "card-detail-actor-mention-button card-detail-agent-mention-button card-detail-member-mention-button" } else { "card-detail-actor-mention-button card-detail-member-mention-button" })
        .name(mention_name)
        .semantics(Some(Box::new(glory::render::Semantics { described_by: Some(description_id), ..Default::default() })))
        .enabled(account.is_some()).fill(children)
        .on(glory::render::EventKind::Activate, move |_| {
            if let Some(account) = account.clone() { detail.mention(account, is_agent); }
        })) as View;
    stack(
        format!(
            "card-detail-actor-row card-member-row{}{}",
            if is_agent {
                " participant-agent-row card-detail-agent-row"
            } else {
                ""
            },
            if in_strand { " participant" } else { "" }
        ),
        vec![mention],
    )
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod production_retention_tests {
    use glory::render::{Event, NodeId, Props};

    use super::*;
    fn nodes(app: &glory::ui::App) -> Vec<NodeId> {
        let tree = app.tree();
        let mut pending = tree.roots().to_vec();
        let mut out = Vec::new();
        while let Some(id) = pending.pop() {
            out.push(id);
            pending.extend(tree.node(id).unwrap().children.iter().copied());
        }
        out
    }
    fn input(app: &glory::ui::App) -> NodeId {
        nodes(app)
            .into_iter()
            .find(|id| {
                let tree = app.tree();
                let view = tree.node(*id).unwrap().descriptor.view();
                view.classes.iter().any(|class| class == "chat-input")
                    && matches!(view.props, Props::Input(_))
            })
            .expect("production embedded composer exists")
    }
    fn value(app: &glory::ui::App, id: NodeId) -> String {
        let tree = app.tree();
        match tree.node(id).unwrap().descriptor.view().props {
            Props::Input(input) => input.value.clone(),
            _ => panic!("message input"),
        }
    }
    fn class_node(app: &glory::ui::App, class: &str) -> NodeId {
        nodes(app)
            .into_iter()
            .find(|id| {
                app.tree()
                    .node(*id)
                    .unwrap()
                    .descriptor
                    .view()
                    .classes
                    .iter()
                    .any(|value| value == class)
            })
            .unwrap_or_else(|| panic!("missing production class {class}"))
    }
    fn text_content(app: &glory::ui::App, class: &str) -> String {
        let mut pending = vec![class_node(app, class)];
        let mut content = String::new();
        while let Some(id) = pending.pop() {
            let tree = app.tree();
            let node = tree.node(id).unwrap();
            if node
                .descriptor
                .view()
                .semantics
                .as_ref()
                .is_some_and(|value| value.hidden)
            {
                continue;
            }
            match node.descriptor.view().props {
                Props::Text(text) => content.push_str(&text.content),
                Props::Button(button) => content.push_str(&button.label),
                _ => {}
            }
            pending.extend(node.children.iter().rev().copied());
        }
        content
    }
    fn settle(app: &glory::ui::App, executor: &glory::core::executor::Executor) {
        for _ in 0..64 {
            executor.poll_one();
            app.flush().unwrap();
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn production_card_detail_keeps_chat_draft_owner_across_current_updates_and_gaps() {
        let directory = tempfile::Builder::new()
            .prefix("card-detail-owner-")
            .tempdir_in("D:/BuildCache/inkson-glory/tmp")
            .unwrap();
        let executor = Rc::new(glory::core::executor::Executor::new(256));
        let app = glory::ui::App::with_host(executor.clone(), glory::render::memory::Memory::new);
        let authority = crate::test_support::authority("ak:did_core:web:alice.example");
        let realm = super::super::tests::TEST_REALM_ID.to_string();
        let device =
            arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap();
        let account:crate::config::ActiveAccountContext=serde_json::from_value(serde_json::json!({"profile_id":"card-owner","authority":authority,"principal_control_realm_id":realm,"resolution":{"did":"did:web:alice.example","method_history_head":"head-1","version_id":"1","resolution_event_ref":"accepted-resolution","updated_at":"2026-10-20T00:00:00.000Z"},"device_id":device,"server_url":"https://browser.example/"})).unwrap();
        let config = crate::config::ClientConfig {
            active_account: Some(account),
            ..Default::default()
        };
        let make_card = |byte| {
            let id = arkret_sdk::StrandId::from_event_id(&arkret_sdk::EventId::from_digest(
                arkret_sdk::DigestSuite::Sha256,
                [byte; 32],
            ))
            .to_string();
            let mut card = super::super::tests::test_card(&id, "U");
            card.primary_strand_id = id;
            card.authoring_basis = Some(arkret_wire::CurrentRevision {
                commit_id: arkret_wire::RealmCommitId::from_digest([byte; 32]),
                stream_position: 1,
            });
            card
        };
        let mut first = make_card(0x37);
        let assigned_actor = arkret_sdk::ActorId::account(authority.clone());
        first.assigned_to_relations.push(CardAssignedToRelation {
            relation_id: "fixture-assigned-relation".into(),
            actor_id: assigned_actor.clone(),
        });
        first.due = "2026-10-15".into();
        let second = make_card(0x38);
        let route = Route::KanbanTask {
            realm_id: realm.clone(),
            task_id: first.id.clone(),
            tab: "discussion".into(),
        };
        let context = InksonContext::new(
            app.scope(),
            crate::presentation::BootState {
                config_store: crate::config::LocalConfigStore::with_path(
                    directory.path().join("config.json"),
                ),
                config,
                state_store: SharedStateStore::new(LocalStateStore::with_path(
                    directory.path().join("state.json"),
                )),
                initial_credential: String::new(),
                realm_tree_nodes: vec![],
            },
            route.clone(),
            |_| {
                Box::pin(async {
                    crate::runtime::session::CurrentSessionRefresh::retry_later("fixture")
                })
            },
        );
        let scope = app.scope();
        let c = new_kanban_controller(scope, &route, vec![], None);
        c.selected_card.revise(|value| *value = Some(first.clone()));
        c.card_detail_tab
            .revise(|value| *value = CardDetailContentTab::Discussion);
        c.card_detail_discussion_mounted_for
            .revise(|value| *value = Some(first.primary_strand_id.clone()));
        let suspended =
            discussion_suspended(scope, c.selected_card, first.primary_strand_id.clone());
        let revisions = vec![
            CardSynthesisRevision {
                id: "history-v1".into(),
                body: "Original synthesis".into(),
                actor_id: "did:web:bob.example".into(),
                author_label: "Bob".into(),
                timestamp_label: "Earlier".into(),
                sort_key: "1".into(),
            },
            CardSynthesisRevision {
                id: "history-v2".into(),
                body: "Updated synthesis".into(),
                actor_id: authority.principal_id.to_string(),
                author_label: "Alice".into(),
                timestamp_label: "Now".into(),
                sort_key: "2".into(),
            },
        ];
        let latest = revisions.last().unwrap().clone();
        let entries = vec![CardSynthesisTrackEntry {
            id: "synthesis-entry".into(),
            body: latest.body,
            actor_id: latest.actor_id,
            author_label: latest.author_label,
            timestamp_label: latest.timestamp_label,
            sort_key: latest.sort_key,
            edited: true,
            revisions,
        }];
        app.mount(card_detail(
            scope,
            context.clone(),
            c,
            CardDetailContext {
                principal_id: authority.principal_id.clone(),
                authority: authority.clone(),
                device_id: device.clone(),
                selected_realm_id: realm.clone(),
                projection_realm_id: realm.clone(),
                synthesis_entries: scope.bond(move || entries.clone()),
                selected_scope_security_encrypted: scope.bond(|| Some(false)),
            },
        ))
        .unwrap();
        settle(&app, &executor);
        // Exercise the actual production controls before checking the retained
        // discussion owner. The assigned actor remains visible without a roster.
        class_node(&app, "card-detail-header");
        class_node(&app, "card-detail-title-meta");
        class_node(&app, "card-detail-tabs-section");
        c.card_detail_sidebar_visible
            .revise(|visible| *visible = true);
        settle(&app, &executor);
        app.dispatch(
            class_node(&app, "card-detail-assignee-add"),
            Event::Activate,
        )
        .unwrap();
        settle(&app, &executor);
        class_node(&app, "assignee-popover");
        let option = class_node(&app, "assignee-option");
        assert!(
            c.assignee_selected_actor_ids
                .get_untracked()
                .contains(&assigned_actor)
        );
        app.dispatch(option, Event::Activate).unwrap();
        settle(&app, &executor);
        assert_eq!(
            class_node(&app, "assignee-option"),
            option,
            "selecting preserves the option node and focus"
        );
        assert!(
            !c.assignee_selected_actor_ids
                .get_untracked()
                .contains(&assigned_actor)
        );
        let filter = class_node(&app, "card-detail-assignee-filter");
        let revision = match app.tree().node(filter).unwrap().descriptor.view().props {
            Props::Input(input) => input.revision,
            _ => panic!("real assignee input"),
        };
        app.dispatch(
            filter,
            Event::ValueChanged {
                value: "no such member".into(),
                composing: false,
                revision,
            },
        )
        .unwrap();
        settle(&app, &executor);
        class_node(&app, "assignee-option-empty");
        app.dispatch(
            class_node(&app, "card-detail-assignee-cancel"),
            Event::Activate,
        )
        .unwrap();
        settle(&app, &executor);
        assert!(!c.assignee_picker_open.get_untracked());
        assert!(c.assignee_filter.get_untracked().is_empty());
        assert_eq!(
            card_assigned_actor_ids(&c.selected_card.get_untracked().unwrap()),
            vec![assigned_actor]
        );
        app.dispatch(class_node(&app, "card-detail-due-trigger"), Event::Activate)
            .unwrap();
        settle(&app, &executor);
        class_node(&app, "due-date-modal-head");
        class_node(&app, "due-date-modal-body");
        class_node(&app, "due-date-modal-actions");
        assert_eq!(
            nodes(&app)
                .into_iter()
                .filter(|id| app
                    .tree()
                    .node(*id)
                    .unwrap()
                    .descriptor
                    .view()
                    .classes
                    .iter()
                    .any(|class| class == "due-calendar-day"))
                .count(),
            42
        );
        let day = nodes(&app)
            .into_iter()
            .find(|id| {
                app.tree()
                    .node(*id)
                    .unwrap()
                    .descriptor
                    .view()
                    .name
                    .as_deref()
                    == Some("2026-10-20")
            })
            .unwrap();
        app.dispatch(day, Event::Activate).unwrap();
        settle(&app, &executor);
        assert_eq!(c.due_edit_value.get_untracked(), "2026-10-20");
        app.dispatch(class_node(&app, "card-detail-due-cancel"), Event::Activate)
            .unwrap();
        settle(&app, &executor);
        assert!(!c.due_picker_open.get_untracked());
        assert_eq!(
            c.selected_card.get_untracked().unwrap().due,
            "2026-10-15",
            "cancel never writes the selected card"
        );
        let editor = input(&app);
        assert!(!suspended.get());
        let revision = {
            let tree = app.tree();
            match tree.node(editor).unwrap().descriptor.view().props {
                Props::Input(input) => input.revision,
                _ => unreachable!(),
            }
        };
        app.dispatch(
            editor,
            Event::ValueChanged {
                value: "unsent card discussion".into(),
                composing: false,
                revision,
            },
        )
        .unwrap();
        assert_eq!(value(&app, editor), "unsent card discussion");
        // Select a real historical revision through the production popup while
        // the discussion input and its unsent draft remain mounted.
        app.dispatch(
            class_node(&app, "card-detail-tab-synthesis"),
            Event::Activate,
        )
        .unwrap();
        settle(&app, &executor);
        class_node(&app, "is-own");
        class_node(&app, "is-latest");
        assert_eq!(text_content(&app, "card-synthesis-author"), "AliceME");
        assert_eq!(text_content(&app, "card-synthesis-time"), "Now");
        app.dispatch(
            class_node(&app, "card-synthesis-history-trigger"),
            Event::Activate,
        )
        .unwrap();
        settle(&app, &executor);
        assert_eq!(
            text_content(&app, "card-synthesis-history-latest"),
            "latest"
        );
        assert_eq!(
            text_content(&app, "card-synthesis-history-self-badge"),
            "ME"
        );
        let old_version = nodes(&app)
            .into_iter()
            .find(|id| {
                app.tree()
                    .node(*id)
                    .unwrap()
                    .descriptor
                    .view()
                    .name
                    .as_deref()
                    == Some("v1 Bob Earlier")
            })
            .unwrap();
        app.dispatch(old_version, Event::Activate).unwrap();
        settle(&app, &executor);
        class_node(&app, "is-history");
        assert_eq!(text_content(&app, "card-synthesis-author"), "Bob");
        assert_eq!(text_content(&app, "card-synthesis-time"), "Earlier");
        assert!(!nodes(&app).iter().any(|id| {
            app.tree()
                .node(*id)
                .unwrap()
                .descriptor
                .view()
                .classes
                .iter()
                .any(|class| class == "card-synthesis-history-menu" || class == "is-own")
        }));
        assert!(nodes(&app).iter().any(|id| matches!(app.tree().node(*id).unwrap().descriptor.view().props, Props::Text(text) if text.content == "Original synthesis")));
        app.dispatch(
            class_node(&app, "card-synthesis-latest-button"),
            Event::Activate,
        )
        .unwrap();
        settle(&app, &executor);
        class_node(&app, "is-own");
        class_node(&app, "is-latest");
        assert_eq!(text_content(&app, "card-synthesis-time"), "Now");
        app.dispatch(
            class_node(&app, "card-detail-tab-discussion"),
            Event::Activate,
        )
        .unwrap();
        settle(&app, &executor);
        assert_eq!(input(&app), editor);
        assert_eq!(value(&app, editor), "unsent card discussion");
        let mut updated = first.clone();
        updated.title = "Updated title".into();
        c.selected_card
            .revise(|value| *value = Some(updated.clone()));
        settle(&app, &executor);
        assert_eq!(input(&app), editor);
        assert_eq!(value(&app, editor), "unsent card discussion");
        assert!(nodes(&app).iter().any(|id|matches!(app.tree().node(*id).unwrap().descriptor.view().props,Props::Text(text)if text.content=="Updated title")));
        let mut gap = updated.clone();
        gap.authoring_basis = None;
        gap.state = CardState::Quarantined;
        c.selected_card.revise(|value| *value = Some(gap));
        settle(&app, &executor);
        assert!(suspended.get());
        assert_eq!(input(&app), editor);
        c.selected_card.revise(|value| *value = None);
        settle(&app, &executor);
        assert!(suspended.get());
        assert_eq!(input(&app), editor);
        assert_eq!(value(&app, editor), "unsent card discussion");
        c.selected_card.revise(|value| *value = Some(updated));
        settle(&app, &executor);
        assert!(!suspended.get());
        assert_eq!(input(&app), editor);
        assert_eq!(value(&app, editor), "unsent card discussion");
        context.route.revise(|value| {
            *value = Route::KanbanTask {
                realm_id: realm.clone(),
                task_id: second.id.clone(),
                tab: "discussion".into(),
            }
        });
        c.selected_card
            .revise(|value| *value = Some(second.clone()));
        c.card_detail_discussion_mounted_for
            .revise(|value| *value = Some(second.primary_strand_id.clone()));
        settle(&app, &executor);
        let replacement = input(&app);
        assert_ne!(replacement, editor);
        assert_eq!(value(&app, replacement), "");
        assert!(app.tree().node(editor).is_err());
        context.route.revise(|value| {
            *value = Route::KanbanRealm {
                realm_id: realm.clone(),
            }
        });
        settle(&app, &executor);
        assert!(app.tree().node(replacement).is_err());
    }
}
