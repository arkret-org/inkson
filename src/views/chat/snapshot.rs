use super::*;
#[derive(Clone, PartialEq)]
pub(super) struct ChatSnapshot {
    pub(super) sidecar_session: Option<crate::sidecar::HostedSidecarState>,
    pub(super) visible_message_count: usize,
    pub(super) visible_channels: Vec<ChannelEntity>,
    pub(super) selected_channel_info: Option<ChannelEntity>,
    pub(super) selected_channel_name: String,
    pub(super) selected_channel_category: String,
    pub(super) selected_channel_unread: usize,
    pub(super) selected_channel_security_encrypted: bool,
    pub(super) selected_scope_circle: Option<String>,
    pub(super) send_scope: Option<arkret_sdk::ScopeRef>,
    pub(super) selected_realm_pending_mls_binding_reason: Option<String>,
    pub(super) selected_realm_pending_mls_binding: bool,
    pub(super) send_readiness_checking: bool,
    pub(super) sidecar_security_label: Option<String>,
    pub(super) sidecar_send_block_reason: Option<String>,
    pub(super) participants: Vec<SpaceParticipant>,
    pub(super) participants_for_messages: Vec<SpaceParticipant>,
    pub(super) composer_participants: Vec<SpaceParticipant>,
    pub(super) presence_participants: Vec<SpaceParticipant>,
    pub(super) sidecar_owned_agents: Vec<SpaceParticipant>,
    pub(super) public_agent_ids: std::collections::BTreeSet<String>,
    pub(super) public_agent_accounts: std::collections::BTreeSet<arkret_sdk::AccountId>,
    pub(super) interaction_modes_snapshot: agent_modes::Modes,
    pub(super) readable_participation_agent_ids: Vec<String>,
    pub(super) agent_participation_sync_key: String,
    pub(super) participant_ids_for_presence: Vec<String>,
    pub(super) has_remote_presence: bool,
    pub(super) presence_sync_key: String,
    pub(super) self_presence_actor: Option<String>,
    pub(super) discussion_feed_loading: bool,
    pub(super) sidecar_delivery_diagnostics: Option<SidecarDeliveryDiagnostics>,
    pub(super) direct_mls_epoch: Option<String>,
    pub(super) shared_sync_finished: bool,
    pub(super) account_display_label: String,
    pub(super) mode_key: agent_modes::AgentModeReadKey,
}
pub(super) fn active_sidecar(
    app: &crate::presentation::InksonContext,
    props: &ChatPanelProps,
    authority: &arkret_sdk::AccountId,
    strand: &str,
) -> Option<crate::sidecar::HostedSidecarState> {
    props
        .sidecar_session
        .clone()
        .or_else(|| app.hosted_sidecar.get())
        .filter(|session| {
            session.matches_route(&props.selected_realm_id, strand)
                && session.controller_account_id == *authority
        })
}
pub(super) fn snapshot(
    app: &crate::presentation::InksonContext,
    props: &ChatPanelProps,
    controller: ChatController,
    account: &crate::config::ActiveAccountContext,
    sidecar_timeline: Bond<super::sidecar_projection::SidecarTimelineProjection>,
    merged_timeline: Bond<Vec<ChatMessage>>,
    visible_timeline: Bond<Vec<ChatMessage>>,
    probe: crate::views::secure_send::ScopeSendProbe,
    modes: agent_modes::Modes,
) -> ChatSnapshot {
    let _ = app.state_revision.get();
    let ChatPanelProps {
        selected_realm_id,
        initial_strand_id,
        embedded,
        direct_mode,
        direct_peer_id,
        ..
    } = props.clone();
    let all_channels = controller.channels.get();
    let selected_channel_value = controller.selected_channel.get();
    let _visible_channels_empty = all_channels.is_empty();
    let principal_core_id = account.principal_id().clone();
    let principal_id = principal_core_id.as_str().to_owned();
    let authority = account.authority.clone();
    let account_device_id = account.device_id.clone();
    let base_url = app.base_url.get();
    let token = app.token;
    let sync_cursor = app.sync_cursor;
    let realm_live_epoch = app.realm_live_epoch;
    let track_filter = controller.track_filter;
    let account_display_name = controller.account_display_name;
    let owned_agent_slugs = controller.owned_agent_slugs;
    let initial_sync_finished = controller.initial_sync_finished;
    let private = sidecar_timeline.get();
    let sidecar_session = active_sidecar(app, props, &authority, &selected_channel_value);
    let sidecar_mode = sidecar_session.is_some();
    let sidecar_exchange_current = private.current.clone();
    let sidecar_privacy_gate = private.privacy_gate.clone();
    let all_messages_snapshot = merged_timeline.get();
    let visible_messages = visible_timeline.get();
    let visible_message_count = visible_messages.len();
    let _scope_readiness_checking = probe.checking;
    let _scope_send_gate = probe.gate.clone();

    app.state_store.read(|store| {
    let filter_value = track_filter.get();
    let (visible_channels, selected_channel_info) =
        discussion_channels_for_surface(&all_channels, &selected_channel_value, &filter_value);
    let visible_channels_empty = visible_channels.is_empty();
    let selected_channel_name = if embedded {
        "Discussion".to_owned()
    } else {
        selected_channel_info
            .as_ref()
            .map(|channel| channel.name.clone())
            .unwrap_or_else(|| crate::i18n::tr("chat.empty.title"))
    };
    let selected_channel_category = selected_channel_info
        .as_ref()
        .map(|channel| channel.category.clone())
        .unwrap_or_else(|| "discussion".to_owned());
    let selected_channel_unread = selected_channel_info
        .as_ref()
        .filter(|channel| {
            sidecar_privacy_gate.allows_strand(
                crate::sidecar::SidecarDisclosureSurface::Unread,
                &channel.strand_id,
            )
        })
        .map(|channel| channel.unread)
        .unwrap_or(0);
    // Unknown scope current keeps the secure path blocked until verification.
    let selected_scope_circle = selected_channel_info.as_ref().and_then(|channel| {
        channel
            .scope_circle
            .as_ref()
            .map(|circle| circle.circle_id.clone())
    });
    let send_scope = selected_channel_info
        .as_ref()
        .and_then(|channel| channel.effective_scope(&selected_realm_id));
    let scope_readiness_checking = probe.checking;
    let scope_send_gate = probe.gate.clone();
    // This probe belongs to the selected original Strand. A private Agent
    // draft has its own native Sidecar probe in ChatComposer; merely showing
    // private history must not change ordinary message encryption or readiness.
    let selected_channel_security_encrypted = if direct_mode {
        true
    } else {
        !matches!(
            scope_send_gate.as_ref(),
            Some(crate::mls::send_gate::MlsSendGate::Plaintext)
        )
    };
    let direct_message_authority =
        app.active_account.get()
            .and_then(|account| {
                crate::mls::direct_binding::message_authority(
                    store,
                    &selected_realm_id,
                    &arkret_sdk::ActorId::account(account.authority),
                )
            });
    let mut selected_realm_pending_mls_binding_reason = if selected_scope_circle.is_none() {
        store
            .realm_pending_mls_binding_reason(&selected_realm_id)
    } else {
        None
    };
    if (selected_channel_security_encrypted || direct_mode)
        && selected_realm_pending_mls_binding_reason.is_none()
    {
        let installed = send_probe_presentation_current(
            scope_send_gate.as_ref(),
            send_scope
                .as_ref()
                .map(|scope| {
                    // Presentation only: authoring still requires the independent
                    // durable send probe to finish restoring private state.
                    store.installed_scope_mls_current(scope)
                })
                .unwrap_or(crate::current_projection::ScopeMlsCurrent::Unknown),
        );
        let local_epoch = send_scope.as_ref().and_then(|scope| {
            store
                .mls_checkpoint_for_scope(scope)
                .map(|checkpoint| checkpoint.epoch)
        });
        if let Some(reason) = match installed {
            crate::current_projection::ScopeMlsCurrent::Activated(current) => match local_epoch {
                Some(epoch) if epoch != current.epoch => Some(format!(
                    "encryption_transition_pending: waiting for the accepted MLS epoch {}",
                    current.epoch
                )),
                _ => None,
            },
            crate::current_projection::ScopeMlsCurrent::NotActivated => Some(
                "encryption_policy_pending: this scope has no accepted MLS Genesis yet".to_owned(),
            ),
            crate::current_projection::ScopeMlsCurrent::Unknown => Some(
                "encryption_policy_pending: waiting for the scope's verified current state"
                    .to_owned(),
            ),
        } {
            selected_realm_pending_mls_binding_reason = Some(reason);
        } else {
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            let roster_matches = if selected_scope_circle.is_none() {
                crate::mls::runtime::realm_mls_roster_matches_complete_membership_hint(
                    store,
                    secure_store.as_ref(),
                    &selected_realm_id,
                    &authority,
                    &account_device_id,
                )
            } else {
                None
            };
            let local_group_available =
                crate::mls::runtime::mls_group_member_actor_ids_for_effective_scope(
                    store,
                    secure_store.as_ref(),
                    &selected_realm_id,
                    selected_scope_circle.as_deref(),
                    &authority,
                    &account_device_id,
                )
                .is_some();
            if !local_group_available {
                selected_realm_pending_mls_binding_reason = Some(
                    "Waiting for this device's encryption keys. Keep this conversation open to receive the MLS Welcome."
                        .to_owned(),
                );
            } else if roster_matches == Some(false) {
                selected_realm_pending_mls_binding_reason = Some(
                    "encryption_transition_pending: synced roster differs from the verified MLS group"
                        .to_owned(),
                );
            }
        }
    }
    if selected_realm_pending_mls_binding_reason.is_none()
        && (direct_mode
            || store
                .realm_collaboration_role(&selected_realm_id)
                == Some(arkret_sdk::CollaborationRealmRole::DirectConversation))
        && direct_message_authority.is_none()
    {
        selected_realm_pending_mls_binding_reason =
            Some("Waiting for verified conversation authority and encryption keys.".to_owned());
    }
    let scope_send_ready = scope_send_gate.is_some();
    let send_readiness_checking =
        scope_readiness_checking && selected_realm_pending_mls_binding_reason.is_none();
    if !scope_send_ready && selected_realm_pending_mls_binding_reason.is_none() {
        selected_realm_pending_mls_binding_reason = Some(
            "Waiting for this scope's verified send state and this device's local encryption keys."
                .to_owned(),
        );
    }
    let selected_realm_pending_mls_binding = selected_realm_pending_mls_binding_reason.is_some();
    let sidecar_security_label = sidecar_session.as_ref().map(|session| {
        if !session.membership_ready() {
            "Reconciling access"
        } else {
            "E2EE"
        }
    });
    let sidecar_send_block_reason = sidecar_session.as_ref().and_then(|session| {
        if let Err(error) = &sidecar_exchange_current {
            Some(format!("Sidecar exchange is unavailable: {error}"))
        } else if !session.membership_ready() {
            Some(format!(
                "Private access is still reconciling for {} principal(s). Sending is disabled until the native Sidecar MLS snapshot is available on this device.",
                session.pending_reconciliation_count()
            ))
        } else {
            None
        }
    });
    let participant_projection = store.realm_tree_projection(&selected_realm_id);
    let account_display_label = account_display_name.get();
    let mut participants = space_participants(
        participant_projection.as_ref(),
        store,
        &selected_realm_id,
        &principal_id,
    );
    let direct_peer_id = if direct_mode {
        crate::transport::account::cached_direct_conversation_peer(
            store,
            &selected_realm_id,
            &initial_strand_id,
        )
        .unwrap_or_else(|| {
            let peer = crate::app::direct_conversation_peer_id(
                &app.contact_rows.get(),
                &selected_realm_id,
                &initial_strand_id,
            );
            if peer.is_empty() { direct_peer_id } else { peer }
        })
    } else {
        String::new()
    };
    let projected_member_ids = participants
        .iter()
        .filter_map(|participant| participant.actor_id.as_ref().map(ToString::to_string))
        .collect::<std::collections::BTreeSet<_>>();
    let own_controller_handle = participants
        .iter()
        .find(|participant| participant.is_self && !participant.is_agent)
        .and_then(mention_label_for_participant);
    // Agent identity comes from the controller-owned inventory. Mention
    // selector fields are persistent audit snapshots and may only enrich an
    // already-authoritative agent; they never promote an arbitrary DID to an
    // agent. This keeps the roster fail-closed when profile, selector-claim,
    // and accountability evidence is unavailable.
    {
        let mut agent_metadata = owned_agent_metadata(
            &owned_agent_slugs.get(),
            &principal_id,
            own_controller_handle.as_deref(),
        );
        enrich_authoritative_agent_metadata(
            &mut agent_metadata,
            agent_metadata_from_mentions(&all_messages_snapshot),
        );
        let joined_members = store
            .complete_joined_member_hint_for_realm(&selected_realm_id)
            .ok()
            .flatten();
        upsert_joined_owned_agent_participants(
            &mut participants,
            joined_members.as_ref(),
            &agent_metadata,
            &principal_id,
        );
        upsert_agent_participants(&mut participants, &agent_metadata, &principal_id);
        annotate_agent_participants_with_metadata(&mut participants, &agent_metadata);
    }
    let participants_for_messages = participants.clone();

    let mut known_agent_ids = participants_for_messages
        .iter()
        .filter(|participant| participant.is_agent)
        .map(|participant| participant.principal_id.to_string())
        .collect::<Vec<_>>();
    known_agent_ids.sort();
    known_agent_ids.dedup();
    // The participation resource is controller-self-only. Remote agents are
    // never probed here; they become roster-visible only through already
    // visible reply history, which avoids both forbidden requests and agent
    // policy enumeration.
    let readable_participation_agent_ids =
        readable_participation_agent_ids(&participants_for_messages, &principal_id);
    // A readable history baseline does not require this endpoint's private
    // sending state. Keep the restorable-key probe on the composer above.
    let shared_sync_finished = initial_sync_finished.get()
        && if sidecar_mode {
            sidecar_session
                .as_ref()
                .is_some_and(|session| session.membership_ready())
        } else {
                    !store.current_reset_required()
                && !store.realm_detail_invalidated(&selected_realm_id)
                && send_scope.as_ref().is_some_and(|scope| {
                    !matches!(
                        store.installed_scope_mls_current(scope),
                        crate::current_projection::ScopeMlsCurrent::Unknown
                    )
                })
        };
    // Participation is a durable Realm projection. The account cursor is an
    // opaque resume checkpoint and can be re-minted for typing/receipts/calls;
    // reduce it to the one useful transition (bootstrap is ready) and use the
    // Realm epoch for subsequent durable invalidation.
    let account_sync_ready = crate::app::account_sync_ready(&sync_cursor.get());
    let agent_participation_sync_key = format!(
        "{}|{}|{}|{}|{}|{}",
        selected_realm_id,
        selected_channel_value,
        selected_scope_circle.as_deref().unwrap_or_default(),
        account_sync_ready as u8,
        realm_live_epoch.get(),
        readable_participation_agent_ids.join(",")
    );
    let mode_accounts = participants_for_messages
        .iter()
        .filter(|p| p.is_agent)
        .filter_map(participant_mention_account)
        .collect::<Vec<_>>();
    let mode_key = {
            agent_modes::AgentModeReadKey {
            base: base_url.clone(),
            authority: authority.clone(),
            realm: selected_realm_id.clone(),
            credential: token.get(),
            session_epoch: crate::identity::device_directory::session_cache_epoch(),
            sync_ready: account_sync_ready,
            ready: store.current_product_view_ready(&selected_realm_id),
            complete: store
                .current_product_view()
                .is_some_and(|view| view.realm_id == selected_realm_id && view.complete_cut),
            reset: store.current_reset_required(),
            head: arkret_sdk::RealmId::new(selected_realm_id.clone())
                .ok()
                .and_then(|realm_id| {
                    store
                        .verified_commit_stream_cursor(&arkret_sdk::CommitStreamRef::Realm {
                            realm_id,
                        })
                        .ok()
                        .flatten()
                }),
            accounts: mode_accounts,
        }
    };
    let interaction_modes_snapshot=modes;
    let mut public_agent_accounts = participants_for_messages
        .iter()
        .filter(|p| {
            participant_mention_account(p).is_some_and(|account| {
                interaction_modes_snapshot.get(&account)
                    == Some(&arkret_sdk::AgentInteractionMode::Public)
            })
        })
        .filter_map(participant_mention_account)
        .collect::<std::collections::BTreeSet<_>>();
    if direct_mode {
        public_agent_accounts.extend(
            participants_for_messages
                .iter()
                .filter(|participant| {
                    participant.is_agent
                        && direct_agent_is_conversation_peer(
                            &participant.roster_key(),
                            &direct_peer_id,
                            &projected_member_ids,
                        )
                })
                .filter_map(participant_mention_account),
        );
    }
    let public_agent_ids = public_agent_accounts
        .iter()
        .map(|a| arkret_sdk::ActorId::account(a.clone()).to_string())
        .collect::<std::collections::BTreeSet<_>>();
    participants.retain(|participant| {
        !participant.is_agent
            || (if direct_mode {
                direct_agent_is_conversation_peer(
                    &participant.roster_key(),
                    &direct_peer_id,
                    &projected_member_ids,
                )
            } else {
                participant_mention_account(participant)
                    .is_some_and(|a| public_agent_accounts.contains(&a))
            })
    });
    let sidecar_owned_agents =
        sidecar_owned_agent_participants(&participants_for_messages, &principal_id);
    // The source composer keeps both ordinary members and selectable owned
    // Agents. Current structured mentions choose the write audience; private
    // history neither narrows the picker nor grants public Agent participation.
    let composer_participants: Vec<_> = participants_for_messages
        .iter()
        .filter(|p| {
            !p.is_agent
                || participant_mention_account(p)
                    .is_some_and(|a| public_agent_accounts.contains(&a))
                || p.agent_metadata
                    .as_ref()
                    .is_some_and(|m| same_principal_core(&m.controller_principal_id, &principal_id))
        })
        .cloned()
        .collect();

    let presence_participants = if sidecar_mode {
        sidecar_presence_participants(&participants, &principal_id)
    } else {
        participants.clone()
    };

    let participant_ids_for_presence = presence_participant_ids(&presence_participants);
    let self_presence_actor = app.active_account.get()
        .map(|account| arkret_sdk::ActorId::account(account.authority).to_string());
    let has_remote_presence = participant_ids_for_presence
        .iter()
        .any(|id| Some(id) != self_presence_actor.as_ref());
    let presence_sync_key = format!(
        "{}|{}",
        selected_realm_id,
        participant_ids_for_presence.join(",")
    );
    let discussion_feed_loading = !visible_channels_empty
        && visible_message_count == 0
        && !token.get().trim().is_empty()
        && !initial_sync_finished.get();
    // Connection details must describe observed state, not hard-coded
    // placeholders. A durable `ak:event:*` row is evidence that the message
    // submit completed. Notification fanout is performed server-side after
    // acceptance and the current protocol exposes no Agent delivery receipt,
    // so label those facts explicitly instead of claiming "Not started" or
    // "Not received".
    let sidecar_delivery_diagnostics = sidecar_session.as_ref().map(|session| {
        let latest = visible_messages
            .iter()
            .filter(|message| {
                message.sender == principal_id
                    && message
                        .created_at
                        .is_none_or(|created_at| created_at >= session.opened_at)
            })
            .max_by_key(|message| message.created_at);
        let (submit, fanout, receipt) = match latest {
            Some(message) if message.failed => ("Failed", "Not queued", "Not reported"),
            Some(message) if message.pending => ("Submitting", "Not queued", "Not reported"),
            Some(message) if message.id.starts_with("ak:event:") => {
                ("Accepted", "Server-managed", "Not reported")
            }
            Some(_) => ("Accepted locally", "Pending acceptance", "Not reported"),
            None => ("Not started", "Not started", "Not reported"),
        };
        let last_updated = latest
            .and_then(|message| message.created_at)
            .unwrap_or(session.opened_at)
            .format("%H:%M:%S")
            .to_string();
        SidecarDeliveryDiagnostics {
            submit,
            fanout,
            receipt,
            last_updated,
        }
    });
    let direct_mls_epoch = direct_mode
        .then(|| {
            store
                .mls_checkpoint_for_effective_scope(&selected_realm_id, None)
                .map(|snapshot| snapshot.epoch.to_string())
        })
        .flatten();

ChatSnapshot {sidecar_session,visible_message_count,visible_channels,selected_channel_info,selected_channel_name,selected_channel_category,selected_channel_unread,selected_channel_security_encrypted,selected_scope_circle,send_scope,selected_realm_pending_mls_binding_reason,selected_realm_pending_mls_binding,send_readiness_checking,sidecar_security_label:sidecar_security_label.map(str::to_owned),sidecar_send_block_reason,participants,participants_for_messages,composer_participants,presence_participants,sidecar_owned_agents,public_agent_ids,public_agent_accounts,interaction_modes_snapshot,readable_participation_agent_ids,agent_participation_sync_key,participant_ids_for_presence,has_remote_presence,presence_sync_key,self_presence_actor,discussion_feed_loading,sidecar_delivery_diagnostics,direct_mls_epoch,shared_sync_finished,account_display_label,mode_key}
})
}
