use std::cell::RefCell;
use std::rc::Rc;

use super::*;

#[test]
fn semantic_keyboard_submit_preserves_original_chat_modifier_rules() {
    for key in ["Enter", "x"] {
        for shift in [false, true] {
            for alt in [false, true] {
                for composing in [false, true] {
                    for repeat in [false, true] {
                        for (control, meta) in [(false, false), (true, false), (false, true)] {
                            let command = glory::render::KeyboardInput {
                                key,
                                shift,
                                alt,
                                composing,
                                repeat,
                                control,
                                meta,
                                editable: true,
                            }
                            .command();
                            assert_eq!(
                                command == Some(glory::render::KeyboardCommand::Submit),
                                chat_composer_should_send_key(key, shift, alt, composing, repeat),
                            );
                        }
                    }
                }
            }
        }
    }
}

fn prior_private_session(controller: arkret_sdk::AccountId) -> crate::sidecar::HostedSidecarState {
    crate::sidecar::HostedSidecarState {
        trace_id: "prior-private-request".into(),
        controller_account_id: controller,
        addressed_agent_ids: vec!["ak:did_core:web:agents.example:previous".into()],
        addressed_agent_label: "Previous".into(),
        source_realm_id: "ak:realm:AUqzNZlfuL-7z087TbZhKOdYyKUNPAa2o_neyoFRh3o2".into(),
        source_strand_id: "ak:strand:AUvEs_-d1tc81yDszBZAVWapgIr3Gs6ofbmtZSLQNejL".into(),
        sidecar_id: arkret_sdk::SidecarId::new(
            "ak:sidecar:Abbk-ALq9nZszIh8qJC26XasNIx9TYjU5-BzXWyqwDVx",
        )
        .unwrap(),
        access_readiness: arkret_sdk::AgentSidecarAccessReadiness::KeyMaterialPending,
        pending_access_reconciliations: vec![],
        mls_context: arkret_sdk::AgentSidecarMlsContext {
            participant_authority_digest: arkret_sdk::Hash::new(format!(
                "sha256:{}",
                "1".repeat(64)
            ))
            .unwrap(),
            authority_stream_head: vec![],
            mls_group_id: None,
            epoch: None,
            genesis_event_ref: None,
            current_controller_device_ready: false,
        },
        native_mls_ready: false,
        migrated_draft: "an old private draft".into(),
        opened_at: chrono::Utc::now(),
    }
}

#[test]
fn private_history_does_not_supply_a_draft_target_or_block_original_send() {
    use crate::views::chat::tests::{local_fixture_account, local_fixture_actor};
    let principal = "ak:did_core:web:alice.example";
    let authority = local_fixture_account(principal);
    let session = prior_private_session(authority.clone());
    assert!(!session.membership_ready());
    let agent_principal = "ak:did_core:web:agents.example:current";
    let agent = SpaceParticipant {
        actor_id: Some(local_fixture_actor(agent_principal)),
        principal_id: arkret_sdk::DidCoreId::new(agent_principal).unwrap(),
        display_name: Some("current".into()),
        handle_label: None,
        display_name_rank: 1,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: true,
        agent_metadata: Some(AgentParticipantMetadata {
            controller_principal_id: principal.into(),
            controller_handle: "alice.example".into(),
            agent_slug: "".into(),
            display_name: "current".into(),
        }),
    };
    let participants = vec![agent.clone()];
    let candidate = mention_candidate_for_participant(&agent, &participants, principal).unwrap();
    let mut picker = crate::messaging::mentions::MentionPickerState::new();
    let private_modes = std::collections::BTreeMap::from([(
        candidate.subject_account_id.clone(),
        arkret_sdk::AgentInteractionMode::Private,
    )]);
    let route_for = |draft: &str,
                     picker: &crate::messaging::mentions::MentionPickerState,
                     modes: &std::collections::BTreeMap<_, _>| {
        let bound = picker.bound_candidates(draft);
        let mentions = composer_mention_nodes(true, draft, &bound, principal);
        let route = composer_agent_mode_route(
            arkret_sdk::AgentMentionComposerScope::Realm,
            &mentions,
            &participants,
            &authority,
            &bound,
            modes,
        );
        (route, mentions, bound)
    };
    let private_draft = picker.select(candidate.clone(), "@", Some((0, 1)));
    let (private_route, mentions, _) = route_for(&private_draft, &picker, &private_modes);
    assert_eq!(private_route, arkret_sdk::AgentMentionRoute::Sidecar);
    assert!(sidecar_session_for_draft(private_route, Some(&session)).is_some());
    assert_eq!(
        sidecar_request_targets(true, &mentions, &participants, principal),
        vec![agent_principal.to_owned()]
    );
    assert!(draft_scope_send_blocked(private_route, false, true));
    assert!(!draft_scope_send_blocked(private_route, true, false));

    let public_modes = std::collections::BTreeMap::from([(
        candidate.subject_account_id.clone(),
        arkret_sdk::AgentInteractionMode::Public,
    )]);
    let (route, mentions, bound) = route_for(&private_draft, &picker, &public_modes);
    assert_eq!(route, arkret_sdk::AgentMentionRoute::Shared);
    assert!(sidecar_session_for_draft(route, Some(&session)).is_none());
    assert_eq!(
        composer_shared_agent_targets(
            arkret_sdk::AgentMentionComposerScope::Realm,
            &mentions,
            &participants,
            &bound
        ),
        vec![candidate.subject_account_id]
    );
    assert!(!draft_scope_send_blocked(route, false, true));

    picker.edit(&private_draft, "ordinary message");
    for draft in ["ordinary message", "@me/current raw text", ""] {
        let (route, mentions, bound) = route_for(draft, &picker, &Default::default());
        assert_eq!(route, arkret_sdk::AgentMentionRoute::Shared);
        assert!(sidecar_session_for_draft(route, Some(&session)).is_none());
        assert!(sidecar_request_targets(true, &mentions, &participants, principal).is_empty());
        assert!(
            composer_shared_agent_targets(
                arkret_sdk::AgentMentionComposerScope::Realm,
                &mentions,
                &participants,
                &bound
            )
            .is_empty()
        );
        assert!(
            !draft_scope_send_blocked(route, false, true),
            "old private readiness and mode failures cannot gate an ordinary draft"
        );
        assert!(
            draft_scope_send_blocked(route, true, false),
            "ordinary scope readiness still applies"
        );
    }
    assert!(draft_scope_send_blocked(
        arkret_sdk::AgentMentionRoute::BlockedMixedPrivateTargets,
        false,
        false
    ));
    assert!(!draft_scope_send_blocked(
        arkret_sdk::AgentMentionRoute::Direct,
        false,
        true
    ));
}

#[test]
fn installed_sidecar_requires_its_own_private_group_without_parent_scope_keys() {
    let current: arkret_wire::MlsGroupValue = serde_json::from_value(serde_json::json!({
        "effective_scope": {"kind":"sidecar", "realm_id":"ak:realm:AeEFmfOZxsx5kLi2kpOJu8m7TFXZ_G8E4019rUp4wmT6", "sidecar_id":"ak:sidecar:Abbk-ALq9nZszIh8qJC26XasNIx9TYjU5-BzXWyqwDVx"},
        "genesis_event_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "current_mls_commit_event_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519", "epoch": "4",
        "current_key_access_revision": "2", "covered_key_access_revision": "2",
        "public_tree_ref": "ak:blob:sha256:431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460"
    })).unwrap();
    let probe = crate::mls::send_gate::decide_mls_send_gate(Ok(Some(current)), None);
    assert_eq!(
        probe,
        Err(crate::mls::send_gate::MlsSendGateBlocked::LocalGroupBehind { current_epoch: 4 })
    );
    let gate = probe.ok();
    assert!(installed_sidecar_send_blocked(
        true,
        true,
        false,
        gate.as_ref()
    ));
    assert!(
        !installed_sidecar_send_blocked(true, false, false, gate.as_ref()),
        "fresh opening acquires its independent scope"
    );
    assert!(
        !installed_sidecar_send_blocked(false, true, false, gate.as_ref()),
        "old private state cannot gate a shared draft"
    );
}

fn primary(app: &glory::App) -> (glory::render::NodeId, bool) {
    fn visit(
        app: &glory::App,
        id: glory::render::NodeId,
        result: &mut Vec<(glory::render::NodeId, bool)>,
    ) {
        let tree = app.tree();
        let node = tree.node(id).unwrap();
        if let glory::render::Props::Button(props) = node.descriptor.view().props {
            result.push((id, props.enabled));
        }
        for child in &node.children {
            visit(app, *child, result);
        }
    }
    let mut result = Vec::new();
    for id in app.tree().roots() {
        visit(app, *id, &mut result);
    }
    assert_eq!(result.len(), 1, "there must be exactly one primary Send");
    result[0]
}
#[test]
fn primary_send_keeps_its_dom_identity_across_scope_probe_and_encryption_changes() {
    let app = glory::App::memory();
    let scope = app.scope();
    let state = scope.cage((false, true, false));
    let enabled = scope.bond(move || {
        let (_, pending, _) = state.get();
        !pending
    });
    let busy = scope.bond(move || state.get().1);
    app.mount(primary_send_action(scope, "Send", enabled, busy, || {}))
        .unwrap();
    let (id, enabled) = primary(&app);
    assert!(!enabled);
    for next in [
        (true, false, false),
        (false, true, true),
        (false, false, false),
        (true, true, false),
        (true, false, false),
    ] {
        state.revise(|value| *value = next);
        app.flush().unwrap();
        let (next_id, enabled) = primary(&app);
        assert_eq!(next_id, id, "scope probes must retain primary Send");
        assert_eq!(enabled, !next.1);
        assert_eq!(
            app.tree()
                .node(id)
                .unwrap()
                .descriptor
                .view()
                .semantics
                .as_ref()
                .unwrap()
                .busy,
            Some(next.1)
        );
    }
}

type FailureState = Rc<RefCell<Option<(Cage<Vec<ChatMessage>>, Cage<String>, Cage<String>)>>>;

#[test]
fn private_echoes_and_unconfirmed_rows_cannot_anchor_the_next_private_request() {
    let control = Rc::new(RefCell::new(None));
    let app = glory::App::memory();
    send_failure_harness(app.scope(), control.clone());
    {
        let (messages, ..) = control.borrow().unwrap();
        let id =
            |byte| arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [byte; 32]);
        let realm = arkret_sdk::RealmId::from_event_id(&id(1));
        let strand = arkret_sdk::StrandId::from_event_id(&id(2));
        let mut source = messages.get()[0].clone();
        source.realm_id = realm.to_string();
        source.strand_id = strand.to_string();
        source.id = id(3).to_string();
        source.pending = false;
        source.protocol_content = Some(AuthenticatedMessageContent {
            scope: arkret_sdk::ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            source: id(3),
            content: serde_json::from_value(json!({
                "kind": "ak.content.text", "format": "plain", "body": "ordinary source"
            }))
            .unwrap(),
        });
        let mut private = source.clone();
        private.id = id(4).to_string();
        let content = private.protocol_content.as_mut().unwrap();
        content.source = id(4);
        content.scope = arkret_sdk::ScopeRef::Sidecar {
            realm_id: realm.clone(),
            sidecar_id: arkret_sdk::SidecarId::from_event_id(&id(5)),
        };
        let mut unknown = source.clone();
        unknown.id = id(6).to_string();
        unknown.protocol_content = None;
        let mut pending = source.clone();
        pending.pending = true;
        let mut failed = source.clone();
        failed.failed = true;
        let rows = vec![
            source.clone(),
            private.clone(),
            unknown.clone(),
            pending,
            failed,
        ];
        assert_eq!(
            latest_source_event_anchor(&rows, realm.as_str(), strand.as_str()),
            Some(source.id)
        );
        assert_eq!(
            latest_source_event_anchor(&[private, unknown], realm.as_str(), strand.as_str()),
            None
        );
    }
}

fn send_failure_harness(scope: &Scope, control: FailureState) {
    let messages = scope.cage(vec![ChatMessage {
        protocol_content: None,
        local_scope: None,
        realm_id: String::new(),
        id: "local-send".to_owned(),
        protocol_message_id: Some("protocol-send".to_owned()),
        actor_id: None,
        sender: String::new(),
        executed_by: None,
        body: "original draft".to_owned(),
        content_format: None,
        timestamp: String::new(),
        created_at: None,
        strand_id: String::new(),
        reply_to: None,
        reactions: Vec::new(),
        redacted: false,
        edited: false,
        revisions: Vec::new(),
        revision_source: None,
        pending: true,
        failed: false,
        error: None,
        mentions: Vec::new(),
        crypto_state: MessageCryptoState::Plaintext,
    }]);
    let status = scope.cage(String::new());
    let draft = scope.cage(String::new());
    *control.borrow_mut() = Some((messages, status, draft));
}

#[test]
fn encryption_context_refusal_restores_plaintext_for_fresh_authoring() {
    for next_draft in ["", "next message"] {
        let control = Rc::new(RefCell::new(None));
        let app = glory::App::memory();
        send_failure_harness(app.scope(), control.clone());
        {
            let (messages, status, draft) = control.borrow().unwrap();
            draft.revise(|value| *value = next_draft.to_owned());
            commands::present_chat_send_failure(
                messages,
                status,
                draft,
                "protocol-send",
                "original draft",
                &garth::MessageAuthoringFailure::EncryptionContextChanged {
                    detail: "epoch_mismatch".to_owned(),
                },
            );
            let rows = messages.get();
            assert!(!rows[0].pending);
            assert!(rows[0].failed);
            assert_eq!(rows[0].error.as_deref(), Some(status.get().as_str()));
            assert_eq!(
                draft.get(),
                if next_draft.is_empty() {
                    "original draft"
                } else {
                    next_draft
                }
            );
        }
    }
}

#[test]
fn unknown_submission_remains_pending_without_inviting_duplicate_authoring() {
    let control = Rc::new(RefCell::new(None));
    let app = glory::App::memory();
    send_failure_harness(app.scope(), control.clone());
    {
        let (messages, status, draft) = control.borrow().unwrap();
        commands::present_chat_send_failure(
            messages,
            status,
            draft,
            "protocol-send",
            "original draft",
            &garth::MessageAuthoringFailure::SubmissionOutcomeUnknown {
                detail: "connection lost after submission".to_owned(),
            },
        );
        assert!(messages.get()[0].pending);
        assert!(!messages.get()[0].failed);
        assert!(draft.get().is_empty());
        assert!(!status.get().is_empty());
    }
}
