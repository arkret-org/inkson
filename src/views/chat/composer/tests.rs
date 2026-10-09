use std::cell::RefCell;
use std::rc::Rc;

use dioxus::dioxus_core::{AttributeValue, ElementId, Mutation};

use super::*;

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

type SendState = Rc<RefCell<Option<Signal<(bool, bool, bool)>>>>;

#[test]
fn installed_sidecar_requires_its_own_private_group_without_parent_scope_keys() {
    let current: arkret_wire::MlsGroupCurrent = serde_json::from_value(serde_json::json!({
        "effective_scope": {"kind":"sidecar", "realm_id":"ak:realm:AeEFmfOZxsx5kLi2kpOJu8m7TFXZ_G8E4019rUp4wmT6", "sidecar_id":"ak:sidecar:Abbk-ALq9nZszIh8qJC26XasNIx9TYjU5-BzXWyqwDVx"},
        "genesis_event_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "current_mls_commit_event_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519", "epoch": 4,
        "current_key_access_revision": 2, "covered_key_access_revision": 2,
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

fn send_actions_harness(control: SendState) -> Element {
    let state = use_signal(|| (false, true, false));
    *control.borrow_mut() = Some(state);
    let (plaintext, pending, checking) = state();
    rsx! {
        OrdinarySendActions {
            plaintext,
            plaintext_disabled: pending,
            secure_disabled: pending,
            mls_binding_pending: pending,
            creator_bootstrap_pending: pending,
            secure_title: if pending { "Waiting for verified current" } else { "" },
            opening: false,
            readiness_checking: checking,
            on_plaintext: move |_| {},
            on_secure: move |_| {},
        }
    }
}

fn primary_send_id(edits: &[Mutation]) -> ElementId {
    let ids: Vec<_> = edits
        .iter()
        .filter_map(|edit| match edit {
            Mutation::SetAttribute {
                name: "data-testid",
                value: AttributeValue::Text(value),
                id,
                ..
            } if value == "send-chat-button" => Some(*id),
            _ => None,
        })
        .collect();
    assert_eq!(ids.len(), 1, "there must be exactly one primary Send");
    ids[0]
}

fn assert_primary_disabled(edits: &[Mutation], primary: ElementId, disabled: bool) {
    assert!(
        edits.iter().any(|edit| matches!(
            edit,
            Mutation::SetAttribute {
                name: "disabled",
                value: AttributeValue::Bool(value),
                id,
                ..
            } if *id == primary && *value == disabled
        )),
        "the mounted primary Send must receive the current send gate"
    );
}

#[test]
fn primary_send_keeps_its_dom_identity_across_scope_probe_and_encryption_changes() {
    let control = Rc::new(RefCell::new(None));
    let mut dom = VirtualDom::new_with_props(send_actions_harness, control.clone());
    let initial = dom.rebuild_to_vec();
    let primary = primary_send_id(&initial.edits);
    assert_primary_disabled(&initial.edits, primary, true);

    for (plaintext, pending, checking) in [
        (true, false, false),
        (false, true, true),
        (false, false, false),
        (true, true, false),
        (true, false, false),
    ] {
        dom.in_runtime(|| {
            control
                .borrow()
                .unwrap()
                .set((plaintext, pending, checking));
        });
        let update = dom.render_immediate_to_vec();
        assert_primary_disabled(&update.edits, primary, pending);
        for edit in &update.edits {
            match edit {
                Mutation::Remove { id } | Mutation::ReplaceWith { id, .. } => {
                    assert_ne!(*id, primary, "scope probes must not replace primary Send");
                }
                Mutation::SetAttribute {
                    name: "data-testid",
                    value: AttributeValue::Text(value),
                    id,
                    ..
                } if *id == primary => {
                    assert_eq!(value, "send-chat-button");
                }
                _ => {}
            }
        }
    }
}

type FailureState = Rc<RefCell<Option<(Signal<Vec<ChatMessage>>, Signal<String>, Signal<String>)>>>;

fn send_failure_harness(control: FailureState) -> Element {
    let messages = use_signal(|| {
        vec![ChatMessage {
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
        }]
    });
    let status = use_signal(String::new);
    let draft = use_signal(String::new);
    *control.borrow_mut() = Some((messages, status, draft));
    rsx! {}
}

#[test]
fn encryption_context_refusal_restores_plaintext_for_fresh_authoring() {
    for next_draft in ["", "next message"] {
        let control = Rc::new(RefCell::new(None));
        let mut dom = VirtualDom::new_with_props(send_failure_harness, control.clone());
        dom.rebuild_to_vec();
        dom.in_scope(dioxus::dioxus_core::ScopeId::ROOT, || {
            let (messages, status, mut draft) = control.borrow().unwrap();
            draft.set(next_draft.to_owned());
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
            let rows = messages.read();
            assert!(!rows[0].pending);
            assert!(rows[0].failed);
            assert_eq!(rows[0].error.as_deref(), Some(status().as_str()));
            assert_eq!(
                draft(),
                if next_draft.is_empty() {
                    "original draft"
                } else {
                    next_draft
                }
            );
        });
    }
}

#[test]
fn unknown_submission_remains_pending_without_inviting_duplicate_authoring() {
    let control = Rc::new(RefCell::new(None));
    let mut dom = VirtualDom::new_with_props(send_failure_harness, control.clone());
    dom.rebuild_to_vec();
    dom.in_scope(dioxus::dioxus_core::ScopeId::ROOT, || {
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
        assert!(messages.read()[0].pending);
        assert!(!messages.read()[0].failed);
        assert!(draft().is_empty());
        assert!(!status().is_empty());
    });
}
