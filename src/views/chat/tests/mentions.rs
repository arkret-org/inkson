//! Mention labels, agent selector metadata and composer mention gating.

use super::*;

#[test]
fn mention_label_for_participant_never_derives_handle_from_did() {
    let participant = SpaceParticipant {
        actor_id: None,
        principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:web:example.com:users:bob".to_owned(),
        )
        .unwrap(),
        display_name: None,
        handle_label: None,
        display_name_rank: u8::MAX,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: false,
        agent_metadata: None,
    };

    assert!(mention_label_for_participant(&participant).is_none());
}

#[test]
fn mention_label_for_participant_requires_handle() {
    let participant = SpaceParticipant {
        actor_id: None,
        principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:webvh:zQmed2r1bBnz5cpB6SoL1UxvqNQPQpimEnHy7Rc9VLLrifC".to_owned(),
        )
        .unwrap(),
        display_name: None,
        handle_label: None,
        display_name_rank: u8::MAX,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: false,
        agent_metadata: None,
    };

    assert!(mention_label_for_participant(&participant).is_none());
}

#[test]
fn agent_metadata_from_mentions_recovers_selector_audit_metadata() {
    let messages = vec![ChatMessage {
        realm_id: "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE".to_owned(),
        id: "ak:event:A42FkwFdQPw7aC_yPcdlVU5ZjKLAnFCbmrXTVRJTNhRc".to_owned(),
        protocol_message_id: Some(
            "ak:message:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5".to_owned(),
        ),
        actor_id: None,
        sender: "ak:did_core:web:example.com:users:bob".to_owned(),
        executed_by: None,
        body: "@alice:example.com/summary".to_owned(),
        content_format: None,
        timestamp: "10:00".to_owned(),
        created_at: None,
        strand_id: "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q".to_owned(),
        reply_to: None,
        reactions: Vec::new(),
        redacted: false,
        edited: false,
        revisions: Vec::new(),
        revision_basis_refs: Vec::new(),
        pending: false,
        failed: false,
        error: None,
        mentions: vec![MentionNode::mention(
            arkret_sdk::Mention::new(local_fixture_account(
                "ak:did_core:web:agents.example:summary",
            ))
            .with_display_name_at_time("Summary Assistant")
            .with_agent_selector_metadata(
                local_fixture_account("ak:did_core:web:example.com:users:alice"),
                arkret_sdk::Handle::parse("alice:example.com").unwrap(),
                "summary",
            )
            .with_mention_text_original("@alice:example.com/summary")
            .with_resolved_at(
                chrono::DateTime::parse_from_rfc3339("2026-06-12T00:00:00.000Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
        )],
        crypto_state: MessageCryptoState::Plaintext,
    }];

    let metadata = agent_metadata_from_mentions(&messages);
    let summary = metadata
        .get("ak:did_core:web:agents.example:summary")
        .expect("agent metadata");
    assert_eq!(
        summary.controller_principal_id,
        "ak:did_core:web:example.com:users:alice"
    );
    assert_eq!(summary.controller_handle, "alice:example.com");
    assert_eq!(summary.agent_slug, "summary");
    assert_eq!(summary.display_name, "Summary Assistant");
}

#[test]
fn mention_audit_metadata_cannot_promote_or_rebind_an_agent() {
    let agent_id = "ak:did_core:web:agents.example:summary";
    let mut authoritative = std::collections::BTreeMap::from([(
        agent_id.to_owned(),
        AgentParticipantMetadata {
            controller_principal_id: "ak:did_core:web:example.com:users:alice".to_owned(),
            controller_handle: "alice:example.com".to_owned(),
            agent_slug: "summary".to_owned(),
            display_name: "summary".to_owned(),
        },
    )]);
    let audit_metadata = std::collections::BTreeMap::from([
        (
            agent_id.to_owned(),
            AgentParticipantMetadata {
                controller_principal_id: "ak:did_core:web:example.com:users:mallory".to_owned(),
                controller_handle: "mallory:example.com".to_owned(),
                agent_slug: "stolen".to_owned(),
                display_name: "Forged Agent".to_owned(),
            },
        ),
        (
            "ak:did_core:web:example.com:users:bob".to_owned(),
            AgentParticipantMetadata {
                controller_principal_id: "ak:did_core:web:example.com:users:alice".to_owned(),
                controller_handle: "alice:example.com".to_owned(),
                agent_slug: "review".to_owned(),
                display_name: "Forged Bob Agent".to_owned(),
            },
        ),
    ]);

    enrich_authoritative_agent_metadata(&mut authoritative, audit_metadata);

    assert_eq!(authoritative.len(), 1);
    let summary = authoritative.get(agent_id).unwrap();
    assert_eq!(
        summary.controller_principal_id,
        "ak:did_core:web:example.com:users:alice"
    );
    assert_eq!(summary.controller_handle, "alice:example.com");
    assert_eq!(summary.agent_slug, "summary");
    assert_eq!(summary.display_name, "summary");
}

#[test]
fn owned_agent_ids_only_select_current_controllers_agents() {
    let controller = "ak:did_core:web:example.com:users:alice";
    let own_agent = arkret_sdk::Mention::new(local_fixture_account(
        "ak:did_core:web:agents.example:summary",
    ))
    .with_agent_selector_metadata(
        local_fixture_account(controller),
        arkret_sdk::Handle::parse("alice:example.com").unwrap(),
        "summary",
    );
    let other_agent = arkret_sdk::Mention::new(local_fixture_account(
        "ak:did_core:web:agents.example:review",
    ))
    .with_agent_selector_metadata(
        local_fixture_account("ak:did_core:web:example.com:users:bob"),
        arkret_sdk::Handle::parse("bob:example.com").unwrap(),
        "review",
    );

    let ids = owned_agent_ids_from_mentions(
        &[
            MentionNode::mention(own_agent.clone()),
            MentionNode::mention(other_agent),
            MentionNode::mention(own_agent),
        ],
        controller,
    );

    assert_eq!(ids, vec!["ak:did_core:web:agents.example:summary"]);
}

#[test]
fn composer_owned_agent_ids_keep_verified_picker_agent_before_handle_loads() {
    let controller = "ak:did_core:web:example.com:users:alice";
    let picker = vec![crate::messaging::mentions::MentionCandidate {
        subject_account_id: local_fixture_account("ak:did_core:web:agents.example:summary"),
        display_name: "Summary Assistant".to_owned(),
        insert_label: "me/summary".to_owned(),
        subtitle: "Your agent".to_owned(),
        is_agent: true,
        controller_subject_account_id: Some(local_fixture_account(controller)),
        controller_handle_at_time: String::new(),
        agent_slug_at_time: "summary".to_owned(),
    }];

    let ids = owned_agent_ids_from_composer(
        true,
        "ask @me/summary for an update",
        &[],
        &picker,
        controller,
    );

    assert_eq!(ids, vec!["ak:did_core:web:agents.example:summary"]);
    assert!(
        owned_agent_ids_from_composer(true, "ask for an update", &[], &picker, controller)
            .is_empty()
    );
}

#[test]
fn owned_agent_mentions_do_not_reopen_sidecar_from_private_composer() {
    assert!(should_route_owned_agent_to_sidecar(
        false, false, true, true
    ));
    assert!(!should_route_owned_agent_to_sidecar(
        true, false, true, true
    ));
    assert!(!should_route_owned_agent_to_sidecar(
        false, true, true, true
    ));
}

#[test]
fn direct_chat_disables_mention_ui_triggers_and_send_metadata() {
    let principal_id = "ak:did_core:web:example.com:users:alice";
    let stale_picker = vec![crate::messaging::mentions::MentionCandidate {
        subject_account_id: local_fixture_account("ak:did_core:web:example.com:users:bob"),
        display_name: "Bob".to_owned(),
        insert_label: "bob:example.com".to_owned(),
        subtitle: String::new(),
        is_agent: false,
        controller_subject_account_id: None,
        controller_handle_at_time: String::new(),
        agent_slug_at_time: String::new(),
    }];

    let mentions_enabled = composer::chat_mentions_enabled(true);
    assert!(!mentions_enabled);
    assert!(
        !composer::chat_composer_placeholder(mentions_enabled).contains('@'),
        "direct-chat placeholder must not advertise mentions"
    );
    assert!(
        composer::active_composer_mention_token(mentions_enabled, "hello @").is_none(),
        "typing @ in direct chat must not activate the picker"
    );
    assert!(
        composer_mention_nodes(
            mentions_enabled,
            "hello @me @all @bob:example.com",
            &stale_picker,
            principal_id,
        )
        .is_empty(),
        "direct-chat sends must not carry mention metadata"
    );
    assert!(
        owned_agent_ids_from_composer(
            mentions_enabled,
            "ask @me/summary",
            &[],
            &stale_picker,
            principal_id,
        )
        .is_empty(),
        "direct-chat text must not trigger agent mention routing"
    );

    let collaboration_mentions_enabled = composer::chat_mentions_enabled(false);
    assert!(collaboration_mentions_enabled);
    assert!(
        composer::active_composer_mention_token(collaboration_mentions_enabled, "hello @")
            .is_some()
    );
    assert!(
        composer::chat_composer_placeholder(collaboration_mentions_enabled).contains('@'),
        "collaboration composer must keep advertising mentions"
    );
}

#[test]
fn composer_enter_behavior_matches_chat_conventions_and_protects_ime_input() {
    assert!(composer::chat_composer_should_send_key(
        "Enter", false, false, false, false,
    ));
    assert!(
        !composer::chat_composer_should_send_key("Enter", true, false, false, false),
        "Shift+Enter must remain available for new lines"
    );
    assert!(
        !composer::chat_composer_should_send_key("Enter", false, false, true, false),
        "IME candidate confirmation must not send a message"
    );
    assert!(
        !composer::chat_composer_should_send_key("Enter", false, false, false, true),
        "holding Enter must not trigger repeated sends"
    );
    assert!(
        !composer::chat_composer_should_send_key("Enter", false, true, false, false),
        "Alt+Enter must remain available to the platform"
    );
    assert!(!composer::chat_composer_should_send_key(
        "Space", false, false, false, false,
    ));
}

#[test]
fn encrypted_send_stays_blocked_until_creator_governance_bootstrap_converges() {
    assert!(composer::chat_secure_send_blocked(
        false, true, false, false
    ));
    assert!(!composer::chat_secure_send_blocked(
        false, false, false, false
    ));
}
