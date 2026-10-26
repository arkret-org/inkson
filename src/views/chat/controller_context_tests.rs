use super::*;
pub(super) fn context(
    scope: &Scope,
    path: &std::path::Path,
) -> Rc<crate::presentation::InksonContext> {
    crate::presentation::InksonContext::new(
        scope,
        crate::presentation::BootState {
            config_store: crate::config::LocalConfigStore::with_path(path.join("config.json")),
            config: crate::config::ClientConfig::default(),
            state_store: crate::presentation::SharedStateStore::new(LocalStateStore::with_path(
                path.join("state.json"),
            )),
            initial_credential: String::new(),
            realm_tree_nodes: Vec::new(),
        },
        Route::Dashboard,
        |_| {
            Box::pin(async {
                crate::runtime::session::CurrentSessionRefresh::retry_later("fixture")
            })
        },
    )
}
#[test]
fn production_controller_callback_keeps_owned_state_without_context_hooks() {
    let dir = tempfile::tempdir().unwrap();
    let app = glory::ui::App::memory();
    let scope = app.scope();
    let context = context(scope, dir.path());
    let authority = crate::test_support::authority("ak:did_core:web:alice.example");
    let device_id =
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap();
    let controller =
        chat_controller(scope, context.clone(), "", "", &authority, &device_id).unwrap();
    let command = ChatCommandContext {
        base_url: "://invalid-controller-fixture".into(),
        principal_id: authority.principal_id.clone(),
        authority,
        device_id,
        selected_realm_id: "invalid-realm".into(),
        selected_channel_id: "invalid-strand".into(),
        selected_channel_security_encrypted: true,
        token: context.token,
        frontier_state: context.frontier_state,
        known_agent_accounts: Default::default(),
        private_agent_scope: false,
    };
    let sentinel = scope.cage("stable controller state".to_owned());
    for _ in 0..4 {
        controller.add_reaction(
            command.clone(),
            "missing-message".into(),
            "invalid-event".into(),
            "👍".into(),
        );
        let settled = app.settle(glory::ui::App::DEFAULT_SETTLE_PASSES).unwrap();
        assert!(
            !settled.pending,
            "the invalid-target callback must settle without a loop"
        );
        assert_eq!(sentinel.get_untracked(), "stable controller state");
        assert!(
            controller
                .status_msg
                .get_untracked()
                .starts_with("Reaction skipped: invalid reaction target Event id:")
        );
    }
}

fn message(realm: &str, strand: &str) -> ChatMessage {
    ChatMessage {
        protocol_content: None,
        local_scope: None,
        realm_id: realm.into(),
        id: "private-row".into(),
        protocol_message_id: None,
        actor_id: None,
        sender: "fixture".into(),
        executed_by: None,
        body: "private session projection".into(),
        content_format: None,
        timestamp: "00:00".into(),
        created_at: None,
        strand_id: strand.into(),
        reply_to: None,
        reactions: vec![],
        redacted: false,
        edited: false,
        revisions: vec![],
        revision_source: None,
        pending: false,
        failed: false,
        error: None,
        mentions: vec![],
        crypto_state: MessageCryptoState::Plaintext,
    }
}

#[test]
fn common_controller_reuse_keeps_writes_and_pool_retirement_clears_private_projections() {
    let directory = tempfile::tempdir().unwrap();
    let app = glory::App::memory();
    let scope = app.scope();
    let context = context(scope, directory.path());
    let authority = crate::test_support::authority("ak:did_core:web:alice.example");
    let device =
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap();
    let event = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [31; 32]);
    let realm = arkret_sdk::RealmId::from_event_id(&event).to_string();
    let strand = arkret_sdk::StrandId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::DigestSuite::Sha256,
        [32; 32],
    ))
    .to_string();
    let original =
        chat_controller(scope, context.clone(), &realm, &strand, &authority, &device).unwrap();
    original
        .draft
        .revise(|draft| *draft = "retained unsent body".into());
    original
        .messages
        .revise(|rows| rows.push(message(&realm, &strand)));
    original.private_saved_account_data.revise(|values| {
        values.insert(
            "private-entry".into(),
            serde_json::json!({"private":"session-only"}),
        );
    });
    original
        .strand_watch_pending
        .revise(|pending| *pending = true);
    original
        .sidecar_send_pending
        .revise(|pending| *pending = true);
    let before = app.graph_stats().nodes;
    for _ in 0..8 {
        let again =
            chat_controller(scope, context.clone(), &realm, &strand, &authority, &device).unwrap();
        assert_eq!(again.messages.get_untracked().len(), 1);
        assert!(
            again.strand_watch_pending.get_untracked(),
            "a route return cannot retire an in-flight write"
        );
        assert!(again.sidecar_send_pending.get_untracked());
        assert_eq!(again.draft.get_untracked(), "retained unsent body");
        assert_eq!(
            app.graph_stats().nodes,
            before,
            "same target must reuse the root-owned graph"
        );
    }
    let revision = original.selection_revision.get_untracked();
    context.chat_state.retire_session();
    assert!(original.messages.get_untracked().is_empty());
    assert!(
        original
            .private_saved_account_data
            .get_untracked()
            .is_empty()
    );
    assert!(!original.strand_watch_pending.get_untracked());
    assert!(!original.sidecar_send_pending.get_untracked());
    assert_ne!(original.selection_revision.get_untracked(), revision);
    assert_eq!(original.draft.get_untracked(), "retained unsent body");
    let returned =
        chat_controller(scope, context.clone(), &realm, &strand, &authority, &device).unwrap();
    assert_eq!(returned.selected_channel.get_untracked(), strand);
    assert_eq!(
        app.graph_stats().nodes,
        before,
        "retirement must reset in place rather than orphan root nodes"
    );
    original
        .messages
        .revise(|rows| rows.push(message(&realm, &strand)));
    assert_eq!(
        returned.messages.get_untracked().len(),
        1,
        "command handles remain valid after reacquiring the controller"
    );
}

#[test]
fn common_target_distinguishes_station_device_realm_strand_and_unselected_or_invalid_coordinates() {
    let authority = crate::test_support::authority("ak:did_core:web:alice.example");
    let remote = crate::test_support::authority_at_station(
        "ak:did_core:web:alice.example",
        "ak:did_core:web:other-station.example",
    );
    let device =
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap();
    let other_device =
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000002").unwrap();
    let event =
        |byte| arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [byte; 32]);
    let realm = arkret_sdk::RealmId::from_event_id(&event(41)).to_string();
    let other_realm = arkret_sdk::RealmId::from_event_id(&event(42)).to_string();
    let strand = arkret_sdk::StrandId::from_event_id(&event(43)).to_string();
    let other_strand = arkret_sdk::StrandId::from_event_id(&event(44)).to_string();
    let targets = [
        CommonTarget::new(&authority, &device, &realm, &strand),
        CommonTarget::new(&remote, &device, &realm, &strand),
        CommonTarget::new(&authority, &other_device, &realm, &strand),
        CommonTarget::new(&authority, &device, &other_realm, &strand),
        CommonTarget::new(&authority, &device, &realm, &other_strand),
        CommonTarget::new(&authority, &device, &realm, ""),
        CommonTarget::new(&authority, &device, &realm, "invalid-strand"),
    ];
    assert_eq!(
        targets
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        targets.len()
    );
    assert!(matches!(targets[0].realm, CommonCoordinate::Typed(_)));
    assert!(matches!(
        targets[5].initial_strand,
        CommonCoordinate::Unselected
    ));
    assert!(matches!(
        targets[6].initial_strand,
        CommonCoordinate::Invalid(_)
    ));
}
