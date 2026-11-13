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
fn late_secure_draft_hydration_updates_the_installed_pool_without_rebinding() {
    use crate::secure_key_store::SecureKeyStore as _;
    let secure = std::sync::Arc::new(crate::secure_key_store::MemorySecureKeyStore::default());
    let _secure = crate::secure_key_store::DefaultSecureKeyStoreTestGuard::replace(secure.clone());
    let directory = tempfile::tempdir().unwrap();
    let app = glory::App::memory();
    let context = context(app.scope(), directory.path());
    let account = crate::test_support::AccountFixture::new("did:web:alice.example").build();
    context
        .state_store
        .write(|store| store.switch_active_account(&account))
        .unwrap();
    context
        .active_account
        .revise(|active| *active = Some(account.clone()));
    let target = ComposerTarget {
        authority: account.authority.clone(),
        device_id: account.device_id.clone(),
        realm_id: arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [73; 32],
        ))
        .to_string(),
        strand_id: arkret_sdk::StrandId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [74; 32],
        ))
        .to_string(),
    };
    let state = composer_state(&context, target.clone()).unwrap();
    // Another durable write owns the worker; hydration may queue this draft,
    // but may not claim it is saved before the real writer acknowledges it.
    context.chat_state.running.revise(|running| *running = true);
    app.settle(glory::App::DEFAULT_SETTLE_PASSES).unwrap();
    assert_eq!(
        context.state_store.read(|store| store.active_authority()),
        Some(account.authority.clone())
    );
    assert!(composer_session_matches(
        &context,
        &target,
        context.session_generation.get_untracked()
    ));
    assert!(state.draft.get_untracked().is_empty());
    let mut backing = LocalStateStore::with_path(directory.path().join("backing.json"));
    backing.switch_active_account(&account).unwrap();
    let (key, json) = backing
        .prepare_composer_draft_write(
            &target.authority,
            &target.device_id,
            &target.realm_id,
            &target.strand_id,
            "late retained main draft".into(),
        )
        .unwrap();
    secure.store_secret(&key, json.as_deref().unwrap()).unwrap();
    context
        .state_store
        .write(|store| store.hydrate_e2ee_plaintext_cache_with_secure_store(secure.as_ref()))
        .unwrap();
    context
        .state_revision
        .revise(|revision| *revision = revision.wrapping_add(1));
    app.settle(glory::App::DEFAULT_SETTLE_PASSES).unwrap();
    assert_eq!(state.draft.get_untracked(), "late retained main draft");
    assert!(state.draft_saved.get_untracked().is_empty());
    assert_eq!(state.draft_storage.get_untracked(), "saving");
    assert_eq!(
        context
            .chat_state
            .pending
            .get_untracked()
            .get(&target)
            .unwrap()
            .1,
        "late retained main draft",
    );
    state.draft_edited.revise(|edited| *edited = true);
    state.draft.revise(String::clear);
    context
        .state_revision
        .revise(|revision| *revision = revision.wrapping_add(1));
    app.settle(glory::App::DEFAULT_SETTLE_PASSES).unwrap();
    assert!(
        state.draft.get_untracked().is_empty(),
        "a user clear owns the view"
    );
}

#[test]
fn pooled_empty_composer_accepts_late_private_hydration_without_replacing_user_edits() {
    let directory = tempfile::tempdir().unwrap();
    let app = glory::App::memory();
    let context = context(app.scope(), directory.path());
    let authority = crate::test_support::authority("ak:did_core:web:alice.example");
    let device =
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap();
    let target = ComposerTarget {
        authority,
        device_id: device,
        realm_id: "late-realm".into(),
        strand_id: "main-chat".into(),
    };
    let state = composer_state(&context, target).unwrap();
    assert!(state.draft.get_untracked().is_empty());
    assert!(restore_untouched_composer_draft(
        state,
        "retained main draft"
    ));
    assert_eq!(state.draft.get_untracked(), "retained main draft");
    assert!(!restore_untouched_composer_draft(state, "older draft"));
    state.draft.revise(|draft| draft.clear());
    state.draft_saved.revise(|draft| draft.clear());
    state.draft_edited.revise(|edited| *edited = true);
    assert!(!restore_untouched_composer_draft(
        state,
        "must not revive an explicit clear"
    ));
    state.draft_edited.revise(|edited| *edited = false);
    state.pending_drafts.revise(|pending| {
        pending.insert("pending-send".into(), "owned pending body".into());
    });
    assert!(!restore_untouched_composer_draft(
        state,
        "must not replace a pending send"
    ));
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
        controller.add_reaction(command.clone(), "invalid-event".into(), "👍".into());
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
                .starts_with("Reaction skipped: invalid reaction target Message id:")
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

#[test]
fn realm_default_refresh_preserves_explicit_circle_selection_and_pinned_targets() {
    let directory = tempfile::tempdir().unwrap();
    let app = glory::App::memory();
    let scope = app.scope();
    let context = context(scope, directory.path());
    let authority = crate::test_support::authority("ak:did_core:web:alice.example");
    let device =
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap();
    let event =
        |byte| arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [byte; 32]);
    let realm = arkret_sdk::RealmId::from_event_id(&event(51)).to_string();
    let strand = |byte| arkret_sdk::StrandId::from_event_id(&event(byte)).to_string();
    let original_default = strand(52);
    let updated_default = strand(53);
    let circle_strand = strand(54);
    let acquire = |initial: &str, pinned| {
        chat_controller_for_initial_target(
            scope,
            context.clone(),
            &realm,
            initial,
            &authority,
            &device,
            pinned,
        )
        .unwrap()
    };
    let original = acquire("", false);
    assert!(original.selected_channel.get_untracked().is_empty());
    let hydrated = acquire(&original_default, false);
    ChatProjectionSink::new(hydrated).emit(ChatProjectionEvent::EnsureChannel(
        discussion_channel_for_strand(&original_default).unwrap(),
    ));
    assert_eq!(original.selected_channel.get_untracked(), original_default);
    original.select_channel(circle_strand.clone());
    let circle_composer = original
        .for_strand(&context, &authority, &device, &realm, &circle_strand)
        .unwrap();
    assert_eq!(
        circle_composer.draft_strand_id.get_untracked(),
        circle_strand
    );
    circle_composer
        .draft
        .revise(|draft| *draft = "unsent Circle body".into());
    let selected_revision = original.selection_revision.get_untracked();
    let node_count = app.graph_stats().nodes;
    for initial in [&original_default, &updated_default, ""] {
        let refreshed = acquire(initial, false);
        if let Some(channel) = discussion_channel_for_strand(&updated_default) {
            ChatProjectionSink::new(refreshed).emit(ChatProjectionEvent::EnsureChannel(channel));
        } else {
            panic!("The updated default fixture must be a valid Strand");
        }
        assert_eq!(refreshed.selected_channel.get_untracked(), circle_strand);
        assert_eq!(
            refreshed.selection_revision.get_untracked(),
            selected_revision
        );
        let composer = refreshed
            .for_strand(&context, &authority, &device, &realm, &circle_strand)
            .unwrap();
        assert_eq!(composer.draft.get_untracked(), "unsent Circle body");
        assert_eq!(app.graph_stats().nodes, node_count);
    }
    let pinned_original = acquire(&original_default, true);
    let pinned_updated = acquire(&updated_default, true);
    assert_eq!(
        pinned_original.selected_channel.get_untracked(),
        original_default
    );
    assert_eq!(
        pinned_updated.selected_channel.get_untracked(),
        updated_default
    );
    let original_revision = pinned_original.selection_revision.get_untracked();
    pinned_original.prepare_channel_switch(&updated_default);
    assert_ne!(
        pinned_original.selection_revision.get_untracked(),
        original_revision
    );
    assert_eq!(
        acquire(&original_default, true)
            .selected_channel
            .get_untracked(),
        original_default,
        "reopening the original pinned controller retains its own Strand",
    );
    assert_eq!(original.selected_channel.get_untracked(), circle_strand);
    assert_ne!(
        CommonTarget::for_initial_target(&authority, &device, &realm, "", false),
        CommonTarget::new(&authority, &device, &realm, ""),
        "An unpinned Realm is distinct from an empty pinned target",
    );
    context.chat_state.retire_session();
    let returned = acquire(&updated_default, false);
    assert_eq!(returned.selected_channel.get_untracked(), updated_default);
    returned.select_channel(circle_strand.clone());
    assert_eq!(original.selected_channel.get_untracked(), circle_strand);
}
