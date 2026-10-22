use std::cell::RefCell;
use std::rc::Rc;

use super::*;
use crate::state::current_index::search::tests::authorized_store;

#[tokio::test(flavor = "current_thread")]
async fn native_host_search_uses_secure_grant_without_publishing_it_to_account_state() {
    let (_directory, mut store, account, original) = authorized_store().await;
    let grant = store.session_grant().unwrap();
    store.set_session_grant(None);
    let shared = std::sync::Arc::new(std::sync::Mutex::new(store));
    let reader = shared.clone();
    let writer = shared.clone();
    let handle = crate::runtime::input::StateStoreHandle::new(
        move |read| read(&reader.lock().unwrap()),
        move |write| write(&mut writer.lock().unwrap()),
    );
    for variant in 0..4 {
        let mut candidate = grant.clone();
        match variant {
            1 => candidate.account_id.station_id = "ak:did_core:web:other.example".parse().unwrap(),
            2 => {
                candidate.device_id = "ak:device:0196419b-0000-7000-8000-000000000002"
                    .parse()
                    .unwrap()
            }
            3 => candidate.grant_expires_at = Some(chrono::Utc::now()),
            _ => {}
        }
        let (view, deadline) = search_native_index(
            handle.clone(),
            &account.authority,
            &account.device_id,
            &candidate,
            "needle",
            &[],
            100,
        )
        .await
        .unwrap();
        assert_eq!(view.results.len(), usize::from(variant == 0));
        assert_eq!(deadline.is_some(), variant == 0);
        if variant == 0 {
            assert_eq!(view.results[0]["event_id"], json!(original.event.event_id));
            assert_eq!(view.results[0]["covering_commit"], json!(original.commit));
        }
        assert!(shared.lock().unwrap().session_grant().is_none());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn native_search_policy_window_withdraws_and_restores_without_a_new_cut() {
    use crate::state::current_index::search::tests::{install_search_policies, search_policy};
    for kind in [
        arkret_wire::PolicyKind::Access,
        arkret_wire::PolicyKind::Moderation,
        arkret_wire::PolicyKind::Retention,
    ] {
        let (_directory, mut store, account, original) = authorized_store().await;
        let starts = chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis())
            .unwrap()
            + chrono::Duration::seconds(2);
        let ends = starts + chrono::Duration::seconds(2);
        let policy = search_policy(&original, kind, Some(starts), Some(ends));
        install_search_policies(&mut store, &[policy]).await;
        let generation = store.current_generation();
        let (mut dom, harness) = mount(store, account);
        settle(&mut dom, &harness, 1).await;
        let (context, search) = harness.handles.borrow().unwrap();
        dom.in_runtime(|| assert_eq!(*search.recheck_at.peek(), Some(starts)));
        settle(&mut dom, &harness, 0).await;
        dom.in_runtime(|| {
            assert_eq!(*search.recheck_at.peek(), Some(ends));
            assert_eq!(context.state_store.peek().current_generation(), generation);
            assert!(search_holder_ready(context));
        });
        settle(&mut dom, &harness, 1).await;
        dom.in_runtime(|| {
            assert_eq!(*search.recheck_at.peek(), None);
            assert_eq!(context.state_store.peek().current_generation(), generation);
            assert_eq!(
                search.results.peek()[0]["event_id"],
                json!(original.event.event_id)
            );
            assert_eq!(
                search.results.peek()[0]["covering_commit"],
                json!(original.commit)
            );
            assert_eq!(
                search.results.peek()[0]["content"]["body"],
                "exact original needle"
            );
            assert!(search.error_key.peek().is_none());
        });
    }
}

#[tokio::test(flavor = "current_thread")]
async fn native_search_policy_replacement_cancels_the_old_boundary_and_cold_read_rechecks() {
    use crate::state::current_index::search::tests::{install_search_policies, search_policy};
    let (directory, mut store, account, original) = authorized_store().await;
    let old_start = chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis())
        .unwrap()
        + chrono::Duration::seconds(2);
    let first = search_policy(
        &original,
        arkret_wire::PolicyKind::Retention,
        Some(old_start),
        None,
    );
    install_search_policies(&mut store, std::slice::from_ref(&first)).await;
    let (mut dom, harness) = mount(store, account.clone());
    settle(&mut dom, &harness, 1).await;
    let (mut context, search) = harness.handles.borrow().unwrap();
    let mut replacement = first.clone();
    replacement.not_before = Some(old_start + chrono::Duration::seconds(2));
    let mut updated = dom.in_runtime(|| context.state_store.peek().clone());
    install_search_policies(&mut updated, &[first, replacement.clone()]).await;
    dom.in_runtime(|| context.state_store.set(updated));
    settle(&mut dom, &harness, 1).await;
    while chrono::Utc::now() < old_start + chrono::Duration::milliseconds(100) {
        dom.render_immediate_to_vec();
        crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(10)).await;
    }
    dom.in_runtime(|| {
        assert_eq!(search.results.peek().len(), 1);
        assert_eq!(*search.recheck_at.peek(), replacement.not_before);
    });
    settle(&mut dom, &harness, 0).await;
    let mut reopened = LocalStateStore::with_path(directory.path().join("holder.json"));
    reopened.switch_active_account(&account).unwrap();
    assert!(
        local_decrypted_index_search(
            &reopened,
            &account.authority,
            &account.device_id,
            "needle",
            &[],
            None,
            50
        )
        .await
        .unwrap()
        .results
        .is_empty()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn native_search_event_crop_withdraws_visible_body_and_full_replay_cannot_restore_it() {
    use crate::state::current_index::search::tests::{
        install_current_only_search_event_redaction, install_search_disclosure,
    };
    let (directory, store, account, _) = authorized_store().await;
    let (mut dom, harness) = mount(store, account.clone());
    settle(&mut dom, &harness, 1).await;
    let (mut context, search) = harness.handles.borrow().unwrap();
    let mut updated = dom.in_runtime(|| context.state_store.peek().clone());
    install_current_only_search_event_redaction(&mut updated).await;
    dom.in_runtime(|| {
        harness.retry.borrow().unwrap().call(());
        context.state_store.set(updated);
    });
    settle(&mut dom, &harness, 0).await;
    let mut recovered = LocalStateStore::with_path(directory.path().join("holder.json"));
    recovered.switch_active_account(&account).unwrap();
    install_search_disclosure(&mut recovered, true, false).await;
    dom.in_runtime(|| {
        context.state_store.set(recovered);
        harness.retry.borrow().unwrap().call(());
    });
    settle(&mut dom, &harness, 0).await;
    dom.in_runtime(|| assert!(search.error_key.peek().is_none()));
}

#[tokio::test(flavor = "current_thread")]
async fn native_search_disclosure_withdraws_and_recovers_only_after_durable_full_publication() {
    use crate::state::current_index::search::tests::install_search_disclosure;
    let (directory, store, account, original) = authorized_store().await;
    let (mut dom, harness) = mount(store, account.clone());
    settle(&mut dom, &harness, 1).await;
    let (mut context, search) = harness.handles.borrow().unwrap();
    let mut updated = dom.in_runtime(|| context.state_store.peek().clone());
    install_search_disclosure(&mut updated, false, false).await;
    dom.in_runtime(|| context.state_store.set(updated));
    settle(&mut dom, &harness, 0).await;
    let mut updated = dom.in_runtime(|| context.state_store.peek().clone());
    install_search_disclosure(&mut updated, true, true).await;
    dom.in_runtime(|| {
        context.state_store.set(updated);
        harness.retry.borrow().unwrap().call(());
    });
    settle(&mut dom, &harness, 0).await;
    let mut recovered = LocalStateStore::with_path(directory.path().join("holder.json"));
    recovered.switch_active_account(&account).unwrap();
    install_search_disclosure(&mut recovered, true, false).await;
    dom.in_runtime(|| context.state_store.set(recovered));
    settle(&mut dom, &harness, 1).await;
    dom.in_runtime(|| {
        let rows = search.results.peek();
        assert_eq!(rows[0]["event_id"], original.event.event_id.as_str());
        assert_eq!(
            rows[0]["source_commit"],
            serde_json::to_value(&original.commit).unwrap()
        );
        assert_eq!(rows[0]["content"]["body"], "exact original needle");
    });
    let mut updated = dom.in_runtime(|| context.state_store.peek().clone());
    install_search_disclosure(&mut updated, false, false).await;
    dom.in_runtime(|| context.state_store.set(updated));
    settle(&mut dom, &harness, 0).await;
}

#[tokio::test(flavor = "current_thread")]
async fn native_search_local_block_withdraws_visible_body_and_unblock_restores_retained_original() {
    let (directory, store, account, original) = authorized_store().await;
    let (mut dom, harness) = mount(store, account.clone());
    settle(&mut dom, &harness, 1).await;
    let (mut context, search) = harness.handles.borrow().unwrap();
    let actor = original.event.actor_id.to_string();
    let (generation, revision) = dom.in_runtime(|| {
        let store = context.state_store.peek();
        (
            store.current_generation(),
            store.client_blocklist_revision(),
        )
    });
    dom.in_runtime(|| {
        assert!(context.state_store.write().block_target(
            crate::account_data::BlocklistUiTargetKind::Actor, &actor, None,
            vec![arkret_models_collaboration::objects::productivity::AccountBlocklistSurface::Messages], None,
        ));
        let store = context.state_store.peek();
        assert_eq!(store.current_generation(), generation);
        assert_eq!(store.client_blocklist_revision(), revision);
    });
    settle(&mut dom, &harness, 0).await;
    dom.in_runtime(|| harness.retry.borrow().unwrap().call(()));
    settle(&mut dom, &harness, 0).await;
    let mut recovered = LocalStateStore::with_path(directory.path().join("holder.json"));
    recovered.switch_active_account(&account).unwrap();
    assert!(
        local_decrypted_index_search(
            &recovered,
            &account.authority,
            &account.device_id,
            "needle",
            &[],
            None,
            50
        )
        .await
        .unwrap()
        .results
        .is_empty()
    );
    dom.in_runtime(|| {
        context.state_store.set(recovered);
        assert!(context.state_store.write().unblock_user(&actor));
    });
    settle(&mut dom, &harness, 1).await;
    dom.in_runtime(|| {
        let results = search.results.peek();
        assert_eq!(results[0]["event_id"], original.event.event_id.as_str());
        assert_eq!(
            results[0]["covering_commit"],
            serde_json::to_value(&original.commit).unwrap()
        );
        assert_eq!(results[0]["content"]["body"], "exact original needle");
        assert!(search.error_key.peek().is_none());
    });
}

#[tokio::test(flavor = "current_thread")]
async fn native_search_blocklist_uses_exact_actor_mode_surface_and_expiry() {
    use arkret_models_collaboration::objects::productivity::{
        AccountBlocklistMode as Mode, AccountBlocklistSurface as Surface,
    };
    for scenario in [
        "block",
        "hide",
        "mute",
        "other_surface",
        "expired",
        "other_station",
    ] {
        let (_directory, store, account, original) = authorized_store().await;
        let (mut dom, harness) = mount(store, account);
        settle(&mut dom, &harness, 1).await;
        let (mut context, search) = harness.handles.borrow().unwrap();
        let actor = if scenario == "other_station" {
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                original.event.actor_id.signing_principal_id().clone(),
                "ak:did_core:web:other.example".parse().unwrap(),
            ))
        } else {
            original.event.actor_id.clone()
        };
        let mut entry = crate::account_data::new_blocklist_entry(
            crate::account_data::BlocklistUiTargetKind::Actor,
            &actor.to_string(),
            None,
            vec![if scenario == "other_surface" {
                Surface::Calls
            } else {
                Surface::Messages
            }],
            (scenario == "expired").then(|| chrono::Utc::now() - chrono::Duration::seconds(1)),
            chrono::Utc::now() - chrono::Duration::minutes(1),
        )
        .unwrap();
        entry.mode = match scenario {
            "hide" => Mode::Hide,
            "mute" => Mode::Mute,
            _ => Mode::Block,
        };
        dom.in_runtime(|| {
            context
                .state_store
                .write()
                .set_client_blocklist(1, vec![entry])
        });
        let expected = usize::from(!matches!(scenario, "block" | "hide"));
        // The explicit query also proves unchanged effective predicates remain
        // searchable when a mute, another surface or another Station is edited.
        dom.in_runtime(|| harness.retry.borrow().unwrap().call(()));
        settle(&mut dom, &harness, expected).await;
        dom.in_runtime(|| assert!(search.error_key.peek().is_none(), "{scenario}"));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn native_search_pending_request_cannot_republish_a_newly_blocked_sender() {
    let (_directory, store, account, original) = authorized_store().await;
    let (mut dom, harness) = mount(store, account);
    settle(&mut dom, &harness, 1).await;
    let (mut context, search) = harness.handles.borrow().unwrap();
    dom.in_runtime(|| {
        harness.retry.borrow().unwrap().call(());
        assert!(*search.loading.peek());
        assert!(context.state_store.write().block_target(
            crate::account_data::BlocklistUiTargetKind::Actor, original.event.actor_id.to_string(), None,
            vec![arkret_models_collaboration::objects::productivity::AccountBlocklistSurface::Messages], None,
        ));
    });
    settle(&mut dom, &harness, 0).await;
    for _ in 0..10 {
        dom.render_immediate_to_vec();
        crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(2)).await;
        dom.in_runtime(|| assert!(search.results.peek().is_empty()));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn native_search_current_revision_hides_stale_body_and_recovers_exact_original() {
    let (_directory, store, account, original) = authorized_store().await;
    let (mut dom, harness) = mount(store, account);
    settle(&mut dom, &harness, 1).await;
    let (mut context, search) = harness.handles.borrow().unwrap();
    dom.in_runtime(|| {
        assert_eq!(
            search.results.peek()[0]["event_id"],
            original.event.event_id.as_str()
        )
    });
    let mut updated = dom.in_runtime(|| context.state_store.peek().clone());
    crate::state::current_index::search::tests::install_search_revision(&mut updated, false).await;
    dom.in_runtime(|| context.state_store.set(updated));
    settle(&mut dom, &harness, 0).await;
    dom.in_runtime(|| harness.retry.borrow().unwrap().call(()));
    settle(&mut dom, &harness, 0).await;
    let mut updated = dom.in_runtime(|| context.state_store.peek().clone());
    let revision =
        crate::state::current_index::search::tests::install_search_revision(&mut updated, true)
            .await;
    dom.in_runtime(|| context.state_store.set(updated));
    settle(&mut dom, &harness, 1).await;
    dom.in_runtime(|| {
        let results = search.results.peek();
        assert_eq!(results[0]["event_id"], original.event.event_id.as_str());
        assert_eq!(results[0]["content"]["body"], "current replacement needle");
        assert_eq!(
            results[0]["source_event_id"],
            revision.event.event_id.as_str()
        );
        assert_eq!(
            results[0]["source_commit"],
            serde_json::to_value(&revision.commit).unwrap()
        );
        assert!(search.error_key.peek().is_none());
        assert_eq!(
            revision.event.payload["content"]["body"],
            "current replacement needle"
        );
    });
}

#[tokio::test(flavor = "current_thread")]
async fn native_search_current_only_redaction_removes_visible_body_and_retry_stays_empty() {
    let (_directory, store, account, original) = authorized_store().await;
    let (mut dom, harness) = mount(store, account);
    settle(&mut dom, &harness, 1).await;
    let (mut context, search) = harness.handles.borrow().unwrap();
    dom.in_runtime(|| {
        assert_eq!(
            search.results.peek()[0]["event_id"],
            original.event.event_id.as_str()
        )
    });
    let mut updated = dom.in_runtime(|| context.state_store.peek().clone());
    crate::state::current_index::search::tests::install_current_only_search_redaction(&mut updated)
        .await;
    dom.in_runtime(|| context.state_store.set(updated));
    settle(&mut dom, &harness, 0).await;
    dom.in_runtime(|| harness.retry.borrow().unwrap().call(()));
    settle(&mut dom, &harness, 0).await;
    dom.in_runtime(|| assert!(search.error_key.peek().is_none()));
}

type Input = (LocalStateStore, crate::config::ActiveAccountContext);

#[tokio::test(flavor = "current_thread")]
async fn native_search_account_list_removal_withdraws_retained_body_and_cold_retry_stays_empty() {
    let (directory, store, account, original) = authorized_store().await;
    let (mut dom, harness) = mount(store, account.clone());
    settle(&mut dom, &harness, 1).await;
    let (mut context, search) = harness.handles.borrow().unwrap();
    let mut updated = dom.in_runtime(|| context.state_store.peek().clone());
    let frame = serde_json::from_value(json!({"kind":"delta","cursor":"ak:cursor:YQ",
        "realm_list_changes":{"upserts":[],"removals":[{"realm_id":original.event.realm_id,"revision":100_000}]}})).unwrap();
    crate::state::current_index::search::tests::install_account_scope_frame(&mut updated, &frame)
        .await;
    assert!(updated.search_session_matches(&account.authority, &account.device_id));
    dom.in_runtime(|| context.state_store.set(updated));
    settle(&mut dom, &harness, 0).await;
    dom.in_runtime(|| harness.retry.borrow().unwrap().call(()));
    settle(&mut dom, &harness, 0).await;
    dom.in_runtime(|| assert!(search.error_key.peek().is_none()));
    let mut cold = LocalStateStore::with_path(directory.path().join("holder.json"));
    cold.switch_active_account(&account).unwrap();
    assert!(cold.search_session_matches(&account.authority, &account.device_id));
    let (view, _) = search_local(
        SearchSource::Borrowed(&cold),
        &account.authority,
        &account.device_id,
        "needle",
        &[],
        Some(&["message"]),
        100,
    )
    .await
    .unwrap();
    assert!(view.results.is_empty());
}
type Handles = (crate::app::SessionContext, LocalSearchState);

#[derive(Clone)]
struct Harness {
    input: Rc<RefCell<Option<Input>>>,
    handles: Rc<RefCell<Option<Handles>>>,
    retry: Rc<RefCell<Option<EventHandler<()>>>>,
}

fn surface(harness: Harness) -> Element {
    let (store, account) = use_hook(|| harness.input.borrow_mut().take().unwrap());
    let state_store = use_signal_sync(|| store);
    let active_account = use_signal(|| Some(account));
    let base_url = use_signal(String::new);
    let session_generation = use_signal(|| 0);
    let owned_agents_rev = use_signal(|| 0);
    let context = use_context_provider(|| crate::app::SessionContext {
        active_account,
        state_store,
        base_url,
        session_generation,
        owned_agents_rev,
    });
    let search = use_local_search("needle".into());
    let retry = use_callback(move |()| {
        let account = context.active_account.peek().clone().unwrap();
        run_search(
            "needle".into(),
            context.state_store,
            account.authority,
            account.device_id,
            search.results,
            search.loading,
            search.error_key,
            search.has_searched,
            search.search_epoch,
            search.last_search,
            search.recheck_at,
        );
    });
    *harness.handles.borrow_mut() = Some((context, search));
    *harness.retry.borrow_mut() = Some(retry);
    rsx! {}
}

fn mount(
    store: LocalStateStore,
    account: crate::config::ActiveAccountContext,
) -> (VirtualDom, Harness) {
    let harness = Harness {
        input: Rc::new(RefCell::new(Some((store, account)))),
        handles: Rc::new(RefCell::new(None)),
        retry: Rc::new(RefCell::new(None)),
    };
    let mut dom = VirtualDom::new_with_props(surface, harness.clone());
    dom.rebuild_in_place();
    (dom, harness)
}

async fn settle(dom: &mut VirtualDom, harness: &Harness, expected: usize) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            dom.render_immediate_to_vec();
            let (_, search) = harness.handles.borrow().unwrap();
            if dom.in_runtime(|| {
                *search.has_searched.peek()
                    && !*search.loading.peek()
                    && search.results.peek().len() == expected
            }) {
                return;
            }
            crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("production search must settle at the expected authorization cut");
}

#[tokio::test(flavor = "current_thread")]
async fn native_search_visible_results_expire_at_each_holder_deadline() {
    for boundary in ["session", "projection", "authorization"] {
        let (_directory, mut store, account, original) = authorized_store().await;
        let expiry = chrono::Utc::now() + chrono::Duration::seconds(2);
        let mut state = store.load();
        match boundary {
            "session" => state.session_grant.as_mut().unwrap().grant_expires_at = Some(expiry),
            "projection" => {
                state
                    .device_authoring_authority
                    .as_mut()
                    .unwrap()
                    .device_projection
                    .expires_at = expiry
            }
            _ => {
                state
                    .device_authoring_authority
                    .as_mut()
                    .unwrap()
                    .device_projection
                    .authorization_window
                    .expires_at = Some(expiry)
            }
        }
        store.save(state);
        assert_eq!(
            store.search_session_valid_until(
                &account.authority,
                &account.device_id,
                expiry - chrono::Duration::milliseconds(1)
            ),
            Some(expiry)
        );
        assert_eq!(
            store.search_session_valid_until(&account.authority, &account.device_id, expiry),
            None
        );
        let (mut dom, harness) = mount(store, account);
        settle(&mut dom, &harness, 1).await;
        let (_, search) = harness.handles.borrow().unwrap();
        dom.in_runtime(|| {
            let rows = search.results.peek();
            assert_eq!(rows[0]["event_id"], json!(original.event.event_id));
            assert_eq!(rows[0]["covering_commit"], json!(original.commit));
            assert_eq!(rows[0]["content"]["body"], "exact original needle");
        });
        // No store mutation, query or generation change triggers this removal.
        settle(&mut dom, &harness, 0).await;
        let (context, _) = harness.handles.borrow().unwrap();
        dom.in_runtime(|| assert!(!search_holder_ready(context)));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn native_search_new_query_becomes_readable_after_not_before_without_store_change() {
    let (_directory, mut store, account, _) = authorized_store().await;
    let not_before = chrono::Utc::now() + chrono::Duration::seconds(1);
    let mut state = store.load();
    state
        .device_authoring_authority
        .as_mut()
        .unwrap()
        .device_projection
        .authorization_window
        .not_before = not_before;
    state
        .device_authoring_authority
        .as_mut()
        .unwrap()
        .device_projection
        .authorization_window
        .expires_at = Some(not_before + chrono::Duration::seconds(2));
    store.save(state);
    let (mut dom, harness) = mount(store, account);
    settle(&mut dom, &harness, 0).await;
    let (context, _) = harness.handles.borrow().unwrap();
    dom.in_runtime(|| assert!(!search_holder_ready(context)));
    while chrono::Utc::now() <= not_before {
        crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(10)).await;
    }
    // The original evidence is unchanged. The real form callback must now
    // accept a new query, and its render gate must use current wall time.
    dom.in_runtime(|| harness.retry.borrow().unwrap().call(()));
    settle(&mut dom, &harness, 1).await;
    dom.in_runtime(|| assert!(search_holder_ready(context)));
    settle(&mut dom, &harness, 0).await;
    dom.in_runtime(|| assert!(!search_holder_ready(context)));
}

#[tokio::test(flavor = "current_thread")]
async fn native_search_renewed_holder_cancels_old_expiry_and_rechecks_new_expiry() {
    let (_directory, mut store, account, _) = authorized_store().await;
    let old_expiry = chrono::Utc::now() + chrono::Duration::seconds(2);
    let mut grant = store.session_grant().unwrap();
    grant.grant_expires_at = Some(old_expiry);
    store.set_session_grant(Some(grant));
    let (mut dom, harness) = mount(store, account);
    settle(&mut dom, &harness, 1).await;
    let (mut context, search) = harness.handles.borrow().unwrap();
    dom.in_runtime(|| {
        let mut grant = context.state_store.peek().session_grant().unwrap();
        grant.grant_expires_at = Some(old_expiry + chrono::Duration::seconds(2));
        context.state_store.write().set_session_grant(Some(grant));
    });
    settle(&mut dom, &harness, 1).await;
    while chrono::Utc::now() < old_expiry + chrono::Duration::milliseconds(100) {
        dom.render_immediate_to_vec();
        crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(10)).await;
    }
    dom.in_runtime(|| {
        assert_eq!(
            search.results.peek().len(),
            1,
            "old timer must not clear a renewed holder"
        )
    });
    settle(&mut dom, &harness, 0).await;
}

#[tokio::test(flavor = "current_thread")]
async fn native_search_holder_replacement_revocation_and_late_request_fail_closed() {
    for boundary in ["device", "account", "grant", "revoked", "session_epoch"] {
        let (_directory, store, account, _) = authorized_store().await;
        let (mut dom, harness) = mount(store, account.clone());
        settle(&mut dom, &harness, 1).await;
        let (mut context, search) = harness.handles.borrow().unwrap();
        dom.in_runtime(|| {
            // Call the scope-bound event handler just like the product form,
            // then replace its holder before Dioxus polls candidate reads.
            harness.retry.borrow().unwrap().call(());
            match boundary {
                "device" => {
                    context.active_account.write().as_mut().unwrap().device_id =
                        crate::test_support::device_id(
                            "ak:device:0196419b-0000-7000-8000-000000000099",
                        )
                }
                "account" => context.active_account.set(None),
                "grant" => context.state_store.write().set_session_grant(None),
                "revoked" => {
                    let mut state = context.state_store.peek().load();
                    state
                        .device_authoring_authority
                        .as_mut()
                        .unwrap()
                        .device_projection
                        .device_status = arkret_models_crypto::DeviceStatus::Revoked;
                    context.state_store.write().save(state);
                }
                _ => context.session_generation.with_mut(|epoch| *epoch += 1),
            }
        });
        for _ in 0..50 {
            dom.render_immediate_to_vec();
            crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(2)).await;
        }
        dom.in_runtime(|| {
            assert!(
                search.results.peek().is_empty(),
                "{boundary} must not release late plaintext"
            )
        });
    }
}
