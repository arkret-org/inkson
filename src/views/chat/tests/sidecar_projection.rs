use std::cell::RefCell;
use std::rc::Rc;

use super::*;

#[derive(Clone)]
struct ProjectionControl {
    path: std::path::PathBuf,
    signals: Rc<RefCell<Option<ProjectionSignals>>>,
}

#[derive(Clone, Copy)]
struct ProjectionSignals {
    store: SyncSignal<LocalStateStore>,
    noise: Signal<usize>,
    evidence: Signal<u64>,
    realm: Signal<String>,
    authority: Signal<arkret_sdk::AccountId>,
    ordinary: Memo<Vec<ChatMessage>>,
    realm_epoch: Signal<u64>,
}

fn projection_harness(control: ProjectionControl) -> Element {
    let store = use_signal_sync(|| LocalStateStore::with_path(control.path));
    let noise = use_signal(|| 0_usize);
    let evidence = use_signal(|| 0_u64);
    let realm = use_signal(|| "ak:realm:ARUALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE".to_owned());
    let authority = use_signal(|| local_fixture_account("did:web:alice.example"));
    let realm_epoch = use_signal(|| 0_u64);
    let basis =
        super::super::timeline_projection::use_timeline_projection_basis(store, realm_epoch);
    let projection = super::super::sidecar_projection::use_sidecar_timeline_projection(
        store,
        basis,
        authority(),
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap(),
        realm(),
        evidence(),
    );
    let messages = use_signal(Vec::new);
    let ordinary = super::super::timeline_projection::use_ordinary_timeline_projection(
        store,
        basis,
        messages,
        authority().principal_id.to_string(),
        authority(),
        arkret_sdk::DeviceId::new(CHAT_FIXTURE_DEVICE).unwrap(),
        evidence(),
    );
    *control.signals.borrow_mut() = Some(ProjectionSignals {
        store,
        noise,
        evidence,
        realm,
        authority,
        ordinary,
        realm_epoch,
    });
    let read = projection.read();
    assert!(
        read.current.is_err(),
        "an unverified cut must never become an empty success"
    );
    assert!(read.messages.is_empty());
    assert!(read.closes.is_empty());
    let message_count = read.messages.len();
    let ordinary_count = ordinary.read().len();
    rsx! { div { "{noise}:{message_count}:{ordinary_count}" } }
}

#[test]
fn ordinary_accepted_event_appears_without_cursor_or_controller_update() {
    use super::super::timeline_projection::ORDINARY_BUILDS;
    ORDINARY_BUILDS.with(|count| count.set(0));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let control = ProjectionControl {
        path: path.clone(),
        signals: Rc::new(RefCell::new(None)),
    };
    let mut dom = VirtualDom::new_with_props(projection_harness, control.clone());
    dom.rebuild_in_place();
    let mut signals = control.signals.borrow().unwrap();
    let settle = |dom: &mut VirtualDom| {
        for _ in 0..4 {
            dom.render_immediate_to_vec();
        }
    };
    settle(&mut dom);
    let realm = "ak:realm:ARUALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE";
    let strand = "ak:strand:A2XzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c";
    let event = signed_chat_event(
        "ak.message.create",
        realm,
        json!(local_fixture_actor("did:web:alice.example")),
        "2026-10-06T00:00:00.000Z",
        json!({"strand_id":strand, "track_name":"discussion", "content":{"kind":"ak.content.text", "body":"accepted ordinary fixture"}}),
    );
    let event_id = event["event_id"].as_str().unwrap().to_owned();
    dom.in_runtime(|| {
        signals.store.write().upsert_raw_operation(
            "holder-local",
            Some(realm.to_owned()),
            json!({"event":event, "event_id":event_id, "write_state":"committed"}),
        );
    });
    settle(&mut dom);
    dom.in_runtime(|| {
        let ordinary = signals.ordinary.read();
        assert_eq!(ordinary.len(), 1);
        assert_eq!(ordinary[0].body, "accepted ordinary fixture");
        assert!(!ordinary[0].pending);
        assert_eq!(
            project_visible_messages(&ordinary, strand, realm, None, &[], false).len(),
            1
        );
    });
    let builds = ORDINARY_BUILDS.with(|count| count.get());
    for update in 0..20 {
        dom.in_runtime(|| {
            let mut state = signals.store.peek().load();
            state.sync_cursor = Some(format!("cursor-only-{update}"));
            state.presence_projection = vec![json!({"presence":update})];
            signals.store.write().save(state);
        });
        settle(&mut dom);
    }
    assert_eq!(ORDINARY_BUILDS.with(|count| count.get()), builds);
    let restored = LocalStateStore::with_path(path);
    let restored_state = restored.load();
    assert_eq!(
        chat_messages_from_local_state_with_sidecar(&restored_state, Some(&restored), None).len(),
        1
    );
    dom.in_runtime(|| {
        let mut state = signals.store.peek().load();
        state.raw_operations[0].payload["event"]["payload"]["content"]["body"] = json!("tampered");
        signals.store.write().save(state);
    });
    settle(&mut dom);
    dom.in_runtime(|| assert!(signals.ordinary.read().is_empty()));
}

#[test]
fn current_view_only_changes_invalidate_the_timeline_without_cursor_noise() {
    use super::super::timeline_projection::ORDINARY_BUILDS;
    ORDINARY_BUILDS.with(|count| count.set(0));
    let dir = tempfile::tempdir().unwrap();
    let control = ProjectionControl {
        path: dir.path().join("state.json"),
        signals: Rc::new(RefCell::new(None)),
    };
    let mut dom = VirtualDom::new_with_props(projection_harness, control.clone());
    dom.rebuild_in_place();
    let mut signals = control.signals.borrow().unwrap();
    let settle = |dom: &mut VirtualDom| {
        for _ in 0..4 {
            dom.render_immediate_to_vec();
        }
    };
    settle(&mut dom);
    dom.in_runtime(|| {
        let state = signals.store.peek().load();
        signals.store.write().save(state);
    });
    settle(&mut dom);
    let mut detached = dom.in_runtime(|| signals.store.peek().clone());
    let before_state = detached.load();
    let view = crate::current_projection::RealmCurrentView {
        realm_id: dom.in_runtime(|| (signals.realm)()),
        entries: Vec::new(),
        complete_cut: false,
    };
    let before_builds = ORDINARY_BUILDS.with(|count| count.get());
    detached.install_current_product_view(view.clone()).unwrap();
    assert_eq!(detached.load(), before_state);
    dom.in_runtime(|| signals.realm_epoch.set(1));
    settle(&mut dom);
    assert!(ORDINARY_BUILDS.with(|count| count.get()) > before_builds);
    let installed_builds = ORDINARY_BUILDS.with(|count| count.get());
    detached.install_current_product_view(view).unwrap();
    dom.in_runtime(|| signals.realm_epoch.set(2));
    settle(&mut dom);
    assert_eq!(ORDINARY_BUILDS.with(|count| count.get()), installed_builds);
    detached.clear_current_product_view();
    dom.in_runtime(|| signals.realm_epoch.set(3));
    settle(&mut dom);
    assert!(ORDINARY_BUILDS.with(|count| count.get()) > installed_builds);
}

#[test]
fn sidecar_projection_ignores_ui_repaints_but_invalidates_security_inputs() {
    use super::super::sidecar_projection::PROJECTION_BUILDS;
    PROJECTION_BUILDS.with(|count| count.set(0));
    let dir = tempfile::tempdir().unwrap();
    let control = ProjectionControl {
        path: dir.path().join("state.json"),
        signals: Rc::new(RefCell::new(None)),
    };
    let mut dom = VirtualDom::new_with_props(projection_harness, control.clone());
    dom.rebuild_in_place();
    let mut signals = control.signals.borrow().unwrap();
    let settle = |dom: &mut VirtualDom| {
        for _ in 0..4 {
            dom.render_immediate_to_vec();
        }
    };
    settle(&mut dom);
    let initial = PROJECTION_BUILDS.with(|count| count.get());
    for repaint in 1..=40 {
        dom.in_runtime(|| signals.noise.set(repaint));
        settle(&mut dom);
    }
    assert_eq!(PROJECTION_BUILDS.with(|count| count.get()), initial);

    for update in 0..20 {
        dom.in_runtime(|| {
            let mut state = signals.store.peek().load();
            state.sync_cursor = Some(format!("opaque-resume-{update}"));
            state.presence_projection = vec![json!({"presence": update})];
            signals.store.write().save(state);
        });
        settle(&mut dom);
    }
    assert_eq!(PROJECTION_BUILDS.with(|count| count.get()), initial);

    let mutations: Vec<Box<dyn FnMut()>> = vec![
        Box::new(move || {
            let mut state = signals.store.peek().load();
            state.current_reset_required = true;
            signals.store.write().save(state);
        }),
        Box::new(move || signals.evidence.set(1)),
        Box::new(move || {
            signals
                .realm
                .set("ak:realm:ATwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q".to_owned())
        }),
        Box::new(move || {
            signals
                .authority
                .set(local_fixture_account("did:web:bob.example"))
        }),
    ];
    for mut mutate in mutations {
        let before = PROJECTION_BUILDS.with(|count| count.get());
        dom.in_runtime(&mut mutate);
        settle(&mut dom);
        let after = PROJECTION_BUILDS.with(|count| count.get());
        assert!(
            after > before,
            "state, evidence and context changes must invalidate the private projection"
        );
        assert!(
            after <= before + 2,
            "each dependency change must settle without a render loop"
        );
    }
}
