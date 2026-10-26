use std::cell::RefCell;
use std::rc::Rc;

use super::*;
use crate::views::chat::native_harness::NativeHarness;
#[derive(Clone)]
struct ProjectionControl {
    path: std::path::PathBuf,
    signals: Rc<RefCell<Option<ProjectionSignals>>>,
}
#[derive(Clone)]
struct ProjectionSignals {
    store: crate::presentation::SharedStateStore,
    noise: Cage<usize>,
    evidence: Cage<u64>,
    realm: Cage<String>,
    authority: Cage<arkret_sdk::AccountId>,
    ordinary: Bond<Vec<ChatMessage>>,
    realm_epoch: Cage<u64>,
}
fn projection_harness(control: ProjectionControl) -> NativeHarness {
    let dom = NativeHarness::new();
    let context = dom.context(control.path);
    let scope = dom.app.scope();
    let store = context.state_store.clone();
    let noise = scope.cage(0_usize);
    let evidence = scope.cage(0_u64);
    let realm = scope.cage("ak:realm:ARUALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE".to_owned());
    let authority = scope.cage(local_fixture_account("did:web:alice.example"));
    let realm_epoch = context.realm_live_epoch;
    let basis = super::super::timeline_projection::timeline_projection_basis(scope, context);
    let messages = scope.cage(Vec::new());
    let published = scope.cage(Vec::<ChatMessage>::new());
    let ordinary = scope.bond(move || published.get());
    *control.signals.borrow_mut() = Some(ProjectionSignals {
        store: store.clone(),
        noise,
        evidence,
        realm,
        authority,
        ordinary,
        realm_epoch,
    });
    let source = scope.bond(move || (evidence.get(), realm.get(), authority.get()));
    let view = crate::presentation::widgets::reactive_distinct(
        source,
        move |scope, (evidence, realm, authority)| {
            let projection = super::super::sidecar_projection::sidecar_timeline_projection(
                scope,
                store.clone(),
                basis,
                authority.clone(),
                arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001")
                    .unwrap(),
                realm,
                evidence,
            );
            let ordinary = super::super::timeline_projection::ordinary_timeline_projection(
                scope,
                store.clone(),
                basis,
                messages,
                authority.principal_id.to_string(),
                authority,
                arkret_sdk::DeviceId::new(CHAT_FIXTURE_DEVICE).unwrap(),
                evidence,
            );
            scope.effect(move || {
                let read = projection.get();
                assert!(
                    read.current.is_err(),
                    "an unverified cut must never become an empty success"
                );
                assert!(read.messages.is_empty());
                assert!(read.closes.is_empty());
                let next = ordinary.get();
                if published.get_untracked() != next {
                    published.revise(|value| *value = next);
                }
            });
            crate::presentation::widgets::paragraph(
                "projection-harness",
                scope.bond(move || {
                    format!(
                        "{}:{}:{}",
                        noise.get(),
                        projection.get().messages.len(),
                        ordinary.get().len()
                    )
                }),
            )
        },
    );
    dom.app.mount(view).unwrap();
    dom.flush();
    dom
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
    let mut dom = projection_harness(control.clone());
    let signals = control.signals.borrow().as_ref().unwrap().clone();
    let settle = |dom: &mut NativeHarness| dom.flush();
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
    {
        signals.store.write(|store| {
            store.upsert_raw_operation(
                "holder-local",
                Some(realm.to_owned()),
                json!({"event":event, "event_id":event_id, "write_state":"committed"}),
            )
        });
    };
    settle(&mut dom);
    {
        let ordinary = signals.ordinary.get_untracked();
        assert_eq!(ordinary.len(), 1);
        assert_eq!(ordinary[0].body, "accepted ordinary fixture");
        assert!(!ordinary[0].pending);
        assert_eq!(
            project_visible_messages(&ordinary, strand, realm, None, &[], false).len(),
            1
        );
    };
    let builds = ORDINARY_BUILDS.with(|count| count.get());
    for update in 0..20 {
        {
            let mut state = signals.store.read(|store| store.load());
            state.sync_cursor = Some(format!("cursor-only-{update}"));
            state.presence_projection = vec![json!({"presence":update})].into();
            signals.store.write(|store| store.save(state));
        };
        settle(&mut dom);
    }
    assert_eq!(ORDINARY_BUILDS.with(|count| count.get()), builds);
    let restored = LocalStateStore::with_path(path);
    let restored_state = restored.load();
    assert_eq!(
        chat_messages_from_local_state_with_sidecar(&restored_state, Some(&restored), None).len(),
        1
    );
    {
        let mut state = signals.store.read(|store| store.load());
        state.raw_operations[0].payload["event"]["payload"]["content"]["body"] = json!("tampered");
        signals.store.write(|store| store.save(state));
    };
    settle(&mut dom);
    assert!(signals.ordinary.get_untracked().is_empty());
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
    let mut dom = projection_harness(control.clone());
    let signals = control.signals.borrow().as_ref().unwrap().clone();
    let settle = |dom: &mut NativeHarness| dom.flush();
    settle(&mut dom);
    {
        let state = signals.store.read(|store| store.load());
        signals.store.write(|store| store.save(state));
    };
    settle(&mut dom);
    let mut detached = signals.store.read(|store| store.clone());
    let before_state = detached.load();
    let view = crate::current_projection::RealmCurrentView {
        realm_id: signals.realm.get_untracked(),
        entries: Vec::new(),
        complete_cut: false,
    };
    let before_builds = ORDINARY_BUILDS.with(|count| count.get());
    detached.install_current_product_view(view.clone()).unwrap();
    assert_eq!(detached.load(), before_state);
    signals.realm_epoch.revise(|value| *value = 1);
    settle(&mut dom);
    assert!(ORDINARY_BUILDS.with(|count| count.get()) > before_builds);
    let installed_builds = ORDINARY_BUILDS.with(|count| count.get());
    detached.install_current_product_view(view).unwrap();
    signals.realm_epoch.revise(|value| *value = 2);
    settle(&mut dom);
    assert_eq!(ORDINARY_BUILDS.with(|count| count.get()), installed_builds);
    detached.clear_current_product_view();
    signals.realm_epoch.revise(|value| *value = 3);
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
    let mut dom = projection_harness(control.clone());
    let signals = control.signals.borrow().as_ref().unwrap().clone();
    let settle = |dom: &mut NativeHarness| dom.flush();
    settle(&mut dom);
    let initial = PROJECTION_BUILDS.with(|count| count.get());
    for repaint in 1..=40 {
        signals.noise.revise(|value| *value = repaint);
        settle(&mut dom);
    }
    assert_eq!(PROJECTION_BUILDS.with(|count| count.get()), initial);

    for update in 0..20 {
        {
            let mut state = signals.store.read(|store| store.load());
            state.sync_cursor = Some(format!("opaque-resume-{update}"));
            state.presence_projection = vec![json!({"presence": update})].into();
            signals.store.write(|store| store.save(state));
        };
        settle(&mut dom);
    }
    assert_eq!(PROJECTION_BUILDS.with(|count| count.get()), initial);

    let mutation_store = signals.store.clone();
    let mutation_evidence = signals.evidence;
    let mutation_realm = signals.realm;
    let mutation_authority = signals.authority;
    let mutations: Vec<Box<dyn FnMut()>> = vec![
        Box::new(move || {
            let mut state = mutation_store.read(|store| store.load());
            state.current_reset_required = true;
            mutation_store.write(|store| store.save(state));
        }),
        Box::new(move || mutation_evidence.revise(|value| *value = 1)),
        Box::new(move || {
            mutation_realm.revise(|value| {
                *value = "ak:realm:ATwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q".to_owned()
            })
        }),
        Box::new(move || {
            mutation_authority.revise(|value| *value = local_fixture_account("did:web:bob.example"))
        }),
    ];
    for mut mutate in mutations {
        let before = PROJECTION_BUILDS.with(|count| count.get());
        mutate();
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
