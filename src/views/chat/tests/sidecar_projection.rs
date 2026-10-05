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
}

fn projection_harness(control: ProjectionControl) -> Element {
    let store = use_signal_sync(|| LocalStateStore::with_path(control.path));
    let noise = use_signal(|| 0_usize);
    let evidence = use_signal(|| 0_u64);
    let realm = use_signal(|| "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw".to_owned());
    let authority = use_signal(|| local_fixture_account("did:web:alice.example"));
    *control.signals.borrow_mut() = Some(ProjectionSignals {
        store,
        noise,
        evidence,
        realm,
        authority,
    });
    let projection = super::super::sidecar_projection::use_sidecar_timeline_projection(
        store,
        authority(),
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap(),
        realm(),
        evidence(),
    );
    let read = projection.read();
    assert!(
        read.current.is_err(),
        "an unverified cut must never become an empty success"
    );
    assert!(read.messages.is_empty());
    assert!(read.closes.is_empty());
    let message_count = read.messages.len();
    rsx! { div { "{noise}:{message_count}" } }
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

    let mutations: Vec<Box<dyn FnMut()>> = vec![
        Box::new(move || signals.store.write().save(ClientLocalState::default())),
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
