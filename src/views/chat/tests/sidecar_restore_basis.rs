use std::cell::RefCell;
use std::rc::Rc;

use super::*;

const REALM: &str = "ak:realm:ARUALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE";
const STRAND: &str = "ak:strand:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7";

fn account() -> arkret_sdk::AccountId {
    crate::test_support::authority_at_station(
        "ak:did_core:webvh:zAlice",
        "ak:did_core:webvh:zStation",
    )
}

#[derive(Clone)]
struct Control {
    path: std::path::PathBuf,
    signals: Rc<RefCell<Option<Signals>>>,
}

#[derive(Clone, Copy)]
struct Signals {
    store: SyncSignal<LocalStateStore>,
    realm_epoch: Signal<u64>,
    authority: Signal<arkret_sdk::AccountId>,
    device: Signal<arkret_sdk::DeviceId>,
}

fn restore_harness(control: Control) -> Element {
    let store = use_signal_sync(|| LocalStateStore::with_path(control.path));
    let realm_epoch = use_signal(|| 0_u64);
    let authority = use_signal(account);
    let device = use_signal(|| {
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap()
    });
    let token = use_signal(String::new);
    let hosted = use_signal(|| None);
    use_context_provider(|| crate::sidecar::HostedSidecarStateContext(hosted));
    let basis =
        super::super::timeline_projection::use_timeline_projection_basis(store, realm_epoch);
    use_sidecar_restore(
        "https://station.example".to_owned(),
        REALM.to_owned(),
        STRAND.to_owned(),
        authority(),
        device(),
        token,
        basis,
        store,
    );
    *control.signals.borrow_mut() = Some(Signals {
        store,
        realm_epoch,
        authority,
        device,
    });
    rsx! { div { "restore harness" } }
}

#[test]
fn restore_ignores_cursor_noise_and_revalidates_content_current_account_and_device() {
    arkret_sdk::RealmId::new(REALM).expect("fixture has a supported Realm identity token");
    arkret_sdk::StrandId::new(STRAND).expect("fixture has a supported Strand identity token");
    RESTORE_LOOKUPS.with(|count| count.set(0));
    let dir = tempfile::tempdir().unwrap();
    let control = Control {
        path: dir.path().join("state.json"),
        signals: Rc::new(RefCell::new(None)),
    };
    let mut dom = VirtualDom::new_with_props(restore_harness, control.clone());
    dom.rebuild_in_place();
    let settle = |dom: &mut VirtualDom| {
        for _ in 0..8 {
            dom.render_immediate_to_vec();
        }
    };
    settle(&mut dom);
    let mut signals = control.signals.borrow().unwrap();
    let initial = RESTORE_LOOKUPS.with(|count| count.get());
    assert!(initial > 0);
    for change in 0..20 {
        dom.in_runtime(|| {
            let mut state = signals.store.peek().load();
            state.sync_cursor = Some(format!("reminted-{change}"));
            state.presence_projection = vec![json!({"presence": change})];
            signals.store.write().save(state);
        });
        settle(&mut dom);
    }
    assert_eq!(RESTORE_LOOKUPS.with(|count| count.get()), initial);
    dom.in_runtime(|| {
        signals.store.write().upsert_raw_operation(
            "security-change",
            Some(REALM.to_owned()),
            json!({"evidence": "changed"}),
        )
    });
    settle(&mut dom);
    let after_content = RESTORE_LOOKUPS.with(|count| count.get());
    assert!(after_content > initial);
    let mut detached = dom.in_runtime(|| signals.store.peek().clone());
    let before_state = detached.load();
    detached
        .install_current_product_view(crate::current_projection::RealmCurrentView {
            realm_id: REALM.to_owned(),
            entries: Vec::new(),
            complete_cut: false,
        })
        .unwrap();
    assert_eq!(detached.load(), before_state);
    dom.in_runtime(|| signals.realm_epoch.set(1));
    settle(&mut dom);
    let after_current = RESTORE_LOOKUPS.with(|count| count.get());
    assert!(after_current > after_content);
    dom.in_runtime(|| {
        signals
            .authority
            .set(crate::test_support::authority_at_station(
                "ak:did_core:webvh:zBob",
                "ak:did_core:webvh:zStation",
            ))
    });
    settle(&mut dom);
    let after_account = RESTORE_LOOKUPS.with(|count| count.get());
    assert!(after_account > after_current);
    dom.in_runtime(|| {
        signals.device.set(
            arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000002").unwrap(),
        )
    });
    settle(&mut dom);
    assert!(RESTORE_LOOKUPS.with(|count| count.get()) > after_account);
}

#[test]
fn restore_retry_budget_survives_success_and_another_component() {
    let mut book = RestoreRetryBook::default();
    let account = account();
    let now = chrono::DateTime::from_timestamp(1_000, 0).unwrap();
    for attempt in 0..arkret_retry::SPEC_MAX_RETRIES {
        let at = now + chrono::Duration::seconds(i64::from(attempt));
        assert!(matches!(
            book.claim(&account, at, true),
            RestoreAdmission::Admitted
        ));
        assert!(matches!(
            book.claim(&account, at, false),
            RestoreAdmission::Wait(_)
        ));
        book.finish(&account, at, None);
    }
    // A fresh component's automatic retry cannot reset an endpoint's budget,
    // even though every preceding attempt succeeded and reset its ladder.
    assert!(
        matches!(book.claim(&account, now + chrono::Duration::seconds(10), true), RestoreAdmission::Wait(delay) if delay.as_secs() == 290)
    );
    assert!(matches!(
        book.claim(&account, now + chrono::Duration::seconds(300), true),
        RestoreAdmission::Admitted
    ));
}

#[test]
fn restore_retry_preserves_server_hint_and_rejects_permanent_failures() {
    let mut book = RestoreRetryBook::default();
    let account = account();
    let now = chrono::DateTime::from_timestamp(1_000, 0).unwrap();
    assert!(matches!(
        book.claim(&account, now, false),
        RestoreAdmission::Admitted
    ));
    book.finish(
        &account,
        now,
        Some(Some(std::time::Duration::from_secs(900))),
    );
    assert!(
        matches!(book.claim(&account, now, false), RestoreAdmission::Wait(delay) if delay.as_secs() == 900)
    );
    let problem = |status: u16, code| {
        anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status,
            error: Box::new(arkret_sdk::Problem::new(code, status, "fixture")),
        })
    };
    assert!(restore_retry_hint(&problem(503, "temporarily_unavailable")).is_some());
    assert!(restore_retry_hint(&problem(429, "rate_limited")).is_some());
    assert!(restore_retry_hint(&problem(403, "forbidden")).is_none());
    assert!(restore_retry_hint(&problem(503, "internal_error")).is_none());
    assert!(
        restore_retry_hint(&anyhow::Error::new(
            arkret_sdk::http_client::Error::Protocol("invalid current".to_owned())
        ))
        .is_none()
    );
    assert!(
        restore_retry_hint(&anyhow::Error::new(arkret_sdk::http_client::Error::Http(
            "disconnected".to_owned()
        )))
        .is_some()
    );
    let invalid_request = reqwest::Client::new()
        .get("://invalid-url")
        .build()
        .unwrap_err();
    assert!(invalid_request.is_builder());
    assert!(!restore_reqwest_transient(&invalid_request));
    assert!(restore_retry_hint(&anyhow::Error::new(invalid_request)).is_none());
}
