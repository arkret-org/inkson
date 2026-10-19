//! The real receipt hub and timeline component mounted in a browser DOM.
#![cfg(all(target_arch = "wasm32", feature = "web", feature = "spec-conformance"))]

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use dioxus::prelude::*;
use inkson::views::read_receipts::{
    AdmittedSignal, ClientLocalState, ReadReceiptHub, ReadReceiptIndicator,
};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
const STRAND: &str = "ak:strand:ASyFf0qTUQ55a2qZp5fuTXRnIgf3ovKChQZ_XSkxdIPK";
const EVENT: &str = "ak:event:ATOz4l-vKJUCGZDmS_knGS9TjZ64pkOzx-HNGAgY5RGJ";

fn actor(principal: &str, station: &str) -> arkret_sdk::ActorId {
    arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        format!("ak:did_core:web:{principal}.example")
            .parse()
            .unwrap(),
        format!("ak:did_core:web:{station}.example")
            .parse()
            .unwrap(),
    ))
}

fn author() -> arkret_sdk::ActorId {
    actor("author", "station-a")
}
fn reader() -> arkret_sdk::ActorId {
    actor("reader", "station-a")
}
fn message_id() -> String {
    arkret_sdk::MessageId::from_event_id(&EVENT.parse().unwrap()).to_string()
}

fn signal() -> AdmittedSignal {
    AdmittedSignal {
        domain: arkret_sdk::SignalSequenceDomain {
            sender_actor_id: reader(),
            endpoint: arkret_sdk::SignalSequenceEndpoint::AccountDevice {
                device_id: arkret_sdk::DeviceId::new_v7_at(1_800_000_000_000),
            },
            scope_ref: arkret_sdk::ScopeRef::Realm {
                realm_id: REALM.parse().unwrap(),
            },
        },
        signer_verification_method: arkret_sdk::DidUrl::new("did:web:reader.example#device-1")
            .unwrap(),
        product_authority: None,
        call_invitation: None,
        authority_commit_id: arkret_sdk::RealmCommitId::from_digest([41; 32]),
        parent_realm_authority_commit_id: None,
        payload: arkret_sdk::SignalPlaintext::ReadReceipt(
            arkret_sdk::ReadReceipt::new(
                3,
                reader(),
                EVENT.parse().unwrap(),
                arkret_sdk::ReadReceiptScope::strand(STRAND, Some("discussion")),
            )
            .unwrap(),
        ),
        expires_at: chrono::DateTime::from_timestamp(1_800_000_030, 0).unwrap(),
    }
}

fn accepted_state(has_target: bool) -> ClientLocalState {
    let mut value = serde_json::to_value(ClientLocalState::default()).unwrap();
    if has_target {
        // The sink consumes the existing verified MessageCreate index. Its
        // authentication is exercised separately by accepted-history tests.
        value["verified_message_commits"] = serde_json::json!([{
            "accepted_ref": {
                "event_id": EVENT,
                "commit_id": arkret_sdk::RealmCommitId::from_digest([42; 32]),
                "stream_ref": {"kind": "realm", "realm_id": REALM},
                "stream_position": 1
            },
            "actor_id": author(),
            "scope_ref": {"kind": "realm", "realm_id": REALM},
            "strand_id": STRAND,
            "track_name": "discussion"
        }]);
    }
    serde_json::from_value(value).unwrap()
}

#[derive(Clone, Default)]
struct Control {
    handles: Rc<RefCell<Option<(Signal<arkret_sdk::ActorId>, ReadReceiptHub)>>>,
    policy: Rc<RefCell<Option<Signal<Option<arkret_sdk::ReadReceiptPolicy>>>>>,
    applied: Rc<Cell<Option<bool>>>,
}

#[derive(Clone)]
struct Case {
    viewer: arkret_sdk::ActorId,
    target: bool,
    visible_author: Option<arkret_sdk::ActorId>,
    policy: arkret_sdk::ReadReceiptPolicy,
    display: bool,
    control: Control,
}

impl Default for Case {
    fn default() -> Self {
        Self {
            viewer: author(),
            target: true,
            visible_author: Some(author()),
            policy: arkret_sdk::ReadReceiptPolicy {
                visibility: arkret_sdk::ReadReceiptVisibility::Private,
                ..Default::default()
            },
            display: true,
            control: Control::default(),
        }
    }
}

fn receipt_page(case: Case) -> Element {
    let viewer = use_signal(|| case.viewer.clone());
    let policy = use_signal(|| Some(case.policy.clone()));
    *case.control.policy.borrow_mut() = Some(policy);
    let mut hub = use_context_provider(ReadReceiptHub::new);
    use_hook(|| {
        case.control.applied.set(Some(hub.apply_authorized(
            &signal(),
            &case.policy,
            &case.viewer,
            &accepted_state(case.target),
        )));
    });
    *case.control.handles.borrow_mut() = Some((viewer, hub));
    rsx! {
        div {
            "data-testid": "receipt-page-ready",
            ReadReceiptIndicator {
                realm_id: REALM,
                strand_id: STRAND,
                message_id: Some(message_id()),
                target_author: case.visible_author,
                viewer: viewer(),
                display: case.display,
                policy: policy(),
            }
        }
    }
}

async fn mount(
    case: Case,
) -> (
    web_sys::Element,
    Rc<dioxus::core::Runtime>,
    futures_util::future::AbortHandle,
) {
    let document = web_sys::window().unwrap().document().unwrap();
    let root = document.create_element("div").unwrap();
    document.body().unwrap().append_child(&root).unwrap();
    let dom = VirtualDom::new_with_props(receipt_page, case);
    let runtime = dom.runtime();
    let (abort, registration) = futures_util::future::AbortHandle::new_pair();
    let render_root = root.clone();
    wasm_bindgen_futures::spawn_local(async move {
        let _ = futures_util::future::Abortable::new(
            dioxus::web::run(dom, dioxus::web::Config::new().rootelement(render_root)),
            registration,
        )
        .await;
    });
    for _ in 0..100 {
        if root
            .query_selector("[data-testid='receipt-page-ready']")
            .unwrap()
            .is_some()
        {
            return (root, runtime, abort);
        }
        gloo_timers::future::TimeoutFuture::new(10).await;
    }
    abort.abort();
    panic!("receipt page did not mount");
}

async fn unmount(root: web_sys::Element, abort: futures_util::future::AbortHandle) {
    abort.abort();
    gloo_timers::future::TimeoutFuture::new(0).await;
    root.remove();
}

#[wasm_bindgen_test(async)]
async fn browser_private_receipt_uses_target_author_and_complete_actor_identity() {
    for (viewer, expected) in [
        (author(), true),
        (reader(), false),
        (actor("other", "station-a"), false),
        (actor("author", "station-b"), false),
    ] {
        let case = Case {
            viewer: viewer.clone(),
            ..Default::default()
        };
        let control = case.control.clone();
        let (root, _, abort) = mount(case).await;
        assert_eq!(control.applied.get(), Some(expected));
        let badge = root
            .query_selector("[data-testid='read-receipt-indicator']")
            .unwrap();
        assert_eq!(badge.is_some(), expected, "viewer {viewer}");
        if let Some(badge) = badge {
            let readers: Vec<arkret_sdk::ActorId> =
                serde_json::from_str(&badge.get_attribute("data-readers").unwrap()).unwrap();
            assert_eq!(readers, vec![reader()]);
        }
        unmount(root, abort).await;
    }
}

#[wasm_bindgen_test(async)]
async fn browser_receipt_fails_closed_without_target_or_author_and_preserves_disabled() {
    for case in [
        Case {
            target: false,
            ..Default::default()
        },
        Case {
            visible_author: None,
            ..Default::default()
        },
        Case {
            policy: arkret_sdk::ReadReceiptPolicy {
                disclosure: arkret_sdk::ReadReceiptDisclosure::Disabled,
                visibility: arkret_sdk::ReadReceiptVisibility::Private,
                ..Default::default()
            },
            ..Default::default()
        },
        Case {
            display: false,
            ..Default::default()
        },
    ] {
        let (root, _, abort) = mount(case).await;
        assert!(
            root.query_selector("[data-testid='read-receipt-indicator']")
                .unwrap()
                .is_none()
        );
        unmount(root, abort).await;
    }
}

#[wasm_bindgen_test(async)]
async fn browser_receipt_disappears_when_current_account_changes_station() {
    let case = Case::default();
    let control = case.control.clone();
    let (root, runtime, abort) = mount(case).await;
    assert!(
        root.query_selector("[data-testid='read-receipt-indicator']")
            .unwrap()
            .is_some()
    );
    let (mut viewer, _) = control.handles.borrow().unwrap();
    runtime.in_scope(ScopeId::ROOT, || viewer.set(actor("author", "station-b")));
    for _ in 0..100 {
        if root
            .query_selector("[data-testid='read-receipt-indicator']")
            .unwrap()
            .is_none()
        {
            break;
        }
        gloo_timers::future::TimeoutFuture::new(10).await;
    }
    assert!(
        root.query_selector("[data-testid='read-receipt-indicator']")
            .unwrap()
            .is_none()
    );
    unmount(root, abort).await;
}

#[wasm_bindgen_test(async)]
async fn browser_receipt_retracts_retained_members_hint_after_policy_tightens() {
    let case = Case {
        viewer: reader(),
        policy: arkret_sdk::ReadReceiptPolicy::default(),
        ..Default::default()
    };
    let control = case.control.clone();
    let (root, runtime, abort) = mount(case).await;
    assert!(
        root.query_selector("[data-testid='read-receipt-indicator']")
            .unwrap()
            .is_some()
    );
    let mut policy = control.policy.borrow().unwrap();
    for next in [
        Some(arkret_sdk::ReadReceiptPolicy {
            visibility: arkret_sdk::ReadReceiptVisibility::Private,
            ..Default::default()
        }),
        Some(arkret_sdk::ReadReceiptPolicy {
            disclosure: arkret_sdk::ReadReceiptDisclosure::Disabled,
            ..Default::default()
        }),
        None,
    ] {
        runtime.in_scope(ScopeId::ROOT, || policy.set(next));
        for _ in 0..100 {
            if root
                .query_selector("[data-testid='read-receipt-indicator']")
                .unwrap()
                .is_none()
            {
                break;
            }
            gloo_timers::future::TimeoutFuture::new(10).await;
        }
        assert!(
            root.query_selector("[data-testid='read-receipt-indicator']")
                .unwrap()
                .is_none()
        );
    }
    unmount(root, abort).await;
}
