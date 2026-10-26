//! The real receipt hub and timeline component mounted in a browser DOM.
#![cfg(all(target_arch = "wasm32", feature = "web", feature = "spec-conformance"))]

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use glory::{Cage, Scope};
#[path = "support/glory_web.rs"]
mod glory_web;
use inkson::views::read_receipts::{
    AdmittedSignal, ClientLocalState, ReadReceiptHub, ReadReceiptIndicatorProps,
    read_receipt_indicator,
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
    handles: Rc<RefCell<Option<(Cage<arkret_sdk::ActorId>, ReadReceiptHub)>>>,
    policy: Rc<RefCell<Option<Cage<Option<arkret_sdk::ReadReceiptPolicy>>>>>,
    applied: Rc<Cell<Option<bool>>>,
}

#[derive(Clone)]
struct Case {
    viewer: arkret_sdk::ActorId,
    target: bool,
    visible_author: Option<arkret_sdk::ActorId>,
    policy: arkret_sdk::ReadReceiptPolicy,
    display: bool,
    scope: arkret_sdk::ScopeRef,
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
            scope: signal().domain.scope_ref,
            control: Control::default(),
        }
    }
}

fn receipt_page(scope: &Scope, case: Case) -> inkson::presentation::View {
    let context = glory_web::context(scope);
    let viewer = scope.cage(case.viewer.clone());
    let policy = scope.cage(Some(case.policy.clone()));
    *case.control.policy.borrow_mut() = Some(policy);
    context
        .active_account
        .revise(|value| *value = Some(glory_web::account(&case.viewer)));
    {
        let context = context.clone();
        scope.effect(move || {
            let actor = viewer.get();
            context
                .active_account
                .revise(|value| *value = Some(glory_web::account(&actor)));
        });
    }
    let mut admitted = signal();
    admitted.domain.scope_ref = case.scope.clone();
    let mut state = serde_json::to_value(accepted_state(case.target)).unwrap();
    if case.target {
        state["verified_message_commits"][0]["scope_ref"] =
            serde_json::to_value(&case.scope).unwrap();
        state["verified_message_commits"][0]["accepted_ref"]["stream_ref"] = serde_json::to_value(
            arkret_sdk::CommitStreamRef::from_scope(&case.scope, Some(REALM.parse().unwrap()))
                .unwrap(),
        )
        .unwrap();
    }
    let state: ClientLocalState = serde_json::from_value(state).unwrap();
    let mut hub = context.read_receipt_hub;
    case.control.applied.set(Some(hub.apply_authorized(
        &admitted,
        &case.policy,
        &case.viewer,
        &state,
    )));
    *case.control.handles.borrow_mut() = Some((viewer, hub));
    inkson::presentation::widgets::reactive(
        scope.bond(move || (viewer.get(), policy.get())),
        move |scope, (viewer, policy)| {
            read_receipt_indicator(
                scope,
                context.clone(),
                ReadReceiptIndicatorProps {
                    realm_id: REALM.into(),
                    strand_id: STRAND.into(),
                    message_id: Some(message_id()),
                    target_author: case.visible_author.clone(),
                    viewer,
                    display: case.display,
                    policy,
                },
            )
        },
    )
}

async fn mount(case: Case) -> (web_sys::Element, (), glory::web::WebApp) {
    let root = glory_web::root();
    let app =
        glory::web::launch_with(root.clone(), move |scope| receipt_page(scope, case)).unwrap();
    glory_web::settle().await;
    (root, (), app)
}
async fn unmount(root: web_sys::Element, app: glory::web::WebApp) {
    drop(app);
    glory_web::settle().await;
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
        let badge = root.query_selector(".read-receipt-indicator").unwrap();
        assert_eq!(badge.is_some(), expected, "viewer {viewer}");
        if let Some(badge) = badge {
            let readers: Vec<arkret_sdk::ActorId> = {
                let avatars = badge
                    .query_selector_all(".read-receipt-avatar [data-gly-kind=graphic]")
                    .unwrap();
                (0..avatars.length())
                    .map(|index| {
                        use wasm_bindgen::JsCast;
                        let avatar = avatars
                            .item(index)
                            .unwrap()
                            .dyn_into::<web_sys::Element>()
                            .unwrap();
                        serde_json::from_str(&avatar.get_attribute("aria-label").unwrap()).unwrap()
                    })
                    .collect()
            };
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
            root.query_selector(".read-receipt-indicator")
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
    let (root, _, abort) = mount(case).await;
    assert!(
        root.query_selector(".read-receipt-indicator")
            .unwrap()
            .is_some()
    );
    let (viewer, _) = control.handles.borrow().unwrap();
    viewer.revise(|value| *value = actor("author", "station-b"));
    for _ in 0..100 {
        if root
            .query_selector(".read-receipt-indicator")
            .unwrap()
            .is_none()
        {
            break;
        }
        gloo_timers::future::TimeoutFuture::new(10).await;
    }
    assert!(
        root.query_selector(".read-receipt-indicator")
            .unwrap()
            .is_none()
    );
    unmount(root, abort).await;
}

#[wasm_bindgen_test(async)]
async fn browser_circle_receipt_retracts_without_resurrection_after_policy_tightens() {
    let case = Case {
        viewer: reader(),
        scope: arkret_sdk::ScopeRef::Circle {
            realm_id: REALM.parse().unwrap(),
            circle_id: arkret_sdk::CircleId::from_event_id(&EVENT.parse().unwrap()),
        },
        policy: arkret_sdk::ReadReceiptPolicy::default(),
        ..Default::default()
    };
    let control = case.control.clone();
    let (root, _, abort) = mount(case).await;
    assert!(
        root.query_selector(".read-receipt-indicator")
            .unwrap()
            .is_some()
    );
    let policy = control.policy.borrow().unwrap();
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
        policy.revise(|value| *value = next);
        for _ in 0..100 {
            if root
                .query_selector(".read-receipt-indicator")
                .unwrap()
                .is_none()
            {
                break;
            }
            gloo_timers::future::TimeoutFuture::new(10).await;
        }
        assert!(
            root.query_selector(".read-receipt-indicator")
                .unwrap()
                .is_none()
        );
    }
    gloo_timers::future::TimeoutFuture::new(30).await;
    {
        policy.revise(|value| *value = Some(arkret_sdk::ReadReceiptPolicy::default()))
    };
    gloo_timers::future::TimeoutFuture::new(30).await;
    assert!(
        root.query_selector(".read-receipt-indicator")
            .unwrap()
            .is_none(),
        "discarded hint must not revive after policy relaxes"
    );
    unmount(root, abort).await;
}
