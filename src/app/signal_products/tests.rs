//! Exercise the actual admitted Signal consumer and timeline receipt component.

use std::cell::RefCell;
use std::rc::Rc;

use dioxus::prelude::*;

use super::*;
use crate::views::read_receipts::{ReadReceiptHub, ReadReceiptIndicator};

const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
const STRAND: &str = "ak:strand:ASyFf0qTUQ55a2qZp5fuTXRnIgf3ovKChQZ_XSkxdIPK";
const EVENT: &str = "ak:event:ATOz4l-vKJUCGZDmS_knGS9TjZ64pkOzx-HNGAgY5RGJ";
const STATION: &str = "ak:did_core:web:station-a.example";
const OTHER_STATION: &str = "ak:did_core:web:station-b.example";

fn actor(principal: &str, station: &str) -> arkret_sdk::ActorId {
    arkret_sdk::ActorId::account(
        crate::test_support::AccountFixture::new(principal)
            .station(station)
            .authority(),
    )
}

fn author() -> arkret_sdk::ActorId {
    actor("did:web:author.example", STATION)
}
fn reader() -> arkret_sdk::ActorId {
    actor("did:web:reader.example", STATION)
}
fn message_id() -> String {
    arkret_sdk::MessageId::from_event_id(&EVENT.parse().unwrap()).to_string()
}

fn admitted() -> crate::runtime::projection::AdmittedSignal {
    let scope_ref = arkret_sdk::ScopeRef::Realm {
        realm_id: REALM.parse().unwrap(),
    };
    crate::runtime::projection::AdmittedSignal {
        domain: arkret_sdk::SignalSequenceDomain {
            sender_actor_id: reader(),
            endpoint: arkret_sdk::SignalSequenceEndpoint::AccountDevice {
                device_id: arkret_sdk::DeviceId::new_v7_at(1_800_000_000_000),
            },
            scope_ref,
        },
        signer_verification_method: arkret_sdk::DidUrl::new("did:web:reader.example#device-1")
            .unwrap(),
        product_authority: None,
        call_invitation: None,
        authority_commit_id: arkret_sdk::RealmCommitId::from_digest([41; 32]),
        parent_realm_authority_commit_id: None,
        payload: arkret_sdk::SignalPlaintext::ReadReceipt(arkret_sdk::ReadReceipt::new(
            3, reader(), EVENT.parse().unwrap(),
            serde_json::from_value(serde_json::json!({"kind":"strand", "object_ref":STRAND, "track_name":"discussion"})).unwrap(),
        ).unwrap()),
        expires_at: chrono::DateTime::from_timestamp(1_800_000_030, 0).unwrap(),
    }
}

fn target() -> crate::state::VerifiedMessageCommit {
    crate::state::VerifiedMessageCommit {
        accepted_ref: arkret_sdk::CommittedEventRef {
            event_id: EVENT.parse().unwrap(),
            commit_id: arkret_sdk::RealmCommitId::from_digest([42; 32]),
            stream_ref: arkret_sdk::CommitStreamRef::Realm {
                realm_id: REALM.parse().unwrap(),
            },
            stream_position: 1,
        },
        actor_id: author(),
        scope_ref: arkret_sdk::ScopeRef::Realm {
            realm_id: REALM.parse().unwrap(),
        },
        strand_id: STRAND.parse().unwrap(),
        track_name: "discussion".to_owned(),
    }
}

#[derive(Clone)]
struct Case {
    viewer: Option<crate::config::ActiveAccountContext>,
    targets: Vec<crate::state::VerifiedMessageCommit>,
    policy: arkret_sdk::ReadReceiptPolicy,
    signal: crate::runtime::projection::AdmittedSignal,
    message: Option<String>,
    visible_author: Option<arkret_sdk::ActorId>,
    display: bool,
    send: bool,
    path: std::path::PathBuf,
    control: Rc<RefCell<Option<(ReadReceiptHub, crate::app::SessionContext)>>>,
}

impl Case {
    fn private(path: std::path::PathBuf) -> Self {
        Self {
            viewer: Some(
                crate::test_support::AccountFixture::new("did:web:author.example")
                    .station(STATION)
                    .build(),
            ),
            targets: vec![target()],
            policy: arkret_sdk::ReadReceiptPolicy {
                visibility: arkret_sdk::ReadReceiptVisibility::Private,
                ..Default::default()
            },
            signal: admitted(),
            message: Some(message_id()),
            visible_author: Some(author()),
            display: true,
            send: true,
            path,
            control: Rc::new(RefCell::new(None)),
        }
    }

    fn as_viewer(&mut self, principal: &str, station: &str) {
        self.viewer = Some(
            crate::test_support::AccountFixture::new(principal)
                .station(station)
                .build(),
        );
    }
}

fn receipt_page(case: Case) -> Element {
    let viewer = use_signal(|| case.viewer.clone());
    let state_store = use_signal_sync(|| {
        let mut store = crate::state::LocalStateStore::with_path(case.path.clone());
        let mut state = store.load();
        state.verified_message_commits = case.targets.clone().into();
        state.read_receipt_default_send = case.send;
        store.save(state);
        store
    });
    let session = crate::app::SessionContext {
        active_account: viewer,
        state_store,
        base_url: use_signal(String::new),
        session_generation: use_signal(|| 0),
        owned_agents_rev: use_signal(|| 0),
    };
    let receipts = use_context_provider(ReadReceiptHub::new);
    let calls = use_hook(crate::views::call_signals::CallSignalHub::new);
    let messages = use_hook(crate::views::message_streams::MessageStreamHub::new);
    use_hook(|| {
        let sink = AppSignalProductSink::new(calls, messages, receipts, session);
        sink.read_receipt(&case.signal, &case.policy);
    });
    *case.control.borrow_mut() = Some((receipts, session));
    let Some(local) = viewer
        .read()
        .as_ref()
        .map(|account| arkret_sdk::ActorId::account(account.authority.clone()))
    else {
        return rsx! {};
    };
    rsx! {
        ReadReceiptIndicator {
            realm_id: REALM,
            strand_id: STRAND,
            message_id: case.message,
            target_author: case.visible_author,
            viewer: local,
            display: case.display,
            policy: Some(case.policy.clone()),
        }
    }
}

fn rendered_readers(mutations: dioxus::core::Mutations) -> Vec<arkret_sdk::ActorId> {
    mutations
        .edits
        .into_iter()
        .find_map(|edit| match edit {
            dioxus::core::Mutation::SetAttribute {
                name: "data-readers",
                value: dioxus::core::AttributeValue::Text(value),
                ..
            } => Some(serde_json::from_str(&value).unwrap()),
            _ => None,
        })
        .unwrap_or_default()
}

fn render_case(change: impl FnOnce(&mut Case)) -> Vec<arkret_sdk::ActorId> {
    let temp = tempfile::tempdir().unwrap();
    let mut case = Case::private(temp.path().join("state.json"));
    change(&mut case);
    let mut dom = VirtualDom::new_with_props(receipt_page, case);
    rendered_readers(dom.rebuild_to_vec())
}

#[test]
fn private_receipt_consumer_and_page_show_reader_only_to_target_author() {
    assert_eq!(render_case(|_| {}), vec![reader()]);
    for principal in ["did:web:reader.example", "did:web:other.example"] {
        assert!(render_case(|case| case.as_viewer(principal, STATION)).is_empty());
    }
}

#[test]
fn private_receipt_consumer_rejects_same_principal_at_another_station_and_signed_out() {
    assert!(render_case(|case| case.as_viewer("did:web:author.example", OTHER_STATION)).is_empty());
    assert!(render_case(|case| case.viewer = None).is_empty());
}

#[test]
fn receipt_consumer_rejects_missing_or_mismatched_verified_target() {
    assert!(render_case(|case| case.targets.clear()).is_empty());
    assert!(
        render_case(|case| case.targets[0].accepted_ref.event_id =
            arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [44; 32]))
        .is_empty()
    );
    assert!(
        render_case(
            |case| case.targets[0].strand_id = arkret_sdk::StrandId::from_event_id(
                &arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [45; 32])
            )
        )
        .is_empty()
    );
    assert!(
        render_case(
            |case| case.targets[0].scope_ref = arkret_sdk::ScopeRef::Circle {
                realm_id: REALM.parse().unwrap(),
                circle_id: arkret_sdk::CircleId::from_event_id(&arkret_sdk::EventId::from_digest(
                    arkret_sdk::DigestSuite::Sha256,
                    [46; 32]
                ))
            }
        )
        .is_empty()
    );
    assert!(render_case(|case| case.targets[0].track_name = "other".to_owned()).is_empty());
}

#[test]
fn receipt_page_fails_closed_without_visible_message_or_author() {
    assert!(render_case(|case| case.message = None).is_empty());
    assert!(render_case(|case| case.visible_author = None).is_empty());
    assert!(
        render_case(
            |case| case.visible_author = Some(actor("did:web:author.example", OTHER_STATION))
        )
        .is_empty()
    );
}

#[test]
fn receipt_consumer_preserves_disabled_and_independent_send_display_preferences() {
    assert!(
        render_case(|case| case.policy.disclosure = arkret_sdk::ReadReceiptDisclosure::Disabled)
            .is_empty()
    );
    assert_eq!(render_case(|case| case.send = false), vec![reader()]);
    assert!(render_case(|case| case.display = false).is_empty());
    for visibility in [
        arkret_sdk::ReadReceiptVisibility::Public,
        arkret_sdk::ReadReceiptVisibility::Members,
    ] {
        assert_eq!(
            render_case(|case| {
                case.policy.visibility = visibility;
                case.as_viewer("did:web:other.example", STATION);
            }),
            vec![reader()]
        );
    }
}

#[test]
fn receipt_page_hides_retained_positions_after_account_switch() {
    let temp = tempfile::tempdir().unwrap();
    let case = Case::private(temp.path().join("state.json"));
    let control = case.control.clone();
    let mut dom = VirtualDom::new_with_props(receipt_page, case);
    assert_eq!(rendered_readers(dom.rebuild_to_vec()), vec![reader()]);
    let (hub, mut session) = control.borrow().unwrap();
    dom.in_runtime(|| {
        session.active_account.set(Some(
            crate::test_support::AccountFixture::new("did:web:author.example")
                .station(OTHER_STATION)
                .build(),
        ));
        assert!(
            hub.readers_of(
                REALM,
                STRAND,
                &message_id(),
                &actor("did:web:author.example", OTHER_STATION),
                &author()
            )
            .is_empty()
        );
    });
    let edits = dom.render_immediate_to_vec();
    assert!(edits.edits.iter().any(|edit| matches!(
        edit,
        dioxus::core::Mutation::Remove { .. } | dioxus::core::Mutation::ReplaceWith { .. }
    )));
}

#[test]
fn receipt_consumer_only_projects_strand_receipts_and_accepts_optional_track() {
    assert_eq!(
        render_case(|case| {
            if let arkret_sdk::SignalPlaintext::ReadReceipt(receipt) = &mut case.signal.payload {
                receipt.read_scope.track = None;
            }
        }),
        vec![reader()]
    );
    for scope in [
        arkret_sdk::ReadReceiptScope::realm(),
        arkret_sdk::ReadReceiptScope::thread(message_id()),
    ] {
        assert!(
            render_case(|case| {
                if let arkret_sdk::SignalPlaintext::ReadReceipt(receipt) = &mut case.signal.payload
                {
                    receipt.read_scope = scope;
                }
            })
            .is_empty()
        );
    }
}
