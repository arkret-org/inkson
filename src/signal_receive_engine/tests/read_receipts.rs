//! The actual encrypted-Signal product router reads accepted policy current.
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use super::*;

#[derive(Default)]
struct ReceiptProducts(RefCell<Vec<arkret_sdk::ReadReceiptPolicy>>);
impl SignalProductSink for ReceiptProducts {
    fn call_signal<'a>(
        &'a self,
        _: &'a AdmittedSignal,
        _: Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
        Box::pin(async {})
    }
    fn message_stream<'a>(
        &'a self,
        _: &'a AdmittedSignal,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
        Box::pin(async {})
    }
    fn read_receipt(&self, _: &AdmittedSignal, policy: &arkret_sdk::ReadReceiptPolicy) {
        self.0.borrow_mut().push(policy.clone());
    }
    fn advance_clock(&self, _: DateTime<Utc>) {}
}

fn received(signal: &AdmittedSignal) -> SignalReceiveOutcome {
    SignalReceiveOutcome::Accepted {
        domain: Box::new(signal.domain.clone()),
        plaintext: Box::new(signal.payload.clone()),
        effective_expires_at: signal.expires_at,
        authority_commit_id: signal.authority_commit_id.clone(),
        parent_realm_authority_commit_id: signal.parent_realm_authority_commit_id.clone(),
        product_authority: signal.product_authority.clone(),
        call_invitation: signal.call_invitation.clone(),
        signer_verification_method: signal.signer_verification_method.clone(),
    }
}

async fn routed_policy(value: Option<Value>, complete: bool) -> Vec<arkret_sdk::ReadReceiptPolicy> {
    let directory = tempfile::tempdir().unwrap();
    let mut local = crate::LocalStateStore::with_path(directory.path().join("receipt-policy.json"));
    local.promote_accepted_context_for_test(&"did:web:bob.example".parse().unwrap());
    let account = local.active_authority().unwrap();
    let realm: arkret_sdk::RealmId = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
        .parse()
        .unwrap();
    // This obsolete cache deliberately contradicts accepted current. Routing
    // must ignore it, rather than consuming a test-only policy setter.
    local.set_read_receipt_policy_snapshot(
        realm.to_string(),
        Some(crate::state::ReadReceiptPolicySnapshot {
            disclosure: "optional".to_owned(),
            visibility: Some("public".to_owned()),
        }),
    );
    let index = crate::state::CurrentIndex::open(&account, 0, local.current_index_location())
        .await
        .unwrap();
    let store = Arc::new(Mutex::new(local));
    let read = store.clone();
    let write = store.clone();
    let products = Rc::new(ReceiptProducts::default());
    let router = SignalProductRouter::default();
    router.install(products.clone());
    let sink = InksonSignalSink {
        call_account: None,
        call_http: None,
        state_store: crate::runtime::input::StateStoreHandle::new(
            move |consume| consume(&read.lock().unwrap()),
            move |consume| consume(&mut write.lock().unwrap()),
        ),
        products: router,
        live: Mutex::new(Default::default()),
    };
    let event = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [91; 32]);
    let strand = arkret_sdk::StrandId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::DigestSuite::Sha256,
        [92; 32],
    ));
    let mut signal = plaintext_of(
        "ak.receipt.read",
        json!({
            "kind":"ak.receipt.read", "actor_id":arkret_sdk::ActorId::account(account),
            "event_id":event, "read_scope":{"kind":"strand","object_ref":strand,"track_name":"discussion"}
        }),
    );
    if let arkret_sdk::SignalPlaintext::ReadReceipt(receipt) = &signal.payload {
        signal.domain.sender_actor_id = receipt.actor_id.clone();
    }
    let stream = arkret_sdk::CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let commit = arkret_sdk::RealmCommitId::from_digest([93; 32]);
    let row = |selector, value| arkret_sdk::TypedCurrentRow::Value {
        selector,
        source_stream_ref: stream.clone(),
        revision: arkret_sdk::CurrentRevision {
            commit_id: commit.clone(),
            stream_position: 1,
        },
        value,
    };
    let mut entries = vec![row(
        arkret_sdk::CurrentSelector::Strand {
            strand_id: strand.clone(),
        },
        serde_json::to_value(arkret_sdk::Strand::discussion(
            strand,
            realm.clone(),
            "Target",
            signal.actor_id().clone(),
        ))
        .unwrap(),
    )];
    if let Some(value) = value {
        entries.push(row(
            arkret_sdk::CurrentSelector::RealmReadReceiptPolicy,
            value,
        ));
    }
    let head = arkret_sdk::CommitStreamHead {
        stream_ref: stream,
        commit_id: commit,
        stream_position: 1,
    };
    let frame: arkret_sdk::sync::AccountSubscribeFrame = serde_json::from_value(json!({
        "kind":"delta", "cursor":"ak:cursor:YQ", "realms":{realm.to_string(): {
            "current":{"realm_id":realm,"governance_generation":1,"stream_heads":[head],"entries":entries},
            "baseline":{"snapshot_cursor":"ak:cursor:Yg", "cut_revision":1,
                "coverage":{"realm_id":realm,"stream_heads":[head],"complete_for_authorized_streams":true},"complete":complete}
        }}
    })).unwrap();
    let stage = index.stage_frame(0, &frame).await.unwrap();
    store
        .lock()
        .unwrap()
        .commit_current_stage_for_test(stage)
        .unwrap();
    store.lock().unwrap().set_current_generation(1);
    assert_eq!(
        sink.realm_read_receipt_policy(&signal).await.is_some(),
        complete
    );
    sink.handle(received(&signal)).await.unwrap();
    let answer = products.0.borrow().clone();
    answer
}

#[tokio::test]
async fn read_receipt_route_consumes_private_typed_current_instead_of_legacy_cache() {
    let observed = routed_policy(Some(json!({"visibility":"private"})), true).await;
    assert_eq!(observed.len(), 1);
    assert_eq!(
        observed[0].visibility,
        arkret_sdk::ReadReceiptVisibility::Private
    );
    let absent = routed_policy(None, true).await;
    assert_eq!(absent, vec![arkret_sdk::ReadReceiptPolicy::default()]);
}

#[tokio::test]
async fn read_receipt_route_discards_without_complete_current_even_with_legacy_policy() {
    assert!(
        routed_policy(Some(json!({"visibility":"private"})), false)
            .await
            .is_empty()
    );
    assert!(routed_policy(None, false).await.is_empty());
}
