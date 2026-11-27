//! Receipt policy reads consume the same durable, verified current cut.
use super::*;

fn scope() -> arkret_sdk::ScopeRef {
    arkret_sdk::ScopeRef::Realm {
        realm_id: REALM.parse().unwrap(),
    }
}

fn policy_row(value: serde_json::Value) -> CurrentState {
    CurrentState::Value {
        selector: CurrentSelector::ScopeReadReceiptPolicy,
        source_stream_ref: arkret_sdk::CommitStreamRef::Realm {
            realm_id: REALM.parse().unwrap(),
        },
        revision: arkret_wire::CurrentRevision {
            commit_id: COMMIT.parse().unwrap(),
            stream_position: 1,
        },
        value,
    }
}

#[tokio::test]
async fn read_receipt_policy_defaults_require_proven_absence_at_complete_cut() {
    let location = path();
    let store = index(&location, 0).await;
    assert!(
        store
            .read_read_receipt_policy_ready(&scope())
            .await
            .is_err()
    );
    store
        .stage_frame(0, &frame(vec![], Some(baseline(CURSORS[0], 1, false))))
        .await
        .unwrap()
        .finish();
    assert!(
        store
            .read_read_receipt_policy_ready(&scope())
            .await
            .is_err()
    );
    store
        .stage_frame(1, &frame(vec![], Some(baseline(CURSORS[1], 1, true))))
        .await
        .unwrap()
        .finish();
    assert_eq!(
        store
            .read_read_receipt_policy_ready(&scope())
            .await
            .unwrap(),
        arkret_sdk::ReadReceiptPolicy::default()
    );
    drop(store);
    let reopened = index(&location, 2).await;
    assert_eq!(
        reopened
            .read_read_receipt_policy_ready(&scope())
            .await
            .unwrap(),
        arkret_sdk::ReadReceiptPolicy::default()
    );
}

#[tokio::test]
async fn read_receipt_policy_for_one_realm_cannot_authorize_another() {
    let location = path();
    let store = index(&location, 0).await;
    let other_realm = arkret_sdk::ScopeRef::Realm { realm_id: arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [81; 32],
        )) };
    store
        .stage_frame(
            0,
            &frame(
                vec![policy_row(
                    json!({"disclosure":"disabled","visibility":"private"}),
                )],
                Some(baseline(CURSORS[0], 1, true)),
            ),
        )
        .await
        .unwrap()
        .finish();
    assert!(store.read_read_receipt_policy_ready(&other_realm).await.is_err());

}

#[tokio::test]
async fn read_receipt_policy_rejects_unrecognized_or_empty_current_values() {
    for value in [
        json!({}),
        json!({"visibility":"unknown"}),
        json!({"disclosure":"optional", "extra":true}),
    ] {
        let location = path();
        let store = index(&location, 0).await;
        let result = store
            .stage_frame(
                0,
                &frame(vec![policy_row(value)], Some(baseline(CURSORS[0], 1, true))),
            )
            .await;
        if let Ok(stage) = result {
            stage.finish();
            assert!(
                store
                    .read_read_receipt_policy_ready(&scope())
                    .await
                    .is_err()
            );
        }
    }
}
