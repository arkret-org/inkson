//! Receipt policy reads consume the same durable, verified current cut.
use super::*;

fn scope() -> arkret_sdk::ScopeRef {
    arkret_sdk::ScopeRef::Realm {
        realm_id: REALM.parse().unwrap(),
    }
}

fn policy_row(value: serde_json::Value) -> TypedCurrentRow {
    TypedCurrentRow::Value {
        selector: CurrentSelector::ScopeReadReceiptPolicy { scope_ref: scope() },
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
async fn read_receipt_policy_consumes_typed_current_and_closes_unprovable_circle_floor() {
    let location = path();
    let store = index(&location, 0).await;
    store
        .stage_frame(
            0,
            &frame(
                vec![policy_row(json!({"visibility":"private"}))],
                Some(baseline(CURSORS[0], 1, true)),
            ),
        )
        .await
        .unwrap()
        .finish();
    let parent = store
        .read_read_receipt_policy_ready(&scope())
        .await
        .unwrap();
    assert_eq!(
        parent.visibility,
        arkret_sdk::ReadReceiptVisibility::Private
    );
    assert_eq!(
        parent.disclosure,
        arkret_sdk::ReadReceiptDisclosure::Optional
    );
    let circle = arkret_sdk::ScopeRef::Circle {
        realm_id: REALM.parse().unwrap(),
        circle_id: arkret_sdk::CircleId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [81; 32],
        )),
    };
    assert!(store.read_read_receipt_policy_ready(&circle).await.is_err());
    let mut explicit = policy_row(json!({"visibility":"private"}));
    let TypedCurrentRow::Value { revision, .. } = &mut explicit;
    revision.stream_position = 2;
    store
        .stage_frame(
            1,
            &frame(vec![explicit], Some(baseline(CURSORS[1], 2, true))),
        )
        .await
        .unwrap()
        .finish();
    assert!(store.read_read_receipt_policy_ready(&circle).await.is_err());
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
