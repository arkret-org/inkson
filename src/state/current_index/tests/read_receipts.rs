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
async fn read_receipt_policy_independent_scopes_require_their_own_complete_coverage() {
    let location = path();
    let store = index(&location, 0).await;
    let circle = arkret_sdk::ScopeRef::Circle {
        realm_id: REALM.parse().unwrap(),
        circle_id: arkret_sdk::CircleId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [81; 32],
        )),
    };
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
    assert!(store.read_read_receipt_policy_ready(&circle).await.is_err());
    let mut cut = baseline(CURSORS[1], 2, true);
    let mut circle_head = cut["coverage"]["stream_heads"][0].clone();
    circle_head["stream_ref"] = serde_json::to_value(
        arkret_sdk::CommitStreamRef::from_scope(&circle, Some(REALM.parse().unwrap())).unwrap(),
    )
    .unwrap();
    cut["coverage"]["stream_heads"]
        .as_array_mut()
        .unwrap()
        .push(circle_head);
    store
        .stage_frame(
            1,
            &frame(
                vec![policy_row(
                    json!({"disclosure":"disabled","visibility":"private"}),
                )],
                Some(cut.clone()),
            ),
        )
        .await
        .unwrap()
        .finish();
    assert_eq!(
        store.read_read_receipt_policy_ready(&circle).await.unwrap(),
        arkret_sdk::ReadReceiptPolicy::default()
    );
    let mut own = policy_row(json!({"disclosure":"required","visibility":"members"}));
    let TypedCurrentRow::Value {
        selector,
        source_stream_ref,
        ..
    } = &mut own;
    *selector = CurrentSelector::ScopeReadReceiptPolicy {
        scope_ref: circle.clone(),
    };
    *source_stream_ref =
        arkret_sdk::CommitStreamRef::from_scope(&circle, Some(REALM.parse().unwrap())).unwrap();
    let policy_commit = arkret_sdk::RealmCommitId::from_digest([82; 32]);
    let TypedCurrentRow::Value { revision, .. } = &mut own;
    revision.stream_position = 3;
    revision.commit_id = policy_commit.clone();
    cut["snapshot_cursor"] = json!(CURSORS[2]);
    cut["cut_revision"] = json!(3);
    cut["coverage"]["stream_heads"][1]["stream_position"] = json!(3);
    cut["coverage"]["stream_heads"][1]["commit_id"] = json!(policy_commit);
    store
        .stage_frame(
            2,
            &frame(
                vec![
                    policy_row(json!({"disclosure":"disabled","visibility":"private"})),
                    own,
                ],
                Some(cut),
            ),
        )
        .await
        .unwrap()
        .finish();
    assert_eq!(
        store
            .read_read_receipt_policy_ready(&circle)
            .await
            .unwrap()
            .disclosure,
        arkret_sdk::ReadReceiptDisclosure::Required
    );
    assert_eq!(
        store
            .read_read_receipt_policy_ready(&scope())
            .await
            .unwrap()
            .disclosure,
        arkret_sdk::ReadReceiptDisclosure::Disabled
    );
    drop(store);
    let reopened = index(&location, 3).await;
    assert_eq!(
        reopened
            .read_read_receipt_policy_ready(&circle)
            .await
            .unwrap()
            .disclosure,
        arkret_sdk::ReadReceiptDisclosure::Required
    );
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
