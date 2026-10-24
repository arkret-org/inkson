//! Resume the original card's placement after its create receipt, without UI ownership.

use super::*;
use crate::outbound_store::card_placement::CardPlacement;

impl EventSubmitter {
    pub(crate) async fn submit_card_create(
        &self,
        operation: &LocalOperation,
        placement: CardPlacement,
    ) -> anyhow::Result<SubmitEventResult> {
        self.submit_sdk_event_inner(operation, Some(placement))
            .await
    }

    // The foreground writer and background drain both hold outbound_submit_lock.
    // A crash before the vault CAS publishes no Move. A crash after it always
    // resumes the exact retained Move, including an unknown accepted response.
    pub(super) async fn resume_card_placements(
        &self,
        outbound: &InksonOutboundEngine,
    ) -> anyhow::Result<Vec<QueuedSubmission>> {
        let mut pending = Vec::new();
        let mut work = outbound.store().card_placement_work().await?;
        for (create, plan, placed) in &mut work {
            let item = match placed.as_ref() {
                Some(item) => item.clone(),
                None => {
                    let event = create.primary_event();
                    anyhow::ensure!(
                        event.actor_id.as_account_id() == Some(self.authority()?),
                        "card continuation changed Account"
                    );
                    let intent =
                        arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::StrandMove>::new(
                            event.scope_ref.clone(),
                            event.actor_id.clone(),
                            plan.payload(&create.event_id),
                        )?
                        .into_intent(crate::clock::now_utc())?;
                    let candidate = match self.author_intent(&intent).await {
                        Ok(event) => event_submission(&event)?,
                        Err(error) => {
                            tracing::debug!(%error, create = %create.event_id, "card placement awaits current authoring authority");
                            continue;
                        }
                    };
                    let frozen = outbound
                        .store()
                        .freeze_card_move(&create.event_id, candidate)
                        .await?;
                    outbound
                        .snapshot()
                        .await?
                        .items
                        .into_iter()
                        .find(|item| item.event_id() == &frozen.event_id)
                        .ok_or_else(|| anyhow::anyhow!("frozen card Move is missing"))?
                }
            };
            if is_unsettled(item.status) {
                pending.push(item.submission.clone());
            }
            *placed = Some(item);
        }
        if !work.is_empty()
            && let Some(store) = &self.state_store
        {
            let updates = store.read(|store| card_placement_projection_updates(store, &work));
            if !updates.is_empty() {
                store.write(|store| {
                    apply_card_placement_projection(store, updates);
                });
            }
        }
        Ok(pending)
    }
}

type CardPlacementProjectionUpdate = (String, Option<String>, Value);

fn apply_card_placement_projection(
    store: &mut crate::state::LocalStateStore,
    updates: Vec<CardPlacementProjectionUpdate>,
) {
    for (id, realm, payload) in updates {
        store.upsert_raw_operation(id, realm, payload);
    }
}

fn card_placement_projection_updates(
    store: &crate::state::LocalStateStore,
    work: &[(
        QueuedSubmission,
        CardPlacement,
        Option<garth::SendQueueItem>,
    )],
) -> Vec<CardPlacementProjectionUpdate> {
    if work.is_empty() {
        return Vec::new();
    }
    // One snapshot per drain, with no repeated unchanged writes or resurrection
    // of old rows already evicted from the bounded product projection.
    let snapshot = store.load();
    let rows = snapshot
        .raw_operations
        .iter()
        .map(|row| (row.operation_id.as_str(), &row.payload))
        .collect::<BTreeMap<_, _>>();
    let mut updates = Vec::new();
    for (create, plan, placed) in work {
        let original = rows.get(plan.local_operation_id.as_str()).copied();
        if let Some(row) = original
            && !row.get("producer_proof").is_some_and(Value::is_object)
            && (row.get("event_id").and_then(Value::as_str) != Some(create.event_id.as_str())
                || !matches!(
                    row.get("write_state").and_then(Value::as_str),
                    Some("accepted" | "synced")
                ))
        {
            let Some(mut payload) = row.as_object().cloned() else {
                continue;
            };
            payload.insert("event_id".into(), serde_json::json!(create.event_id));
            payload.insert("write_state".into(), serde_json::json!("accepted"));
            payload.remove("error");
            updates.push((
                plan.local_operation_id.clone(),
                Some(create.primary_event().realm_id.to_string()),
                Value::Object(payload),
            ));
        }
        let Some(item) = placed else {
            continue;
        };
        let id = item.event_id().to_string();
        let previous = rows.get(id.as_str());
        if previous.is_some_and(|row| row.get("producer_proof").is_some_and(Value::is_object)) {
            continue;
        }
        if original.is_none() && previous.is_none() {
            continue;
        }
        let state = match item.status {
            SendQueueStatus::Committed => "accepted",
            SendQueueStatus::Rejected => "rejected",
            SendQueueStatus::Failed => "failed",
            SendQueueStatus::Cancelled => "cancelled",
            _ => "queued",
        };
        if previous.is_some_and(|row| {
            row.get("event_id").and_then(Value::as_str) == Some(id.as_str())
                && (row.get("write_state").and_then(Value::as_str) == Some(state)
                    || row.get("write_state").and_then(Value::as_str) == Some("synced"))
        }) {
            continue;
        }
        let event = item.submission.primary_event();
        let strand = arkret_sdk::StrandId::from_event_id(&create.event_id);
        updates.push((
            id.clone(),
            Some(event.realm_id.to_string()),
            serde_json::json!({
                "kind": event_kind_str::STRAND_MOVE,
                "move_id": id,
                "event_id": item.event_id(),
                "cell": format!("{}#{}", plan.board_space_id, strand),
                "board_space_id": plan.board_space_id,
                "strand_id": strand,
                "expected_position": null,
                "target_position": {"list_space_id": plan.list_space_id, "rank": plan.rank},
                "body": event.payload,
                "write_state": state,
            }),
        ));
    }
    updates
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use arkret_sdk::{EventId, SpaceId};

    use super::*;
    use crate::outbound_store::InksonOutboundStore;

    impl InksonOutboundStore {
        async fn card_test_snapshot(&self) -> garth::Result<garth::SendQueueSnapshot> {
            self.mutate_outbound(|queue| Ok(queue.snapshot())).await
        }
    }

    fn fixture() -> (garth::QueuedSubmission, CardPlacement) {
        let actor = crate::event_submit::tests::account_actor();
        let realm = arkret_sdk::RealmId::new(crate::event_submit::tests::REALM).unwrap();
        let object = arkret_sdk::StrandCreateObject::new(realm.clone(), actor.clone()).with_track(
            "synthesis",
            arkret_sdk::StrandTrack::new()
                .primary()
                .with_profile("kanban_card"),
        );
        let intent = arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::StrandCreate>::new(
            arkret_sdk::ScopeRef::Realm { realm_id: realm },
            actor,
            crate::operation::ak_ops::strand_create_payload(object).unwrap(),
        )
        .unwrap()
        .into_intent(crate::clock::now_utc())
        .unwrap();
        let event = crate::event_submit::tests::author_and_sign(
            intent,
            &crate::event_submit::tests::test_signer(),
        );
        let plan = CardPlacement::new(
            SpaceId::from_event_id(&EventId::from_digest(
                arkret_sdk::DigestSuite::Sha256,
                [45; 32],
            )),
            SpaceId::from_event_id(&EventId::from_digest(
                arkret_sdk::DigestSuite::Sha256,
                [46; 32],
            )),
            "U".into(),
            "local-card-create".into(),
        )
        .unwrap();
        (crate::event_submit::event_submission(&event).unwrap(), plan)
    }

    fn movement(
        create: &garth::QueuedSubmission,
        plan: &CardPlacement,
        offset: i64,
    ) -> garth::QueuedSubmission {
        let original = create.primary_event();
        let intent = arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::StrandMove>::new(
            original.scope_ref.clone(),
            original.actor_id.clone(),
            plan.payload(&create.event_id),
        )
        .unwrap()
        .into_intent(original.created_at + chrono::Duration::seconds(offset))
        .unwrap();
        crate::event_submit::event_submission(&crate::event_submit::tests::author_and_sign(
            intent,
            &crate::event_submit::tests::test_signer(),
        ))
        .unwrap()
    }

    async fn settle(store: &InksonOutboundStore, id: &EventId, accepted: bool) {
        store
            .mutate_outbound(|queue| {
                let mut snapshot = queue.snapshot();
                let item = snapshot
                    .items
                    .iter_mut()
                    .find(|item| item.event_id() == id)
                    .unwrap();
                let outcome = if accepted {
                    arkret_wire::AuthoritySubmitResponseBody::Accepted {
                        status: arkret_wire::AuthorityCommitStatus::Committed,
                        commit: crate::event_submit::tests::commit_for(
                            item.submission.primary_event(),
                            1,
                        ),
                    }
                } else {
                    arkret_wire::AuthoritySubmitResponseBody::Rejected {
                        status: arkret_wire::AuthorityRejectionStatus::Rejected,
                        reason_code: "permission_denied".into(),
                    }
                };
                item.submission.apply_outcome(outcome)?;
                item.status = if accepted {
                    garth::SendQueueStatus::Committed
                } else {
                    garth::SendQueueStatus::Rejected
                };
                item.settled_at = Some(crate::clock::now_utc());
                *queue = garth::SendQueue::from_snapshot(snapshot);
                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn card_receipt_and_cold_restart_keep_one_exact_followup_through_response_loss() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("card.json");
        let (create, plan) = fixture();
        let store = InksonOutboundStore::for_test_path(path.clone());
        store
            .freeze_card_create(create.clone(), plan.clone())
            .await
            .unwrap();
        assert!(store.card_placement_work().await.unwrap().is_empty());
        assert!(
            store
                .freeze_card_move(&create.event_id, movement(&create, &plan, 1))
                .await
                .is_err()
        );
        let store = InksonOutboundStore::for_test_path(path.clone());
        assert_eq!(
            store.card_test_snapshot().await.unwrap().items[0].request(),
            &create.request
        );
        settle(&store, &create.event_id, true).await;
        drop(store);
        let store = InksonOutboundStore::for_test_path(path.clone());
        assert_eq!(store.card_placement_work().await.unwrap().len(), 1);
        let first = movement(&create, &plan, 1);
        let frozen = store
            .freeze_card_move(&create.event_id, first.clone())
            .await
            .unwrap();
        assert_eq!(frozen, first);
        let reopened = InksonOutboundStore::for_test_path(path.clone());
        let other = movement(&create, &plan, 2);
        assert_ne!(other.event_id, first.event_id);
        let (a, b) = tokio::join!(
            reopened.freeze_card_move(&create.event_id, other.clone()),
            store.freeze_card_move(&create.event_id, other),
        );
        assert_eq!(a.unwrap().request, first.request);
        assert_eq!(b.unwrap().request, first.request);
        reopened
            .mutate_outbound(|queue| {
                let mut snapshot = queue.snapshot();
                let item = snapshot
                    .items
                    .iter_mut()
                    .find(|item| item.event_id() == &first.event_id)
                    .unwrap();
                item.status = garth::SendQueueStatus::Forwarding;
                item.attempts = 1;
                *queue = garth::SendQueue::from_snapshot(snapshot);
                Ok(())
            })
            .await
            .unwrap();
        drop(reopened);
        let reopened = InksonOutboundStore::for_test_path(path);
        let work = reopened.card_placement_work().await.unwrap();
        assert_eq!(work[0].2.as_ref().unwrap().request(), &first.request);
        assert_eq!(reopened.card_test_snapshot().await.unwrap().items.len(), 2);
        settle(&reopened, &first.event_id, true).await;
        reopened
            .freeze_card_create(create.clone(), plan.clone())
            .await
            .unwrap();
        assert_eq!(
            reopened
                .freeze_card_move(&create.event_id, movement(&create, &plan, 3))
                .await
                .unwrap()
                .request,
            first.request
        );
        assert_eq!(reopened.card_test_snapshot().await.unwrap().items.len(), 2);
    }

    #[tokio::test]
    async fn rejected_create_never_places_and_refused_move_never_recreates_or_changes_intent() {
        let directory = tempfile::tempdir().unwrap();
        for accepted in [false, true] {
            let path = directory.path().join(format!("card-{accepted}.json"));
            let store = InksonOutboundStore::for_test_path(path.clone());
            let (create, plan) = fixture();
            store
                .freeze_card_create(create.clone(), plan.clone())
                .await
                .unwrap();
            settle(&store, &create.event_id, accepted).await;
            let candidate = movement(&create, &plan, 1);
            if accepted {
                store
                    .freeze_card_move(&create.event_id, candidate.clone())
                    .await
                    .unwrap();
                settle(&store, &candidate.event_id, false).await;
                let reopened = InksonOutboundStore::for_test_path(path);
                let retained = reopened
                    .freeze_card_move(&create.event_id, movement(&create, &plan, 2))
                    .await
                    .unwrap();
                assert_eq!(retained.request, candidate.request);
                assert_eq!(
                    reopened.card_placement_work().await.unwrap()[0]
                        .2
                        .as_ref()
                        .unwrap()
                        .status,
                    garth::SendQueueStatus::Rejected
                );
                let mut changed = plan.clone();
                changed.rank = "V".into();
                assert!(
                    reopened
                        .freeze_card_create(create.clone(), changed.clone())
                        .await
                        .is_err()
                );
                assert!(
                    reopened
                        .freeze_card_move(&create.event_id, movement(&create, &changed, 3))
                        .await
                        .is_err()
                );
                assert_eq!(reopened.card_test_snapshot().await.unwrap().items.len(), 2);
            } else {
                assert!(
                    store
                        .freeze_card_move(&create.event_id, candidate)
                        .await
                        .is_err()
                );
                assert!(
                    InksonOutboundStore::for_test_path(path)
                        .card_placement_work()
                        .await
                        .unwrap()
                        .is_empty()
                );
                assert_eq!(store.card_test_snapshot().await.unwrap().items.len(), 1);
            }
        }
    }
    #[tokio::test]
    async fn settled_card_projection_has_no_repeated_updates_or_evicted_row_resurrection() {
        let directory = tempfile::tempdir().unwrap();
        let queue = InksonOutboundStore::for_test_path(directory.path().join("queue.json"));
        let (create, plan) = fixture();
        queue
            .freeze_card_create(create.clone(), plan.clone())
            .await
            .unwrap();
        settle(&queue, &create.event_id, true).await;
        let movement = movement(&create, &plan, 1);
        queue
            .freeze_card_move(&create.event_id, movement.clone())
            .await
            .unwrap();
        settle(&queue, &movement.event_id, true).await;
        let work = queue.card_placement_work().await.unwrap();
        let path = directory.path().join("state.json");
        let mut state = crate::state::LocalStateStore::with_path(&path);
        state.upsert_raw_operation(
            plan.local_operation_id.clone(),
            Some(create.primary_event().realm_id.to_string()),
            serde_json::json!({"kind":"ak.strand.create", "write_state":"queued"}),
        );
        let updates = card_placement_projection_updates(&state, &work);
        assert_eq!(updates.len(), 2);
        apply_card_placement_projection(&mut state, updates);
        let before = state.load().raw_operations;
        for _ in 0..20 {
            assert!(card_placement_projection_updates(&state, &work).is_empty());
        }
        assert_eq!(state.load().raw_operations, before);
        let empty = crate::state::LocalStateStore::with_path(directory.path().join("evicted.json"));
        assert!(card_placement_projection_updates(&empty, &work).is_empty());
        assert!(empty.load().raw_operations.is_empty());
    }
    #[tokio::test]
    async fn card_projection_never_rewrites_signed_original_rows() {
        let directory = tempfile::tempdir().unwrap();
        let queue = InksonOutboundStore::for_test_path(directory.path().join("queue.json"));
        let (create, plan) = fixture();
        queue
            .freeze_card_create(create.clone(), plan.clone())
            .await
            .unwrap();
        settle(&queue, &create.event_id, true).await;
        let movement = movement(&create, &plan, 1);
        queue
            .freeze_card_move(&create.event_id, movement.clone())
            .await
            .unwrap();
        settle(&queue, &movement.event_id, true).await;
        let work = queue.card_placement_work().await.unwrap();
        let mut state =
            crate::state::LocalStateStore::with_path(directory.path().join("signed.json"));
        for (id, event) in [
            (plan.local_operation_id.clone(), create.primary_event()),
            (movement.event_id.to_string(), movement.primary_event()),
        ] {
            state.upsert_raw_operation(
                id,
                Some(event.realm_id.to_string()),
                serde_json::to_value(event).unwrap(),
            );
        }
        let before = state.load().raw_operations;
        assert!(card_placement_projection_updates(&state, &work).is_empty());
        assert_eq!(state.load().raw_operations, before);
        for row in before {
            let event: arkret_sdk::Event = serde_json::from_value(row.payload).unwrap();
            event
                .verify_event_id_matches_content_with_digest_suite(
                    event.event_id.digest_suite_code().digest_suite(),
                )
                .unwrap();
        }
    }
}
