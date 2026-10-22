//! One unresolved original per exact self-watch cell, in the existing queue.

use super::*;

fn validate_watch_request(
    authority: &arkret_sdk::AccountId,
    request: &arkret_sdk::StrandWatchCurrentRequestBody,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        request.watcher_actor_id.as_account_id() == Some(authority),
        "watch queue observation belongs to another complete Account"
    );
    Ok(())
}

fn matches_watch_cell(
    submission: &QueuedSubmission,
    authority: &arkret_sdk::AccountId,
    request: &arkret_sdk::StrandWatchCurrentRequestBody,
) -> anyhow::Result<bool> {
    validate_watch_request(authority, request)?;
    let event = submission.primary_event();
    if event.kind != arkret_sdk::EventKind::StrandWatchSet
        || event.actor_id.as_account_id() != Some(authority)
        || event.realm_id != request.realm_id
    {
        return Ok(false);
    }
    let payload: arkret_sdk::StrandWatchSetPayload =
        serde_json::from_value(serde_json::to_value(&event.payload)?)?;
    if payload.strand_id != request.strand_id
        || payload.watcher_actor_id != request.watcher_actor_id
    {
        return Ok(false);
    }
    submission.validate_queued_request()?;
    anyhow::ensure!(
        matches!(&event.scope_ref, arkret_sdk::ScopeRef::Realm { realm_id } if realm_id == &request.realm_id),
        "retained watch original names another effective scope"
    );
    Ok(true)
}

fn authority_settled_watch(item: &garth::SendQueueItem) -> anyhow::Result<bool> {
    match (&item.status, &item.submission.state) {
        (SendQueueStatus::Committed, garth::SubmissionState::Committed { status, commit }) => {
            // Validate the covering Commit against these exact frozen bytes.
            // A local terminal flag alone is not an authority answer.
            let mut checked = item.submission.clone();
            checked.apply_outcome(arkret_wire::AuthoritySubmitOutcome::Accepted {
                status: *status,
                commit: (**commit).clone(),
            })?;
            Ok(true)
        }
        (
            SendQueueStatus::Rejected,
            garth::SubmissionState::Rejected {
                status: arkret_wire::AuthorityRejectionStatus::Rejected,
                reason_code,
            },
        ) => {
            let mut checked = item.submission.clone();
            checked.apply_outcome(arkret_wire::AuthoritySubmitOutcome::Rejected {
                status: arkret_wire::AuthorityRejectionStatus::Rejected,
                reason_code: reason_code.clone(),
            })?;
            Ok(true)
        }
        // Failed/Cancelled can retain SubmissionState::Queued. Retryable
        // unavailable is also not a definitive refusal of the original.
        _ => Ok(false),
    }
}

fn pending_watch_from_snapshot(
    snapshot: &garth::SendQueueSnapshot,
    authority: &arkret_sdk::AccountId,
    request: &arkret_sdk::StrandWatchCurrentRequestBody,
) -> anyhow::Result<Option<garth::SendQueueItem>> {
    validate_watch_request(authority, request)?;
    let mut pending = None;
    for item in &snapshot.items {
        if !matches_watch_cell(&item.submission, authority, request)?
            || authority_settled_watch(item)?
        {
            continue;
        }
        anyhow::ensure!(
            pending.is_none(),
            "multiple unresolved originals exist for the exact watch cell"
        );
        pending = Some(item.clone());
    }
    Ok(pending)
}

/// Call once for early UI observation and again under `outbound_submit_lock`
/// before authoring. Current-value reads cannot settle an unknown original.
pub(crate) async fn ensure_strand_watch_settled(
    authority: &arkret_sdk::AccountId,
    request: &arkret_sdk::StrandWatchCurrentRequestBody,
) -> anyhow::Result<()> {
    validate_watch_request(authority, request)?;
    let outbound = OutboundEngine::new(
        InksonOutboundStore::open(authority, OutboundLane::Standard)?,
        InksonHostClock,
    );
    if let Some(item) =
        pending_watch_from_snapshot(&outbound.snapshot().await?, authority, request)?
    {
        return Err(DurablyQueuedError {
            operation_id: item.event_id().to_string(),
            reason: Some("previous watch write awaits its exact terminal outcome".to_owned()),
        }
        .into());
    }
    Ok(())
}

fn requeue_original_watch(
    queue: &mut garth::SendQueue,
    authority: &arkret_sdk::AccountId,
    request: &arkret_sdk::StrandWatchCurrentRequestBody,
    original: &QueuedSubmission,
    now: chrono::DateTime<chrono::Utc>,
    check: impl Fn() -> anyhow::Result<()>,
) -> garth::Result<bool> {
    let invalid = |error: anyhow::Error| garth::Error::Protocol(error.to_string());
    check().map_err(invalid)?;
    if !matches_watch_cell(original, authority, request).map_err(invalid)? {
        return Err(garth::Error::Protocol(
            "watch recovery original belongs to another Account or cell".to_owned(),
        ));
    }
    let retained = queue
        .get(&original.event_id)
        .ok_or_else(|| garth::Error::Storage("pending watch original disappeared".to_owned()))?;
    ensure_exact_queued_request(&retained.submission, original).map_err(invalid)?;
    check().map_err(invalid)?;
    queue.retry_unknown(&original.event_id, now)
}

impl EventSubmitter {
    /// Resume only this cell's existing signed Event. No new current preimage,
    /// Event identity, authoring timestamp or producer proof is constructed.
    pub(crate) async fn recover_pending_strand_watch(
        &self,
        request: &arkret_sdk::StrandWatchCurrentRequestBody,
    ) -> anyhow::Result<Option<SubmitEventResult>> {
        let authority = self.authority()?.clone();
        validate_watch_request(&authority, request)?;
        let epoch = crate::identity::device_directory::session_cache_epoch();
        let fence = crate::transport::auth::AuthoringSessionFence::capture()?;
        let device = arkret_sdk::DeviceId::new(
            fence
                .signer
                .device_id()
                .ok_or_else(|| anyhow::anyhow!("watch recovery requires an active device"))?
                .to_owned(),
        )?;
        let _single_writer = outbound_submit_lock().lock().await;
        let outbound = self.outbound(OutboundLane::Standard)?;
        let check = || -> anyhow::Result<()> {
            fence.check()?;
            self.ensure_device_authoring_fence(&authority, &device, &fence.signer, epoch)?;
            anyhow::ensure!(
                self.state_store.is_some(),
                "watch recovery requires the account store"
            );
            anyhow::ensure!(
                outbound.store().account_id() == Some(&authority),
                "watch recovery queue belongs to another Account"
            );
            if let Some(client) = self.http.own_station_result_client()? {
                anyhow::ensure!(
                    client.session()?.account_id() == &authority,
                    "watch recovery HTTP session names another Account"
                );
            }
            Ok(())
        };
        check()?;
        let Some(original) =
            pending_watch_from_snapshot(&outbound.snapshot().await?, &authority, request)?
        else {
            return Ok(None);
        };
        check()?;
        let retained = original.submission.clone();
        let now = crate::clock::now_utc();
        outbound
            .store()
            .mutate_outbound(|queue| {
                requeue_original_watch(queue, &authority, request, &retained, now, check)
            })
            .await?;
        check()?;
        let pending = outbound
            .snapshot()
            .await?
            .items
            .into_iter()
            .find(|item| item.event_id() == original.event_id())
            .ok_or_else(|| anyhow::anyhow!("pending watch original disappeared"))?;
        let source = crate::transport::own_station_results::client_for_http(&self.http).await?;
        check()?;
        if let Some(settled) = outbound_recovery::recover_disclosed_event_item(
            &outbound, &authority, &source, &pending, &check,
        )
        .await?
        {
            check()?;
            if let Some(state) = &self.state_store {
                state.write(|store| {
                    reconcile_settled_outbound_item(store, &settled);
                });
            }
            return Ok(Some(settled_outbound_result(&settled)?));
        }
        // No disclosed original is not a refusal. Replay the retained request
        // through the ordinary SDK authority engine and its current gates.
        check()?;
        let item = self
            .enqueue_and_drive_checked(
                QueuedWrite {
                    lane: OutboundLane::Standard,
                    submission: original.submission,
                    local_operation_id: pending.event_id().to_string(),
                    post_accept: PostAccept::None,
                    retry_scope: InteractiveRetryScope::Ordinary,
                },
                &check,
            )
            .await?;
        check()?;
        Ok(Some(settled_outbound_result(&item)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(
        level: arkret_sdk::StrandWatchLevel,
    ) -> (
        arkret_sdk::AccountId,
        arkret_sdk::StrandWatchCurrentRequestBody,
        QueuedSubmission,
    ) {
        let actor = crate::event_submit::tests::account_actor();
        let authority = actor.as_account_id().unwrap().clone();
        let request = arkret_sdk::StrandWatchCurrentRequestBody {
            realm_id: arkret_sdk::RealmId::new(crate::event_submit::tests::REALM).unwrap(),
            strand_id: arkret_sdk::StrandId::new(
                "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
            )
            .unwrap(),
            watcher_actor_id: actor.clone(),
        };
        let payload = arkret_sdk::StrandWatchSetPayload::set(
            request.strand_id.clone(),
            actor.clone(),
            level,
            None,
        )
        .with_expected_value(arkret_sdk::StrandWatchCurrentValue::Cleared(()));
        let intent = arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::StrandWatchSet>::new(
            arkret_sdk::ScopeRef::Realm {
                realm_id: request.realm_id.clone(),
            },
            actor,
            payload,
        )
        .unwrap()
        .into_intent(
            chrono::DateTime::parse_from_rfc3339("2026-05-19T00:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
        .unwrap();
        let event = crate::event_submit::tests::author_and_sign(
            intent,
            &crate::event_submit::tests::test_signer(),
        );
        (authority, request, event_submission(&event).unwrap())
    }

    fn queue(original: &QueuedSubmission) -> garth::SendQueue {
        let mut queue = garth::SendQueue::default();
        queue
            .enqueue(original.clone(), crate::clock::now_utc())
            .unwrap();
        queue
    }

    #[test]
    fn watch_pending_cell_is_complete_account_realm_strand_and_watcher() {
        let (authority, request, original) = fixture(arkret_sdk::StrandWatchLevel::All);
        let snapshot = queue(&original).snapshot();
        assert!(
            pending_watch_from_snapshot(&snapshot, &authority, &request)
                .unwrap()
                .is_some()
        );
        let mut other = request.clone();
        other.realm_id = arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [91; 32],
        ));
        assert!(
            pending_watch_from_snapshot(&snapshot, &authority, &other)
                .unwrap()
                .is_none()
        );
        let mut other = request.clone();
        other.strand_id = arkret_sdk::StrandId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [92; 32],
        ));
        assert!(
            pending_watch_from_snapshot(&snapshot, &authority, &other)
                .unwrap()
                .is_none()
        );
        let foreign = arkret_sdk::AccountId::new(
            authority.principal_id.clone(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        );
        assert!(pending_watch_from_snapshot(&snapshot, &foreign, &request).is_err());
        let mut other = request.clone();
        other.watcher_actor_id = arkret_sdk::ActorId::account(foreign.clone());
        assert!(
            pending_watch_from_snapshot(&snapshot, &foreign, &other)
                .unwrap()
                .is_none()
        );
        let message = crate::event_submit::tests::author_and_sign(
            crate::event_submit::tests::message_intent(
                crate::event_submit::tests::REALM,
                request.strand_id.as_str(),
            ),
            &crate::event_submit::tests::test_signer(),
        );
        assert!(
            pending_watch_from_snapshot(
                &queue(&event_submission(&message).unwrap()).snapshot(),
                &authority,
                &request,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn only_original_authority_commit_or_definitive_refusal_releases_watch() {
        let (authority, request, original) = fixture(arkret_sdk::StrandWatchLevel::All);
        for status in [
            SendQueueStatus::Queued,
            SendQueueStatus::Forwarding,
            SendQueueStatus::Failed,
            SendQueueStatus::Cancelled,
            SendQueueStatus::Committed,
        ] {
            let mut snapshot = queue(&original).snapshot();
            snapshot.items[0].status = status;
            assert!(
                pending_watch_from_snapshot(&snapshot, &authority, &request)
                    .unwrap()
                    .is_some(),
                "{status:?}"
            );
        }
        let mut snapshot = queue(&original).snapshot();
        snapshot.items[0].submission.state = garth::SubmissionState::Rejected {
            status: arkret_wire::AuthorityRejectionStatus::RetryableUnavailable,
            reason_code: "backend_unavailable".into(),
        };
        snapshot.items[0].status = SendQueueStatus::Rejected;
        assert!(
            pending_watch_from_snapshot(&snapshot, &authority, &request)
                .unwrap()
                .is_some()
        );
        snapshot.items[0].submission.state = garth::SubmissionState::Rejected {
            status: arkret_wire::AuthorityRejectionStatus::Rejected,
            reason_code: "permission_denied".into(),
        };
        assert!(
            pending_watch_from_snapshot(&snapshot, &authority, &request)
                .unwrap()
                .is_none()
        );
        snapshot = queue(&original).snapshot();
        let commit = crate::event_submit::tests::commit_for(original.primary_event(), 1);
        snapshot.items[0]
            .submission
            .apply_outcome(arkret_wire::AuthoritySubmitOutcome::Accepted {
                status: arkret_wire::AuthorityCommitStatus::Committed,
                commit,
            })
            .unwrap();
        snapshot.items[0].status = SendQueueStatus::Committed;
        assert!(
            pending_watch_from_snapshot(&snapshot, &authority, &request)
                .unwrap()
                .is_none()
        );
        let garth::SubmissionState::Committed { commit, .. } =
            &mut snapshot.items[0].submission.state
        else {
            unreachable!()
        };
        commit.event_ref =
            arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [93; 32]);
        assert!(pending_watch_from_snapshot(&snapshot, &authority, &request).is_err());
    }

    #[test]
    fn two_unknown_candidates_cannot_be_arbitrarily_coalesced() {
        let (authority, request, first) = fixture(arkret_sdk::StrandWatchLevel::All);
        let (_, _, second) = fixture(arkret_sdk::StrandWatchLevel::Muted);
        let mut queue = queue(&first);
        queue.enqueue(second, crate::clock::now_utc()).unwrap();
        assert!(pending_watch_from_snapshot(&queue.snapshot(), &authority, &request).is_err());
    }

    #[test]
    fn failed_watch_cold_recovery_keeps_exact_original_and_ignores_current_value() {
        let (authority, request, original) = fixture(arkret_sdk::StrandWatchLevel::All);
        let mut snapshot = queue(&original).snapshot();
        snapshot.items[0].status = SendQueueStatus::Failed;
        snapshot.items[0].attempts = 1;
        let bytes = serde_json::to_vec(&snapshot).unwrap();
        let reopened: garth::SendQueueSnapshot = serde_json::from_slice(&bytes).unwrap();
        let item = pending_watch_from_snapshot(&reopened, &authority, &request)
            .unwrap()
            .unwrap();
        let frozen = serde_json::to_vec(item.request()).unwrap();
        let mut queue = garth::SendQueue::from_snapshot(reopened);
        assert!(
            requeue_original_watch(
                &mut queue,
                &authority,
                &request,
                &item.submission,
                crate::clock::now_utc(),
                || Ok(())
            )
            .unwrap()
        );
        let retained = queue.get(&original.event_id).unwrap();
        assert_eq!(retained.status, SendQueueStatus::Queued);
        assert_eq!(retained.attempts, 1);
        assert_eq!(serde_json::to_vec(retained.request()).unwrap(), frozen);
        assert_eq!(retained.submission.event_id, original.event_id);
        assert!(
            pending_watch_from_snapshot(&queue.snapshot(), &authority, &request)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn watch_recovery_fence_cell_and_original_substitution_leave_queue_unchanged() {
        let (authority, request, original) = fixture(arkret_sdk::StrandWatchLevel::All);
        let mut queue = queue(&original);
        let before = queue.snapshot();
        assert!(
            requeue_original_watch(
                &mut queue,
                &authority,
                &request,
                &original,
                crate::clock::now_utc(),
                || anyhow::bail!("replaced account")
            )
            .is_err()
        );
        assert_eq!(queue.snapshot(), before);
        let checks = std::cell::Cell::new(0);
        assert!(
            requeue_original_watch(
                &mut queue,
                &authority,
                &request,
                &original,
                crate::clock::now_utc(),
                || {
                    checks.set(checks.get() + 1);
                    anyhow::ensure!(checks.get() == 1, "account replaced before mutation");
                    Ok(())
                },
            )
            .is_err()
        );
        assert_eq!(queue.snapshot(), before);
        let (_, _, changed) = fixture(arkret_sdk::StrandWatchLevel::Muted);
        assert!(
            requeue_original_watch(
                &mut queue,
                &authority,
                &request,
                &changed,
                crate::clock::now_utc(),
                || Ok(())
            )
            .is_err()
        );
        assert_eq!(queue.snapshot(), before);
        let mut changed_proof = original.clone();
        let arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
            submission,
        ) = &mut changed_proof.request
        else {
            unreachable!()
        };
        submission.event.producer_proof.as_mut().unwrap().created_at +=
            chrono::Duration::seconds(1);
        assert!(
            requeue_original_watch(
                &mut queue,
                &authority,
                &request,
                &changed_proof,
                crate::clock::now_utc(),
                || Ok(())
            )
            .is_err()
        );
        assert_eq!(queue.snapshot(), before);
    }
}
