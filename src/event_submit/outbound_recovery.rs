//! Recover disclosed historical acceptance before applying a new-send gate.

use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;

use super::*;

impl EventSubmitter {
    pub(super) async fn recover_accepted_application_items(
        &self,
        outbound: &InksonOutboundEngine,
    ) -> anyhow::Result<usize> {
        let mut recovered = 0usize;
        for item in outbound.snapshot().await?.items {
            if !is_unsettled(item.status) || item.attempts == 0 {
                continue;
            }
            let SelfAuthoritySubmitRequest::Event(submission) = item.request() else {
                continue;
            };
            if crate::mls::send_gate::ApplicationBody::of_event(
                &submission.event.kind,
                &submission.event.payload,
            )?
            .is_none()
                || self
                    .ensure_queued_application_send_gate(item.request())
                    .await
                    .is_ok()
            {
                continue;
            }
            // Absence or unavailable disclosure never proves a rejection.
            let client = crate::transport::own_station_results::client_for_http(&self.http).await?;
            anyhow::ensure!(
                client.session()?.account_id() == self.authority()?,
                "outbound recovery belongs to another Account"
            );
            let response = match client.committed_event_get(item.event_id()).await {
                Ok(response) => response,
                Err(_) => continue,
            };
            let commit = response.value()?.commit();
            let reference = arkret_wire::CommittedEventRef {
                event_id: item.event_id().clone(),
                commit_id: commit.commit_id.clone(),
                stream_ref: commit.stream_ref.clone(),
                stream_position: commit.stream_position,
            };
            let response =
                garth::own_station_results::consume_bound_event(&client, &reference, response)
                    .await?;
            let arkret_wire::CommittedEventView::Full(accepted) = response.value()? else {
                anyhow::bail!("outbound historical original is withheld");
            };
            let accepted = accepted.clone();
            let original = item.submission.clone();
            let settled = outbound
                .store()
                .mutate_outbound(move |queue| {
                    client
                        .check_session()
                        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
                    restore_application_outcome(queue, &original, &accepted)
                })
                .await?;
            if let Some(state) = self.state_store.as_ref() {
                state.write(|store| {
                    reconcile_settled_outbound_item(store, &settled);
                });
            }
            #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
            tracing::warn!("ordinary historical outbound acceptance restored");
            recovered = recovered.saturating_add(1);
        }
        Ok(recovered)
    }
}

// The caller must consume the full own-Station historical original first.
fn restore_application_outcome(
    queue: &mut garth::SendQueue,
    original: &QueuedSubmission,
    accepted: &arkret_wire::CommittedEventFullView,
) -> garth::Result<garth::SendQueueItem> {
    let SelfAuthoritySubmitRequest::Event(submission) = &original.request else {
        return Err(garth::Error::Protocol("not an application Event".into()));
    };
    if submission.event != accepted.event {
        return Err(garth::Error::Protocol(
            "historical acceptance changed the frozen Event".into(),
        ));
    }
    let mut snapshot = queue.snapshot();
    let item = snapshot
        .items
        .iter_mut()
        .find(|item| item.event_id() == &original.event_id)
        .ok_or_else(|| garth::Error::Storage("outbound recovery lost its original".into()))?;
    if item.request() != &original.request
        || (item.status.is_terminal() && item.status != SendQueueStatus::Committed)
    {
        return Err(garth::Error::Protocol(
            "outbound recovery conflicts with retained original or outcome".into(),
        ));
    }
    item.submission
        .apply_outcome(arkret_wire::AuthoritySubmitOutcome::Accepted {
            status: arkret_wire::AuthorityCommitStatus::Committed,
            commit: accepted.commit.clone(),
        })?;
    item.status = SendQueueStatus::Committed;
    item.settled_at = Some(accepted.commit.committed_at);
    item.last_error = None;
    item.last_problem = None;
    let settled = item.clone();
    *queue = garth::SendQueue::from_snapshot(snapshot);
    Ok(settled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_preserves_exact_bytes_and_rejects_substitution_or_terminal_conflict() {
        let event = crate::event_submit::tests::author_and_sign(
            crate::event_submit::tests::message_intent(
                crate::event_submit::tests::REALM,
                "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
            ),
            &crate::event_submit::tests::test_signer(),
        );
        let original = event_submission(&event).unwrap();
        let accepted = arkret_wire::CommittedEventFullView {
            event: event.event().clone(),
            commit: crate::event_submit::tests::commit_for(event.event(), 1),
        };
        let mut queue = garth::SendQueue::default();
        queue
            .enqueue(original.clone(), crate::clock::now_utc())
            .unwrap();
        let before = queue.snapshot();
        let mut wrong = accepted.clone();
        wrong.event.created_at += chrono::Duration::seconds(1);
        assert!(restore_application_outcome(&mut queue, &original, &wrong).is_err());
        assert_eq!(queue.snapshot(), before);
        let mut wrong_commit = accepted.clone();
        wrong_commit.commit.event_ref =
            arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [99; 32]);
        assert!(restore_application_outcome(&mut queue, &original, &wrong_commit).is_err());
        assert_eq!(queue.snapshot(), before);
        let settled = restore_application_outcome(&mut queue, &original, &accepted).unwrap();
        assert_eq!(settled.request(), &original.request);
        assert_eq!(settled.commit(), Some(&accepted.commit));
        assert_eq!(settled.status, SendQueueStatus::Committed);
        assert_eq!(settled.attempts, 0);
        let reopened = garth::SendQueue::from_snapshot(queue.snapshot());
        assert_eq!(reopened.get(&original.event_id).unwrap(), &settled);
        assert_eq!(
            restore_application_outcome(&mut queue, &original, &accepted).unwrap(),
            settled
        );
        let mut wrong_commit = accepted.clone();
        wrong_commit.commit.commit_id = arkret_wire::RealmCommitId::from_digest([99; 32]);
        let before = queue.snapshot();
        assert!(restore_application_outcome(&mut queue, &original, &wrong_commit).is_err());
        assert_eq!(queue.snapshot(), before);
        let mut cancelled = garth::SendQueue::default();
        cancelled
            .enqueue(original.clone(), crate::clock::now_utc())
            .unwrap();
        cancelled
            .cancel(&original.event_id, crate::clock::now_utc())
            .unwrap();
        let before = cancelled.snapshot();
        assert!(restore_application_outcome(&mut cancelled, &original, &accepted).is_err());
        assert_eq!(cancelled.snapshot(), before);
    }
}
