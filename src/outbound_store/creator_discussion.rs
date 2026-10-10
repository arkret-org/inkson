//! Holder-local linkage for ordinary Realm product initialization.
//!
//! Each signed Event remains an independent protocol submission. Its identity
//! and queue bytes are installed by the same native/IndexedDB vault CAS.

use arkret_sdk::{EventId, EventKind, RealmId, ScopeRef, StrandId};

use super::*;

#[derive(Clone, Copy)]
pub(crate) enum CreatorDiscussionStep {
    Create,
    Select,
}

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreatorRealmDiscussion {
    create: Option<EventId>,
    select: Option<EventId>,
}

impl CreatorRealmDiscussion {
    fn id(&self, step: CreatorDiscussionStep) -> Option<&EventId> {
        match step {
            CreatorDiscussionStep::Create => self.create.as_ref(),
            CreatorDiscussionStep::Select => self.select.as_ref(),
        }
    }
}

impl DurableOutboundState {
    fn discussion_record(&self, realm: &RealmId) -> garth::Result<&MlsCreatorBootstrapRecord> {
        self.creator_bootstrap_records.iter().find(|record| {
            record.intent().effective_scope() == &ScopeRef::Realm { realm_id: realm.clone() }
                && matches!(record.intent().signed_scope_create_unit(),
                    arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(_))
        }).ok_or_else(|| garth::Error::Storage("default discussion has no ordinary Realm creator intent".into()))
    }

    pub(super) fn discussion_submission(
        &self,
        realm: &RealmId,
        step: CreatorDiscussionStep,
    ) -> garth::Result<Option<garth::QueuedSubmission>> {
        let plan = self.creator_realm_discussions.get(realm).ok_or_else(|| {
            garth::Error::Storage("ordinary Realm creator lost its discussion initializer".into())
        })?;
        plan.id(step)
            .map(|id| {
                self.items
                    .iter()
                    .find(|item| item.event_id() == id)
                    .map(|item| item.submission.clone())
                    .ok_or_else(|| {
                        garth::Error::Storage("default discussion lost its frozen Event".into())
                    })
            })
            .transpose()
    }

    fn completed_discussion(&self, realm: &RealmId) -> garth::Result<Option<StrandId>> {
        if self
            .discussion_record(realm)?
            .quarantine_diagnostic()
            .is_some()
        {
            return Err(garth::Error::Storage(
                "quarantined discussion initialization cannot resume".into(),
            ));
        }
        let Some(create) = self.discussion_submission(realm, CreatorDiscussionStep::Create)? else {
            return Ok(None);
        };
        let Some(select) = self.discussion_submission(realm, CreatorDiscussionStep::Select)? else {
            return Ok(None);
        };
        if [&create.event_id, &select.event_id].iter().all(|id| {
            self.items.iter().any(|item| {
                item.event_id() == *id
                    && item.status == garth::SendQueueStatus::Committed
                    && item.commit().is_some()
                    && item.settled_at.is_some()
            })
        }) {
            return Ok(Some(StrandId::from_event_id(&create.event_id)));
        }
        Ok(None)
    }

    fn validate_discussion_event(
        &self,
        realm: &RealmId,
        step: CreatorDiscussionStep,
        submission: &garth::QueuedSubmission,
    ) -> garth::Result<()> {
        let record = self.discussion_record(realm)?;
        let event = submission.primary_event();
        if !matches!(
            submission.request,
            arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(_)
        ) || &event.scope_ref != record.intent().effective_scope()
            || &event.actor_id != record.intent().owner_actor_id()
            || event
                .producer_proof
                .as_ref()
                .map(|proof| &proof.verification_method)
                != Some(record.intent().creator_signer_method())
        {
            return Err(garth::Error::Protocol(
                "default discussion changed its exact Realm or creator".into(),
            ));
        }
        match step {
            CreatorDiscussionStep::Create => {
                let payload: arkret_sdk::StrandCreatePayload =
                    serde_json::from_value(serde_json::to_value(&event.payload)?)?;
                if event.kind != EventKind::StrandCreate
                    || &payload.object.realm_id != realm
                    || &payload.object.created_by != record.intent().owner_actor_id()
                    || payload.object.tracks
                        != std::collections::BTreeMap::from([(
                            "discussion".to_owned(),
                            arkret_sdk::StrandTrack::discussion_primary(),
                        )])
                    || payload.object.scope_circle_id.is_some()
                    || payload.object.metadata.is_some()
                    || payload.object.content.is_some()
                    || payload.object.encrypted_metadata.is_some()
                    || payload.object.encrypted_content.is_some()
                {
                    return Err(garth::Error::Protocol(
                        "default discussion must be a metadata-free Realm Strand".into(),
                    ));
                }
            }
            CreatorDiscussionStep::Select => {
                let create = self
                    .discussion_submission(realm, CreatorDiscussionStep::Create)?
                    .ok_or_else(|| {
                        garth::Error::Storage(
                            "default selection precedes its original Strand".into(),
                        )
                    })?;
                let payload: arkret_sdk::RealmSetDefaultStrandPayload =
                    serde_json::from_value(serde_json::to_value(&event.payload)?)?;
                if event.kind != EventKind::RealmSetDefaultStrand
                    || &payload.realm_id != realm
                    || payload.strand_id != StrandId::from_event_id(&create.event_id)
                    || payload.expected_default_strand_id.is_some()
                    || payload.reason.is_some()
                {
                    return Err(garth::Error::Protocol(
                        "default selection does not name the original Strand".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) fn validate_creator_discussions(&self) -> garth::Result<()> {
        for (realm, plan) in &self.creator_realm_discussions {
            let record = self.discussion_record(realm)?;
            // Quarantine retains opaque diagnostics; they cannot resume writes.
            if record.quarantine_diagnostic().is_some() {
                continue;
            }
            for step in [CreatorDiscussionStep::Create, CreatorDiscussionStep::Select] {
                if let Some(submission) = self.discussion_submission(realm, step)? {
                    self.validate_discussion_event(realm, step, &submission)?;
                }
            }
            if record.queued_genesis().is_some()
                && [plan.create.as_ref(), plan.select.as_ref()]
                    .iter()
                    .any(|id| {
                        !id.is_some_and(|id| {
                            self.items.iter().any(|item| {
                                item.event_id() == id
                                    && item.status == garth::SendQueueStatus::Committed
                                    && item.commit().is_some()
                                    && item.settled_at.is_some()
                            })
                        })
                    })
            {
                return Err(garth::Error::Storage(
                    "Genesis precedes durable default discussion initialization".into(),
                ));
            }
        }
        Ok(())
    }

    fn freeze_discussion_step(
        &mut self,
        realm: &RealmId,
        step: CreatorDiscussionStep,
        candidate: garth::QueuedSubmission,
    ) -> garth::Result<garth::QueuedSubmission> {
        self.validate_discussion_event(realm, step, &candidate)?;
        let record = self.discussion_record(realm)?;
        if record.quarantine_diagnostic().is_some() {
            return Err(garth::Error::Storage(
                "quarantined creator cannot initialize a discussion".into(),
            ));
        }
        // Independent holders join the CAS winner; losing authored candidates
        // never enter the queue and never leave the process.
        if let Some(original) = self.discussion_submission(realm, step)? {
            return Ok(original);
        }
        if record.queued_genesis().is_some() {
            return Err(garth::Error::Storage(
                "cannot initialize a missing discussion after Genesis".into(),
            ));
        }
        let predecessor = match step {
            CreatorDiscussionStep::Create => record.intent().scope_create_event_id(),
            CreatorDiscussionStep::Select => self.creator_realm_discussions[realm]
                .create
                .as_ref()
                .ok_or_else(|| garth::Error::Storage("default selection has no Strand".into()))?,
        };
        if !self.items.iter().any(|item| {
            item.event_id() == predecessor
                && item.status == garth::SendQueueStatus::Committed
                && item.commit().is_some()
                && item.settled_at.is_some()
        }) {
            return Err(garth::Error::Storage(
                "default discussion predecessor has not committed".into(),
            ));
        }
        let mut queue = garth::SendQueue::from_snapshot(garth::SendQueueSnapshot {
            items: self.items.clone(),
        });
        queue.enqueue(candidate.clone(), crate::clock::now_utc())?;
        self.items = queue.snapshot().items;
        let plan = self
            .creator_realm_discussions
            .get_mut(realm)
            .ok_or_else(|| garth::Error::Storage("default discussion plan is missing".into()))?;
        match step {
            CreatorDiscussionStep::Create => plan.create = Some(candidate.event_id.clone()),
            CreatorDiscussionStep::Select => plan.select = Some(candidate.event_id.clone()),
        }
        Ok(candidate)
    }
}

impl InksonOutboundStore {
    /// Completed product work is a read, not another send-lane acquisition.
    /// MLS acceptance recovery must not wait behind the uncertain Genesis it
    /// is responsible for reconciling.
    pub(crate) async fn completed_creator_discussion(
        &self,
        realm: &RealmId,
    ) -> garth::Result<Option<StrandId>> {
        self.mutate_state(|state| state.completed_discussion(realm))
            .await
    }

    pub(crate) async fn creator_discussion_submission(
        &self,
        realm: &RealmId,
        step: CreatorDiscussionStep,
    ) -> garth::Result<Option<garth::QueuedSubmission>> {
        self.mutate_state(|state| state.discussion_submission(realm, step))
            .await
    }

    pub(crate) async fn freeze_creator_discussion_step(
        &self,
        realm: &RealmId,
        step: CreatorDiscussionStep,
        candidate: garth::QueuedSubmission,
    ) -> garth::Result<garth::QueuedSubmission> {
        self.mutate_state(|state| state.freeze_discussion_step(realm, step, candidate))
            .await
    }
}
