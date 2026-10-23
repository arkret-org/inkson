//! Card initialization shares the existing encrypted outbound vault and CAS.

use arkret_sdk::{EventId, EventKind, SpaceId, StrandId};

use super::*;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CardPlacement {
    pub board_space_id: SpaceId,
    pub list_space_id: SpaceId,
    pub rank: String,
    pub local_operation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    move_event: Option<EventId>,
}

impl CardPlacement {
    pub(crate) fn new(
        board: SpaceId,
        list: SpaceId,
        rank: String,
        local_operation_id: String,
    ) -> garth::Result<Self> {
        if local_operation_id.is_empty()
            || rank.is_empty()
            || rank.len() > 128
            || !rank.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Err(garth::Error::Protocol("invalid initial card rank".into()));
        }
        Ok(Self {
            board_space_id: board,
            list_space_id: list,
            rank,
            local_operation_id,
            move_event: None,
        })
    }

    pub(crate) fn payload(&self, create: &EventId) -> arkret_sdk::StrandMovePayload {
        arkret_sdk::StrandMovePayload::new(
            self.board_space_id.clone(),
            StrandId::from_event_id(create),
            self.list_space_id.clone(),
            self.rank.clone(),
        )
    }
}

impl DurableOutboundState {
    fn freeze_card_create(
        &mut self,
        submission: garth::QueuedSubmission,
        plan: CardPlacement,
    ) -> garth::Result<()> {
        let event = submission.primary_event();
        if event.kind != EventKind::StrandCreate || plan.move_event.is_some() {
            return Err(garth::Error::Protocol(
                "card initializer requires an unplaced Strand create".into(),
            ));
        }
        let payload: arkret_sdk::StrandCreatePayload =
            serde_json::from_value(serde_json::to_value(&event.payload)?)?;
        if !payload.object.tracks.contains_key("synthesis")
            || payload.object.scope_circle_id.is_some()
        {
            return Err(garth::Error::Protocol(
                "card initializer requires a Realm card".into(),
            ));
        }
        if let Some(existing) = self.card_placements.get(&submission.event_id) {
            let mut original = existing.clone();
            original.move_event = None;
            if original != plan {
                return Err(garth::Error::Protocol(
                    "card placement intent changed".into(),
                ));
            }
        }
        if let Some(original) = self
            .items
            .iter()
            .find(|item| item.event_id() == &submission.event_id)
        {
            if original.request() != &submission.request {
                return Err(garth::Error::Protocol(
                    "card create changed its frozen request".into(),
                ));
            }
        } else {
            let mut queue = garth::SendQueue::from_snapshot(garth::SendQueueSnapshot {
                items: self.items.clone(),
            });
            queue.enqueue(submission.clone(), crate::clock::now_utc())?;
            self.items = queue.snapshot().items;
        }
        self.card_placements
            .entry(submission.event_id)
            .or_insert(plan);
        Ok(())
    }

    fn freeze_card_move(
        &mut self,
        create: &EventId,
        candidate: garth::QueuedSubmission,
    ) -> garth::Result<garth::QueuedSubmission> {
        let plan = self
            .card_placements
            .get(create)
            .ok_or_else(|| garth::Error::Storage("missing card initializer".into()))?;
        let original = self
            .items
            .iter()
            .find(|item| item.event_id() == create)
            .filter(|item| {
                item.status == garth::SendQueueStatus::Committed && item.commit().is_some()
            })
            .ok_or_else(|| garth::Error::Protocol("card create has no covering Commit".into()))?;
        let event = candidate.primary_event();
        let payload: arkret_sdk::StrandMovePayload =
            serde_json::from_value(serde_json::to_value(&event.payload)?)?;
        if event.kind != EventKind::StrandMove
            || event.scope_ref != original.submission.primary_event().scope_ref
            || event.actor_id != original.submission.primary_event().actor_id
            || payload != plan.payload(create)
        {
            return Err(garth::Error::Protocol(
                "card Move changed the accepted create or intended position".into(),
            ));
        }
        if let Some(id) = &plan.move_event {
            return self
                .items
                .iter()
                .find(|item| item.event_id() == id)
                .map(|item| item.submission.clone())
                .ok_or_else(|| {
                    garth::Error::Storage("card initializer lost its frozen Move".into())
                });
        }
        let mut queue = garth::SendQueue::from_snapshot(garth::SendQueueSnapshot {
            items: self.items.clone(),
        });
        queue.enqueue(candidate.clone(), crate::clock::now_utc())?;
        self.items = queue.snapshot().items;
        self.card_placements
            .get_mut(create)
            .ok_or_else(|| garth::Error::Storage("missing card initializer".into()))?
            .move_event = Some(candidate.event_id.clone());
        Ok(candidate)
    }
}

impl InksonOutboundStore {
    pub(crate) async fn freeze_card_create(
        &self,
        submission: garth::QueuedSubmission,
        plan: CardPlacement,
    ) -> garth::Result<()> {
        self.mutate_state(|state| state.freeze_card_create(submission, plan))
            .await
    }

    pub(crate) async fn card_placement_work(
        &self,
    ) -> garth::Result<
        Vec<(
            garth::QueuedSubmission,
            CardPlacement,
            Option<garth::SendQueueItem>,
        )>,
    > {
        self.mutate_state(|state| {
            let mut work = Vec::new();
            for (id, plan) in &state.card_placements {
                let create = state
                    .items
                    .iter()
                    .find(|item| item.event_id() == id)
                    .ok_or_else(|| {
                        garth::Error::Storage("card initializer lost its create".into())
                    })?;
                if create.status != garth::SendQueueStatus::Committed || create.commit().is_none() {
                    continue;
                }
                let placed = plan
                    .move_event
                    .as_ref()
                    .map(|id| {
                        state
                            .items
                            .iter()
                            .find(|item| item.event_id() == id)
                            .cloned()
                            .ok_or_else(|| {
                                garth::Error::Storage("card initializer lost its Move".into())
                            })
                    })
                    .transpose()?;
                work.push((create.submission.clone(), plan.clone(), placed));
            }
            Ok(work)
        })
        .await
    }

    pub(crate) async fn freeze_card_move(
        &self,
        create: &EventId,
        candidate: garth::QueuedSubmission,
    ) -> garth::Result<garth::QueuedSubmission> {
        self.mutate_state(|state| state.freeze_card_move(create, candidate))
            .await
    }
}
