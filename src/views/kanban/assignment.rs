use std::collections::{BTreeMap, BTreeSet};

use dioxus::prelude::*;
use serde_json::json;

use super::model::*;
use crate::local_state::LocalStateStore;
use crate::operation::sdk_event_local_operation_id;
use crate::views::helpers::{short_protocol_id, with_authed_api};

#[derive(Clone)]
pub(super) enum CardAssignmentMutation {
    Create {
        actor_id: String,
        relation_id: String,
        operation: cokret_sdk::Event,
    },
    Tombstone {
        actor_id: String,
        relation_id: String,
        operation: cokret_sdk::Event,
    },
}

impl CardAssignmentMutation {
    pub(super) fn relation_id(&self) -> &str {
        match self {
            Self::Create { relation_id, .. } | Self::Tombstone { relation_id, .. } => relation_id,
        }
    }

    pub(super) fn actor_id(&self) -> &str {
        match self {
            Self::Create { actor_id, .. } | Self::Tombstone { actor_id, .. } => actor_id,
        }
    }

    pub(super) fn operation(&self) -> &cokret_sdk::Event {
        match self {
            Self::Create { operation, .. } | Self::Tombstone { operation, .. } => operation,
        }
    }
}

pub(super) fn assignment_activity_summary(
    mutation: &CardAssignmentMutation,
    assignee_labels: &BTreeMap<String, String>,
) -> String {
    let actor = assignee_labels
        .get(mutation.actor_id())
        .cloned()
        .unwrap_or_else(|| short_protocol_id(mutation.actor_id()));
    match mutation {
        CardAssignmentMutation::Create { .. } => format!("Assignee added: {actor}"),
        CardAssignmentMutation::Tombstone { .. } => format!("Assignee removed: {actor}"),
    }
}

pub(super) fn relation_id_from_event_id(event_id: &str) -> Option<String> {
    event_id
        .strip_prefix("ck:event:")
        .map(|suffix| format!("ck:relation:{suffix}"))
}

pub(super) fn normalize_assignee_selection(
    selected_actor_ids: BTreeSet<String>,
) -> Result<BTreeSet<String>, String> {
    let mut normalized = BTreeSet::new();
    for actor_id in selected_actor_ids {
        let actor_id = actor_id.trim();
        if actor_id.is_empty() {
            continue;
        }
        if !actor_id.starts_with("did:") {
            return Err(format!("assignee actor id must be a DID: {actor_id}"));
        }
        normalized.insert(actor_id.to_owned());
    }
    Ok(normalized)
}

pub(super) fn card_assignment_mutations(
    realm_id: &str,
    actor_id: &str,
    current: &KanbanCard,
    selected_actor_ids: &BTreeSet<String>,
) -> Result<Vec<CardAssignmentMutation>, String> {
    let current_actor_ids = card_assigned_actor_ids(current)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut relation_ids_by_actor = BTreeMap::<String, Vec<String>>::new();
    for relation in &current.assigned_to_relations {
        let relation_id = relation.relation_id.trim();
        let actor_id = relation.actor_id.trim();
        if relation_id.is_empty() || actor_id.is_empty() {
            continue;
        }
        relation_ids_by_actor
            .entry(actor_id.to_owned())
            .or_default()
            .push(relation_id.to_owned());
    }

    let mut mutations = Vec::new();
    // `actor_id` (the acting user / event author, an account_did) signs the
    // assignment events; `assignee_id` is the person being assigned/unassigned
    // and only appears as the relation target.
    for assignee_id in selected_actor_ids.difference(&current_actor_ids) {
        let operation = crate::operation::ck_ops::relation_create(
            realm_id,
            actor_id,
            "assigned_to",
            &current.id,
            assignee_id,
        )
        .map_err(|err| format!("cannot build assigned_to relation: {err:#}"))?
        .build_sdk_event("yougen")
        .map_err(|err| format!("cannot build assigned_to relation event: {err}"))?;
        let relation_id =
            relation_id_from_event_id(operation.event_id.as_str()).ok_or_else(|| {
                format!(
                    "internal: cannot derive assigned_to relation id from {}",
                    operation.event_id.as_str()
                )
            })?;
        mutations.push(CardAssignmentMutation::Create {
            actor_id: assignee_id.clone(),
            relation_id,
            operation,
        });
    }

    for assignee_id in current_actor_ids.difference(selected_actor_ids) {
        let Some(relation_ids) = relation_ids_by_actor.get(assignee_id) else {
            return Err(format!(
                "assignment for {} is missing its relation_id; refresh before removing it",
                short_protocol_id(assignee_id)
            ));
        };
        for relation_id in relation_ids {
            let operation =
                crate::operation::ck_ops::relation_tombstone(realm_id, actor_id, relation_id)
                    .build_sdk_event("yougen")
                    .map_err(|err| format!("cannot build assigned_to tombstone event: {err}"))?;
            mutations.push(CardAssignmentMutation::Tombstone {
                actor_id: assignee_id.clone(),
                relation_id: relation_id.clone(),
                operation,
            });
        }
    }
    Ok(mutations)
}

pub(super) fn assignment_relations_after_mutations(
    current: &KanbanCard,
    selected_actor_ids: &BTreeSet<String>,
    mutations: &[CardAssignmentMutation],
) -> Vec<CardAssignedToRelation> {
    let tombstoned = mutations
        .iter()
        .filter_map(|mutation| match mutation {
            CardAssignmentMutation::Tombstone { relation_id, .. } => Some(relation_id.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let mut relations = current
        .assigned_to_relations
        .iter()
        .filter(|relation| selected_actor_ids.contains(relation.actor_id.trim()))
        .filter(|relation| !tombstoned.contains(relation.relation_id.trim()))
        .cloned()
        .collect::<Vec<_>>();
    for mutation in mutations {
        if let CardAssignmentMutation::Create {
            actor_id,
            relation_id,
            ..
        } = mutation
            && selected_actor_ids.contains(actor_id)
        {
            relations.push(CardAssignedToRelation {
                relation_id: relation_id.clone(),
                actor_id: actor_id.clone(),
            });
        }
    }
    relations.sort_by(|left, right| {
        left.actor_id
            .cmp(&right.actor_id)
            .then(left.relation_id.cmp(&right.relation_id))
    });
    relations.dedup_by(|left, right| left.relation_id == right.relation_id);
    relations
}

#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch_card_assignees_update(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    current: KanbanCard,
    selected_actor_ids: BTreeSet<String>,
    assignee_labels: BTreeMap<String, String>,
    mut selected_card: Signal<Option<KanbanCard>>,
    mut state_store: Signal<LocalStateStore>,
    mut board_status: Signal<String>,
    mut assignee_edit_status: Signal<String>,
) -> bool {
    let selected_actor_ids = match normalize_assignee_selection(selected_actor_ids) {
        Ok(selected) => selected,
        Err(msg) => {
            assignee_edit_status.set(msg.clone());
            board_status.set(msg);
            return false;
        }
    };
    if actor_id.trim().is_empty() {
        let msg = "sign in before editing assignees".to_owned();
        assignee_edit_status.set(msg.clone());
        board_status.set(msg);
        return false;
    }
    if realm_id.trim().is_empty() {
        let msg = "select a Realm before editing assignees".to_owned();
        assignee_edit_status.set(msg.clone());
        board_status.set(msg);
        return false;
    }

    let mutations =
        match card_assignment_mutations(&realm_id, &actor_id, &current, &selected_actor_ids) {
            Ok(mutations) => mutations,
            Err(msg) => {
                assignee_edit_status.set(msg.clone());
                board_status.set(msg);
                return false;
            }
        };
    if mutations.is_empty() {
        board_status.set("No assignee changes to save".to_owned());
        assignee_edit_status.set(String::new());
        return true;
    }

    let optimistic_relations =
        assignment_relations_after_mutations(&current, &selected_actor_ids, &mutations);
    // Optimistic detail-panel feedback: apply the assignment to the open card.
    // The board re-renders from the appended `ck.relation.*` ops below —
    // `columns` is a `use_memo` over `raw_operations`, folded by
    // `overlay_local_card_assignment_records`, so there is no direct signal
    // write.
    let mut updated_card = current.clone();
    apply_card_assignment_projection(
        &mut updated_card,
        &selected_actor_ids,
        optimistic_relations.clone(),
        CardState::Queued,
    );
    selected_card.set(Some(updated_card));

    for mutation in &mutations {
        let operation = mutation.operation();
        let operation_id = sdk_event_local_operation_id(operation).to_owned();
        state_store.write().append_raw_operation(
            operation_id.clone(),
            Some(realm_id.clone()),
            json!({
                "kind": operation.kind.as_str(),
                "operation_id": operation_id,
                "actor_id": operation.actor_id.to_string(),
                "created_at": operation.created_at.to_rfc3339(),
                "write_state": "queued",
                "body": operation.payload.clone(),
                "assignment_strand_id": current.id.clone(),
                "assignment_actor_id": mutation.actor_id(),
                "assignment_relation_id": mutation.relation_id(),
                "activity_summary": assignment_activity_summary(mutation, &assignee_labels),
            }),
        );
    }

    let operation_count = mutations.len();
    board_status.set(format!(
        "submitting {operation_count} assignee relation operation{}",
        if operation_count == 1 { "" } else { "s" }
    ));
    assignee_edit_status.set("Saving...".to_owned());
    let api_token = token();
    let strand_id = current.id.clone();
    spawn(async move {
        for mutation in mutations {
            let operation = mutation.operation().clone();
            let operation_id = sdk_event_local_operation_id(&operation).to_owned();
            let kind = operation.kind.as_str().to_owned();
            match with_authed_api(&base_url, api_token.clone(), |api| async move {
                api.submit_sdk_event(&operation).await
            })
            .await
            {
                Ok(resp) => {
                    state_store.write().update_raw_operation_write_state(
                        &operation_id,
                        "accepted",
                        Some(resp.event_id.clone()),
                        None,
                    );
                }
                Err(err) => {
                    let err_text = err.display().to_string();
                    state_store.write().update_raw_operation_write_state(
                        &operation_id,
                        "failed",
                        None,
                        Some(err_text.clone()),
                    );
                    let selected = selected_card.read().clone();
                    if let Some(mut card) = selected
                        && card.id == strand_id
                    {
                        card.state = CardState::SoftFailed;
                        selected_card.set(Some(card));
                    }
                    assignee_edit_status.set(format!("{kind} failed"));
                    board_status.set(format!("{kind} operation failed: {err_text}"));
                    return;
                }
            }
        }
        let selected = selected_card.read().clone();
        if let Some(mut card) = selected
            && card.id == strand_id
        {
            card.state = CardState::Accepted;
            selected_card.set(Some(card));
        }
        assignee_edit_status.set(String::new());
        board_status.set("Assignees updated".to_owned());
    });
    true
}
