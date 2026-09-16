use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::model::*;
use crate::state::LocalStateStore;
use crate::transport::auth::with_authed_api;
use crate::views::helpers::short_protocol_id;

#[derive(Clone)]
pub(super) enum CardAssignmentMutation {
    /// A new assignment. The Relation is named by `retype(create.event_id)`, so
    /// it has no id until the create is accepted: the optimistic row is keyed by
    /// the write's holder-local operation id until then.
    Create {
        actor_id: arkret_sdk::ActorId,
        operation: crate::operation::LocalOperation,
    },
    /// Removing an existing assignment, which already has a Relation id.
    Tombstone {
        actor_id: arkret_sdk::ActorId,
        relation_id: String,
        operation: crate::operation::LocalOperation,
    },
}

impl CardAssignmentMutation {
    /// The Relation this mutation acts on, when it already exists.
    pub(super) fn relation_id(&self) -> Option<&str> {
        match self {
            Self::Create { .. } => None,
            Self::Tombstone { relation_id, .. } => Some(relation_id),
        }
    }

    pub(super) fn actor_id(&self) -> &arkret_sdk::ActorId {
        match self {
            Self::Create { actor_id, .. } | Self::Tombstone { actor_id, .. } => actor_id,
        }
    }

    pub(super) fn operation(&self) -> &crate::operation::LocalOperation {
        match self {
            Self::Create { operation, .. } | Self::Tombstone { operation, .. } => operation,
        }
    }
}

/// Closed set of assignment bodies: a created or tombstoned assignee
/// Relation, read back through its typed marker payload so the queued
/// record's `body` stays a closed discriminated shape.
#[derive(Serialize)]
#[serde(untagged)]
enum QueuedAssignmentBody {
    Create(Box<arkret_sdk::RelationCreatePayload>),
    Tombstone(arkret_sdk::RelationTombstonePayload),
}

/// Queued op-log record for one card-assignee mutation; field order matches
/// the wire layout the previous `json!` literal produced.
#[derive(Serialize)]
struct QueuedAssignmentRecord<'a> {
    kind: arkret_sdk::EventKind,
    operation_id: &'a str,
    actor_id: arkret_sdk::ActorId,
    created_at: String,
    write_state: &'static str,
    body: QueuedAssignmentBody,
    assignment_strand_id: &'a str,
    assignment_actor_id: &'a arkret_sdk::ActorId,
    assignment_relation_id: String,
}

fn queued_assignment_body(
    mutation: &CardAssignmentMutation,
) -> anyhow::Result<QueuedAssignmentBody> {
    Ok(match mutation {
        CardAssignmentMutation::Create { operation, .. } => QueuedAssignmentBody::Create(Box::new(
            operation.typed_payload::<arkret_wire::event_spec::RelationCreate>()?,
        )),
        CardAssignmentMutation::Tombstone { operation, .. } => QueuedAssignmentBody::Tombstone(
            operation.typed_payload::<arkret_wire::event_spec::RelationTombstone>()?,
        ),
    })
}

pub(super) fn normalize_assignee_selection(
    selected_actor_ids: BTreeSet<arkret_sdk::ActorId>,
) -> Result<BTreeSet<arkret_sdk::ActorId>, String> {
    Ok(selected_actor_ids)
}

pub(super) fn card_assignment_mutations(
    realm_id: &str,
    actor_id: &str,
    current: &KanbanCard,
    selected_actor_ids: &BTreeSet<arkret_sdk::ActorId>,
    lifecycle_bases: &BTreeMap<String, Vec<arkret_sdk::Hash>>,
) -> Result<Vec<CardAssignmentMutation>, String> {
    let current_actor_ids = card_assigned_actor_ids(current)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut relation_ids_by_actor = BTreeMap::<arkret_sdk::ActorId, Vec<String>>::new();
    for relation in &current.assigned_to_relations {
        let relation_id = relation.relation_id.trim();
        let actor_id = &relation.actor_id;
        if relation_id.is_empty() {
            continue;
        }
        relation_ids_by_actor
            .entry(actor_id.to_owned())
            .or_default()
            .push(relation_id.to_owned());
    }

    let mut mutations = Vec::new();
    // `actor_id` (the acting user / event author, an principal_id) signs the
    // assignment events; `assignee_id` is the person being assigned/unassigned
    // and only appears as the relation target.
    for assignee_id in selected_actor_ids.difference(&current_actor_ids) {
        let operation = crate::operation::ak_ops::relation_create_for_actor(
            realm_id,
            actor_id,
            "assigned_to",
            &current.id,
            assignee_id,
        )
        .map_err(|err| format!("cannot build assigned_to relation: {err:#}"))?
        .build_sdk_event("inkson")
        .map_err(|err| format!("cannot build assigned_to relation event: {err}"))?;
        // The Relation id is derived from this create Event, not carried in the
        // payload (spec `zh/models/common-fields.md` section 6.0), so it exists
        // only once the Event is accepted.
        mutations.push(CardAssignmentMutation::Create {
            actor_id: assignee_id.clone(),
            operation,
        });
    }

    for assignee_id in current_actor_ids.difference(selected_actor_ids) {
        let Some(relation_ids) = relation_ids_by_actor.get(assignee_id) else {
            return Err(format!(
                "assignment for {} is missing its relation_id; refresh before removing it",
                short_protocol_id(assignee_id.signing_principal_id().as_str())
            ));
        };
        for relation_id in relation_ids {
            let basis_refs = lifecycle_bases.get(relation_id).ok_or_else(|| {
                format!(
                    "assignment relation {} has no canonical lifecycle basis; refresh before removing it",
                    short_protocol_id(relation_id)
                )
            })?;
            let operation =
                crate::operation::ak_ops::relation_tombstone(realm_id, actor_id, relation_id)
                    .map_err(|err| format!("cannot build assigned_to tombstone: {err:#}"))?
                    .causal_refs(basis_refs.clone())
                    .build_sdk_event("inkson")
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

fn assignment_lifecycle_bases(
    state_store: &LocalStateStore,
    realm_id: &str,
    current: &KanbanCard,
) -> Result<BTreeMap<String, Vec<arkret_sdk::Hash>>, String> {
    let entries = state_store
        .realm_tree_projection(realm_id)
        .and_then(|projection| projection.get("current").cloned())
        .and_then(|value| serde_json::from_value::<arkret_sdk::CurrentEntries>(value).ok())
        .map(|current| current.entries)
        .ok_or_else(|| "assignment current state is still loading".to_owned())?;
    let mut result = BTreeMap::new();
    for relation in &current.assigned_to_relations {
        let relation_id = relation.relation_id.trim();
        let lifecycle = format!("ak:cell:ak.component.relation.lifecycle.v1:{relation_id}");
        let object = format!("ak:cell:ak.component.relation.v1:{relation_id}");
        let refs = match current_register_basis(&entries, &lifecycle) {
            CurrentRegisterBasis::Source(refs) => refs,
            CurrentRegisterBasis::ConfirmedEmpty | CurrentRegisterBasis::Removed => Vec::new(),
            CurrentRegisterBasis::Missing
                if !matches!(
                    current_register_basis(&entries, &object),
                    CurrentRegisterBasis::Missing | CurrentRegisterBasis::Unavailable
                ) =>
            {
                Vec::new()
            }
            CurrentRegisterBasis::Missing => {
                return Err(format!(
                    "assignment relation {} is still loading",
                    short_protocol_id(relation_id)
                ));
            }
            CurrentRegisterBasis::Unavailable => {
                return Err(format!(
                    "assignment relation {} is unresolved",
                    short_protocol_id(relation_id)
                ));
            }
        };
        result.insert(relation_id.to_owned(), refs);
    }
    Ok(result)
}

pub(super) fn assignment_relations_after_mutations(
    current: &KanbanCard,
    selected_actor_ids: &BTreeSet<arkret_sdk::ActorId>,
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
        .filter(|relation| selected_actor_ids.contains(&relation.actor_id))
        .filter(|relation| !tombstoned.contains(relation.relation_id.trim()))
        .cloned()
        .collect::<Vec<_>>();
    for mutation in mutations {
        if let CardAssignmentMutation::Create {
            actor_id,
            operation,
        } = mutation
            && selected_actor_ids.contains(actor_id)
        {
            // A pending create has no Relation id yet; the optimistic row is
            // keyed by the write's holder-local operation id until the accepted
            // Event names the Relation.
            relations.push(CardAssignedToRelation {
                relation_id: operation.local_operation_id().to_string(),
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
    selected_actor_ids: BTreeSet<arkret_sdk::ActorId>,
    mut selected_card: Signal<Option<KanbanCard>>,
    mut state_store: SyncSignal<LocalStateStore>,
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

    let lifecycle_bases = match assignment_lifecycle_bases(&state_store.read(), &realm_id, &current)
    {
        Ok(bases) => bases,
        Err(msg) => {
            assignee_edit_status.set(msg.clone());
            board_status.set(msg);
            return false;
        }
    };
    let mutations = match card_assignment_mutations(
        &realm_id,
        &actor_id,
        &current,
        &selected_actor_ids,
        &lifecycle_bases,
    ) {
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
    // The board re-renders from the appended `ak.relation.*` ops below —
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
        let operation_id = operation.local_operation_id().to_string();
        let body = match queued_assignment_body(mutation) {
            Ok(body) => body,
            Err(err) => {
                let msg = format!("cannot queue assignee operation: {err:#}");
                assignee_edit_status.set(msg.clone());
                board_status.set(msg);
                return false;
            }
        };
        let record = match serde_json::to_value(QueuedAssignmentRecord {
            kind: operation.kind().clone(),
            operation_id: &operation_id,
            actor_id: operation.actor_id().clone(),
            created_at: arkret_sdk::canonical::format_timestamp_canonical(operation.created_at()),
            write_state: "queued",
            body,
            assignment_strand_id: &current.id,
            assignment_actor_id: mutation.actor_id(),
            assignment_relation_id: mutation
                .relation_id()
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| operation.local_operation_id().to_string()),
        }) {
            Ok(record) => record,
            Err(err) => {
                let msg = format!("cannot queue assignee operation: {err}");
                assignee_edit_status.set(msg.clone());
                board_status.set(msg);
                return false;
            }
        };
        state_store.write().enqueue_local_projection_command(
            operation_id.clone(),
            Some(realm_id.clone()),
            record,
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
            let operation_id = operation.local_operation_id().to_string();
            let kind = operation.kind().as_str().to_owned();
            match with_authed_api(&base_url, api_token.clone(), |api| async move {
                api.event_submitter()?.submit_sdk_event(&operation).await
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
