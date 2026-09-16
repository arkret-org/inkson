//! The accepted MLS transition a device installs, and the checks that make it
//! safe to install.
//!
//! An MLS transition becomes installable exactly when the governance Station
//! has committed its Event into the scope's own independent commit stream. The
//! client never asks a separate endpoint whether a transition was accepted: a
//! locally authored Commit pairs its Event with the `RealmCommit` the submit
//! returned, and a remote transition arrives as a `StreamItem` on the scope's
//! stream. Both shapes are the same `arkret_wire::StreamItem`, so this module
//! takes that and nothing else.

use arkret_wire::{CommittedEventRef, StreamItem};

/// One accepted `ak.mls.genesis` / `ak.mls.commit` with the exact commit
/// coordinate that ordered it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AcceptedMlsTransition {
    pub(crate) item: StreamItem,
    pub(crate) effective_scope: arkret_sdk::ScopeRef,
    pub(crate) mls_group_id: String,
    pub(crate) previous_epoch: u64,
    pub(crate) next_epoch: u64,
}

impl AcceptedMlsTransition {
    /// The Event this transition materialized.
    pub(crate) fn event(&self) -> &arkret_sdk::Event {
        &self.item.event
    }

    /// The exact committed coordinate an install queues against.
    pub(crate) fn accepted_ref(&self) -> CommittedEventRef {
        CommittedEventRef {
            event_id: self.item.event.event_id.clone(),
            commit_id: self.item.commit.commit_id.clone(),
            stream_ref: self.item.commit.stream_ref.clone(),
            stream_position: self.item.commit.stream_position,
        }
    }
}

/// Read one accepted stream item as an MLS transition.
///
/// Every cross-check the installer depends on happens here: the commit must
/// bind this exact Event in this exact scope stream, the payload's governance
/// binding must name the same scope, and the group id must be the one derived
/// from that scope. A transition that fails any of them is refused rather than
/// installed under a scope it does not belong to.
pub(crate) fn accepted_mls_transition(item: &StreamItem) -> Result<AcceptedMlsTransition, String> {
    item.validate_shape()
        .map_err(|error| format!("accepted MLS transition is malformed: {error}"))?;
    let binding = match item.event.kind {
        arkret_sdk::EventKind::MlsGenesis => {
            let payload: arkret_sdk::MlsGenesisPayload = event_payload(&item.event)?;
            payload
                .validate()
                .map_err(|error| format!("invalid accepted MLS Genesis: {error}"))?;
            payload.governance_binding
        }
        arkret_sdk::EventKind::MlsCommit => {
            let payload: arkret_sdk::MlsCommitPayload = event_payload(&item.event)?;
            payload
                .validate()
                .map_err(|error| format!("invalid accepted MLS Commit: {error}"))?;
            payload.governance_binding().clone()
        }
        other => {
            return Err(format!(
                "accepted MLS transition must be a genesis or commit Event, not {}",
                other.as_str()
            ));
        }
    };
    if binding.effective_scope() != &item.event.scope_ref {
        return Err(
            "accepted MLS governance binding names another scope than its Event".to_owned(),
        );
    }
    let mls_group_id = binding
        .mls_group_id()
        .map_err(|error| format!("accepted MLS transition has no group id: {error}"))?;
    Ok(AcceptedMlsTransition {
        item: item.clone(),
        effective_scope: binding.effective_scope().clone(),
        mls_group_id,
        previous_epoch: binding.previous_epoch(),
        next_epoch: binding.next_epoch(),
    })
}

/// Pair a locally authored MLS Event with the `RealmCommit` its submission
/// returned, which is the same accepted shape the scan path delivers.
pub(crate) fn accepted_from_submission(
    event: arkret_sdk::Event,
    commit: arkret_wire::RealmCommit,
) -> Result<AcceptedMlsTransition, String> {
    accepted_mls_transition(&StreamItem { commit, event })
}

fn event_payload<T: serde::de::DeserializeOwned>(
    event: &arkret_sdk::Event,
) -> Result<T, String> {
    let payload = serde_json::Value::Object(event.payload.clone().into_iter().collect());
    serde_json::from_value(payload)
        .map_err(|error| format!("accepted MLS payload is unreadable: {error}"))
}
