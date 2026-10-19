// Re-export the parent (`chat/mod.rs`) glob into this module AND down to the
// sub-files. `super` here is `chat/mod.rs`; `pub(crate) use super::*;` pulls in
// every name it brought via `use ...;` (Value, json!, MentionNode, WatchLevel,
// ClientLocalState, arkret_sdk, crate::* …) and re-exports them so each
// sub-file's own `use super::*;` (where their `super` is this module) resolves
// the same set of names. Rust does not propagate glob-imported names through a
// glob, so this explicit re-export is what keeps the children compiling.
pub(crate) use super::*;

mod agents;
mod connectivity;
mod events;
mod mentions;
mod operations;
mod participants;
mod strands;
mod types;

// Re-export every sub-file's `pub(crate)` items so (a) sibling sub-files see
// each other through their `use super::*;`, and (b) `chat/mod.rs`'s
// `use model::*;` keeps resolving every name unchanged.
pub(crate) use agents::*;
pub(crate) use connectivity::*;
pub(crate) use events::*;
pub(crate) use mentions::*;
pub(crate) use operations::*;
pub(crate) use participants::*;
pub(crate) use strands::*;
pub(crate) use types::*;

#[cfg(test)]
mod tests;

/// Choose an automatic receipt only from a holder-visible retained message.
pub(crate) fn visible_read_receipt_event(
    messages: &[ChatMessage],
    realm: &str,
    strand: &str,
    blocked: &std::collections::BTreeSet<String>,
) -> Option<String> {
    messages
        .iter()
        .rev()
        .find(|message| {
            message.strand_id == strand
                && (realm.trim().is_empty() || message.realm_id == realm)
                && !message.id.is_empty()
                && !message.pending
                && !message.actor_id.as_ref().is_some_and(|actor| {
                    crate::account_data::message_actor_is_blocked(actor, blocked)
                })
        })
        .map(|message| message.id.clone())
}

/// The ordinary visible-cursor decision and optional encrypted receipt transport.
/// Local cursor advancement remains independent of receipt disclosure policy.
pub(crate) struct AutomaticReadReceiptPlan {
    pub event_id: String,
    pub material: Option<crate::signal::SignalKeyMaterial>,
    pub scope: Option<arkret_sdk::ScopeRef>,
}

pub(crate) fn automatic_read_receipt_plan(
    store: &crate::state::LocalStateStore,
    messages: &[ChatMessage],
    realm: &str,
    strand: &str,
    latest_cursor: &str,
) -> Option<AutomaticReadReceiptPlan> {
    let blocked = crate::account_data::blocked_message_actor_ids(&store.client_blocklist());
    let event_id = visible_read_receipt_event(messages, realm, strand, &blocked)?;
    let state = store.load();
    let target = state.verified_message_commits.iter().find(|target| {
        (target.accepted_ref.event_id.as_str() == event_id
            || arkret_sdk::MessageId::from_event_id(&target.accepted_ref.event_id).as_str()
                == event_id)
            && target.scope_ref.realm_id().as_str() == realm
            && target.strand_id.as_str() == strand
            && target.track_name == "discussion"
    });
    let scope = target.map(|target| target.scope_ref.clone());
    let event_id = target
        .map(|target| target.accepted_ref.event_id.to_string())
        .unwrap_or(event_id);
    if latest_cursor == event_id {
        return None;
    }
    let material = target.and_then(|target| {
        store
            .require_read_receipt_send(
                &target.scope_ref,
                &target.strand_id,
                &target.accepted_ref.event_id,
            )
            .ok()?;
        let circle = match &target.scope_ref {
            arkret_sdk::ScopeRef::Circle { circle_id, .. } => Some(circle_id.as_str()),
            _ => None,
        };
        crate::signal::key_material_for_scope(store, realm, circle).ok()
    });
    Some(AutomaticReadReceiptPlan {
        event_id,
        material,
        scope,
    })
}
