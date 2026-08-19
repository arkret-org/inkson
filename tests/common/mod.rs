//! Authoring inputs an integration test has to supply for itself.
//!
//! A write finishes at one boundary: the actor chain position and the signing
//! stamp go in, one `event_id` comes out. Production reads both from the accepted
//! realm actor frontier and the durable stamp allocator; a test has neither, so it
//! pins them and authors through the same public API a real submitter uses.
//!
//! Deliberately built only from `inkson`'s public surface: the crate's own
//! `cfg(test)` helpers are unreachable here, and a test-only escape hatch in the
//! library would be reachable from production.

#![allow(dead_code)]

use inkson::operation::LocalOperation;

/// The pinned signing stamp for position `actor_seq`.
pub fn pinned_hlc(actor_seq: u64) -> arkret_sdk::Hlc {
    arkret_sdk::Hlc::new(format!("01970e589d21-{actor_seq:04}-a13f9c2e"))
        .expect("a pinned test HLC parses")
}

/// Finalize `operation` at the first position of its actor chain.
pub fn author(operation: LocalOperation) -> arkret_sdk::AuthoredEvent {
    author_at_seq(operation, 1)
}

/// Finalize `operation` at an explicit position of its actor chain.
pub fn author_at_seq(operation: LocalOperation, actor_seq: u64) -> arkret_sdk::AuthoredEvent {
    operation
        .into_intent()
        .author(actor_seq, pinned_hlc(actor_seq))
        .expect("a built write finalizes")
}

/// One stage of an authoring unit, as `event_builders` hands it over.
pub type UnitStep = Box<
    dyn FnOnce(&[arkret_sdk::AuthoredEvent]) -> anyhow::Result<Vec<inkson::operation::EventIntent>>
        + Send,
>;

/// Run an authoring unit with a pinned actor chain.
///
/// Keeps the ordering contract the real submitter keeps: stage `n` sees the final
/// identities of everything the stages before it authored, which is what lets a
/// later member name an earlier one. A genesis unit opens its own chain at 0.
pub fn author_unit(steps: Vec<UnitStep>) -> Vec<arkret_sdk::AuthoredEvent> {
    let mut authored: Vec<arkret_sdk::AuthoredEvent> = Vec::new();
    for step in steps {
        for intent in step(&authored).expect("a unit stage builds its intents") {
            let actor_seq = authored.len() as u64;
            let prev_refs = authored
                .last()
                .map(|event| vec![event.event_id().clone()])
                .unwrap_or_default();
            authored.push(author_intent_at_seq(
                intent.with_prev_refs(prev_refs),
                actor_seq,
            ));
        }
    }
    authored
}

/// Finalize a bare intent at an explicit position of its actor chain.
pub fn author_intent_at_seq(
    intent: inkson::operation::EventIntent,
    actor_seq: u64,
) -> arkret_sdk::AuthoredEvent {
    intent
        .author(actor_seq, pinned_hlc(actor_seq))
        .expect("an intent finalizes")
}
