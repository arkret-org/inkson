//! Authoring inputs an integration test has to supply for itself.
//!
//! A write finishes at one boundary: a frozen producer timestamp goes in and
//! one `event_id` comes out. Stream position belongs to the Station-authored
//! RealmCommit and is never an input to producer Event authoring.
//!
//! Deliberately built only from `inkson`'s public surface: the crate's own
//! `cfg(test)` helpers are unreachable here, and a test-only escape hatch in the
//! library would be reachable from production.

#![allow(dead_code)]

use inkson::operation::LocalOperation;

/// The `did:key` multibase of a Principal Control Realm's inception root key.
///
/// Mirrors `event_builders::test_inception_root_key_multibase`: these tests
/// are built only from `inkson`'s public surface, so the fixture is duplicated
/// rather than reached through a `cfg(test)` helper.
pub fn test_inception_root_key_multibase(principal_did: &str) -> String {
    arkret_sdk::ed25519_pubkey_to_did_key_multibase(
        arkret_signatures::development_verifying_key(&format!("{principal_did}#inception-root"))
            .as_bytes(),
    )
}

/// A distinct, canonical timestamp for each Event in a test unit.
pub fn pinned_created_at(nth: u64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-09-19T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc)
        + chrono::Duration::milliseconds(i64::try_from(nth).unwrap())
}

/// Finalize `operation` at the first position of its actor chain.
pub fn author(operation: LocalOperation) -> arkret_sdk::AuthoredEvent {
    author_at_seq(operation, 1)
}

/// Finalize `operation` at an explicit position of its actor chain.
pub fn author_at_seq(operation: LocalOperation, actor_seq: u64) -> arkret_sdk::AuthoredEvent {
    operation
        .into_intent()
        .with_created_at(pinned_created_at(actor_seq))
        .author_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
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
            authored.push(author_intent_at_seq(intent, actor_seq));
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
        .with_created_at(pinned_created_at(actor_seq))
        .author_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
        .expect("an intent finalizes")
}
