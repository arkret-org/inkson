use super::*;

#[test]
fn board_write_manual_review_is_only_for_conflicts() {
    let transient_failure = board_write_record(
        CardState::Quarantined,
        "submit failed: projection still pending",
    );
    assert!(
        !transient_failure.needs_manual_conflict_review(),
        "ordinary submit failures should not show the board admin review banner"
    );

    let exhausted_conflict = board_write_record(
        CardState::Quarantined,
        "cas_conflict exhausted 3 rebase attempts",
    );
    assert!(exhausted_conflict.needs_manual_conflict_review());

    let active_conflict = board_write_record(CardState::Conflict, "server returned cas_conflict");
    assert!(active_conflict.needs_manual_conflict_review());
}

/// `try_load_api_columns` is the synchronous-init probe. Real API
/// fetching now lives in the async refresh handler that calls
/// `CokretApi::collection_projection`. This test still pins the
/// init-time behaviour as None so UI startup stays empty unless explicit
/// demo seed is enabled; async projection hydrate promotes to ApiDerived
/// once the HTTP call returns.
#[test]
fn try_load_api_columns_returns_none_in_sync_init_context() {
    let result = try_load_api_columns("");
    assert!(
        result.is_none(),
        "synchronous init MUST return None; async refresh handles real fetch"
    );
}

/// Wire state strings emitted by soland's
/// `/_cokret/self/realms/{realm_id}/{spaces|strands}` round-trip into the
/// renderer enums. Unknown values stay at the safe `Active` default.
#[test]
fn lifecycle_wire_strings_decode_to_enums() {
    assert_eq!(
        space_container_state_from_wire("active"),
        SpaceContainerLifecycleState::Active
    );
    assert_eq!(
        space_container_state_from_wire("archived"),
        SpaceContainerLifecycleState::Archived
    );
    assert_eq!(
        space_container_state_from_wire("tombstoned"),
        SpaceContainerLifecycleState::Tombstoned
    );
    assert_eq!(
        space_container_state_from_wire("garbage"),
        SpaceContainerLifecycleState::Active
    );

    assert_eq!(
        strand_lifecycle_from_wire("active"),
        StrandLifecycleState::Active
    );
    assert_eq!(
        strand_lifecycle_from_wire("archived"),
        StrandLifecycleState::Archived
    );
    // R11: `redacted` is the only spec terminal (strand.schema.json).
    assert_eq!(
        strand_lifecycle_from_wire("redacted"),
        StrandLifecycleState::Redacted
    );
    // `deleted` is NOT in the spec enum; it degrades to the safe
    // non-terminal `Active` default (and logs a warning) rather than
    // being treated as a terminal.
    assert_eq!(
        strand_lifecycle_from_wire("deleted"),
        StrandLifecycleState::Active
    );
    assert_eq!(
        strand_lifecycle_from_wire("garbage"),
        StrandLifecycleState::Active
    );
}

/// Space-container lifecycle state defaults to Active per the spec wire
/// default; seed columns and projection-mapped columns MUST start
/// active so they appear in the main board grid.
#[test]
fn space_container_lifecycle_state_default_is_active() {
    assert_eq!(
        SpaceContainerLifecycleState::default(),
        SpaceContainerLifecycleState::Active
    );
    // Every seeded column starts Active.
    for column in seed_columns() {
        assert_eq!(
            column.state,
            SpaceContainerLifecycleState::Active,
            "seed column {} must start Active",
            column.id
        );
    }
}

/// Space-container lifecycle validator rejects (a) same-state self-transition
/// and (b) UI-emitted Tombstone target. The legal transitions
/// (Active → Archived and Archived → Active) MUST be accepted so
/// archive / restore continue to work end-to-end.
#[test]
fn validate_space_container_lifecycle_transition_rules() {
    // Same-state refusal — Active → Active.
    let err = validate_space_container_lifecycle_transition(
        "ck:space:test",
        SpaceContainerLifecycleState::Active,
        SpaceContainerLifecycleState::Active,
    )
    .expect_err("same-state Active→Active must be refused");
    assert!(err.contains("already in"));
    assert!(err.contains("ck:space:test"));

    // Same-state refusal — Archived → Archived.
    validate_space_container_lifecycle_transition(
        "ck:space:test",
        SpaceContainerLifecycleState::Archived,
        SpaceContainerLifecycleState::Archived,
    )
    .expect_err("same-state Archived→Archived must be refused");

    // Tombstone target refusal — UI never emits Tombstone.
    let err = validate_space_container_lifecycle_transition(
        "ck:space:test",
        SpaceContainerLifecycleState::Active,
        SpaceContainerLifecycleState::Tombstoned,
    )
    .expect_err("UI-emitted Tombstone must be refused");
    assert!(err.contains("Tombstone"));

    // Legal transitions stay green.
    validate_space_container_lifecycle_transition(
        "ck:space:test",
        SpaceContainerLifecycleState::Active,
        SpaceContainerLifecycleState::Archived,
    )
    .expect("Active→Archived is a legal transition");
    validate_space_container_lifecycle_transition(
        "ck:space:test",
        SpaceContainerLifecycleState::Archived,
        SpaceContainerLifecycleState::Active,
    )
    .expect("Archived→Active is a legal transition");
}

/// Symmetric to `validate_space_container_lifecycle_transition_rules` at the
/// Strand layer. Same two refusal cases, same two legal transitions.
#[test]
fn validate_strand_lifecycle_transition_rules() {
    let err = validate_strand_lifecycle_transition(
        "ck:strand:test",
        StrandLifecycleState::Active,
        StrandLifecycleState::Active,
    )
    .expect_err("same-state Active→Active must be refused");
    assert!(err.contains("already in"));
    assert!(err.contains("ck:strand:test"));

    validate_strand_lifecycle_transition(
        "ck:strand:test",
        StrandLifecycleState::Archived,
        StrandLifecycleState::Archived,
    )
    .expect_err("same-state Archived→Archived must be refused");

    let err = validate_strand_lifecycle_transition(
        "ck:strand:test",
        StrandLifecycleState::Active,
        StrandLifecycleState::Redacted,
    )
    .expect_err("UI-emitted Redaction must be refused");
    assert!(err.contains("Redaction"));

    validate_strand_lifecycle_transition(
        "ck:strand:test",
        StrandLifecycleState::Active,
        StrandLifecycleState::Archived,
    )
    .expect("Active→Archived is a legal transition");
    validate_strand_lifecycle_transition(
        "ck:strand:test",
        StrandLifecycleState::Archived,
        StrandLifecycleState::Active,
    )
    .expect("Archived→Active is a legal transition");
}

/// Symmetric to `space_container_lifecycle_state_default_is_active` —
/// StrandLifecycleState MUST default to Active and every seeded card
/// MUST start Active so the demo board exercises the happy path.
#[test]
fn strand_lifecycle_state_default_is_active() {
    assert_eq!(
        StrandLifecycleState::default(),
        StrandLifecycleState::Active
    );
    for column in seed_columns() {
        for card in &column.cards {
            assert_eq!(
                card.lifecycle,
                StrandLifecycleState::Active,
                "seed card {} in column {} must start Active",
                card.id,
                column.id
            );
        }
    }
}
