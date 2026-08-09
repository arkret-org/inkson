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
/// `TransportClient::collection_projection`. This test still pins the
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

/// SDK projection lifecycle values map exhaustively into renderer enums.
#[test]
fn projection_lifecycle_values_map_to_renderer_enums() {
    assert_eq!(
        space_container_state_from_projection(&arkret_sdk::ProjectionSpaceState::Active),
        SpaceContainerLifecycleState::Active
    );
    assert_eq!(
        space_container_state_from_projection(&arkret_sdk::ProjectionSpaceState::Archived),
        SpaceContainerLifecycleState::Archived
    );
    assert_eq!(
        space_container_state_from_projection(&arkret_sdk::ProjectionSpaceState::Tombstoned),
        SpaceContainerLifecycleState::Tombstoned
    );

    assert_eq!(
        strand_lifecycle_from_projection(&arkret_sdk::ProjectionObjectState::Active),
        StrandLifecycleState::Active
    );
    assert_eq!(
        strand_lifecycle_from_projection(&arkret_sdk::ProjectionObjectState::Archived),
        StrandLifecycleState::Archived
    );
    assert_eq!(
        strand_lifecycle_from_projection(&arkret_sdk::ProjectionObjectState::Redacted),
        StrandLifecycleState::Redacted
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
