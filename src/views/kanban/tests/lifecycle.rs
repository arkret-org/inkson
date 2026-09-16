use super::*;

/// SDK projection lifecycle values map exhaustively into renderer enums.
#[test]
fn projection_lifecycle_values_map_to_renderer_enums() {
    assert_eq!(
        space_container_state_from_projection(&arkret_sdk::SpaceState::Active),
        SpaceContainerLifecycleState::Active
    );
    assert_eq!(
        space_container_state_from_projection(&arkret_sdk::SpaceState::Archived),
        SpaceContainerLifecycleState::Archived
    );
    assert_eq!(
        space_container_state_from_projection(&arkret_sdk::SpaceState::Tombstoned),
        SpaceContainerLifecycleState::Tombstoned
    );

    assert_eq!(
        strand_lifecycle_from_projection(&arkret_sdk::ObjectState::Active),
        StrandLifecycleState::Active
    );
    assert_eq!(
        strand_lifecycle_from_projection(&arkret_sdk::ObjectState::Archived),
        StrandLifecycleState::Archived
    );
    assert_eq!(
        strand_lifecycle_from_projection(&arkret_sdk::ObjectState::Redacted),
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
