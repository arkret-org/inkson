use super::*;
use crate::state::projection_views::{RsvpCellProjectionView, RsvpHeadProjectionView};

const TEST_CALENDAR_STRAND_ID: &str = "ak:strand:0196419b-0000-7000-8000-000000000901";

#[test]
fn calendar_patch_writes_one_activation_pair_and_clears_the_legacy_shape() {
    let current = test_card(TEST_CALENDAR_STRAND_ID, "U");
    let mut draft = card_detail_draft_from_card(&current);
    draft.calendar = CalendarCardFields {
        start: "2026-06-20T09:00:00".to_owned(),
        end: "2026-06-20T10:00:00".to_owned(),
        timezone: "Asia/Shanghai".to_owned(),
        recurrence_frequency: "weekly".to_owned(),
        recurrence_interval: "1".to_owned(),
        recurrence_by_day: "MO, WE".to_owned(),
        location: "Board room".to_owned(),
        ..CalendarCardFields::default()
    };

    let patch = card_detail_update_patch(&current, &draft).unwrap();

    // Activation is exactly one pair: the schema ref plus the whole subtree.
    assert_eq!(
        patch["schema_refs"]["value"],
        json!([arkret_sdk::schema::CALENDAR_EVENT_SCHEMA])
    );
    let calendar = &patch["metadata.fields.calendar"]["value"];
    assert_eq!(calendar["start"], "2026-06-20T09:00:00");
    assert_eq!(calendar["end"], "2026-06-20T10:00:00");
    assert_eq!(calendar["timezone"], "Asia/Shanghai");
    assert_eq!(calendar["tzdb_version"], DEFAULT_CALENDAR_TZDB_VERSION);
    assert_eq!(calendar["status"], "confirmed");
    assert_eq!(
        calendar["recurrence"],
        json!({
            "frequency": "weekly",
            "interval": 1,
            "by_day": [{"day": "mo"}, {"day": "we"}]
        })
    );
    // `location` is the one schedule member that may be encrypted, so it is
    // written on its own child path where the private-value pipeline can reach
    // it; the child sorts after its parent object.
    assert!(calendar.get("location").is_none());
    assert_eq!(
        patch[CALENDAR_LOCATION_PRIVATE_PATH]["value"],
        json!({ "title": "Board room" })
    );

    // The pre-closure shape is cleared in the same patch, so no object ever
    // carries two schedules or a profile-id activation impostor.
    for path in [
        "metadata.fields.profile",
        "metadata.fields.profile_refs",
        "metadata.fields.start",
        "metadata.fields.end",
        "metadata.fields.timezone",
        "metadata.fields.all_day",
        "metadata.fields.recurrence",
        "metadata.fields.location",
    ] {
        assert_eq!(patch[path]["$op"], "unset", "{path} must be cleared");
    }

    let private_values = collect_encryptable_private_patch_values(&patch).unwrap();
    assert_eq!(private_values.len(), 1);
    assert_eq!(private_values[0].0, CALENDAR_LOCATION_PRIVATE_PATH);
}

#[test]
fn clearing_the_schedule_unsets_the_ref_and_the_subtree_together() {
    let mut current = test_card(TEST_CALENDAR_STRAND_ID, "U");
    current.calendar = CalendarCardFields {
        start: "2026-06-20T09:00:00".to_owned(),
        end: "2026-06-20T10:00:00".to_owned(),
        timezone: "Asia/Shanghai".to_owned(),
        ..CalendarCardFields::default()
    };
    let mut draft = card_detail_draft_from_card(&current);
    draft.calendar = CalendarCardFields::default();

    let patch = card_detail_update_patch(&current, &draft).unwrap();

    // A lone ref or a lone subtree is calendar_activation_mismatch, so both
    // sides have to go in the same patch.
    assert_eq!(patch["schema_refs"]["$op"], "unset");
    assert_eq!(patch["metadata.fields.calendar"]["$op"], "unset");
}

#[test]
fn calendar_rsvp_operation_carries_the_complete_entry_and_effect() {
    let basis = arkret_sdk::Hash::new(
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .unwrap();
    let calendar = arkret_sdk::CalendarEventFields {
        start: "2026-06-20T09:00:00".to_owned(),
        end: "2026-06-20T10:00:00".to_owned(),
        timezone: "Asia/Shanghai".to_owned(),
        tzdb_version: "2025a".to_owned(),
        all_day: false,
        status: arkret_sdk::CalendarStatus::Confirmed,
        recurrence: Some(arkret_sdk::CalendarRecurrence {
            frequency: arkret_sdk::RecurrenceFrequency::Weekly,
            interval: None,
            by_day: Vec::new(),
            by_month: None,
            by_month_day: None,
            by_set_position: None,
            first_day_of_week: None,
            count: Some(10),
            until: None,
        }),
        location: None,
        call_id: None,
        attendees: Vec::new(),
    };

    let event = calendar_rsvp_operation(
        TEST_REALM_ID,
        "did:web:auth.local.host:users:alice",
        TEST_CALENDAR_STRAND_ID,
        "accepted",
        "2026-06-20T09:00:00[Asia/Shanghai]",
        vec![basis.clone()],
        &calendar,
    )
    .unwrap();

    assert_eq!(event.kind.as_str(), "ak.rsvp.set");
    assert_eq!(
        sdk_event_local_target_ref(&event),
        Some(TEST_CALENDAR_STRAND_ID)
    );
    assert_eq!(event.payload["event_ref"], TEST_CALENDAR_STRAND_ID);
    assert_eq!(
        event.payload["occurrence"],
        "2026-06-20T09:00:00[Asia/Shanghai]"
    );
    // The response lives inside the complete entry together with the basis.
    assert_eq!(event.payload["entry"]["response"]["status"], "accepted");
    assert_eq!(
        event.payload["entry"]["schedule_basis_refs"],
        json!([basis.as_str()])
    );
    // The basis must be causally carried, otherwise a receiver rejects it.
    assert_eq!(
        event
            .causal_refs
            .iter()
            .map(arkret_sdk::Hash::as_str)
            .collect::<Vec<_>>(),
        vec![basis.as_str()]
    );
    // The builder derives the registered cell effect; the pre-closure client
    // sent none at all, so the Event never reached its CBA cell.
    assert_eq!(event.effects.len(), 1);
    assert!(
        event.effects[0]
            .cell
            .as_str()
            .starts_with("ak:cell:ak.component.calendar.rsvp.v1:")
    );
    assert_eq!(
        event.effects[0].op.value.as_ref().unwrap(),
        &event.payload["entry"]
    );
    assert_registered_payload_valid(&event);
}

#[test]
fn calendar_rsvp_without_an_observed_schedule_fails_closed() {
    let calendar = arkret_sdk::CalendarEventFields {
        start: "2026-06-20T09:00:00".to_owned(),
        end: "2026-06-20T10:00:00".to_owned(),
        timezone: "Asia/Shanghai".to_owned(),
        tzdb_version: "2025a".to_owned(),
        all_day: false,
        status: arkret_sdk::CalendarStatus::Confirmed,
        recurrence: None,
        location: None,
        call_id: None,
        attendees: Vec::new(),
    };
    // No frontier means we cannot claim to have observed the schedule, so
    // authoring refuses instead of signing an unbacked basis.
    assert!(
        calendar_rsvp_operation(
            TEST_REALM_ID,
            "did:web:auth.local.host:users:alice",
            TEST_CALENDAR_STRAND_ID,
            "accepted",
            "",
            Vec::new(),
            &calendar,
        )
        .is_err()
    );
}

#[test]
fn calendar_projection_reads_schedule_and_plain_location() {
    // The schedule lives under one `calendar` namespace; `profile` /
    // `profile_refs` and flat schedule keys are rejected activation impostors.
    let fields = Map::from_iter([(
        "calendar".to_owned(),
        json!({
            "start": "2026-06-20T09:00:00",
            "end": "2026-06-20T10:00:00",
            "timezone": "Asia/Shanghai",
            "tzdb_version": "2025a",
            "all_day": false,
            "status": "confirmed",
            "recurrence": {
                "frequency": "weekly",
                "interval": 1,
                "by_day": [{"day": "mo"}, {"day": "we"}]
            },
            "location": { "title": "Board room" }
        }),
    )]);
    let strand = crate::state::projection_views::StrandProjectionView {
        strand_id: TEST_CALENDAR_STRAND_ID.to_owned(),
        realm_id: TEST_REALM_ID.to_owned(),
        title: "Planning session".to_owned(),
        summary: Some("Release planning".to_owned()),
        body: None,
        board_space_id: None,
        list_space_id: None,
        rank: Some("U".to_owned()),
        assigned_actor_ids: Vec::new(),
        assigned_to_relations: Vec::new(),
        fields,
        schema_refs: vec![arkret_sdk::schema::CALENDAR_EVENT_SCHEMA.to_owned()],
        rsvps: Vec::new(),
        schedule_revision_heads: vec![
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        ],
        state: "active".to_owned(),
        created_by: None,
        created_at: None,
        updated_by: None,
        updated_at: None,
    };

    let card = card_from_strand_projection(&strand, None);

    assert_eq!(card.calendar.start, "2026-06-20T09:00:00");
    assert_eq!(card.calendar.end, "2026-06-20T10:00:00");
    assert_eq!(card.calendar.tzdb_version, "2025a");
    assert_eq!(card.calendar.status, "confirmed");
    assert_eq!(card.calendar.timezone, "Asia/Shanghai");
    assert_eq!(card.calendar.recurrence_frequency, "weekly");
    assert_eq!(card.calendar.recurrence_interval, "1");
    assert_eq!(card.calendar.recurrence_by_day, "MO, WE");
    assert_eq!(card.calendar.location, "Board room");
    assert!(!card.calendar.location_locked);
    // The frontier reaches the card, which is what lets RSVP authoring sign a
    // basis it can actually back.
    assert_eq!(card.calendar_schedule_basis_refs().len(), 1);
}

#[test]
fn card_without_a_projected_frontier_cannot_author_an_rsvp() {
    let card = test_card(TEST_CALENDAR_STRAND_ID, "U");
    assert!(card.calendar_schedule_basis_refs().is_empty());
}

#[test]
fn calendar_overlay_replaces_the_whole_schedule_subtree() {
    let mut card = test_card(TEST_CALENDAR_STRAND_ID, "U");
    card.calendar = CalendarCardFields {
        start: "2026-06-20T09:00:00".to_owned(),
        end: "2026-06-20T10:00:00".to_owned(),
        timezone: "Asia/Shanghai".to_owned(),
        recurrence_frequency: "weekly".to_owned(),
        recurrence_interval: "1".to_owned(),
        recurrence_by_day: "MO, WE".to_owned(),
        location: "Board room".to_owned(),
        ..CalendarCardFields::default()
    };
    let columns = vec![KanbanColumn {
        id: "ak:space:list-a".to_owned(),
        title: "A".to_owned(),
        rank: "U".to_owned(),
        cards: vec![card],
        state: SpaceContainerLifecycleState::Active,
    }];
    let queued = RawOperationRecord {
        operation_id: "op-calendar-start".to_owned(),
        realm_id: Some(TEST_REALM_ID.to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ak.strand.update",
            "operation_id": "op-calendar-start",
            "write_state": "queued",
            "body": {
                "strand_id": TEST_CALENDAR_STRAND_ID,
                "patch": {
                    "metadata.fields.calendar": {
                        "$op": "set",
                        "value": {
                            "start": "2026-06-20T11:00:00",
                            "end": "2026-06-20T12:00:00",
                            "timezone": "Asia/Shanghai",
                            "tzdb_version": "2025a",
                            "all_day": false,
                            "status": "confirmed",
                            "recurrence": {
                                "frequency": "weekly",
                                "interval": 1,
                                "by_day": [{"day": "mo"}, {"day": "we"}]
                            },
                            "location": { "title": "Board room" }
                        }
                    }
                }
            }
        }),
    };

    let overlaid = overlay_local_card_update_records(columns, &[queued], None);
    let calendar = &overlaid[0].cards[0].calendar;

    // The schedule is one signed object, so a queued patch replaces it whole
    // rather than merging field by field.
    assert_eq!(calendar.start, "2026-06-20T11:00:00");
    assert_eq!(calendar.end, "2026-06-20T12:00:00");
    assert_eq!(calendar.timezone, "Asia/Shanghai");
    assert_eq!(calendar.recurrence_frequency, "weekly");
    assert_eq!(calendar.recurrence_by_day, "MO, WE");
    assert_eq!(calendar.location, "Board room");
}

fn rsvp_head(digest_byte: u8, basis: &str, status: &str) -> RsvpHeadProjectionView {
    RsvpHeadProjectionView {
        source_event_id: format!("ak:event:01904100-0000-7000-8000-0000000000{digest_byte:02x}"),
        source_event_digest: format!("sha256:{}", format!("{digest_byte:02x}").repeat(32)),
        entry: json!({
            "schedule_basis_refs": [basis],
            "response": {"status": status}
        }),
    }
}

const FRONTIER: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn rsvp_display_shows_own_answer_and_aggregate() {
    let cells = vec![
        RsvpCellProjectionView {
            occurrence: None,
            actor_id: "did:web:alice.example".to_owned(),
            heads: vec![rsvp_head(1, FRONTIER, "accepted")],
        },
        RsvpCellProjectionView {
            occurrence: None,
            actor_id: "did:web:bob.example".to_owned(),
            heads: vec![rsvp_head(2, FRONTIER, "declined")],
        },
    ];

    let display = calendar_rsvp_display(
        &cells,
        &[FRONTIER.to_owned()],
        None,
        "did:web:alice.example",
    );
    assert_eq!(display.own_status.as_deref(), Some("accepted"));
    assert!(!display.own_conflicted);
    assert_eq!(display.accepted, 1);
    assert_eq!(display.declined, 1);
    assert_eq!(display.excluded, 0);
}

#[test]
fn rsvp_display_surfaces_a_conflict_instead_of_choosing_a_side() {
    // Two concurrent answers from the same responder. Only they can resolve
    // it, so the card must not display one of them as the answer.
    let cells = vec![RsvpCellProjectionView {
        occurrence: None,
        actor_id: "did:web:alice.example".to_owned(),
        heads: vec![
            rsvp_head(1, FRONTIER, "accepted"),
            rsvp_head(2, FRONTIER, "declined"),
        ],
    }];

    let display = calendar_rsvp_display(
        &cells,
        &[FRONTIER.to_owned()],
        None,
        "did:web:alice.example",
    );
    assert!(display.own_conflicted);
    assert!(display.own_status.is_none());
    // A conflicted responder contributes to no aggregate bucket.
    assert_eq!(display.accepted + display.declined + display.tentative, 0);
}

#[test]
fn rsvp_display_excludes_heads_resting_on_an_unknown_schedule() {
    let stale = "sha256:9999999999999999999999999999999999999999999999999999999999999999";
    let cells = vec![RsvpCellProjectionView {
        occurrence: None,
        actor_id: "did:web:alice.example".to_owned(),
        heads: vec![rsvp_head(1, stale, "accepted")],
    }];

    let display = calendar_rsvp_display(
        &cells,
        &[FRONTIER.to_owned()],
        None,
        "did:web:alice.example",
    );
    assert!(display.own_status.is_none());
    assert_eq!(display.excluded, 1);
    assert_eq!(display.accepted, 0);
}

#[test]
fn rsvp_display_prefers_the_instance_answer_over_the_series_fallback() {
    let occurrence = "2026-06-20T09:00:00[Asia/Shanghai]";
    let cells = vec![
        RsvpCellProjectionView {
            occurrence: None,
            actor_id: "did:web:alice.example".to_owned(),
            heads: vec![rsvp_head(1, FRONTIER, "accepted")],
        },
        RsvpCellProjectionView {
            occurrence: Some(occurrence.to_owned()),
            actor_id: "did:web:alice.example".to_owned(),
            heads: vec![rsvp_head(2, FRONTIER, "declined")],
        },
    ];

    let display = calendar_rsvp_display(
        &cells,
        &[FRONTIER.to_owned()],
        Some(occurrence),
        "did:web:alice.example",
    );
    // Instance overrides series; the two tiers are never unioned into a
    // conflict.
    assert_eq!(display.own_status.as_deref(), Some("declined"));
    assert!(!display.own_conflicted);
}
