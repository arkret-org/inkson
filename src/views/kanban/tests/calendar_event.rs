use super::*;

const TEST_CALENDAR_STRAND_ID: &str = "ak:strand:0196419b-0000-7000-8000-000000000901";

#[test]
fn calendar_patch_sets_schedule_recurrence_profile_and_private_location_path() {
    let current = test_card(TEST_CALENDAR_STRAND_ID, "U");
    let mut draft = card_detail_draft_from_card(&current);
    draft.calendar = CalendarCardFields {
        start: "2026-06-20T09:00:00Z".to_owned(),
        end: "2026-06-20T10:00:00Z".to_owned(),
        timezone: "Asia/Shanghai".to_owned(),
        recurrence_frequency: "WEEKLY".to_owned(),
        recurrence_interval: "1".to_owned(),
        recurrence_by_day: "MO, WE".to_owned(),
        location: "Board room".to_owned(),
        ..CalendarCardFields::default()
    };

    let patch = card_detail_update_patch(&current, &draft).unwrap();

    assert_eq!(
        patch["metadata.fields.profile"]["value"],
        cokret_sdk::PROFILE_CALENDAR_EVENT
    );
    assert_eq!(
        patch["metadata.fields.profile_refs"]["value"][0],
        cokret_sdk::PROFILE_CALENDAR_EVENT
    );
    assert_eq!(
        patch["metadata.fields.start"]["value"],
        "2026-06-20T09:00:00Z"
    );
    assert_eq!(
        patch["metadata.fields.end"]["value"],
        "2026-06-20T10:00:00Z"
    );
    assert_eq!(patch["metadata.fields.timezone"]["value"], "Asia/Shanghai");
    assert_eq!(
        patch["metadata.fields.recurrence"]["value"],
        json!({
            "frequency": "WEEKLY",
            "interval": 1,
            "by_day": ["MO", "WE"]
        })
    );
    assert_eq!(
        patch["metadata.fields.location"]["value"],
        json!({ "title": "Board room" })
    );

    let private_values = collect_encryptable_private_patch_values(&patch).unwrap();
    assert_eq!(private_values.len(), 1);
    assert_eq!(private_values[0].0, CALENDAR_LOCATION_PRIVATE_PATH);
    assert_eq!(
        serde_json::from_slice::<Value>(&private_values[0].1).unwrap(),
        json!({ "title": "Board room" })
    );
}

#[test]
fn calendar_rsvp_operation_uses_occurrence_payload() {
    let event = calendar_rsvp_operation(
        TEST_REALM_ID,
        "did:web:auth.local.host:users:alice",
        TEST_CALENDAR_STRAND_ID,
        "accepted",
        "2026-06-20T09:00:00[Asia/Shanghai]",
    )
    .unwrap();

    assert_eq!(event.kind.as_str(), "ck.rsvp.set");
    assert_eq!(
        sdk_event_local_target_ref(&event),
        Some(TEST_CALENDAR_STRAND_ID)
    );
    assert_eq!(event.payload["event_ref"], TEST_CALENDAR_STRAND_ID);
    assert_eq!(event.payload["status"], "accepted");
    assert_eq!(
        event.payload["occurrence"],
        "2026-06-20T09:00:00[Asia/Shanghai]"
    );
    assert_registered_payload_valid(&event);
}

#[test]
fn calendar_projection_reads_schedule_and_plain_location() {
    let fields = Map::from_iter([
        (
            "profile".to_owned(),
            json!(cokret_sdk::PROFILE_CALENDAR_EVENT),
        ),
        (
            "profile_refs".to_owned(),
            json!([cokret_sdk::PROFILE_CALENDAR_EVENT]),
        ),
        ("start".to_owned(), json!("2026-06-20T09:00:00Z")),
        ("end".to_owned(), json!("2026-06-20T10:00:00Z")),
        ("timezone".to_owned(), json!("Asia/Shanghai")),
        ("all_day".to_owned(), json!(false)),
        (
            "recurrence".to_owned(),
            json!({
                "frequency": "WEEKLY",
                "interval": 1,
                "by_day": ["MO", "WE"]
            }),
        ),
        ("location".to_owned(), json!({ "title": "Board room" })),
    ]);
    let strand = crate::projection_views::StrandProjectionView {
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
        state: "active".to_owned(),
        created_by: None,
        created_at: None,
        updated_by: None,
        updated_at: None,
    };

    let card = card_from_strand_projection(&strand, None);

    assert_eq!(card.calendar.start, "2026-06-20T09:00:00Z");
    assert_eq!(card.calendar.end, "2026-06-20T10:00:00Z");
    assert_eq!(card.calendar.timezone, "Asia/Shanghai");
    assert_eq!(card.calendar.recurrence_frequency, "WEEKLY");
    assert_eq!(card.calendar.recurrence_interval, "1");
    assert_eq!(card.calendar.recurrence_by_day, "MO, WE");
    assert_eq!(card.calendar.location, "Board room");
    assert!(!card.calendar.location_locked);
}

#[test]
fn calendar_overlay_merges_partial_direct_schedule_patch() {
    let mut card = test_card(TEST_CALENDAR_STRAND_ID, "U");
    card.calendar = CalendarCardFields {
        start: "2026-06-20T09:00:00Z".to_owned(),
        end: "2026-06-20T10:00:00Z".to_owned(),
        timezone: "Asia/Shanghai".to_owned(),
        recurrence_frequency: "WEEKLY".to_owned(),
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
            "kind": "ck.strand.update",
            "operation_id": "op-calendar-start",
            "write_state": "queued",
            "body": {
                "strand_id": TEST_CALENDAR_STRAND_ID,
                "patch": {
                    "metadata.fields.start": {
                        "$op": "set",
                        "value": "2026-06-20T11:00:00Z"
                    }
                }
            }
        }),
    };

    let overlaid = overlay_local_card_update_records(columns, &[queued], None);
    let calendar = &overlaid[0].cards[0].calendar;

    assert_eq!(calendar.start, "2026-06-20T11:00:00Z");
    assert_eq!(calendar.end, "2026-06-20T10:00:00Z");
    assert_eq!(calendar.timezone, "Asia/Shanghai");
    assert_eq!(calendar.recurrence_frequency, "WEEKLY");
    assert_eq!(calendar.recurrence_by_day, "MO, WE");
    assert_eq!(calendar.location, "Board room");
}
