use super::*;
use crate::state::projection_views::{RsvpCellProjectionView, RsvpHeadProjectionView};

const TEST_CALENDAR_STRAND_ID: &str = "ak:strand:Ac_zaRRyp7i2guabQjAsFr7CdWBbP2ULfqGAcp4_we-V";

#[test]
fn calendar_patch_writes_one_activation_pair() {
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
        json!([arkret_sdk::SchemaId::CALENDAR_EVENT_V1])
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
    // The whole calendar subtree is one atomic patch value. The private-value
    // pipeline discovers the nested location without adding an overlapping
    // child patch path.
    assert_eq!(calendar["location"], json!({ "title": "Board room" }));

    // The activation pair plus the encrypted `location` child are the only
    // schedule entries: no flat field or profile-id impostor is ever written.
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
        assert!(patch.get(path).is_none(), "{path} must not be written");
    }

    let private_values = collect_encryptable_private_patch_values(&patch).unwrap();
    assert_eq!(private_values.len(), 1);
    assert_eq!(private_values[0].0, CALENDAR_LOCATION_PRIVATE_PATH);

    let mut encrypted_patch = patch.clone();
    replace_private_patch_values(
        &mut encrypted_patch,
        &[CALENDAR_LOCATION_PRIVATE_PATH.to_owned()],
        vec![json!({"ciphertext": "calendar-location"})],
    )
    .unwrap();
    assert!(
        encrypted_patch
            .get(CALENDAR_LOCATION_PRIVATE_PATH)
            .is_none()
    );
    assert_eq!(
        encrypted_patch[CALENDAR_SUBTREE_PATH]["value"]["location"]["ciphertext"],
        "calendar-location"
    );
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
    let calendar = CalendarCardFields {
        start: "2026-06-20T09:00:00".to_owned(),
        end: "2026-06-20T10:00:00".to_owned(),
        timezone: "Asia/Shanghai".to_owned(),
        tzdb_version: "2025a".to_owned(),
        recurrence_frequency: "weekly".to_owned(),
        recurrence_count: "10".to_owned(),
        ..CalendarCardFields::default()
    };

    let event = calendar_rsvp_operation(
        TEST_REALM_ID,
        "ak:did_core:web:auth.local.host:users:alice",
        TEST_CALENDAR_STRAND_ID,
        "accepted",
        "2026-06-20T09:00:00[Asia/Shanghai]",
        &calendar,
        vec![basis.clone()],
    )
    .unwrap();

    assert_eq!(event.kind().as_str(), "ak.rsvp.set");
    assert_eq!(event.local_target_ref(), None);
    assert_eq!(event.payload()["event_ref"], TEST_CALENDAR_STRAND_ID);
    assert_eq!(
        event.payload()["occurrence"],
        "2026-06-20T09:00:00[Asia/Shanghai]"
    );
    // The response lives inside the complete entry together with the basis.
    assert_eq!(event.payload()["entry"]["response"]["status"], "accepted");
    assert_eq!(
        event.payload()["entry"]["schedule_basis_refs"],
        json!([basis.as_str()])
    );
    // The basis must be causally carried, otherwise a receiver rejects it.
    assert_eq!(
        event
            .intent()
            .causal_refs()
            .iter()
            .map(arkret_sdk::Hash::as_str)
            .collect::<Vec<_>>(),
        vec![basis.as_str()]
    );
    // v1 ships no producer `effects[]`. The receiver derives the write from the
    // registered `ak.rsvp.set` contract, whose `effect_projection` is
    // `set value = {"field": "payload.entry"}` over the `mv_register` facet —
    // so asserting the projection is the successor to the old array, and a
    // stronger claim: the pre-closure client shipped no effect at all and the
    // Event never reached its cell.
    let writes = crate::operation::pre_authoring_cell_writes(
        event.intent(),
        arkret_sdk::DigestSuite::Sha256,
    )
    .unwrap();
    assert_eq!(writes.len(), 1);
    assert!(
        writes[0]
            .cell_id
            .as_str()
            .starts_with("ak:cell:ak.component.calendar.rsvp.v1:")
    );
    assert_eq!(
        crate::operation::direct_registered_cell_writes(
            &crate::operation::author_for_test(&event),
            arkret_sdk::DigestSuite::Sha256,
        )
        .unwrap()[0]
            .op
            .value
            .as_ref()
            .unwrap(),
        &event.payload()["entry"]
    );
    assert_registered_payload_valid(&event);
}

#[test]
fn calendar_rsvp_without_an_observed_schedule_fails_closed() {
    let calendar = CalendarCardFields {
        start: "2026-06-20T09:00:00".to_owned(),
        end: "2026-06-20T10:00:00".to_owned(),
        timezone: "Asia/Shanghai".to_owned(),
        tzdb_version: "2025a".to_owned(),
        ..CalendarCardFields::default()
    };
    // No frontier means we cannot claim to have observed the schedule, so
    // authoring refuses instead of signing an unbacked basis.
    assert!(
        calendar_rsvp_operation(
            TEST_REALM_ID,
            "ak:did_core:web:auth.local.host:users:alice",
            TEST_CALENDAR_STRAND_ID,
            "accepted",
            "",
            &calendar,
            Vec::new(),
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
        content: None,
        encrypted_content: None,
        tracks: Default::default(),
        board_space_id: None,
        list_space_id: None,
        rank: Some("U".to_owned()),
        assigned_actor_ids: Vec::new(),
        assigned_to_relations: Vec::new(),
        fields,
        schema_refs: vec![arkret_sdk::SchemaId::CALENDAR_EVENT_V1.to_owned()],
        rsvps: Vec::new(),
        schedule_revision_heads: vec![
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        ],
        state: arkret_sdk::ProjectionObjectState::Active,
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
fn calendar_editor_round_trips_the_complete_v1_schedule() {
    let source = json!({
        "start": "2026-06-22T09:00:00",
        "end": "2026-06-22T10:00:00",
        "timezone": "America/Los_Angeles",
        "tzdb_version": DEFAULT_CALENDAR_TZDB_VERSION,
        "all_day": false,
        "status": "tentative",
        "recurrence": {
            "frequency": "monthly",
            "interval": 2,
            "by_day": [{"day": "fr", "nth_of_period": -1}],
            "by_month": ["1", "3", "5"],
            "by_month_day": [-1],
            "by_set_position": [-1],
            "first_day_of_week": "su",
            "until": "2027-12-31T09:00:00"
        },
        "location": {
            "title": "Planning room",
            "address": "1 Example Street",
            "geo_uri": "geo:31.2304,121.4737",
            "url": "https://meet.example/room"
        },
        "call_id": "ak:call:AWXbZ-mBelWXBOM1haN1Q6WcwR_RscrylSZph2icMZ6y",
        "attendees": [
            {
                "actor_id": {"kind":"account","account_id":{
                    "principal_id":"ak:did_core:web:alice.example",
                    "station_id":"ak:did_core:web:principal.example"
                }},
                "role": "organizer",
                "display_name_snapshot": "Alice"
            },
            {
                "actor_id": {"kind":"account","account_id":{
                    "principal_id":"ak:did_core:web:bob.example",
                    "station_id":"ak:did_core:web:principal.example"
                }},
                "role": "required",
                "display_name_snapshot": "Bob"
            }
        ]
    });
    let fields = Map::from_iter([("calendar".to_owned(), source.clone())]);
    let editor = calendar_fields_from_metadata(&fields, None, TEST_CALENDAR_STRAND_ID);

    assert_eq!(editor.recurrence_by_day, "-1FR");
    assert_eq!(editor.recurrence_by_month, "1, 3, 5");
    assert_eq!(editor.recurrence_by_month_day, "-1");
    assert_eq!(editor.recurrence_by_set_position, "-1");
    assert_eq!(editor.recurrence_first_day_of_week, "SU");
    assert_eq!(
        editor.call_id,
        "ak:call:AWXbZ-mBelWXBOM1haN1Q6WcwR_RscrylSZph2icMZ6y"
    );
    assert!(editor.attendees_json.contains("display_name_snapshot"));

    let rebuilt = calendar_event_fields_from_draft(&editor).unwrap();
    assert_eq!(serde_json::to_value(rebuilt).unwrap(), source);
}

#[test]
fn calendar_editor_rejects_duplicate_attendee_actor_ids() {
    let calendar = CalendarCardFields {
        start: "2026-06-22T09:00:00".to_owned(),
        end: "2026-06-22T10:00:00".to_owned(),
        timezone: "Etc/UTC".to_owned(),
        tzdb_version: DEFAULT_CALENDAR_TZDB_VERSION.to_owned(),
        status: "confirmed".to_owned(),
        attendees_json: json!([
            {"actor_id": {"kind":"account","account_id":{
                "principal_id":"ak:did_core:web:alice.example",
                "station_id":"ak:did_core:web:principal.example"
            }}, "role": "organizer"},
            {"actor_id": {"kind":"account","account_id":{
                "principal_id":"ak:did_core:web:alice.example",
                "station_id":"ak:did_core:web:principal.example"
            }}, "role": "required"}
        ])
        .to_string(),
        ..CalendarCardFields::default()
    };

    assert!(calendar_event_fields_from_draft(&calendar).is_err());
}

#[test]
fn calendar_agenda_uses_shared_recurrence_expansion() {
    let calendar = CalendarCardFields {
        start: "2026-06-22T09:00:00".to_owned(),
        end: "2026-06-22T10:00:00".to_owned(),
        timezone: "Etc/UTC".to_owned(),
        tzdb_version: DEFAULT_CALENDAR_TZDB_VERSION.to_owned(),
        status: "confirmed".to_owned(),
        recurrence_frequency: "weekly".to_owned(),
        recurrence_count: "4".to_owned(),
        ..CalendarCardFields::default()
    };
    let now = chrono::DateTime::parse_from_rfc3339("2026-06-21T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let items = calendar_agenda(&calendar, &[FRONTIER.to_owned()], now).unwrap();
    assert_eq!(
        items
            .iter()
            .map(|item| item.local_start.as_str())
            .collect::<Vec<_>>(),
        [
            "2026-06-22T09:00:00",
            "2026-06-29T09:00:00",
            "2026-07-06T09:00:00",
            "2026-07-13T09:00:00"
        ]
    );
}

#[test]
fn card_without_a_projected_frontier_cannot_author_an_rsvp() {
    let card = test_card(TEST_CALENDAR_STRAND_ID, "U");
    assert!(card.calendar_schedule_basis_refs().is_empty());
}

#[test]
fn locally_accepted_rsvp_retains_the_observed_schedule_frontier() {
    let source_event_id =
        arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [9_u8; 32]);
    let projected = vec![crate::state::projection_views::StrandProjectionView {
        strand_id: TEST_CALENDAR_STRAND_ID.to_owned(),
        realm_id: TEST_REALM_ID.to_owned(),
        title: "Calendar".to_owned(),
        summary: None,
        content: None,
        encrypted_content: None,
        tracks: Default::default(),
        board_space_id: None,
        list_space_id: None,
        rank: None,
        assigned_actor_ids: Vec::new(),
        assigned_to_relations: Vec::new(),
        fields: Default::default(),
        schema_refs: Vec::new(),
        rsvps: Vec::new(),
        schedule_revision_heads: Vec::new(),
        state: arkret_sdk::ProjectionObjectState::Active,
        created_by: None,
        created_at: None,
        updated_by: None,
        updated_at: None,
    }];
    let accepted = RawOperationRecord {
        operation_id: source_event_id.to_string(),
        realm_id: Some(TEST_REALM_ID.to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ak.rsvp.set",
            "event_id": source_event_id,
            "actor_id": "ak:did_core:web:alice.example",
            "write_state": "synced",
            "locally_observed_schedule_heads": [FRONTIER],
            "body": {
                "event_ref": TEST_CALENDAR_STRAND_ID,
                "entry": {
                    "schedule_basis_refs": [FRONTIER],
                    "response": {"status": "accepted"}
                }
            }
        }),
    };

    let views = strand_views_from_projection_and_ops(&projected, &[accepted]);
    assert_eq!(views[0].schedule_revision_heads, vec![FRONTIER.to_owned()]);
    assert_eq!(views[0].rsvps.len(), 1);
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
    let source_event_id = arkret_sdk::EventId::from_digest(
        arkret_sdk::canonical::DigestSuite::Sha256,
        [digest_byte; 32],
    );
    RsvpHeadProjectionView {
        source_event_id: source_event_id.to_string(),
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
            actor_id: "ak:did_core:web:alice.example".to_owned(),
            heads: vec![rsvp_head(1, FRONTIER, "accepted")],
        },
        RsvpCellProjectionView {
            occurrence: None,
            actor_id: "ak:did_core:web:bob.example".to_owned(),
            heads: vec![rsvp_head(2, FRONTIER, "declined")],
        },
    ];

    let display = calendar_rsvp_display(
        &cells,
        &[FRONTIER.to_owned()],
        None,
        "ak:did_core:web:alice.example",
    );
    assert_eq!(display.own_status.as_deref(), Some("accepted"));
    assert!(!display.own_conflicted);
    assert_eq!(display.accepted, 1);
    assert_eq!(display.declined, 1);
    assert_eq!(display.excluded, 0);
}

#[test]
fn rsvp_display_matches_a_complete_account_actor_to_the_self_principal() {
    let cells = vec![RsvpCellProjectionView {
        occurrence: None,
        actor_id: r#"{"account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:station.example"},"kind":"account"}"#.to_owned(),
        heads: vec![rsvp_head(1, FRONTIER, "accepted")],
    }];

    let display = calendar_rsvp_display(
        &cells,
        &[FRONTIER.to_owned()],
        None,
        "ak:did_core:web:alice.example",
    );

    assert_eq!(display.own_status.as_deref(), Some("accepted"));
}

#[test]
fn rsvp_display_surfaces_a_conflict_instead_of_choosing_a_side() {
    // Two concurrent answers from the same responder. Only they can resolve
    // it, so the card must not display one of them as the answer.
    let cells = vec![RsvpCellProjectionView {
        occurrence: None,
        actor_id: "ak:did_core:web:alice.example".to_owned(),
        heads: vec![
            rsvp_head(1, FRONTIER, "accepted"),
            rsvp_head(2, FRONTIER, "declined"),
        ],
    }];

    let display = calendar_rsvp_display(
        &cells,
        &[FRONTIER.to_owned()],
        None,
        "ak:did_core:web:alice.example",
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
        actor_id: "ak:did_core:web:alice.example".to_owned(),
        heads: vec![rsvp_head(1, stale, "accepted")],
    }];

    let display = calendar_rsvp_display(
        &cells,
        &[FRONTIER.to_owned()],
        None,
        "ak:did_core:web:alice.example",
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
            actor_id: "ak:did_core:web:alice.example".to_owned(),
            heads: vec![rsvp_head(1, FRONTIER, "accepted")],
        },
        RsvpCellProjectionView {
            occurrence: Some(occurrence.to_owned()),
            actor_id: "ak:did_core:web:alice.example".to_owned(),
            heads: vec![rsvp_head(2, FRONTIER, "declined")],
        },
    ];

    let display = calendar_rsvp_display(
        &cells,
        &[FRONTIER.to_owned()],
        Some(occurrence),
        "ak:did_core:web:alice.example",
    );
    // Instance overrides series; the two tiers are never unioned into a
    // conflict.
    assert_eq!(display.own_status.as_deref(), Some("declined"));
    assert!(!display.own_conflicted);
}
