use super::*;
use crate::operation::EventExt;

#[test]
fn card_activity_items_show_local_strand_and_assignment_writes() {
    let mut card = test_card("ak:strand:activity", "U");
    card.primary_strand_id = card.id.clone();
    let received_at = |value: &str| {
        chrono::DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&chrono::Utc)
    };
    let raw_operations = vec![
        RawOperationRecord {
            operation_id: "op-assignee".to_owned(),
            realm_id: Some(TEST_REALM_ID.to_owned()),
            received_at: received_at("2026-06-10T10:00:00.000Z"),
            payload: json!({
                "kind": "ak.relation.tombstone",
                "operation_id": "op-assignee",
                "write_state": "accepted",
                "assignment_strand_id": card.id.clone(),
                "assignment_actor_id": "did:web:alice.example",
                "assignment_relation_id": "ak:relation:activity",
                "activity_summary": "Assignee removed: alice",
                "body": {
                    "relation_id": "ak:relation:activity"
                }
            }),
        },
        RawOperationRecord {
            operation_id: "op-due".to_owned(),
            realm_id: Some(TEST_REALM_ID.to_owned()),
            received_at: received_at("2026-06-10T11:00:00.000Z"),
            payload: json!({
                "kind": "ak.strand.update",
                "operation_id": "op-due",
                "write_state": "queued",
                "activity_summary": "Due date cleared",
                "body": {
                    "strand_id": card.id.clone(),
                    "patch": {
                        "metadata.fields": {
                            "$op": "set",
                            "value": { "labels": [] }
                        }
                    }
                }
            }),
        },
    ];

    let items = card_activity_items(&card, &raw_operations, &|actor| {
        crate::views::helpers::short_protocol_id(actor)
    });
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].title, "Due date cleared");
    assert_eq!(items[0].status, CardActivityStatus::Pending);
    assert_eq!(items[1].title, "Assignee removed: alice");
    assert_eq!(items[1].status, CardActivityStatus::Accepted);
}

#[test]
fn card_detail_update_patch_uses_strand_update_patch_paths() {
    let mut current = test_card("ak:strand:f1", "U");
    current.title = "Old".to_owned();
    current.description = "old summary".to_owned();
    current.labels = vec!["old".to_owned()];
    current.assignee = "did:web:bob.example".to_owned();
    current.due = "2026-05-19".to_owned();
    let draft = CardDetailDraft {
        title: "Launch checklist".to_owned(),
        description: "Ship blockers only".to_owned(),
        body: String::new(),
        synthesis: String::new(),
        labels: vec!["release".to_owned(), "ops".to_owned()],
        assignee: "did:web:alice.example".to_owned(),
        due: "2026-05-20".to_owned(),
        calendar: CalendarCardFields::default(),
    };

    let patch = card_detail_update_patch(&current, &draft).unwrap();
    assert_eq!(patch["metadata.title"]["value"], "Launch checklist");
    assert_eq!(patch["metadata.summary"]["value"], "Ship blockers only");
    assert_eq!(patch["metadata.fields.labels"]["value"][0], "release");
    assert_eq!(patch["metadata.fields.due_at"]["value"], "2026-05-20");
    assert!(patch.get("metadata.fields.assignee").is_none());
    assert!(patch.get("metadata.fields.due").is_none());
}

#[test]
fn card_assignment_mutations_create_and_tombstone_relation_events() {
    let mut current = test_card("ak:strand:0196419b-0000-8000-8000-000000000101", "U");
    current.assignee = "did:web:bob.example".to_owned();
    current.assigned_to_relations = vec![CardAssignedToRelation {
        relation_id: "ak:relation:0196419b-0000-8000-8000-0000000000bb".to_owned(),
        actor_id: "did:web:bob.example".to_owned(),
    }];
    let selected = BTreeSet::from(["did:web:alice.example".to_owned()]);

    let mutations = card_assignment_mutations(
        "ak:realm:0196419b-0000-8000-8000-000000000000",
        "did:web:owner.example",
        &current,
        &selected,
    )
    .unwrap();

    assert_eq!(mutations.len(), 2);
    let create = mutations
        .iter()
        .find(|mutation| matches!(mutation, CardAssignmentMutation::Create { .. }))
        .expect("create mutation");
    assert_eq!(create.actor_id(), "did:web:alice.example");
    assert_eq!(create.operation().kind.as_str(), "ak.relation.create");
    // `relation_create_payload` has two branches; only the object branch is
    // projectable, because the registered contract sets
    // `value = {"field": "payload.relation"}` into the relation cell.
    let relation = &create.operation().payload["relation"];
    assert_eq!(relation["relation_kind"], json!("assigned_to"));
    assert_eq!(relation["from_ref"], json!(current.id));
    assert_eq!(relation["to_ref"], json!("did:web:alice.example"));
    // No `relation.id` on a create payload: the id is derived from this Event
    // and reappears as the cell subject and the local target ref below.
    assert!(relation.get("id").is_none());
    let writes = crate::operation::direct_registered_cell_writes(create.operation()).unwrap();
    assert_eq!(
        writes[0].cell.as_str(),
        format!("ak:cell:ak.component.relation.v1:{}", create.relation_id())
    );
    assert_eq!(writes[0].op.value.as_ref(), Some(relation));
    assert_eq!(
        create.operation().local_target_ref(),
        Some(create.relation_id())
    );

    let tombstone = mutations
        .iter()
        .find(|mutation| matches!(mutation, CardAssignmentMutation::Tombstone { .. }))
        .expect("tombstone mutation");
    assert_eq!(
        tombstone.relation_id(),
        "ak:relation:0196419b-0000-8000-8000-0000000000bb"
    );
    assert_eq!(tombstone.operation().kind.as_str(), "ak.relation.tombstone");
    assert_eq!(
        tombstone.operation().payload["relation_id"],
        json!("ak:relation:0196419b-0000-8000-8000-0000000000bb")
    );

    let after = assignment_relations_after_mutations(&current, &selected, &mutations);
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].actor_id, "did:web:alice.example");
    assert!(after[0].relation_id.starts_with("ak:relation:"));
}

#[test]
fn card_assignment_mutations_clear_all_assignees() {
    let mut current = test_card("ak:strand:0196419b-0000-8000-8000-000000000101", "U");
    current.assigned_to_relations = vec![
        CardAssignedToRelation {
            relation_id: "ak:relation:0196419b-0000-8000-8000-0000000000aa".to_owned(),
            actor_id: "did:web:alice.example".to_owned(),
        },
        CardAssignedToRelation {
            relation_id: "ak:relation:0196419b-0000-8000-8000-0000000000bb".to_owned(),
            actor_id: "did:web:bob.example".to_owned(),
        },
    ];

    let selected = BTreeSet::new();
    let mutations = card_assignment_mutations(
        "ak:realm:0196419b-0000-8000-8000-000000000000",
        "did:web:owner.example",
        &current,
        &selected,
    )
    .unwrap();

    assert_eq!(mutations.len(), 2);
    assert!(
        mutations
            .iter()
            .all(|mutation| matches!(mutation, CardAssignmentMutation::Tombstone { .. }))
    );
    assert!(assignment_relations_after_mutations(&current, &selected, &mutations).is_empty());
}
