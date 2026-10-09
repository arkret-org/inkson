use super::*;

fn current_space_siblings(
    id: &str,
    kind: &str,
    title: &str,
    parent: Option<&str>,
) -> Vec<arkret_wire::TypedCurrentRow> {
    use arkret_wire::{CommitStreamRef, CurrentRevision, CurrentSelector, TypedCurrentRow};
    let space_id = arkret_sdk::SpaceId::new(id).unwrap();
    let space = arkret_sdk::Space::new(
        space_id.clone(),
        arkret_sdk::RealmId::new(PENDING_TEST_REALM).unwrap(),
        kind,
        title,
        crate::test_support::account_actor("ak:did_core:web:alice.example"),
    );
    [
        (
            CurrentSelector::Space {
                space_id: space_id.clone(),
            },
            serde_json::to_value(space).unwrap(),
        ),
        (
            CurrentSelector::SpaceParent {
                space_id: space_id.clone(),
            },
            json!({"parent_space_id": parent}),
        ),
        (
            CurrentSelector::SpaceChildScopePolicy { space_id },
            Value::Null,
        ),
    ]
    .into_iter()
    .map(|(selector, value)| TypedCurrentRow::Value {
        selector,
        source_stream_ref: CommitStreamRef::Realm {
            realm_id: arkret_sdk::RealmId::new(PENDING_TEST_REALM).unwrap(),
        },
        revision: CurrentRevision {
            commit_id: arkret_wire::RealmCommitId::from_digest([9; 32]),
            stream_position: 9,
        },
        value,
    })
    .collect()
}

#[test]
fn board_and_lists_render_from_current_without_create_history() {
    let list_id = "ak:space:AXDc1EwPcJZuThaCiR4FHq4V7rQ4I9QBR1YmEVB4xroH";
    let mut entries = current_space_siblings(PENDING_TEST_SPACE, "board", "Current board", None);
    entries.extend(current_space_siblings(
        list_id,
        "list",
        "Current list",
        Some(PENDING_TEST_SPACE),
    ));
    let canonical = entries.clone();
    let (columns, options, selected) = project_board_with_projection_for_actor(
        &[],
        &[],
        &[],
        PENDING_TEST_SPACE,
        PENDING_TEST_REALM,
        None,
        "",
        &entries,
    );
    assert_eq!(selected.as_deref(), Some(PENDING_TEST_SPACE));
    assert_eq!(options[0].title, "Current board");
    assert_eq!(columns.len(), 1);
    assert_eq!(columns[0].id, list_id);
    assert_eq!(columns[0].title, "Current list");
    assert_eq!(
        overlay_local_board_space_options(Vec::new(), &[], PENDING_TEST_REALM, &entries)[0].title,
        "Current board"
    );
    assert_eq!(entries, canonical);
    assert_eq!(
        kanban_space_current_selectors(Some(&options[0].id), &columns).len(),
        6
    );
}

#[test]
fn queued_list_is_visible_under_a_current_only_board() {
    let entries = current_space_siblings(PENDING_TEST_SPACE, "board", "Current board", None);
    let mut list = accepted_board_create_record();
    list.operation_id = "pending-list-operation".to_owned();
    list.payload["write_state"] = json!("queued");
    list.payload.as_object_mut().unwrap().remove("event_id");
    list.payload["operation_id"] = json!("pending-list-operation");
    list.payload["local_target_ref"] = json!("pending-list-operation");
    list.payload["body"]["object"]["kind"] = json!("list");
    list.payload["body"]["object"]["title"] = json!("New list");
    list.payload["body"]["object"]["parent_space_id"] = json!(PENDING_TEST_SPACE);
    let (columns, ..) = project_board_with_projection_for_actor(
        &[list],
        &[],
        &[],
        PENDING_TEST_SPACE,
        PENDING_TEST_REALM,
        None,
        "",
        &entries,
    );
    assert_eq!(columns.len(), 1);
    assert_eq!(columns[0].title, "New list");
}

#[test]
fn current_space_name_wins_over_historical_create_and_update() {
    let entries = current_space_siblings(PENDING_TEST_SPACE, "board", "Renamed board", None);
    let create = accepted_board_create_record();
    let mut update = create.clone();
    update.payload = json!({"kind": "ak.space.update", "write_state": "synced", "body": {
        "space_id": PENDING_TEST_SPACE, "patch": {"title": {"$op": "set", "value": "Old name"}}
    }});
    let views = space_container_views_from_projection_and_ops(
        &[],
        &[create, update.clone()],
        PENDING_TEST_REALM,
        &entries,
    );
    assert_eq!(views[0].title, "Renamed board");
    update.payload["write_state"] = json!("queued");
    let views =
        space_container_views_from_projection_and_ops(&[], &[update], PENDING_TEST_REALM, &entries);
    assert_eq!(views[0].title, "Old name");
}

#[test]
fn current_space_requires_exact_realm_and_complete_resolved_siblings() {
    let entries = current_space_siblings(PENDING_TEST_SPACE, "board", "Board", None);
    assert_eq!(
        space_container_views_from_current(&entries, PENDING_TEST_REALM).len(),
        1
    );
    for omitted in 0..3 {
        let mut partial = entries.clone();
        partial.remove(omitted);
        assert!(space_container_views_from_current(&partial, PENDING_TEST_REALM).is_empty());
    }
    let list_id = "ak:space:AXDc1EwPcJZuThaCiR4FHq4V7rQ4I9QBR1YmEVB4xroH";
    assert!(
        space_container_views_from_current(
            &current_space_siblings(list_id, "list", "Orphan", Some(PENDING_TEST_SPACE)),
            PENDING_TEST_REALM
        )
        .is_empty()
    );
    let mut cycle = current_space_siblings(PENDING_TEST_SPACE, "board", "Board", Some(list_id));
    cycle.extend(current_space_siblings(
        list_id,
        "list",
        "List",
        Some(PENDING_TEST_SPACE),
    ));
    assert!(space_container_views_from_current(&cycle, PENDING_TEST_REALM).is_empty());
    let mut foreign = entries.clone();
    let arkret_wire::TypedCurrentRow::Value {
        source_stream_ref, ..
    } = &mut foreign[1];
    *source_stream_ref = arkret_wire::CommitStreamRef::Realm {
        realm_id: arkret_sdk::RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-")
            .unwrap(),
    };
    assert!(space_container_views_from_current(&foreign, PENDING_TEST_REALM).is_empty());
}

#[test]
fn detached_space_submission_status_settles_and_preserves_newer_ui_actions() {
    let mut record = accepted_board_create_record();
    let submitting = format!(
        "submitting ak.space.create operation {}",
        crate::views::helpers::short_protocol_id(&record.operation_id)
    );
    record.payload["write_state"] = json!("queued");
    assert_eq!(
        kanban_operation_status_text(&submitting, &[record.clone()]),
        submitting
    );
    record.payload["write_state"] = json!("accepted");
    assert_eq!(
        kanban_operation_status_text(&submitting, &[record.clone()]),
        "ak.space.create completed"
    );
    record.payload["write_state"] = json!("failed");
    record.payload["error"] = json!("parent not readable");
    assert_eq!(
        kanban_operation_status_text(&submitting, &[record.clone()]),
        "ak.space.create failed: parent not readable"
    );
    assert_eq!(
        kanban_operation_status_text("Board selected", &[record.clone()]),
        "Board selected"
    );
    record
        .payload
        .as_object_mut()
        .unwrap()
        .remove("write_state");
    record.payload["producer_proof"] = json!({});
    assert_eq!(
        kanban_operation_status_text(&submitting, &[record]),
        "ak.space.create completed"
    );
}

const PENDING_TEST_REALM: &str = "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk";
const PENDING_TEST_OPERATION: &str = "01a01bdd-804b-7ad0-bee8-194898437ad7";
const PENDING_TEST_EVENT: &str = "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
const PENDING_TEST_SPACE: &str = "ak:space:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

/// A queued Board-create op-log row exactly as `submit_kanban_operation_event`
/// appends it: keyed by the holder-local operation id, no `event_id` yet.
fn pending_board_create_record(write_state: &str) -> RawOperationRecord {
    RawOperationRecord {
        operation_id: PENDING_TEST_OPERATION.to_owned(),
        realm_id: Some(PENDING_TEST_REALM.to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ak.space.create",
            "operation_id": PENDING_TEST_OPERATION,
            "local_target_ref": PENDING_TEST_OPERATION,
            "write_state": write_state,
            "body": { "object": { "kind": "board", "title": "Design board", "realm_id": PENDING_TEST_REALM } }
        }),
    }
}

/// The same row after the accept receipt / canonical backfill merge: the
/// final Event id is recorded and the draft handle survives as
/// `local_temporary_target_ref`.
fn accepted_board_create_record() -> RawOperationRecord {
    RawOperationRecord {
        operation_id: PENDING_TEST_OPERATION.to_owned(),
        realm_id: Some(PENDING_TEST_REALM.to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ak.space.create",
            "operation_id": PENDING_TEST_OPERATION,
            "event_id": PENDING_TEST_EVENT,
            "local_target_ref": PENDING_TEST_SPACE,
            "local_temporary_target_ref": PENDING_TEST_OPERATION,
            "write_state": "synced",
            "body": { "object": { "kind": "board", "title": "Design board", "realm_id": PENDING_TEST_REALM } }
        }),
    }
}

/// Pending Board creates are keyed by their holder-local `LocalOperationId`
/// and carry the user-entered title plus the op's write state — never a fake
/// protocol id.
#[test]
fn pending_board_create_derives_title_and_write_state_from_the_op_log() {
    let pending = pending_board_creates_from_ops(
        &[pending_board_create_record("queued")],
        PENDING_TEST_REALM,
    );
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].operation_id.as_str(), PENDING_TEST_OPERATION);
    assert_eq!(pending[0].title, "Design board");
    assert_eq!(pending[0].state, CardState::Queued);
    assert_eq!(pending[0].status_hint(), "creating");
    assert!(!pending[0].is_retryable());
    assert_eq!(pending[0].error, None);

    // A failed create stays visible as a failed pending write instead of
    // degrading into a fake Board id.
    let pending = pending_board_creates_from_ops(
        &[pending_board_create_record("failed")],
        PENDING_TEST_REALM,
    );
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].state, CardState::SoftFailed);
    assert_eq!(pending[0].status_hint(), "create failed");
    assert!(pending[0].is_retryable());

    // A dropped (cancelled) write leaves no pending surface at all.
    assert!(
        pending_board_creates_from_ops(
            &[pending_board_create_record("dropped")],
            PENDING_TEST_REALM
        )
        .is_empty()
    );
}

#[test]
fn stamped_create_identity_stays_pending_until_submit_acceptance() {
    for write_state in [
        "queued",
        "submitting",
        "submitted",
        "pending_commit",
        "failed",
        "rejected",
        "effective",
        "unknown",
    ] {
        let mut record = pending_board_create_record(write_state);
        record.payload["event_id"] = json!(PENDING_TEST_EVENT);
        let records = vec![record];
        assert_eq!(
            raw_operation_accepted_create_target_id(&records[0].payload),
            None
        );
        let pending = pending_board_creates_from_ops(&records, PENDING_TEST_REALM);
        assert_eq!(pending.len(), 1, "{write_state} is not a receipt");
        let aliases = event_derived_target_aliases(&records);
        assert!(
            aliases.is_empty(),
            "{write_state} must not confirm an alias"
        );
        let (candidate, awaiting) = accepted_board_create_transition(
            &BTreeSet::from([PENDING_TEST_OPERATION.to_owned()]),
            &pending,
            &aliases,
        );
        assert_eq!(candidate, None);
        assert!(awaiting.contains(PENDING_TEST_OPERATION));
        assert!(
            overlay_local_board_space_options(Vec::new(), &records, PENDING_TEST_REALM, &[],)
                .is_empty()
        );
    }
}

#[test]
fn create_acceptance_requires_terminal_owner_state_and_retains_exact_identity() {
    let mut missing_state = accepted_board_create_record();
    missing_state
        .payload
        .as_object_mut()
        .unwrap()
        .remove("write_state");
    assert_eq!(
        raw_operation_accepted_create_target_id(&missing_state.payload),
        None
    );
    assert!(event_derived_target_aliases(&[missing_state]).is_empty());

    for write_state in ["accepted", "synced", "committed"] {
        let mut accepted = accepted_board_create_record();
        accepted.payload["write_state"] = json!(write_state);
        assert_eq!(
            raw_operation_accepted_create_target_id(&accepted.payload).as_deref(),
            Some(PENDING_TEST_SPACE),
        );
        let records = vec![accepted];
        let pending = pending_board_creates_from_ops(&records, PENDING_TEST_REALM);
        assert!(pending.is_empty());
        let aliases = event_derived_target_aliases(&records);
        let (candidate, awaiting) = accepted_board_create_transition(
            &BTreeSet::from([PENDING_TEST_OPERATION.to_owned()]),
            &pending,
            &aliases,
        );
        assert_eq!(
            candidate.as_ref().map(arkret_sdk::SpaceId::as_str),
            Some(PENDING_TEST_SPACE)
        );
        let (repeated, _) = accepted_board_create_transition(&awaiting, &pending, &aliases);
        assert_eq!(repeated, None);
    }
}

/// The confirmed option set fails closed on anything that is not a canonical
/// `ak:space:` id: a pending create's holder-local handle never becomes a
/// `BoardSpaceOption`.
#[test]
fn pending_board_create_never_enters_confirmed_board_options() {
    let raw_operations = vec![pending_board_create_record("queued")];

    let containers = space_container_views_from_ops(&raw_operations, PENDING_TEST_REALM);
    let options = board_space_options_from_projection(&containers);
    assert!(
        options.is_empty(),
        "a pending create keyed by its holder-local handle is not a Board option"
    );
    let overlaid =
        overlay_local_board_space_options(Vec::new(), &raw_operations, PENDING_TEST_REALM, &[]);
    assert!(
        overlaid.is_empty(),
        "the local overlay must not promote a pending create into the confirmed option set"
    );
}

/// Once the accept receipt (or a canonical backfill merge) records the final
/// Event id on the same operation row, the pending surface drops out, the
/// holder-local alias resolves to the event-derived `SpaceId`, and exactly one
/// confirmed option carries the user-entered title.
#[test]
fn accepted_receipt_reconciles_pending_create_into_a_confirmed_space_id() {
    let raw_operations = vec![accepted_board_create_record()];

    assert!(
        pending_board_creates_from_ops(&raw_operations, PENDING_TEST_REALM).is_empty(),
        "an accepted create is no longer pending"
    );

    let aliases = event_derived_target_aliases(&raw_operations);
    let resolved = resolve_event_derived_target_alias(&aliases, PENDING_TEST_OPERATION);
    let space_id =
        arkret_sdk::SpaceId::new(resolved).expect("the reconciled alias is a canonical Space id");
    assert_eq!(space_id.as_str(), PENDING_TEST_SPACE);

    let containers = space_container_views_from_ops(&raw_operations, PENDING_TEST_REALM);
    let options = board_space_options_from_projection(&containers);
    assert_eq!(
        options.len(),
        1,
        "no duplicate option for the reconciled Board"
    );
    assert_eq!(options[0].id.as_str(), PENDING_TEST_SPACE);
    assert_eq!(options[0].title, "Design board");
}

/// The receipt migration is a TRANSITION: the pass that first remembers the
/// pending operation migrates nothing; the pass after the receipt merged
/// (row accepted, alias resolvable) yields exactly the event-derived Space id;
/// any later pass is a no-op.
#[test]
fn accepted_board_create_transition_fires_once_on_receipt() {
    // Pass 1: queued — the operation joins the remembered pending set.
    let queued_ops = vec![pending_board_create_record("queued")];
    let pending = pending_board_creates_from_ops(&queued_ops, PENDING_TEST_REALM);
    let (candidate, awaiting) =
        accepted_board_create_transition(&BTreeSet::new(), &pending, &BTreeMap::new());
    assert_eq!(
        candidate, None,
        "nothing migrates while the create is pending"
    );
    assert_eq!(
        awaiting,
        BTreeSet::from([PENDING_TEST_OPERATION.to_owned()])
    );

    // Pass 2: the receipt merged — the row left the pending set and its
    // holder-local id now resolves to the accepted Space id.
    let accepted_ops = vec![accepted_board_create_record()];
    let pending = pending_board_creates_from_ops(&accepted_ops, PENDING_TEST_REALM);
    let aliases = event_derived_target_aliases(&accepted_ops);
    let (candidate, awaiting) = accepted_board_create_transition(&awaiting, &pending, &aliases);
    assert_eq!(
        candidate.as_ref().map(arkret_sdk::SpaceId::as_str),
        Some(PENDING_TEST_SPACE)
    );
    assert!(awaiting.is_empty());

    // Pass 3 (repeated receipt / backfill-first replay): idempotent no-op.
    let (candidate, awaiting) = accepted_board_create_transition(&awaiting, &pending, &aliases);
    assert_eq!(candidate, None);
    assert!(awaiting.is_empty());
}

/// A row that leaves the pending set WITHOUT an accepted alias (cancelled, or
/// failed and later dropped) must never migrate the selection.
#[test]
fn accepted_board_create_transition_ignores_dropped_departures() {
    let dropped_ops = vec![pending_board_create_record("dropped")];
    let pending = pending_board_creates_from_ops(&dropped_ops, PENDING_TEST_REALM);
    let aliases = event_derived_target_aliases(&dropped_ops);
    let awaiting = BTreeSet::from([PENDING_TEST_OPERATION.to_owned()]);

    let (candidate, still_pending) =
        accepted_board_create_transition(&awaiting, &pending, &aliases);
    assert_eq!(candidate, None);
    assert!(still_pending.is_empty());
}

/// Several creates reconciling in the same pass migrate to the NEWEST one:
/// `LocalOperationId` is UUIDv7, so string order is time order.
#[test]
fn accepted_board_create_transition_prefers_the_newest_candidate() {
    let older = "01a01bdd-804b-7ad0-bee8-194898437ad7";
    let newer = "01a01bdd-804b-7ad0-bee8-194898437ad8";
    let older_space = "ak:space:AaDn_ypTG8vV4ToKfz6JtG2xnepF9QDlafPZCT-UYPyR";
    let newer_space = PENDING_TEST_SPACE;
    let awaiting = BTreeSet::from([older.to_owned(), newer.to_owned()]);
    let aliases = BTreeMap::from([
        (older.to_owned(), older_space.to_owned()),
        (newer.to_owned(), newer_space.to_owned()),
    ]);

    let (candidate, still_pending) = accepted_board_create_transition(&awaiting, &[], &aliases);
    assert_eq!(
        candidate.as_ref().map(arkret_sdk::SpaceId::as_str),
        Some(newer_space)
    );
    assert!(still_pending.is_empty());
}

#[test]
fn board_space_options_pick_board_spaces_from_projection() {
    let options = board_space_options_from_projection(&[
        crate::state::projection_views::SpaceContainerProjectionView {
            space_id: "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-".to_owned(),
            realm_id: "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk".to_owned(),
            kind: "board".to_owned(),
            title: "Release".to_owned(),
            state: arkret_sdk::SpaceState::Active,
            rank: None,
            parent_space_id: None,
        },
        crate::state::projection_views::SpaceContainerProjectionView {
            space_id: "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL".to_owned(),
            realm_id: "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk".to_owned(),
            kind: "list".to_owned(),
            title: "Todo".to_owned(),
            state: arkret_sdk::SpaceState::Active,
            rank: Some("U".to_owned()),
            parent_space_id: Some(
                "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-".to_owned(),
            ),
        },
    ]);

    assert_eq!(options.len(), 1);
    assert_eq!(
        options[0].id.as_str(),
        "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
    );
    assert_eq!(options[0].title, "Release");
}

#[test]
fn missing_or_terminal_board_metadata_cannot_be_recreated_from_a_list_parent() {
    let board = "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let list = crate::state::projection_views::SpaceContainerProjectionView {
        space_id: "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL".to_owned(),
        realm_id: PENDING_TEST_REALM.to_owned(),
        kind: "list".to_owned(),
        title: "List".to_owned(),
        state: arkret_sdk::SpaceState::Active,
        rank: None,
        parent_space_id: Some(board.to_owned()),
    };
    let canonical = list.clone();
    assert!(
        board_space_options_from_projection(&[list.clone()]).is_empty(),
        "a List parent ref is not evidence that its unavailable Board is active"
    );
    let mut metadata = list.clone();
    metadata.space_id = board.to_owned();
    metadata.kind = "board".to_owned();
    metadata.parent_space_id = None;
    metadata.state = arkret_sdk::SpaceState::Tombstoned;
    assert!(board_space_options_from_projection(&[metadata.clone(), list.clone()]).is_empty());
    metadata.state = arkret_sdk::SpaceState::Archived;
    assert_eq!(
        board_space_options_from_projection(&[metadata.clone(), list.clone()]).len(),
        1
    );
    metadata.state = arkret_sdk::SpaceState::Active;
    metadata.kind.clear();
    assert!(
        board_space_options_from_projection(&[metadata, list.clone()]).is_empty(),
        "a missing kind cannot infer Board semantics from root placement"
    );
    assert_eq!(
        list, canonical,
        "derived options cannot clear a canonical parent reference"
    );
}

#[test]
fn space_create_without_its_own_realm_cannot_borrow_the_page_realm() {
    let mut raw = accepted_board_create_record();
    raw.realm_id = None;
    raw.payload["body"]["object"]
        .as_object_mut()
        .unwrap()
        .remove("realm_id");
    assert!(local_space_create_records(&[raw.clone()], PENDING_TEST_REALM).is_empty());
    assert!(
        space_container_views_from_projection_and_ops(&[], &[raw], PENDING_TEST_REALM, &[])
            .is_empty()
    );
    let mut foreign = accepted_board_create_record();
    foreign.payload["body"]["object"]["realm_id"] =
        json!("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-");
    assert!(local_space_create_records(&[foreign], PENDING_TEST_REALM).is_empty());
}

#[test]
fn historical_create_or_restore_cannot_reactivate_a_terminal_board() {
    let raw = vec![accepted_board_create_record()];
    let terminal = BoardSpaceOption {
        id: arkret_sdk::SpaceId::new(PENDING_TEST_SPACE).unwrap(),
        title: "Terminal board".to_owned(),
        state: SpaceContainerLifecycleState::Tombstoned,
    };
    let overlaid = overlay_local_board_space_options(vec![terminal], &raw, PENDING_TEST_REALM, &[]);
    assert_eq!(
        overlaid[0].state,
        SpaceContainerLifecycleState::Tombstoned,
        "an old accepted create cannot reopen a confirmed terminal target"
    );
    let metadata = crate::state::projection_views::SpaceContainerProjectionView {
        space_id: PENDING_TEST_SPACE.to_owned(),
        realm_id: PENDING_TEST_REALM.to_owned(),
        kind: "board".to_owned(),
        title: "Terminal board".to_owned(),
        state: arkret_sdk::SpaceState::Tombstoned,
        rank: None,
        parent_space_id: None,
    };
    let mut restore = raw[0].clone();
    restore.payload = json!({"kind": "ak.space.restore", "body": {"space_id": PENDING_TEST_SPACE}});
    let views = space_container_views_from_projection_and_ops(
        &[metadata],
        &[raw[0].clone(), restore],
        PENDING_TEST_REALM,
        &[],
    );
    assert_eq!(
        views[0].state,
        arkret_sdk::SpaceState::Tombstoned,
        "confirmed terminal metadata dominates an old restore annotation"
    );
}

#[test]
fn terminal_current_suppresses_history_when_projection_omits_the_board() {
    let raw = vec![accepted_board_create_record()];
    let mut space = arkret_sdk::Space::new(
        arkret_sdk::SpaceId::new(PENDING_TEST_SPACE).unwrap(),
        arkret_sdk::RealmId::new(PENDING_TEST_REALM).unwrap(),
        "board",
        "Terminal board",
        serde_json::from_value(json!({"kind":"account","account_id":{
            "principal_id":"ak:did_core:web:alice.example",
            "station_id":"ak:did_core:web:station.example"}}))
        .unwrap(),
    );
    space.state = Some(arkret_sdk::SpaceState::Tombstoned);
    let entry = arkret_wire::TypedCurrentRow::Value {
        selector: arkret_wire::CurrentSelector::Space {
            space_id: space.id.clone().unwrap(),
        },
        source_stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: space.realm_id.clone(),
        },
        revision: arkret_wire::CurrentRevision {
            commit_id: arkret_wire::RealmCommitId::from_digest([9; 32]),
            stream_position: 9,
        },
        value: serde_json::to_value(&space).unwrap(),
    };
    let entries = vec![entry];
    let canonical = entries.clone();
    assert!(
        overlay_local_board_space_options(Vec::new(), &raw, PENDING_TEST_REALM, &entries)
            .is_empty()
    );
    assert!(
        space_container_views_from_projection_and_ops(&[], &raw, PENDING_TEST_REALM, &entries)
            .is_empty()
    );
    let (columns, options, selected) = project_board_with_projection_for_actor(
        &raw,
        &[],
        &[],
        PENDING_TEST_SPACE,
        PENDING_TEST_REALM,
        None,
        "",
        &entries,
    );
    assert!(columns.is_empty());
    assert!(options.is_empty());
    assert!(selected.is_none());
    assert_eq!(
        entries, canonical,
        "derived suppression preserves canonical current and revision"
    );

    let mut foreign = entries.clone();
    let arkret_wire::TypedCurrentRow::Value {
        source_stream_ref, ..
    } = &mut foreign[0]
    else {
        unreachable!()
    };
    *source_stream_ref = arkret_wire::CommitStreamRef::Realm {
        realm_id: arkret_sdk::RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-")
            .unwrap(),
    };
    assert!(terminal_space_ids_from_current(&foreign, PENDING_TEST_REALM).is_empty());
    foreign = entries.clone();
    let arkret_wire::TypedCurrentRow::Value { selector, .. } = &mut foreign[0] else {
        unreachable!()
    };
    *selector = arkret_wire::CurrentSelector::Space {
        space_id: arkret_sdk::SpaceId::new("ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-")
            .unwrap(),
    };
    assert!(terminal_space_ids_from_current(&foreign, PENDING_TEST_REALM).is_empty());
}

#[test]
fn local_space_create_state_becomes_synced_once_projection_contains_target() {
    let board_id = "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let raw_operations = vec![RawOperationRecord {
        operation_id: "sha256:local-board-create".to_owned(),
        realm_id: Some("ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk".to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ak.space.create",
            "operation_id": "sha256:local-board-create",
            "body": {
                "object": {
                    "id": board_id,
                    "schema": "ak.schema.space.v1",
                    "kind": "board",
                    "title": "Design board"
                }
            },
            "write_state": "queued"
        }),
    }];
    let projected_ids = BTreeSet::from([board_id.to_owned()]);

    let state = local_space_create_state_for_target(&raw_operations, &projected_ids, board_id);

    assert_eq!(state, Some(CardState::Synced));
}

#[test]
fn displayed_card_state_uses_server_strand_projection_over_local_queue() {
    let strand_id = "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2";
    let mut card = test_card(strand_id, "U");
    card.state = CardState::Queued;
    let projected_strand_ids = BTreeSet::from([strand_id.to_owned()]);

    assert_eq!(
        displayed_card_state(&card, &projected_strand_ids),
        CardState::Synced
    );
}

#[test]
fn lifecycle_projection_builds_persisted_board_columns_and_cards() {
    let board_id = "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let list_id = "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL";
    let containers = vec![
        crate::state::projection_views::SpaceContainerProjectionView {
            space_id: board_id.to_owned(),
            realm_id: "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk".to_owned(),
            kind: "board".to_owned(),
            title: "Release".to_owned(),
            state: arkret_sdk::SpaceState::Active,
            rank: None,
            parent_space_id: None,
        },
        crate::state::projection_views::SpaceContainerProjectionView {
            space_id: list_id.to_owned(),
            realm_id: "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk".to_owned(),
            kind: "list".to_owned(),
            title: "Todo".to_owned(),
            state: arkret_sdk::SpaceState::Active,
            rank: Some("U".to_owned()),
            parent_space_id: Some(board_id.to_owned()),
        },
    ];
    let strands = vec![crate::state::projection_views::StrandProjectionView {
        strand_id: "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2".to_owned(),
        realm_id: "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk".to_owned(),
        title: "Persisted card".to_owned(),
        summary: Some("Loaded from projection".to_owned()),
        content: Some(
            arkret_sdk::ContentBlock::text("Projection description content")
                .with_field("format", json!("markdown")),
        ),
        encrypted_content: None,
        tracks: BTreeMap::from([(
            arkret_sdk::STRAND_TRACK_NAME_SYNTHESIS.to_owned(),
            arkret_sdk::StrandTrack {
                content: Some(arkret_sdk::ContentBlock::text(
                    "Projection synthesis content",
                )),
                ..Default::default()
            },
        )]),
        board_space_id: Some(board_id.to_owned()),
        list_space_id: Some(list_id.to_owned()),
        rank: Some("U".to_owned()),
        assigned_actor_ids: vec![
            crate::mls_api_helpers::local_account_actor_id("ak:did_core:web:alice.example")
                .unwrap(),
        ],
        assigned_to_relations: vec![
            crate::state::projection_views::AssignedToRelationProjectionView {
                relation_id: "ak:relation:ASc_XP_IqOBAY6GgbPMLFCeZmi0uBNaWvHazHgmn-B8K".to_owned(),
                actor_id: crate::mls_api_helpers::local_account_actor_id(
                    "ak:did_core:web:alice.example",
                )
                .unwrap(),
            },
        ],
        schema_refs: Vec::new(),
        rsvps: Vec::new(),
        schedule_revision_source: None,
        fields: Map::from_iter([
            ("labels".to_owned(), json!(["demo", "db"])),
            ("due_at".to_owned(), json!("2026-05-22")),
        ]),
        created_by: Some("ak:did_core:web:acme.example:users:alice".to_owned()),
        created_at: Some("2026-05-22T10:00:00.000Z".to_owned()),
        updated_by: None,
        updated_at: None,
        state: arkret_sdk::ObjectState::Active,
    }];

    let (columns, options, selected_board) =
        columns_from_lifecycle_projection(&containers, &strands, "", None);

    assert_eq!(selected_board.as_deref(), Some(board_id));
    assert_eq!(options.len(), 1);
    assert_eq!(columns.len(), 1);
    assert_eq!(columns[0].title, "Todo");
    assert_eq!(columns[0].cards.len(), 1);
    let card = &columns[0].cards[0];
    assert_eq!(card.title, "Persisted card");
    assert_eq!(card.description, "Loaded from projection");
    assert_eq!(card.description_body, "Projection description content");
    assert_eq!(card.synthesis, "Projection synthesis content");
    assert_eq!(card.labels, vec!["demo".to_owned(), "db".to_owned()]);
    assert_eq!(card.assignee, "ak:did_core:web:alice.example");
    assert_eq!(
        card.assigned_to_relations,
        vec![CardAssignedToRelation {
            relation_id: "ak:relation:ASc_XP_IqOBAY6GgbPMLFCeZmi0uBNaWvHazHgmn-B8K".to_owned(),
            actor_id: crate::mls_api_helpers::local_account_actor_id(
                "ak:did_core:web:alice.example"
            )
            .unwrap(),
        }]
    );
    assert_eq!(card.due, "2026-05-22");
}

#[test]
fn lifecycle_projection_requires_board_metadata_for_list_parent() {
    let board_id = "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let list_id = "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL";
    let containers = vec![
        crate::state::projection_views::SpaceContainerProjectionView {
            space_id: list_id.to_owned(),
            realm_id: "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk".to_owned(),
            kind: "list".to_owned(),
            title: "Todo".to_owned(),
            state: arkret_sdk::SpaceState::Active,
            rank: Some("U".to_owned()),
            parent_space_id: Some(board_id.to_owned()),
        },
    ];

    let (columns, options, selected_board) =
        columns_from_lifecycle_projection(&containers, &[], "", None);

    assert!(selected_board.is_none());
    assert!(options.is_empty());
    assert!(columns.is_empty());
    assert_eq!(containers[0].parent_space_id.as_deref(), Some(board_id));
}

#[test]
fn local_strand_create_overlay_restores_card_until_projection_catches_up() {
    let board_id = "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let list_id = "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL";
    let strand_id = "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2";
    let raw_operations = vec![RawOperationRecord {
        operation_id: "sha256:local-create".to_owned(),
        realm_id: Some("ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk".to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ak.strand.create",
            "operation_id": "sha256:local-create",
            "effect": {
                "strand_id": strand_id,
                "board_space_id": board_id,
                "list_space_id": list_id,
                "title": "Refresh-surviving card",
                "rank": "U",
                "strand_kind": "card"
            },
            "write_state": "queued"
        }),
    }];
    let projected_columns = vec![KanbanColumn {
        id: list_id.to_owned(),
        title: "Todo".to_owned(),
        rank: "U".to_owned(),
        cards: Vec::new(),
        state: SpaceContainerLifecycleState::Active,
    }];

    let overlaid =
        overlay_local_card_create_records(projected_columns.clone(), &raw_operations, board_id);
    assert_eq!(overlaid[0].cards.len(), 1);
    assert_eq!(overlaid[0].cards[0].id, strand_id);
    assert_eq!(overlaid[0].cards[0].title, "Refresh-surviving card");
    assert_eq!(overlaid[0].cards[0].description, "");
    assert_eq!(overlaid[0].cards[0].state, CardState::Queued);

    let overlaid_again =
        overlay_local_card_create_records(overlaid.clone(), &raw_operations, board_id);
    assert_eq!(
        overlaid_again[0].cards.len(),
        1,
        "overlay must be idempotent across repeated projection refreshes"
    );

    let mut projected_with_server_card = projected_columns;
    projected_with_server_card[0]
        .cards
        .push(test_card(strand_id, "U"));
    let de_duped =
        overlay_local_card_create_records(projected_with_server_card, &raw_operations, board_id);
    assert_eq!(
        de_duped[0].cards.len(),
        1,
        "server projection wins once the reducer has materialized the card"
    );
    assert_eq!(de_duped[0].cards[0].state, CardState::Synced);
}

#[test]
fn stamped_pending_card_has_exact_holder_local_render_evidence_without_acceptance() {
    let local_id = "01904100-0000-7000-8000-000000000099";
    let event_id = "ak:event:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2";
    let strand_id = "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2";
    let list_id = "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL";
    let mut store = isolated_store_for_tests("stamped-pending-card-render-evidence");
    store.upsert_raw_operation(
        local_id,
        Some(PENDING_TEST_REALM.to_owned()),
        json!({
            "kind": "ak.strand.create", "operation_id": local_id,
            "local_target_ref": local_id, "event_id": event_id, "write_state": "queued",
            "effect": {"strand_id": local_id, "board_space_id": PENDING_TEST_SPACE,
                "list_space_id": list_id, "title": "Held card", "rank": "U"}
        }),
    );
    let original = store.load().raw_operations;
    let card = local_card_create_from_raw_operation(&original[0])
        .unwrap()
        .card;
    assert_eq!(card.id, strand_id);
    assert!(card.authoring_basis.is_none());
    assert!(!card_detail_write_ready(&card));
    for state in ["queued", "submitting", "submitted", "pending_commit"] {
        let mut rows = original.clone();
        rows[0].payload["write_state"] = json!(state);
        assert!(holder_local_pending_card_create(
            &card,
            PENDING_TEST_SPACE,
            list_id,
            &rows
        ));
        assert!(raw_operation_accepted_create_target_id(&rows[0].payload).is_none());
        assert!(event_derived_target_aliases(&rows).is_empty());
        assert!(!displayed_card_state(&card, &BTreeSet::new()).is_settled());
    }
    for state in [
        "failed",
        "rejected",
        "cancelled",
        "dropped",
        "unknown",
        "effective",
        "accepted",
        "synced",
        "committed",
    ] {
        let mut rows = original.clone();
        rows[0].payload["write_state"] = json!(state);
        assert!(
            !holder_local_pending_card_create(&card, PENDING_TEST_SPACE, list_id, &rows),
            "{state}"
        );
    }
    assert!(!holder_local_pending_card_create(
        &card,
        "other-board",
        list_id,
        &original
    ));
    assert!(!holder_local_pending_card_create(
        &card,
        PENDING_TEST_SPACE,
        "other-list",
        &original
    ));
    for field in ["local_target_ref", "event_id"] {
        let mut rows = original.clone();
        rows[0].payload[field] = json!("different-target");
        assert!(
            !holder_local_pending_card_create(&card, PENDING_TEST_SPACE, list_id, &rows),
            "{field}"
        );
    }
    let mut rows = original.clone();
    rows[0].payload["effect"]["strand_id"] = json!("different-target");
    assert!(!holder_local_pending_card_create(
        &card,
        PENDING_TEST_SPACE,
        list_id,
        &rows
    ));
    rows[0]
        .payload
        .as_object_mut()
        .unwrap()
        .remove("write_state");
    assert!(!holder_local_pending_card_create(
        &card,
        PENDING_TEST_SPACE,
        list_id,
        &rows
    ));
}

#[test]
fn card_create_stays_visible_through_commit_and_backfill_until_placement() {
    let board_id = PENDING_TEST_SPACE;
    let list_id = "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL";
    let event_id = "ak:event:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2";
    let strand_id = "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2";
    let local_id = "01904100-0000-7000-8000-000000000099";
    let mut store = isolated_store_for_tests("card-create-display-handoff");
    store.upsert_raw_operation(
        local_id,
        Some(PENDING_TEST_REALM.to_owned()),
        json!({
            "kind": "ak.strand.create",
            "operation_id": local_id,
            "local_target_ref": local_id,
            "write_state": "queued",
            "effect": {
                "strand_id": local_id, "board_space_id": board_id,
                "list_space_id": list_id, "title": "Continuous card", "rank": "U"
            }
        }),
    );
    let columns = vec![KanbanColumn {
        id: list_id.to_owned(),
        title: "Todo".to_owned(),
        rank: "U".to_owned(),
        cards: Vec::new(),
        state: SpaceContainerLifecycleState::Active,
    }];
    for (write_state, expected_id, expected_state) in [
        ("queued", local_id, CardState::Queued),
        ("pending_commit", strand_id, CardState::Submitted),
        ("effective", strand_id, CardState::Synced),
    ] {
        store.update_raw_operation_write_state(
            local_id,
            write_state,
            (write_state != "queued").then(|| event_id.to_owned()),
            None,
        );
        if write_state == "pending_commit" {
            let rows = store.load().raw_operations;
            assert_eq!(
                raw_operation_accepted_create_target_id(&rows[0].payload),
                None
            );
            assert!(event_derived_target_aliases(&rows).is_empty());
        }
        let shown = overlay_local_card_create_records(
            columns.clone(),
            &store.load().raw_operations,
            board_id,
        );
        assert_eq!(shown[0].cards.len(), 1, "card disappeared at {write_state}");
        assert_eq!(shown[0].cards[0].id, expected_id);
        assert_eq!(shown[0].cards[0].title, "Continuous card");
        assert_eq!(shown[0].cards[0].state, expected_state);
    }
    // The create's canonical stream copy arrives before its placement Move.
    store.upsert_raw_operation(
        event_id,
        Some(PENDING_TEST_REALM.to_owned()),
        json!({
            "kind": "ak.strand.create", "operation_id": event_id,
            "local_target_ref": strand_id, "write_state": "synced",
            "body": {"object": {"kind": "card"}}
        }),
    );
    let rows = store.load().raw_operations;
    assert_eq!(rows.len(), 1);
    let shown = overlay_local_card_create_records(columns.clone(), &rows, board_id);
    assert_eq!(
        shown[0].cards.len(),
        1,
        "backfill must preserve the intended placement"
    );
    assert_eq!(shown[0].cards[0].id, strand_id);
    assert_eq!(shown[0].cards[0].title, "Continuous card");
    let confirmed = overlay_local_card_create_records(shown, &rows, board_id);
    assert_eq!(
        confirmed[0].cards.len(),
        1,
        "projection handoff must not duplicate the card"
    );

    // Once placed, subsequent moves/archives must not resurrect the create's
    // original destination, even when that column no longer contains the card.
    store.upsert_raw_operation(
        "placement",
        Some(PENDING_TEST_REALM.to_owned()),
        json!({
            "kind": "ak.strand.move", "write_state": "effective",
            "body": {"strand_id": strand_id}
        }),
    );
    assert!(
        overlay_local_card_create_records(columns.clone(), &store.load().raw_operations, board_id)
            [0]
        .cards
        .is_empty()
    );

    for terminal in ["rejected", "quarantined", "dropped"] {
        let mut failed = rows.clone();
        failed[0].payload["write_state"] = json!(terminal);
        assert!(
            overlay_local_card_create_records(columns.clone(), &failed, board_id)[0]
                .cards
                .is_empty()
        );
    }
}

#[test]
fn remote_strand_update_events_overlay_detail_fields_on_projection() {
    let board_id = "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let strand_id = "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2";
    let mut card = test_card(strand_id, "U");
    card.description = "old summary".to_owned();
    card.synthesis = String::new();
    let columns = vec![KanbanColumn {
        id: "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL".to_owned(),
        title: "Todo".to_owned(),
        rank: "U".to_owned(),
        cards: vec![card],
        state: SpaceContainerLifecycleState::Active,
    }];
    let events = vec![json!({
        "event_id": "ak:event:AZUYAeUiTiKHqTOGKrrTfa2xZPZj09T6IRYuDuCNc9ZQ",
        "operation_id": "ak:operation:0196419b-0000-7000-8000-00000000f001",
        "event_kind": "ak.strand.update",
        "actor_id": "ak:did_core:web:alice.example",
        "created_at": "2026-05-22T10:00:00.000Z",
        "realm_id": "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk",
        "payload": {
            "target_ref": strand_id,
            "patch": {
                "metadata.summary": { "$op": "set", "value": "new summary" },
                "tracks.synthesis.content": {
                    "$op": "set",
                    "value": {
                        "kind": "ak.content.text",
                        "format": "markdown",
                        "body": "new synthesis note"
                    }
                },
                "metadata.fields": {
                    "$op": "set",
                    "value": {
                        "labels": ["remote"],
                        "due_at": "2026-05-30"
                    }
                }
            }
        }
    })];
    let events = crate::state::projection::kanban_ops::sdk_events_from_values(&events);
    let remote_operations = strand_update_operations_from_events(&events);

    let projected = overlay_card_projection_with_operations(
        columns,
        &LocalStateStore::default(),
        board_id,
        &remote_operations,
    );

    let card = &projected[0].cards[0];
    assert_eq!(card.description, "new summary");
    assert_eq!(card.synthesis, "new synthesis note");
    assert_eq!(card.labels, vec!["remote"]);
    assert_eq!(card.due, "2026-05-30");
    assert_eq!(card.state, CardState::Synced);
}

#[test]
fn remote_encrypted_strand_update_overlay_marks_private_fields_locked() {
    let board_id = "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let strand_id = "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2";
    let mut card = test_card(strand_id, "U");
    card.synthesis = String::new();
    let columns = vec![KanbanColumn {
        id: "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL".to_owned(),
        title: "Todo".to_owned(),
        rank: "U".to_owned(),
        cards: vec![card],
        state: SpaceContainerLifecycleState::Active,
    }];
    let envelope = json!({
        "scheme": "mls_rfc9420",
        "ciphertext": "AAAA",
        "content_type": KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
        "group_id": "g",
        "epoch": 0,
    });
    let events = vec![json!({
        "event_id": "ak:event:AYiSAxDIS8PlP8d9iucotDVTdZ9-CahOJVw2Km3R38HU",
        "operation_id": "ak:operation:0196419b-0000-7000-8000-00000000f002",
        "event_kind": "ak.strand.update",
        "actor_id": "ak:did_core:web:alice.example",
        "created_at": "2026-05-22T10:00:00.000Z",
        "realm_id": "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk",
        "payload": {
            "target_ref": strand_id,
            "patch": {
                "tracks.synthesis.encrypted_content": { "$op": "set", "value": envelope }
            }
        }
    })];
    let events = crate::state::projection::kanban_ops::sdk_events_from_values(&events);
    let remote_operations = strand_update_operations_from_events(&events);
    let store = LocalStateStore::default();
    let ctx = MlsDecryptCtx {
        identity: None,
        state_store: &store,
        realm_id: TEST_REALM_ID,
    };

    let projected = overlay_card_projection_with_operations_and_decrypt(
        columns,
        &store,
        board_id,
        &remote_operations,
        Some(&ctx),
    );

    let card = &projected[0].cards[0];
    assert_eq!(card.synthesis, "");
    assert!(card.synthesis_locked);
    assert_eq!(card.state, CardState::Synced);
}

/// Non-spec Strand paths are NOT a second way to spell content.
///
/// `strand.schema.json` forbids top-level `body` / `title` / `summary` /
/// `fields`, and neither `metadata.fields.synthesis` nor `tracks.<name>.body`
/// is a wire path at all. A patch that uses them is a schema violation the
/// server rejects, so the local overlay must ignore it outright — otherwise
/// a rejected write would still paint the board and read back as if accepted.
#[test]
fn non_spec_strand_patch_paths_are_ignored_by_the_local_overlay() {
    let board_id = "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let strand_id = "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2";
    let mut card = test_card(strand_id, "U");
    card.title = "kept title".to_owned();
    card.description = "kept summary".to_owned();
    card.synthesis = "kept synthesis".to_owned();
    card.labels = vec!["kept".to_owned()];
    let columns = vec![KanbanColumn {
        id: "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL".to_owned(),
        title: "Todo".to_owned(),
        rank: "U".to_owned(),
        cards: vec![card],
        state: SpaceContainerLifecycleState::Active,
    }];
    let events = vec![json!({
        "event_id": "ak:event:AZUYAeUiTiKHqTOGKrrTfa2xZPZj09T6IRYuDuCNc9ZQ",
        "operation_id": "ak:operation:0196419b-0000-7000-8000-00000000f004",
        "event_kind": "ak.strand.update",
        "actor_id": "ak:did_core:web:alice.example",
        "created_at": "2026-05-22T10:00:00.000Z",
        "realm_id": "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk",
        "payload": {
            "target_ref": strand_id,
            "patch": {
                "title": { "$op": "set", "value": "forbidden title" },
                "summary": { "$op": "set", "value": "forbidden summary" },
                "body": { "$op": "set", "value": "forbidden body" },
                "synthesis": { "$op": "set", "value": "forbidden synthesis" },
                "fields.body": { "$op": "set", "value": "forbidden fields body" },
                "fields.synthesis": { "$op": "set", "value": "forbidden fields synthesis" },
                "tracks.synthesis.body": { "$op": "set", "value": "forbidden track body" },
                "tracks.discussion.body": { "$op": "set", "value": "forbidden discussion body" },
                "fields": { "$op": "set", "value": { "labels": ["forbidden"] } }
            }
        }
    })];
    let events = crate::state::projection::kanban_ops::sdk_events_from_values(&events);
    let remote_operations = strand_update_operations_from_events(&events);

    let projected = overlay_card_projection_with_operations(
        columns,
        &LocalStateStore::default(),
        board_id,
        &remote_operations,
    );

    let card = &projected[0].cards[0];
    assert_eq!(card.title, "kept title");
    assert_eq!(card.description, "kept summary");
    assert_eq!(card.synthesis, "kept synthesis");
    assert!(!card.synthesis_locked);
    assert_eq!(card.labels, vec!["kept".to_owned()]);
}

/// A projection row that only carries the retired locations exposes NO
/// content: reading them back would resurrect the non-spec shape locally.
#[test]
fn non_spec_projection_paths_expose_no_strand_content() {
    let strand = crate::state::projection_views::StrandProjectionView {
        strand_id: "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2".to_owned(),
        realm_id: TEST_REALM_ID.to_owned(),
        title: "Card".to_owned(),
        summary: None,
        content: None,
        encrypted_content: None,
        tracks: Default::default(),
        board_space_id: None,
        list_space_id: None,
        rank: None,
        assigned_actor_ids: Vec::new(),
        assigned_to_relations: Vec::new(),
        schema_refs: Vec::new(),
        rsvps: Vec::new(),
        schedule_revision_source: None,
        fields: Map::from_iter([
            ("body".to_owned(), json!("non-spec body")),
            ("synthesis".to_owned(), json!("non-spec synthesis")),
        ]),
        created_by: None,
        created_at: None,
        updated_by: None,
        updated_at: None,
        state: arkret_sdk::ObjectState::Active,
    };

    assert!(strand_projection_synthesis_content(&strand).is_none());
    let card = card_from_strand_projection(&strand, None);
    assert_eq!(card.synthesis, "");
    assert!(!card.synthesis_locked);
}

/// The demo-seed opt-in is spelled `INKSON_ALLOW_KANBAN_SEED_FALLBACK=1` /
/// `=true` and nothing else — an empty or unset variable MUST NOT seed a board
/// that the server never returned.
#[test]
fn kanban_seed_fallback_opt_in_accepts_only_explicit_truthy_values() {
    assert!(truthy_env_value(Some("1")));
    assert!(truthy_env_value(Some("true")));
    assert!(!truthy_env_value(Some("0")));
    assert!(!truthy_env_value(None));
}
