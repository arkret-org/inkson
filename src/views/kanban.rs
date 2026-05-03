use dioxus::prelude::*;
use dioxus_router::Link;
use serde_json::json;

use crate::{
    local_state::LocalStateStore,
    operation::{EventEnvelope, cx_ops, uuid_v8},
    routes::Route,
    views::helpers::{active_sync_token, authed_api_with_sync},
};

#[derive(Clone, Debug, PartialEq)]
struct KanbanColumn {
    id: String,
    title: String,
    rank: String,
    cards: Vec<KanbanCard>,
}

#[derive(Clone, Debug, PartialEq)]
struct KanbanCard {
    id: String,
    title: String,
    description: String,
    labels: Vec<String>,
    assignee: String,
    due: String,
    primary_flow_id: String,
    primary_flow: String,
    linked_flows: Vec<FlowLink>,
    locked_flow: Option<LockedFlow>,
    external_visibility: String,
    history_visibility: String,
    activity_hint: String,
    audit_hint: String,
    state: CardState,
}

#[derive(Clone, Debug, PartialEq)]
struct FlowLink {
    flow_id: String,
    name: String,
    access_state: DiscussionAccessState,
}

#[derive(Clone, Debug, PartialEq)]
struct LockedFlow {
    flow_id_hash: String,
    reason: String,
}

#[derive(Clone, Debug, PartialEq)]
enum DiscussionAccessState {
    Readable,
    External,
}

impl DiscussionAccessState {
    fn label(&self) -> &'static str {
        match self {
            Self::Readable => "readable",
            Self::External => "external",
        }
    }

    fn class_name(&self) -> &'static str {
        match self {
            Self::Readable => "badge blue",
            Self::External => "badge green",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum CardState {
    Synced,
    Optimistic,
    Queued,
    Submitted,
    Accepted,
    SoftFailed,
    Quarantined,
    Conflict,
}

impl CardState {
    fn label(&self) -> &'static str {
        match self {
            CardState::Synced => "synced",
            CardState::Optimistic => "optimistic",
            CardState::Queued => "queued",
            CardState::Submitted => "submitted",
            CardState::Accepted => "accepted",
            CardState::SoftFailed => "soft failed",
            CardState::Quarantined => "quarantined",
            CardState::Conflict => "CAS conflict",
        }
    }

    fn class_name(&self) -> &'static str {
        match self {
            CardState::Synced | CardState::Accepted => "badge green",
            CardState::Optimistic | CardState::Queued | CardState::Submitted => "badge blue",
            CardState::SoftFailed | CardState::Conflict => "badge red",
            CardState::Quarantined => "badge amber",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct BoardWriteRecord {
    state: CardState,
    event: EventEnvelope,
    note: String,
}

#[component]
pub fn KanbanPanel(
    base_url: String,
    token: Signal<String>,
    account_did: String,
    selected_space: String,
    sync_cursor: Signal<String>,
    repo_state: Signal<String>,
    state_store: Signal<LocalStateStore>,
    event_write_ready: bool,
) -> Element {
    let mut columns = use_signal(seed_columns);
    let mut new_column_title = use_signal(String::new);
    let mut new_card_title = use_signal(String::new);
    let mut adding_card_to = use_signal(|| Option::<String>::None);
    let mut selected_card = use_signal(|| Option::<KanbanCard>::None);
    let mut write_records = use_signal(Vec::<BoardWriteRecord>::new);
    let mut board_status = use_signal(|| {
        if event_write_ready {
            "Event write plane ready".to_owned()
        } else {
            "Event write plane unavailable; board writes queue locally".to_owned()
        }
    });

    rsx! {
        div { class: "timeline", "data-testid": "kanban-panel",
            div { class: "event",
                div { class: "event-head",
                    span { "Launch Board" }
                    span { "board workspace / {selected_space}" }
                }
                div { class: "space-title", "Board/List/Card workbench" }
                div { class: "muted",
                    "Projection uses Board -> List -> Flow(kind=\"card\") contains relations with explicit rank and position edges. Card visibility and discussion visibility stay independent."
                }
                div { class: "actions", "data-testid": "board-write-states",
                    for state in write_state_samples() {
                        span { class: state.class_name(), "{state.label()}" }
                    }
                }
                div { class: "metric-grid", "data-testid": "board-projection-model",
                    div { class: "metric", strong { "Board" } span { "cx:board:launch" } div { class: "muted", "View renderer: kanban" } }
                    div { class: "metric", strong { "Relation" } span { "contains" } div { class: "muted", "List contains Card by rank" } }
                    div { class: "metric", strong { "Frontier" } span { "{repo_state}" } div { class: "muted", "CAS moves rebase from latest projection" } }
                    div { class: "metric", strong { "Write plane" } span { if event_write_ready { "cx.events.submit" } else { "queued local" } } div { class: "muted", "legacy operation helpers remain bridge-only" } }
                }
                div { class: "workflow-form",
                    div { class: "actions",
                        input {
                            "data-testid": "new-column-input",
                            value: "{new_column_title}",
                            placeholder: "New list title",
                            oninput: move |evt| new_column_title.set(evt.value()),
                        }
                        button {
                            class: "secondary",
                            "data-testid": "add-column-button",
                            onclick: {
                                let space = selected_space.clone();
                                let actor = account_did.clone();
                                move |_| {
                                    let title = new_column_title().trim().to_owned();
                                    if !title.is_empty() {
                                        let col_count = columns().len();
                                        let rank = format!("r{:03}", col_count + 1);
                                        let list_id = format!("cx:list:{}", uuid_v8());
                                        columns.write().push(KanbanColumn {
                                            id: list_id.clone(),
                                            title: title.clone(),
                                            rank: rank.clone(),
                                            cards: Vec::new(),
                                        });
                                        let op = cx_ops::list_create(
                                            &space,
                                            &actor,
                                            "cx:board:launch",
                                            &list_id,
                                            &title,
                                            &rank,
                                        ).build("yougen");
                                        state_store.write().append_raw_operation(
                                            op.operation_id.clone(),
                                            Some(space.clone()),
                                            json!({
                                                "kind": "cx.list.create",
                                                "operation": op,
                                                "write_state": "queued",
                                            }),
                                        );
                                        board_status.set(format!("queued list create for {title}"));
                                        new_column_title.set(String::new());
                                    }
                                }
                            },
                            "Add List"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "replay-board-queue",
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    replay_first_event(
                                        base.clone(),
                                        token,
                                        sync_cursor,
                                        repo_state,
                                        state_store,
                                        write_records,
                                        board_status,
                                        event_write_ready,
                                    );
                                }
                            },
                            "Replay Queue"
                        }
                    }
                }
            }

            div { class: "board-grid", "data-testid": "kanban-board-grid",
                for column in columns().iter() {
                    div {
                        class: "event board-column",
                        "data-testid": "kanban-column",
                        div { class: "event-head",
                            span { class: "space-title", "{column.title}" }
                            span { "rank {column.rank} / {column.cards.len()}" }
                        }

                for card in &column.cards {
                            div {
                                class: "event board-card",
                                "data-testid": "kanban-card",
                                onclick: {
                                    let c = card.clone();
                                    move |_| selected_card.set(Some(c.clone()))
                                },
                                div { class: "event-head",
                                    span { class: "space-title", "{card.title}" }
                                    span { class: card.state.class_name(), "{card.state.label()}" }
                                }
                                div { class: "actions",
                                    for label in &card.labels {
                                        span { class: "badge", "{label}" }
                                    }
                                }
                                div { class: "muted", "{card.description}" }
                                div { class: "space-meta", "assignee {card.assignee} / due {card.due}" }
                                div { class: "actions",
                                    span { class: "badge blue", "Discussion: {card.primary_flow}" }
                                if card.locked_flow.is_some() {
                                        span { class: "badge amber", "Locked discussion hidden" }
                                    }
                                }
                            }
                        }

                        if adding_card_to() == Some(column.id.clone()) {
                            div { class: "workflow-form",
                                input {
                                    "data-testid": "new-card-title-input",
                                    value: "{new_card_title}",
                                    placeholder: "Card title",
                                    oninput: move |evt| new_card_title.set(evt.value()),
                                }
                                div { class: "actions",
                                    button {
                                        class: "primary",
                                        "data-testid": "save-card-button",
                                        onclick: {
                                            let col_id = column.id.clone();
                                            let space = selected_space.clone();
                                            let actor = account_did.clone();
                                            move |_| {
                                                let title = new_card_title().trim().to_owned();
                                                if title.is_empty() {
                                                    return;
                                                }
                                                let flow_id = format!("cx:flow:{}", uuid_v8());
                                                let rank = format!("r{}", chrono::Utc::now().timestamp_millis());
                                                let card = KanbanCard {
                                                    id: flow_id.clone(),
                                                    title: title.clone(),
                                                    description: "New local card waiting for reducer receipt.".to_owned(),
                                                    labels: vec!["draft".to_owned()],
                                                    assignee: "yougen".to_owned(),
                                                    due: "unscheduled".to_owned(),
                                                    primary_flow_id: "cx:flow:launch-discussion".to_owned(),
                                                    primary_flow: "Launch discussion".to_owned(),
                                                    linked_flows: vec![FlowLink {
                                                        flow_id: "cx:flow:launch-discussion".to_owned(),
                                                        name: "Launch board discussion".to_owned(),
                                                        access_state: DiscussionAccessState::Readable,
                                                    }],
                                                    locked_flow: None,
                                                    external_visibility: "Not shared externally".to_owned(),
                                                    history_visibility: "board default".to_owned(),
                                                    activity_hint: "Activity will populate after the first accepted event.".to_owned(),
                                                    audit_hint: "Event Envelope queued locally until cx.events.submit is ready.".to_owned(),
                                                    state: CardState::Queued,
                                                };
                                                if let Some(col) = columns.write().iter_mut().find(|c| c.id == col_id) {
                                                    col.cards.push(card);
                                                }
                                                let event = cx_ops::flow_create_event(
                                                    &space,
                                                    &actor,
                                                    &col_id,
                                                    &flow_id,
                                                    &title,
                                                    "card",
                                                    &rank,
                                                )
                                                .auth_ref("cx:capability:board.write")
                                                .build("yougen");
                                                persist_board_event(
                                                    state_store,
                                                    &space,
                                                    &event,
                                                    CardState::Queued,
                                                );
                                                write_records.write().push(BoardWriteRecord {
                                                    state: CardState::Queued,
                                                    event,
                                                    note: "queued locally; replay when event write plane is ready".to_owned(),
                                                });
                                                board_status.set(format!("queued card create event for {title}"));
                                                new_card_title.set(String::new());
                                                adding_card_to.set(None);
                                            }
                                        },
                                        "Add"
                                    }
                                    button {
                                        class: "secondary",
                                        onclick: move |_| adding_card_to.set(None),
                                        "Cancel"
                                    }
                                }
                            }
                        } else {
                            div { class: "actions",
                                button {
                                    class: "secondary",
                                    "data-testid": "add-card-button",
                                    onclick: {
                                        let col_id = column.id.clone();
                                        move |_| adding_card_to.set(Some(col_id.clone()))
                                    },
                                    "+ Add Card"
                                }
                            }
                        }
                    }
                }
            }

            div { class: "event", "data-testid": "board-offline-queue",
                div { class: "event-head", span { "Event Envelope Queue" } span { "{write_records().len()} event(s)" } }
                div { class: "muted", "data-testid": "board-status", "{board_status}" }
                for record in write_records() {
                    div { class: "event", "data-testid": "board-event-record",
                        div { class: "event-head",
                            span { "{record.event.event_type}" }
                            span { class: record.state.class_name(), "{record.state.label()}" }
                        }
                        div { class: "muted", "event_id {record.event.event_id}" }
                        div { class: "muted", "actor_seq {record.event.actor_seq} / hlc {record.event.hlc}" }
                        div { class: "muted", "auth_refs {record.event.auth_refs.join(\", \")}" }
                        div { class: "muted", "schema {record.event.schema_profile} / reducer {record.event.reducer_profile}" }
                        div { class: "muted", "{record.note}" }
                    }
                }
                if write_records().is_empty() {
                    div { class: "muted", "No local board events queued." }
                }
            }

            if let Some(ref card) = selected_card() {
                div { class: "event card-detail-drawer", "data-testid": "card-detail-modal",
                    div { class: "event-head",
                        span { "Card Detail" }
                        span { "{card.id} / {card.state.label()}" }
                    }
                    div { class: "space-title", "{card.title}" }
                    div { class: "muted", "{card.description}" }
                    div { class: "actions",
                        for label in &card.labels {
                            span { class: "badge", "{label}" }
                        }
                        span { class: card.state.class_name(), "{card.state.label()}" }
                    }
                    div { class: "event", "data-testid": "card-discussion-boundary",
                        div { class: "event-head",
                            span { "Discussions" }
                            span { "card visibility != discussion visibility" }
                        }
                        div { class: "space-meta", "Primary discussion" }
                        div { class: "actions",
                            span { class: "badge blue", "{card.primary_flow}" }
                            Link {
                                class: "secondary",
                                "data-testid": "open-primary-discussion",
                                to: Route::ChatSpace { space_id: selected_space.clone() },
                                "Open Discussion"
                            }
                        }
                        div { class: "space-meta", "Linked discussions" }
                        div { class: "actions",
                            for flow in &card.linked_flows {
                                span { class: flow.access_state.class_name(), "{flow.name} / {flow.access_state.label()}" }
                            }
                        }
                        if let Some(locked_flow) = &card.locked_flow {
                            div { class: "space-meta", "Locked Discussion" }
                            div { class: "event error-banner", "data-testid": "locked-discussion-fail-closed",
                                div { class: "event-head", span { "Hidden by policy" } span { "fail-closed" } }
                                div { class: "muted", "Flow/discussion name and members are not disclosed. Opaque ref: {locked_flow.flow_id_hash}" }
                                div { class: "muted", "{locked_flow.reason}" }
                            }
                        }
                    }
                    div { class: "event",
                        div { class: "event-head",
                            span { "Visibility" }
                            span { "external / history" }
                        }
                        div { class: "muted", "External: {card.external_visibility}" }
                        div { class: "muted", "History: {card.history_visibility}" }
                    }
                    div { class: "event",
                        div { class: "event-head",
                            span { "Activity / Audit" }
                            span { "projection hints" }
                        }
                        div { class: "muted", "{card.activity_hint}" }
                        div { class: "muted", "{card.audit_hint}" }
                    }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "queue-link-discussion-event",
                            onclick: {
                                let card_id = card.id.clone();
                                let branch_id = card.primary_flow_id.clone();
                                let space = selected_space.clone();
                                let actor = account_did.clone();
                                move |_| {
                                    let event = cx_ops::flow_branch_member_event(
                                        &space,
                                        &actor,
                                        &card_id,
                                        "discussion",
                                        &branch_id,
                                        true,
                                    )
                                    .auth_ref("cx:capability:flow.branch.member")
                                    .build("yougen");
                                    persist_board_event(state_store, &space, &event, CardState::Queued);
                                    write_records.write().push(BoardWriteRecord {
                                        state: CardState::Queued,
                                        event,
                                        note: "flow branch member queued; branch ACL remains independent".to_owned(),
                                    });
                                    board_status.set("queued cx.flow.branch.member event".to_owned());
                                }
                            },
                            "Queue flow branch member"
                        }
                        button {
                            class: "secondary",
                            onclick: move |_| selected_card.set(None),
                            "Close"
                        }
                    }
                }
            }
        }
    }
}

fn replay_first_event(
    base_url: String,
    token: Signal<String>,
    mut sync_cursor: Signal<String>,
    mut repo_state: Signal<String>,
    mut state_store: Signal<LocalStateStore>,
    mut write_records: Signal<Vec<BoardWriteRecord>>,
    mut board_status: Signal<String>,
    event_write_ready: bool,
) {
    if !event_write_ready {
        let mut records = write_records.write();
        if let Some(record) = records
            .iter_mut()
            .find(|record| record.state == CardState::Queued)
        {
            record.state = CardState::SoftFailed;
            record.note = "server does not advertise cx.events.submit yet".to_owned();
            board_status.set("soft_failed: cx.events.submit unavailable".to_owned());
        } else {
            board_status.set("no queued board event to replay".to_owned());
        }
        return;
    }

    let Some((idx, event)) = write_records
        .read()
        .iter()
        .enumerate()
        .find(|(_, record)| record.state == CardState::Queued)
        .map(|(idx, record)| (idx, record.event.clone()))
    else {
        board_status.set("no queued board event to replay".to_owned());
        return;
    };

    write_records.write()[idx].state = CardState::Submitted;
    write_records.write()[idx].note = "submitted to cx.events.submit".to_owned();
    board_status.set(format!("submitted {}", event.event_id));
    let api_token = token();
    let wait_for = active_sync_token(&sync_cursor());
    spawn(async move {
        match authed_api_with_sync(&base_url, api_token, wait_for) {
            Ok(api) => match api.submit_event(&event).await {
                Ok(response) => {
                    if let Some(record) = write_records.write().get_mut(idx) {
                        record.state = CardState::Accepted;
                        record.note = format!("accepted reducer receipt {}", response.status);
                    }
                    if let Some(sync) = response.sync_token {
                        sync_cursor.set(sync.clone());
                        state_store.write().save_sync_cursor(sync);
                    }
                    if let Some(frontier) = response.accepted_frontier.last() {
                        repo_state.set(frontier.clone());
                    }
                    board_status.set(format!("accepted {}", response.event_id));
                }
                Err(error) => {
                    if let Some(record) = write_records.write().get_mut(idx) {
                        record.state = CardState::Quarantined;
                        record.note = format!("submit failed: {error}");
                    }
                    board_status.set(format!("quarantined event: {error}"));
                }
            },
            Err(error) => board_status.set(format!("invalid server URL: {error}")),
        }
    });
}

fn persist_board_event(
    mut state_store: Signal<LocalStateStore>,
    selected_space: &str,
    event: &EventEnvelope,
    state: CardState,
) {
    state_store.write().append_raw_operation(
        event.event_id.clone(),
        Some(selected_space.to_owned()),
        json!({
            "kind": event.event_type,
            "event_envelope": event,
            "write_state": state.label(),
        }),
    );
}

fn write_state_samples() -> Vec<CardState> {
    vec![
        CardState::Optimistic,
        CardState::Queued,
        CardState::Submitted,
        CardState::Accepted,
        CardState::SoftFailed,
        CardState::Quarantined,
        CardState::Conflict,
    ]
}

fn seed_columns() -> Vec<KanbanColumn> {
    vec![
        KanbanColumn {
            id: "cx:list:todo".to_owned(),
            title: "To Do".to_owned(),
            rank: "r001".to_owned(),
            cards: vec![KanbanCard {
                id: "cx:flow:legal-review".to_owned(),
                title: "Legal review for public beta".to_owned(),
                description: "Finalize external processor wording before launch checklist can move.".to_owned(),
                labels: vec!["legal".to_owned(), "beta".to_owned()],
                assignee: "Alice".to_owned(),
                due: "May 08".to_owned(),
                primary_flow_id: "cx:flow:review-discussion".to_owned(),
                primary_flow: "Review discussion".to_owned(),
                linked_flows: vec![
                    FlowLink {
                        flow_id: "cx:flow:launch-discussion".to_owned(),
                        name: "Launch board discussion".to_owned(),
                        access_state: DiscussionAccessState::Readable,
                    },
                    FlowLink {
                        flow_id: "cx:flow:external-counsel".to_owned(),
                        name: "External counsel".to_owned(),
                        access_state: DiscussionAccessState::External,
                    },
                ],
                locked_flow: Some(LockedFlow {
                    flow_id_hash: "sha256:locked-private-decision".to_owned(),
                reason: "You can see that a restricted discussion is linked, but not its name or members.".to_owned(),
                }),
                external_visibility: "External counsel discussion only".to_owned(),
                history_visibility: "joined history".to_owned(),
                activity_hint: "Activity shows discussion mentions, card moves, and message references.".to_owned(),
                audit_hint: "Audit records cx.flow.branch.member and cx.message.create without granting discussion access.".to_owned(),
                state: CardState::Synced,
            }],
        },
        KanbanColumn {
            id: "cx:list:progress".to_owned(),
            title: "In Progress".to_owned(),
            rank: "r002".to_owned(),
            cards: vec![KanbanCard {
                id: "cx:flow:onboarding-copy".to_owned(),
                title: "Onboarding copy".to_owned(),
                description: "Waiting on discussion-scoped feedback from support and docs reviewers.".to_owned(),
                labels: vec!["copy".to_owned(), "support".to_owned()],
                assignee: "Bob".to_owned(),
                due: "May 10".to_owned(),
                primary_flow_id: "cx:flow:support-discussion".to_owned(),
                primary_flow: "Support desk discussion".to_owned(),
                linked_flows: vec![FlowLink {
                    flow_id: "cx:flow:launch-discussion".to_owned(),
                    name: "Launch board discussion".to_owned(),
                    access_state: DiscussionAccessState::Readable,
                }],
                locked_flow: None,
                external_visibility: "No external discussions linked".to_owned(),
                history_visibility: "shared history".to_owned(),
                activity_hint: "Pending move is visible until the reducer accepts the board event.".to_owned(),
                audit_hint: "Audit preview will include local pending event and final reducer receipt.".to_owned(),
                state: CardState::Queued,
            }],
        },
        KanbanColumn {
            id: "cx:list:done".to_owned(),
            title: "Done".to_owned(),
            rank: "r003".to_owned(),
            cards: vec![KanbanCard {
                id: "cx:flow:security-signoff".to_owned(),
                title: "Security sign-off".to_owned(),
                description: "Projection detected a stale column head after an offline move.".to_owned(),
                labels: vec!["security".to_owned(), "reviewed".to_owned()],
                assignee: "Carol".to_owned(),
                due: "May 01".to_owned(),
                primary_flow_id: "cx:flow:security-review".to_owned(),
                primary_flow: "Security review".to_owned(),
                linked_flows: vec![FlowLink {
                    flow_id: "cx:flow:launch-discussion".to_owned(),
                    name: "Launch board discussion".to_owned(),
                    access_state: DiscussionAccessState::Readable,
                }],
                locked_flow: Some(LockedFlow {
                    flow_id_hash: "sha256:locked-incident-notes".to_owned(),
                    reason: "Incident notes require separate discussion capability.".to_owned(),
                }),
                external_visibility: "Internal discussions only".to_owned(),
                history_visibility: "restricted history".to_owned(),
                activity_hint: "Conflict banner links to the reducer result and competing event.".to_owned(),
                audit_hint: "Audit trail preserves rejected cx.flow.move with cas_conflict.".to_owned(),
                state: CardState::Conflict,
            }],
        },
    ]
}

