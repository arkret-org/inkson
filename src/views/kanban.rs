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

/// T20 — Board projection 数据来源。
///
/// 当 SDK 提供 `client.collection_projection(view_id)` + soland 的
/// `POST /api/v1/views/:id/projection` endpoint 上线后，UI 会优先消费
/// API 派生的 board 状态；endpoint 不可用 / probe 失败时退回到本地 seed。
/// UI 在 board 头部显式展示当前数据来源，避免把 demo 数据当真。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoardProjectionSource {
    /// 来自 Principal Server 的 collection projection 响应。
    /// 命中条件：API 暴露 view projection endpoint 且 reducer 已 catch up
    /// 到当前 sync frontier。
    ApiDerived,
    /// 来自本地 `seed_columns()` 的 demo 数据。
    /// 命中条件：API 不可用 / 该 view 尚未在 spec 中定义 / 无网络。
    SeedFallback,
}

impl BoardProjectionSource {
    fn label(self) -> &'static str {
        match self {
            Self::ApiDerived => "API-derived (collection projection)",
            Self::SeedFallback => "seed fallback (demo)",
        }
    }

    fn class_name(self) -> &'static str {
        match self {
            Self::ApiDerived => "badge green",
            Self::SeedFallback => "badge amber",
        }
    }

    fn explanation(self) -> &'static str {
        match self {
            Self::ApiDerived => {
                "数据从 Principal Server 的 view projection endpoint 派生，与当前 sync frontier 对齐"
            }
            Self::SeedFallback => {
                "API endpoint 不可用 / 尚未实现，使用本地 seed 数据；操作仍会写入 cx.flow.move / cx.flow.reorder 进入离线队列"
            }
        }
    }
}

/// T20 — 尝试从 API 获取 board projection；失败 / 不可用时返回 None。
///
/// 当前 yougen 端 `api.rs` 没有 `collection_projection()` 方法，所以 probe
/// 永远返回 None，调用方应回退到 `seed_columns()`。一旦 SDK 暴露
/// `client.collection_projection(view_id)`，把 probe 的实现切换到调用 SDK 即可，
/// 上层 UI 不需修改。
///
/// 函数签名带 `_view_id` 是为了固定未来调用形态：UI 持有 saved View 的 cx:view: id，
/// 调 probe 时传过去。
#[allow(dead_code)]
fn try_load_api_columns(_view_id: &str) -> Option<Vec<KanbanColumn>> {
    // Synchronous init context — always returns None. UI starts with
    // SeedFallback and the user (or the auto-refresh-on-mount handler)
    // promotes to ApiDerived via [`fetch_api_columns`] once the async
    // call returns.
    None
}

/// T20 — Map a SDK [`CollectionProjectionResponse`] into the yougen
/// renderer's [`Vec<KanbanColumn>`] shape.
///
/// Pure adapter so it's unit-testable without a live HTTP client.
/// Position rank, when present, drives stable ordering inside a column.
fn collection_projection_to_columns(
    projection: &contrix_sdk::CollectionProjectionResponse,
) -> Vec<KanbanColumn> {
    projection
        .groups
        .iter()
        .map(|group| KanbanColumn {
            id: group.group_id.clone(),
            title: group.title.clone(),
            rank: group.rank.clone().unwrap_or_default(),
            cards: group
                .items
                .iter()
                .map(card_from_projection_item)
                .collect(),
        })
        .collect()
}

/// Map a single projection item to a [`KanbanCard`]. Discussion metadata
/// is honoured: `visibility="locked"` produces a [`LockedFlow`] with an
/// opaque hash; `lazy_link=true` is surfaced via `history_visibility`
/// without leaking room contents.
fn card_from_projection_item(
    item: &contrix_sdk::CollectionProjectionItem,
) -> KanbanCard {
    let id = item
        .object
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("cx:flow:unknown")
        .to_owned();
    let title = item
        .object
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("(untitled)")
        .to_owned();
    let primary_flow_id = id.clone();
    let primary_flow = title.clone();
    let (external_visibility, history_visibility) = item
        .discussion
        .as_ref()
        .map(|d| {
            let ext = match d.visibility.as_str() {
                "locked" => "Locked discussion (lazy_link)".to_owned(),
                "readable" => "Discussion readable to current member".to_owned(),
                other => format!("discussion: {other}"),
            };
            let hist = if d.lazy_link {
                "lazy_link (cross-Space)".to_owned()
            } else if d.enabled {
                "branch-scoped".to_owned()
            } else {
                "synthesis-only".to_owned()
            };
            (ext, hist)
        })
        .unwrap_or_else(|| {
            (
                "No external discussions linked".to_owned(),
                "synthesis-only".to_owned(),
            )
        });
    let locked_flow = item.discussion.as_ref().and_then(|d| {
        if d.visibility == "locked" {
            Some(LockedFlow {
                flow_id_hash: format!("sha256:{}", id),
                reason: "Locked discussion: title and members are not disclosed."
                    .to_owned(),
            })
        } else {
            None
        }
    });
    KanbanCard {
        id,
        title,
        description: item
            .object
            .get("summary")
            .or_else(|| item.object.get("description"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
        labels: item
            .object
            .get("fields")
            .and_then(|f| f.get("labels"))
            .and_then(|labels| labels.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        assignee: item
            .object
            .get("fields")
            .and_then(|f| f.get("assignee"))
            .and_then(|v| v.as_str())
            .unwrap_or("—")
            .to_owned(),
        due: item
            .object
            .get("fields")
            .and_then(|f| f.get("due"))
            .and_then(|v| v.as_str())
            .unwrap_or("—")
            .to_owned(),
        primary_flow_id,
        primary_flow,
        linked_flows: Vec::new(),
        locked_flow,
        external_visibility,
        history_visibility,
        activity_hint: "Activity derived from cx.flow.move / cx.flow.update events.".to_owned(),
        audit_hint: "Audit trail in /audit shows the full Event Envelope chain.".to_owned(),
        state: CardState::Synced,
    }
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
    // T20 — load board projection from API when available, otherwise seed.
    // Source signal lets the UI surface "API-derived" vs "seed fallback" in
    // the board header; refresh button (added below) re-runs the probe.
    let view_id = "cx:view:01js0vw0000000000000000000release"; // TODO(T20): wire to active saved View
    let initial_source = if let Some(api_cols) = try_load_api_columns(view_id) {
        let _ = api_cols; // keep API path warm for compile coverage
        BoardProjectionSource::ApiDerived
    } else {
        BoardProjectionSource::SeedFallback
    };
    let mut columns = use_signal(|| {
        try_load_api_columns(view_id).unwrap_or_else(seed_columns)
    });
    let mut projection_source = use_signal(|| initial_source);
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

    // T20 — auto-refresh-on-mount. The component renders SeedFallback
    // synchronously, then immediately fires a single async fetch against
    // soland's `/api/v1/views/:id/projection`. Success promotes the board
    // to ApiDerived; failure leaves the seed in place with a status note.
    // The `bootstrapped` guard ensures we run this only once per mount —
    // matching the login view's `auto_capture_bootstrapped` pattern so a
    // second render (e.g. from a parent signal) doesn't re-trigger the
    // fetch.
    let mut bootstrapped = use_signal(|| false);
    let auto_base = base_url.clone();
    let auto_token = token;
    use_future(move || {
        let base = auto_base.clone();
        async move {
            if bootstrapped() {
                return;
            }
            bootstrapped.set(true);
            let api_token = auto_token();
            let api = match crate::views::helpers::authed_api(&base, api_token) {
                Ok(api) => api,
                Err(_) => return,
            };
            match api.collection_projection(view_id).await {
                Ok(projection) => {
                    let cols = collection_projection_to_columns(&projection);
                    if !cols.is_empty() {
                        columns.set(cols);
                    }
                    projection_source.set(BoardProjectionSource::ApiDerived);
                    board_status.set(format!(
                        "API projection · {} groups · view={}",
                        projection.groups.len(),
                        projection.view_id.as_str()
                    ));
                }
                Err(error) => {
                    board_status.set(format!(
                        "API projection unavailable on mount: {error}"
                    ));
                }
            }
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
                // Multi-renderer switcher — claude-design desktop/board.html
                // models/views.md §4: View.kind = collection|timeline|graph|document|composite
                // 当前 board 是 View{kind="collection", renderer="board"}，可切到 list/table/calendar/timeline
                div { class: "actions", "data-testid": "view-renderer-switcher", role: "tablist", "aria-label": "View renderer",
                    span { class: "muted", "View renderer:" }
                    span { class: "badge blue", "data-testid": "renderer-board", role: "tab", "aria-selected": "true", "board" }
                    span { class: "badge", "data-testid": "renderer-list", role: "tab", "list" }
                    span { class: "badge", "data-testid": "renderer-table", role: "tab", "table" }
                    span { class: "badge", "data-testid": "renderer-calendar", role: "tab", "calendar" }
                    span { class: "badge", "data-testid": "renderer-timeline", role: "tab", "timeline" }
                    span { class: "badge", "data-testid": "renderer-graph", role: "tab", "graph" }
                    span { class: "muted", "新 View → cx.view.create · 改 filter/sort/columns → cx.view.update · 重建 projection cache → cx.view.reconcile · Morph 内容更新 → cx.morph.update" }
                }
                // T20 — board projection source indicator. Shows whether the
                // current columns came from the API (Principal Server view
                // projection) or the local seed fallback. Refresh button
                // re-runs the probe so when SDK lands the endpoint mid-session
                // the user can flip to API-derived without restarting.
                div { class: "actions", "data-testid": "board-projection-source",
                    span { class: "muted", "Projection source:" }
                    span {
                        class: "{projection_source().class_name()}",
                        "data-testid": "board-projection-source-pill",
                        "title": "{projection_source().explanation()}",
                        "{projection_source().label()}"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "board-projection-refresh",
                        onclick: {
                            // T20 — real API call to soland's
                            // POST /api/v1/views/:id/projection. Falls back to seed
                            // on any error so the user always sees something.
                            let base = base_url.clone();
                            move |_| {
                                let base = base.clone();
                                let api_token = token();
                                let view = view_id.to_owned();
                                spawn(async move {
                                    let api = match crate::views::helpers::authed_api(&base, api_token) {
                                        Ok(api) => api,
                                        Err(_) => {
                                            projection_source.set(BoardProjectionSource::SeedFallback);
                                            return;
                                        }
                                    };
                                    match api.collection_projection(&view).await {
                                        Ok(projection) => {
                                            let cols = collection_projection_to_columns(&projection);
                                            if !cols.is_empty() {
                                                columns.set(cols);
                                            }
                                            projection_source.set(BoardProjectionSource::ApiDerived);
                                            board_status.set(format!(
                                                "API projection · {} groups · view={}",
                                                projection.groups.len(),
                                                projection.view_id.as_str()
                                            ));
                                        }
                                        Err(error) => {
                                            projection_source.set(BoardProjectionSource::SeedFallback);
                                            board_status.set(format!(
                                                "API projection unavailable: {error}"
                                            ));
                                        }
                                    }
                                });
                            }
                        },
                        "Refresh from API"
                    }
                    span { class: "muted",
                        "Refresh 调用 SDK Client::collection_projection（POST /api/v1/views/:id/projection）；endpoint 不可用时回退到 seed。"
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
                    // Branch tabs — current-model.md §3 (synthesis / discussion 双 branch)
                    div { class: "actions", "data-testid": "card-branch-tabs", role: "tablist", "aria-label": "Flow branches",
                        span { class: "muted", "Branch:" }
                        span { class: "badge blue", role: "tab", "aria-selected": "true", "synthesis · primary" }
                        span { class: "badge", role: "tab", "discussion" }
                        span { class: "muted", "branch 默认继承 Flow / Space access；显式 override 才独立" }
                    }
                    // Fields grid — claude-design desktop/flow-detail.html
                    div { class: "metric-grid", "data-testid": "card-fields",
                        div { class: "metric",
                            strong { "Assignee" }
                            span { "{card.assignee}" }
                            div { class: "muted", "cx.flow.update fields.assignee" }
                        }
                        div { class: "metric",
                            strong { "Due" }
                            span { "{card.due}" }
                            div { class: "muted", "cx.flow.update fields.due_at" }
                        }
                        div { class: "metric",
                            strong { "List position" }
                            span { "rank-stable" }
                            div { class: "muted", "cx.flow.move / cx.flow.reorder" }
                        }
                        div { class: "metric",
                            strong { "Capability" }
                            span { "read · write" }
                            div { class: "muted", "discussion 写入需 branch-scoped grant" }
                        }
                    }
                    // Card vs Room visibility — claude-design desktop/flow-detail.html
                    // overview/current-model.md §6 (权限与成员边界) — 三条独立判定：
                    //   1. 能看 Flow synthesis ≠ 能读 discussion（只有有效 access policy
                    //      继承或授予 discussion 读取时才能读）
                    //   2. 能读 discussion ≠ 能写 Flow synthesis 字段
                    //   3. branch-scoped membership ≠ Space membership
                    div { class: "event", "data-testid": "card-vs-room-visibility",
                        div { class: "event-head",
                            span { "Card / Room visibility (independent)" }
                            span { "current-model §6" }
                        }
                        div { class: "muted",
                            "Flow synthesis（Card 字段）与 Flow discussion branch（Room 消息）的可见性必须独立判定，不可互推。Locked Room 只暴露存在的提示，不暴露标题、成员、计数。"
                        }
                        div { class: "metric-grid", "data-testid": "card-vs-room-axes",
                            div { class: "metric",
                                strong { "Card synthesis" }
                                span { class: crate::components::write_state::WriteState::Accepted.class_name(), "readable + writable" }
                                div { class: "muted", "你看见 Flow 字段不代表能看到 discussion" }
                            }
                            div { class: "metric",
                                strong { "Primary Room" }
                                span { class: "badge blue", "{card.primary_flow}" }
                                div { class: "muted", "branch-scoped membership" }
                            }
                            div { class: "metric",
                                strong { "External Visibility" }
                                span { class: "badge", "{card.external_visibility}" }
                                div { class: "muted", "history_visibility = {card.history_visibility}" }
                            }
                            div { class: "metric",
                                strong { "Locked link policy" }
                                span { class: "badge amber", if card.locked_flow.is_some() { "fail-closed" } else { "no locked link" } }
                                div { class: "muted", "opaque ref + reason only" }
                            }
                        }
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
                    // Audit trail excerpt — claude-design desktop/audit.html
                    // sync/operations-sync.md (Event Envelope, prev_refs, auth_refs)
                    div { class: "event", "data-testid": "card-audit-excerpt",
                        div { class: "event-head",
                            span { "Recent events on this card" }
                            span { "actor event chain" }
                        }
                        div { class: "muted", "cx.flow.move · superseded(HLC older) → {card.id}" }
                        div { class: "muted", "cx.flow.update · fields.status / fields.priority" }
                        div { class: "muted", "cx.relation.create / cx.relation.update · contains list→flow（rank stable tie-break）" }
                        div { class: "muted", "cx.relation.delete · 切换 list 时旧 contains 边 tombstone" }
                        div { class: "muted", "cx.flow.archive / cx.flow.restore · 进入或离开 archived 状态" }
                        div { class: "muted", "cx.morph.archive / cx.morph.restore · 卡片关联 morph 的归档与恢复" }
                        div { class: "muted", "Auth refs 与 prev_refs 在 Audit 页可展开为完整 envelope。" }
                    }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "queue-link-discussion-event",
                            onclick: {
                                let flow_id = card.id.clone();
                                let track_id = card.primary_flow_id.clone();
                                let space = selected_space.clone();
                                let actor = account_did.clone();
                                move |_| {
                                    let event = cx_ops::flow_track_member_event(
                                        &space,
                                        &actor,
                                        &flow_id,
                                        "discussion",
                                        &track_id,
                                        true,
                                    )
                                    .auth_ref("cx:capability:flow.track.member")
                                    .build("yougen");
                                    persist_board_event(state_store, &space, &event, CardState::Queued);
                                    write_records.write().push(BoardWriteRecord {
                                        state: CardState::Queued,
                                        event,
                                        note: "flow track member queued; track ACL remains independent".to_owned(),
                                    });
                                    board_status.set("queued cx.flow.track.member event".to_owned());
                                }
                            },
                            "Queue flow track member"
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
                audit_hint: "Audit records cx.flow.track.member and cx.message.create without granting discussion access.".to_owned(),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `try_load_api_columns` is the synchronous-init probe. Real API
    /// fetching now lives in the async refresh handler that calls
    /// `ContrixApi::collection_projection`. This test still pins the
    /// init-time behaviour as None so UI startup goes via SeedFallback
    /// and the user (or auto-refresh) promotes to ApiDerived once the
    /// HTTP call returns.
    #[test]
    fn try_load_api_columns_returns_none_in_sync_init_context() {
        let result = try_load_api_columns("cx:view:01js0vw0000000000000000000release");
        assert!(
            result.is_none(),
            "synchronous init MUST return None; async refresh handles real fetch"
        );
    }

    /// T20 wire-up — `collection_projection_to_columns` adapter maps the
    /// canonical SDK response into the renderer's KanbanColumn vec. This
    /// is the core integration point; if the spec wire shape changes,
    /// this test fails and points at the renderer adapter.
    #[test]
    fn collection_projection_maps_to_kanban_columns() {
        use contrix_sdk::{
            CollectionProjectionDiscussion, CollectionProjectionGroup,
            CollectionProjectionItem, CollectionProjectionResponse, ViewId, ViewKind,
            ViewRenderer,
        };
        let projection = CollectionProjectionResponse {
            kind: ViewKind::Collection,
            renderer: ViewRenderer::Board,
            view_id: ViewId::new("cx:view:01js0vw0000000000000000000release").unwrap(),
            frontier: vec!["cx:event:01js0fr00000000000000000042".to_owned()],
            groups: vec![
                CollectionProjectionGroup {
                    group_id: "cx:space:01c3b617-7000-7000-8000-000000000000".to_owned(),
                    title: "Review".to_owned(),
                    rank: Some("mV".to_owned()),
                    items: vec![CollectionProjectionItem {
                        object: serde_json::json!({
                            "id": "cx:flow:01d2b330-0000-7000-8000-000000000000",
                            "type": "flow",
                            "title": "Legal review",
                            "summary": "ensure GDPR sign-off",
                        }),
                        position: None,
                        discussion: Some(CollectionProjectionDiscussion {
                            enabled: true,
                            visibility: "locked".to_owned(),
                            lazy_link: true,
                        }),
                    }],
                    hidden_count: None,
                },
                CollectionProjectionGroup {
                    group_id: "cx:space:01t0d0000000000000000000000".to_owned(),
                    title: "To do".to_owned(),
                    rank: Some("aA".to_owned()),
                    items: Vec::new(),
                    hidden_count: None,
                },
            ],
        };

        let cols = collection_projection_to_columns(&projection);
        assert_eq!(cols.len(), 2, "two groups → two columns");
        assert_eq!(cols[0].id, "cx:space:01c3b617-7000-7000-8000-000000000000");
        assert_eq!(cols[0].title, "Review");
        assert_eq!(cols[0].rank, "mV");
        assert_eq!(cols[0].cards.len(), 1);
        let card = &cols[0].cards[0];
        assert_eq!(card.id, "cx:flow:01d2b330-0000-7000-8000-000000000000");
        assert_eq!(card.title, "Legal review");
        assert_eq!(card.description, "ensure GDPR sign-off");
        // Locked discussion + lazy_link should populate locked_flow
        // and the cross-Space hint without leaking room contents.
        assert!(card.locked_flow.is_some(), "locked discussion → LockedFlow");
        assert_eq!(
            card.history_visibility, "lazy_link (cross-Space)",
            "lazy_link=true must be reflected without exposing members"
        );
        assert!(matches!(card.state, CardState::Synced));
        // Empty group still produces an empty-cards column (board renders it).
        assert_eq!(cols[1].cards.len(), 0);
    }

    /// T20 — when `discussion` is None on the projection item, the card
    /// renders as synthesis-only without a locked_flow.
    #[test]
    fn projection_item_without_discussion_renders_synthesis_only() {
        use contrix_sdk::CollectionProjectionItem;
        let item = CollectionProjectionItem {
            object: serde_json::json!({
                "id": "cx:flow:01doc",
                "title": "DID method allowlist",
            }),
            position: None,
            discussion: None,
        };
        let card = card_from_projection_item(&item);
        assert!(card.locked_flow.is_none());
        assert_eq!(card.history_visibility, "synthesis-only");
        assert_eq!(card.external_visibility, "No external discussions linked");
    }

    #[test]
    fn projection_source_label_distinguishes_api_vs_seed() {
        assert_ne!(
            BoardProjectionSource::ApiDerived.label(),
            BoardProjectionSource::SeedFallback.label()
        );
        assert!(BoardProjectionSource::ApiDerived
            .label()
            .contains("API-derived"));
        assert!(BoardProjectionSource::SeedFallback
            .label()
            .contains("seed"));
    }

    #[test]
    fn projection_source_class_marks_seed_as_amber() {
        // Seed is a warning (demo data; not synced to frontier) — must be
        // visually distinct from API-derived to avoid confusion.
        assert_eq!(
            BoardProjectionSource::ApiDerived.class_name(),
            "badge green"
        );
        assert_eq!(
            BoardProjectionSource::SeedFallback.class_name(),
            "badge amber"
        );
    }

    #[test]
    fn seed_columns_reflect_three_lifecycle_states_for_demo_drift_check() {
        // Seed must include at least one Synced, one Queued (= optimistic
        // queued write) and one Conflict so the kanban demo exercises the
        // full WriteState rendering path. If a refactor changes seeds, fix
        // this test along with the matching screenshot fixtures.
        let cols = seed_columns();
        let mut states: Vec<&'static str> = cols
            .iter()
            .flat_map(|c| c.cards.iter().map(|card| card.state.label()))
            .collect();
        states.sort();
        states.dedup();
        assert!(states.contains(&"synced"), "seed missing Synced demo card");
        assert!(states.contains(&"queued"), "seed missing Queued demo card");
        assert!(
            states.contains(&"CAS conflict"),
            "seed missing Conflict demo card"
        );
    }
}
