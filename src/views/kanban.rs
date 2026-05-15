use dioxus::prelude::*;
use dioxus_router::Link;
use serde_json::json;

use crate::{
    components::HelpTip,
    hlc::Hlc,
    local_state::{LocalStateStore, MoveSubmissionState},
    move_builder::{
        FlowPositionEffect, FlowPositionExpectation, UnsignedMove, build_flow_position_cas_move,
        build_flow_position_move, did_key_verification_method, flow_position_cell_id,
        sign_unsigned_move,
    },
    operation::uuid_v7,
    rank::{RankError, rank_for_drop},
    routes::Route,
    views::helpers::{authed_api, with_authed_api},
};

/// Fallback Board Place id used by the demo seed data. Production
/// kanban routes resolve this from the URL / saved View; until that
/// wiring lands the seed columns and offline-queued Moves share this
/// constant so CAS cell keys are stable across reloads.
const DEMO_BOARD_PLACE_ID: &str = "cx:place:01launch-board0000000000000000";

/// Maximum number of times a CAS-conflicted Move is automatically
/// rebased + re-submitted before the UI surfaces it as Quarantined and
/// requires manual review. Three is enough to absorb typical
/// two-actor races without spinning indefinitely if the cell is hot.
const MAX_CONFLICT_REBASE_ATTEMPTS: u8 = 3;

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
    /// The card's current rank inside its column. This is the local
    /// mirror of the `cx.component.flow.position.v1` cell's `rank`
    /// field and seeds the `expected_position` of any subsequent
    /// `cx.flow.move` / `cx.flow.reorder` Move. When the projection
    /// refreshes (server-side cell update), this must be re-synced.
    rank: String,
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

/// Snapshot of the card-being-dragged's pre-move state. The cas-register
/// model in [`operations-sync.md` §9.1](../../contrix-spec/spec/v1/zh/sync/operations-sync.md)
/// requires the source `(list_place_id, rank)` to seed `head_eq` on the
/// resulting `cx.flow.move` / `cx.flow.reorder` Move. We capture it on
/// `ondragstart` so the drop handler doesn't have to re-derive it from
/// the column state (which may have been mutated optimistically in the
/// meantime).
#[derive(Clone, Debug, PartialEq)]
struct DraggedCard {
    card_id: String,
    from_column_id: String,
    from_rank: String,
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

/// Round 24 (F1): board write records now track a Move pipeline submission
/// instead of an EventEnvelope. The Move's canonical body lives in
/// `cell_id` + `effect_summary` (string preview); `move_id` is the
/// content-addressed `cx:move:sha256:...` id. `kind` mirrors the
/// MoveSubmissionState classifier (`cx.list.create` / `cx.flow.create` /
/// `cx.flow.position`) so the tracker UI can decorate state pills.
///
/// `signed_move_json` is the typed [`contrix_sdk::Move`] serialised to
/// JSON. We persist it on the queued record so that Replay can re-POST
/// the exact same signed payload — server-side dedup is content-addressed
/// on `move_id`, making replay idempotent. None on legacy records that
/// were built via the old envelope path; those replay through the
/// kind+value reconstruction fallback in [`replay_first_move`].
#[derive(Clone, Debug, PartialEq)]
struct BoardWriteRecord {
    state: CardState,
    move_id: String,
    kind: String,
    cell_id: String,
    effect_summary: String,
    anchor_ref: String,
    hlc: String,
    note: String,
    signed_move_json: Option<serde_json::Value>,
    /// Number of CAS-conflict rebase attempts so far. The submit path
    /// auto-retries up to [`MAX_CONFLICT_REBASE_ATTEMPTS`] before
    /// surfacing the record as Quarantined for manual review.
    rebase_attempts: u8,
}

/// T20 — Where the board projection data comes from.
///
/// Once `client.collection_projection(view_id)` ships in the SDK and soland's
/// `POST /api/v1/views/:id/projection` endpoint goes live, the UI will prefer
/// the API-derived board state; if the endpoint is unavailable or the probe
/// fails, the UI falls back to local seed data. The board header surfaces
/// the current source explicitly so demo data is never mistaken for real
/// data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoardProjectionSource {
    /// Sourced from the Principal Server's collection projection response.
    /// Conditions: the API exposes the view-projection endpoint AND the
    /// reducer has caught up to the current sync frontier.
    ApiDerived,
    /// Sourced from local `seed_columns()` demo data. Conditions: API
    /// unavailable, the view is not yet defined in the spec, or the client
    /// is offline.
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
                "Data is derived from the Principal Server view-projection endpoint and aligned with the current sync frontier."
            }
            Self::SeedFallback => {
                "The view-projection endpoint is unavailable, so we are showing local seed data. Drag-and-drop edits still emit cx.flow.move / cx.flow.reorder and queue offline."
            }
        }
    }
}

/// T20 — Attempt to load the board projection from the API; return `None`
/// on failure or when the endpoint is unavailable.
///
/// The current `api.rs` does not expose a `collection_projection()` method,
/// so this probe always returns `None` and the caller falls back to
/// `seed_columns()`. Once the SDK exposes `client.collection_projection
/// (view_id)`, swap the probe's body to call the SDK; the surrounding UI
/// does not need to change.
///
/// The `_view_id` parameter is reserved so the future signature is stable:
/// the UI holds the saved View's `cx:view:` id and threads it in when calling
/// the probe.
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
            cards: group.items.iter().map(card_from_projection_item).collect(),
        })
        .collect()
}

/// Map a single projection item to a [`KanbanCard`]. Discussion metadata
/// is honoured: `visibility="locked"` produces a [`LockedFlow`] with an
/// opaque hash; `lazy_link=true` is surfaced via `history_visibility`
/// without leaking room contents.
fn card_from_projection_item(item: &contrix_sdk::CollectionProjectionItem) -> KanbanCard {
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
                reason: "Locked discussion: title and members are not disclosed.".to_owned(),
            })
        } else {
            None
        }
    });
    // Per CollectionProjectionItem.position.rank: this is the
    // card's authoritative rank in the column from the API's view of
    // the cas-register cell. Falls back to "" so the seed-conversion
    // path still works when the projection omits position metadata
    // (e.g. group-level rank only).
    let rank = item
        .position
        .as_ref()
        .map(|p| p.rank.clone())
        .unwrap_or_default();
    KanbanCard {
        id,
        rank,
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
    selected_space_scope: Vec<String>,
    sync_cursor: Signal<String>,
    frontier_state: Signal<String>,
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
    let mut columns = use_signal(|| try_load_api_columns(view_id).unwrap_or_else(seed_columns));
    let mut projection_source = use_signal(|| initial_source);
    let mut new_column_title = use_signal(String::new);
    let mut new_card_title = use_signal(String::new);
    let mut adding_card_to = use_signal(|| Option::<String>::None);
    let mut selected_card = use_signal(|| Option::<KanbanCard>::None);
    let mut dragging_card = use_signal(|| Option::<DraggedCard>::None);
    let write_records = use_signal(Vec::<BoardWriteRecord>::new);
    let mut board_status = use_signal(|| {
        if event_write_ready {
            "Event write plane ready".to_owned()
        } else {
            "Event write plane unavailable; board writes queue locally".to_owned()
        }
    });
    let scope_count = selected_space_scope.len().max(1);
    let scope_label = if scope_count > 1 {
        format!("{scope_count} Spaces in scope")
    } else {
        "Current Space".to_owned()
    };

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
            match with_authed_api(&base, api_token, |api| async move {
                api.collection_projection(view_id).await
            })
            .await
            {
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
                Err(err) => {
                    board_status.set(format!(
                        "API projection unavailable on mount: {}",
                        err.display()
                    ));
                }
            }
        }
    });

    rsx! {
        div { class: "timeline", "data-testid": "kanban-panel",
            div { class: "event board-header",
                div { class: "event-head",
                    span { {crate::i18n::tr("kanban.board_header")} }
                    span { "{scope_label} / writes to {selected_space}" }
                }
                div { class: "space-title", {crate::i18n::tr("kanban.board_title")} }
                div { class: "muted",
                    {crate::i18n::tr("kanban.board_hint")}
                }
                div { class: "actions", "data-testid": "board-write-states",
                    for state in write_state_samples() {
                        span { class: state.class_name(), "{state.label()}" }
                    }
                }
                // Multi-renderer switcher — claude-design desktop/board.html
                // models/views.md §4: View.kind = collection|timeline|graph|document|composite
                // The current board is View{kind="collection", renderer="board"} and can switch to list/table/calendar/timeline.
                div { class: "actions", "data-testid": "view-renderer-switcher", role: "tablist", "aria-label": "View renderer",
                    span { class: "muted", "View renderer:" }
                    span { class: "badge blue", "data-testid": "renderer-board", role: "tab", "aria-selected": "true", "board" }
                    span { class: "badge", "data-testid": "renderer-list", role: "tab", "list" }
                    span { class: "badge", "data-testid": "renderer-table", role: "tab", "table" }
                    span { class: "badge", "data-testid": "renderer-calendar", role: "tab", "calendar" }
                    span { class: "badge", "data-testid": "renderer-timeline", role: "tab", "timeline" }
                    span { class: "badge", "data-testid": "renderer-graph", role: "tab", "graph" }
                    span { class: "muted", "New View → cx.view.create · Filter/sort/columns → cx.view.update · Rebuild projection cache → cx.view.reconcile · Morph content → cx.morph.update" }
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
                        "Refresh calls Client::collection_projection (POST /api/v1/views/:id/projection); when unavailable we fall back to seed data."
                    }
                }

                div { class: "metric-grid", "data-testid": "board-projection-model",
                    div { class: "metric", strong { "Board" } span { "cx:board:launch" } div { class: "muted", "View renderer: kanban" } }
                    div { class: "metric", strong { "Relation" } span { "contains" } div { class: "muted", "List contains Card by rank" } }
                    div { class: "metric", strong { "Frontier" } span { "{frontier_state}" } div { class: "muted", "CAS moves rebase from latest projection" } }
                    div { class: "metric", strong { "Write plane" } span { if event_write_ready { "cx.events.submit" } else { "queued local" } } div { class: "muted", "active writes use operation/event surfaces directly" } }
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
                                // Round 24 (F1): list-create now travels
                                // through the canonical Move pipeline. We
                                // build a `cx.component.flow.position.v1`
                                // Move whose subject is the list_id and
                                // whose value carries the list metadata
                                // (title + rank + container ref). soland's
                                // reducer treats it as a cas-register set
                                // and the position cell becomes the
                                // canonical source of truth for the list.
                                let base = base_url.clone();
                                let space = selected_space.clone();
                                move |_| {
                                    let title = new_column_title().trim().to_owned();
                                    if title.is_empty() {
                                        return;
                                    }
                                    let col_count = columns().len();
                                    let rank = format!("r{:03}", col_count + 1);
                                    let list_id = format!("cx:list:{}", uuid_v7());
                                    columns.write().push(KanbanColumn {
                                        id: list_id.clone(),
                                        title: title.clone(),
                                        rank: rank.clone(),
                                        cards: Vec::new(),
                                    });
                                    let value = json!({
                                        "kind": "list",
                                        "list_id": list_id,
                                        "title": title,
                                        "rank": rank,
                                        "container_ref": "cx:board:launch",
                                    });
                                    submit_kanban_move(
                                        base.clone(),
                                        token,
                                        space.clone(),
                                        list_id.clone(),
                                        "cx.list.create",
                                        value,
                                        state_store,
                                        write_records,
                                        board_status,
                                    );
                                    new_column_title.set(String::new());
                                }
                            },
                            "Add List"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "replay-board-queue",
                            onclick: {
                                // Round 24 (F1): replay path now resubmits
                                // a queued Move via api.submit_move (no
                                // event-envelope path).
                                let base = base_url.clone();
                                let space = selected_space.clone();
                                move |_| {
                                    replay_first_move(
                                        base.clone(),
                                        token,
                                        space.clone(),
                                        state_store,
                                        write_records,
                                        board_status,
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
                        ondragover: move |event| event.prevent_default(),
                        ondrop: {
                            // Drop landing on the column background (not on
                            // a card) lands the card at the END of the
                            // column. Drops on individual cards (handled
                            // by their own `ondrop`) land ABOVE that card.
                            let target_column_id = column.id.clone();
                            let last_rank = column.cards.last().map(|c| c.rank.clone());
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            move |event| {
                                event.prevent_default();
                                let Some(dragged) = dragging_card() else {
                                    return;
                                };
                                dragging_card.set(None);
                                let neighbours = ColumnNeighbours {
                                    prev_rank: last_rank.clone(),
                                    next_rank: None,
                                };
                                dispatch_flow_position_move(
                                    base.clone(),
                                    token,
                                    space.clone(),
                                    DEMO_BOARD_PLACE_ID.to_owned(),
                                    dragged,
                                    target_column_id.clone(),
                                    neighbours,
                                    columns,
                                    state_store,
                                    write_records,
                                    board_status,
                                );
                            }
                        },
                        div { class: "event-head",
                            span { class: "space-title", "{column.title}" }
                            span { "rank {column.rank} / {column.cards.len()}" }
                        }

                for (card_index, card) in column.cards.iter().enumerate() {
                            div {
                                class: "event board-card",
                                "data-testid": "kanban-card",
                                draggable: "true",
                                // Card-level drop target: drop on this card
                                // means "insert above this card". The
                                // column-level ondrop above handles "drop
                                // past all cards". We need both because
                                // browsers fire the drop event on the
                                // innermost matching target.
                                ondragover: move |event| event.prevent_default(),
                                ondrop: {
                                    let target_column_id = column.id.clone();
                                    let this_rank = card.rank.clone();
                                    let prev_rank = if card_index == 0 {
                                        None
                                    } else {
                                        Some(column.cards[card_index - 1].rank.clone())
                                    };
                                    let base = base_url.clone();
                                    let space = selected_space.clone();
                                    move |event| {
                                        event.prevent_default();
                                        // Stop propagation so the column's
                                        // ondrop above doesn't also fire
                                        // and double-insert at the tail.
                                        event.stop_propagation();
                                        let Some(dragged) = dragging_card() else {
                                            return;
                                        };
                                        dragging_card.set(None);
                                        let neighbours = ColumnNeighbours {
                                            prev_rank: prev_rank.clone(),
                                            next_rank: Some(this_rank.clone()),
                                        };
                                        dispatch_flow_position_move(
                                            base.clone(),
                                            token,
                                            space.clone(),
                                            DEMO_BOARD_PLACE_ID.to_owned(),
                                            dragged,
                                            target_column_id.clone(),
                                            neighbours,
                                            columns,
                                            state_store,
                                            write_records,
                                            board_status,
                                        );
                                    }
                                },
                                ondragstart: {
                                    let card_id = card.id.clone();
                                    let column_id = column.id.clone();
                                    let from_rank = card.rank.clone();
                                    move |_| {
                                        dragging_card.set(Some(DraggedCard {
                                            card_id: card_id.clone(),
                                            from_column_id: column_id.clone(),
                                            from_rank: from_rank.clone(),
                                        }));
                                    }
                                },
                                ondragend: move |_| dragging_card.set(None),
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
                                            // Round 24 (F1): card create now
                                            // submits a flow.position Move
                                            // (subject = flow_id) carrying
                                            // the canonical position record
                                            // {list_id, rank, title}. Soland's
                                            // reducer treats it as cas-register
                                            // set on the flow.position cell.
                                            let base = base_url.clone();
                                            let col_id = column.id.clone();
                                            let space = selected_space.clone();
                                            move |_| {
                                                let title = new_card_title().trim().to_owned();
                                                if title.is_empty() {
                                                    return;
                                                }
                                                let flow_id = format!("cx:flow:{}", uuid_v7());
                                                // Place the new card at the end of the column.
                                                // Look up the column's current tail rank and ask
                                                // `rank_between` for a strictly-greater rank. If
                                                // exhausted, fall back to the alphabet midpoint —
                                                // the user can trigger a rebalance from the next
                                                // failed insert.
                                                let last_rank = columns()
                                                    .iter()
                                                    .find(|c| c.id == col_id)
                                                    .and_then(|c| c.cards.last().map(|card| card.rank.clone()));
                                                let rank = rank_for_drop(
                                                    last_rank.as_deref(),
                                                    None,
                                                )
                                                .unwrap_or_else(|_| "U".to_owned());
                                                let card = KanbanCard {
                                                    id: flow_id.clone(),
                                                    rank: rank.clone(),
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
                                                    activity_hint: "Activity will populate after the first accepted Move.".to_owned(),
                                                    audit_hint: "Move record queued locally until submit_move succeeds.".to_owned(),
                                                    state: CardState::Queued,
                                                };
                                                if let Some(col) = columns.write().iter_mut().find(|c| c.id == col_id) {
                                                    col.cards.push(card);
                                                }
                                                let value = json!({
                                                    "kind": "flow",
                                                    "flow_id": flow_id,
                                                    "list_id": col_id,
                                                    "title": title,
                                                    "rank": rank,
                                                    "kind": "card",
                                                });
                                                submit_kanban_move(
                                                    base.clone(),
                                                    token,
                                                    space.clone(),
                                                    flow_id.clone(),
                                                    "cx.flow.create",
                                                    value,
                                                    state_store,
                                                    write_records,
                                                    board_status,
                                                );
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
                div { class: "event-head", span { "Move Queue" } span { "{write_records().len()} move(s)" } }
                div { class: "muted", "data-testid": "board-status", "{board_status}" }
                for record in write_records() {
                    div { class: "event", "data-testid": "board-event-record",
                        div { class: "event-head",
                            span { "{record.kind}" }
                            span { class: record.state.class_name(), "{record.state.label()}" }
                        }
                        div { class: "muted", "move_id {record.move_id}" }
                        div { class: "muted", "cell {record.cell_id} / hlc {record.hlc}" }
                        div { class: "muted", "anchor_ref {record.anchor_ref}" }
                        div { class: "muted", "effect {record.effect_summary}" }
                        div { class: "muted", "{record.note}" }
                    }
                }
                if write_records().is_empty() {
                    div { class: "muted", "No local board Moves queued." }
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
                    // Branch tabs — current-model.md §3 (synthesis / discussion dual branch)
                    div { class: "actions", "data-testid": "card-branch-tabs", role: "tablist", "aria-label": "Flow branches",
                        span { class: "muted", "Branch:" }
                        span { class: "badge blue", role: "tab", "aria-selected": "true", "synthesis · primary" }
                        span { class: "badge", role: "tab", "discussion" }
                        span { class: "muted", "Branches inherit Flow / Space access by default; only an explicit override makes them independent." }
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
                            div { class: "muted", "Discussion writes require a branch-scoped grant" }
                        }
                    }
                    // Card vs Room visibility — claude-design desktop/flow-detail.html
                    // overview/current-model.md §6 (permission and membership boundaries) —
                    // three independent decisions:
                    //   1. Seeing the Flow synthesis ≠ being able to read the discussion
                    //      (reading requires an effective access policy that inherits or
                    //      explicitly grants discussion read).
                    //   2. Reading the discussion ≠ being able to write Flow synthesis fields.
                    //   3. Branch-scoped membership ≠ Space membership.
                    div { class: "event", "data-testid": "card-vs-room-visibility",
                        div { class: "event-head",
                            span { "Card / Room visibility (independent)" }
                            span { "current-model §6" }
                            HelpTip { text: "Card field visibility (Flow synthesis) and discussion Room visibility (Flow discussion branch) are evaluated independently — one does not imply the other. A locked Room only reveals that it exists; titles, members, and counts stay hidden." }
                        }
                        div { class: "metric-grid", "data-testid": "card-vs-room-axes",
                            div { class: "metric",
                                strong { "Card synthesis" }
                                span { class: crate::components::write_state::WriteState::Accepted.class_name(), "readable + writable" }
                                div { class: "muted", "Seeing Flow fields does not imply you can see the discussion" }
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
                            div { class: "space-meta", "Locked discussion" }
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
                    // sync/operations-sync.md (Event Envelope, prev_refs, refs)
                    div { class: "event", "data-testid": "card-audit-excerpt",
                        div { class: "event-head",
                            span { "Recent events on this card" }
                            span { "actor event chain" }
                        }
                        div { class: "muted", "cx.flow.move · superseded(HLC older) → {card.id}" }
                        div { class: "muted", "cx.flow.update · fields.status / fields.priority" }
                        div { class: "muted", "cx.relation.create / cx.relation.update · contains list→flow（rank stable tie-break）" }
                        div { class: "muted", "cx.relation.delete · tombstones the prior contains edge when a card switches lists" }
                        div { class: "muted", "cx.flow.archive / cx.flow.restore · enters or leaves archived state" }
                        div { class: "muted", "cx.morph.archive / cx.morph.restore · archives or restores the morph attached to the card" }
                        div { class: "muted", "Auth refs and prev_refs expand to a full envelope on the Audit page." }
                    }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "queue-link-discussion-event",
                            onclick: {
                                // Round 24 (F1): flow track member also
                                // goes through the Move pipeline. We
                                // record a flow.position Move whose
                                // payload carries the track binding —
                                // soland's reducer treats this as a
                                // metadata update on the same cell.
                                let base = base_url.clone();
                                let flow_id = card.id.clone();
                                let track_id = card.primary_flow_id.clone();
                                let space = selected_space.clone();
                                move |_| {
                                    let value = json!({
                                        "kind": "flow.track.member",
                                        "flow_id": flow_id,
                                        "track": "discussion",
                                        "track_id": track_id,
                                        "member": true,
                                    });
                                    submit_kanban_move(
                                        base.clone(),
                                        token,
                                        space.clone(),
                                        flow_id.clone(),
                                        "cx.flow.track.member",
                                        value,
                                        state_store,
                                        write_records,
                                        board_status,
                                    );
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

/// Round 24 (F1): build + sign + submit a `cx.component.flow.position.v1`
/// Move via `api.submit_move(...)`, recording a [`BoardWriteRecord`] in
/// the local queue regardless of submit outcome. Used by both list and
/// card create paths — `subject` is the cell subject (list_id or
/// flow_id), `kind` is the classifier the MoveSubmissionState tracker
/// uses to decorate state pills (`cx.list.create` / `cx.flow.create`).
fn submit_kanban_move(
    base_url: String,
    token: Signal<String>,
    space_id: String,
    subject: String,
    kind: &'static str,
    value: serde_json::Value,
    mut state_store: Signal<LocalStateStore>,
    mut write_records: Signal<Vec<BoardWriteRecord>>,
    mut board_status: Signal<String>,
) {
    let hlc = Hlc::now("yougen").to_string();
    let anchor_ref = state_store.read().anchor_ref_for_move(&space_id);
    let identity = match state_store.write().ensure_local_identity() {
        Ok(id) => id,
        Err(err) => {
            board_status.set(format!("identity unavailable: {err}"));
            return;
        }
    };
    let did = identity.device_did.clone();
    let vm = did_key_verification_method(&identity.signing_key.verifying_key());
    let unsigned: UnsignedMove =
        match build_flow_position_move(&did, &space_id, &subject, value.clone(), &anchor_ref, &hlc)
        {
            Ok(u) => u,
            Err(err) => {
                board_status.set(format!("build {kind} Move failed: {err}"));
                return;
            }
        };
    let signed = sign_unsigned_move(unsigned, &identity.signing_key, &vm);
    let move_id = signed.id.as_str().to_owned();
    let cell_id = format!("cx:cell:cx.component.flow.position.v1:{subject}");
    let effect_summary = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_owned());
    let signed_move_json = serde_json::to_value(&signed).ok();
    let record = BoardWriteRecord {
        state: CardState::Queued,
        move_id: move_id.clone(),
        kind: kind.to_owned(),
        cell_id: cell_id.clone(),
        effect_summary: effect_summary.clone(),
        anchor_ref: anchor_ref.clone(),
        hlc: hlc.clone(),
        note: "submitting Move via api.submit_move".to_owned(),
        signed_move_json,
        rebase_attempts: 0,
    };
    write_records.write().push(record);
    state_store.write().append_raw_operation(
        move_id.clone(),
        Some(space_id.clone()),
        json!({
            "kind": kind,
            "move_id": move_id,
            "cell": cell_id,
            "effect": value,
            "write_state": "queued",
        }),
    );
    board_status.set(format!("submitting {kind} Move {move_id}"));
    let api_token = token();
    let space_for_record = space_id.clone();
    let anchor_for_record = anchor_ref.clone();
    let kind_for_record = kind.to_owned();
    let move_for_track = move_id.clone();
    spawn(async move {
        match authed_api(&base_url, api_token) {
            Ok(api) => match api.submit_move(&signed).await {
                Ok(resp) => {
                    let state = MoveSubmissionState::from_submit_state(
                        resp.state.as_str(),
                        resp.reason.as_deref(),
                    );
                    state_store.write().record_move_submission(
                        resp.move_id.clone(),
                        space_for_record,
                        kind_for_record.clone(),
                        state,
                        resp.reason.clone(),
                        Some(anchor_for_record),
                    );
                    let card_state = if state.is_failed() {
                        CardState::SoftFailed
                    } else {
                        CardState::Accepted
                    };
                    if let Some(record) = write_records
                        .write()
                        .iter_mut()
                        .find(|r| r.move_id == move_for_track)
                    {
                        record.state = card_state;
                        record.note =
                            format!("submit_move state={} reason={:?}", resp.state, resp.reason);
                    }
                    board_status.set(format!(
                        "{kind_for_record} Move {} state={}",
                        resp.move_id, resp.state
                    ));
                }
                Err(error) => {
                    if let Some(record) = write_records
                        .write()
                        .iter_mut()
                        .find(|r| r.move_id == move_for_track)
                    {
                        record.state = CardState::Quarantined;
                        record.note = format!("submit_move failed: {error}");
                    }
                    board_status.set(format!("quarantined Move: {error}"));
                }
            },
            Err(error) => board_status.set(format!("invalid server URL: {error}")),
        }
    });
}

/// `(prev_rank, next_rank)` for a drop landing. `None` on either side
/// means the drop is at the start / end of the column.
#[derive(Clone, Debug, PartialEq)]
struct ColumnNeighbours {
    prev_rank: Option<String>,
    next_rank: Option<String>,
}

/// End-to-end handler for a drag-drop landing. Computes the new rank,
/// decides cross-list move vs in-list reorder, updates the local
/// optimistic state, and submits the spec-compliant CAS Move.
///
/// Spec mapping ([views.md §2.6](../../contrix-spec/spec/v1/zh/models/views.md)):
///
/// - Cross-column drop ⇒ `cx.flow.move` Event kind.
/// - Same-column drop ⇒ `cx.flow.reorder`.
/// - Both compile to the same
///   `cx:cell:cx.component.flow.position.v1:<board>:<flow>` cas-register
///   cell; the difference is whether `effect.list_place_id` equals
///   `expected.list_place_id`.
fn dispatch_flow_position_move(
    base_url: String,
    token: Signal<String>,
    space_id: String,
    board_place_id: String,
    dragged: DraggedCard,
    target_column_id: String,
    neighbours: ColumnNeighbours,
    mut columns: Signal<Vec<KanbanColumn>>,
    state_store: Signal<LocalStateStore>,
    write_records: Signal<Vec<BoardWriteRecord>>,
    mut board_status: Signal<String>,
) {
    // Don't emit a Move when the drag and drop land on the same exact
    // position: same column, dragged card already sits between
    // `prev_rank` and `next_rank` because we'd be re-asserting its
    // existing rank. UX-wise this is what a user expects (no spurious
    // state mismatch ping).
    if dragged.from_column_id == target_column_id {
        let same_slot = neighbours.prev_rank.as_deref() == Some(dragged.from_rank.as_str())
            || neighbours.next_rank.as_deref() == Some(dragged.from_rank.as_str());
        if same_slot {
            return;
        }
    }
    let new_rank = match rank_for_drop(
        neighbours.prev_rank.as_deref(),
        neighbours.next_rank.as_deref(),
    ) {
        Ok(r) => r,
        Err(RankError::Exhausted) => {
            board_status.set(
                "rank exhausted between neighbours — request cx.container.rebalance before retrying"
                    .to_owned(),
            );
            return;
        }
        Err(other) => {
            board_status.set(format!("rank generation failed: {other}"));
            return;
        }
    };
    // Local optimistic update first so the user sees the card move
    // immediately. The Move submission then catches up; CAS conflicts
    // re-pull projection and re-apply.
    let card_opt = {
        let mut cols = columns.write();
        relocate_card(
            &mut cols,
            &dragged.card_id,
            &dragged.from_column_id,
            &target_column_id,
            &new_rank,
        )
    };
    let Some(_card) = card_opt else {
        board_status.set("internal: dragged card not found in source column".to_owned());
        return;
    };
    let expected = FlowPositionExpectation::At {
        list_place_id: dragged.from_column_id.clone(),
        rank: dragged.from_rank.clone(),
    };
    let effect = FlowPositionEffect::Place {
        list_place_id: target_column_id.clone(),
        rank: new_rank.clone(),
    };
    let kind = if dragged.from_column_id == target_column_id {
        "cx.flow.reorder"
    } else {
        "cx.flow.move"
    };
    submit_flow_position_cas_move(
        base_url,
        token,
        space_id,
        board_place_id,
        dragged.card_id,
        kind,
        expected,
        effect,
        state_store,
        write_records,
        board_status,
    );
}

/// Locate `card_id` in `from_column`, remove it, re-insert into
/// `target_column` such that the resulting column is sorted by `rank`
/// (we keep it lexicographically sorted on the assumption every card
/// has a valid rank). Returns the relocated card or `None` if the
/// source isn't found.
fn relocate_card(
    columns: &mut [KanbanColumn],
    card_id: &str,
    from_column_id: &str,
    target_column_id: &str,
    new_rank: &str,
) -> Option<KanbanCard> {
    let source_idx = columns.iter().position(|c| c.id == from_column_id)?;
    let card_idx = columns[source_idx]
        .cards
        .iter()
        .position(|c| c.id == card_id)?;
    let mut card = columns[source_idx].cards.remove(card_idx);
    card.rank = new_rank.to_owned();
    card.state = CardState::Queued;
    let target_idx = columns
        .iter()
        .position(|c| c.id == target_column_id)
        .or_else(|| Some(source_idx))?;
    let insert_idx = columns[target_idx]
        .cards
        .iter()
        .position(|c| c.rank.as_str() > new_rank)
        .unwrap_or(columns[target_idx].cards.len());
    columns[target_idx].cards.insert(insert_idx, card.clone());
    Some(card)
}

/// Build, sign, and submit a `cx.flow.move` / `cx.flow.reorder` CAS
/// Move via the new spec-compliant builder. Tracks the submission in
/// `write_records` and, on failed precondition, kicks off automatic
/// rebase via [`rebase_flow_position_after_conflict`] up to
/// [`MAX_CONFLICT_REBASE_ATTEMPTS`] times.
#[allow(clippy::too_many_arguments)]
fn submit_flow_position_cas_move(
    base_url: String,
    token: Signal<String>,
    space_id: String,
    board_place_id: String,
    flow_id: String,
    kind: &'static str,
    expected: FlowPositionExpectation,
    effect: FlowPositionEffect,
    state_store: Signal<LocalStateStore>,
    write_records: Signal<Vec<BoardWriteRecord>>,
    board_status: Signal<String>,
) {
    submit_flow_position_cas_move_with_attempt(
        base_url,
        token,
        space_id,
        board_place_id,
        flow_id,
        kind,
        expected,
        effect,
        0,
        state_store,
        write_records,
        board_status,
    );
}

/// Internal variant of [`submit_flow_position_cas_move`] that threads
/// the rebase attempt counter. `attempt` is the **next** attempt number
/// (`0` for the user-initiated drop, `1` for the first rebase, …);
/// reaching [`MAX_CONFLICT_REBASE_ATTEMPTS`] without an Accepted /
/// PendingAnchor result quarantines the record for manual review.
#[allow(clippy::too_many_arguments)]
fn submit_flow_position_cas_move_with_attempt(
    base_url: String,
    token: Signal<String>,
    space_id: String,
    board_place_id: String,
    flow_id: String,
    kind: &'static str,
    expected: FlowPositionExpectation,
    effect: FlowPositionEffect,
    attempt: u8,
    mut state_store: Signal<LocalStateStore>,
    mut write_records: Signal<Vec<BoardWriteRecord>>,
    mut board_status: Signal<String>,
) {
    let hlc = Hlc::now("yougen").to_string();
    let anchor_ref = state_store.read().anchor_ref_for_move(&space_id);
    let identity = match state_store.write().ensure_local_identity() {
        Ok(id) => id,
        Err(err) => {
            board_status.set(format!("identity unavailable: {err}"));
            return;
        }
    };
    let did = identity.device_did.clone();
    let vm = did_key_verification_method(&identity.signing_key.verifying_key());
    let unsigned: UnsignedMove = match build_flow_position_cas_move(
        &did,
        &space_id,
        &board_place_id,
        &flow_id,
        &expected,
        &effect,
        &anchor_ref,
        &hlc,
    ) {
        Ok(u) => u,
        Err(err) => {
            board_status.set(format!("build {kind} Move failed: {err}"));
            return;
        }
    };
    let signed = sign_unsigned_move(unsigned, &identity.signing_key, &vm);
    let move_id = signed.id.as_str().to_owned();
    let cell_id = flow_position_cell_id(&board_place_id, &flow_id);
    let effect_summary = match &effect {
        FlowPositionEffect::Place {
            list_place_id,
            rank,
        } => format!("set {{list_place_id={list_place_id}, rank={rank}}}"),
        FlowPositionEffect::Remove => "set null (remove)".to_owned(),
    };
    let signed_move_json = serde_json::to_value(&signed).ok();
    let record = BoardWriteRecord {
        state: CardState::Submitted,
        move_id: move_id.clone(),
        kind: kind.to_owned(),
        cell_id: cell_id.clone(),
        effect_summary,
        anchor_ref: anchor_ref.clone(),
        hlc: hlc.clone(),
        note: if attempt == 0 {
            format!("submitting {kind} via api.submit_move")
        } else {
            format!("rebase attempt {attempt} of {kind}")
        },
        signed_move_json,
        rebase_attempts: attempt,
    };
    write_records.write().push(record);
    state_store.write().append_raw_operation(
        move_id.clone(),
        Some(space_id.clone()),
        json!({
            "kind": kind,
            "move_id": move_id,
            "cell": cell_id,
            "expected_position": match &expected {
                FlowPositionExpectation::Initial => serde_json::Value::Null,
                FlowPositionExpectation::At {
                    list_place_id,
                    rank,
                } => json!({"list_place_id": list_place_id, "rank": rank}),
            },
            "effect": match &effect {
                FlowPositionEffect::Place {
                    list_place_id,
                    rank,
                } => json!({"list_place_id": list_place_id, "rank": rank}),
                FlowPositionEffect::Remove => serde_json::Value::Null,
            },
            "write_state": "submitted",
        }),
    );
    board_status.set(format!("submitting {kind} Move {move_id}"));
    let api_token = token();
    let move_for_track = move_id.clone();
    let kind_for_record = kind.to_owned();
    let anchor_for_record = anchor_ref.clone();
    let space_for_record = space_id.clone();
    let base_for_rebase = base_url.clone();
    let space_for_rebase = space_id.clone();
    let board_for_rebase = board_place_id.clone();
    let flow_for_rebase = flow_id.clone();
    let effect_for_rebase = effect.clone();
    spawn(async move {
        let api = match authed_api(&base_url, api_token) {
            Ok(api) => api,
            Err(error) => {
                board_status.set(format!("invalid server URL: {error}"));
                return;
            }
        };
        match api.submit_move(&signed).await {
            Ok(resp) => {
                let submission_state = MoveSubmissionState::from_submit_state(
                    resp.state.as_str(),
                    resp.reason.as_deref(),
                );
                state_store.write().record_move_submission(
                    resp.move_id.clone(),
                    space_for_record,
                    kind_for_record.clone(),
                    submission_state,
                    resp.reason.clone(),
                    Some(anchor_for_record),
                );
                let card_state = match submission_state {
                    MoveSubmissionState::Effective | MoveSubmissionState::PendingAnchor => {
                        CardState::Accepted
                    }
                    MoveSubmissionState::FailedPrecondition
                    | MoveSubmissionState::FailedBottom => CardState::Conflict,
                    _ => CardState::SoftFailed,
                };
                if let Some(record) = write_records
                    .write()
                    .iter_mut()
                    .find(|r| r.move_id == move_for_track)
                {
                    record.state = card_state.clone();
                    record.note =
                        format!("submit_move state={} reason={:?}", resp.state, resp.reason);
                }
                board_status.set(format!(
                    "{kind_for_record} Move {} state={}",
                    resp.move_id, resp.state
                ));
                // Auto-rebase the CAS Move after a conflict: re-fetch
                // the cell's current head via the projection endpoint,
                // build a fresh `expected_position`, and re-submit
                // (with the same target effect) up to
                // MAX_CONFLICT_REBASE_ATTEMPTS times.
                if matches!(card_state, CardState::Conflict)
                    && attempt + 1 < MAX_CONFLICT_REBASE_ATTEMPTS
                {
                    rebase_flow_position_after_conflict(
                        base_for_rebase,
                        token,
                        space_for_rebase,
                        board_for_rebase,
                        flow_for_rebase,
                        kind_for_record,
                        effect_for_rebase,
                        attempt + 1,
                        state_store,
                        write_records,
                        board_status,
                    );
                } else if matches!(card_state, CardState::Conflict) {
                    // Out of attempts → quarantine for manual review.
                    if let Some(record) = write_records
                        .write()
                        .iter_mut()
                        .find(|r| r.move_id == move_for_track)
                    {
                        record.state = CardState::Quarantined;
                        record.note = format!(
                            "CAS conflict exhausted {MAX_CONFLICT_REBASE_ATTEMPTS} rebase attempts; \
                             reason={:?}",
                            resp.reason
                        );
                    }
                    board_status.set(format!(
                        "{kind_for_record} quarantined after {MAX_CONFLICT_REBASE_ATTEMPTS} rebase attempts"
                    ));
                }
            }
            Err(error) => {
                if let Some(record) = write_records
                    .write()
                    .iter_mut()
                    .find(|r| r.move_id == move_for_track)
                {
                    record.state = CardState::Quarantined;
                    record.note = format!("submit_move failed: {error}");
                }
                board_status.set(format!("quarantined Move: {error}"));
            }
        }
    });
}

/// Re-fetch the kanban projection after a CAS conflict to discover the
/// flow's current cell state, then re-submit the move with a refreshed
/// `expected_position`. Effect (target list + rank) is preserved — the
/// user's drop intent doesn't change just because someone else moved
/// the card concurrently.
///
/// Spec ([operations-sync.md §8](../../contrix-spec/spec/v1/zh/sync/operations-sync.md)):
/// the conflict-recovery path takes a snapshot + state witness +
/// inclusion proof; this MVP approximation just refetches the
/// collection projection (which the soland reducer derives from the
/// same cell store) and reads the flow's current `list_place_id` /
/// `rank` from it.
#[allow(clippy::too_many_arguments)]
fn rebase_flow_position_after_conflict(
    base_url: String,
    token: Signal<String>,
    space_id: String,
    board_place_id: String,
    flow_id: String,
    kind: String,
    effect: FlowPositionEffect,
    attempt: u8,
    state_store: Signal<LocalStateStore>,
    write_records: Signal<Vec<BoardWriteRecord>>,
    mut board_status: Signal<String>,
) {
    board_status.set(format!(
        "rebase {kind} attempt {attempt}/{MAX_CONFLICT_REBASE_ATTEMPTS} — refetching projection"
    ));
    spawn(async move {
        let api = match authed_api(&base_url, token()) {
            Ok(api) => api,
            Err(error) => {
                board_status.set(format!("rebase aborted (invalid server URL): {error}"));
                return;
            }
        };
        // We hardcode the view id to match the rest of this view —
        // production wiring should pass it through from the saved
        // View. Falling back to seed leaves the conflict in place.
        let view_id = "cx:view:01js0vw0000000000000000000release";
        let new_expected = match api.collection_projection(view_id).await {
            Ok(projection) => locate_flow_position_in_projection(&projection, &flow_id),
            Err(error) => {
                board_status.set(format!(
                    "rebase aborted (projection refresh failed): {error}"
                ));
                return;
            }
        };
        // The static lifetime requirement on `kind` is satisfied by
        // mapping the dynamic String back to one of the known
        // classifiers. Anything else falls through to cx.flow.move
        // because that's the spec wire shape for drag operations.
        let kind_static: &'static str = match kind.as_str() {
            "cx.flow.reorder" => "cx.flow.reorder",
            "cx.flow.move" => "cx.flow.move",
            _ => "cx.flow.move",
        };
        submit_flow_position_cas_move_with_attempt(
            base_url,
            token,
            space_id,
            board_place_id,
            flow_id,
            kind_static,
            new_expected,
            effect,
            attempt,
            state_store,
            write_records,
            board_status,
        );
    });
}

/// Walk the projection groups looking for the flow's current cell
/// pre-state. Returns `Initial` if the flow isn't on the board (i.e.
/// the cell is in initial state) so the next CAS Move uses
/// `head_eq null`.
fn locate_flow_position_in_projection(
    projection: &contrix_sdk::CollectionProjectionResponse,
    flow_id: &str,
) -> FlowPositionExpectation {
    for group in &projection.groups {
        for item in &group.items {
            let item_id = item
                .object
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if item_id == flow_id {
                if let Some(position) = item.position.as_ref() {
                    return FlowPositionExpectation::At {
                        list_place_id: group.group_id.clone(),
                        rank: position.rank.clone(),
                    };
                }
                // Item present but no position metadata → treat as if
                // the cell were initial so we use `head_eq null`. This
                // is conservative; soland's reducer will reject if the
                // cell actually has a non-null head.
                return FlowPositionExpectation::Initial;
            }
        }
    }
    FlowPositionExpectation::Initial
}

/// Replay the first queued / soft-failed Move. When the record carries
/// `signed_move_json` (the post-CAS-refactor path), we re-POST the
/// signed payload verbatim — server-side dedup is content-addressed
/// on `move_id` so the replay is idempotent. Records without a stored
/// signed Move fall through to the legacy rebuild path that hands
/// `effect_summary` back to [`submit_kanban_move`].
fn replay_first_move(
    base_url: String,
    token: Signal<String>,
    space_id: String,
    mut state_store: Signal<LocalStateStore>,
    mut write_records: Signal<Vec<BoardWriteRecord>>,
    mut board_status: Signal<String>,
) {
    let Some(idx) = write_records.read().iter().position(|record| {
        record.state == CardState::Queued
            || record.state == CardState::SoftFailed
            || record.state == CardState::Conflict
    }) else {
        board_status.set("no queued Move to replay".to_owned());
        return;
    };
    let queued = write_records.read()[idx].clone();

    // Fast path: signed Move already on disk — just re-POST it. The
    // server validates the JWS, recomputes the content-addressed move
    // id, and treats an already-anchored move_id as idempotent. This
    // is the spec-blessed offline-queue replay path.
    if let Some(signed_value) = queued.signed_move_json.clone() {
        let signed: contrix_sdk::Move = match serde_json::from_value(signed_value) {
            Ok(m) => m,
            Err(error) => {
                board_status.set(format!("queued record has malformed Move: {error}"));
                return;
            }
        };
        let api_token = token();
        let base = base_url.clone();
        let move_for_track = queued.move_id.clone();
        let kind_for_record = queued.kind.clone();
        spawn(async move {
            let api = match authed_api(&base, api_token) {
                Ok(api) => api,
                Err(error) => {
                    board_status.set(format!("invalid server URL: {error}"));
                    return;
                }
            };
            match api.submit_move(&signed).await {
                Ok(resp) => {
                    if let Some(record) = write_records
                        .write()
                        .iter_mut()
                        .find(|r| r.move_id == move_for_track)
                    {
                        record.state = if MoveSubmissionState::from_submit_state(
                            resp.state.as_str(),
                            resp.reason.as_deref(),
                        )
                        .is_failed()
                        {
                            CardState::SoftFailed
                        } else {
                            CardState::Accepted
                        };
                        record.note = format!(
                            "replay state={} reason={:?}",
                            resp.state, resp.reason
                        );
                    }
                    board_status.set(format!(
                        "{kind_for_record} replay state={}",
                        resp.state
                    ));
                }
                Err(error) => {
                    if let Some(record) = write_records
                        .write()
                        .iter_mut()
                        .find(|r| r.move_id == move_for_track)
                    {
                        record.state = CardState::Quarantined;
                        record.note = format!("replay failed: {error}");
                    }
                    board_status.set(format!("replay quarantined: {error}"));
                }
            }
        });
        return;
    }

    // Legacy fallback: rebuild from `effect_summary` + `cell_id` and
    // re-submit through `submit_kanban_move`. This produces a NEW
    // content-addressed move_id because the HLC advances.
    let value: serde_json::Value =
        serde_json::from_str(&queued.effect_summary).unwrap_or_else(|_| json!({}));
    let subject = queued
        .cell_id
        .strip_prefix("cx:cell:cx.component.flow.position.v1:")
        .map(str::to_owned)
        .unwrap_or_default();
    if subject.is_empty() {
        board_status.set("queued record has no cell subject".to_owned());
        return;
    }
    write_records.write().remove(idx);
    let kind: &'static str = match queued.kind.as_str() {
        "cx.list.create" => "cx.list.create",
        "cx.flow.move" => "cx.flow.move",
        "cx.flow.reorder" => "cx.flow.reorder",
        "cx.flow.position" => "cx.flow.position",
        _ => "cx.flow.create",
    };
    submit_kanban_move(
        base_url,
        token,
        space_id,
        subject,
        kind,
        value,
        state_store,
        write_records,
        board_status,
    );
    let _ = &mut state_store; // keep mut binding for IDE / unused-warn coverage
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
            id: "cx:place:01list-todo000000000000000000".to_owned(),
            title: "To Do".to_owned(),
            rank: "U".to_owned(),
            cards: vec![KanbanCard {
                id: "cx:flow:legal-review".to_owned(),
                // Seed cards seed `cards[i].rank` from the
                // lexofractional alphabet so the next rank_between
                // call has well-formed neighbours to work with. "U" is
                // the alphabet midpoint; subsequent seeds at "f" and
                // "p" keep them strictly ascending.
                rank: "U".to_owned(),
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
            id: "cx:place:01list-progress00000000000000".to_owned(),
            title: "In Progress".to_owned(),
            rank: "f".to_owned(),
            cards: vec![KanbanCard {
                id: "cx:flow:onboarding-copy".to_owned(),
                rank: "U".to_owned(),
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
            id: "cx:place:01list-done00000000000000000".to_owned(),
            title: "Done".to_owned(),
            rank: "p".to_owned(),
            cards: vec![KanbanCard {
                id: "cx:flow:security-signoff".to_owned(),
                rank: "U".to_owned(),
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
            CollectionProjectionDiscussion, CollectionProjectionGroup, CollectionProjectionItem,
            CollectionProjectionResponse, ViewId, ViewKind, ViewRenderer,
        };
        let projection = CollectionProjectionResponse {
            kind: ViewKind::Collection,
            renderer: ViewRenderer::Board,
            view_id: ViewId::new("cx:view:01904100-0000-7000-8000-000000000001").unwrap(),
            frontier: vec!["cx:event:01904100-0000-7000-8000-000000000042".to_owned()],
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
        assert!(
            BoardProjectionSource::ApiDerived
                .label()
                .contains("API-derived")
        );
        assert!(BoardProjectionSource::SeedFallback.label().contains("seed"));
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

    /// `relocate_card` is the optimistic local mutation that runs as
    /// soon as the user drops a card — before the server sees the
    /// Move. It MUST:
    ///   1. remove the card from the source column,
    ///   2. assign the new rank,
    ///   3. insert into the target column such that ascending-rank
    ///      ordering is preserved (otherwise the next drag uses
    ///      wrong neighbours for `rank_between`).
    #[test]
    fn relocate_card_preserves_rank_ordering_after_move() {
        let mut cols = vec![
            KanbanColumn {
                id: "cx:place:list-a".to_owned(),
                title: "A".to_owned(),
                rank: "U".to_owned(),
                cards: vec![
                    test_card("cx:flow:a1", "U"),
                    test_card("cx:flow:a2", "f"),
                ],
            },
            KanbanColumn {
                id: "cx:place:list-b".to_owned(),
                title: "B".to_owned(),
                rank: "f".to_owned(),
                cards: vec![
                    test_card("cx:flow:b1", "U"),
                    test_card("cx:flow:b3", "z"),
                ],
            },
        ];
        // Move a1 from A → B, dropped at rank "m" (between b1=U and b3=z).
        let moved = relocate_card(&mut cols, "cx:flow:a1", "cx:place:list-a", "cx:place:list-b", "m").unwrap();
        assert_eq!(moved.id, "cx:flow:a1");
        assert_eq!(moved.rank, "m");
        // Source column no longer contains a1, still has a2.
        let a = &cols[0];
        assert_eq!(a.cards.len(), 1);
        assert_eq!(a.cards[0].id, "cx:flow:a2");
        // Target column has b1 (U) < a1 (m) < b3 (z), ordering preserved.
        let b = &cols[1];
        assert_eq!(b.cards.len(), 3);
        assert_eq!(b.cards[0].id, "cx:flow:b1");
        assert_eq!(b.cards[1].id, "cx:flow:a1");
        assert_eq!(b.cards[2].id, "cx:flow:b3");
    }

    /// In-list reorder: removing from a column then re-inserting into
    /// the **same** column (target == source) at a new rank should
    /// land at the right position.
    #[test]
    fn relocate_card_handles_in_list_reorder() {
        let mut cols = vec![KanbanColumn {
            id: "cx:place:list-a".to_owned(),
            title: "A".to_owned(),
            rank: "U".to_owned(),
            cards: vec![
                test_card("cx:flow:a1", "U"),
                test_card("cx:flow:a2", "f"),
                test_card("cx:flow:a3", "p"),
            ],
        }];
        // Move a3 to the top of the same list (rank "0" — before "U").
        let moved = relocate_card(&mut cols, "cx:flow:a3", "cx:place:list-a", "cx:place:list-a", "0").unwrap();
        assert_eq!(moved.rank, "0");
        let a = &cols[0];
        assert_eq!(a.cards.len(), 3);
        assert_eq!(a.cards[0].id, "cx:flow:a3");
        assert_eq!(a.cards[1].id, "cx:flow:a1");
        assert_eq!(a.cards[2].id, "cx:flow:a2");
    }

    /// `locate_flow_position_in_projection` is the post-conflict rebase
    /// adapter — it must find the flow's current cell pre-state from a
    /// freshly-fetched projection. When the flow is present with a
    /// position, return `At { list_place_id, rank }`; absent ⇒ `Initial`.
    #[test]
    fn locate_flow_position_finds_present_flow_with_rank() {
        use contrix_sdk::{
            CollectionProjectionGroup, CollectionProjectionItem, CollectionProjectionPosition,
            CollectionProjectionResponse, ViewId, ViewKind, ViewRenderer,
        };
        let projection = CollectionProjectionResponse {
            kind: ViewKind::Collection,
            renderer: ViewRenderer::Board,
            view_id: ViewId::new("cx:view:01904100-0000-7000-8000-000000000001").unwrap(),
            frontier: Vec::new(),
            groups: vec![CollectionProjectionGroup {
                group_id: "cx:place:01list-review".to_owned(),
                title: "Review".to_owned(),
                rank: Some("U".to_owned()),
                items: vec![CollectionProjectionItem {
                    object: serde_json::json!({
                        "id": "cx:flow:01wanted",
                        "title": "Find me",
                    }),
                    position: Some(CollectionProjectionPosition {
                        relation_id: "cx:relation:01rel".to_owned(),
                        rank: "h3".to_owned(),
                    }),
                    discussion: None,
                }],
                hidden_count: None,
            }],
        };
        let expected = locate_flow_position_in_projection(&projection, "cx:flow:01wanted");
        assert_eq!(
            expected,
            FlowPositionExpectation::At {
                list_place_id: "cx:place:01list-review".to_owned(),
                rank: "h3".to_owned(),
            }
        );
    }

    /// When the flow isn't in the projection, the rebase must use
    /// `head_eq null` (Initial) — soland's reducer rejects if the cell
    /// is actually non-initial, which is the safe behaviour.
    #[test]
    fn locate_flow_position_missing_flow_returns_initial() {
        use contrix_sdk::{
            CollectionProjectionResponse, ViewId, ViewKind, ViewRenderer,
        };
        let projection = CollectionProjectionResponse {
            kind: ViewKind::Collection,
            renderer: ViewRenderer::Board,
            view_id: ViewId::new("cx:view:01904100-0000-7000-8000-000000000001").unwrap(),
            frontier: Vec::new(),
            groups: Vec::new(),
        };
        let expected = locate_flow_position_in_projection(&projection, "cx:flow:01missing");
        assert_eq!(expected, FlowPositionExpectation::Initial);
    }

    /// Helper for `relocate_card` tests — builds a KanbanCard with the
    /// supplied id and rank, defaulting the rest of the demo fields.
    fn test_card(id: &str, rank: &str) -> KanbanCard {
        KanbanCard {
            id: id.to_owned(),
            rank: rank.to_owned(),
            title: "test".to_owned(),
            description: String::new(),
            labels: Vec::new(),
            assignee: String::new(),
            due: String::new(),
            primary_flow_id: String::new(),
            primary_flow: String::new(),
            linked_flows: Vec::new(),
            locked_flow: None,
            external_visibility: String::new(),
            history_visibility: String::new(),
            activity_hint: String::new(),
            audit_hint: String::new(),
            state: CardState::Synced,
        }
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
