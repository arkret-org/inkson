use dioxus::prelude::*;
use dioxus_router::hooks::{use_navigator, use_route};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    components::{EmptyState, EmptyStateKind, UiIcon},
    hlc::Hlc,
    local_state::{LocalStateStore, MoveSubmissionState, RawOperationRecord},
    move_builder::{FlowPositionEffect, FlowPositionExpectation, flow_position_cell_id},
    operation::uuid_v7,
    rank::{RankError, rank_for_drop},
    routes::Route,
    views::helpers::{short_protocol_id, with_authed_api},
};

/// Board Space id used only when the explicit demo seed fallback is
/// enabled. Normal kanban routes render server projections instead of
/// hard-coded cards.
const DEMO_BOARD_SPACE_ID: &str = "cx:space:0196419b-0000-7000-8000-00000000b0a0";

/// Maximum number of times a CAS-conflicted Move is automatically
/// rebased + re-submitted before the UI surfaces it as Quarantined and
/// requires manual review. Three is enough to absorb typical
/// two-actor races without spinning indefinitely if the cell is hot.
const MAX_CONFLICT_REBASE_ATTEMPTS: u8 = 3;

/// F-KANBAN-LIVE-1: how often the board polls
/// `/views/:id/projection` so another device's `cx.flow.move` /
/// `cx.flow.reorder` / `cx.flow.update` shows up without a manual
/// refresh. 5s matches soland's ephemeral fanout cadence — short
/// enough to feel "live", long enough that a single user's tab
/// doesn't hammer the server.
const KANBAN_LIVE_POLL_SECONDS: u64 = 5;

const LOCAL_PENDING_CARD_DESCRIPTION: &str = "New local card waiting for reducer receipt.";
const CARD_DESCRIPTION_COLLAPSE_CHAR_THRESHOLD: usize = 360;
const CARD_DESCRIPTION_COLLAPSE_LINE_THRESHOLD: usize = 6;

/// Browser-`localStorage` keys for the card-detail panel display
/// preference. Dock mode + width are device-/browser-level UI state
/// (not tied to an account or Space), so they live in `localStorage`
/// on the web build and become no-ops on desktop where there is no
/// browser storage — the session-default applies there instead.
const CARD_DETAIL_DOCKED_STORAGE_KEY: &str = "yougen.card-detail.docked";
const CARD_DETAIL_DOCK_WIDTH_STORAGE_KEY: &str = "yougen.card-detail.dock-width";
const CARD_DETAIL_DOCK_WIDTH_DEFAULT: f64 = 720.0;
const CARD_DETAIL_DOCK_WIDTH_MIN: f64 = 380.0;
const CARD_DETAIL_DOCK_WIDTH_MAX: f64 = 1100.0;

#[cfg(target_arch = "wasm32")]
fn local_storage_get(key: &str) -> Option<String> {
    web_sys::window()?
        .local_storage()
        .ok()
        .flatten()?
        .get_item(key)
        .ok()
        .flatten()
}

#[cfg(target_arch = "wasm32")]
fn local_storage_set(key: &str, value: &str) {
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = storage.set_item(key, value);
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn local_storage_get(_key: &str) -> Option<String> {
    None
}

#[cfg(not(target_arch = "wasm32"))]
fn local_storage_set(_key: &str, _value: &str) {}

/// Hydrate the docked-vs-dialog choice from `localStorage`. Defaults to
/// the centered dialog when unset or on desktop.
fn read_card_detail_docked() -> bool {
    local_storage_get(CARD_DETAIL_DOCKED_STORAGE_KEY)
        .map(|value| value == "true")
        .unwrap_or(false)
}

/// Hydrate the docked-panel width from `localStorage`, clamped to the
/// same bounds the drag handle enforces. Falls back to the default when
/// unset, unparseable, or on desktop.
fn read_card_detail_dock_width() -> f64 {
    local_storage_get(CARD_DETAIL_DOCK_WIDTH_STORAGE_KEY)
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|width| width.is_finite())
        .map(|width| width.clamp(CARD_DETAIL_DOCK_WIDTH_MIN, CARD_DETAIL_DOCK_WIDTH_MAX))
        .unwrap_or(CARD_DETAIL_DOCK_WIDTH_DEFAULT)
}

fn persist_card_detail_docked(docked: bool) {
    local_storage_set(
        CARD_DETAIL_DOCKED_STORAGE_KEY,
        if docked { "true" } else { "false" },
    );
}

fn persist_card_detail_dock_width(width: f64) {
    local_storage_set(CARD_DETAIL_DOCK_WIDTH_STORAGE_KEY, &format!("{width:.0}"));
}

#[derive(Clone, Debug, PartialEq)]
struct KanbanColumn {
    id: String,
    title: String,
    rank: String,
    cards: Vec<KanbanCard>,
    /// Space-container lifecycle state. `Active` is the wire default; `Archived` is set
    /// optimistically after a successful `cx.space.archive` submit and reset
    /// after `cx.space.restore`. Spec: `models/realm-and-space.md §4.4`
    /// (post-R1.7 rename).
    /// `Tombstoned` is irreversible and modeled here for completeness but the
    /// UI currently has no tombstone affordance — server-only path.
    state: SpaceContainerLifecycleState,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SpaceContainerLifecycleState {
    #[default]
    Active,
    Archived,
    /// Server-only terminal state. UI never produces this; the variant
    /// exists so `dispatch_space_container_lifecycle` can exhaustively match.
    #[allow(dead_code)]
    Tombstoned,
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
    /// Flow `summary` — short one-line/paragraph overview.
    description: String,
    /// Flow `body` — rich long-form content shown in the Description tab.
    body: String,
    /// Flow `synthesis` — rich content shown in the Synthesis tab. Stored
    /// on the Flow object alongside `body` so the kanban popup can edit
    /// it inline without round-tripping through the Document/Morph view.
    /// Canonical wire path: `object.synthesis` (with `object.tracks.synthesis.body`
    /// honored as a back-compat fallback in projection reads).
    synthesis: String,
    labels: Vec<String>,
    assignee: String,
    due: String,
    primary_flow_id: String,
    locked_flow: Option<LockedFlow>,
    external_visibility: String,
    history_visibility: String,
    activity_hint: String,
    audit_hint: String,
    state: CardState,
    /// Flow lifecycle state (orthogonal to `state` above which is
    /// Move-lifecycle). Spec: `flow-and-message.md §3`,
    /// `common-fields.md §5.1`. Active cards render in the column;
    /// Archived cards move to the archived-cards drawer. Tombstoned is
    /// included for state-machine completeness but UI never emits it.
    lifecycle: FlowLifecycleState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CardDetailDraft {
    title: String,
    description: String,
    /// Flow `body` — long-form content shown in the Description tab.
    body: String,
    /// Flow `synthesis` — long-form content shown in the Synthesis tab.
    synthesis: String,
    labels: Vec<String>,
    assignee: String,
    due: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum FlowLifecycleState {
    #[default]
    Active,
    Archived,
    /// Server-only terminal (`deleted` / `redacted` per the wire enum,
    /// merged here for UI). The UI never produces this; the variant
    /// exists so `dispatch_flow_lifecycle` can exhaustively match.
    #[allow(dead_code)]
    Tombstoned,
}

#[derive(Clone, Debug, PartialEq)]
struct LockedFlow {
    flow_id_hash: String,
    reason: String,
}

/// Snapshot of the card-being-dragged's pre-move state. The cas-register
/// model in [`operations-sync.md` §9.1](../../contrix-spec/spec/v1/zh/sync/operations-sync.md)
/// requires the source `(list_space_id, rank)` to seed `head_eq` on the
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct DraggedColumn {
    column_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BoardSpaceOption {
    id: String,
    title: String,
    state: SpaceContainerLifecycleState,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum BoardToolbarPopover {
    #[default]
    None,
    CreateBoard,
    Projection,
    Queue,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum CardDetailContentTab {
    #[default]
    Description,
    Synthesis,
    Discussion,
}

/// Which tab the right-hand card-detail sidebar is showing.
/// - `Details`: per-card metadata (Flow ID, Assignee, Due, Visibility) + Activity hints.
/// - `Members`: every actor in the surrounding Realm/Space — sourced from
///   the cached space projection (`members`/`participants`/`owners` keys).
///   Each row is also marked when the actor has authored an event against
///   the current Flow (derived from local raw operations), so participation
///   is surfaced inline instead of in a separate tab.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum CardDetailSidebarTab {
    #[default]
    Details,
    Members,
}

/// Which slice of card fields the inline edit form is currently editing.
/// The Summary scope edits title + the short summary blurb; the
/// Description scope edits only the long-form body shown in the
/// Description tab. Each entry point seeds the matching scope so the
/// form only renders the relevant editor (avoids the "edit description"
/// CTA opening an unrelated Title + Summary editor as well).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum CardEditScope {
    #[default]
    Summary,
    Description,
    Synthesis,
}

const TOAST_EDITOR_SCRIPT_URL: &str =
    "https://uicdn.toast.com/editor/latest/toastui-editor-all.min.js";
const TOAST_EDITOR_CSS_URL: &str = "https://uicdn.toast.com/editor/latest/toastui-editor.min.css";

#[component]
fn CardMarkdownEditor(
    value: String,
    base_url: String,
    token: String,
    on_change: EventHandler<String>,
    /// Optional id suffix so multiple editor instances on the same card
    /// detail (e.g. Summary + Description) don't share a DOM id and
    /// confuse the toast bootstrap script. Defaults to the legacy
    /// `"description"` slot for back-compat with existing data-testids.
    slot: Option<String>,
) -> Element {
    let slot = slot.unwrap_or_else(|| "description".to_owned());
    let host_id = format!("card-detail-{slot}-toast-editor");
    let fallback_id = format!("card-detail-{slot}-input");

    use_effect({
        let host_id = host_id.clone();
        let fallback_id = fallback_id.clone();
        let value = value.clone();
        let base_url = base_url.clone();
        let token = token.clone();
        move || {
            if let Some(script) =
                toast_editor_bootstrap_script(&host_id, &fallback_id, &value, &base_url, &token)
            {
                let _ = document::eval(&script);
            }
        }
    });

    rsx! {
        div { class: "card-rich-editor",
            div {
                id: "{host_id}",
                class: "card-rich-editor-host",
                "data-testid": "card-detail-description-rich-editor",
            }
            textarea {
                id: "{fallback_id}",
                class: "textarea card-rich-editor-fallback",
                "data-testid": "card-detail-description-input",
                value: "{value}",
                maxlength: "8192",
                oninput: move |evt| on_change.call(evt.value()),
            }
        }
    }
}

fn toast_editor_bootstrap_script(
    host_id: &str,
    fallback_id: &str,
    value: &str,
    base_url: &str,
    token: &str,
) -> Option<String> {
    let config = serde_json::to_string(&json!({
        "hostId": host_id,
        "fallbackId": fallback_id,
        "value": value,
        "baseUrl": base_url,
        "token": token,
        "scriptUrl": TOAST_EDITOR_SCRIPT_URL,
        "cssUrl": TOAST_EDITOR_CSS_URL,
    }))
    .ok()?;
    Some(format!(
        r##"(async () => {{
    const config = {config};
    const host = document.getElementById(config.hostId);
    const fallback = document.getElementById(config.fallbackId);
    if (!host || !fallback) {{
        return;
    }}

    const registry = window.__yougenToastEditors || (window.__yougenToastEditors = new Map());
    const existing = registry.get(config.hostId);
    if (existing && host.childElementCount > 0) {{
        return;
    }}

    if (!window.__yougenLoadToastEditor) {{
        window.__yougenLoadToastEditor = () => new Promise((resolve, reject) => {{
            const cssId = "yougen-toast-editor-css";
            if (!document.getElementById(cssId)) {{
                const link = document.createElement("link");
                link.id = cssId;
                link.rel = "stylesheet";
                link.href = config.cssUrl;
                document.head.appendChild(link);
            }}

            if (window.toastui && window.toastui.Editor) {{
                resolve();
                return;
            }}

            const scriptId = "yougen-toast-editor-script";
            const loadedScript = document.getElementById(scriptId);
            if (loadedScript) {{
                loadedScript.addEventListener("load", () => resolve(), {{ once: true }});
                loadedScript.addEventListener("error", () => reject(new Error("Toast UI Editor failed to load")), {{ once: true }});
                return;
            }}

            const script = document.createElement("script");
            script.id = scriptId;
            script.src = config.scriptUrl;
            script.async = true;
            script.onload = () => resolve();
            script.onerror = () => reject(new Error("Toast UI Editor failed to load"));
            document.head.appendChild(script);
        }});
    }}

    try {{
        await window.__yougenLoadToastEditor();
    }} catch (error) {{
        console.warn("[yougen] Toast UI Editor unavailable; using textarea fallback", error);
        fallback.classList.remove("toast-fallback-hidden");
        return;
    }}

    if (!window.toastui || !window.toastui.Editor) {{
        fallback.classList.remove("toast-fallback-hidden");
        return;
    }}

    if (existing) {{
        try {{ existing.destroy(); }} catch (_) {{}}
        registry.delete(config.hostId);
    }}

    host.innerHTML = "";
    fallback.classList.add("toast-fallback-hidden");

    const sync = (editor) => {{
        fallback.value = editor.getMarkdown();
        fallback.dispatchEvent(new InputEvent("input", {{
            bubbles: true,
            inputType: "insertText",
            data: null
        }}));
    }};

    const uploadImage = async (blob, callback) => {{
        try {{
            const base = (config.baseUrl || window.location.origin).replace(/\/+$/, "");
            const headers = {{
                "content-type": blob.type || "application/octet-stream"
            }};
            if (config.token) {{
                headers.authorization = `Bearer ${{config.token}}`;
            }}
            const response = await fetch(`${{base}}/api/v1/blob/upload`, {{
                method: "POST",
                headers,
                body: blob
            }});
            if (!response.ok) {{
                throw new Error(`upload failed: ${{response.status}}`);
            }}
            const body = await response.json();
            const blobRef = body.blob_ref || body.blobRef || body.blob_id;
            if (!blobRef) {{
                throw new Error("upload response missing blob_ref");
            }}
            const mediaType = blob.type || body.media_type || "image/png";
            const markdownTarget = blobRef.includes("#") ? blobRef : `${{blobRef}}#${{mediaType}}`;
            callback(markdownTarget, blob.name || "image");
        }} catch (error) {{
            console.warn("[yougen] image upload failed", error);
            window.alert("Image upload failed.");
        }}
        return false;
    }};

    const editor = new window.toastui.Editor({{
        el: host,
        height: "320px",
        initialEditType: "wysiwyg",
        previewStyle: "tab",
        initialValue: config.value || "",
        usageStatistics: false,
        toolbarItems: [
            ["heading", "bold", "italic", "strike"],
            ["hr", "quote"],
            ["ul", "ol", "task"],
            ["table", "image", "link"],
            ["code", "codeblock"]
        ],
        hooks: {{
            addImageBlobHook: uploadImage
        }}
    }});

    editor.on("change", () => sync(editor));
    registry.set(config.hostId, editor);
}})();"##
    ))
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

/// Board write records track a Move pipeline submission. The Move's
/// canonical body lives in `cell_id` + `effect_summary` (string preview);
/// `move_id` is the content-addressed `sha256:...` id. `kind`
/// mirrors the MoveSubmissionState classifier (`cx.space.create` /
/// `cx.flow.create` /
/// `cx.flow.position`) so the tracker UI can decorate state pills.
///
/// `signed_move_json` is the typed [`contrix_sdk::Move`] serialised to
/// JSON. We persist it on the queued record so that Replay can re-POST
/// the exact same signed payload — server-side dedup is content-addressed
/// on `move_id`, making replay idempotent. None means the record cannot
/// be replayed idempotently.
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
/// The UI prefers API-derived board state from either the collection view
/// projection or the server's Space-container / Flow projection endpoints.
/// The local seed path is explicit demo-only so hard-coded cards are never
/// mistaken for persisted board data.
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
    /// No projection was available and demo seed fallback is disabled for
    /// this server profile.
    Unavailable,
}

fn kanban_seed_fallback_allowed(_base_url: &str) -> bool {
    if truthy_env_value(option_env!("YOUGEN_ALLOW_KANBAN_SEED_FALLBACK"))
        || std::env::var("YOUGEN_ALLOW_KANBAN_SEED_FALLBACK")
            .ok()
            .as_deref()
            .is_some_and(|value| truthy_env_value(Some(value)))
    {
        return true;
    }
    false
}

#[cfg(test)]
fn kanban_seed_fallback_allowed_for_url(_base_url: &str) -> bool {
    false
}

fn truthy_env_value(value: Option<&str>) -> bool {
    value.is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
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
    // Unavailable unless explicit demo seed is enabled; async projection
    // hydrate promotes the board to ApiDerived once the server returns data.
    None
}

fn initial_board_space_options(seed_fallback_allowed: bool) -> Vec<BoardSpaceOption> {
    if seed_fallback_allowed {
        vec![BoardSpaceOption {
            id: DEMO_BOARD_SPACE_ID.to_owned(),
            title: "Local demo board".to_owned(),
            state: SpaceContainerLifecycleState::Active,
        }]
    } else {
        Vec::new()
    }
}

fn board_space_options_from_projection(
    containers: &[crate::api::SpaceContainerProjectionView],
) -> Vec<BoardSpaceOption> {
    let mut options = containers
        .iter()
        .filter(|view| {
            view.kind == "board" || (view.kind.trim().is_empty() && view.parent_space_id.is_none())
        })
        .map(|view| BoardSpaceOption {
            id: view.container_space_id.clone(),
            title: if view.title.trim().is_empty() {
                view.container_space_id.clone()
            } else {
                view.title.clone()
            },
            state: space_container_state_from_wire(&view.state),
        })
        .collect::<Vec<_>>();
    options.sort_by(|left, right| left.id.cmp(&right.id).then(left.title.cmp(&right.title)));
    options.dedup_by(|left, right| left.id == right.id);
    options.sort_by(|left, right| left.title.cmp(&right.title).then(left.id.cmp(&right.id)));
    options
}

/// T20 — Map a SDK [`CollectionProjectionResBody`] into the yougen
/// renderer's [`Vec<KanbanColumn>`] shape.
///
/// Pure adapter so it's unit-testable without a live HTTP client.
/// Position rank, when present, drives stable ordering inside a column.
fn collection_projection_to_columns(
    projection: &contrix_sdk::CollectionProjectionResBody,
) -> Vec<KanbanColumn> {
    projection
        .groups
        .iter()
        .map(|group| KanbanColumn {
            id: group.group_id.clone(),
            title: group.title.clone(),
            rank: group.rank.clone().unwrap_or_default(),
            cards: group.items.iter().map(card_from_projection_item).collect(),
            state: SpaceContainerLifecycleState::Active,
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
                // T2.3: tracks no longer carry independent access; a child
                // Discussion Space owns its own access policy. The history
                // visibility here reflects "the discussion is a child Space
                // with its own access" — render as such, not as a
                // branch-scoped grant.
                "child Space access".to_owned()
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
        body: flow_body_display_text(item.object.get("body").or_else(|| {
            item.object
                .get("fields")
                .and_then(|fields| fields.get("body"))
        })),
        synthesis: flow_body_display_text(item.object.get("synthesis").or_else(|| {
            item.object
                .get("tracks")
                .and_then(|tracks| tracks.get("synthesis"))
                .and_then(|track| track.get("body"))
        })),
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
            .and_then(|f| f.get("due_at").or_else(|| f.get("due")))
            .and_then(|v| v.as_str())
            .unwrap_or("—")
            .to_owned(),
        primary_flow_id,
        locked_flow,
        external_visibility,
        history_visibility,
        activity_hint: "Activity derived from cx.flow.move / cx.flow.update events.".to_owned(),
        audit_hint: "Audit trail in /audit shows the full Event Envelope chain.".to_owned(),
        state: CardState::Synced,
        lifecycle: FlowLifecycleState::Active,
    }
}

fn columns_from_lifecycle_projection(
    containers: &[crate::api::SpaceContainerProjectionView],
    flows: &[crate::api::FlowProjectionView],
    preferred_board_id: &str,
) -> (Vec<KanbanColumn>, Vec<BoardSpaceOption>, Option<String>) {
    let board_options = board_space_options_from_projection(containers);
    let selected_board_id = if !preferred_board_id.trim().is_empty()
        && board_options
            .iter()
            .any(|option| option.id == preferred_board_id)
    {
        Some(preferred_board_id.to_owned())
    } else {
        board_options.first().map(|option| option.id.clone())
    };
    let Some(board_id) = selected_board_id else {
        return (Vec::new(), board_options, None);
    };

    let mut cols = containers
        .iter()
        .filter(|view| {
            view.kind == "list" && view.parent_space_id.as_deref() == Some(board_id.as_str())
        })
        .map(|view| KanbanColumn {
            id: view.container_space_id.clone(),
            title: if view.title.trim().is_empty() {
                view.container_space_id.clone()
            } else {
                view.title.clone()
            },
            rank: view.rank.clone().unwrap_or_default(),
            cards: Vec::new(),
            state: space_container_state_from_wire(&view.state),
        })
        .collect::<Vec<_>>();
    cols.sort_by(|left, right| {
        left.rank
            .cmp(&right.rank)
            .then(left.title.cmp(&right.title))
            .then(left.id.cmp(&right.id))
    });

    for flow in flows.iter().filter(|flow| {
        flow_projection_field_string(flow, flow.board_space_id.as_deref(), &["board_space_id"])
            .as_deref()
            == Some(board_id.as_str())
    }) {
        let Some(list_space_id) =
            flow_projection_field_string(flow, flow.list_space_id.as_deref(), &["list_space_id"])
        else {
            continue;
        };
        if let Some(column) = cols.iter_mut().find(|col| col.id == list_space_id) {
            column.cards.push(card_from_flow_projection(flow));
        }
    }

    for column in &mut cols {
        sort_kanban_cards(&mut column.cards);
    }

    (cols, board_options, Some(board_id))
}

fn sort_kanban_cards(cards: &mut [KanbanCard]) {
    cards.sort_by(|left, right| {
        left.rank
            .cmp(&right.rank)
            .then(left.title.cmp(&right.title))
            .then(left.id.cmp(&right.id))
    });
}

fn reorder_column_before(
    columns: &mut Vec<KanbanColumn>,
    dragged_id: &str,
    target_id: &str,
) -> bool {
    if dragged_id == target_id {
        return false;
    }
    let Some(from_index) = columns.iter().position(|column| column.id == dragged_id) else {
        return false;
    };
    let Some(target_index) = columns.iter().position(|column| column.id == target_id) else {
        return false;
    };
    let dragged = columns.remove(from_index);
    let insert_index = if from_index < target_index {
        target_index.saturating_sub(1)
    } else {
        target_index
    };
    columns.insert(insert_index, dragged);
    for (index, column) in columns.iter_mut().enumerate() {
        column.rank = format!("r{:03}", index + 1);
    }
    true
}

fn flow_projection_field_string(
    flow: &crate::api::FlowProjectionView,
    top_level: Option<&str>,
    field_names: &[&str],
) -> Option<String> {
    top_level
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            field_names.iter().find_map(|field_name| {
                flow.fields
                    .get(*field_name)
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .map(ToOwned::to_owned)
            })
        })
}

fn flow_projection_labels(flow: &crate::api::FlowProjectionView) -> Vec<String> {
    match flow.fields.get("labels") {
        Some(Value::Array(labels)) => labels
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|label| !label.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        Some(Value::String(labels)) => parse_card_labels(labels),
        _ => Vec::new(),
    }
}

fn flow_body_display_text(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    let mut lines = Vec::new();
    collect_content_text(value, &mut lines);
    lines
        .into_iter()
        .map(|line| line.trim().to_owned())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn collect_content_text(value: &Value, lines: &mut Vec<String>) {
    match value {
        Value::String(text) => lines.push(text.clone()),
        Value::Array(items) => {
            for item in items {
                collect_content_text(item, lines);
            }
        }
        Value::Object(object) => {
            for key in [
                "body",
                "text",
                "markdown",
                "plain_text",
                "content",
                "caption",
                "alt",
            ] {
                if let Some(child) = object.get(key) {
                    collect_content_text(child, lines);
                }
            }
            if let Some(blocks) = object.get("blocks") {
                collect_content_text(blocks, lines);
            }
        }
        _ => {}
    }
}

fn card_from_flow_projection(flow: &crate::api::FlowProjectionView) -> KanbanCard {
    let title = if flow.title.trim().is_empty() {
        flow.flow_id.clone()
    } else {
        flow.title.clone()
    };
    let description =
        flow_projection_field_string(flow, flow.summary.as_deref(), &["summary", "description"])
            .unwrap_or_default();
    let discussion_visibility =
        flow_projection_field_string(flow, None, &["discussion_visibility", "visibility"]);
    let locked_flow = if discussion_visibility.as_deref() == Some("locked") {
        Some(LockedFlow {
            flow_id_hash: flow_projection_field_string(flow, None, &["discussion_ref_hash"])
                .unwrap_or_else(|| format!("sha256:{}", flow.flow_id)),
            reason: flow_projection_field_string(flow, None, &["locked_reason"]).unwrap_or_else(
                || "Locked discussion: title and members are not disclosed.".to_owned(),
            ),
        })
    } else {
        None
    };
    let external_visibility = if locked_flow.is_some() {
        "Locked discussion (lazy_link)".to_owned()
    } else {
        "No external discussions linked".to_owned()
    };
    let history_visibility = flow_projection_field_string(flow, None, &["history_visibility"])
        .unwrap_or_else(|| {
            if locked_flow.is_some() {
                "lazy_link (cross-Space)".to_owned()
            } else {
                "Managed by board".to_owned()
            }
        });
    KanbanCard {
        id: flow.flow_id.clone(),
        rank: flow_projection_field_string(flow, flow.rank.as_deref(), &["rank"])
            .unwrap_or_default(),
        title: title.clone(),
        description,
        body: flow_body_display_text(flow.body.as_ref().or_else(|| flow.fields.get("body"))),
        synthesis: flow_body_display_text(flow.fields.get("synthesis").or_else(|| {
            flow.fields
                .get("tracks")
                .and_then(|tracks| tracks.get("synthesis"))
                .and_then(|track| track.get("body"))
        })),
        labels: flow_projection_labels(flow),
        assignee: flow_projection_field_string(flow, None, &["assignee"])
            .unwrap_or_else(|| "—".to_owned()),
        due: flow_projection_field_string(flow, None, &["due_at", "due"])
            .unwrap_or_else(|| "—".to_owned()),
        primary_flow_id: flow.flow_id.clone(),
        locked_flow,
        external_visibility,
        history_visibility,
        activity_hint: "Activity derived from cx.flow.move / cx.flow.update events.".to_owned(),
        audit_hint: "Audit trail in /audit shows the full Event Envelope chain.".to_owned(),
        state: CardState::Synced,
        lifecycle: flow_lifecycle_from_wire(&flow.state),
    }
}

#[derive(Clone, Debug, PartialEq)]
struct LocalCardCreate {
    board_space_id: String,
    list_space_id: String,
    card: KanbanCard,
}

fn local_created_card(
    flow_id: String,
    title: String,
    rank: String,
    description: String,
) -> KanbanCard {
    KanbanCard {
        id: flow_id.clone(),
        rank,
        title,
        description,
        body: String::new(),
        synthesis: String::new(),
        labels: vec!["draft".to_owned()],
        assignee: "yougen".to_owned(),
        due: "unscheduled".to_owned(),
        primary_flow_id: flow_id,
        locked_flow: None,
        external_visibility: "Not shared externally".to_owned(),
        history_visibility: "board default".to_owned(),
        activity_hint: "Activity will populate after the first accepted Move.".to_owned(),
        audit_hint: "Write queued locally until cx.events.submit succeeds.".to_owned(),
        state: CardState::Queued,
        lifecycle: FlowLifecycleState::Active,
    }
}

fn overlay_local_card_creates(
    columns: Vec<KanbanColumn>,
    state_store: &LocalStateStore,
    board_space_id: &str,
) -> Vec<KanbanColumn> {
    let state = state_store.load();
    let columns = overlay_local_card_create_records(columns, &state.raw_operations, board_space_id);
    overlay_local_card_update_records(columns, &state.raw_operations)
}

/// Re-apply locally-queued `cx.flow.update` patches on top of the
/// server projection. Without this overlay, optimistic edits to a
/// card's title / summary / body / fields would vanish on page reload
/// because the server projection is refetched but the local mutation
/// lived only in the in-memory `columns` signal. The reducer copy of
/// each Move is the source of truth once the server confirms, but in
/// the meantime we keep the user's edit visible by replaying the
/// queued payload here. Ops marked as terminally-failed are skipped
/// so a rejected edit doesn't keep clobbering the projection.
fn overlay_local_card_update_records(
    mut columns: Vec<KanbanColumn>,
    raw_operations: &[RawOperationRecord],
) -> Vec<KanbanColumn> {
    for update in raw_operations
        .iter()
        .filter_map(local_card_update_from_raw_operation)
    {
        for column in columns.iter_mut() {
            if let Some(card) = column
                .cards
                .iter_mut()
                .find(|card| card.id == update.flow_id)
            {
                apply_card_update_overlay(card, &update);
            }
        }
    }
    columns
}

#[derive(Clone, Debug, PartialEq)]
struct LocalCardUpdate {
    flow_id: String,
    title: Option<Option<String>>,
    summary: Option<Option<String>>,
    body: Option<Option<String>>,
    synthesis: Option<Option<String>>,
    fields: Option<Value>,
}

fn local_card_update_from_raw_operation(record: &RawOperationRecord) -> Option<LocalCardUpdate> {
    let payload = &record.payload;
    let kind = json_path_string(Some(payload), &["kind"])
        .or_else(|| json_path_string(Some(payload), &["wire_kind"]))?;
    if kind != "cx.flow.update" {
        return None;
    }
    let write_state =
        json_path_string(Some(payload), &["write_state"]).unwrap_or_else(|| "queued".to_owned());
    if matches!(
        write_state.as_str(),
        "failed" | "rejected" | "quarantined" | "cancelled" | "canceled" | "dropped"
    ) {
        return None;
    }
    let body = payload.get("body").or_else(|| payload.get("payload"))?;
    let flow_id = json_path_string(Some(body), &["flow_id"])
        .or_else(|| json_path_string(Some(body), &["target_ref"]))?;
    let patch = body.get("patch")?.as_object()?;

    fn extract_set_unset(op: &Value) -> Option<Option<String>> {
        let op_kind = op.get("$op").and_then(Value::as_str)?;
        match op_kind {
            "set" => op
                .get("value")
                .and_then(Value::as_str)
                .map(|s| Some(s.to_owned())),
            "unset" => Some(None),
            _ => None,
        }
    }

    let title = patch.get("title").and_then(extract_set_unset);
    let summary = patch.get("summary").and_then(extract_set_unset);
    let body_op = patch.get("body").and_then(extract_set_unset);
    let synthesis = patch.get("synthesis").and_then(extract_set_unset);
    let fields = patch.get("fields").and_then(|fields_op| {
        if fields_op.get("$op").and_then(Value::as_str) == Some("set") {
            fields_op.get("value").cloned()
        } else {
            None
        }
    });

    Some(LocalCardUpdate {
        flow_id,
        title,
        summary,
        body: body_op,
        synthesis,
        fields,
    })
}

fn apply_card_update_overlay(card: &mut KanbanCard, update: &LocalCardUpdate) {
    if let Some(slot) = &update.title {
        card.title = slot.clone().unwrap_or_default();
    }
    if let Some(slot) = &update.summary {
        card.description = slot.clone().unwrap_or_default();
    }
    if let Some(slot) = &update.body {
        card.body = slot.clone().unwrap_or_default();
    }
    if let Some(slot) = &update.synthesis {
        card.synthesis = slot.clone().unwrap_or_default();
    }
    if let Some(fields) = &update.fields {
        if let Some(labels) = fields.get("labels").and_then(Value::as_array) {
            card.labels = labels
                .iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect();
        }
        if let Some(assignee) = fields.get("assignee").and_then(Value::as_str) {
            card.assignee = display_optional_card_field(assignee);
        }
        if let Some(due) = fields
            .get("due_at")
            .or_else(|| fields.get("due"))
            .and_then(Value::as_str)
        {
            card.due = display_optional_card_field(due);
        }
    }
    card.state = CardState::Queued;
}

fn overlay_local_card_create_records(
    mut columns: Vec<KanbanColumn>,
    raw_operations: &[RawOperationRecord],
    board_space_id: &str,
) -> Vec<KanbanColumn> {
    let board_space_id = board_space_id.trim();
    if board_space_id.is_empty() {
        return columns;
    }

    let mut existing_card_ids = columns
        .iter()
        .flat_map(|column| column.cards.iter().map(|card| card.id.clone()))
        .collect::<BTreeSet<_>>();
    for local_create in raw_operations
        .iter()
        .filter_map(local_card_create_from_raw_operation)
    {
        if local_create.board_space_id != board_space_id {
            continue;
        }
        if existing_card_ids.contains(&local_create.card.id) {
            continue;
        }
        let Some(column) = columns
            .iter_mut()
            .find(|column| column.id == local_create.list_space_id)
        else {
            continue;
        };
        existing_card_ids.insert(local_create.card.id.clone());
        column.cards.push(local_create.card);
        sort_kanban_cards(&mut column.cards);
    }

    columns
}

fn local_card_create_from_raw_operation(record: &RawOperationRecord) -> Option<LocalCardCreate> {
    let payload = &record.payload;
    let kind = json_path_string(Some(payload), &["kind"])
        .or_else(|| json_path_string(Some(payload), &["wire_kind"]))?;
    if kind != "cx.flow.create" {
        return None;
    }
    let write_state =
        json_path_string(Some(payload), &["write_state"]).unwrap_or_else(|| "queued".to_owned());
    if matches!(
        write_state.as_str(),
        "failed" | "rejected" | "quarantined" | "cancelled" | "canceled" | "dropped"
    ) {
        return None;
    }

    let effect = payload.get("effect");
    let body = payload.get("body").or_else(|| payload.get("payload"));
    let position_component = flow_position_component(body);
    let flow_id = json_path_string(effect, &["flow_id"])
        .or_else(|| json_path_string(body, &["flow_id"]))
        .or_else(|| json_path_string(body, &["object", "id"]))?;
    let board_space_id = json_path_string(effect, &["board_space_id"])
        .or_else(|| json_path_string(position_component, &["board_space_id"]))
        .or_else(|| json_path_string(body, &["object", "fields", "board_space_id"]))
        .or_else(|| json_path_string(body, &["fields", "board_space_id"]))?;
    let list_space_id = json_path_string(effect, &["list_space_id"])
        .or_else(|| json_path_string(position_component, &["list_space_id"]))
        .or_else(|| json_path_string(body, &["object", "fields", "list_space_id"]))
        .or_else(|| json_path_string(body, &["fields", "list_space_id"]))?;
    let title = json_path_string(effect, &["title"])
        .or_else(|| json_path_string(body, &["object", "title"]))
        .or_else(|| json_path_string(body, &["title"]))
        .unwrap_or_else(|| flow_id.clone());
    let rank = json_path_string(effect, &["rank"])
        .or_else(|| json_path_string(position_component, &["rank"]))
        .or_else(|| json_path_string(body, &["object", "fields", "rank"]))
        .or_else(|| json_path_string(body, &["rank"]))
        .unwrap_or_else(|| "U".to_owned());
    let description = json_path_string(effect, &["description"])
        .or_else(|| json_path_string(effect, &["summary"]))
        .or_else(|| json_path_string(body, &["object", "summary"]))
        .or_else(|| json_path_string(body, &["summary"]))
        .unwrap_or_else(|| LOCAL_PENDING_CARD_DESCRIPTION.to_owned());

    Some(LocalCardCreate {
        board_space_id,
        list_space_id,
        card: local_created_card(flow_id, title, rank, description),
    })
}

fn flow_position_component(body: Option<&Value>) -> Option<&Value> {
    body?
        .get("components")?
        .as_array()?
        .iter()
        .find(|component| {
            component.get("family").and_then(Value::as_str) == Some("cx.component.flow.position.v1")
        })
}

fn json_path_string(value: Option<&Value>, path: &[&str]) -> Option<String> {
    let mut current = value?;
    for segment in path {
        current = current.get(*segment)?;
    }
    current
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

const INCIDENT_INITIAL_STATUS: &str = "investigating";

fn incident_status_transition_local_error(current: &str, target: &str) -> Option<&'static str> {
    if current == target {
        return None;
    }
    match (current, target) {
        ("investigating", "resolved") => Some("invalid transition: must mitigate first"),
        _ => None,
    }
}

#[component]
pub fn KanbanPanel(
    base_url: String,
    plaintext_service_did: String,
    token: Signal<String>,
    account_did: String,
    selected_space: String,
    projection_realm_id: String,
    selected_space_scope: Vec<String>,
    sync_cursor: Signal<String>,
    frontier_state: Signal<String>,
    state_store: Signal<LocalStateStore>,
    event_write_ready: bool,
) -> Element {
    // T20 — load board projection from API when available, otherwise seed.
    // Source signal lets the UI surface persisted API projection vs
    // explicit demo seed in the board header.
    let seed_fallback_allowed = kanban_seed_fallback_allowed(&base_url);
    let initial_api_columns = try_load_api_columns("");
    let initial_source = match initial_api_columns {
        Some(_) => BoardProjectionSource::ApiDerived,
        None if seed_fallback_allowed => BoardProjectionSource::SeedFallback,
        None => BoardProjectionSource::Unavailable,
    };
    let initial_columns = initial_api_columns.unwrap_or_else(|| {
        if seed_fallback_allowed {
            seed_columns()
        } else {
            Vec::new()
        }
    });
    let navigator = use_navigator();
    let route = use_route::<Route>();
    // The board id lives in the URL (`/kanban/<realm>/board/<board>` and
    // its `/task/<flow>` extension). Seeding `selected_board_space_id`
    // from the route — instead of always `board_options.first()` — is
    // what makes a refresh restore the exact board the user had open,
    // including when the open card is a local draft the server
    // projection does not know about yet.
    let routed_board_id = route_board_id(&route);
    let initial_board_options = initial_board_space_options(seed_fallback_allowed);
    let initial_board_space_id = routed_board_id.clone().unwrap_or_else(|| {
        initial_board_options
            .first()
            .map(|option| option.id.clone())
            .unwrap_or_default()
    });
    let initial_columns = {
        let store = state_store.read();
        overlay_local_card_creates(initial_columns, &store, &initial_board_space_id)
    };
    let mut columns = use_signal(|| initial_columns);
    let mut board_space_options = use_signal(move || initial_board_options.clone());
    let mut selected_board_space_id = use_signal(move || initial_board_space_id.clone());
    let mut board_view_id = use_signal(String::new);
    let mut lifecycle_container_projection =
        use_signal(Vec::<crate::api::SpaceContainerProjectionView>::new);
    let mut lifecycle_flow_projection = use_signal(Vec::<crate::api::FlowProjectionView>::new);
    // Cap-Gate-2: consume the app-level CapabilityEngine context so the
    // Archive / Restore buttons can pre-gate themselves. When the engine
    // carries no grants for the actor the gate stays open (yougen still
    // trusts the server). Cap-Gate-3 (below) computes the per-button
    // gate inside the render path.
    let capability_engine = use_context::<Signal<crate::capability::CapabilityEngine>>();
    let mut projection_source = use_signal(|| initial_source);
    let mut new_board_title = use_signal(|| "Board".to_owned());
    let mut new_column_title = use_signal(String::new);
    let mut new_card_title = use_signal(String::new);
    let mut adding_card_to = use_signal(|| Option::<String>::None);
    let mut selected_card = use_signal(|| Option::<KanbanCard>::None);
    let mut board_popover = use_signal(BoardToolbarPopover::default);
    let mut editing_card_detail = use_signal(|| false);
    let mut card_edit_scope = use_signal(CardEditScope::default);
    let mut card_detail_sidebar_visible = use_signal(|| true);
    let mut card_detail_actions_open = use_signal(|| false);
    let mut card_detail_description_expanded = use_signal(|| false);
    let mut card_detail_tab = use_signal(CardDetailContentTab::default);
    let mut card_detail_sidebar_tab = use_signal(CardDetailSidebarTab::default);
    let mut card_detail_overlay_press_started = use_signal(|| false);
    let mut card_detail_overlay_press_ended = use_signal(|| false);
    let mut card_detail_docked = use_signal(read_card_detail_docked);
    let mut card_detail_dock_width = use_signal(read_card_detail_dock_width);
    let mut card_detail_resizing = use_signal(|| false);
    let mut card_detail_resize_start_x = use_signal(|| 0.0_f64);
    let mut card_detail_resize_start_width = use_signal(|| 0.0_f64);
    let mut card_edit_title = use_signal(String::new);
    let mut card_edit_description = use_signal(String::new);
    let mut card_edit_body = use_signal(String::new);
    let mut card_edit_synthesis = use_signal(String::new);
    let mut card_edit_labels = use_signal(String::new);
    let mut card_edit_assignee = use_signal(String::new);
    let mut card_edit_due = use_signal(String::new);
    let mut dragging_card = use_signal(|| Option::<DraggedCard>::None);
    let mut dragging_column = use_signal(|| Option::<DraggedColumn>::None);
    let incident_flow_id = use_signal(|| format!("cx:flow:{}", uuid_v7()));
    let incident_status_current = use_signal(|| INCIDENT_INITIAL_STATUS.to_owned());
    let mut incident_status_select = use_signal(|| INCIDENT_INITIAL_STATUS.to_owned());
    let incident_status_error = use_signal(String::new);
    let incident_flow_initialized = use_signal(|| false);
    let write_records = use_signal(Vec::<BoardWriteRecord>::new);
    let mut board_status = use_signal(|| {
        if initial_source == BoardProjectionSource::Unavailable {
            "Board data unavailable; sample fallback disabled for this server".to_owned()
        } else if event_write_ready {
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
    let selected_board_label = {
        let board_id = selected_board_space_id();
        board_space_options()
            .iter()
            .find(|option| option.id == board_id)
            .map(|option| option.title.clone())
            .unwrap_or_else(|| crate::i18n::tr("kanban.board_title"))
    };
    let selected_board_space_id_value = selected_board_space_id();
    let selected_board_space_id_label = short_protocol_id(&selected_board_space_id_value);
    let board_view_id_value = board_view_id();
    let board_view_id_label = short_protocol_id(&board_view_id_value);

    {
        let routed_flow_id = route_card_flow_id(&route);
        use_effect(move || {
            let Some(flow_id) = routed_flow_id.clone() else {
                return;
            };
            if selected_card()
                .as_ref()
                .is_some_and(|card| card_matches_flow_id(card, &flow_id))
            {
                return;
            }
            if let Some(card) = find_card_by_flow_id(&columns.read(), &flow_id) {
                let draft = card_detail_draft_from_card(&card);
                card_edit_title.set(draft.title);
                card_edit_description.set(draft.description);
                card_edit_body.set(draft.body);
                card_edit_synthesis.set(draft.synthesis);
                card_edit_labels.set(draft.labels.join(", "));
                card_edit_assignee.set(draft.assignee);
                card_edit_due.set(draft.due);
                editing_card_detail.set(false);
                card_detail_actions_open.set(false);
                card_detail_description_expanded.set(false);
                card_detail_tab.set(CardDetailContentTab::Description);
                card_detail_overlay_press_started.set(false);
                card_detail_overlay_press_ended.set(false);
                selected_card.set(Some(card));
            }
        });
    }

    // Route board → selection sync. The board id is authoritative when
    // it is present in the URL (`/kanban/<realm>/board/<board>` and the
    // `/task/<flow>` extension). This effect keeps
    // `selected_board_space_id` aligned with the route across in-app
    // navigations (back/forward, arriving from another KanbanPanel) and
    // re-projects the columns from the cached lifecycle snapshot so the
    // matching board's lists/cards render without waiting for a refetch.
    // The initial mount is already handled by seeding the signal from
    // the route above; this effect covers later route changes.
    {
        let routed_board_id = route_board_id(&route);
        use_effect(move || {
            let Some(board_id) = routed_board_id.clone() else {
                return;
            };
            if selected_board_space_id() == board_id {
                return;
            }
            selected_board_space_id.set(board_id.clone());
            let containers = lifecycle_container_projection();
            let flows = lifecycle_flow_projection();
            if containers.is_empty() && flows.is_empty() {
                return;
            }
            let (projected_columns, options, projected_board_id) =
                columns_from_lifecycle_projection(&containers, &flows, &board_id);
            if projected_board_id.as_deref() == Some(board_id.as_str()) {
                if !options.is_empty() {
                    board_space_options.set(options);
                }
                let projected_columns =
                    overlay_local_card_creates(projected_columns, &state_store.read(), &board_id);
                if columns() != projected_columns {
                    columns.set(projected_columns);
                }
                projection_source.set(BoardProjectionSource::ApiDerived);
            }
        });
    }

    // Route → board reconciler. When the URL points at a card-detail
    // page (`/kanban/<realm>/task/<flow>`) and the card's home board
    // is NOT the currently-selected board, switch the board and
    // re-project the columns from the cached lifecycle snapshot. This
    // handles the case where the user arrives at the card-detail URL
    // via a fresh KanbanPanel mount (e.g. coming from `/spaces/<realm>`
    // Board tab where a different KanbanPanel instance held the
    // previous selection) — the bootstrap fetch may have already
    // picked `board_options.first()` before this reconciler runs, so
    // we override here whenever the URL's task_id resolves to a known
    // flow with a different `board_space_id`.
    {
        let routed_flow_id = route_card_flow_id(&route);
        use_effect(move || {
            let Some(flow_id) = routed_flow_id.clone() else {
                return;
            };
            let flow_items = lifecycle_flow_projection.read();
            let Some(flow_board) = flow_items
                .iter()
                .find(|f| f.flow_id == flow_id)
                .and_then(|f| f.board_space_id.clone())
            else {
                return;
            };
            if selected_board_space_id() == flow_board {
                return;
            }
            // Re-project columns for the resolved board so the existing
            // card-detail effect (above) can find the card on the next
            // render cycle.
            let containers = lifecycle_container_projection.read().clone();
            let flows = flow_items.clone();
            drop(flow_items);
            let (projected_columns, options, projected_board_id) =
                columns_from_lifecycle_projection(&containers, &flows, &flow_board);
            if let Some(board_id) = projected_board_id {
                if !options.is_empty() {
                    board_space_options.set(options);
                }
                let board_id_for_overlay = board_id.clone();
                selected_board_space_id.set(board_id);
                let projected_columns = overlay_local_card_creates(
                    projected_columns,
                    &state_store.read(),
                    &board_id_for_overlay,
                );
                if columns() != projected_columns {
                    columns.set(projected_columns);
                }
            }
        });
    }

    // T20 — auto-refresh-on-mount. The component renders empty or explicit
    // SeedFallback synchronously, then fires an async fetch against soland's
    // `/api/v1/views/:id/projection` when a View id is provided. Success
    // promotes the board to ApiDerived; failure leaves the current server
    // projection / empty state in place with a status note.
    // The `bootstrapped` guard ensures we run this only once per mount —
    // matching the login view's `auto_capture_bootstrapped` pattern so a
    // second render (e.g. from a parent signal) doesn't re-trigger the
    // fetch.
    let mut bootstrapped = use_signal(|| false);
    let auto_base = base_url.clone();
    let auto_token = token;
    let auto_seed_fallback_allowed = seed_fallback_allowed;
    let auto_board_view_id = board_view_id;
    use_future(move || {
        let base = auto_base.clone();
        async move {
            if bootstrapped() {
                return;
            }
            bootstrapped.set(true);
            let api_token = auto_token();
            let view = auto_board_view_id();
            if view.trim().is_empty() {
                board_status.set(
                    "No board View selected; using Space-container/Flow projections and local queue only"
                        .to_owned(),
                );
                return;
            }
            match with_authed_api(&base, api_token, |api| async move {
                api.collection_projection(&view).await
            })
            .await
            {
                Ok(projection) => {
                    let cols = overlay_local_card_creates(
                        collection_projection_to_columns(&projection),
                        &state_store.read(),
                        &selected_board_space_id(),
                    );
                    if !cols.is_empty() {
                        columns.set(cols);
                    }
                    projection_source.set(BoardProjectionSource::ApiDerived);
                    board_status.set(format!(
                        "Board view loaded: {} group(s) · view={}",
                        projection.groups.len(),
                        projection.view_id.as_str()
                    ));
                }
                Err(err) => {
                    if auto_seed_fallback_allowed {
                        projection_source.set(BoardProjectionSource::SeedFallback);
                        board_status.set(format!(
                            "Board data unavailable on mount: {}; showing sample fallback",
                            err.display()
                        ));
                    } else {
                        columns.set(Vec::new());
                        projection_source.set(BoardProjectionSource::Unavailable);
                        board_status.set(format!(
                            "Board data unavailable on mount: {}; sample fallback disabled",
                            err.display()
                        ));
                    }
                }
            }
        }
    });

    // F-KANBAN-LIVE-1: poll the same `/views/:id/projection` endpoint
    // every KANBAN_LIVE_POLL_SECONDS so another device's
    // `cx.flow.move` / `cx.flow.reorder` / `cx.flow.update` lands
    // in this client without a manual refresh. The poll is deliberately
    // simple (request-per-tick) rather than a long-poll subscription:
    // the soland endpoint already cheap-paginates, and the polling
    // worker stops touching the network when the View id is empty
    // (so it stays a no-op for the seed-fallback path).
    //
    // A full sync_engine projection push is the natural follow-up;
    // this revision proves the wire-up by closing the "another device
    // moved a card, mine doesn't update" gap.
    let live_base = base_url.clone();
    let live_token = token;
    let live_board_view_id = board_view_id;
    use_future(move || {
        let base = live_base.clone();
        async move {
            // Defer the first poll so the bootstrap fetch finishes
            // first and we don't double-fire on mount.
            #[cfg(not(target_arch = "wasm32"))]
            tokio::time::sleep(std::time::Duration::from_secs(KANBAN_LIVE_POLL_SECONDS)).await;
            loop {
                let api_token = live_token();
                let view = live_board_view_id();
                if !view.trim().is_empty() {
                    let view_for_call = view.clone();
                    if let Ok(projection) = with_authed_api(&base, api_token, |api| async move {
                        api.collection_projection(&view_for_call).await
                    })
                    .await
                    {
                        let cols = overlay_local_card_creates(
                            collection_projection_to_columns(&projection),
                            &state_store.read(),
                            &selected_board_space_id(),
                        );
                        // Only overwrite when the server actually
                        // returned a non-empty projection — an empty
                        // response shouldn't wipe a locally-queued
                        // optimistic move.
                        if !cols.is_empty() && cols != columns() {
                            columns.set(cols);
                            projection_source.set(BoardProjectionSource::ApiDerived);
                        }
                    }
                }
                #[cfg(not(target_arch = "wasm32"))]
                tokio::time::sleep(std::time::Duration::from_secs(KANBAN_LIVE_POLL_SECONDS)).await;
                #[cfg(target_arch = "wasm32")]
                break; // wasm has no tokio::time; bail after one
                // tick — the bootstrap fetch already ran.
            }
        }
    });

    // Hydrate Space-container / Flow lifecycle state from the soland
    // `/api/v1/projection/{spaces|flows}` endpoints so
    // an Archive accepted on the server stays archived after a page
    // refresh. The probe is fire-and-forget; a 404 / 401 just leaves
    // columns/cards in their `Active` default and the user is no worse
    // off than before this wiring.
    let mut lifecycle_bootstrapped_for = use_signal(String::new);
    let lifecycle_realm_id = projection_realm_id.trim().to_owned();
    // When the kanban panel mounts on a card-detail URL
    // (`/kanban/<realm>/task/<flow>`), the user typically came from a
    // different shell (e.g. `/spaces/<realm>` with the Board tab open)
    // and the freshly-mounted panel has no `selected_board_space_id`
    // yet. Without a hint, `columns_from_lifecycle_projection` falls
    // back to `board_options.first()`, which may not be the board that
    // actually contains the card. Capture the routed flow id so the
    // lifecycle fetch below can resolve the card's home board.
    let lifecycle_routed_flow_id = route_card_flow_id(&route);
    if !lifecycle_realm_id.is_empty() && lifecycle_bootstrapped_for() != lifecycle_realm_id {
        lifecycle_bootstrapped_for.set(lifecycle_realm_id.clone());
        let base = base_url.clone();
        let lifecycle_token = token;
        let lifecycle_routed_flow_id = lifecycle_routed_flow_id.clone();
        spawn(async move {
            let realm_id = lifecycle_realm_id.clone();
            let api_token = lifecycle_token();
            let containers_res = {
                let realm_id = realm_id.clone();
                with_authed_api(&base, api_token.clone(), |api| async move {
                    api.list_space_container_projections(&realm_id).await
                })
                .await
            };
            let flows_res = {
                let realm_id = realm_id.clone();
                with_authed_api(&base, api_token, |api| async move {
                    api.list_flow_projections(&realm_id).await
                })
                .await
            };
            let mut applied = 0_usize;
            let mut server_projection_applied = false;
            let containers_ok = containers_res.is_ok();
            let flows_ok = flows_res.is_ok();
            if containers_ok || flows_ok {
                let container_items = containers_res
                    .ok()
                    .map(|resp| resp.items)
                    .unwrap_or_default();
                let flow_items = flows_res.ok().map(|resp| resp.items).unwrap_or_default();
                lifecycle_container_projection.set(container_items.clone());
                lifecycle_flow_projection.set(flow_items.clone());
                let current_board = selected_board_space_id();
                // If the user landed on a card-detail URL and no board
                // is selected yet, resolve the card's home board from
                // the just-fetched flow projection so the matching
                // board is loaded (instead of `board_options.first()`).
                let current_board = if current_board.trim().is_empty() {
                    lifecycle_routed_flow_id
                        .as_deref()
                        .and_then(|flow_id| {
                            flow_items
                                .iter()
                                .find(|f| f.flow_id == flow_id)
                                .and_then(|f| f.board_space_id.clone())
                        })
                        .unwrap_or(current_board)
                } else {
                    current_board
                };
                let (projected_columns, options, projected_board_id) =
                    columns_from_lifecycle_projection(
                        &container_items,
                        &flow_items,
                        &current_board,
                    );
                if let Some(board_id) = projected_board_id {
                    if !options.is_empty() {
                        board_space_options.set(options);
                    }
                    let board_id_for_overlay = board_id.clone();
                    selected_board_space_id.set(board_id);
                    let projected_columns = overlay_local_card_creates(
                        projected_columns,
                        &state_store.read(),
                        &board_id_for_overlay,
                    );
                    let list_count = projected_columns.len();
                    let card_count = projected_columns
                        .iter()
                        .map(|column| column.cards.len())
                        .sum::<usize>();
                    if columns() != projected_columns {
                        columns.set(projected_columns);
                        applied += list_count.max(1);
                    }
                    projection_source.set(BoardProjectionSource::ApiDerived);
                    server_projection_applied = true;
                    board_status.set(format!(
                        "Board loaded: {list_count} list(s), {card_count} card(s)"
                    ));
                } else {
                    let mut cols = columns.write();
                    for view in &container_items {
                        if let Some(col) = cols.iter_mut().find(|c| c.id == view.container_space_id)
                        {
                            let new_state = space_container_state_from_wire(&view.state);
                            if col.state != new_state {
                                col.state = new_state;
                                applied += 1;
                            }
                        }
                    }
                    for view in &flow_items {
                        for col in cols.iter_mut() {
                            if let Some(card) = col.cards.iter_mut().find(|c| c.id == view.flow_id)
                            {
                                let new_lifecycle = flow_lifecycle_from_wire(&view.state);
                                if card.lifecycle != new_lifecycle {
                                    card.lifecycle = new_lifecycle;
                                    applied += 1;
                                }
                            }
                        }
                    }
                }
            }
            if applied > 0 && !server_projection_applied {
                board_status.set(format!("Board refreshed: {applied} item(s) reconciled"));
            }
        });
    }

    let write_record_count = write_records().len();
    let manual_review_count = write_records()
        .iter()
        .filter(|record| matches!(record.state, CardState::Conflict | CardState::Quarantined))
        .count();
    let board_selected = !selected_board_space_id().trim().is_empty();
    // Pre-wrapped Realm id for building board / card URLs inside event
    // handlers (the raw `selected_space` String can't be moved into more
    // than one closure).
    let board_route_space_id = card_detail_route_space_id(&selected_space);
    rsx! {
        div { class: "timeline kanban-panel", "data-testid": "kanban-panel",
            div { class: "event board-header board-toolbar",
                div { class: "board-toolbar-main",
                    div { class: "board-title-block",
                        div { class: "event-head board-kicker",
                            span { {crate::i18n::tr("kanban.board_header")} }
                            span {
                                title: "writes to {selected_space}",
                                "{scope_label}"
                            }
                        }
                        div { class: "space-title", "{selected_board_label}" }
                    }
                    div { class: "actions board-toolbar-controls", "data-testid": "board-space-selector",
                        if board_popover() != BoardToolbarPopover::None {
                            div {
                                class: "board-popover-scrim",
                                onclick: move |_| board_popover.set(BoardToolbarPopover::None),
                            }
                        }
                        select {
                            class: "board-select",
                            "data-testid": "board-space-select",
                            value: "{selected_board_space_id}",
                            onchange: move |event| {
                                let board_id = event.value();
                                selected_board_space_id.set(board_id.clone());
                                board_popover.set(BoardToolbarPopover::None);
                                // Persist the board in the URL so a refresh
                                // restores it instead of falling back to the
                                // first board. Closing any open card too: a
                                // board switch should not keep a card from a
                                // different board mounted.
                                selected_card.set(None);
                                let _ = navigator
                                    .replace(kanban_board_route(&board_route_space_id, &board_id));
                                let containers = lifecycle_container_projection();
                                let flows = lifecycle_flow_projection();
                                if board_id.trim().is_empty() {
                                    columns.set(Vec::new());
                                    adding_card_to.set(None);
                                    board_status.set("Select or create a board before adding lists".to_owned());
                                    return;
                                }
                                if containers.is_empty() && flows.is_empty() {
                                    board_status.set(format!(
                                        "Board selected · {}",
                                        short_protocol_id(&board_id)
                                    ));
                                    return;
                                }
                                let (projected_columns, options, projected_board_id) =
                                    columns_from_lifecycle_projection(
                                        &containers,
                                        &flows,
                                        &board_id,
                                    );
                                if !options.is_empty() {
                                    board_space_options.set(options);
                                }
                                if projected_board_id.as_deref() == Some(board_id.as_str()) {
                                    let projected_columns = overlay_local_card_creates(
                                        projected_columns,
                                        &state_store.read(),
                                        &board_id,
                                    );
                                    let list_count = projected_columns.len();
                                    let card_count = projected_columns
                                        .iter()
                                        .map(|column| column.cards.len())
                                        .sum::<usize>();
                                    columns.set(projected_columns);
                                    projection_source.set(BoardProjectionSource::ApiDerived);
                                    board_status.set(format!(
                                        "Board loaded: {list_count} list(s), {card_count} card(s)"
                                    ));
                                } else {
                                    columns.set(Vec::new());
                                    adding_card_to.set(None);
                                    board_status.set(format!(
                                        "No list projection available for selected Board · {}",
                                        short_protocol_id(&board_id)
                                    ));
                                }
                            },
                            option {
                                value: "",
                                selected: selected_board_space_id().is_empty(),
                                "Select board"
                            }
                            for board_option in board_space_options().iter() {
                                option {
                                    value: "{board_option.id}",
                                    selected: selected_board_space_id() == board_option.id,
                                    "{board_option.title}"
                                }
                            }
                        }
                        div {
                            class: if board_popover() == BoardToolbarPopover::CreateBoard { "board-popover-host is-open" } else { "board-popover-host" },
                            button {
                                class: "btn sm secondary board-popover-trigger",
                                "data-testid": "new-board-toggle",
                                onclick: move |_| {
                                    let next = if board_popover() == BoardToolbarPopover::CreateBoard {
                                        BoardToolbarPopover::None
                                    } else {
                                        BoardToolbarPopover::CreateBoard
                                    };
                                    board_popover.set(next);
                                },
                                "New board"
                            }
                            if board_popover() == BoardToolbarPopover::CreateBoard {
                                div {
                                    class: "board-popover-panel",
                                    onclick: move |event: dioxus::events::MouseEvent| event.stop_propagation(),
                                    input {
                                        "data-testid": "new-board-title-input",
                                        value: "{new_board_title}",
                                        placeholder: "Board title",
                                        oninput: move |evt| new_board_title.set(evt.value()),
                                    }
                                    button {
                                        class: "primary",
                                        "data-testid": "create-board-space-button",
                                        onclick: {
                                            let base = base_url.clone();
                                            let space = selected_space.clone();
                                            let actor = account_did.clone();
                                            move |_| {
                                                let title = new_board_title().trim().to_owned();
                                                if title.is_empty() {
                                                    board_status.set("board title is required".to_owned());
                                                    return;
                                                }
                                                if actor.trim().is_empty() {
                                                    board_status.set("sign in before creating a Board".to_owned());
                                                    return;
                                                }
                                                let board_space_id = format!("cx:space:{}", uuid_v7());
                                                board_space_options.write().push(BoardSpaceOption {
                                                    id: board_space_id.clone(),
                                                    title: title.clone(),
                                                    state: SpaceContainerLifecycleState::Active,
                                                });
                                                selected_board_space_id.set(board_space_id.clone());
                                                let _ = navigator
                                                    .replace(kanban_board_route(&space, &board_space_id));
                                                columns.set(Vec::new());
                                                adding_card_to.set(None);
                                                let op = crate::operation::cx_ops::space_create(
                                                    &space,
                                                    &actor,
                                                    &board_space_id,
                                                    "board",
                                                    &title,
                                                    None,
                                                    None,
                                                )
                                                .build("yougen");
                                                submit_kanban_operation_event(
                                                    base.clone(),
                                                    token,
                                                    space.clone(),
                                                    op,
                                                    state_store,
                                                    board_status,
                                                );
                                                board_status.set("Board created. Add a list before adding cards.".to_owned());
                                                new_board_title.set("Board".to_owned());
                                                board_popover.set(BoardToolbarPopover::None);
                                            }
                                        },
                                        "Create Board"
                                    }
                                }
                            }
                        }
                        div {
                            class: if board_popover() == BoardToolbarPopover::Projection { "board-popover-host is-open" } else { "board-popover-host" },
                            button {
                                class: "btn sm secondary board-popover-trigger",
                                "data-testid": "board-projection-toggle",
                                onclick: move |_| {
                                    let next = if board_popover() == BoardToolbarPopover::Projection {
                                        BoardToolbarPopover::None
                                    } else {
                                        BoardToolbarPopover::Projection
                                    };
                                    board_popover.set(next);
                                },
                                "Projection"
                            }
                            if board_popover() == BoardToolbarPopover::Projection {
                                div {
                                    class: "board-popover-panel board-projection-panel",
                                    onclick: move |event: dioxus::events::MouseEvent| event.stop_propagation(),
                                    label { class: "field board-inline-field",
                                        span { "View ID" }
                                        input {
                                            "data-testid": "board-view-id-input",
                                            value: "{board_view_id}",
                                            placeholder: "cx:view:...",
                                            oninput: move |evt| board_view_id.set(evt.value()),
                                        }
                                    }
                                    button {
                                        class: "secondary",
                                        "data-testid": "board-projection-refresh",
                                        onclick: {
                                            // T20 — real API call to soland's
                                            // POST /api/v1/views/:id/projection. Demo seed is
                                            // opt-in so normal boards never show fake cards.
                                            let base = base_url.clone();
                                            move |_| {
                                                let base = base.clone();
                                                let api_token = token();
                                                let view = board_view_id();
                                                if view.trim().is_empty() {
                                                    board_status.set(
                                                        "enter a Board View ID before refreshing collection projection"
                                                            .to_owned(),
                                                    );
                                                    return;
                                                }
                                                board_popover.set(BoardToolbarPopover::None);
                                                spawn(async move {
                                                    match with_authed_api(&base, api_token, |api| async move {
                                                        api.collection_projection(&view).await
                                                    })
                                                    .await
                                                    {
                                                        Ok(projection) => {
                                                            let cols = overlay_local_card_creates(
                                                                collection_projection_to_columns(&projection),
                                                                &state_store.read(),
                                                                &selected_board_space_id(),
                                                            );
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
                                                            if seed_fallback_allowed {
                                                                let cols = overlay_local_card_creates(
                                                                    seed_columns(),
                                                                    &state_store.read(),
                                                                    &selected_board_space_id(),
                                                                );
                                                                columns.set(cols);
                                                                projection_source.set(BoardProjectionSource::SeedFallback);
                                                                board_status.set(format!(
                                                                    "Board data unavailable: {}; showing sample fallback",
                                                                    err.display()
                                                                ));
                                                            } else {
                                                                columns.set(Vec::new());
                                                                projection_source.set(BoardProjectionSource::Unavailable);
                                                                board_status.set(format!(
                                                                    "Board data unavailable: {}; sample fallback disabled",
                                                                    err.display()
                                                                ));
                                                            }
                                                        }
                                                    }
                                                });
                                            }
                                        },
                                        {crate::i18n::tr("kanban.refresh_from_api")}
                                    }
                                    details { class: "board-diagnostics", "data-testid": "board-diagnostics",
                                        summary { "Diagnostics" }
                                        div { class: "actions", "data-testid": "board-write-states",
                                            for state in write_state_samples() {
                                                span { class: state.class_name(), "{state.label()}" }
                                            }
                                        }
                                        div { class: "metric-grid", "data-testid": "board-projection-model",
                                            div { class: "metric", strong { "Board" } span { title: "{selected_board_space_id_value}", "{selected_board_space_id_label}" } div { class: "muted", "renderer: kanban" } }
                                            div { class: "metric", strong { "View" } span { title: "{board_view_id_value}", "{board_view_id_label}" } div { class: "muted", "collection projection" } }
                                            div { class: "metric", strong { "Relation" } span { "contains" } div { class: "muted", "List contains Card by rank" } }
                                            div { class: "metric", strong { "Sync" } span { "{frontier_state}" } div { class: "muted", "rebases moves" } }
                                            div { class: "metric", strong { "Writes" } span { if event_write_ready { "Online" } else { "Queued" } } div { class: "muted", "server when online" } }
                                        }
                                        div { class: "muted",
                                            "View lifecycle: create, update, reconcile. Refresh uses server projection; demo seed requires YOUGEN_ALLOW_KANBAN_SEED_FALLBACK=1."
                                        }
                                    }
                                }
                            }
                        }
                        div {
                            class: if board_popover() == BoardToolbarPopover::Queue { "board-popover-host is-open" } else { "board-popover-host" },
                            "data-testid": "board-offline-queue",
                            button {
                                class: "btn sm secondary board-popover-trigger",
                                "data-testid": "board-queue-toggle",
                                onclick: move |_| {
                                    let next = if board_popover() == BoardToolbarPopover::Queue {
                                        BoardToolbarPopover::None
                                    } else {
                                        BoardToolbarPopover::Queue
                                    };
                                    board_popover.set(next);
                                },
                                "Queue {write_record_count}"
                            }
                            if board_popover() == BoardToolbarPopover::Queue {
                                div {
                                    class: "board-popover-panel board-queue-panel",
                                    onclick: move |event: dioxus::events::MouseEvent| event.stop_propagation(),
                                    div { class: "actions board-queue-actions",
                                        button {
                                            class: "secondary",
                                            "data-testid": "replay-board-queue",
                                            onclick: {
                                                // Replay path resubmits a queued Move via
                                                // api.submit_move.
                                                let base = base_url.clone();
                                                move |_| {
                                                    replay_first_move(
                                                        base.clone(),
                                                        token,
                                                        write_records,
                                                        board_status,
                                                    );
                                                }
                                            },
                                            "Replay Queue"
                                        }
                                        span { class: "muted", "{manual_review_count} review / {write_record_count} total" }
                                    }
                                    div { class: "muted", "Queue stays quiet unless a CAS conflict exhausts automatic rebase and needs a board admin." }
                                    for record in write_records() {
                                        {
                                            let move_id_label = short_protocol_id(&record.move_id);
                                            let cell_id_label = short_protocol_id(&record.cell_id);
                                            let anchor_ref_label = short_protocol_id(&record.anchor_ref);
                                            rsx! {
                                                div { class: "event", "data-testid": "board-event-record",
                                                    div { class: "event-head",
                                                        span { "{record.kind}" }
                                                        span { class: record.state.class_name(), "{record.state.label()}" }
                                                    }
                                                    div { class: "muted", title: "{record.move_id}", "move_id {move_id_label}" }
                                                    div { class: "muted", title: "{record.cell_id}", "cell {cell_id_label} / hlc {record.hlc}" }
                                                    div { class: "muted", title: "{record.anchor_ref}", "anchor_ref {anchor_ref_label}" }
                                                    div { class: "muted", "effect {record.effect_summary}" }
                                                    div { class: "muted", "{record.note}" }
                                                }
                                            }
                                        }
                                    }
                                    if write_records().is_empty() {
                                        div { class: "muted", {crate::i18n::tr("kanban.move_queue_empty")} }
                                    }
                                }
                            }
                        }
                    }
                }

                if board_selected {
                    div { class: "board-toolbar-secondary",
                        div { class: "actions board-list-compose",
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
                                    // Lists are Space containers in v1. The optimistic
                                    // local column uses the new Space-container id while
                                    // the write submits `cx.space.create`.
                                    let base = base_url.clone();
                                    let space = selected_space.clone();
                                    let actor = account_did.clone();
                                    move |_| {
                                        let title = new_column_title().trim().to_owned();
                                        if title.is_empty() {
                                            return;
                                        }
                                        if actor.trim().is_empty() {
                                            board_status.set("sign in before adding lists".to_owned());
                                            return;
                                        }
                                        let board_space_id = selected_board_space_id();
                                        if board_space_id.trim().is_empty() {
                                            board_status.set("select or create a Board Space before adding lists".to_owned());
                                            return;
                                        }
                                        let col_count = columns().len();
                                        let rank = format!("r{:03}", col_count + 1);
                                        let list_space_id = format!("cx:space:{}", uuid_v7());
                                        columns.write().push(KanbanColumn {
                                            id: list_space_id.clone(),
                                            title: title.clone(),
                                            rank: rank.clone(),
                                            cards: Vec::new(),
                                            state: SpaceContainerLifecycleState::Active,
                                        });
                                        let op = crate::operation::cx_ops::space_create(
                                            &space,
                                            &actor,
                                            &list_space_id,
                                            "list",
                                            &title,
                                            Some(&board_space_id),
                                            Some(&rank),
                                        )
                                        .build("yougen");
                                        submit_kanban_operation_event(
                                            base.clone(),
                                            token,
                                            space.clone(),
                                            op,
                                            state_store,
                                            board_status,
                                        );
                                        new_column_title.set(String::new());
                                    }
                                },
                                {crate::i18n::tr("kanban.add_list")}
                            }
                        }
                    }
                }
            }

            div { class: "event incident-status-panel", "data-testid": "incident-status-panel",
                div { class: "event-head",
                    span { "Incident status" }
                    span { title: "{incident_flow_id()}", "{short_protocol_id(&incident_flow_id())}" }
                }
                div { class: "actions",
                    label {
                        span { "Status" }
                        select {
                            "data-testid": "incident-status-select",
                            value: "{incident_status_select}",
                            onchange: move |evt| incident_status_select.set(evt.value()),
                            option { value: "investigating", "Investigating" }
                            option { value: "mitigated", "Mitigated" }
                            option { value: "resolved", "Resolved" }
                        }
                    }
                    button {
                        class: "primary",
                        "data-testid": "save-incident-status-button",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            let actor = account_did.clone();
                            move |_| {
                                submit_incident_status_transition(
                                    base.clone(),
                                    token,
                                    space.clone(),
                                    actor.clone(),
                                    incident_flow_id(),
                                    incident_status_select(),
                                    incident_status_current,
                                    incident_flow_initialized,
                                    incident_status_error,
                                    board_status,
                                );
                            }
                        },
                        "Save Status"
                    }
                }
                div {
                    class: "muted",
                    "data-testid": "incident-status-current",
                    "Current: {incident_status_current}"
                }
                if !incident_status_error().is_empty() {
                    div {
                        class: "muted",
                        "data-testid": "incident-status-error",
                        "{incident_status_error}"
                    }
                }
            }

            if manual_review_count > 0 {
                div { class: "event board-conflict-alert", "data-testid": "board-conflict-alert",
                    div {
                        strong { "Board admin review required" }
                        div { class: "muted", "{manual_review_count} queued write(s) need manual conflict resolution before replay." }
                    }
                }
            }

            // F-KANBAN-DRAG-VFX-1: derive a dragging snapshot once per
            // render so every column / card can paint the right visual
            // state. The drag source picks up `dragging-source`
            // (low-opacity ghost), the rest of the columns pick up
            // `drop-zone-available` (subtle outline), and the
            // board-grid root picks up `is-dragging` (sets cursor:
            // grabbing for the whole board).
            {
                let dragging_now = dragging_card();
                let is_dragging = dragging_now.is_some();
                let dragged_card_id_for_match = dragging_now
                    .as_ref()
                    .map(|d| d.card_id.clone())
                    .unwrap_or_default();
                let column_dragging_now = dragging_column();
                let is_column_dragging = column_dragging_now.is_some();
                let board_grid_class = match (is_dragging, is_column_dragging) {
                    (true, true) => "board-grid is-dragging is-column-dragging",
                    (true, false) => "board-grid is-dragging",
                    (false, true) => "board-grid is-column-dragging",
                    (false, false) => "board-grid",
                };
                let board_column_class = if is_dragging || is_column_dragging {
                    "event board-column drop-zone-available"
                } else {
                    "event board-column"
                };
                let visible_columns = columns()
                    .into_iter()
                    .filter(|column| column.state == SpaceContainerLifecycleState::Active)
                    .collect::<Vec<_>>();
                rsx! {
            div { class: "{board_grid_class}", "data-testid": "kanban-board-grid",
                if visible_columns.is_empty() {
                    div { class: "board-empty-state",
                        if board_selected {
                            EmptyState {
                                title: "No lists yet".to_owned(),
                                kind: EmptyStateKind::Empty,
                                message: Some("Add a list before adding cards to this board.".to_owned()),
                                badge_override: Some("empty board".to_owned()),
                                test_id: Some("kanban-empty-board".to_owned()),
                            }
                        } else {
                            EmptyState {
                                title: "No board selected".to_owned(),
                                kind: EmptyStateKind::Empty,
                                message: Some("Create or select a board before adding lists and cards.".to_owned()),
                                badge_override: Some("select board".to_owned()),
                                test_id: Some("kanban-empty-board".to_owned()),
                            }
                        }
                    }
                } else {
                for column in visible_columns.iter() {
                    {
                    let column_id_for_drop = column.id.clone();
                    let column_id_for_drag = column.id.clone();
                    let column_title_for_drop = column.title.clone();
                    let column_title_for_drag = column.title.clone();
                    rsx! {
                    div {
                        class: "{board_column_class}",
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
                            let actor = account_did.clone();
                            move |event| {
                                event.prevent_default();
                                let Some(dragged) = dragging_card() else {
                                    return;
                                };
                                let board_space_id = selected_board_space_id();
                                if board_space_id.trim().is_empty() {
                                    board_status.set("select or create a Board Space before moving cards".to_owned());
                                    return;
                                }
                                dragging_card.set(None);
                                let neighbours = ColumnNeighbours {
                                    prev_rank: last_rank.clone(),
                                    next_rank: None,
                                };
                                let view_id_for_rebase = board_view_id();
                                dispatch_flow_position_move(
                                    base.clone(),
                                    token,
                                    space.clone(),
                                    board_space_id,
                                    view_id_for_rebase,
                                    actor.clone(),
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
                        div {
                            class: "column-drop-target-before",
                            "data-testid": "column-drop-target-before",
                            "aria-label": "Drop column before {column_title_for_drop}",
                            title: "Drop column before {column_title_for_drop}",
                            ondragover: move |event| event.prevent_default(),
                            ondrop: {
                                let target_column_id = column_id_for_drop.clone();
                                let base = base_url.clone();
                                let space = selected_space.clone();
                                let actor = account_did.clone();
                                move |event| {
                                    event.prevent_default();
                                    let Some(dragged) = dragging_column() else {
                                        return;
                                    };
                                    dragging_column.set(None);
                                    let reordered_columns = {
                                        let mut cols = columns.write();
                                        if reorder_column_before(
                                            &mut cols,
                                            &dragged.column_id,
                                            &target_column_id,
                                        ) {
                                            Some(cols.clone())
                                        } else {
                                            None
                                        }
                                    };
                                    if let Some(reordered_columns) = reordered_columns {
                                        submit_column_order_updates(
                                            base.clone(),
                                            token,
                                            space.clone(),
                                            actor.clone(),
                                            reordered_columns,
                                            state_store,
                                            board_status,
                                        );
                                    }
                                }
                            },
                        }
                        div { class: "event-head board-column-head",
                            div { class: "board-column-title",
                                button {
                                    class: "column-drag-handle",
                                    "data-testid": "column-drag-handle",
                                    draggable: "true",
                                    title: "Drag column {column_title_for_drag}",
                                    "aria-label": "Drag column {column_title_for_drag}",
                                    ondragstart: {
                                        let column_id = column_id_for_drag.clone();
                                        move |_| {
                                            dragging_column.set(Some(DraggedColumn {
                                                column_id: column_id.clone(),
                                            }));
                                        }
                                    },
                                    ondragend: move |_| dragging_column.set(None),
                                    "::"
                                }
                                span {
                                    class: "space-title",
                                    "data-testid": "kanban-column-title",
                                    "{column.title}"
                                }
                            }
                            div { class: "board-column-actions",
                            {
                                let gate = capability_gate_for_space_container(
                                    &capability_engine,
                                    &account_did,
                                    &selected_space,
                                    &column.id,
                                    "cx.space.archive",
                                );
                                let title_text = if gate.enabled {
                                    "Archive this list (cx.space.archive)".to_owned()
                                } else {
                                    format!("Archive gated: {}", gate.reason)
                                };
                                let testid_state = if gate.enabled { "open" } else { "denied" };
                                rsx! {
                                    button {
                                        class: "secondary",
                                        "data-testid": "list-archive-button",
                                        "data-space-container-id": "{column.id}",
                                        "data-cap-gate": testid_state,
                                        disabled: !gate.enabled,
                                        title: title_text,
                                        onclick: {
                                            let base = base_url.clone();
                                            let space = selected_space.clone();
                                            let actor = account_did.clone();
                                            let space_container_id = column.id.clone();
                                            move |_| {
                                                dispatch_space_container_lifecycle(
                                                    base.clone(),
                                                    token,
                                                    space.clone(),
                                                    actor.clone(),
                                                    space_container_id.clone(),
                                                    SpaceContainerLifecycleState::Archived,
                                                    columns,
                                                    board_status,
                                                );
                                            }
                                        },
                                        {crate::i18n::tr("kanban.archive_action")}
                                    }
                                }
                            }
                            }
                        }

                for (card_index, card) in column
                    .cards
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| c.lifecycle == FlowLifecycleState::Active)
                {
                            div {
                                class: {
                                    let mut classes = String::from("event board-card");
                                    if !dragged_card_id_for_match.is_empty()
                                        && card.id == dragged_card_id_for_match
                                    {
                                        classes.push_str(" dragging-source");
                                    }
                                    classes
                                },
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
                                    let actor = account_did.clone();
                                    move |event| {
                                        event.prevent_default();
                                        // Stop propagation so the column's
                                        // ondrop above doesn't also fire
                                        // and double-insert at the tail.
                                        event.stop_propagation();
                                        let Some(dragged) = dragging_card() else {
                                            return;
                                        };
                                        let board_space_id = selected_board_space_id();
                                        if board_space_id.trim().is_empty() {
                                            board_status.set("select or create a Board Space before moving cards".to_owned());
                                            return;
                                        }
                                        dragging_card.set(None);
                                        let neighbours = ColumnNeighbours {
                                            prev_rank: prev_rank.clone(),
                                            next_rank: Some(this_rank.clone()),
                                        };
                                        let view_id_for_rebase = board_view_id();
                                        dispatch_flow_position_move(
                                            base.clone(),
                                            token,
                                            space.clone(),
                                            board_space_id,
                                            view_id_for_rebase,
                                            actor.clone(),
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
                                    let route_space_id = card_detail_route_space_id(&selected_space);
                                    move |_| {
                                        let draft = card_detail_draft_from_card(&c);
                                        card_edit_title.set(draft.title);
                                        card_edit_description.set(draft.description);
                                        card_edit_body.set(draft.body);
                                        card_edit_synthesis.set(draft.synthesis);
                                        card_edit_labels.set(draft.labels.join(", "));
                                        card_edit_assignee.set(draft.assignee);
                                        card_edit_due.set(draft.due);
                                        editing_card_detail.set(false);
                                        card_detail_actions_open.set(false);
                                        card_detail_description_expanded.set(false);
                                        card_detail_tab.set(CardDetailContentTab::Description);
                                        card_detail_overlay_press_started.set(false);
                                        card_detail_overlay_press_ended.set(false);
                                        selected_card.set(Some(c.clone()));
                                        let _ = navigator.push(kanban_card_task_route(
                                            &route_space_id,
                                            &selected_board_space_id(),
                                            &c.id,
                                        ));
                                    }
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
                                div { class: "board-card-footer",
                                    {
                                        let gate = capability_gate_for_flow(
                                            &capability_engine,
                                            &account_did,
                                            &selected_space,
                                            &card.id,
                                            "cx.flow.archive",
                                        );
                                        let title_text = if gate.enabled {
                                            "Archive this card (cx.flow.archive)".to_owned()
                                        } else {
                                            format!("Archive gated: {}", gate.reason)
                                        };
                                        let testid_state = if gate.enabled { "open" } else { "denied" };
                                        rsx! {
                                            button {
                                                class: "secondary",
                                                "data-testid": "card-archive-button",
                                                "data-flow-id": "{card.id}",
                                                "data-cap-gate": testid_state,
                                                disabled: !gate.enabled,
                                                title: title_text,
                                                onclick: {
                                                    let base = base_url.clone();
                                                    let space = selected_space.clone();
                                                    let actor = account_did.clone();
                                                    let flow_id = card.id.clone();
                                                    move |evt: dioxus::events::MouseEvent| {
                                                        evt.stop_propagation();
                                                        dispatch_flow_lifecycle(
                                                            base.clone(),
                                                            token,
                                                            space.clone(),
                                                            actor.clone(),
                                                            flow_id.clone(),
                                                            FlowLifecycleState::Archived,
                                                            columns,
                                                            board_status,
                                                        );
                                                    }
                                                },
                                                {crate::i18n::tr("kanban.archive_action")}
                                            }
                                        }
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
                                            // Card create submits a real
                                            // cx.flow.create envelope. The
                                            // initial Board/List placement
                                            // rides in the flow.position
                                            // component so the projection can
                                            // materialise it in this column.
                                            let base = base_url.clone();
                                            let col_id = column.id.clone();
                                            let space = selected_space.clone();
                                            let actor = account_did.clone();
                                            move |_| {
                                                let title = new_card_title().trim().to_owned();
                                                if title.is_empty() {
                                                    return;
                                                }
                                                let board_space_id = selected_board_space_id();
                                                if board_space_id.trim().is_empty() {
                                                    board_status.set("select or create a Board Space before adding cards".to_owned());
                                                    return;
                                                }
                                                let flow_id = format!("cx:flow:{}", uuid_v7());
                                                // Insert the new card at the end of the column.
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
                                                let card = local_created_card(
                                                    flow_id.clone(),
                                                    title.clone(),
                                                    rank.clone(),
                                                    LOCAL_PENDING_CARD_DESCRIPTION.to_owned(),
                                                );
                                                if let Some(col) = columns.write().iter_mut().find(|c| c.id == col_id) {
                                                    col.cards.push(card);
                                                }
                                                let value = json!({
                                                    "flow_id": flow_id,
                                                    "board_space_id": board_space_id,
                                                    "list_space_id": col_id,
                                                    "title": title,
                                                    "rank": rank,
                                                    "flow_kind": "card",
                                                });
                                                submit_kanban_move(
                                                    base.clone(),
                                                    token,
                                                    space.clone(),
                                                    actor.clone(),
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
                                        {crate::i18n::tr("kanban.save_card")}
                                    }
                                    button {
                                        class: "secondary",
                                        onclick: move |_| adding_card_to.set(None),
                                        {crate::i18n::tr("kanban.cancel_card")}
                                    }
                                }
                            }
                        } else {
                            div { class: "board-add-card-row",
                                button {
                                    class: "secondary",
                                    "data-testid": "add-card-button",
                                    onclick: {
                                        let col_id = column.id.clone();
                                        move |_| adding_card_to.set(Some(col_id.clone()))
                                    },
                                    {format!("+ {}", crate::i18n::tr("kanban.add_card"))}
                                }
                            }
                        }
                    }
                    }
                    }
                }
                }
            }

            // Archived lists panel — container Space lifecycle `archived` state.
            // Lists appear here after `cx.space.archive` is accepted and
            // are removed from the main board-grid above. Each row carries
            // a Restore button that submits `cx.space.restore` (SDK reducer
            // enforces `state == archived` server-side / next sync).
            {
                let archived: Vec<KanbanColumn> = columns()
                    .iter()
                    .filter(|c| c.state == SpaceContainerLifecycleState::Archived)
                    .cloned()
                    .collect();
                let archived_count = archived.len();
                rsx! {
                    details {
                        class: if archived_count == 0 { "event board-maintenance is-empty" } else { "event board-maintenance" },
                        "data-testid": "kanban-archived-lists",
                        summary {
                            span { {crate::i18n::tr("kanban.archived_lists_header")} }
                            span { "{archived_count} list(s)" }
                        }
                        if archived_count == 0 {
                            div { class: "muted", {crate::i18n::tr("kanban.archived_lists_empty")} }
                        } else {
                            for column in archived.iter() {
                                div { class: "event", "data-testid": "kanban-archived-list-row",
                                    div { class: "event-head",
                                        span { class: "space-title", "{column.title}" }
                                        span { "rank {column.rank} / {column.cards.len()} card(s)" }
                                        {
                                            let gate = capability_gate_for_space_container(
                                                &capability_engine,
                                                &account_did,
                                                &selected_space,
                                                &column.id,
                                                "cx.space.restore",
                                            );
                                            let title_text = if gate.enabled {
                                                "Restore this list (cx.space.restore)".to_owned()
                                            } else {
                                                format!("Restore gated: {}", gate.reason)
                                            };
                                            let testid_state = if gate.enabled { "open" } else { "denied" };
                                            rsx! {
                                                button {
                                                    class: "secondary",
                                                    "data-testid": "list-restore-button",
                                                    "data-space-container-id": "{column.id}",
                                                    "data-cap-gate": testid_state,
                                                    disabled: !gate.enabled,
                                                    title: title_text,
                                                    onclick: {
                                                        let base = base_url.clone();
                                                        let space = selected_space.clone();
                                                        let actor = account_did.clone();
                                                        let space_container_id = column.id.clone();
                                                        move |_| {
                                                            dispatch_space_container_lifecycle(
                                                                base.clone(),
                                                                token,
                                                                space.clone(),
                                                                actor.clone(),
                                                                space_container_id.clone(),
                                                                SpaceContainerLifecycleState::Active,
                                                                columns,
                                                                board_status,
                                                            );
                                                        }
                                                    },
                                                    {crate::i18n::tr("kanban.restore_action")}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
                }
            }

            // Archived cards drawer — Flow lifecycle `archived` state.
            // Cards appear here after `cx.flow.archive` is accepted and
            // are removed from the column above. Each row carries the
            // column title (where it came from) + a Restore button that
            // submits `cx.flow.restore` (SDK reducer enforces
            // `state == archived` per common-fields.md §5.1).
            {
                #[derive(Clone)]
                struct ArchivedCardRow {
                    card: KanbanCard,
                    column_title: String,
                }
                let archived_cards: Vec<ArchivedCardRow> = columns()
                    .iter()
                    .flat_map(|col| {
                        let col_title = col.title.clone();
                        col.cards
                            .iter()
                            .filter(|c| c.lifecycle == FlowLifecycleState::Archived)
                            .cloned()
                            .map(move |card| ArchivedCardRow {
                                card,
                                column_title: col_title.clone(),
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect();
                let archived_count = archived_cards.len();
                rsx! {
                    details {
                        class: if archived_count == 0 { "event board-maintenance is-empty" } else { "event board-maintenance" },
                        "data-testid": "kanban-archived-cards",
                        open: archived_count > 0,
                        summary {
                            span { {crate::i18n::tr("kanban.archived_cards_header")} }
                            span { "{archived_count} card(s)" }
                        }
                        if archived_count == 0 {
                            div { class: "muted", {crate::i18n::tr("kanban.archived_cards_empty")} }
                        } else {
                            for row in archived_cards.iter() {
                                div { class: "event", "data-testid": "kanban-archived-card-row",
                                    div { class: "event-head",
                                        span { class: "space-title", "{row.card.title}" }
                                        span { "from list: {row.column_title}" }
                                        {
                                            let gate = capability_gate_for_flow(
                                                &capability_engine,
                                                &account_did,
                                                &selected_space,
                                                &row.card.id,
                                                "cx.flow.restore",
                                            );
                                            let title_text = if gate.enabled {
                                                "Restore this card (cx.flow.restore)".to_owned()
                                            } else {
                                                format!("Restore gated: {}", gate.reason)
                                            };
                                            let testid_state = if gate.enabled { "open" } else { "denied" };
                                            rsx! {
                                                button {
                                                    class: "secondary",
                                                    "data-testid": "card-restore-button",
                                                    "data-flow-id": "{row.card.id}",
                                                    "data-cap-gate": testid_state,
                                                    disabled: !gate.enabled,
                                                    title: title_text,
                                                    onclick: {
                                                        let base = base_url.clone();
                                                        let space = selected_space.clone();
                                                        let actor = account_did.clone();
                                                        let flow_id = row.card.id.clone();
                                                        move |_| {
                                                            dispatch_flow_lifecycle(
                                                                base.clone(),
                                                                token,
                                                                space.clone(),
                                                                actor.clone(),
                                                                flow_id.clone(),
                                                                FlowLifecycleState::Active,
                                                                columns,
                                                                board_status,
                                                            );
                                                        }
                                                    },
                                                    {crate::i18n::tr("kanban.restore_action")}
                                                }
                                            }
                                        }
                                    }
                                    if !row.card.description.is_empty() {
                                        div { class: "muted", "{row.card.description}" }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if let Some(ref card) = selected_card() {
                {
                    let card_id_label = short_protocol_id(&card.id);
                    let card_link_path = flow_detail_deep_link_path(&selected_space, &card.id);
                    let board_route_after_close =
                        kanban_card_detail_board_route(&selected_space, &selected_board_space_id());
                    let route_is_card_detail = matches!(
                        route,
                        Route::KanbanTask { .. } | Route::KanbanBoardTask { .. }
                    );
                    let sidebar_is_visible = card_detail_sidebar_visible();
                    let sidebar_toggle_label = if sidebar_is_visible {
                        "Hide details"
                    } else {
                        "Show details"
                    };
                    let sidebar_toggle_icon = if sidebar_is_visible {
                        "panel-right-close"
                    } else {
                        "panel-right-open"
                    };
                    let detail_layout_class = if sidebar_is_visible {
                        "card-detail-layout"
                    } else {
                        "card-detail-layout no-sidebar"
                    };
                    let is_docked = card_detail_docked();
                    let dock_width = card_detail_dock_width();
                    let dock_toggle_label = if is_docked {
                        "Expand to dialog"
                    } else {
                        "Dock to side"
                    };
                    let dock_toggle_icon = if is_docked { "maximize" } else { "minimize" };
                    let overlay_class = if is_docked {
                        "card-detail-overlay is-docked"
                    } else {
                        "card-detail-overlay"
                    };
                    let popup_class = if is_docked {
                        "card-detail-popup is-docked"
                    } else {
                        "card-detail-popup"
                    };
                    let popup_style = if is_docked {
                        format!("width: {dock_width}px;")
                    } else {
                        String::new()
                    };
                    let active_detail_tab = card_detail_tab();
                    let description_tab_class = if active_detail_tab == CardDetailContentTab::Description {
                        "card-detail-tab active"
                    } else {
                        "card-detail-tab"
                    };
                    let synthesis_tab_class = if active_detail_tab == CardDetailContentTab::Synthesis {
                        "card-detail-tab active"
                    } else {
                        "card-detail-tab"
                    };
                    let discussion_tab_class = if active_detail_tab == CardDetailContentTab::Discussion {
                        "card-detail-tab active"
                    } else {
                        "card-detail-tab"
                    };
                    let description_is_collapsible = card_description_should_collapse(&card.body);
                    let description_is_expanded = card_detail_description_expanded();
                    let description_class = if description_is_collapsible && !description_is_expanded {
                        "card-detail-description is-collapsed"
                    } else {
                        "card-detail-description"
                    };
                    let description_toggle_label = if description_is_expanded {
                        "Less"
                    } else {
                        "More"
                    };
                    let action_menu_class = if editing_card_detail() {
                        "card-detail-action-menu is-editing"
                    } else {
                        "card-detail-action-menu"
                    };
                    let summary_text = card_summary_text(&card.description);
                    let overlay_navigator = navigator;
                    let overlay_board_route = board_route_after_close.clone();
                    let close_navigator = navigator;
                    let close_board_route = board_route_after_close.clone();
                    rsx! {
                        if card_detail_resizing() {
                            div {
                                class: "card-detail-resize-capture",
                                "data-testid": "card-detail-resize-capture",
                                onmousemove: move |event: dioxus::events::MouseEvent| {
                                    let current_x = event.client_coordinates().x;
                                    let delta = card_detail_resize_start_x() - current_x;
                                    let next = (card_detail_resize_start_width() + delta)
                                        .clamp(CARD_DETAIL_DOCK_WIDTH_MIN, CARD_DETAIL_DOCK_WIDTH_MAX);
                                    card_detail_dock_width.set(next);
                                },
                                onmouseup: move |event: dioxus::events::MouseEvent| {
                                    event.stop_propagation();
                                    card_detail_resizing.set(false);
                                    persist_card_detail_dock_width(card_detail_dock_width());
                                },
                                onmouseleave: move |_| {
                                    card_detail_resizing.set(false);
                                    persist_card_detail_dock_width(card_detail_dock_width());
                                },
                            }
                        }
                        div {
                            class: "{overlay_class}",
                            "data-testid": "card-detail-overlay",
                            role: "presentation",
                            onmousedown: move |_| {
                                card_detail_overlay_press_started.set(true);
                                card_detail_overlay_press_ended.set(false);
                            },
                            onmouseup: move |_| {
                                card_detail_overlay_press_ended.set(true);
                            },
                            onclick: move |_| {
                                if card_detail_overlay_press_started()
                                    && card_detail_overlay_press_ended()
                                {
                                    selected_card.set(None);
                                    editing_card_detail.set(false);
                                    card_detail_actions_open.set(false);
                                    if route_is_card_detail {
                                        let _ = overlay_navigator.push(overlay_board_route.clone());
                                    }
                                }
                                card_detail_overlay_press_started.set(false);
                                card_detail_overlay_press_ended.set(false);
                            },
                            div {
                                class: "{popup_class}",
                                style: "{popup_style}",
                                "data-testid": "card-detail-modal",
                                role: "dialog",
                                "aria-modal": "true",
                                onmousedown: move |event: dioxus::events::MouseEvent| {
                                    card_detail_overlay_press_started.set(false);
                                    card_detail_overlay_press_ended.set(false);
                                    event.stop_propagation();
                                },
                                onmouseup: move |event: dioxus::events::MouseEvent| {
                                    card_detail_overlay_press_ended.set(false);
                                    event.stop_propagation();
                                },
                                onclick: move |event: dioxus::events::MouseEvent| event.stop_propagation(),
                                if is_docked {
                                    div {
                                        class: "card-detail-resize-handle",
                                        "data-testid": "card-detail-resize-handle",
                                        "aria-hidden": "true",
                                        onmousedown: move |event: dioxus::events::MouseEvent| {
                                            event.stop_propagation();
                                            card_detail_resize_start_x.set(event.client_coordinates().x);
                                            card_detail_resize_start_width.set(card_detail_dock_width());
                                            card_detail_resizing.set(true);
                                        },
                                    }
                                }
                                div { class: "card-detail-header",
                                    div { class: "card-detail-title-block",
                                        div { class: "card-detail-title-row",
                                            h2 { "{card.title}" }
                                            div { class: "card-detail-title-meta",
                                                span { class: card.state.class_name(), "{card.state.label()}" }
                                                for label in &card.labels {
                                                    span { class: "badge", "{label}" }
                                                }
                                            }
                                        }
                                    }
                                    div { class: "card-detail-header-actions",
                                        button {
                                            class: "secondary card-detail-header-button",
                                            "data-testid": "card-detail-share-link-button",
                                            "aria-label": "Copy flow link",
                                            title: "Copy flow link",
                                            onclick: {
                                                let link_path = card_link_path.clone();
                                                move |_| {
                                                    share_kanban_flow_link(&link_path);
                                                    board_status.set("Flow link copied".to_owned());
                                                    card_detail_actions_open.set(false);
                                                }
                                            },
                                            UiIcon { name: "share" }
                                        }
                                        if !editing_card_detail() {
                                            button {
                                                class: "secondary card-detail-header-button",
                                                "data-testid": "card-detail-sidebar-toggle",
                                                "aria-label": "{sidebar_toggle_label}",
                                                "aria-pressed": "{sidebar_is_visible}",
                                                title: "{sidebar_toggle_label}",
                                                onclick: move |_| {
                                                    card_detail_sidebar_visible.set(!card_detail_sidebar_visible());
                                                    card_detail_actions_open.set(false);
                                                },
                                                UiIcon { name: sidebar_toggle_icon }
                                            }
                                        }
                                        button {
                                            class: "secondary card-detail-header-button",
                                            "data-testid": "card-detail-dock-toggle",
                                            "aria-label": "{dock_toggle_label}",
                                            "aria-pressed": "{is_docked}",
                                            title: "{dock_toggle_label}",
                                            onclick: move |_| {
                                                let next = !card_detail_docked();
                                                card_detail_docked.set(next);
                                                persist_card_detail_docked(next);
                                                card_detail_actions_open.set(false);
                                            },
                                            UiIcon { name: dock_toggle_icon }
                                        }
                                        div { class: "card-detail-action-menu-wrap",
                                            button {
                                                class: "secondary card-detail-header-button",
                                                "data-testid": "card-detail-actions-button",
                                                "aria-label": "Actions",
                                                "aria-expanded": "{card_detail_actions_open()}",
                                                title: "Actions",
                                                onclick: move |_| card_detail_actions_open.set(!card_detail_actions_open()),
                                                UiIcon { name: "more-horizontal" }
                                            }
                                            if card_detail_actions_open() {
                                                div { class: "{action_menu_class}", "data-testid": "card-detail-actions-menu",
                                                    if editing_card_detail() {
                                                        div { class: "card-detail-action-menu-field",
                                                            label { "Labels" }
                                                            input {
                                                                class: "input",
                                                                "data-testid": "card-detail-labels-input",
                                                                value: "{card_edit_labels}",
                                                                placeholder: "release, ops",
                                                                oninput: move |evt| card_edit_labels.set(evt.value()),
                                                            }
                                                        }
                                                        div { class: "card-detail-action-menu-field",
                                                            label { "Assignee" }
                                                            input {
                                                                class: "input",
                                                                "data-testid": "card-detail-assignee-input",
                                                                value: "{card_edit_assignee}",
                                                                placeholder: "alice:example.com or did:web:...",
                                                                oninput: move |evt| card_edit_assignee.set(evt.value()),
                                                            }
                                                        }
                                                        div { class: "card-detail-action-menu-field",
                                                            label { "Due date" }
                                                            input {
                                                                class: "input",
                                                                "data-testid": "card-detail-due-input",
                                                                value: "{card_edit_due}",
                                                                placeholder: "2026-05-20",
                                                                oninput: move |evt| card_edit_due.set(evt.value()),
                                                            }
                                                        }
                                                    } else {
                                                        button {
                                                            class: "card-detail-action-menu-item",
                                                            "data-testid": "card-detail-menu-edit-button",
                                                            onclick: {
                                                                let current = card.clone();
                                                                move |_| {
                                                                    let draft = card_detail_draft_from_card(&current);
                                                                    card_edit_title.set(draft.title);
                                                                    card_edit_description.set(draft.description);
                                                                    card_edit_labels.set(draft.labels.join(", "));
                                                                    card_edit_assignee.set(draft.assignee);
                                                                    card_edit_due.set(draft.due);
                                                                    editing_card_detail.set(true);
                                                                    card_detail_actions_open.set(false);
                                                                }
                                                            },
                                                            UiIcon { name: "settings" }
                                                            span { {crate::i18n::tr("common.edit")} }
                                                        }
                                                        {
                                                            let target = if card.lifecycle == FlowLifecycleState::Archived {
                                                                FlowLifecycleState::Active
                                                            } else {
                                                                FlowLifecycleState::Archived
                                                            };
                                                            let action = if target == FlowLifecycleState::Archived {
                                                                "cx.flow.archive"
                                                            } else {
                                                                "cx.flow.restore"
                                                            };
                                                            let gate = capability_gate_for_flow(
                                                                &capability_engine,
                                                                &account_did,
                                                                &selected_space,
                                                                &card.id,
                                                                action,
                                                            );
                                                            let label = if target == FlowLifecycleState::Archived {
                                                                crate::i18n::tr("kanban.archive_action")
                                                            } else {
                                                                crate::i18n::tr("kanban.restore_action")
                                                            };
                                                            let testid = if target == FlowLifecycleState::Archived {
                                                                "card-detail-archive-button"
                                                            } else {
                                                                "card-detail-restore-button"
                                                            };
                                                            let title_text = if gate.enabled {
                                                                format!("{label} this card ({action})")
                                                            } else {
                                                                format!("{label} gated: {}", gate.reason)
                                                            };
                                                            let testid_state = if gate.enabled { "open" } else { "denied" };
                                                            let action_navigator = navigator;
                                                            let action_board_route = board_route_after_close.clone();
                                                            rsx! {
                                                                button {
                                                                    class: "card-detail-action-menu-item",
                                                                    "data-testid": testid,
                                                                    "data-flow-id": "{card.id}",
                                                                    "data-cap-gate": testid_state,
                                                                    disabled: !gate.enabled,
                                                                    title: title_text,
                                                                    onclick: {
                                                                        let base = base_url.clone();
                                                                        let space = selected_space.clone();
                                                                        let actor = account_did.clone();
                                                                        let flow_id = card.id.clone();
                                                                        move |_| {
                                                                            dispatch_flow_lifecycle(
                                                                                base.clone(),
                                                                                token,
                                                                                space.clone(),
                                                                                actor.clone(),
                                                                                flow_id.clone(),
                                                                                target,
                                                                                columns,
                                                                                board_status,
                                                                            );
                                                                            selected_card.set(None);
                                                                            editing_card_detail.set(false);
                                                                            card_detail_actions_open.set(false);
                                                                            if route_is_card_detail {
                                                                                let _ = action_navigator.push(action_board_route.clone());
                                                                            }
                                                                        }
                                                                    },
                                                                    UiIcon { name: if target == FlowLifecycleState::Archived { "archive" } else { "refresh" } }
                                                                    span { "{label}" }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        button {
                                            class: "secondary card-detail-header-button card-detail-close",
                                            "data-testid": "card-detail-close-button",
                                            "aria-label": "Close card detail",
                                            title: "Close",
                                            onclick: move |_| {
                                                selected_card.set(None);
                                                editing_card_detail.set(false);
                                                card_detail_actions_open.set(false);
                                                if route_is_card_detail {
                                                    let _ = close_navigator.push(close_board_route.clone());
                                                }
                                            },
                                            UiIcon { name: "x" }
                                        }
                                    }
                                }

                                if editing_card_detail() {
                                    div { class: "workflow-form card-detail-edit-form", "data-testid": "card-detail-edit-form",
                                        if card_edit_scope() == CardEditScope::Summary {
                                            div { class: "field",
                                                label { "Title" }
                                                input {
                                                    class: "input",
                                                    "data-testid": "card-detail-title-input",
                                                    value: "{card_edit_title}",
                                                    maxlength: "512",
                                                    oninput: move |evt| card_edit_title.set(evt.value()),
                                                }
                                            }
                                            div { class: "field",
                                                label { "Summary" }
                                                CardMarkdownEditor {
                                                    value: card_edit_description(),
                                                    base_url: base_url.clone(),
                                                    token: token(),
                                                    on_change: move |value| card_edit_description.set(value),
                                                    slot: "summary".to_owned(),
                                                }
                                            }
                                        }
                                        if card_edit_scope() == CardEditScope::Description {
                                            div { class: "field",
                                                label { "Description" }
                                                CardMarkdownEditor {
                                                    value: card_edit_body(),
                                                    base_url: base_url.clone(),
                                                    token: token(),
                                                    on_change: move |value| card_edit_body.set(value),
                                                    slot: "description".to_owned(),
                                                }
                                            }
                                        }
                                        if card_edit_scope() == CardEditScope::Synthesis {
                                            div { class: "field",
                                                label { "Synthesis" }
                                                CardMarkdownEditor {
                                                    value: card_edit_synthesis(),
                                                    base_url: base_url.clone(),
                                                    token: token(),
                                                    on_change: move |value| card_edit_synthesis.set(value),
                                                    slot: "synthesis".to_owned(),
                                                }
                                            }
                                        }
                                        div { class: "card-detail-form-actions",
                                            button {
                                                class: "primary",
                                                "data-testid": "card-detail-save-button",
                                                onclick: {
                                                    let base = base_url.clone();
                                                    let space = selected_space.clone();
                                                    let actor = account_did.clone();
                                                    let current = card.clone();
                                                    move |_| {
                                                        let draft = CardDetailDraft {
                                                            title: card_edit_title().trim().to_owned(),
                                                            description: card_edit_description().trim().to_owned(),
                                                            body: card_edit_body().trim().to_owned(),
                                                            synthesis: card_edit_synthesis().trim().to_owned(),
                                                            labels: parse_card_labels(&card_edit_labels()),
                                                            assignee: card_edit_assignee().trim().to_owned(),
                                                            due: card_edit_due().trim().to_owned(),
                                                        };
                                                        if dispatch_card_detail_update(
                                                            base.clone(),
                                                            token,
                                                            space.clone(),
                                                            actor.clone(),
                                                            current.clone(),
                                                            draft,
                                                            columns,
                                                            selected_card,
                                                            state_store,
                                                            board_status,
                                                        ) {
                                                            editing_card_detail.set(false);
                                                            card_detail_actions_open.set(false);
                                                        }
                                                    }
                                                },
                                                {crate::i18n::tr("common.save")}
                                            }
                                            button {
                                                class: "secondary",
                                                "data-testid": "card-detail-cancel-edit-button",
                                                onclick: {
                                                    let current = card.clone();
                                                    move |_| {
                                                        let draft = card_detail_draft_from_card(&current);
                                                        card_edit_title.set(draft.title);
                                                        card_edit_description.set(draft.description);
                                                        card_edit_body.set(draft.body);
                                                        card_edit_synthesis.set(draft.synthesis);
                                                        card_edit_labels.set(draft.labels.join(", "));
                                                        card_edit_assignee.set(draft.assignee);
                                                        card_edit_due.set(draft.due);
                                                        editing_card_detail.set(false);
                                                        card_detail_actions_open.set(false);
                                                    }
                                                },
                                                {crate::i18n::tr("common.cancel")}
                                            }
                                        }
                                    }
                                } else {
                                    div { class: "{detail_layout_class}",
                                        main { class: "card-detail-main",
                                            section { class: "card-detail-section",
                                                div { class: "card-detail-section-head",
                                                    div { class: "card-detail-section-title",
                                                        UiIcon { name: "file" }
                                                        span { "Summary" }
                                                    }
                                                    button {
                                                        class: "secondary card-detail-mini-action",
                                                        "data-testid": "card-detail-edit-button",
                                                        onclick: {
                                                            let current = card.clone();
                                                            move |_| {
                                                                let draft = card_detail_draft_from_card(&current);
                                                                card_edit_title.set(draft.title);
                                                                card_edit_description.set(draft.description);
                                                                card_edit_body.set(draft.body);
                                                                card_edit_synthesis.set(draft.synthesis);
                                                                card_edit_labels.set(draft.labels.join(", "));
                                                                card_edit_assignee.set(draft.assignee);
                                                                card_edit_due.set(draft.due);
                                                                card_edit_scope.set(CardEditScope::Summary);
                                                                editing_card_detail.set(true);
                                                            }
                                                        },
                                                        UiIcon { name: "settings" }
                                                        span { {crate::i18n::tr("common.edit")} }
                                                    }
                                                }
                                                if summary_text.is_empty() {
                                                    div { class: "card-detail-empty", "No summary" }
                                                } else {
                                                    div {
                                                        class: "card-detail-summary",
                                                        "data-testid": "card-summary",
                                                        "{summary_text}"
                                                    }
                                                }
                                            }

                                            section { class: "card-detail-section card-detail-tabs-section",
                                                div {
                                                    class: "card-detail-tabs",
                                                    "data-testid": "card-detail-tabs",
                                                    role: "tablist",
                                                    "aria-label": "Flow tracks",
                                                    button {
                                                        r#type: "button",
                                                        class: "{description_tab_class}",
                                                        "data-testid": "card-detail-tab-description",
                                                        role: "tab",
                                                        "aria-selected": "{active_detail_tab == CardDetailContentTab::Description}",
                                                        onclick: move |_| card_detail_tab.set(CardDetailContentTab::Description),
                                                        "Description"
                                                    }
                                                    button {
                                                        r#type: "button",
                                                        class: "{synthesis_tab_class}",
                                                        "data-testid": "card-detail-tab-synthesis",
                                                        role: "tab",
                                                        "aria-selected": "{active_detail_tab == CardDetailContentTab::Synthesis}",
                                                        onclick: move |_| card_detail_tab.set(CardDetailContentTab::Synthesis),
                                                        "Synthesis"
                                                    }
                                                    button {
                                                        r#type: "button",
                                                        class: "{discussion_tab_class}",
                                                        "data-testid": "card-detail-tab-discussion",
                                                        role: "tab",
                                                        "aria-selected": "{active_detail_tab == CardDetailContentTab::Discussion}",
                                                        onclick: move |_| card_detail_tab.set(CardDetailContentTab::Discussion),
                                                        "Discussion"
                                                    }
                                                }
                                                if active_detail_tab == CardDetailContentTab::Description {
                                                    div {
                                                        class: "card-detail-description-panel",
                                                        "data-testid": "card-description-panel",
                                                        role: "tabpanel",
                                                        if card.body.trim().is_empty() {
                                                            div { class: "card-detail-empty",
                                                                div { "No description" }
                                                                button {
                                                                    class: "secondary card-detail-mini-action",
                                                                    "data-testid": "card-detail-add-description-button",
                                                                    onclick: {
                                                                        let current = card.clone();
                                                                        move |_| {
                                                                            let draft = card_detail_draft_from_card(&current);
                                                                            card_edit_title.set(draft.title);
                                                                            card_edit_description.set(draft.description);
                                                                            card_edit_body.set(draft.body);
                                                                            card_edit_synthesis.set(draft.synthesis);
                                                                            card_edit_labels.set(draft.labels.join(", "));
                                                                            card_edit_assignee.set(draft.assignee);
                                                                            card_edit_due.set(draft.due);
                                                                            card_edit_scope.set(CardEditScope::Description);
                                                                            editing_card_detail.set(true);
                                                                        }
                                                                    },
                                                                    UiIcon { name: "plus" }
                                                                    span { "Add description" }
                                                                }
                                                            }
                                                        } else {
                                                            div { class: "card-detail-tab-actions",
                                                                button {
                                                                    class: "secondary card-detail-mini-action",
                                                                    "data-testid": "card-detail-edit-description-button",
                                                                    onclick: {
                                                                        let current = card.clone();
                                                                        move |_| {
                                                                            let draft = card_detail_draft_from_card(&current);
                                                                            card_edit_title.set(draft.title);
                                                                            card_edit_description.set(draft.description);
                                                                            card_edit_body.set(draft.body);
                                                                            card_edit_synthesis.set(draft.synthesis);
                                                                            card_edit_labels.set(draft.labels.join(", "));
                                                                            card_edit_assignee.set(draft.assignee);
                                                                            card_edit_due.set(draft.due);
                                                                            card_edit_scope.set(CardEditScope::Description);
                                                                            editing_card_detail.set(true);
                                                                        }
                                                                    },
                                                                    UiIcon { name: "settings" }
                                                                    span { {crate::i18n::tr("common.edit")} }
                                                                }
                                                            }
                                                            div { class: "{description_class}",
                                                                {crate::content::render_blocks(
                                                                    &crate::content::parse_message_body(&card.body),
                                                                )}
                                                            }
                                                            if description_is_collapsible {
                                                                button {
                                                                    class: "card-detail-description-toggle",
                                                                    "data-testid": "card-detail-description-toggle",
                                                                    onclick: move |_| {
                                                                        card_detail_description_expanded.set(
                                                                            !card_detail_description_expanded(),
                                                                        );
                                                                    },
                                                                    "{description_toggle_label}"
                                                                }
                                                            }
                                                        }
                                                    }
                                                } else if active_detail_tab == CardDetailContentTab::Synthesis {
                                                    div {
                                                        class: "card-detail-description-panel",
                                                        "data-testid": "card-synthesis-panel",
                                                        role: "tabpanel",
                                                        if card.synthesis.trim().is_empty() {
                                                            div { class: "card-detail-empty",
                                                                div { "No synthesis yet." }
                                                                button {
                                                                    class: "secondary card-detail-mini-action",
                                                                    "data-testid": "card-detail-add-synthesis-button",
                                                                    onclick: {
                                                                        let current = card.clone();
                                                                        move |_| {
                                                                            let draft = card_detail_draft_from_card(&current);
                                                                            card_edit_title.set(draft.title);
                                                                            card_edit_description.set(draft.description);
                                                                            card_edit_body.set(draft.body);
                                                                            card_edit_synthesis.set(draft.synthesis);
                                                                            card_edit_labels.set(draft.labels.join(", "));
                                                                            card_edit_assignee.set(draft.assignee);
                                                                            card_edit_due.set(draft.due);
                                                                            card_edit_scope.set(CardEditScope::Synthesis);
                                                                            editing_card_detail.set(true);
                                                                        }
                                                                    },
                                                                    UiIcon { name: "plus" }
                                                                    span { "Add synthesis" }
                                                                }
                                                            }
                                                        } else {
                                                            div { class: "card-detail-tab-actions",
                                                                button {
                                                                    class: "secondary card-detail-mini-action",
                                                                    "data-testid": "card-detail-edit-synthesis-button",
                                                                    onclick: {
                                                                        let current = card.clone();
                                                                        move |_| {
                                                                            let draft = card_detail_draft_from_card(&current);
                                                                            card_edit_title.set(draft.title);
                                                                            card_edit_description.set(draft.description);
                                                                            card_edit_body.set(draft.body);
                                                                            card_edit_synthesis.set(draft.synthesis);
                                                                            card_edit_labels.set(draft.labels.join(", "));
                                                                            card_edit_assignee.set(draft.assignee);
                                                                            card_edit_due.set(draft.due);
                                                                            card_edit_scope.set(CardEditScope::Synthesis);
                                                                            editing_card_detail.set(true);
                                                                        }
                                                                    },
                                                                    UiIcon { name: "settings" }
                                                                    span { {crate::i18n::tr("common.edit")} }
                                                                }
                                                            }
                                                            div { class: "card-detail-description",
                                                                {crate::content::render_blocks(
                                                                    &crate::content::parse_message_body(&card.synthesis),
                                                                )}
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    div {
                                                        class: "card-detail-discussion-panel",
                                                        "data-testid": "card-discussion-panel",
                                                        role: "tabpanel",
                                                        crate::views::chat::ChatPanel {
                                                            base_url: base_url.clone(),
                                                            plaintext_service_did: plaintext_service_did.clone(),
                                                            account_did: account_did.clone(),
                                                            token,
                                                            selected_space: selected_space.clone(),
                                                            selected_space_scope: selected_space_scope.clone(),
                                                            sync_cursor,
                                                            frontier_state,
                                                            state_store,
                                                            initial_flow_id: card.primary_flow_id.clone(),
                                                            embedded: true,
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if sidebar_is_visible {
                                        aside { class: "card-detail-sidebar",
                                            {
                                                let store = state_store.read().load();
                                                let realm_member_rows = realm_member_roster(
                                                    store.space_projections.get(&selected_space),
                                                );
                                                let realm_member_count = realm_member_rows.len();
                                                let participant_set: BTreeSet<String> = flow_participant_dids(
                                                    &store.raw_operations,
                                                    &card.primary_flow_id,
                                                )
                                                .into_iter()
                                                .collect();
                                                let active_sidebar_tab = card_detail_sidebar_tab();
                                                let details_tab_class = if active_sidebar_tab == CardDetailSidebarTab::Details {
                                                    "card-detail-tab active"
                                                } else {
                                                    "card-detail-tab"
                                                };
                                                let members_tab_class = if active_sidebar_tab == CardDetailSidebarTab::Members {
                                                    "card-detail-tab active"
                                                } else {
                                                    "card-detail-tab"
                                                };
                                                rsx! {
                                                    div {
                                                        class: "card-detail-tabs card-detail-sidebar-tabs",
                                                        "data-testid": "card-detail-sidebar-tabs",
                                                        role: "tablist",
                                                        "aria-label": "Sidebar views",
                                                        button {
                                                            r#type: "button",
                                                            class: "{details_tab_class}",
                                                            "data-testid": "card-detail-sidebar-tab-details",
                                                            role: "tab",
                                                            "aria-selected": "{active_sidebar_tab == CardDetailSidebarTab::Details}",
                                                            onclick: move |_| card_detail_sidebar_tab.set(CardDetailSidebarTab::Details),
                                                            "Details"
                                                        }
                                                        button {
                                                            r#type: "button",
                                                            class: "{members_tab_class}",
                                                            "data-testid": "card-detail-sidebar-tab-members",
                                                            role: "tab",
                                                            "aria-selected": "{active_sidebar_tab == CardDetailSidebarTab::Members}",
                                                            onclick: move |_| card_detail_sidebar_tab.set(CardDetailSidebarTab::Members),
                                                            "Members ({realm_member_count})"
                                                        }
                                                    }
                                                    if active_sidebar_tab == CardDetailSidebarTab::Details {
                                                        div { class: "card-detail-side-fields", "data-testid": "card-fields",
                                                            dl { class: "card-detail-field-list",
                                                                div {
                                                                    dt { "Flow ID" }
                                                                    dd { class: "card-detail-field-code", title: "{card.id}", "{card_id_label}" }
                                                                }
                                                                div {
                                                                    dt { "Assignee" }
                                                                    dd { "{card.assignee}" }
                                                                }
                                                                div {
                                                                    dt { "Due" }
                                                                    dd { "{card.due}" }
                                                                }
                                                                div {
                                                                    dt { "Visibility" }
                                                                    dd { "{card.external_visibility}" }
                                                                }
                                                            }
                                                        }
                                                        div { class: "card-detail-side-section card-detail-activity", "data-testid": "card-audit-excerpt",
                                                            h3 { "Activity" }
                                                            div { class: "card-detail-activity-item",
                                                                span { class: "card-detail-activity-dot" }
                                                                div { "{card.activity_hint}" }
                                                            }
                                                            div { class: "card-detail-activity-item muted",
                                                                span { class: "card-detail-activity-dot" }
                                                                div { "{card.audit_hint}" }
                                                            }
                                                        }
                                                    }
                                                    if active_sidebar_tab == CardDetailSidebarTab::Members {
                                                        if realm_member_rows.is_empty() {
                                                            div { class: "card-detail-empty", "data-testid": "card-detail-realm-members",
                                                                div { "No members yet for this Realm." }
                                                            }
                                                        } else {
                                                            ul {
                                                                class: "card-detail-actor-list",
                                                                "data-testid": "card-detail-realm-members",
                                                                for row in realm_member_rows.iter() {
                                                                    {
                                                                        let did = row.actor_id.clone();
                                                                        // R3.1 MID-6 — pull the resolved
                                                                        // MemberIdentity from the
                                                                        // `cx.member.identity.update` event
                                                                        // store. `None` means either no
                                                                        // identity event has been observed
                                                                        // yet, or every effective event is
                                                                        // still `decryption_pending` (MLS
                                                                        // epoch missing — MID-4 stub).
                                                                        // member_display_label falls back to
                                                                        // the compact DID in both cases.
                                                                        // TODO(R4): swap the decryption-pending
                                                                        // branch for an explicit muted
                                                                        // placeholder string instead of the
                                                                        // bare DID.
                                                                        let identity = state_store
                                                                            .read()
                                                                            .resolved_member_identity(&selected_space, &did);
                                                                        let label = member_display_label(row, identity.as_ref());
                                                                        let in_flow = participant_set.contains(&did);
                                                                        let row_class = if in_flow {
                                                                            "card-detail-actor-row participant"
                                                                        } else {
                                                                            "card-detail-actor-row"
                                                                        };
                                                                        let dot_class = if in_flow {
                                                                            "card-detail-actor-dot participant"
                                                                        } else {
                                                                            "card-detail-actor-dot"
                                                                        };
                                                                        let dot_title = if in_flow {
                                                                            "Participated in this Flow"
                                                                        } else {
                                                                            "Realm member"
                                                                        };
                                                                        rsx! {
                                                                            li {
                                                                                key: "{did}",
                                                                                class: "{row_class}",
                                                                                "data-flow-participant": "{in_flow}",
                                                                                span { class: "{dot_class}", title: "{dot_title}", "aria-label": "{dot_title}" }
                                                                                span { class: "card-detail-actor-did", title: "{did}", "{label}" }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn route_card_flow_id(route: &Route) -> Option<String> {
    match route {
        Route::KanbanTask { task_id, .. } | Route::KanbanBoardTask { task_id, .. } => {
            let task_id = task_id.trim();
            if task_id.is_empty() {
                None
            } else {
                Some(task_id.to_owned())
            }
        }
        _ => None,
    }
}

/// Extract the board Space-container id carried by the board-aware
/// kanban routes. `None` for the board-less routes (plain `/kanban`,
/// `/kanban/<realm>`, and the legacy `/kanban/<realm>/task/<flow>`
/// share-link form) where the board must be resolved from projection.
fn route_board_id(route: &Route) -> Option<String> {
    match route {
        Route::KanbanBoard { board_id, .. } | Route::KanbanBoardTask { board_id, .. } => {
            let board_id = board_id.trim();
            if board_id.is_empty() {
                None
            } else {
                Some(board_id.to_owned())
            }
        }
        _ => None,
    }
}

/// Build the URL for selecting a board (no card open). Falls back to the
/// board-less `/kanban/<realm>` route when no board is selected yet.
fn kanban_board_route(space_id: &str, board_id: &str) -> Route {
    let space_id = card_detail_route_space_id(space_id);
    let board_id = board_id.trim();
    if board_id.is_empty() {
        Route::KanbanSpace { space_id }
    } else {
        Route::KanbanBoard {
            space_id,
            board_id: board_id.to_owned(),
        }
    }
}

/// Build the URL for an open card. Prefers the board-carrying form so a
/// refresh restores the board; falls back to the board-less task route
/// when the board id is unknown.
fn kanban_card_task_route(space_id: &str, board_id: &str, task_id: &str) -> Route {
    let space_id = card_detail_route_space_id(space_id);
    let board_id = board_id.trim();
    let task_id = task_id.trim().to_owned();
    if board_id.is_empty() {
        Route::KanbanTask { space_id, task_id }
    } else {
        Route::KanbanBoardTask {
            space_id,
            board_id: board_id.to_owned(),
            task_id,
        }
    }
}

fn card_matches_flow_id(card: &KanbanCard, flow_id: &str) -> bool {
    let flow_id = flow_id.trim();
    !flow_id.is_empty() && (card.id == flow_id || card.primary_flow_id == flow_id)
}

fn find_card_by_flow_id(columns: &[KanbanColumn], flow_id: &str) -> Option<KanbanCard> {
    columns
        .iter()
        .flat_map(|column| column.cards.iter())
        .find(|card| card_matches_flow_id(card, flow_id))
        .cloned()
}

/// Per-member entry harvested from a cached space projection.
///
/// R3.2 (contrix-spec @ b56cab1) — roster entries MUST NOT carry raw
/// handle / display fields. Identity resolution happens by following
/// `identity_event_ids[]` (or inline `identity_events[]`) and applying
/// the SDK's `effective_identity_events` helper. Handle strings only ever
/// appear inside signed `cx.schema.handle_claim.v1` evidence.
///
/// `actor_id` is the actor DID. `membership` is `join` / `invite` /
/// `knock`. `identity_event_ids` are the effective
/// `cx.member.identity.update` event ids (after replacement edges).
/// `member_display_state_digest` is the roster display cache key (R3.2
/// rename of the prior `identity_state_digest`; now folds the visible
/// handle-claim digest set). `subject_id` is the disclosed principal DID
/// — present only when the server disclosed it (gates the handle-claim
/// evidence fields per the roster v2 dependentRequired rule).
#[derive(Clone, Debug, PartialEq)]
pub(super) struct RealmMemberRow {
    /// Actor DID. Carried as both `actor_id` and (legacy) `did`.
    pub actor_id: String,
    pub membership: Option<String>,
    pub identity_event_ids: Vec<String>,
    pub member_display_state_digest: Option<String>,
    /// R3.2 roster v2 — disclosed principal/holder DID. `None` when the
    /// server did not disclose it (then the handle-claim fields are also
    /// absent). Drives §3.2.1 primary-handle selection + the
    /// "Why am I seeing this handle?" panel.
    pub subject_id: Option<String>,
}

impl RealmMemberRow {
    /// Legacy alias retained for one release. New code SHOULD read
    /// [`actor_id`] directly.
    #[allow(dead_code)]
    pub fn did(&self) -> &str {
        &self.actor_id
    }
}

/// Pick the best UI label for a roster row.
///
/// R3.1: prefer a resolved [`MemberIdentity`] display (via the SDK's
/// effective-set helper); otherwise fall back to the compact actor-DID
/// form so long `did:webvh:...` strings don't overflow.
///
/// `identity` is the current effective [`MemberIdentity`] for this row
/// (when one has been decrypted + verified). [`None`] means the row is
/// `decryption_pending` or no identity event has been observed yet — in
/// either case we render the compact DID instead of a raw `did:...`.
fn member_display_label(
    row: &RealmMemberRow,
    identity: Option<&contrix_sdk::MemberIdentity>,
) -> String {
    if let Some(identity) = identity {
        // R3.2: `MemberIdentity` no longer carries handle fields. The
        // verified handle (if any) comes from running §3.2.1 over the
        // roster handle-claim set; that resolution happens in the mention
        // / member-detail render path (see `render_member_handle`). The
        // roster row label falls back to the disclosed display name.
        let name = identity.display_profile.display_name.trim();
        if !name.is_empty() {
            return name.to_owned();
        }
    }
    short_protocol_id(&row.actor_id)
}

/// Collect the sorted roster of realm members from a cached space
/// projection. R3.2 roster v2 wire shape per
/// `account-subscribe-frame.schema.json#/$defs/member_roster_entry`:
/// `{actor_id, membership, subject_id?, identity_event_ids?,
/// member_display_state_digest?, identity_events?, handle_claim_digests?,
/// handle_claims?, handle_claims_limited?}`. The four handle-claim /
/// identity-event evidence fields are disclosure-gated on `subject_id`;
/// when the server omits `subject_id` it omits them all (we just treat
/// them as `None`). Falls back to bare DID strings or legacy `{did}`
/// objects for projections that haven't been migrated yet.
fn realm_member_roster(projection: Option<&Value>) -> Vec<RealmMemberRow> {
    let Some(root) = projection else {
        return Vec::new();
    };
    let mut rows: BTreeMap<String, RealmMemberRow> = BTreeMap::new();
    let sources: [&Value; 2] = [root, root.get("summary").unwrap_or(root)];
    for source in sources {
        for key in [
            "members",
            "participants",
            "owners",
            "admins",
            "admin_dids",
            "owner",
            "created_by",
            "creator",
        ] {
            collect_member_rows(source.get(key), &mut rows);
        }
    }
    rows.into_values().collect()
}

fn collect_member_rows(value: Option<&Value>, out: &mut BTreeMap<String, RealmMemberRow>) {
    let Some(value) = value else { return };
    match value {
        Value::String(s) => {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                out.entry(trimmed.to_owned())
                    .or_insert_with(|| RealmMemberRow {
                        actor_id: trimmed.to_owned(),
                        membership: None,
                        identity_event_ids: Vec::new(),
                        member_display_state_digest: None,
                        subject_id: None,
                    });
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_member_rows(Some(item), out);
            }
        }
        Value::Object(map) => {
            let did = ["actor_id", "did", "actor_did", "principal_did", "id"]
                .into_iter()
                .find_map(|key| map.get(key).and_then(|child| child.as_str()))
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            let membership = map
                .get("membership")
                .and_then(|child| child.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            let identity_event_ids: Vec<String> = map
                .get("identity_event_ids")
                .and_then(|child| child.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::trim).filter(|s| !s.is_empty()))
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            // R3.2 roster v2 rename: `identity_state_digest` →
            // `member_display_state_digest` (no pre-R3.2 compat).
            let member_display_state_digest = map
                .get("member_display_state_digest")
                .and_then(|child| child.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            // R3.2 roster v2: disclosed principal/holder DID. Gates the
            // inline handle-claim evidence (which we treat as optional /
            // None for now — the mention render path resolves handles
            // live). dependentRequired is enforced server-side; here we
            // simply read what was disclosed.
            let subject_id = map
                .get("subject_id")
                .and_then(|child| child.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            if let Some(did) = did {
                let candidate = RealmMemberRow {
                    actor_id: did.clone(),
                    membership: membership.clone(),
                    identity_event_ids: identity_event_ids.clone(),
                    member_display_state_digest: member_display_state_digest.clone(),
                    subject_id: subject_id.clone(),
                };
                match out.entry(did) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(candidate);
                    }
                    std::collections::btree_map::Entry::Occupied(mut entry) => {
                        let existing = entry.get_mut();
                        if existing.membership.is_none() {
                            existing.membership = membership;
                        }
                        if existing.identity_event_ids.is_empty() {
                            existing.identity_event_ids = identity_event_ids;
                        }
                        if existing.member_display_state_digest.is_none() {
                            existing.member_display_state_digest = member_display_state_digest;
                        }
                        if existing.subject_id.is_none() {
                            existing.subject_id = subject_id;
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

/// R3.1 ROST-4 — roster pagination state harvested from the
/// `account.subscribe` frame.
///
/// `members_limited=true` means the server truncated the `members[]`
/// array; UI MUST NOT treat the visible roster as authoritative and
/// SHOULD expose a "load more" affordance (or trigger
/// `cx.events.query` backfill) keyed on `members_next_cursor`.
///
/// Wire-level type — UI hookup (the actual "load more" button + the
/// `cx.events.query` backfill call) lands in a follow-up that uses
/// this projection. Marked `#[allow(dead_code)]` until then so the
/// unused-warning lint doesn't fire while the renderer wiring is
/// still in flight.
#[derive(Clone, Debug, Default, PartialEq)]
#[allow(dead_code)]
pub(super) struct RealmRosterPagination {
    pub members_limited: bool,
    pub members_next_cursor: Option<String>,
}

impl RealmRosterPagination {
    #[allow(dead_code)]
    pub fn from_projection(projection: Option<&Value>) -> Self {
        let Some(root) = projection else {
            return Self::default();
        };
        let limited = root
            .get("members_limited")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let cursor = root
            .get("members_next_cursor")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);
        Self {
            members_limited: limited,
            members_next_cursor: cursor,
        }
    }
}

/// Collect a deduped list of actor DIDs that have authored *any*
/// queued / accepted raw operation that targets the given flow id
/// (matched against `target_ref`, `flow_id`, or `object.id`). This
/// gives the "who's interacted with this Flow" list shown on the
/// sidebar's Participants tab even before the server returns a
/// canonical discussion-roster projection.
fn flow_participant_dids(raw_operations: &[RawOperationRecord], flow_id: &str) -> Vec<String> {
    let flow_id = flow_id.trim();
    if flow_id.is_empty() {
        return Vec::new();
    }
    let mut dids: BTreeSet<String> = BTreeSet::new();
    for op in raw_operations {
        let payload = &op.payload;
        let target = json_path_string(Some(payload), &["body", "target_ref"])
            .or_else(|| json_path_string(Some(payload), &["body", "flow_id"]))
            .or_else(|| json_path_string(Some(payload), &["body", "object", "id"]))
            .or_else(|| json_path_string(Some(payload), &["payload", "target_ref"]))
            .or_else(|| json_path_string(Some(payload), &["payload", "flow_id"]));
        if target.as_deref() != Some(flow_id) {
            continue;
        }
        for path in [
            &["body", "actor_id"][..],
            &["body", "actor_did"][..],
            &["body", "sender"][..],
            &["body", "author"][..],
            &["body", "created_by"][..],
            &["payload", "actor_id"][..],
            &["actor_id"][..],
            &["actor_did"][..],
        ] {
            if let Some(did) = json_path_string(Some(payload), path) {
                dids.insert(did);
            }
        }
    }
    let mut out: Vec<String> = dids.into_iter().collect();
    out.sort();
    out
}

fn card_detail_route_space_id(space_id: &str) -> String {
    let space_id = space_id.trim();
    if space_id.is_empty() {
        DEMO_BOARD_SPACE_ID.to_owned()
    } else {
        space_id.to_owned()
    }
}

fn kanban_card_detail_board_route(space_id: &str, board_id: &str) -> Route {
    let space_id = space_id.trim();
    if space_id.is_empty() {
        Route::Kanban
    } else {
        kanban_board_route(space_id, board_id)
    }
}

fn flow_detail_deep_link_path(space_id: &str, flow_id: &str) -> String {
    format!(
        "/kanban/{}/task/{}",
        card_detail_route_space_id(space_id),
        flow_id.trim()
    )
}

fn share_kanban_flow_link(path: &str) {
    let Ok(encoded) = serde_json::to_string(path) else {
        return;
    };
    let script = format!(
        r#"(async () => {{
    const path = {encoded};
    const url = new URL(path, window.location.href).href;
    if (navigator.share) {{
        try {{
            await navigator.share({{ url }});
            return true;
        }} catch (err) {{
            if (err && err.name === "AbortError") {{
                return false;
            }}
        }}
    }}
    if (navigator.clipboard && window.isSecureContext) {{
        await navigator.clipboard.writeText(url);
        return true;
    }}
    const node = document.createElement("textarea");
    node.value = url;
    node.setAttribute("readonly", "");
    node.style.position = "fixed";
    node.style.left = "-9999px";
    document.body.appendChild(node);
    node.select();
    const copied = document.execCommand("copy");
    document.body.removeChild(node);
    return copied;
}})()"#
    );
    let _ = document::eval(&script);
}

fn card_summary_text(summary: &str) -> String {
    summary.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn card_description_should_collapse(description: &str) -> bool {
    let trimmed = description.trim();
    trimmed.chars().count() > CARD_DESCRIPTION_COLLAPSE_CHAR_THRESHOLD
        || trimmed.lines().count() > CARD_DESCRIPTION_COLLAPSE_LINE_THRESHOLD
}

fn card_detail_draft_from_card(card: &KanbanCard) -> CardDetailDraft {
    CardDetailDraft {
        title: card.title.clone(),
        description: card.description.clone(),
        body: card.body.clone(),
        synthesis: card.synthesis.clone(),
        labels: card.labels.clone(),
        assignee: editor_value_for_optional_card_field(&card.assignee),
        due: editor_value_for_optional_card_field(&card.due),
    }
}

fn parse_card_labels(raw: &str) -> Vec<String> {
    let mut labels = Vec::new();
    for label in raw
        .split(',')
        .map(str::trim)
        .filter(|label| !label.is_empty())
    {
        if !labels
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(label))
        {
            labels.push(label.to_owned());
        }
    }
    labels
}

fn editor_value_for_optional_card_field(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "—" {
        String::new()
    } else {
        trimmed.to_owned()
    }
}

fn display_optional_card_field(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "—" {
        "—".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn card_detail_update_patch(
    current: &KanbanCard,
    draft: &CardDetailDraft,
) -> Result<Value, String> {
    let title = draft.title.trim();
    if title.is_empty() {
        return Err("card title is required".to_owned());
    }
    if title.chars().count() > 512 {
        return Err("card title exceeds 512 characters".to_owned());
    }
    if draft.description.chars().count() > 2048 {
        return Err("card description exceeds 2048 characters".to_owned());
    }

    let mut patch = Map::new();
    if current.title.trim() != title {
        patch.insert("title".to_owned(), json!({ "$op": "set", "value": title }));
    }

    let description = draft.description.trim();
    if current.description.trim() != description {
        let op = if description.is_empty() {
            json!({ "$op": "unset" })
        } else {
            json!({ "$op": "set", "value": description })
        };
        patch.insert("summary".to_owned(), op);
    }

    let body = draft.body.trim();
    if current.body.trim() != body {
        let op = if body.is_empty() {
            json!({ "$op": "unset" })
        } else {
            json!({ "$op": "set", "value": body })
        };
        patch.insert("body".to_owned(), op);
    }

    let synthesis = draft.synthesis.trim();
    if current.synthesis.trim() != synthesis {
        let op = if synthesis.is_empty() {
            json!({ "$op": "unset" })
        } else {
            json!({ "$op": "set", "value": synthesis })
        };
        patch.insert("synthesis".to_owned(), op);
    }

    let current_assignee = editor_value_for_optional_card_field(&current.assignee);
    let current_due = editor_value_for_optional_card_field(&current.due);
    let fields_changed = current.labels != draft.labels
        || current_assignee != draft.assignee.trim()
        || current_due != draft.due.trim();
    if fields_changed {
        let mut fields = Map::new();
        fields.insert("labels".to_owned(), json!(draft.labels.clone()));
        let assignee = draft.assignee.trim();
        if !assignee.is_empty() && assignee != "—" {
            fields.insert("assignee".to_owned(), json!(assignee));
        }
        let due = draft.due.trim();
        if !due.is_empty() && due != "—" {
            fields.insert("due_at".to_owned(), json!(due));
        }
        patch.insert(
            "fields".to_owned(),
            json!({ "$op": "set", "value": Value::Object(fields) }),
        );
    }

    if patch.is_empty() {
        return Err("no card detail changes to save".to_owned());
    }
    Ok(Value::Object(patch))
}

fn apply_card_detail_draft(card: &mut KanbanCard, draft: &CardDetailDraft) {
    card.title = draft.title.trim().to_owned();
    card.description = draft.description.trim().to_owned();
    card.body = draft.body.trim().to_owned();
    card.synthesis = draft.synthesis.trim().to_owned();
    card.labels = draft.labels.clone();
    card.assignee = display_optional_card_field(&draft.assignee);
    card.due = display_optional_card_field(&draft.due);
    card.state = CardState::Queued;
    card.activity_hint = "Local card update pending server sync.".to_owned();
    card.audit_hint = "Card detail edit submitted as cx.flow.update payload.patch.".to_owned();
}

#[allow(clippy::too_many_arguments)]
fn dispatch_card_detail_update(
    base_url: String,
    token: Signal<String>,
    space_id: String,
    actor_did: String,
    current: KanbanCard,
    draft: CardDetailDraft,
    mut columns: Signal<Vec<KanbanColumn>>,
    mut selected_card: Signal<Option<KanbanCard>>,
    state_store: Signal<LocalStateStore>,
    mut board_status: Signal<String>,
) -> bool {
    let patch = match card_detail_update_patch(&current, &draft) {
        Ok(patch) => patch,
        Err(msg) => {
            board_status.set(msg);
            return false;
        }
    };

    let mut updated_card = current.clone();
    let mut found = false;
    {
        let mut cols = columns.write();
        for col in cols.iter_mut() {
            if let Some(card) = col.cards.iter_mut().find(|card| card.id == current.id) {
                apply_card_detail_draft(card, &draft);
                updated_card = card.clone();
                found = true;
                break;
            }
        }
    }
    if !found {
        board_status.set(format!(
            "internal: card {} not in board state",
            short_protocol_id(&current.id)
        ));
        return false;
    }
    selected_card.set(Some(updated_card));

    let op = crate::operation::cx_ops::flow_update_patch(&space_id, &actor_did, &current.id, patch)
        .build("yougen");
    submit_kanban_operation_event(base_url, token, space_id, op, state_store, board_status);
    true
}

/// Build + sign + submit a `cx.component.flow.position.v1` Move via
/// `api.submit_move(...)`, recording a [`BoardWriteRecord`] in the local
/// queue regardless of submit outcome. Used by both list and card create
/// paths - `subject` is the cell subject (Space-container id or Flow id), `kind` is
/// the classifier the MoveSubmissionState tracker uses to decorate state
/// pills (`cx.space.create` / `cx.flow.create`).
fn submit_kanban_operation_event(
    base_url: String,
    token: Signal<String>,
    space_id: String,
    operation: crate::operation::EventEnvelope,
    mut state_store: Signal<LocalStateStore>,
    mut board_status: Signal<String>,
) {
    let operation_id = operation.local_operation_id().to_owned();
    let kind = operation.kind.clone();
    state_store.write().append_raw_operation(
        operation_id.clone(),
        Some(space_id),
        json!({
            "kind": kind,
            "operation_id": operation_id,
            "write_state": "queued",
            "body": operation.payload.clone(),
        }),
    );
    board_status.set(format!(
        "submitting {kind} operation {}",
        short_protocol_id(&operation_id)
    ));
    let api_token = token();
    spawn(async move {
        let operation_for_submit = operation.clone();
        match with_authed_api(&base_url, api_token, |api| async move {
            api.submit_event_envelope(&operation_for_submit).await
        })
        .await
        {
            Ok(_) => {
                board_status.set(format!("{kind} operation accepted"));
            }
            Err(err) => {
                board_status.set(format!("{kind} operation failed: {}", err.display()));
            }
        }
    });
}

fn submit_incident_status_transition(
    base_url: String,
    token: Signal<String>,
    space_id: String,
    actor_did: String,
    incident_flow_id: String,
    target_status: String,
    mut current_status: Signal<String>,
    mut initialized: Signal<bool>,
    mut status_error: Signal<String>,
    mut board_status: Signal<String>,
) {
    let current = current_status();
    if let Some(message) = incident_status_transition_local_error(&current, &target_status) {
        status_error.set(message.to_owned());
        return;
    }
    if space_id.trim().is_empty() {
        status_error.set("select a Space before updating incident status".to_owned());
        return;
    }
    if actor_did.trim().is_empty() {
        status_error.set("sign in before updating incident status".to_owned());
        return;
    }
    status_error.set("saving incident status".to_owned());
    board_status.set(format!(
        "submitting incident status {current} -> {target_status}"
    ));
    let api_token = token();
    spawn(async move {
        let should_create = !initialized();
        let create_op = should_create.then(|| {
            crate::operation::cx_ops::incident_flow_create(
                &space_id,
                &actor_did,
                &incident_flow_id,
                "Incident response",
                &current,
                "sev2",
            )
            .build("yougen")
        });
        let update_op = (target_status != current).then(|| {
            crate::operation::cx_ops::incident_status_update(
                &space_id,
                &actor_did,
                &incident_flow_id,
                &target_status,
            )
            .build("yougen")
        });
        let result = with_authed_api(&base_url, api_token, |api| async move {
            if let Some(op) = create_op {
                api.submit_event_envelope(&op).await?;
            }
            if let Some(op) = update_op {
                api.submit_event_envelope(&op).await?;
            }
            Ok(())
        })
        .await;
        match result {
            Ok(()) => {
                initialized.set(true);
                current_status.set(target_status.clone());
                status_error.set(String::new());
                board_status.set(format!("Incident status saved: {target_status}"));
            }
            Err(err) => {
                status_error.set(format!("invalid transition: {}", err.display()));
                board_status.set(format!("incident status rejected: {}", err.display()));
            }
        }
    });
}

fn submit_column_order_updates(
    base_url: String,
    token: Signal<String>,
    space_id: String,
    actor_did: String,
    ordered_columns: Vec<KanbanColumn>,
    state_store: Signal<LocalStateStore>,
    mut board_status: Signal<String>,
) {
    if actor_did.trim().is_empty() {
        board_status.set("sign in before reordering lists".to_owned());
        return;
    }
    if space_id.trim().is_empty() {
        board_status.set("select a Realm before reordering lists".to_owned());
        return;
    }
    let updates = ordered_columns
        .into_iter()
        .map(|column| (column.id, column.rank))
        .collect::<Vec<_>>();
    if updates.is_empty() {
        return;
    }
    let update_count = updates.len();
    board_status.set(format!("Column order queued ({update_count} rank updates)"));
    for (column_id, rank) in updates {
        let op = crate::operation::cx_ops::space_update_patch(
            &space_id,
            &actor_did,
            &column_id,
            json!({ "rank": rank }),
        )
        .build("yougen");
        submit_kanban_operation_event(
            base_url.clone(),
            token,
            space_id.clone(),
            op,
            state_store,
            board_status,
        );
    }
}

/// Build + submit a Kanban event and record it in the board write queue.
/// Card creates emit real `cx.flow.create` envelopes with an initial
/// `cx.component.flow.position.v1` component; legacy metadata writes still
/// go through the compatibility `cx.flow.update` patch helper.
fn submit_kanban_move(
    base_url: String,
    token: Signal<String>,
    space_id: String,
    actor_did: String,
    subject: String,
    kind: &'static str,
    value: serde_json::Value,
    mut state_store: Signal<LocalStateStore>,
    mut write_records: Signal<Vec<BoardWriteRecord>>,
    mut board_status: Signal<String>,
) {
    let hlc = Hlc::now("yougen").to_string();
    let anchor_ref = state_store.read().anchor_ref_for_move(&space_id);
    if actor_did.trim().is_empty() {
        board_status.set("sign in before updating cards".to_owned());
        return;
    }
    let envelope = if kind == "cx.flow.create" {
        let Some(board_space_id) = value.get("board_space_id").and_then(Value::as_str) else {
            board_status.set("cannot create card: missing board_space_id".to_owned());
            return;
        };
        let Some(list_space_id) = value.get("list_space_id").and_then(Value::as_str) else {
            board_status.set("cannot create card: missing list_space_id".to_owned());
            return;
        };
        let Some(title) = value.get("title").and_then(Value::as_str) else {
            board_status.set("cannot create card: missing title".to_owned());
            return;
        };
        let Some(rank) = value.get("rank").and_then(Value::as_str) else {
            board_status.set("cannot create card: missing rank".to_owned());
            return;
        };
        crate::operation::cx_ops::kanban_card_flow_create(
            &space_id,
            &actor_did,
            &subject,
            board_space_id,
            list_space_id,
            title,
            rank,
        )
        .build("yougen")
    } else {
        crate::operation::cx_ops::flow_position_update(
            &space_id,
            &actor_did,
            &subject,
            value.clone(),
        )
        .build("yougen")
    };
    let wire_kind = envelope.kind.clone();
    let op_id = envelope.local_operation_id().to_owned();
    let cell_id = value
        .get("board_space_id")
        .and_then(Value::as_str)
        .map(|board_space_id| flow_position_cell_id(board_space_id, &subject))
        .unwrap_or_else(|| format!("cx:cell:cx.component.flow.position.v1:{subject}"));
    let effect_summary = if kind == "cx.flow.create" {
        serde_json::to_string(&envelope.payload).unwrap_or_else(|_| "{}".to_owned())
    } else {
        serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_owned())
    };
    let record = BoardWriteRecord {
        state: CardState::Queued,
        move_id: op_id.clone(),
        kind: kind.to_owned(),
        cell_id: cell_id.clone(),
        effect_summary: effect_summary.clone(),
        anchor_ref: anchor_ref.clone(),
        hlc: hlc.clone(),
        note: format!("submitting {wire_kind} event via cx.events.submit"),
        signed_move_json: None,
        rebase_attempts: 0,
    };
    write_records.write().push(record);
    state_store.write().append_raw_operation(
        op_id.clone(),
        Some(space_id.clone()),
        json!({
            "kind": kind,
            "operation_id": op_id,
            "cell": cell_id,
            "effect": value,
            "wire_kind": wire_kind.clone(),
            "body": envelope.payload.clone(),
            "write_state": "queued",
        }),
    );
    board_status.set(format!(
        "submitting {wire_kind} event {}",
        short_protocol_id(&op_id)
    ));
    let api_token = token();
    let space_for_record = space_id.clone();
    let anchor_for_record = anchor_ref.clone();
    let kind_for_record = kind.to_owned();
    let op_for_track = op_id.clone();
    spawn(async move {
        match with_authed_api(&base_url, api_token, |api| async move {
            api.submit_event_envelope(&envelope).await
        })
        .await
        {
            Ok(resp) => {
                let state = MoveSubmissionState::from_submit_state("accepted", None);
                state_store.write().record_move_submission(
                    op_for_track.clone(),
                    space_for_record,
                    kind_for_record.clone(),
                    state,
                    None,
                    Some(anchor_for_record),
                );
                if let Some(record) = write_records
                    .write()
                    .iter_mut()
                    .find(|r| r.move_id == op_for_track)
                {
                    record.state = CardState::Accepted;
                    record.note = format!(
                        "event accepted event_id={}",
                        short_protocol_id(&resp.event_id)
                    );
                }
                board_status.set(format!(
                    "{kind_for_record} event {} accepted (event_id={})",
                    short_protocol_id(&op_for_track),
                    short_protocol_id(&resp.event_id)
                ));
            }
            Err(err) => {
                if let Some(record) = write_records
                    .write()
                    .iter_mut()
                    .find(|r| r.move_id == op_for_track)
                {
                    record.state = CardState::Quarantined;
                    record.note = format!("submit failed: {}", err.display());
                }
                board_status.set(format!("quarantined event: {}", err.display()));
            }
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
///   cell; the difference is whether `effect.list_space_id` equals
///   `expected.list_space_id`.
fn dispatch_flow_position_move(
    base_url: String,
    token: Signal<String>,
    space_id: String,
    board_space_id: String,
    board_view_id: String,
    actor_did: String,
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
        list_space_id: dragged.from_column_id.clone(),
        rank: dragged.from_rank.clone(),
    };
    let effect = FlowPositionEffect::SetPosition {
        list_space_id: target_column_id.clone(),
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
        board_space_id,
        board_view_id,
        actor_did,
        dragged.card_id,
        kind,
        expected,
        effect,
        state_store,
        write_records,
        board_status,
    );
}

/// Pure guard for Space-container lifecycle transitions. Refuses two illegal cases:
/// (1) same-state self-transition — UI structure already gates this
/// (Archive button only renders on Active columns and vice versa), but
/// keeping a programmatic guard avoids no-op server roundtrips if a future
/// code path bypasses the UI filter; (2) UI-emitted Tombstone — terminal
/// state is server-only. Extracted as a pure fn so the policy is unit-tested
/// without spinning up a Dioxus runtime.
fn validate_space_container_lifecycle_transition(
    space_container_id: &str,
    prior: SpaceContainerLifecycleState,
    target: SpaceContainerLifecycleState,
) -> Result<(), String> {
    if matches!(target, SpaceContainerLifecycleState::Tombstoned) {
        return Err("Tombstone is server-only; UI dispatch refused".to_owned());
    }
    if prior == target {
        return Err(format!(
            "list {} already in {target:?} state; refused",
            short_protocol_id(space_container_id)
        ));
    }
    Ok(())
}

/// Map soland's wire state strings into `SpaceContainerLifecycleState`.
/// Anything we don't recognise stays `Active`
/// (the safe default — server can correct on next sync).
fn space_container_state_from_wire(state: &str) -> SpaceContainerLifecycleState {
    match state {
        "archived" => SpaceContainerLifecycleState::Archived,
        "tombstoned" => SpaceContainerLifecycleState::Tombstoned,
        _ => SpaceContainerLifecycleState::Active,
    }
}

/// Sibling at the Flow object layer. Server emits the four states
/// `active / archived / deleted / redacted`; yougen folds the two
/// terminals into `Tombstoned` since the UI treats them equivalently.
fn flow_lifecycle_from_wire(state: &str) -> FlowLifecycleState {
    match state {
        "archived" => FlowLifecycleState::Archived,
        "deleted" | "redacted" => FlowLifecycleState::Tombstoned,
        _ => FlowLifecycleState::Active,
    }
}

/// Cap-Gate-3: helper that reads the app-provided `CapabilityEngine`
/// signal and returns the UI gate for a Space-container-scoped action. Wraps
/// `engine.read().ui_gate(...)` so kanban callers don't have to spell
/// out the `ResourceRef` / `EvalContext` every time.
fn capability_gate_for_space_container(
    engine: &Signal<crate::capability::CapabilityEngine>,
    actor: &str,
    space_id: &str,
    space_container_id: &str,
    action: &str,
) -> crate::capability::CapabilityGate {
    let resource = crate::capability::ResourceRef {
        space_id: Some(space_id.to_owned()),
        object_ref: Some(space_container_id.to_owned()),
        object_type: Some("space_container".to_owned()),
        ..Default::default()
    };
    let ctx = crate::capability::EvalContext {
        space_id: Some(space_id.to_owned()),
        space_container_id: Some(space_container_id.to_owned()),
        action: Some(action.to_owned()),
        ..Default::default()
    };
    engine.read().ui_gate(actor, action, &resource, &ctx)
}

/// Cap-Gate-3 sibling at the Flow object layer.
fn capability_gate_for_flow(
    engine: &Signal<crate::capability::CapabilityEngine>,
    actor: &str,
    space_id: &str,
    flow_id: &str,
    action: &str,
) -> crate::capability::CapabilityGate {
    let resource = crate::capability::ResourceRef {
        space_id: Some(space_id.to_owned()),
        object_ref: Some(flow_id.to_owned()),
        object_type: Some("Flow".to_owned()),
        ..Default::default()
    };
    let ctx = crate::capability::EvalContext {
        space_id: Some(space_id.to_owned()),
        action: Some(action.to_owned()),
        ..Default::default()
    };
    engine.read().ui_gate(actor, action, &resource, &ctx)
}

/// Dispatch a `cx.space.archive` or `cx.space.restore` operation against
/// the given list (container Space) and optimistically update
/// the column's `SpaceContainerLifecycleState` in the UI signal. Spec:
/// `models/realm-and-space.md §4.4` (post-R1.7 rename). Soland's lifecycle
/// envelope validator and the SDK reducer's lifecycle guard
/// both enforce wire / state shape; this helper only handles the
/// submit + local optimistic projection. If the submit fails the local
/// state is rolled back to the prior value.
fn dispatch_space_container_lifecycle(
    base_url: String,
    token: Signal<String>,
    space_id: String,
    actor_did: String,
    space_container_id: String,
    target: SpaceContainerLifecycleState,
    mut columns: Signal<Vec<KanbanColumn>>,
    mut board_status: Signal<String>,
) {
    // Optimistic state update. Capture prior state for rollback on error
    // and apply the same-state / Tombstone guard inside the write
    // critical section so prior is observed atomically.
    let prior_state = {
        let mut cols = columns.write();
        let Some(col) = cols.iter_mut().find(|c| c.id == space_container_id) else {
            board_status.set(format!(
                "internal: list {} not in board state",
                short_protocol_id(&space_container_id)
            ));
            return;
        };
        let prior = col.state;
        if let Err(msg) =
            validate_space_container_lifecycle_transition(&space_container_id, prior, target)
        {
            board_status.set(msg);
            return;
        }
        col.state = target;
        prior
    };

    // Only Active <-> Archived reach here (validator rejects Tombstone).
    let builder = match target {
        SpaceContainerLifecycleState::Archived => {
            crate::operation::cx_ops::space_archive(&space_id, &actor_did, &space_container_id)
        }
        SpaceContainerLifecycleState::Active => {
            crate::operation::cx_ops::space_restore(&space_id, &actor_did, &space_container_id)
        }
        SpaceContainerLifecycleState::Tombstoned => {
            // Invariant: `validate_space_container_lifecycle_transition` (called above)
            // already rejects any move to Tombstone, so by construction the
            // only targets that reach this match are Active|Archived. If we
            // ever land here something upstream broke the contract — fail
            // loud rather than emitting a silently-wrong Move.
            panic!(
                "invariant violation: validate_space_container_lifecycle_transition guarantees target is Active|Archived; got {target:?}"
            )
        }
    };
    let op = builder.build("yougen");

    let kind = op.kind.clone();
    let base = base_url.clone();
    let api_token = token();
    spawn(async move {
        let result = with_authed_api(&base, api_token, |api| async move {
            api.submit_event_envelope(&op).await
        })
        .await;
        match result {
            Ok(_) => {
                board_status.set(format!(
                    "{kind} accepted; list optimistic state = {target:?}"
                ));
            }
            Err(err) => {
                // Rollback optimistic state on submit failure.
                if let Some(col) = columns
                    .write()
                    .iter_mut()
                    .find(|c| c.id == space_container_id)
                {
                    col.state = prior_state;
                }
                board_status.set(format!("{kind} failed: {}", err.display()));
            }
        }
    });
}

/// Pure guard for Flow lifecycle transitions. Mirrors
/// `validate_space_container_lifecycle_transition` at the Flow layer — refuses
/// same-state self-transitions and UI-emitted Tombstone targets.
fn validate_flow_lifecycle_transition(
    flow_id: &str,
    prior: FlowLifecycleState,
    target: FlowLifecycleState,
) -> Result<(), String> {
    if matches!(target, FlowLifecycleState::Tombstoned) {
        return Err("Tombstone is server-only; UI dispatch refused".to_owned());
    }
    if prior == target {
        return Err(format!(
            "card {} already in {target:?} state; refused",
            short_protocol_id(flow_id)
        ));
    }
    Ok(())
}

/// Dispatch `cx.flow.archive` or `cx.flow.restore` for a card and
/// optimistically update its `FlowLifecycleState`. Mirrors
/// `dispatch_space_container_lifecycle` but at the Flow object layer. Spec:
/// `flow-and-message.md §3`, `common-fields.md §5.1`. SDK reducer
/// enforces `state == archived` for restore (`flow_not_archived`) and
/// `state == active` for archive (`flow_not_active` — once SDK round
/// 10 lands; today only restore is reducer-enforced).
fn dispatch_flow_lifecycle(
    base_url: String,
    token: Signal<String>,
    space_id: String,
    actor_did: String,
    flow_id: String,
    target: FlowLifecycleState,
    mut columns: Signal<Vec<KanbanColumn>>,
    mut board_status: Signal<String>,
) {
    // Locate the card across columns; capture prior state for rollback
    // and apply the same-state / Tombstone guard inside the write
    // critical section.
    let prior_state = {
        let mut cols = columns.write();
        let mut found = None;
        for col in cols.iter_mut() {
            if let Some(card) = col.cards.iter_mut().find(|c| c.id == flow_id) {
                let prior = card.lifecycle;
                if let Err(msg) = validate_flow_lifecycle_transition(&flow_id, prior, target) {
                    board_status.set(msg);
                    return;
                }
                card.lifecycle = target;
                found = Some(prior);
                break;
            }
        }
        match found {
            Some(prior) => prior,
            None => {
                board_status.set(format!(
                    "internal: card {} not in board state",
                    short_protocol_id(&flow_id)
                ));
                return;
            }
        }
    };

    let builder = match target {
        FlowLifecycleState::Archived => {
            crate::operation::cx_ops::flow_archive(&space_id, &actor_did, &flow_id)
        }
        FlowLifecycleState::Active => {
            crate::operation::cx_ops::flow_restore(&space_id, &actor_did, &flow_id)
        }
        FlowLifecycleState::Tombstoned => {
            // Invariant: `validate_flow_lifecycle_transition` (called above)
            // already rejects any move to Tombstone, so by construction the
            // only targets that reach this match are Active|Archived. If we
            // ever land here something upstream broke the contract — fail
            // loud rather than emitting a silently-wrong Move.
            panic!(
                "invariant violation: validate_flow_lifecycle_transition guarantees target is Active|Archived; got {target:?}"
            )
        }
    };
    let op = builder.build("yougen");

    let kind = op.kind.clone();
    let base = base_url.clone();
    let api_token = token();
    spawn(async move {
        let result = with_authed_api(&base, api_token, |api| async move {
            api.submit_event_envelope(&op).await
        })
        .await;
        match result {
            Ok(_) => {
                board_status.set(format!(
                    "{kind} accepted; card optimistic lifecycle = {target:?}"
                ));
            }
            Err(err) => {
                // Rollback on failure.
                for col in columns.write().iter_mut() {
                    if let Some(card) = col.cards.iter_mut().find(|c| c.id == flow_id) {
                        card.lifecycle = prior_state;
                        break;
                    }
                }
                board_status.set(format!("{kind} failed: {}", err.display()));
            }
        }
    });
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
        .or(Some(source_idx))?;
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
    board_space_id: String,
    board_view_id: String,
    actor_did: String,
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
        board_space_id,
        board_view_id,
        actor_did,
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
    board_space_id: String,
    board_view_id: String,
    actor_did: String,
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
    if actor_did.trim().is_empty() {
        board_status.set("sign in before moving cards".to_owned());
        return;
    }
    let expected_json = match &expected {
        FlowPositionExpectation::Initial => serde_json::Value::Null,
        FlowPositionExpectation::At {
            list_space_id,
            rank,
        } => {
            json!({"list_space_id": list_space_id, "rank": rank})
        }
    };
    let effect_json = match &effect {
        FlowPositionEffect::SetPosition {
            list_space_id,
            rank,
        } => {
            json!({"list_space_id": list_space_id, "rank": rank})
        }
        FlowPositionEffect::Remove => serde_json::Value::Null,
    };
    let envelope = crate::operation::cx_ops::flow_position_cas_update(
        &space_id,
        &actor_did,
        kind,
        &board_space_id,
        &flow_id,
        expected_json.clone(),
        effect_json.clone(),
    )
    .build("yougen");
    let move_id = envelope.local_operation_id().to_owned();
    let cell_id = flow_position_cell_id(&board_space_id, &flow_id);
    let effect_summary = match &effect {
        FlowPositionEffect::SetPosition {
            list_space_id,
            rank,
        } => format!("set {{list_space_id={list_space_id}, rank={rank}}}"),
        FlowPositionEffect::Remove => "set null (remove)".to_owned(),
    };
    let record = BoardWriteRecord {
        state: CardState::Submitted,
        move_id: move_id.clone(),
        kind: kind.to_owned(),
        cell_id: cell_id.clone(),
        effect_summary,
        anchor_ref: anchor_ref.clone(),
        hlc: hlc.clone(),
        note: if attempt == 0 {
            format!("submitting {kind} via cx.events.submit")
        } else {
            format!("rebase attempt {attempt} of {kind}")
        },
        signed_move_json: None,
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
            "board_space_id": board_space_id,
            "expected_position": match &expected {
                FlowPositionExpectation::Initial => serde_json::Value::Null,
                FlowPositionExpectation::At {
                    list_space_id,
                    rank,
                } => json!({"space_id": list_space_id, "rank": rank}),
            },
            "target_position": match &effect {
                FlowPositionEffect::SetPosition {
                    list_space_id,
                    rank,
                } => json!({"space_id": list_space_id, "rank": rank}),
                FlowPositionEffect::Remove => serde_json::Value::Null,
            },
            "write_state": "submitted",
        }),
    );
    board_status.set(format!(
        "submitting {kind} event {}",
        short_protocol_id(&move_id)
    ));
    let api_token = token();
    let move_for_track = move_id.clone();
    let kind_for_record = kind.to_owned();
    let anchor_for_record = anchor_ref.clone();
    let space_for_record = space_id.clone();
    let base_for_rebase = base_url.clone();
    let space_for_rebase = space_id.clone();
    let board_for_rebase = board_space_id.clone();
    let view_for_rebase = board_view_id.clone();
    let flow_for_rebase = flow_id.clone();
    let effect_for_rebase = effect.clone();
    spawn(async move {
        let submit_result = with_authed_api(&base_url, api_token, |api| async move {
            api.submit_event_envelope(&envelope).await
        })
        .await;
        match submit_result {
            Ok(resp) => {
                // events.submit accepted path: the server has folded the
                // CAS update into the cell. cas_conflict surfaces as an
                // Err arm because the envelope was rejected with a
                // non-200 status — that branch is handled below.
                let submission_state = MoveSubmissionState::from_submit_state("accepted", None);
                state_store.write().record_move_submission(
                    move_for_track.clone(),
                    space_for_record,
                    kind_for_record.clone(),
                    submission_state,
                    None,
                    Some(anchor_for_record),
                );
                if let Some(record) = write_records
                    .write()
                    .iter_mut()
                    .find(|r| r.move_id == move_for_track)
                {
                    record.state = CardState::Accepted;
                    record.note = format!(
                        "event accepted event_id={}",
                        short_protocol_id(&resp.event_id)
                    );
                }
                board_status.set(format!(
                    "{kind_for_record} event {} accepted (event_id={})",
                    short_protocol_id(&move_for_track),
                    short_protocol_id(&resp.event_id)
                ));
            }
            Err(err) => {
                let err_text = err.display();
                let cas_conflict = err_text.contains("cas_conflict");
                let card_state = if cas_conflict {
                    CardState::Conflict
                } else {
                    CardState::SoftFailed
                };
                if let Some(record) = write_records
                    .write()
                    .iter_mut()
                    .find(|r| r.move_id == move_for_track)
                {
                    record.state = card_state.clone();
                    record.note = format!("events.submit failed: {err_text}");
                }
                board_status.set(format!("{kind_for_record} event {err_text}"));
                // Auto-rebase the CAS event after a cas_conflict: re-fetch
                // the cell's current head via the projection endpoint,
                // build a fresh `expected_position`, and re-submit up to
                // MAX_CONFLICT_REBASE_ATTEMPTS times.
                if matches!(card_state, CardState::Conflict)
                    && attempt + 1 < MAX_CONFLICT_REBASE_ATTEMPTS
                {
                    rebase_flow_position_after_conflict(
                        base_for_rebase,
                        token,
                        space_for_rebase,
                        board_for_rebase,
                        view_for_rebase,
                        actor_did.clone(),
                        flow_for_rebase,
                        kind_for_record,
                        effect_for_rebase,
                        attempt + 1,
                        state_store,
                        write_records,
                        board_status,
                    );
                } else if matches!(card_state, CardState::Conflict) {
                    if let Some(record) = write_records
                        .write()
                        .iter_mut()
                        .find(|r| r.move_id == move_for_track)
                    {
                        record.state = CardState::Quarantined;
                        record.note = format!(
                            "cas_conflict exhausted {MAX_CONFLICT_REBASE_ATTEMPTS} rebase attempts"
                        );
                    }
                    board_status.set(format!(
                        "{kind_for_record} quarantined after {MAX_CONFLICT_REBASE_ATTEMPTS} rebase attempts"
                    ));
                }
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
/// same cell store) and reads the flow's current `list_space_id` /
/// `rank` from it.
#[allow(clippy::too_many_arguments)]
fn rebase_flow_position_after_conflict(
    base_url: String,
    token: Signal<String>,
    space_id: String,
    board_space_id: String,
    board_view_id: String,
    actor_did: String,
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
        if board_view_id.trim().is_empty() {
            board_status.set(
                "rebase aborted: enter a Board View ID so projection can provide the current cell head"
                    .to_owned(),
            );
            return;
        }
        let view_for_projection = board_view_id.clone();
        let new_expected = match with_authed_api(&base_url, token(), |api| async move {
            api.collection_projection(&view_for_projection).await
        })
        .await
        {
            Ok(projection) => locate_flow_position_in_projection(&projection, &flow_id),
            Err(err) => {
                board_status.set(format!(
                    "rebase aborted (projection refresh failed): {}",
                    err.display()
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
            board_space_id,
            board_view_id,
            actor_did,
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
    projection: &contrix_sdk::CollectionProjectionResBody,
    flow_id: &str,
) -> FlowPositionExpectation {
    for group in &projection.groups {
        for item in &group.items {
            let item_id = item.object.get("id").and_then(|v| v.as_str()).unwrap_or("");
            if item_id == flow_id {
                if let Some(position) = item.position.as_ref() {
                    return FlowPositionExpectation::At {
                        list_space_id: group.group_id.clone(),
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

/// Marks the first queued / soft-failed write as Quarantined. Event
/// submit is the only write surface now, and a failed event needs the UI
/// to reconstruct the equivalent envelope (TODO: wire that through
/// cx_ops::flow_position_*) rather than replay stale bytes.
fn replay_first_move(
    _base_url: String,
    _token: Signal<String>,
    mut write_records: Signal<Vec<BoardWriteRecord>>,
    mut board_status: Signal<String>,
) {
    let Some(idx) = write_records.read().iter().position(|record| {
        record.state == CardState::Queued
            || record.state == CardState::SoftFailed
            || record.state == CardState::Conflict
    }) else {
        board_status.set("no queued write to replay".to_owned());
        return;
    };
    if let Some(record) = write_records.write().get_mut(idx) {
        record.state = CardState::Quarantined;
        record.note =
            "replay via cx.events.submit not yet wired; quarantining for manual review".to_owned();
    }
    board_status.set(
        "replay not available — write quarantined (TODO: rebuild cx.flow.update envelope)"
            .to_owned(),
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
            id: "cx:space:01list-todo000000000000000000".to_owned(),
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
                body: String::new(),
                synthesis: String::new(),
                labels: vec!["legal".to_owned(), "beta".to_owned()],
                assignee: "Alice".to_owned(),
                due: "May 08".to_owned(),
                primary_flow_id: "cx:flow:review-discussion".to_owned(),
                locked_flow: Some(LockedFlow {
                    flow_id_hash: "sha256:locked-private-decision".to_owned(),
                reason: "You can see that a restricted discussion is linked, but not its name or members.".to_owned(),
                }),
                external_visibility: "External counsel discussion only".to_owned(),
                history_visibility: "joined history".to_owned(),
                activity_hint: "Activity shows discussion mentions, card moves, and message references.".to_owned(),
                audit_hint: "Audit records cx.flow.track.member and cx.message.create without granting discussion access.".to_owned(),
                state: CardState::Synced,
                lifecycle: FlowLifecycleState::Active,
            }],
            state: SpaceContainerLifecycleState::Active,
        },
        KanbanColumn {
            id: "cx:space:01list-progress00000000000000".to_owned(),
            title: "In Progress".to_owned(),
            rank: "f".to_owned(),
            cards: vec![KanbanCard {
                id: "cx:flow:onboarding-copy".to_owned(),
                rank: "U".to_owned(),
                title: "Onboarding copy".to_owned(),
                description: "Waiting on discussion-scoped feedback from support and docs reviewers.".to_owned(),
                body: String::new(),
                synthesis: String::new(),
                labels: vec!["copy".to_owned(), "support".to_owned()],
                assignee: "Bob".to_owned(),
                due: "May 10".to_owned(),
                primary_flow_id: "cx:flow:support-discussion".to_owned(),
                locked_flow: None,
                external_visibility: "No external discussions linked".to_owned(),
                history_visibility: "shared history".to_owned(),
                activity_hint: "Pending move is visible until the reducer accepts the board event.".to_owned(),
                audit_hint: "Audit preview will include local pending event and final reducer receipt.".to_owned(),
                state: CardState::Queued,
                lifecycle: FlowLifecycleState::Active,
            }],
            state: SpaceContainerLifecycleState::Active,
        },
        KanbanColumn {
            id: "cx:space:01list-done00000000000000000".to_owned(),
            title: "Done".to_owned(),
            rank: "p".to_owned(),
            cards: vec![KanbanCard {
                id: "cx:flow:security-signoff".to_owned(),
                rank: "U".to_owned(),
                title: "Security sign-off".to_owned(),
                description: "Projection detected a stale column head after an offline move.".to_owned(),
                body: String::new(),
                synthesis: String::new(),
                labels: vec!["security".to_owned(), "reviewed".to_owned()],
                assignee: "Carol".to_owned(),
                due: "May 01".to_owned(),
                primary_flow_id: "cx:flow:security-review".to_owned(),
                locked_flow: Some(LockedFlow {
                    flow_id_hash: "sha256:locked-incident-notes".to_owned(),
                    reason: "Incident notes require separate discussion capability.".to_owned(),
                }),
                external_visibility: "Internal discussions only".to_owned(),
                history_visibility: "restricted history".to_owned(),
                activity_hint: "Conflict banner links to the reducer result and competing event.".to_owned(),
                audit_hint: "Audit trail preserves rejected cx.flow.move with cas_conflict.".to_owned(),
                state: CardState::Conflict,
                lifecycle: FlowLifecycleState::Active,
            }],
            state: SpaceContainerLifecycleState::Active,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realm_member_roster_reads_r32_wire_shape() {
        // R3.2 (contrix-spec @ b56cab1): roster v2 entries carry
        // `actor_id` + `membership` + optional `subject_id` /
        // `identity_event_ids` / `member_display_state_digest`. Handle
        // strings only appear inside signed handle_claim evidence.
        let projection = json!({
            "members": [
                {
                    "actor_id": "did:web:acme.example:users:alice",
                    "membership": "join",
                    "subject_id": "did:web:acme.example:principals:alice",
                    "identity_event_ids": ["cx:event:01904100-0000-7000-8000-00000000000a"],
                    "member_display_state_digest": "sha256:abababababababababababababababababababababababababababababababab"
                },
                {
                    "actor_id": "did:webvh:zQmPr8",
                    "membership": "invite"
                }
            ]
        });
        let rows = realm_member_roster(Some(&projection));
        assert_eq!(rows.len(), 2);
        let alice = rows
            .iter()
            .find(|row| row.actor_id.contains("alice"))
            .unwrap();
        assert_eq!(alice.membership.as_deref(), Some("join"));
        assert_eq!(
            alice.identity_event_ids,
            vec!["cx:event:01904100-0000-7000-8000-00000000000a".to_owned()]
        );
        assert!(alice.member_display_state_digest.is_some());
        assert_eq!(
            alice.subject_id.as_deref(),
            Some("did:web:acme.example:principals:alice")
        );

        let webvh = rows
            .iter()
            .find(|row| row.actor_id.starts_with("did:webvh:"))
            .unwrap();
        assert_eq!(webvh.membership.as_deref(), Some("invite"));
        assert!(webvh.identity_event_ids.is_empty());
        assert!(webvh.member_display_state_digest.is_none());
        // subject_id not disclosed for the invite row.
        assert!(webvh.subject_id.is_none());
    }

    #[test]
    fn realm_member_roster_reads_v2_digest_only() {
        // Aggressive no-compat: only the R3.2 `member_display_state_digest`
        // key is read.
        let v2 = json!({
            "members": [{
                "actor_id": "did:web:acme.example:users:v2",
                "membership": "join",
                "member_display_state_digest": "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
            }]
        });
        let rows = realm_member_roster(Some(&v2));
        assert_eq!(rows.len(), 1);
        assert!(rows[0].member_display_state_digest.is_some());
    }

    #[test]
    fn realm_member_roster_ignores_legacy_digest_key() {
        // The pre-R3.2 `identity_state_digest` key is NOT honoured.
        let legacy = json!({
            "members": [{
                "actor_id": "did:web:acme.example:users:legacy",
                "membership": "join",
                "identity_state_digest": "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
            }]
        });
        let rows = realm_member_roster(Some(&legacy));
        assert_eq!(rows.len(), 1);
        assert!(rows[0].member_display_state_digest.is_none());
    }

    #[test]
    fn realm_member_roster_falls_back_to_bare_did_strings() {
        let projection = json!({
            "members": ["did:web:bob.example", "did:web:carol.example"]
        });
        let rows = realm_member_roster(Some(&projection));
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row.membership.is_none()));
        assert!(rows.iter().all(|row| row.identity_event_ids.is_empty()));
    }

    #[test]
    fn member_display_label_uses_member_identity_when_available() {
        use contrix_sdk::{
            DisplayProfile, MemberIdentity, MemberIdentityProof, MemberIdentitySignatureAlgorithm,
        };

        // R3.2: `MemberIdentity` discloses subject_id + display_profile
        // only; the roster label falls back to the display name (handle
        // resolution runs §3.2.1 in the dedicated render path).
        let identity = MemberIdentity {
            schema: contrix_sdk::MEMBER_IDENTITY_SCHEMA.to_owned(),
            realm_id: contrix_sdk::RealmId::new("cx:realm:01904100-0000-7000-8000-000000000001")
                .unwrap(),
            actor_id: contrix_sdk::Did::new("did:web:acme.example:users:alice".to_owned()).unwrap(),
            subject_id: contrix_sdk::Did::new("did:web:acme.example:users:alice".to_owned())
                .unwrap(),
            display_profile: DisplayProfile {
                display_name: "Alice".to_owned(),
                avatar_ref: None,
            },
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            proof: MemberIdentityProof {
                verification_method: "did:web:acme.example#key-1".to_owned(),
                signature_algorithm: MemberIdentitySignatureAlgorithm::Ed25519,
                payload_digest: contrix_sdk::Hash::new(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                signature: "AAAA".to_owned(),
            },
        };

        let row = RealmMemberRow {
            actor_id: "did:web:acme.example:users:alice".to_owned(),
            membership: Some("join".to_owned()),
            identity_event_ids: vec![],
            member_display_state_digest: None,
            subject_id: None,
        };
        assert_eq!(member_display_label(&row, Some(&identity)), "Alice");

        // Decryption-pending / no MemberIdentity → fall back to compact DID.
        let bare = RealmMemberRow {
            actor_id: "did:webvh:zQmPr8aaaaaaaaaaaaaaaaa7h4q87ha".to_owned(),
            membership: None,
            identity_event_ids: vec![],
            member_display_state_digest: None,
            subject_id: None,
        };
        let label = member_display_label(&bare, None);
        assert!(label.starts_with("did:webvh:"));
        assert!(label.contains("..."));
    }

    #[test]
    fn realm_roster_pagination_extracts_limited_and_cursor() {
        // ROST-4: truncated rosters MUST signal `members_limited=true`
        // so the UI surfaces a "load more" affordance.
        let projection = json!({
            "members": [],
            "members_limited": true,
            "members_next_cursor": "cursor-opaque.v1.abc"
        });
        let pagination = RealmRosterPagination::from_projection(Some(&projection));
        assert!(pagination.members_limited);
        assert_eq!(
            pagination.members_next_cursor.as_deref(),
            Some("cursor-opaque.v1.abc")
        );

        // Complete projections leave the flag unset.
        let complete = json!({ "members": [] });
        let pagination = RealmRosterPagination::from_projection(Some(&complete));
        assert!(!pagination.members_limited);
        assert!(pagination.members_next_cursor.is_none());
    }

    /// `try_load_api_columns` is the synchronous-init probe. Real API
    /// fetching now lives in the async refresh handler that calls
    /// `ContrixApi::collection_projection`. This test still pins the
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

    /// Wire state strings emitted by soland's
    /// `/api/v1/projection/{spaces|flows}` round-trip into the
    /// renderer enums. Unknown values stay at the safe `Active` default.
    #[test]
    fn lifecycle_wire_strings_decode_to_enums() {
        assert_eq!(
            space_container_state_from_wire("active"),
            SpaceContainerLifecycleState::Active
        );
        assert_eq!(
            space_container_state_from_wire("archived"),
            SpaceContainerLifecycleState::Archived
        );
        assert_eq!(
            space_container_state_from_wire("tombstoned"),
            SpaceContainerLifecycleState::Tombstoned
        );
        assert_eq!(
            space_container_state_from_wire("garbage"),
            SpaceContainerLifecycleState::Active
        );

        assert_eq!(
            flow_lifecycle_from_wire("active"),
            FlowLifecycleState::Active
        );
        assert_eq!(
            flow_lifecycle_from_wire("archived"),
            FlowLifecycleState::Archived
        );
        // Spec lists both `deleted` and `redacted` as terminal; yougen
        // folds them into the same UI bucket.
        assert_eq!(
            flow_lifecycle_from_wire("deleted"),
            FlowLifecycleState::Tombstoned
        );
        assert_eq!(
            flow_lifecycle_from_wire("redacted"),
            FlowLifecycleState::Tombstoned
        );
        assert_eq!(
            flow_lifecycle_from_wire("garbage"),
            FlowLifecycleState::Active
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

    /// Space-container lifecycle validator rejects (a) same-state self-transition
    /// and (b) UI-emitted Tombstone target. The legal transitions
    /// (Active → Archived and Archived → Active) MUST be accepted so
    /// archive / restore continue to work end-to-end.
    #[test]
    fn validate_space_container_lifecycle_transition_rules() {
        // Same-state refusal — Active → Active.
        let err = validate_space_container_lifecycle_transition(
            "cx:space:test",
            SpaceContainerLifecycleState::Active,
            SpaceContainerLifecycleState::Active,
        )
        .expect_err("same-state Active→Active must be refused");
        assert!(err.contains("already in"));
        assert!(err.contains("cx:space:test"));

        // Same-state refusal — Archived → Archived.
        validate_space_container_lifecycle_transition(
            "cx:space:test",
            SpaceContainerLifecycleState::Archived,
            SpaceContainerLifecycleState::Archived,
        )
        .expect_err("same-state Archived→Archived must be refused");

        // Tombstone target refusal — UI never emits Tombstone.
        let err = validate_space_container_lifecycle_transition(
            "cx:space:test",
            SpaceContainerLifecycleState::Active,
            SpaceContainerLifecycleState::Tombstoned,
        )
        .expect_err("UI-emitted Tombstone must be refused");
        assert!(err.contains("Tombstone"));

        // Legal transitions stay green.
        validate_space_container_lifecycle_transition(
            "cx:space:test",
            SpaceContainerLifecycleState::Active,
            SpaceContainerLifecycleState::Archived,
        )
        .expect("Active→Archived is a legal transition");
        validate_space_container_lifecycle_transition(
            "cx:space:test",
            SpaceContainerLifecycleState::Archived,
            SpaceContainerLifecycleState::Active,
        )
        .expect("Archived→Active is a legal transition");
    }

    /// Symmetric to `validate_space_container_lifecycle_transition_rules` at the
    /// Flow layer. Same two refusal cases, same two legal transitions.
    #[test]
    fn validate_flow_lifecycle_transition_rules() {
        let err = validate_flow_lifecycle_transition(
            "cx:flow:test",
            FlowLifecycleState::Active,
            FlowLifecycleState::Active,
        )
        .expect_err("same-state Active→Active must be refused");
        assert!(err.contains("already in"));
        assert!(err.contains("cx:flow:test"));

        validate_flow_lifecycle_transition(
            "cx:flow:test",
            FlowLifecycleState::Archived,
            FlowLifecycleState::Archived,
        )
        .expect_err("same-state Archived→Archived must be refused");

        let err = validate_flow_lifecycle_transition(
            "cx:flow:test",
            FlowLifecycleState::Active,
            FlowLifecycleState::Tombstoned,
        )
        .expect_err("UI-emitted Tombstone must be refused");
        assert!(err.contains("Tombstone"));

        validate_flow_lifecycle_transition(
            "cx:flow:test",
            FlowLifecycleState::Active,
            FlowLifecycleState::Archived,
        )
        .expect("Active→Archived is a legal transition");
        validate_flow_lifecycle_transition(
            "cx:flow:test",
            FlowLifecycleState::Archived,
            FlowLifecycleState::Active,
        )
        .expect("Archived→Active is a legal transition");
    }

    /// Symmetric to `space_container_lifecycle_state_default_is_active` —
    /// FlowLifecycleState MUST default to Active and every seeded card
    /// MUST start Active so the demo board exercises the happy path.
    #[test]
    fn flow_lifecycle_state_default_is_active() {
        assert_eq!(FlowLifecycleState::default(), FlowLifecycleState::Active);
        for column in seed_columns() {
            for card in &column.cards {
                assert_eq!(
                    card.lifecycle,
                    FlowLifecycleState::Active,
                    "seed card {} in column {} must start Active",
                    card.id,
                    column.id
                );
            }
        }
    }

    #[test]
    fn card_detail_deep_link_targets_kanban_task_route() {
        assert_eq!(
            flow_detail_deep_link_path("cx:space:ops", "cx:flow:abc"),
            "/kanban/cx:space:ops/task/cx:flow:abc"
        );
        assert_eq!(
            flow_detail_deep_link_path("", "cx:flow:abc"),
            format!("/kanban/{DEMO_BOARD_SPACE_ID}/task/cx:flow:abc")
        );
    }

    #[test]
    fn route_card_flow_id_reads_task_segment_only() {
        assert_eq!(
            route_card_flow_id(&Route::KanbanTask {
                space_id: "cx:space:ops".to_owned(),
                task_id: "cx:flow:abc".to_owned(),
            }),
            Some("cx:flow:abc".to_owned())
        );
        assert_eq!(
            route_card_flow_id(&Route::KanbanBoardTask {
                space_id: "cx:space:ops".to_owned(),
                board_id: "cx:space:board".to_owned(),
                task_id: "cx:flow:abc".to_owned(),
            }),
            Some("cx:flow:abc".to_owned())
        );
        assert_eq!(route_card_flow_id(&Route::Kanban), None);
    }

    #[test]
    fn route_board_id_reads_board_segment_only() {
        assert_eq!(
            route_board_id(&Route::KanbanBoard {
                space_id: "cx:realm:ops".to_owned(),
                board_id: "cx:space:board".to_owned(),
            }),
            Some("cx:space:board".to_owned())
        );
        assert_eq!(
            route_board_id(&Route::KanbanBoardTask {
                space_id: "cx:realm:ops".to_owned(),
                board_id: "cx:space:board".to_owned(),
                task_id: "cx:flow:abc".to_owned(),
            }),
            Some("cx:space:board".to_owned())
        );
        // The board-less routes carry no board id — it is resolved from
        // the projection on arrival.
        assert_eq!(
            route_board_id(&Route::KanbanTask {
                space_id: "cx:realm:ops".to_owned(),
                task_id: "cx:flow:abc".to_owned(),
            }),
            None
        );
        assert_eq!(
            route_board_id(&Route::KanbanSpace {
                space_id: "cx:realm:ops".to_owned(),
            }),
            None
        );
    }

    #[test]
    fn kanban_board_route_carries_board_or_falls_back() {
        assert_eq!(
            kanban_board_route("cx:realm:ops", "cx:space:board"),
            Route::KanbanBoard {
                space_id: "cx:realm:ops".to_owned(),
                board_id: "cx:space:board".to_owned(),
            }
        );
        assert_eq!(
            kanban_board_route("cx:realm:ops", ""),
            Route::KanbanSpace {
                space_id: "cx:realm:ops".to_owned(),
            }
        );
    }

    #[test]
    fn kanban_card_task_route_carries_board_or_falls_back() {
        assert_eq!(
            kanban_card_task_route("cx:realm:ops", "cx:space:board", "cx:flow:abc"),
            Route::KanbanBoardTask {
                space_id: "cx:realm:ops".to_owned(),
                board_id: "cx:space:board".to_owned(),
                task_id: "cx:flow:abc".to_owned(),
            }
        );
        assert_eq!(
            kanban_card_task_route("cx:realm:ops", "", "cx:flow:abc"),
            Route::KanbanTask {
                space_id: "cx:realm:ops".to_owned(),
                task_id: "cx:flow:abc".to_owned(),
            }
        );
    }

    #[test]
    fn find_card_by_flow_id_matches_card_or_primary_flow() {
        let columns = seed_columns();
        assert_eq!(
            find_card_by_flow_id(&columns, "cx:flow:legal-review").map(|card| card.title),
            Some("Legal review for public beta".to_owned())
        );
        assert_eq!(
            find_card_by_flow_id(&columns, "cx:flow:review-discussion").map(|card| card.id),
            Some("cx:flow:legal-review".to_owned())
        );
    }

    #[test]
    fn card_description_collapse_threshold_handles_long_text_and_many_lines() {
        assert!(!card_description_should_collapse("Short card summary."));
        assert!(card_description_should_collapse(
            &"x".repeat(CARD_DESCRIPTION_COLLAPSE_CHAR_THRESHOLD + 1)
        ));
        assert!(card_description_should_collapse(
            "one\ntwo\nthree\nfour\nfive\nsix\nseven"
        ));
    }

    #[test]
    fn flow_body_display_text_reads_content_block_body() {
        let body = json!({
            "kind": "cx.content.text",
            "body": "Long-form flow body"
        });

        assert_eq!(flow_body_display_text(Some(&body)), "Long-form flow body");
    }

    #[test]
    fn flow_body_display_text_reads_nested_blocks() {
        let body = json!({
            "blocks": [
                { "kind": "cx.content.text", "body": "First block" },
                { "kind": "cx.content.text", "text": "Second block" }
            ]
        });

        assert_eq!(
            flow_body_display_text(Some(&body)),
            "First block\nSecond block"
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
            CollectionProjectionResBody, ViewId, ViewKind, ViewRenderer,
        };
        let projection = CollectionProjectionResBody {
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
                            "body": {
                                "kind": "cx.content.text",
                                "body": "Review processor wording before beta."
                            },
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
        assert_eq!(card.body, "Review processor wording before beta.");
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
    fn board_space_options_pick_board_spaces_from_projection() {
        let options = board_space_options_from_projection(&[
            crate::api::SpaceContainerProjectionView {
                container_space_id: "cx:space:0196419b-0000-7000-8000-000000000001".to_owned(),
                realm_id: "cx:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
                kind: "board".to_owned(),
                title: "Release".to_owned(),
                state: "active".to_owned(),
                rank: None,
                parent_space_id: None,
            },
            crate::api::SpaceContainerProjectionView {
                container_space_id: "cx:space:0196419b-0000-7000-8000-000000000002".to_owned(),
                realm_id: "cx:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
                kind: "list".to_owned(),
                title: "Todo".to_owned(),
                state: "active".to_owned(),
                rank: Some("U".to_owned()),
                parent_space_id: Some("cx:space:0196419b-0000-7000-8000-000000000001".to_owned()),
            },
        ]);

        assert_eq!(options.len(), 1);
        assert_eq!(
            options[0].id,
            "cx:space:0196419b-0000-7000-8000-000000000001"
        );
        assert_eq!(options[0].title, "Release");
    }

    #[test]
    fn lifecycle_projection_builds_persisted_board_columns_and_cards() {
        let board_id = "cx:space:0196419b-0000-7000-8000-000000000001";
        let list_id = "cx:space:0196419b-0000-7000-8000-000000000002";
        let containers = vec![
            crate::api::SpaceContainerProjectionView {
                container_space_id: board_id.to_owned(),
                realm_id: "cx:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
                kind: "board".to_owned(),
                title: "Release".to_owned(),
                state: "active".to_owned(),
                rank: None,
                parent_space_id: None,
            },
            crate::api::SpaceContainerProjectionView {
                container_space_id: list_id.to_owned(),
                realm_id: "cx:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
                kind: "list".to_owned(),
                title: "Todo".to_owned(),
                state: "active".to_owned(),
                rank: Some("U".to_owned()),
                parent_space_id: Some(board_id.to_owned()),
            },
        ];
        let flows = vec![crate::api::FlowProjectionView {
            flow_id: "cx:flow:0196419b-0000-7000-8000-000000000003".to_owned(),
            space_id: "cx:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
            title: "Persisted card".to_owned(),
            summary: Some("Loaded from projection".to_owned()),
            body: Some(json!({
                "kind": "cx.content.text",
                "body": "Projection body content"
            })),
            board_space_id: Some(board_id.to_owned()),
            list_space_id: Some(list_id.to_owned()),
            rank: Some("U".to_owned()),
            fields: Map::from_iter([
                ("labels".to_owned(), json!(["demo", "db"])),
                ("assignee".to_owned(), json!("Alice")),
                ("due_at".to_owned(), json!("2026-05-22")),
            ]),
            state: "active".to_owned(),
        }];

        let (columns, options, selected_board) =
            columns_from_lifecycle_projection(&containers, &flows, "");

        assert_eq!(selected_board.as_deref(), Some(board_id));
        assert_eq!(options.len(), 1);
        assert_eq!(columns.len(), 1);
        assert_eq!(columns[0].title, "Todo");
        assert_eq!(columns[0].cards.len(), 1);
        let card = &columns[0].cards[0];
        assert_eq!(card.title, "Persisted card");
        assert_eq!(card.description, "Loaded from projection");
        assert_eq!(card.body, "Projection body content");
        assert_eq!(card.labels, vec!["demo".to_owned(), "db".to_owned()]);
        assert_eq!(card.assignee, "Alice");
        assert_eq!(card.due, "2026-05-22");
    }

    #[test]
    fn local_flow_create_overlay_restores_card_until_projection_catches_up() {
        let board_id = "cx:space:0196419b-0000-7000-8000-000000000001";
        let list_id = "cx:space:0196419b-0000-7000-8000-000000000002";
        let flow_id = "cx:flow:0196419b-0000-7000-8000-000000000003";
        let raw_operations = vec![RawOperationRecord {
            operation_id: "sha256:local-create".to_owned(),
            space_id: Some("cx:realm:0196419b-0000-7000-8000-000000000000".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "cx.flow.create",
                "operation_id": "sha256:local-create",
                "effect": {
                    "flow_id": flow_id,
                    "board_space_id": board_id,
                    "list_space_id": list_id,
                    "title": "Refresh-surviving card",
                    "rank": "U",
                    "flow_kind": "card"
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
        assert_eq!(overlaid[0].cards[0].id, flow_id);
        assert_eq!(overlaid[0].cards[0].title, "Refresh-surviving card");
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
            .push(test_card(flow_id, "U"));
        let de_duped = overlay_local_card_create_records(
            projected_with_server_card,
            &raw_operations,
            board_id,
        );
        assert_eq!(
            de_duped[0].cards.len(),
            1,
            "server projection wins once the reducer has materialized the card"
        );
        assert_eq!(de_duped[0].cards[0].state, CardState::Synced);
    }

    #[test]
    fn kanban_seed_fallback_requires_explicit_opt_in() {
        assert!(!kanban_seed_fallback_allowed_for_url("https://local.host"));
        assert!(!kanban_seed_fallback_allowed_for_url(
            "http://127.0.0.1:8787"
        ));
        assert!(!kanban_seed_fallback_allowed_for_url(
            "https://contrix.example"
        ));
        assert!(truthy_env_value(Some("1")));
        assert!(truthy_env_value(Some("true")));
        assert!(!truthy_env_value(Some("0")));
        assert!(!truthy_env_value(None));
    }

    #[test]
    fn parse_card_labels_trims_and_deduplicates() {
        assert_eq!(
            parse_card_labels(" release, ops, release, ,OPS "),
            vec!["release".to_owned(), "ops".to_owned()]
        );
    }

    #[test]
    fn card_detail_update_patch_uses_flow_update_patch_paths() {
        let mut current = test_card("cx:flow:f1", "U");
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
        };

        let patch = card_detail_update_patch(&current, &draft).unwrap();
        assert_eq!(patch["title"]["value"], "Launch checklist");
        assert_eq!(patch["summary"]["value"], "Ship blockers only");
        assert_eq!(patch["fields"]["value"]["labels"][0], "release");
        assert_eq!(
            patch["fields"]["value"]["assignee"],
            "did:web:alice.example"
        );
        assert_eq!(patch["fields"]["value"]["due_at"], "2026-05-20");
        assert!(patch["fields"]["value"].get("due").is_none());
    }

    #[test]
    fn local_card_update_overlay_replays_queued_summary_and_body_on_top_of_projection() {
        // Simulate: server projection returns the pre-edit card; the user
        // had queued a cx.flow.update locally that bumped summary + body.
        // After page refresh, the overlay must re-apply that patch so the
        // user doesn't see their edits silently disappear.
        let mut card = test_card("cx:flow:edit-me", "U");
        card.title = "old title".to_owned();
        card.description = "old summary".to_owned();
        card.body = "old body".to_owned();
        card.synthesis = "old synthesis".to_owned();
        let columns = vec![KanbanColumn {
            id: "cx:space:list-a".to_owned(),
            title: "A".to_owned(),
            rank: "U".to_owned(),
            cards: vec![card],
            state: SpaceContainerLifecycleState::Active,
        }];
        let queued = RawOperationRecord {
            operation_id: "op-1".to_owned(),
            space_id: Some("cx:realm:r1".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "cx.flow.update",
                "operation_id": "op-1",
                "write_state": "queued",
                "body": {
                    "flow_id": "cx:flow:edit-me",
                    "patch": {
                        "title": { "$op": "set", "value": "new title" },
                        "summary": { "$op": "set", "value": "new summary" },
                        "body": { "$op": "set", "value": "new body" },
                        "synthesis": { "$op": "set", "value": "new synthesis" },
                    },
                },
            }),
        };
        let overlaid = overlay_local_card_update_records(columns, &[queued]);
        let card = &overlaid[0].cards[0];
        assert_eq!(card.title, "new title");
        assert_eq!(card.description, "new summary");
        assert_eq!(card.body, "new body");
        assert_eq!(card.synthesis, "new synthesis");
        assert_eq!(card.state, CardState::Queued);
    }

    #[test]
    fn flow_participant_dids_filters_by_target_flow_and_pulls_unique_actors() {
        let ops = vec![
            RawOperationRecord {
                operation_id: "op-a".to_owned(),
                space_id: Some("cx:realm:r1".to_owned()),
                received_at: chrono::Utc::now(),
                payload: json!({
                    "kind": "cx.flow.update",
                    "body": {
                        "flow_id": "cx:flow:target",
                        "actor_id": "did:web:alice.example",
                    },
                }),
            },
            // Same flow, different actor — both should appear.
            RawOperationRecord {
                operation_id: "op-b".to_owned(),
                space_id: Some("cx:realm:r1".to_owned()),
                received_at: chrono::Utc::now(),
                payload: json!({
                    "kind": "cx.message.create",
                    "body": {
                        "target_ref": "cx:flow:target",
                        "sender": "did:web:bob.example",
                    },
                }),
            },
            // Different flow — must be excluded so we don't bleed
            // unrelated realm actors into the per-card participant list.
            RawOperationRecord {
                operation_id: "op-c".to_owned(),
                space_id: Some("cx:realm:r1".to_owned()),
                received_at: chrono::Utc::now(),
                payload: json!({
                    "kind": "cx.flow.update",
                    "body": {
                        "flow_id": "cx:flow:other",
                        "actor_id": "did:web:carol.example",
                    },
                }),
            },
        ];
        let dids = flow_participant_dids(&ops, "cx:flow:target");
        assert_eq!(
            dids,
            vec![
                "did:web:alice.example".to_owned(),
                "did:web:bob.example".to_owned(),
            ]
        );
        assert!(flow_participant_dids(&ops, "").is_empty());
    }

    #[test]
    fn card_detail_update_patch_emits_body_set_and_unset_ops() {
        let mut current = test_card("cx:flow:f1", "U");
        current.title = "Keep".to_owned();
        current.body = "old long-form body".to_owned();
        let mut draft = card_detail_draft_from_card(&current);
        draft.body = "new long-form body".to_owned();
        let patch = card_detail_update_patch(&current, &draft).unwrap();
        assert_eq!(patch["body"]["$op"], "set");
        assert_eq!(patch["body"]["value"], "new long-form body");

        let mut draft_clear = card_detail_draft_from_card(&current);
        draft_clear.body = String::new();
        let patch = card_detail_update_patch(&current, &draft_clear).unwrap();
        assert_eq!(patch["body"]["$op"], "unset");
    }

    #[test]
    fn card_detail_update_patch_unsets_empty_optional_fields() {
        let mut current = test_card("cx:flow:f1", "U");
        current.title = "Keep".to_owned();
        current.description = "old summary".to_owned();
        current.assignee = "did:web:bob.example".to_owned();
        current.due = "2026-05-19".to_owned();
        let draft = CardDetailDraft {
            title: "Keep".to_owned(),
            description: String::new(),
            body: String::new(),
            synthesis: String::new(),
            labels: Vec::new(),
            assignee: String::new(),
            due: String::new(),
        };

        let patch = card_detail_update_patch(&current, &draft).unwrap();
        assert_eq!(patch["summary"]["$op"], "unset");
        assert!(patch["fields"]["value"].get("assignee").is_none());
        assert!(patch["fields"]["value"].get("due_at").is_none());
    }

    #[test]
    fn apply_card_detail_draft_marks_card_queued() {
        let mut card = test_card("cx:flow:f1", "U");
        let draft = CardDetailDraft {
            title: "New title".to_owned(),
            description: "New summary".to_owned(),
            body: "Body content".to_owned(),
            synthesis: "Synthesis content".to_owned(),
            labels: vec!["ops".to_owned()],
            assignee: String::new(),
            due: "2026-05-20".to_owned(),
        };

        apply_card_detail_draft(&mut card, &draft);
        assert_eq!(card.title, "New title");
        assert_eq!(card.description, "New summary");
        assert_eq!(card.body, "Body content");
        assert_eq!(card.synthesis, "Synthesis content");
        assert_eq!(card.labels, vec!["ops".to_owned()]);
        assert_eq!(card.assignee, "—");
        assert_eq!(card.due, "2026-05-20");
        assert_eq!(card.state, CardState::Queued);
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
                id: "cx:space:list-a".to_owned(),
                title: "A".to_owned(),
                rank: "U".to_owned(),
                cards: vec![test_card("cx:flow:a1", "U"), test_card("cx:flow:a2", "f")],
                state: SpaceContainerLifecycleState::Active,
            },
            KanbanColumn {
                id: "cx:space:list-b".to_owned(),
                title: "B".to_owned(),
                rank: "f".to_owned(),
                cards: vec![test_card("cx:flow:b1", "U"), test_card("cx:flow:b3", "z")],
                state: SpaceContainerLifecycleState::Active,
            },
        ];
        // Move a1 from A → B, dropped at rank "m" (between b1=U and b3=z).
        let moved = relocate_card(
            &mut cols,
            "cx:flow:a1",
            "cx:space:list-a",
            "cx:space:list-b",
            "m",
        )
        .unwrap();
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
            id: "cx:space:list-a".to_owned(),
            title: "A".to_owned(),
            rank: "U".to_owned(),
            cards: vec![
                test_card("cx:flow:a1", "U"),
                test_card("cx:flow:a2", "f"),
                test_card("cx:flow:a3", "p"),
            ],
            state: SpaceContainerLifecycleState::Active,
        }];
        // Move a3 to the top of the same list (rank "0" — before "U").
        let moved = relocate_card(
            &mut cols,
            "cx:flow:a3",
            "cx:space:list-a",
            "cx:space:list-a",
            "0",
        )
        .unwrap();
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
    /// position, return `At { list_space_id, rank }`; absent ⇒ `Initial`.
    #[test]
    fn locate_flow_position_finds_present_flow_with_rank() {
        use contrix_sdk::{
            CollectionProjectionGroup, CollectionProjectionItem, CollectionProjectionPosition,
            CollectionProjectionResBody, ViewId, ViewKind, ViewRenderer,
        };
        let projection = CollectionProjectionResBody {
            kind: ViewKind::Collection,
            renderer: ViewRenderer::Board,
            view_id: ViewId::new("cx:view:01904100-0000-7000-8000-000000000001").unwrap(),
            frontier: Vec::new(),
            groups: vec![CollectionProjectionGroup {
                group_id: "cx:space:01list-review".to_owned(),
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
                list_space_id: "cx:space:01list-review".to_owned(),
                rank: "h3".to_owned(),
            }
        );
    }

    /// When the flow isn't in the projection, the rebase must use
    /// `head_eq null` (Initial) — soland's reducer rejects if the cell
    /// is actually non-initial, which is the safe behaviour.
    #[test]
    fn locate_flow_position_missing_flow_returns_initial() {
        use contrix_sdk::{CollectionProjectionResBody, ViewId, ViewKind, ViewRenderer};
        let projection = CollectionProjectionResBody {
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
            body: String::new(),
            synthesis: String::new(),
            labels: Vec::new(),
            assignee: String::new(),
            due: String::new(),
            primary_flow_id: String::new(),
            locked_flow: None,
            external_visibility: String::new(),
            history_visibility: String::new(),
            activity_hint: String::new(),
            audit_hint: String::new(),
            state: CardState::Synced,
            lifecycle: FlowLifecycleState::Active,
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
