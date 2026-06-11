use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use chrono::{Datelike, Duration, NaiveDate};
use dioxus::prelude::*;
use dioxus_router::hooks::{use_navigator, use_route};
use serde_json::{Map, Value, json};

use crate::components::{
    EmptyState, EmptyStateKind, SecurityStateBadge, UiIcon, WriteState, WriteStateIcon,
};
use crate::hlc::Hlc;
use crate::local_state::{
    LocalAnchorView, LocalStateStore, MoveSubmissionState, RawOperationRecord,
};
use crate::move_builder::{FlowPositionEffect, FlowPositionExpectation, flow_position_cell_id};
use crate::operation::{trim_realm_id, uuid_v7};
use crate::rank::{RankError, rank_for_drop};
use crate::routes::Route;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::select::{Select, SelectOption};
use crate::ui::textarea::Textarea;
use crate::views::helpers::{
    display_name_for_did, handle_display_from_did, short_protocol_id, with_authed_api,
};

mod dnd;
/// Board Space id used only when the explicit demo seed fallback is
/// enabled. Normal kanban routes render server projections instead of
/// hard-coded cards.
mod model;

use dnd::*;
use model::*;

#[component]
fn CardMarkdownEditor(
    value: String,
    base_url: String,
    token: String,
    realm_id: String,
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
        let realm_id = realm_id.clone();
        move || {
            if let Some(script) = toast_editor_bootstrap_script(
                &host_id,
                &fallback_id,
                &value,
                &base_url,
                &token,
                &realm_id,
            ) {
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
            Textarea {
                id: "{fallback_id}",
                class: "textarea card-rich-editor-fallback",
                "data-testid": "card-detail-description-input",
                value: "{value}",
                maxlength: "8192",
                oninput: move |event: FormEvent| on_change.call(event.value()),
            }
        }
    }
}

#[component]
fn CardDetailEditActions(
    status: String,
    on_save: EventHandler<()>,
    on_cancel: EventHandler<()>,
) -> Element {
    rsx! {
        if !status.trim().is_empty() {
            div {
                class: "card-detail-edit-status",
                "data-testid": "card-detail-edit-status",
                role: "status",
                "aria-live": "polite",
                "{status}"
            }
        }
        div { class: "card-detail-form-actions",
            Button {
                variant: ButtonVariant::Primary,
                r#type: "button",
                "data-testid": "card-detail-save-button",
                onclick: move |_| on_save.call(()),
                {crate::i18n::tr("common.save")}
            }
            Button {
                variant: ButtonVariant::Secondary,
                r#type: "button",
                "data-testid": "card-detail-cancel-edit-button",
                onclick: move |_| on_cancel.call(()),
                {crate::i18n::tr("common.cancel")}
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
    realm_id: &str,
) -> Option<String> {
    let config = serde_json::to_string(&json!({
        "hostId": host_id,
        "fallbackId": fallback_id,
        "value": value,
        "baseUrl": base_url,
        "token": token,
        "realmId": realm_id,
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
        const event = typeof InputEvent === "function"
            ? new InputEvent("input", {{
                bubbles: true,
                inputType: "insertText",
                data: null
            }})
            : new Event("input", {{ bubbles: true }});
        fallback.dispatchEvent(event);
    }};

    const uploadImage = async (blob, callback) => {{
        try {{
            const base = (config.baseUrl || window.location.origin).replace(/\/+$/, "");
            const headers = {{}};
            if (config.token) {{
                headers.authorization = `Bearer ${{config.token}}`;
            }}
            const safeName = (blob.name || "")
                .split(/[\\/]/)
                .pop()
                .replace(/[^A-Za-z0-9._-]+/g, "_")
                .replace(/^[._-]+|[._-]+$/g, "")
                .slice(0, 128);
            // YOU-01-007: spec blob_upload_request_body is
            // multipart/form-data — content + size_bytes (+ optional
            // realm_id / media_type / filename). The browser sets the
            // multipart boundary content-type itself.
            const mediaType = blob.type || "application/octet-stream";
            const form = new FormData();
            form.append("content", blob, safeName || "upload.bin");
            form.append("size_bytes", String(blob.size));
            form.append("media_type", mediaType);
            if (config.realmId) {{
                form.append("realm_id", config.realmId);
            }}
            if (safeName) {{
                form.append("filename", safeName);
            }}
            const response = await fetch(`${{base}}/_cokret/self/blob/upload`, {{
                method: "POST",
                headers,
                body: form
            }});
            if (!response.ok) {{
                throw new Error(`upload failed: ${{response.status}}`);
            }}
            const body = await response.json();
            const blobRef = body.blob_ref || body.blobRef || body.blob_id;
            if (!blobRef) {{
                throw new Error("upload response missing blob_ref");
            }}
            const markdownMediaType = blob.type || body.media_type || "image/png";
            const markdownTarget = blobRef.includes("#") ? blobRef : `${{blobRef}}#${{markdownMediaType}}`;
            callback(markdownTarget, blob.name || "image");
        }} catch (error) {{
            console.warn("[yougen] image upload failed", error);
            window.alert("Image upload failed.");
        }}
        return false;
    }};

    const editor = new window.toastui.Editor({{
        el: host,
        height: "240px",
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

#[component]
fn WriteStateBadge(state: CardState, icon_only: Option<bool>) -> Element {
    let icon_only = icon_only.unwrap_or(false);
    let class_name = if icon_only {
        format!("{} write-state-badge is-icon-only", state.class_name())
    } else {
        format!("{} write-state-badge", state.class_name())
    };
    let data_state = state.data_state();
    let title = format!("{} - {}", state.label(), state.status_title());
    let write_state = state.write_state();
    rsx! {
        span {
            class: "{class_name}",
            "data-testid": "write-state-badge",
            "data-write-state": "{data_state}",
            title: "{title}",
            WriteStateIcon { state: write_state }
            span { class: "write-state-label", "{state.label()}" }
        }
    }
}

#[component]
pub fn KanbanPanel(
    base_url: String,
    plaintext_service_did: String,
    token: Signal<String>,
    account_did: String,
    device_id: String,
    selected_realm_id: String,
    projection_realm_id: String,
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
    let local_realm_id = local_projection_realm_id(&selected_realm_id, &projection_realm_id);
    // The board id lives in the URL (`/kanban/<realm>/board/<board>` and
    // its `/task/<flow>` extension). Seeding `selected_board_space_id`
    // from the route — instead of always `board_options.first()` — is
    // what makes a refresh restore the exact board the user had open,
    // including when the open card is a local draft the server
    // projection does not know about yet.
    let routed_board_id = route_board_id(&route);
    let initial_board_options = {
        let seed_options = initial_board_space_options(seed_fallback_allowed);
        let state = state_store.read().load();
        overlay_local_board_space_options(seed_options, &state.raw_operations, &local_realm_id)
    };
    let initial_board_space_id = routed_board_id.clone().unwrap_or_else(|| {
        initial_board_options
            .first()
            .map(|option| option.id.clone())
            .unwrap_or_default()
    });
    let initial_columns = {
        let state = state_store.read().load();
        let initial_columns =
            if initial_columns.is_empty() && !initial_board_space_id.trim().is_empty() {
                // Empty server projections here (local raw-op overlay
                // only): no encrypted flow cards are produced, so no
                // decrypt context is required.
                let (local_columns, ..) = columns_from_lifecycle_projection_with_local(
                    &[],
                    &[],
                    &initial_board_space_id,
                    &state.raw_operations,
                    &local_realm_id,
                    None,
                );
                local_columns
            } else {
                initial_columns
            };
        let initial_columns = overlay_local_card_create_records(
            initial_columns,
            &state.raw_operations,
            &initial_board_space_id,
        );
        let initial_columns =
            overlay_local_card_update_records(initial_columns, &state.raw_operations, None);
        overlay_local_card_assignment_records(initial_columns, &state.raw_operations)
    };
    let mut columns = use_signal(|| initial_columns);
    let mut board_space_options = use_signal(move || initial_board_options.clone());
    let mut selected_board_space_id = use_signal(move || initial_board_space_id.clone());
    let selected_board_space_id_selected = use_memo(move || Some(selected_board_space_id()));
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
    let mut card_detail_tab = use_signal(card_detail_tab_from_current_url);
    let mut card_detail_discussion_mounted_for = use_signal(|| Option::<String>::None);
    let mut card_detail_sidebar_tab = use_signal(CardDetailSidebarTab::default);
    let mut card_detail_overlay_press_started = use_signal(|| false);
    let mut card_detail_overlay_press_ended = use_signal(|| false);
    let mut card_detail_docked = use_signal(read_card_detail_docked);
    let mut card_detail_dock_width = use_signal(read_card_detail_dock_width);
    let mut card_detail_resizing = use_signal(|| false);
    let mut card_detail_resize_start_x = use_signal(|| 0.0_f64);
    let mut card_detail_resize_start_width = use_signal(|| 0.0_f64);
    let mut member_handle_fetching = use_signal(BTreeSet::<String>::new);
    let mut card_edit_title = use_signal(String::new);
    let mut card_edit_description = use_signal(String::new);
    let mut card_edit_body = use_signal(String::new);
    let mut card_edit_synthesis = use_signal(String::new);
    let mut card_edit_synthesis_target_id = use_signal(|| Option::<String>::None);
    let mut card_detail_edit_status = use_signal(String::new);
    let mut assignee_picker_open = use_signal(|| false);
    let mut assignee_filter = use_signal(String::new);
    let mut assignee_selected_actor_ids = use_signal(BTreeSet::<String>::new);
    let mut assignee_edit_status = use_signal(String::new);
    let mut due_picker_open = use_signal(|| false);
    let mut due_edit_value = use_signal(String::new);
    let mut due_calendar_month = use_signal(default_due_calendar_month);
    let mut due_edit_status = use_signal(String::new);
    let mut card_synthesis_history_open_id = use_signal(|| Option::<String>::None);
    let mut card_synthesis_selected_revision_id = use_signal(|| Option::<String>::None);
    let mut card_edit_labels = use_signal(String::new);
    let mut card_edit_assignee = use_signal(String::new);
    let mut card_edit_due = use_signal(String::new);
    let mut dragging_card = use_signal(|| Option::<DraggedCard>::None);
    let mut dragging_column = use_signal(|| Option::<DraggedColumn>::None);
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
    let selected_board_space_id_value = selected_board_space_id();
    let selected_board_space_id_label = short_protocol_id(&selected_board_space_id_value);
    let board_view_id_value = board_view_id();
    let board_view_id_label = short_protocol_id(&board_view_id_value);
    let board_select_label = format!("{}:", crate::i18n::tr("kanban.board_header"));
    let selected_board_title = if selected_board_space_id_value.trim().is_empty() {
        "Select board".to_owned()
    } else {
        board_space_options()
            .iter()
            .find(|option| option.id == selected_board_space_id_value)
            .map(|option| option.title.clone())
            .unwrap_or_else(|| short_protocol_id(&selected_board_space_id_value))
    };

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
                card_edit_synthesis_target_id.set(None);
                card_edit_labels.set(draft.labels.join(", "));
                card_edit_assignee.set(draft.assignee);
                card_edit_due.set(draft.due);
                editing_card_detail.set(false);
                card_detail_edit_status.set(String::new());
                assignee_picker_open.set(false);
                assignee_filter.set(String::new());
                assignee_selected_actor_ids
                    .set(card_assigned_actor_ids(&card).into_iter().collect());
                assignee_edit_status.set(String::new());
                due_picker_open.set(false);
                due_edit_value.set(editor_value_for_optional_card_field(&card.due));
                due_calendar_month.set(due_calendar_month_for_value(&card.due));
                due_edit_status.set(String::new());
                card_detail_actions_open.set(false);
                let routed_tab = card_detail_tab_from_current_url();
                if routed_tab == CardDetailContentTab::Discussion {
                    card_detail_discussion_mounted_for.set(Some(card.primary_flow_id.clone()));
                }
                card_detail_tab.set(routed_tab);
                card_synthesis_history_open_id.set(None);
                card_synthesis_selected_revision_id.set(None);
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
        let route_local_realm_id = local_realm_id.clone();
        let decrypt_realm_id = selected_realm_id.clone();
        let decrypt_actor = account_did.clone();
        let decrypt_device = device_id.clone();
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
            let raw_operations = state_store.read().load().raw_operations;
            if containers.is_empty() && flows.is_empty() && raw_operations.is_empty() {
                return;
            }
            let decrypt_store = state_store.read();
            let decrypt_ctx = MlsDecryptCtx {
                state_store: &decrypt_store,
                realm_id: &decrypt_realm_id,
                actor_id: &decrypt_actor,
                device_id: &decrypt_device,
            };
            let (projected_columns, options, projected_board_id) =
                columns_from_lifecycle_projection_with_local(
                    &containers,
                    &flows,
                    &board_id,
                    &raw_operations,
                    &route_local_realm_id,
                    Some(&decrypt_ctx),
                );
            if projected_board_id.as_deref() == Some(board_id.as_str()) {
                if !options.is_empty() {
                    board_space_options.set(options);
                }
                let projected_columns = overlay_local_card_creates_with_decrypt(
                    projected_columns,
                    &decrypt_store,
                    &board_id,
                    Some(&decrypt_ctx),
                );
                drop(decrypt_store);
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
        let route_local_realm_id = local_realm_id.clone();
        let decrypt_realm_id = selected_realm_id.clone();
        let decrypt_actor = account_did.clone();
        let decrypt_device = device_id.clone();
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
            let raw_operations = state_store.read().load().raw_operations;
            let decrypt_store = state_store.read();
            let decrypt_ctx = MlsDecryptCtx {
                state_store: &decrypt_store,
                realm_id: &decrypt_realm_id,
                actor_id: &decrypt_actor,
                device_id: &decrypt_device,
            };
            let (projected_columns, options, projected_board_id) =
                columns_from_lifecycle_projection_with_local(
                    &containers,
                    &flows,
                    &flow_board,
                    &raw_operations,
                    &route_local_realm_id,
                    Some(&decrypt_ctx),
                );
            if let Some(board_id) = projected_board_id {
                if !options.is_empty() {
                    board_space_options.set(options);
                }
                let board_id_for_overlay = board_id.clone();
                selected_board_space_id.set(board_id);
                let projected_columns = overlay_local_card_creates_with_decrypt(
                    projected_columns,
                    &decrypt_store,
                    &board_id_for_overlay,
                    Some(&decrypt_ctx),
                );
                drop(decrypt_store);
                if columns() != projected_columns {
                    columns.set(projected_columns);
                }
            }
        });
    }

    // T20 — auto-refresh-on-mount. The component renders empty or explicit
    // SeedFallback synchronously, then fires an async fetch against soland's
    // `/_cokret/self/views/:id/projection` when a View id is provided. Success
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
    let auto_lifecycle_realm_id = local_realm_id.clone();
    let auto_decrypt_realm_id = selected_realm_id.clone();
    let auto_decrypt_actor = account_did.clone();
    let auto_decrypt_device = device_id.clone();
    use_future(move || {
        let base = auto_base.clone();
        let lifecycle_realm_id = auto_lifecycle_realm_id.clone();
        let decrypt_realm_id = auto_decrypt_realm_id.clone();
        let decrypt_actor = auto_decrypt_actor.clone();
        let decrypt_device = auto_decrypt_device.clone();
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
            let events_res = if lifecycle_realm_id.trim().is_empty() {
                None
            } else {
                let realm_id = lifecycle_realm_id.clone();
                with_authed_api(&base, api_token.clone(), |api| async move {
                    api.backfill(&realm_id).await
                })
                .await
                .ok()
            };
            let remote_update_operations = events_res
                .as_ref()
                .map(|resp| flow_update_operations_from_events(&resp.events))
                .unwrap_or_default();
            match with_authed_api(&base, api_token, |api| async move {
                api.collection_projection(&view).await
            })
            .await
            {
                Ok(projection) => {
                    let cols = {
                        let decrypt_store = state_store.read();
                        let decrypt_ctx = MlsDecryptCtx {
                            state_store: &decrypt_store,
                            realm_id: &decrypt_realm_id,
                            actor_id: &decrypt_actor,
                            device_id: &decrypt_device,
                        };
                        overlay_collection_projection_with_operations(
                            &projection,
                            &decrypt_store,
                            &selected_board_space_id(),
                            &remote_update_operations,
                            Some(&decrypt_ctx),
                        )
                    };
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

    // F-KANBAN-LIVE-1: refresh the board projection only when account
    // subscribe advances. The global SyncEngine owns the liveness channel;
    // this panel must not poll `spaces` / `flows` / `events` on a timer while
    // no durable event has arrived.
    let mut live_refresh_key_seen = use_signal({
        let initial_realm_id = local_realm_id.clone();
        move || {
            let initial_view = board_view_id.peek().clone();
            let initial_cursor = sync_cursor.peek().clone();
            kanban_projection_refresh_key(&initial_realm_id, &initial_view, &initial_cursor)
        }
    });
    let live_base = base_url.clone();
    let live_token = token;
    let live_board_view_id = board_view_id;
    let live_lifecycle_realm_id = local_realm_id.clone();
    let live_lifecycle_local_realm_id = local_realm_id.clone();
    let live_decrypt_realm_id = selected_realm_id.clone();
    let live_decrypt_actor = account_did.clone();
    let live_decrypt_device = device_id.clone();
    use_effect(move || {
        let base = live_base.clone();
        let lifecycle_realm_id = live_lifecycle_realm_id.clone();
        let lifecycle_local_realm_id = live_lifecycle_local_realm_id.clone();
        let decrypt_realm_id = live_decrypt_realm_id.clone();
        let decrypt_actor = live_decrypt_actor.clone();
        let decrypt_device = live_decrypt_device.clone();
        let api_token = live_token();
        let view = live_board_view_id();
        let cursor = sync_cursor();
        let Some(refresh_key) = next_kanban_projection_refresh_key(
            live_refresh_key_seen.peek().as_str(),
            &lifecycle_realm_id,
            &view,
            &cursor,
        ) else {
            return;
        };
        live_refresh_key_seen.set(refresh_key);
        spawn(async move {
            if !view.trim().is_empty() {
                let view_for_call = view.clone();
                let events_res = if lifecycle_realm_id.trim().is_empty() {
                    None
                } else {
                    let realm_id = lifecycle_realm_id.clone();
                    with_authed_api(&base, api_token.clone(), |api| async move {
                        api.backfill(&realm_id).await
                    })
                    .await
                    .ok()
                };
                let remote_update_operations = events_res
                    .as_ref()
                    .map(|resp| flow_update_operations_from_events(&resp.events))
                    .unwrap_or_default();
                if let Ok(projection) = with_authed_api(&base, api_token, |api| async move {
                    api.collection_projection(&view_for_call).await
                })
                .await
                {
                    let cols = {
                        let decrypt_store = state_store.read();
                        let decrypt_ctx = MlsDecryptCtx {
                            state_store: &decrypt_store,
                            realm_id: &decrypt_realm_id,
                            actor_id: &decrypt_actor,
                            device_id: &decrypt_device,
                        };
                        overlay_collection_projection_with_operations(
                            &projection,
                            &decrypt_store,
                            &selected_board_space_id(),
                            &remote_update_operations,
                            Some(&decrypt_ctx),
                        )
                    };
                    // Only overwrite when the server actually returned a
                    // non-empty projection — an empty response shouldn't wipe
                    // a locally-queued optimistic move.
                    if !cols.is_empty() && cols != columns() {
                        columns.set(cols);
                        projection_source.set(BoardProjectionSource::ApiDerived);
                    }
                }
            } else {
                let containers_res = {
                    let realm_id = lifecycle_realm_id.clone();
                    with_authed_api(&base, api_token.clone(), |api| async move {
                        api.list_space_container_projections(&realm_id).await
                    })
                    .await
                };
                let flows_res = {
                    let realm_id = lifecycle_realm_id.clone();
                    with_authed_api(&base, api_token.clone(), |api| async move {
                        api.list_flow_projections(&realm_id).await
                    })
                    .await
                };
                let events_res = {
                    let realm_id = lifecycle_realm_id.clone();
                    with_authed_api(&base, api_token, |api| async move {
                        api.backfill(&realm_id).await
                    })
                    .await
                };
                if containers_res.is_ok() || flows_res.is_ok() {
                    let container_items = containers_res
                        .ok()
                        .map(|resp| resp.items)
                        .unwrap_or_default();
                    let flow_items = flows_res.ok().map(|resp| resp.items).unwrap_or_default();
                    let event_items = events_res.ok().map(|resp| resp.events).unwrap_or_default();
                    let remote_update_operations = flow_update_operations_from_events(&event_items);
                    let remote_space_create_operations =
                        space_create_operations_from_events(&event_items);
                    let container_items = containers_with_local_space_creates(
                        &container_items,
                        &remote_space_create_operations,
                        &lifecycle_local_realm_id,
                    );
                    lifecycle_container_projection.set(container_items.clone());
                    lifecycle_flow_projection.set(flow_items.clone());
                    let current_board = selected_board_space_id();
                    let raw_operations = state_store.read().load().raw_operations;
                    let decrypt_store = state_store.read();
                    let decrypt_ctx = MlsDecryptCtx {
                        state_store: &decrypt_store,
                        realm_id: &decrypt_realm_id,
                        actor_id: &decrypt_actor,
                        device_id: &decrypt_device,
                    };
                    let (projected_columns, options, projected_board_id) =
                        columns_from_lifecycle_projection_with_local(
                            &container_items,
                            &flow_items,
                            &current_board,
                            &raw_operations,
                            &lifecycle_local_realm_id,
                            Some(&decrypt_ctx),
                        );
                    if let Some(board_id) = projected_board_id {
                        if !options.is_empty() && board_space_options() != options {
                            board_space_options.set(options);
                        }
                        if current_board.trim().is_empty() {
                            selected_board_space_id.set(board_id.clone());
                        }
                        let projected_columns = overlay_card_projection_with_operations_and_decrypt(
                            projected_columns,
                            &decrypt_store,
                            &board_id,
                            &remote_update_operations,
                            Some(&decrypt_ctx),
                        );
                        drop(decrypt_store);
                        if columns() != projected_columns {
                            let list_count = projected_columns.len();
                            let card_count = projected_columns
                                .iter()
                                .map(|column| column.cards.len())
                                .sum::<usize>();
                            columns.set(projected_columns.clone());
                            sync_selected_card_from_columns(selected_card, &projected_columns);
                            projection_source.set(BoardProjectionSource::ApiDerived);
                            board_status.set(format!(
                                "Board refreshed: {list_count} list(s), {card_count} card(s)"
                            ));
                        }
                    }
                }
            }
        });
    });

    // Hydrate Space-container / Flow lifecycle state from the soland
    // `/_cokret/self/projection/{spaces|flows}` endpoints so
    // an Archive accepted on the server stays archived after a page
    // refresh. The probe is fire-and-forget; a 404 / 401 just leaves
    // columns/cards in their `Active` default and the user is no worse
    // off than before this wiring.
    let mut lifecycle_bootstrapped_for = use_signal(String::new);
    let lifecycle_realm_id = local_realm_id.clone();
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
        let lifecycle_local_realm_id = local_realm_id.clone();
        let decrypt_realm_id = selected_realm_id.clone();
        let decrypt_actor = account_did.clone();
        let decrypt_device = device_id.clone();
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
                with_authed_api(&base, api_token.clone(), |api| async move {
                    api.list_flow_projections(&realm_id).await
                })
                .await
            };
            let events_res = {
                let realm_id = realm_id.clone();
                with_authed_api(&base, api_token, |api| async move {
                    api.backfill(&realm_id).await
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
                let event_items = events_res.ok().map(|resp| resp.events).unwrap_or_default();
                let remote_update_operations = flow_update_operations_from_events(&event_items);
                let remote_space_create_operations =
                    space_create_operations_from_events(&event_items);
                let container_items = containers_with_local_space_creates(
                    &container_items,
                    &remote_space_create_operations,
                    &lifecycle_local_realm_id,
                );
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
                let raw_operations = state_store.read().load().raw_operations;
                let decrypt_store = state_store.read();
                let decrypt_ctx = MlsDecryptCtx {
                    state_store: &decrypt_store,
                    realm_id: &decrypt_realm_id,
                    actor_id: &decrypt_actor,
                    device_id: &decrypt_device,
                };
                let (projected_columns, options, projected_board_id) =
                    columns_from_lifecycle_projection_with_local(
                        &container_items,
                        &flow_items,
                        &current_board,
                        &raw_operations,
                        &lifecycle_local_realm_id,
                        Some(&decrypt_ctx),
                    );
                if let Some(board_id) = projected_board_id {
                    if !options.is_empty() {
                        board_space_options.set(options);
                    }
                    let board_id_for_overlay = board_id.clone();
                    selected_board_space_id.set(board_id);
                    let projected_columns = overlay_card_projection_with_operations_and_decrypt(
                        projected_columns,
                        &decrypt_store,
                        &board_id_for_overlay,
                        &remote_update_operations,
                        Some(&decrypt_ctx),
                    );
                    drop(decrypt_store);
                    let list_count = projected_columns.len();
                    let card_count = projected_columns
                        .iter()
                        .map(|column| column.cards.len())
                        .sum::<usize>();
                    if columns() != projected_columns {
                        columns.set(projected_columns.clone());
                        sync_selected_card_from_columns(selected_card, &projected_columns);
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
                        if let Some(col) = cols.iter_mut().find(|c| c.id == view.space_id) {
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

    // R3.2 handle rendering: roster rows may omit inline handle claims for
    // privacy, size, or freshness. When the Members tab is actually open,
    // backfill missing current primary handles through the subject/context
    // reverse lookup and cache the result locally with a short TTL.
    {
        let handle_base_url = base_url.clone();
        let handle_realm_id = selected_realm_id.clone();
        let handle_projection_realm_id = projection_realm_id.clone();
        let handle_token = token;
        use_effect(move || {
            let should_fetch_member_handles = card_detail_sidebar_tab()
                == CardDetailSidebarTab::Members
                || card_detail_tab() == CardDetailContentTab::Synthesis;
            if !should_fetch_member_handles {
                return;
            }
            if selected_card().is_none() {
                return;
            }
            let store_snapshot = state_store.read().load();
            let projection = store_snapshot.realm_tree_projections.get(&handle_realm_id);
            let rows = realm_member_roster(projection);
            if rows.is_empty() {
                return;
            }
            let realm_context = member_roster_realm_context(
                &handle_realm_id,
                &handle_projection_realm_id,
                projection,
            );
            let mut fetches: Vec<(String, String, String, Option<String>)> = Vec::new();
            for row in rows {
                if member_inline_handle_label(&row).is_some() {
                    continue;
                }
                let identity = state_store
                    .read()
                    .resolved_member_identity(&realm_context, &row.actor_id);
                let Some(subject_id) = member_handle_lookup_subject(&row, identity.as_ref()) else {
                    continue;
                };
                let digest = row.member_display_state_digest.clone();
                if state_store
                    .read()
                    .cached_member_handle_lookup(
                        &subject_id,
                        Some(&realm_context),
                        digest.as_deref(),
                    )
                    .is_some()
                {
                    continue;
                }
                let request_key =
                    member_handle_fetch_key(&realm_context, &subject_id, digest.as_deref());
                if member_handle_fetching.read().contains(&request_key) {
                    continue;
                }
                member_handle_fetching.write().insert(request_key.clone());
                fetches.push((request_key, subject_id, realm_context.clone(), digest));
            }

            for (request_key, subject_id, realm_id, digest) in fetches {
                let base = handle_base_url.clone();
                let api_token = handle_token();
                let mut fetching = member_handle_fetching;
                let mut store = state_store;
                spawn(async move {
                    let result = with_authed_api(&base, api_token, {
                        let subject_id = subject_id.clone();
                        let realm_id = realm_id.clone();
                        move |api| async move {
                            api.list_handles_for_subject(
                                &subject_id,
                                Some(&realm_id),
                                Some("display"),
                            )
                            .await
                        }
                    })
                    .await;
                    match result {
                        Ok(res) => {
                            let primary = res
                                .primary_handle
                                .as_ref()
                                .map(|handle| handle.canonical().to_owned());
                            let claims_count = res.claims.len();
                            let earliest_expiry = res
                                .claims
                                .iter()
                                .filter_map(|claim| claim.expires_at.as_ref().cloned())
                                .min();
                            store.write().save_member_handle_lookup(
                                res.subject.as_str().to_owned(),
                                Some(realm_id),
                                digest,
                                primary,
                                claims_count,
                                Some(res.as_of),
                                earliest_expiry,
                            );
                        }
                        Err(err) if !err.is_auth_expired() => {
                            store.write().save_member_handle_lookup(
                                subject_id,
                                Some(realm_id),
                                digest,
                                None,
                                0,
                                None,
                                None,
                            );
                        }
                        Err(_) => {}
                    }
                    fetching.write().remove(&request_key);
                });
            }
        });
    }

    let write_record_count = write_records().len();
    let manual_conflict_review_count = write_records()
        .iter()
        .filter(|record| record.needs_manual_conflict_review())
        .count();
    let board_selected = !selected_board_space_id().trim().is_empty();
    // Pre-wrapped Realm id for building board / card URLs inside event
    // handlers (the raw selected Realm String can't be moved into more
    // than one closure).
    let board_route_realm_id = card_detail_route_realm_id(&selected_realm_id);
    // R4 (fail-closed): three-state security signal. `Some(true/false)` means
    // the Realm security projection IS known (encrypted / plaintext); `None`
    // means the projection is missing / not yet synced. We deliberately drop
    // the old `.unwrap_or(false)` — "unknown" must NOT collapse to "plaintext",
    // otherwise a private field destined for an encrypted Realm could be
    // submitted in plaintext while the projection is still in flight. The
    // plaintext-block guard fails closed on `None`.
    let selected_scope_security_encrypted: Option<bool> = {
        let state = state_store.read().load();
        let scope_id = if projection_realm_id.trim().is_empty() {
            selected_realm_id.as_str()
        } else {
            projection_realm_id.as_str()
        };
        crate::security_state::security_projection_for_scope_id(
            &state.realm_tree_projections,
            scope_id,
        )
        .or_else(|| {
            crate::security_state::security_projection_for_scope_id(
                &state.realm_tree_projections,
                &selected_realm_id,
            )
        })
        .map(crate::security_state::realm_projection_is_encrypted)
    };
    // Fail-closed `bool` projection for the non-guard consumers (security
    // badge display, the per-card encrypt decision): when the Realm security
    // state is unknown we treat it as encrypted so those paths never take the
    // plaintext branch. Known-plaintext (`Some(false)`) stays `false`.
    let selected_scope_security_encrypted_or_secure =
        selected_scope_security_encrypted.unwrap_or(true);
    let projected_space_container_ids = lifecycle_container_projection()
        .into_iter()
        .map(|view| view.space_id)
        .collect::<BTreeSet<_>>();
    let projected_flow_ids = lifecycle_flow_projection()
        .into_iter()
        .map(|view| view.flow_id)
        .collect::<BTreeSet<_>>();
    rsx! {
        div { class: "timeline kanban-panel", "data-testid": "kanban-panel",
            div { class: "event board-header board-toolbar",
                div { class: "board-toolbar-main",
                    div { class: "actions board-toolbar-controls", "data-testid": "board-space-selector",
                        if board_popover() != BoardToolbarPopover::None {
                            div {
                                class: "board-popover-scrim",
                                onclick: move |_| board_popover.set(BoardToolbarPopover::None),
                            }
                        }
                        span { class: "board-select-label", "{board_select_label}" }
                        div {
                            class: if board_popover() == BoardToolbarPopover::SelectBoard { "board-select-menu-host is-open" } else { "board-select-menu-host" },
                            {
                                let board_route_realm_id_for_select = board_route_realm_id.clone();
                                let local_realm_id_for_select = local_realm_id.clone();
                                let account_did_for_select = account_did.clone();
                                let device_id_for_select = device_id.clone();
                                rsx! {
                                    Select::<String> {
                                        class: "board-select-native",
                                        "data-testid": "board-space-select",
                                        value: Some(selected_board_space_id_selected.into()),
                                        on_value_change: move |v: Option<String>| {
                                            if let Some(v) = v {
                                                select_kanban_board(
                                                    v,
                                                    selected_board_space_id,
                                                    board_popover,
                                                    selected_card,
                                                    board_route_realm_id_for_select.clone(),
                                                    local_realm_id_for_select.clone(),
                                                    lifecycle_container_projection,
                                                    lifecycle_flow_projection,
                                                    columns,
                                                    adding_card_to,
                                                    board_status,
                                                    board_space_options,
                                                    projection_source,
                                                    state_store,
                                                    account_did_for_select.clone(),
                                                    device_id_for_select.clone(),
                                                );
                                            }
                                        },
                                        SelectOption::<String> {
                                            index: 0usize,
                                            value: "".to_string(),
                                            text_value: "Select board",
                                            "Select board"
                                        }
                                        for (i, board_option) in board_space_options().iter().enumerate() {
                                            SelectOption::<String> {
                                                index: i + 1,
                                                value: board_option.id.to_string(),
                                                text_value: "{board_option.title}",
                                                "{board_option.title}"
                                            }
                                        }
                                    }
                                }
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                class: "board-select-button",
                                "data-testid": "board-space-select-button",
                                title: "Switch board: {selected_board_title}",
                                "aria-label": "Switch board",
                                "aria-expanded": "{board_popover() == BoardToolbarPopover::SelectBoard}",
                                onclick: move |_| {
                                    let next = if board_popover() == BoardToolbarPopover::SelectBoard {
                                        BoardToolbarPopover::None
                                    } else {
                                        BoardToolbarPopover::SelectBoard
                                    };
                                    board_popover.set(next);
                                },
                                UiIcon { name: "board" }
                                span { class: "board-select-button-label", "{selected_board_title}" }
                                UiIcon { name: "chevron-down" }
                            }
                            if board_popover() == BoardToolbarPopover::SelectBoard {
                                div {
                                    class: "board-select-menu-panel",
                                    role: "listbox",
                                    "aria-label": "Boards",
                                    {
                                        let board_route_realm_id_for_empty = board_route_realm_id.clone();
                                        let local_realm_id_for_empty = local_realm_id.clone();
                                        let account_did_for_empty = account_did.clone();
                                        let device_id_for_empty = device_id.clone();
                                        rsx! {
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                class: if selected_board_space_id().trim().is_empty() { "board-select-menu-item is-active" } else { "board-select-menu-item" },
                                                role: "option",
                                                "aria-selected": "{selected_board_space_id().trim().is_empty()}",
                                                onclick: move |_| {
                                                    select_kanban_board(
                                                        String::new(),
                                                        selected_board_space_id,
                                                        board_popover,
                                                        selected_card,
                                                        board_route_realm_id_for_empty.clone(),
                                                        local_realm_id_for_empty.clone(),
                                                        lifecycle_container_projection,
                                                        lifecycle_flow_projection,
                                                        columns,
                                                        adding_card_to,
                                                        board_status,
                                                        board_space_options,
                                                        projection_source,
                                                        state_store,
                                                        account_did_for_empty.clone(),
                                                        device_id_for_empty.clone(),
                                                    );
                                                },
                                                UiIcon { name: "board" }
                                                span { "Select board" }
                                            }
                                        }
                                    }
                                    for board_option in board_space_options().iter() {
                                        {
                                            let option_id = board_option.id.clone();
                                            let option_title = board_option.title.clone();
                                            let option_is_active = selected_board_space_id() == option_id;
                                            let board_route_realm_id_for_option = board_route_realm_id.clone();
                                            let local_realm_id_for_option = local_realm_id.clone();
                                            let account_did_for_option = account_did.clone();
                                            let device_id_for_option = device_id.clone();
                                            rsx! {
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    class: if option_is_active { "board-select-menu-item is-active" } else { "board-select-menu-item" },
                                                    role: "option",
                                                    "aria-selected": "{option_is_active}",
                                                    title: "{option_title}",
                                                    onclick: {
                                                        let option_id = option_id.clone();
                                                        let account_did_for_option = account_did_for_option.clone();
                                                        let device_id_for_option = device_id_for_option.clone();
                                                        move |_| {
                                                            select_kanban_board(
                                                                option_id.clone(),
                                                                selected_board_space_id,
                                                                board_popover,
                                                                selected_card,
                                                                board_route_realm_id_for_option.clone(),
                                                                local_realm_id_for_option.clone(),
                                                                lifecycle_container_projection,
                                                                lifecycle_flow_projection,
                                                                columns,
                                                                adding_card_to,
                                                                board_status,
                                                                board_space_options,
                                                                projection_source,
                                                                state_store,
                                                                account_did_for_option.clone(),
                                                                device_id_for_option.clone(),
                                                            );
                                                        }
                                                    },
                                                    UiIcon { name: "board" }
                                                    span { "{option_title}" }
                                                    {
                                                        let local_state = state_store.read().load();
                                                        let board_write_state = local_space_create_state_for_target(
                                                            &local_state.raw_operations,
                                                            &projected_space_container_ids,
                                                            &option_id,
                                                        );
                                                        rsx! {
                                                            if let Some(state) = board_write_state {
                                                                WriteStateBadge { state, icon_only: true }
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
                        if board_selected {
                            div { class: "actions board-list-compose",
                                Input {
                                    "data-testid": "new-column-input",
                                    value: "{new_column_title}",
                                    placeholder: "New list title",
                                    oninput: move |event: FormEvent| new_column_title.set(event.value()),
                                }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    size: ButtonSize::Sm,
                                    class: "btn",
                                    "data-testid": "add-column-button",
                                    onclick: {
                                        // Lists are Space containers in v1. The local column is
                                        // visible immediately but remains in sending/failed state
                                        // until `ck.self.events.submit` returns.
                                        let base = base_url.clone();
                                        let realm = selected_realm_id.clone();
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
                                            let list_space_id = format!("ck:space:{}", uuid_v7());
                                            let op = match crate::operation::ck_ops::space_create(
                                                &realm,
                                                &actor,
                                                &list_space_id,
                                                "list",
                                                &title,
                                                Some(&board_space_id),
                                                Some(&rank),
                                            ) {
                                                Ok(builder) => builder.build("yougen"),
                                                Err(err) => {
                                                    board_status.set(format!("cannot create list: {err:#}"));
                                                    return;
                                                }
                                            };
                                            if let Some(reason) = kanban_plaintext_block_reason(
                                                selected_scope_security_encrypted,
                                                &op,
                                            ) {
                                                board_status.set(reason);
                                                return;
                                            }
                                            columns.write().push(KanbanColumn {
                                                id: list_space_id.clone(),
                                                title: title.clone(),
                                                rank: rank.clone(),
                                                cards: Vec::new(),
                                                state: SpaceContainerLifecycleState::Active,
                                            });
                                            submit_kanban_operation_event(
                                                base.clone(),
                                                token,
                                                realm.clone(),
                                                op,
                                                selected_scope_security_encrypted,
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
                        div {
                            class: if board_popover() == BoardToolbarPopover::CreateBoard { "board-popover-host is-open" } else { "board-popover-host" },
                            Button {
                                variant: ButtonVariant::Secondary,
                                size: ButtonSize::Sm,
                                class: "btn board-popover-trigger",
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
                                    Input {
                                        "data-testid": "new-board-title-input",
                                        value: "{new_board_title}",
                                        placeholder: "Board title",
                                        oninput: move |event: FormEvent| new_board_title.set(event.value()),
                                    }
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "create-board-space-button",
                                        onclick: {
                                            let base = base_url.clone();
                                            let realm = selected_realm_id.clone();
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
                                                let board_space_id = format!("ck:space:{}", uuid_v7());
                                                let op = match crate::operation::ck_ops::space_create(
                                                    &realm,
                                                    &actor,
                                                    &board_space_id,
                                                    "board",
                                                    &title,
                                                    None,
                                                    None,
                                                ) {
                                                    Ok(builder) => builder.build("yougen"),
                                                    Err(err) => {
                                                        board_status.set(format!("cannot create board: {err:#}"));
                                                        return;
                                                    }
                                                };
                                                if let Some(reason) = kanban_plaintext_block_reason(
                                                    selected_scope_security_encrypted,
                                                    &op,
                                                ) {
                                                    board_status.set(reason);
                                                    return;
                                                }
                                                board_space_options.write().push(BoardSpaceOption {
                                                    id: board_space_id.clone(),
                                                    title: title.clone(),
                                                    state: SpaceContainerLifecycleState::Active,
                                                });
                                                selected_board_space_id.set(board_space_id.clone());
                                                columns.set(Vec::new());
                                                adding_card_to.set(None);
                                                submit_kanban_operation_event(
                                                    base.clone(),
                                                    token,
                                                    realm.clone(),
                                                    op,
                                                    selected_scope_security_encrypted,
                                                    state_store,
                                                    board_status,
                                                );
                                                board_status.set("Creating Board; waiting for server confirmation.".to_owned());
                                                let _ = navigator
                                                    .replace(kanban_board_route(&realm, &board_space_id));
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
                            Button {
                                variant: ButtonVariant::Secondary,
                                size: ButtonSize::Sm,
                                class: "btn board-popover-trigger",
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
                                    Label { html_for: "board-view-id-input-input", class: "field board-inline-field",
                                        span { "View ID" }
                                        Input {
                                            id: "board-view-id-input-input",
                                            "data-testid": "board-view-id-input",
                                            value: "{board_view_id}",
                                            placeholder: "ck:view:...",
                                            oninput: move |event: FormEvent| board_view_id.set(event.value()),
                                        }
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "board-projection-refresh",
                                        onclick: {
                                            // T20 — real API call to soland's
                                            // POST /_cokret/self/views/:id/projection. Demo seed is
                                            // opt-in so normal boards never show fake cards.
                                            let base = base_url.clone();
                                            let onclick_lifecycle_realm_id = local_realm_id.clone();
                                            let onclick_decrypt_realm_id = selected_realm_id.clone();
                                            let onclick_decrypt_actor = account_did.clone();
                                            let onclick_decrypt_device = device_id.clone();
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
                                                let decrypt_realm_id = onclick_decrypt_realm_id.clone();
                                                let decrypt_actor = onclick_decrypt_actor.clone();
                                                let decrypt_device = onclick_decrypt_device.clone();
                                                let lifecycle_realm_id = onclick_lifecycle_realm_id.clone();
                                                spawn(async move {
                                                    let events_res = if lifecycle_realm_id.trim().is_empty() {
                                                        None
                                                    } else {
                                                        let realm_id = lifecycle_realm_id.clone();
                                                        with_authed_api(&base, api_token.clone(), |api| async move {
                                                            api.backfill(&realm_id).await
                                                        })
                                                        .await
                                                        .ok()
                                                    };
                                                    let remote_update_operations = events_res
                                                        .as_ref()
                                                        .map(|resp| flow_update_operations_from_events(&resp.events))
                                                        .unwrap_or_default();
                                                    match with_authed_api(&base, api_token, |api| async move {
                                                        api.collection_projection(&view).await
                                                    })
                                                    .await
                                                    {
                                                        Ok(projection) => {
                                                            let cols = {
                                                                let decrypt_store = state_store.read();
                                                                let decrypt_ctx = MlsDecryptCtx {
                                                                    state_store: &decrypt_store,
                                                                    realm_id: &decrypt_realm_id,
                                                                    actor_id: &decrypt_actor,
                                                                    device_id: &decrypt_device,
                                                                };
                                                                overlay_collection_projection_with_operations(
                                                                    &projection,
                                                                    &decrypt_store,
                                                                    &selected_board_space_id(),
                                                                    &remote_update_operations,
                                                                    Some(&decrypt_ctx),
                                                                )
                                                            };
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
                                                WriteStateBadge { state }
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
                            Button {
                                variant: ButtonVariant::Secondary,
                                size: ButtonSize::Sm,
                                class: "btn board-popover-trigger",
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
                                        Button {
                                            variant: ButtonVariant::Secondary,
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
                                        span { class: "muted", "{manual_conflict_review_count} review / {write_record_count} total" }
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
                                                        WriteStateBadge { state: record.state }
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
            }

            if manual_conflict_review_count > 0 {
                div { class: "event board-conflict-alert", "data-testid": "board-conflict-alert",
                    div {
                        strong { "Board conflict review required" }
                        div { class: "muted", "{manual_conflict_review_count} queued write(s) hit a CAS conflict and need manual resolution before replay." }
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
                    // One id clone shared by both drop/drag closures (each takes its
                    // own clone at the `move ||` boundary). The title is read-only in
                    // the aria/title attributes, so we format `column.title` directly
                    // instead of cloning it twice.
                    let column_id = column.id.clone();
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
                            let realm = selected_realm_id.clone();
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
                                    realm.clone(),
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
                            "aria-label": "Drop column before {column.title}",
                            title: "Drop column before {column.title}",
                            ondragover: move |event| event.prevent_default(),
                            ondrop: {
                                let target_column_id = column_id.clone();
                                let base = base_url.clone();
                                let realm = selected_realm_id.clone();
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
                                            realm.clone(),
                                            actor.clone(),
                                            reordered_columns,
                                            selected_scope_security_encrypted,
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
                                    title: "Drag column {column.title}",
                                    "aria-label": "Drag column {column.title}",
                                    ondragstart: {
                                        let column_id = column_id.clone();
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
                                    class: "entity-title",
                                    "data-testid": "kanban-column-title",
                                    "{column.title}"
                                }
                                {
                                    let local_state = state_store.read().load();
                                    let column_write_state = local_space_create_state_for_target(
                                        &local_state.raw_operations,
                                        &projected_space_container_ids,
                                        &column.id,
                                    );
                                    rsx! {
                                        if let Some(state) = column_write_state {
                                            WriteStateBadge { state, icon_only: true }
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
                                key: "{card.id}",
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
                                    let realm = selected_realm_id.clone();
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
                                            realm.clone(),
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
                                    let route_realm_id = card_detail_route_realm_id(&selected_realm_id);
                                    move |_| {
                                        let draft = card_detail_draft_from_card(&c);
                                        card_edit_title.set(draft.title);
                                        card_edit_description.set(draft.description);
                                        card_edit_body.set(draft.body);
                                        card_edit_synthesis.set(draft.synthesis);
                                        card_edit_synthesis_target_id.set(None);
                                        card_edit_labels.set(draft.labels.join(", "));
                                        card_edit_assignee.set(draft.assignee);
                                        card_edit_due.set(draft.due);
                                        editing_card_detail.set(false);
                                        card_detail_edit_status.set(String::new());
                                        assignee_picker_open.set(false);
                                        assignee_filter.set(String::new());
                                        assignee_selected_actor_ids.set(card_assigned_actor_ids(&c).into_iter().collect());
                                        assignee_edit_status.set(String::new());
                                        due_picker_open.set(false);
                                        due_edit_value.set(editor_value_for_optional_card_field(&c.due));
                                        due_calendar_month.set(due_calendar_month_for_value(&c.due));
                                        due_edit_status.set(String::new());
                                        card_detail_actions_open.set(false);
                                        card_detail_tab.set(CardDetailContentTab::Description);
                                        card_synthesis_history_open_id.set(None);
                                        card_synthesis_selected_revision_id.set(None);
                                        card_detail_overlay_press_started.set(false);
                                        card_detail_overlay_press_ended.set(false);
                                        selected_card.set(Some(c.clone()));
                                        let _ = navigator.push(kanban_card_task_route(
                                            &route_realm_id,
                                            &selected_board_space_id(),
                                            &c.id,
                                        ));
                                        replace_card_detail_tab_query(CardDetailContentTab::Description);
                                    }
                                },
                                div { class: "event-head",
                                    span { class: "entity-title flow-title-with-security",
                                        SecurityStateBadge {
                                            encrypted: card.security_encrypted.unwrap_or(selected_scope_security_encrypted_or_secure),
                                            compact: true,
                                            test_id: Some("flow-card-security-state".to_owned()),
                                        }
                                        span { class: "flow-title-text", "{card.title}" }
                                    }
                                    WriteStateBadge { state: displayed_card_state(card, &projected_flow_ids) }
                                }
                                div { class: "actions",
                                    for label in &card.labels {
                                        span { class: "badge", "{label}" }
                                    }
                                }
                                div { class: "muted", "{card.description}" }
                                div { class: "card-meta", "assignees {card.assignee} / due {card.due}" }
                                div { class: "board-card-footer",
                                    {
                                        let gate = capability_gate_for_flow(
                                            &capability_engine,
                                            &account_did,
                                            &selected_board_space_id(),
                                            &card.id,
                                            "ck.flow.archive",
                                        );
                                        let title_text = if gate.enabled {
                                            "Archive this card (ck.flow.archive)".to_owned()
                                        } else {
                                            format!("Archive gated: {}", gate.reason)
                                        };
                                        let testid_state = if gate.enabled { "open" } else { "denied" };
                                        rsx! {
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                class: "kanban-inline-action",
                                                "data-testid": "card-archive-button",
                                                "data-flow-id": "{card.id}",
                                                "data-cap-gate": testid_state,
                                                disabled: !gate.enabled,
                                                title: title_text,
                                                onclick: {
                                                    let base = base_url.clone();
                                                    let realm = selected_realm_id.clone();
                                                    let actor = account_did.clone();
                                                    let flow_id = card.id.clone();
                                                    move |evt: dioxus::events::MouseEvent| {
                                                        evt.stop_propagation();
                                                        dispatch_flow_lifecycle(
                                                            base.clone(),
                                                            token,
                                                            realm.clone(),
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

                        // R11: `redacted` clears Flow content but retains the
                        // envelope/audit trail (flow.schema.json terminal). The
                        // UI MUST surface a "[消息已撤回]" placeholder rather than
                        // hiding the Flow, so the card stays visible without
                        // leaking its (now-cleared) title/body.
                        for redacted_card in column
                            .cards
                            .iter()
                            .filter(|c| c.lifecycle == FlowLifecycleState::Redacted)
                        {
                            div {
                                key: "{redacted_card.id}",
                                class: "event board-card board-card-redacted",
                                "data-testid": "kanban-card-redacted",
                                "data-flow-id": "{redacted_card.id}",
                                div { class: "event-head",
                                    span { class: "entity-title muted", "{crate::i18n::tr(\"timeline.redacted\")}" }
                                }
                            }
                        }

                        if adding_card_to() == Some(column.id.clone()) {
                            div { class: "board-card-composer",
                                div { class: "board-card-composer-card",
                                Textarea {
                                    class: "board-card-composer-input",
                                    "data-testid": "new-card-title-input",
                                    value: "{new_card_title}",
                                    placeholder: "Card title",
                                    rows: "3",
                                    wrap: "soft",
                                    maxlength: "512",
                                    oninput: move |event: FormEvent| new_card_title.set(event.value()),
                                }
                                }
                                div { class: "board-card-composer-actions",
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        class: "board-card-composer-save",
                                        "data-testid": "save-card-button",
                                        title: "Save card",
                                        "aria-label": "Save card",
                                        onclick: {
                                            // Card create submits a real
                                            // ck.flow.create envelope. The
                                            // initial Board/List placement
                                            // rides in the flow.position
                                            // component so the projection can
                                            // materialise it in this column.
                                            let base = base_url.clone();
                                            let col_id = column.id.clone();
                                            let realm = selected_realm_id.clone();
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
                                                let flow_id = format!("ck:flow:{}", uuid_v7());
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
                                                    CardState::Queued,
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
                                                    realm.clone(),
                                                    actor.clone(),
                                                    flow_id.clone(),
                                                    "ck.flow.create",
                                                    value,
                                                    selected_scope_security_encrypted,
                                                    columns,
                                                    state_store,
                                                    write_records,
                                                    board_status,
                                                );
                                                new_card_title.set(String::new());
                                                adding_card_to.set(None);
                                            }
                                        },
                                        UiIcon { name: "check" }
                                        span { {crate::i18n::tr("kanban.save_card")} }
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        class: "board-card-composer-cancel",
                                        title: "Cancel card",
                                        "aria-label": "Cancel card",
                                        onclick: move |_| adding_card_to.set(None),
                                        UiIcon { name: "x" }
                                        span { {crate::i18n::tr("kanban.cancel_card")} }
                                    }
                                }
                            }
                        } else {
                            div { class: "board-add-card-row",
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "add-card-button",
                                    onclick: {
                                        let col_id = column.id.clone();
                                        move |_| adding_card_to.set(Some(col_id.clone()))
                                    },
                                    {format!("+ {}", crate::i18n::tr("kanban.add_card"))}
                                }
                            }
                        }
                        div { class: "board-column-actions",
                        {
                            let gate = capability_gate_for_space_container(
                                &capability_engine,
                                &account_did,
                                &column.id,
                                "ck.space.archive",
                            );
                            let title_text = if gate.enabled {
                                "Archive this list (ck.space.archive)".to_owned()
                            } else {
                                format!("Archive gated: {}", gate.reason)
                            };
                            let testid_state = if gate.enabled { "open" } else { "denied" };
                            rsx! {
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    class: "kanban-inline-action",
                                    "data-testid": "list-archive-button",
                                    "data-space-container-id": "{column.id}",
                                    "data-cap-gate": testid_state,
                                    disabled: !gate.enabled,
                                    title: title_text,
                                    onclick: {
                                        let base = base_url.clone();
                                        let realm = selected_realm_id.clone();
                                        let actor = account_did.clone();
                                        let space_container_id = column.id.clone();
                                        move |_| {
                                            dispatch_space_container_lifecycle(
                                                base.clone(),
                                                token,
                                                realm.clone(),
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
                    }
                    }
                }
                }
            }

            // Archived lists panel — container Space lifecycle `archived` state.
            // Lists appear here after `ck.space.archive` is accepted and
            // are removed from the main board-grid above. Each row carries
            // a Restore button that submits `ck.space.restore` (SDK reducer
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
                                        span { class: "entity-title", "{column.title}" }
                                        span { "rank {column.rank} / {column.cards.len()} card(s)" }
                                        {
                                            let gate = capability_gate_for_space_container(
                                                &capability_engine,
                                                &account_did,
                                                &column.id,
                                                "ck.space.restore",
                                            );
                                            let title_text = if gate.enabled {
                                                "Restore this list (ck.space.restore)".to_owned()
                                            } else {
                                                format!("Restore gated: {}", gate.reason)
                                            };
                                            let testid_state = if gate.enabled { "open" } else { "denied" };
                                            rsx! {
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    "data-testid": "list-restore-button",
                                                    "data-space-container-id": "{column.id}",
                                                    "data-cap-gate": testid_state,
                                                    disabled: !gate.enabled,
                                                    title: title_text,
                                                    onclick: {
                                                        let base = base_url.clone();
                                                        let realm = selected_realm_id.clone();
                                                        let actor = account_did.clone();
                                                        let space_container_id = column.id.clone();
                                                        move |_| {
                                                            dispatch_space_container_lifecycle(
                                                                base.clone(),
                                                                token,
                                                                realm.clone(),
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
            // Cards appear here after `ck.flow.archive` is accepted and
            // are removed from the column above. Each row carries the
            // column title (where it came from) + a Restore button that
            // submits `ck.flow.restore` (SDK reducer enforces
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
                                        span { class: "entity-title flow-title-with-security",
                                            SecurityStateBadge {
                                                encrypted: row.card.security_encrypted.unwrap_or(selected_scope_security_encrypted_or_secure),
                                                compact: true,
                                                test_id: Some("flow-card-security-state".to_owned()),
                                            }
                                            span { class: "flow-title-text", "{row.card.title}" }
                                        }
                                        span { "from list: {row.column_title}" }
                                        {
                                            let gate = capability_gate_for_flow(
                                                &capability_engine,
                                                &account_did,
                                                &selected_board_space_id(),
                                                &row.card.id,
                                                "ck.flow.restore",
                                            );
                                            let title_text = if gate.enabled {
                                                "Restore this card (ck.flow.restore)".to_owned()
                                            } else {
                                                format!("Restore gated: {}", gate.reason)
                                            };
                                            let testid_state = if gate.enabled { "open" } else { "denied" };
                                            rsx! {
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    "data-testid": "card-restore-button",
                                                    "data-flow-id": "{row.card.id}",
                                                    "data-cap-gate": testid_state,
                                                    disabled: !gate.enabled,
                                                    title: title_text,
                                                    onclick: {
                                                        let base = base_url.clone();
                                                        let realm = selected_realm_id.clone();
                                                        let actor = account_did.clone();
                                                        let flow_id = row.card.id.clone();
                                                        move |_| {
                                                            dispatch_flow_lifecycle(
                                                                base.clone(),
                                                                token,
                                                                realm.clone(),
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
                    let board_route_after_close =
                        kanban_card_detail_board_route(&selected_realm_id, &selected_board_space_id());
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
                    let card_link_path = flow_detail_deep_link_path_with_tab(
                        &selected_realm_id,
                        &card.id,
                        active_detail_tab,
                    );
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
                    let discussion_panel_class = if active_detail_tab == CardDetailContentTab::Discussion {
                        "card-detail-discussion-panel"
                    } else {
                        "card-detail-discussion-panel is-hidden"
                    };
                    let discussion_panel_should_mount = active_detail_tab
                        == CardDetailContentTab::Discussion
                        || card_detail_discussion_mounted_for()
                            .as_deref()
                            .is_some_and(|flow_id| flow_id == card.primary_flow_id.as_str());
                    let action_menu_class = if editing_card_detail() {
                        "card-detail-action-menu is-editing"
                    } else {
                        "card-detail-action-menu"
                    };
                    let summary_text = card_summary_text(&card.description);
                    let synthesis_entries = {
                        let store = state_store.read();
                        let snapshot = store.load();
                        let projection = snapshot.realm_tree_projections.get(&selected_realm_id);
                        let realm_context = member_roster_realm_context(
                            &selected_realm_id,
                            &projection_realm_id,
                            projection,
                        );
                        let member_rows = realm_member_roster(projection);
                        let author_context = CardAuthorDisplayContext {
                            realm_id: &realm_context,
                            member_rows: &member_rows,
                        };
                        card_synthesis_track_entries_with_author_context(
                            card,
                            &snapshot.raw_operations,
                            &store,
                            Some(author_context),
                        )
                    };
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
                                    card_detail_edit_status.set(String::new());
                                    assignee_picker_open.set(false);
                                    assignee_filter.set(String::new());
                                    assignee_selected_actor_ids.set(BTreeSet::new());
                                    assignee_edit_status.set(String::new());
                                    due_picker_open.set(false);
                                    due_edit_value.set(String::new());
                                    due_calendar_month.set(default_due_calendar_month());
                                    due_edit_status.set(String::new());
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
                                            SecurityStateBadge {
                                                encrypted: card.security_encrypted.unwrap_or(selected_scope_security_encrypted_or_secure),
                                                compact: true,
                                                test_id: Some("flow-detail-security-state".to_owned()),
                                            }
                                            h2 { "{card.title}" }
                                            div { class: "card-detail-title-meta",
                                                WriteStateBadge { state: displayed_card_state(card, &projected_flow_ids) }
                                                for label in &card.labels {
                                                    span { class: "badge", "{label}" }
                                                }
                                            }
                                        }
                                    }
                                    div { class: "card-detail-header-actions",
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            class: "card-detail-header-button",
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
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                class: "card-detail-header-button",
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
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            class: "card-detail-header-button",
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
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                class: "card-detail-header-button",
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
                                                            Label { html_for: "card-detail-labels-input-input", "Labels" }
                                                            Input {
                                                                id: "card-detail-labels-input-input",
                                                                class: "input",
                                                                "data-testid": "card-detail-labels-input",
                                                                value: "{card_edit_labels}",
                                                                placeholder: "release, ops",
                                                                oninput: move |event: FormEvent| card_edit_labels.set(event.value()),
                                                            }
                                                        }
                                                        div { class: "card-detail-action-menu-field",
                                                            Label { html_for: "card-detail-due-input-input", "Due date" }
                                                            Input {
                                                                id: "card-detail-due-input-input",
                                                                class: "input",
                                                                "data-testid": "card-detail-due-input",
                                                                value: "{card_edit_due}",
                                                                placeholder: "2026-05-20",
                                                                oninput: move |event: FormEvent| card_edit_due.set(event.value()),
                                                            }
                                                        }
                                                    } else {
                                                        Button {
                                                            variant: ButtonVariant::Secondary,
                                                            class: "card-detail-action-menu-item",
                                                            "data-testid": "card-detail-menu-edit-button",
                                                            onclick: {
                                                                let current = card.clone();
                                                                move |_| {
                                                                    let draft = card_detail_draft_from_card(&current);
                                                                    card_edit_title.set(draft.title);
                                                                    card_edit_description.set(draft.description);
                                                                    card_edit_body.set(draft.body);
                                                                    card_edit_synthesis.set(draft.synthesis);
                                                                    card_edit_synthesis_target_id.set(None);
                                                                    card_edit_labels.set(draft.labels.join(", "));
                                                                    card_edit_assignee.set(draft.assignee);
                                                                    card_edit_due.set(draft.due);
                                                                    card_edit_scope.set(CardEditScope::Summary);
                                                                    card_detail_edit_status.set(String::new());
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
                                                                "ck.flow.archive"
                                                            } else {
                                                                "ck.flow.restore"
                                                            };
                                                            let gate = capability_gate_for_flow(
                                                                &capability_engine,
                                                                &account_did,
                                                                &selected_board_space_id(),
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
                                                                Button {
                                                                    variant: ButtonVariant::Secondary,
                                                                    class: "card-detail-action-menu-item",
                                                                    "data-testid": testid,
                                                                    "data-flow-id": "{card.id}",
                                                                    "data-cap-gate": testid_state,
                                                                    disabled: !gate.enabled,
                                                                    title: title_text,
                                                                    onclick: {
                                                                        let base = base_url.clone();
                                                                        let realm = selected_realm_id.clone();
                                                                        let actor = account_did.clone();
                                                                        let flow_id = card.id.clone();
                                                                        move |_| {
                                                                            dispatch_flow_lifecycle(
                                                                                base.clone(),
                                                                                token,
                                                                                realm.clone(),
                                                                                actor.clone(),
                                                                                flow_id.clone(),
                                                                                target,
                                                                                columns,
                                                                                board_status,
                                                                            );
                                                                            selected_card.set(None);
                                                                            editing_card_detail.set(false);
                                                                            card_detail_edit_status.set(String::new());
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
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            class: "card-detail-header-button card-detail-close",
                                            "data-testid": "card-detail-close-button",
                                            "aria-label": "Close card detail",
                                            title: "Close",
                                            onclick: move |_| {
                                                selected_card.set(None);
                                                editing_card_detail.set(false);
                                                card_detail_edit_status.set(String::new());
                                                assignee_picker_open.set(false);
                                                assignee_filter.set(String::new());
                                                assignee_selected_actor_ids.set(BTreeSet::new());
                                                assignee_edit_status.set(String::new());
                                                due_picker_open.set(false);
                                                due_edit_value.set(String::new());
                                                due_calendar_month.set(default_due_calendar_month());
                                                due_edit_status.set(String::new());
                                                card_detail_actions_open.set(false);
                                                if route_is_card_detail {
                                                    let _ = close_navigator.push(close_board_route.clone());
                                                }
                                            },
                                            UiIcon { name: "x" }
                                        }
                                    }
                                }

                                div { class: "{detail_layout_class}",
                                        main { class: "card-detail-main",
                                            section { class: "card-detail-section",
                                                div { class: "card-detail-section-head",
                                                    div { class: "card-detail-section-title",
                                                        UiIcon { name: "file" }
                                                        span { "Summary" }
                                                    }
                                                    if !editing_card_detail() {
                                                        Button {
                                                            variant: ButtonVariant::Secondary,
                                                            class: "card-detail-mini-action card-detail-edit-action",
                                                            "data-testid": "card-detail-edit-button",
                                                            onclick: {
                                                                let current = card.clone();
                                                                move |_| {
                                                                    let draft = card_detail_draft_from_card(&current);
                                                                    card_edit_title.set(draft.title);
                                                                    card_edit_description.set(draft.description);
                                                                    card_edit_body.set(draft.body);
                                                                    card_edit_synthesis.set(draft.synthesis);
                                                                    card_edit_synthesis_target_id.set(None);
                                                                    card_edit_labels.set(draft.labels.join(", "));
                                                                    card_edit_assignee.set(draft.assignee);
                                                                    card_edit_due.set(draft.due);
                                                                    card_edit_scope.set(CardEditScope::Summary);
                                                                    card_detail_edit_status.set(String::new());
                                                                    editing_card_detail.set(true);
                                                                }
                                                            },
                                                            UiIcon { name: "settings" }
                                                            span { {crate::i18n::tr("common.edit")} }
                                                        }
                                                    }
                                                }
                                                if editing_card_detail() && card_edit_scope() == CardEditScope::Summary {
                                                    div { class: "workflow-form card-detail-edit-form", "data-testid": "card-detail-edit-form",
                                                        div { class: "field",
                                                            Label { html_for: "card-detail-title-input-input", "Title" }
                                                            Input {
                                                                id: "card-detail-title-input-input",
                                                                class: "input",
                                                                "data-testid": "card-detail-title-input",
                                                                value: "{card_edit_title}",
                                                                maxlength: "512",
                                                                oninput: move |event: FormEvent| card_edit_title.set(event.value()),
                                                            }
                                                        }
                                                        div { class: "field",
                                                            Label { html_for: "card-detail-summary-input", "Summary" }
                                                            CardMarkdownEditor {
                                                                value: card_edit_description(),
                                                                base_url: base_url.clone(),
                                                                token: token(),
                                                                realm_id: selected_realm_id.clone(),
                                                                on_change: move |value| card_edit_description.set(value),
                                                                slot: "summary".to_owned(),
                                                            }
                                                        }
                                                        CardDetailEditActions {
                                                            status: card_detail_edit_status(),
                                                            on_save: {
                                                                let base = base_url.clone();
                                                                let realm = selected_realm_id.clone();
                                                                let actor = account_did.clone();
                                                                let device = device_id.clone();
                                                                let current = card.clone();
                                                                let entries = synthesis_entries.clone();
                                                                move |_| {
                                                                    save_card_detail_edit(
                                                                        base.clone(),
                                                                        token,
                                                                        realm.clone(),
                                                                        actor.clone(),
                                                                        device.clone(),
                                                                        current.clone(),
                                                                        entries.clone(),
                                                                        selected_scope_security_encrypted,
                                                                        card_edit_scope,
                                                                        card_edit_title,
                                                                        card_edit_description,
                                                                        card_edit_body,
                                                                        card_edit_synthesis,
                                                                        card_edit_synthesis_target_id,
                                                                        card_edit_labels,
                                                                        card_edit_assignee,
                                                                        card_edit_due,
                                                                        editing_card_detail,
                                                                        card_detail_actions_open,
                                                                        card_detail_edit_status,
                                                                        columns,
                                                                        selected_card,
                                                                        state_store,
                                                                        board_status,
                                                                    );
                                                                }
                                                            },
                                                            on_cancel: {
                                                                let current = card.clone();
                                                                move |_| {
                                                                    reset_card_detail_edit(
                                                                        &current,
                                                                        card_edit_title,
                                                                        card_edit_description,
                                                                        card_edit_body,
                                                                        card_edit_synthesis,
                                                                        card_edit_synthesis_target_id,
                                                                        card_edit_labels,
                                                                        card_edit_assignee,
                                                                        card_edit_due,
                                                                        editing_card_detail,
                                                                        card_detail_actions_open,
                                                                        card_synthesis_history_open_id,
                                                                        card_synthesis_selected_revision_id,
                                                                        card_detail_edit_status,
                                                                    );
                                                                }
                                                            },
                                                        }
                                                    }
                                                } else if summary_text.is_empty() {
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
                                                        disabled: editing_card_detail(),
                                                        onclick: move |_| {
                                                            card_detail_tab.set(CardDetailContentTab::Description);
                                                            replace_card_detail_tab_query(CardDetailContentTab::Description);
                                                        },
                                                        "Description"
                                                    }
                                                    button {
                                                        r#type: "button",
                                                        class: "{synthesis_tab_class}",
                                                        "data-testid": "card-detail-tab-synthesis",
                                                        role: "tab",
                                                        "aria-selected": "{active_detail_tab == CardDetailContentTab::Synthesis}",
                                                        disabled: editing_card_detail(),
                                                        onclick: move |_| {
                                                            card_detail_tab.set(CardDetailContentTab::Synthesis);
                                                            replace_card_detail_tab_query(CardDetailContentTab::Synthesis);
                                                        },
                                                        "Synthesis"
                                                    }
                                                    button {
                                                        r#type: "button",
                                                        class: "{discussion_tab_class}",
                                                        "data-testid": "card-detail-tab-discussion",
                                                        role: "tab",
                                                        "aria-selected": "{active_detail_tab == CardDetailContentTab::Discussion}",
                                                        disabled: editing_card_detail(),
                                                        onclick: {
                                                            let flow_id = card.primary_flow_id.clone();
                                                            move |_| {
                                                                card_detail_discussion_mounted_for.set(Some(flow_id.clone()));
                                                                card_detail_tab.set(CardDetailContentTab::Discussion);
                                                                replace_card_detail_tab_query(CardDetailContentTab::Discussion);
                                                            }
                                                        },
                                                        "Discussion"
                                                    }
                                                }
                                                if active_detail_tab == CardDetailContentTab::Description {
                                                    div {
                                                        class: "card-detail-description-panel",
                                                        "data-testid": "card-description-panel",
                                                        role: "tabpanel",
                                                        if editing_card_detail() && card_edit_scope() == CardEditScope::Description {
                                                            div { class: "workflow-form card-detail-edit-form", "data-testid": "card-detail-edit-form",
                                                                div { class: "field",
                                                                    Label { html_for: "card-detail-description-input", "Description" }
                                                                    CardMarkdownEditor {
                                                                        value: card_edit_body(),
                                                                        base_url: base_url.clone(),
                                                                        token: token(),
                                                                        realm_id: selected_realm_id.clone(),
                                                                        on_change: move |value| card_edit_body.set(value),
                                                                        slot: "description".to_owned(),
                                                                    }
                                                                }
                                                                CardDetailEditActions {
                                                                    status: card_detail_edit_status(),
                                                                    on_save: {
                                                                        let base = base_url.clone();
                                                                        let realm = selected_realm_id.clone();
                                                                        let actor = account_did.clone();
                                                                        let device = device_id.clone();
                                                                        let current = card.clone();
                                                                        let entries = synthesis_entries.clone();
                                                                        move |_| {
                                                                            save_card_detail_edit(
                                                                                base.clone(),
                                                                                token,
                                                                                realm.clone(),
                                                                                actor.clone(),
                                                                                device.clone(),
                                                                                current.clone(),
                                                                                entries.clone(),
                                                                                selected_scope_security_encrypted,
                                                                                card_edit_scope,
                                                                                card_edit_title,
                                                                                card_edit_description,
                                                                                card_edit_body,
                                                                                card_edit_synthesis,
                                                                                card_edit_synthesis_target_id,
                                                                                card_edit_labels,
                                                                                card_edit_assignee,
                                                                                card_edit_due,
                                                                                editing_card_detail,
                                                                                card_detail_actions_open,
                                                                                card_detail_edit_status,
                                                                                columns,
                                                                                selected_card,
                                                                                state_store,
                                                                                board_status,
                                                                            );
                                                                        }
                                                                    },
                                                                    on_cancel: {
                                                                        let current = card.clone();
                                                                        move |_| {
                                                                            reset_card_detail_edit(
                                                                                &current,
                                                                                card_edit_title,
                                                                                card_edit_description,
                                                                                card_edit_body,
                                                                                card_edit_synthesis,
                                                                                card_edit_synthesis_target_id,
                                                                                card_edit_labels,
                                                                                card_edit_assignee,
                                                                                card_edit_due,
                                                                                editing_card_detail,
                                                                                card_detail_actions_open,
                                                                                card_synthesis_history_open_id,
                                                                                card_synthesis_selected_revision_id,
                                                                                card_detail_edit_status,
                                                                            );
                                                                        }
                                                                    },
                                                                }
                                                            }
                                                        } else if card.body.trim().is_empty()
                                                            && card.body_locked
                                                        {
                                                            // X10.2: encrypted field this device can't
                                                            // read yet — show a locked notice (NOT "No
                                                            // description", NOT an edit affordance that
                                                            // would overwrite the real ciphertext).
                                                            div {
                                                                class: "card-detail-empty",
                                                                "data-testid": "card-detail-body-locked",
                                                                div { "{MLS_LOCKED_FIELD_PLACEHOLDER}" }
                                                            }
                                                        } else if card.body.trim().is_empty() {
                                                            div { class: "card-detail-empty",
                                                                div { "No description" }
                                                                if !editing_card_detail() {
                                                                    Button {
                                                                        variant: ButtonVariant::Secondary,
                                                                        class: "card-detail-mini-action",
                                                                        "data-testid": "card-detail-add-description-button",
                                                                        onclick: {
                                                                            let current = card.clone();
                                                                            move |_| {
                                                                                let draft = card_detail_draft_from_card(&current);
                                                                                card_edit_title.set(draft.title);
                                                                                card_edit_description.set(draft.description);
                                                                                card_edit_body.set(draft.body);
                                                                                card_edit_synthesis.set(draft.synthesis);
                                                                                card_edit_synthesis_target_id.set(None);
                                                                                card_edit_labels.set(draft.labels.join(", "));
                                                                                card_edit_assignee.set(draft.assignee);
                                                                                card_edit_due.set(draft.due);
                                                                                card_edit_scope.set(CardEditScope::Description);
                                                                                card_detail_edit_status.set(String::new());
                                                                                editing_card_detail.set(true);
                                                                            }
                                                                        },
                                                                        UiIcon { name: "plus" }
                                                                        span { "Add description" }
                                                                    }
                                                                }
                                                            }
                                                        } else {
                                                            if !editing_card_detail() {
                                                                div { class: "card-detail-tab-actions",
                                                                    Button {
                                                                        variant: ButtonVariant::Secondary,
                                                                        class: "card-detail-mini-action card-detail-edit-action",
                                                                        "data-testid": "card-detail-edit-description-button",
                                                                        onclick: {
                                                                            let current = card.clone();
                                                                            move |_| {
                                                                                let draft = card_detail_draft_from_card(&current);
                                                                                card_edit_title.set(draft.title);
                                                                                card_edit_description.set(draft.description);
                                                                                card_edit_body.set(draft.body);
                                                                                card_edit_synthesis.set(draft.synthesis);
                                                                                card_edit_synthesis_target_id.set(None);
                                                                                card_edit_labels.set(draft.labels.join(", "));
                                                                                card_edit_assignee.set(draft.assignee);
                                                                                card_edit_due.set(draft.due);
                                                                                card_edit_scope.set(CardEditScope::Description);
                                                                                card_detail_edit_status.set(String::new());
                                                                                editing_card_detail.set(true);
                                                                            }
                                                                        },
                                                                        UiIcon { name: "settings" }
                                                                        span { {crate::i18n::tr("common.edit")} }
                                                                    }
                                                                }
                                                            }
                                                            div { class: "card-detail-description",
                                                                {crate::content::render_blocks(
                                                                    &crate::content::parse_message_body(&card.body),
                                                                )}
                                                            }
                                                        }
                                                    }
                                                } else if active_detail_tab == CardDetailContentTab::Synthesis {
                                                    div {
                                                        class: "card-detail-synthesis-panel",
                                                        "data-testid": "card-synthesis-panel",
                                                        role: "tabpanel",
                                                        if synthesis_entries.is_empty()
                                                            && card.synthesis_locked
                                                        {
                                                            div {
                                                                class: "card-detail-empty",
                                                                "data-testid": "card-detail-synthesis-locked",
                                                                div { "{MLS_LOCKED_FIELD_PLACEHOLDER}" }
                                                            }
                                                        } else if synthesis_entries.is_empty() {
                                                            div { class: "card-detail-empty",
                                                                div { "No synthesis yet." }
                                                            }
                                                        } else {
                                                            div { class: "card-synthesis-track", "data-testid": "card-synthesis-track",
                                                                for entry in synthesis_entries.iter() {
                                                                    {
                                                                        let latest_revision = entry.revisions.last().cloned().unwrap_or_else(|| {
                                                                            CardSynthesisRevision {
                                                                                id: entry.id.clone(),
                                                                                body: entry.body.clone(),
                                                                                actor_id: entry.actor_id.clone(),
                                                                                author_label: entry.author_label.clone(),
                                                                                timestamp_label: entry.timestamp_label.clone(),
                                                                                sort_key: entry.sort_key.clone(),
                                                                            }
                                                                        });
                                                                        let selected_revision_id = card_synthesis_selected_revision_id();
                                                                        let selected_revision = selected_revision_id
                                                                            .as_deref()
                                                                            .and_then(|id| entry.revisions.iter().find(|revision| revision.id == id))
                                                                            .cloned();
                                                                        let display_revision = selected_revision.unwrap_or_else(|| latest_revision.clone());
                                                                        let display_revision_index = entry
                                                                            .revisions
                                                                            .iter()
                                                                            .position(|revision| revision.id == display_revision.id)
                                                                            .unwrap_or_else(|| entry.revisions.len().saturating_sub(1));
                                                                        let version_label = format!("v{}", display_revision_index + 1);
                                                                        let selected_synthesis_is_latest = display_revision.id == latest_revision.id;
                                                                        let version_state = if selected_synthesis_is_latest {
                                                                            "latest"
                                                                        } else {
                                                                            "history"
                                                                        };
                                                                        let entry_class = if selected_synthesis_is_latest {
                                                                            "card-synthesis-entry is-latest"
                                                                        } else {
                                                                            "card-synthesis-entry is-history"
                                                                        };
                                                                        let history_open = card_synthesis_history_open_id()
                                                                            .as_deref()
                                                                            == Some(entry.id.as_str());
                                                                        let actor_title = if display_revision.actor_id.trim().is_empty() {
                                                                            "Unknown author".to_owned()
                                                                        } else {
                                                                            display_revision.actor_id.clone()
                                                                        };
                                                                        rsx! {
                                                                            article {
                                                                                key: "{entry.id}",
                                                                                class: "{entry_class}",
                                                                                "data-testid": "card-synthesis-entry",
                                                                                "data-synthesis-version-state": "{version_state}",
                                                                                header { class: "card-synthesis-entry-head",
                                                                                    span { class: "card-synthesis-author", title: "{actor_title}", "{display_revision.author_label}" }
                                                                                    time { class: "card-synthesis-time", "{display_revision.timestamp_label}" }
                                                                                    span { class: "badge", "{version_label}" }
                                                                                    if selected_synthesis_is_latest {
                                                                                        span { class: "badge badge-success", "latest" }
                                                                                    } else {
                                                                                        span { class: "badge badge-warning", "historical version" }
                                                                                        Button {
                                                                                            variant: ButtonVariant::Secondary,
                                                                                            r#type: "button",
                                                                                            class: "badge card-synthesis-latest-button",
                                                                                            "data-testid": "card-synthesis-latest-button",
                                                                                            onclick: move |_| {
                                                                                                card_synthesis_selected_revision_id.set(None);
                                                                                                card_synthesis_history_open_id.set(None);
                                                                                            },
                                                                                            "Latest"
                                                                                        }
                                                                                    }
                                                                                    if entry.revisions.len() > 1 {
                                                                                        div { class: "card-synthesis-history-wrap",
                                                                                            Button {
                                                                                                variant: ButtonVariant::Secondary,
                                                                                                r#type: "button",
                                                                                                class: "badge card-synthesis-history-trigger",
                                                                                                "data-testid": "card-synthesis-history-trigger",
                                                                                                "aria-expanded": "{history_open}",
                                                                                                onclick: {
                                                                                                    let entry_id = entry.id.clone();
                                                                                                    move |_| {
                                                                                                        if card_synthesis_history_open_id().as_deref() == Some(entry_id.as_str()) {
                                                                                                            card_synthesis_history_open_id.set(None);
                                                                                                        } else {
                                                                                                            card_synthesis_history_open_id.set(Some(entry_id.clone()));
                                                                                                        }
                                                                                                    }
                                                                                                },
                                                                                                "edited"
                                                                                            }
                                                                                            if history_open {
                                                                                                div { class: "card-synthesis-history-menu", "data-testid": "card-synthesis-history-menu",
                                                                                                    div { class: "card-synthesis-history-title", "History" }
                                                                                                    for (history_index, history_entry) in entry.revisions.iter().enumerate().rev() {
                                                                                                        {
                                                                                                            let history_entry_id = history_entry.id.clone();
                                                                                                            let history_version_label = format!("v{}", history_index + 1);
                                                                                                            let history_is_latest = history_entry.id == latest_revision.id;
                                                                                                            let history_item_class = if history_entry.id == display_revision.id {
                                                                                                                "card-synthesis-history-item active"
                                                                                                            } else {
                                                                                                                "card-synthesis-history-item"
                                                                                                            };
                                                                                                            let history_author_title = if history_entry.actor_id.trim().is_empty() {
                                                                                                                "Unknown author".to_owned()
                                                                                                            } else {
                                                                                                                history_entry.actor_id.clone()
                                                                                                            };
                                                                                                            let preview = card_summary_text(&history_entry.body);
                                                                                                            let preview = if preview.chars().count() > 72 {
                                                                                                                let shortened = preview.chars().take(72).collect::<String>();
                                                                                                                format!("{shortened}...")
                                                                                                            } else {
                                                                                                                preview
                                                                                                            };
                                                                                                            rsx! {
                                                                                                                Button {
                                                                                                                    variant: ButtonVariant::Secondary,
                                                                                                                    key: "{history_entry.id}",
                                                                                                                    r#type: "button",
                                                                                                                    class: "{history_item_class}",
                                                                                                                    "data-testid": "card-synthesis-history-item",
                                                                                                                    onclick: move |_| {
                                                                                                                        if history_is_latest {
                                                                                                                            card_synthesis_selected_revision_id.set(None);
                                                                                                                        } else {
                                                                                                                            card_synthesis_selected_revision_id.set(Some(history_entry_id.clone()));
                                                                                                                        }
                                                                                                                        card_synthesis_history_open_id.set(None);
                                                                                                                    },
                                                                                                                    span { class: "card-synthesis-history-meta",
                                                                                                                        span { class: "badge", "{history_version_label}" }
                                                                                                                        if history_is_latest {
                                                                                                                            span { class: "badge badge-success", "latest" }
                                                                                                                        }
                                                                                                                        span { title: "{history_author_title}", "{history_entry.author_label}" }
                                                                                                                        time { "{history_entry.timestamp_label}" }
                                                                                                                    }
                                                                                                                    span { class: "card-synthesis-history-preview", "{preview}" }
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                    if !editing_card_detail() {
                                                                                        Button {
                                                                                            variant: ButtonVariant::Secondary,
                                                                                            r#type: "button",
                                                                                            class: "card-detail-mini-action card-synthesis-entry-edit",
                                                                                            "data-testid": "card-detail-edit-synthesis-button",
                                                                                            onclick: {
                                                                                                let current = card.clone();
                                                                                                let entry_id = entry.id.clone();
                                                                                                let entry_body = entry.body.clone();
                                                                                                move |_| {
                                                                                                    let draft = card_detail_draft_from_card(&current);
                                                                                                    card_edit_title.set(draft.title);
                                                                                                    card_edit_description.set(draft.description);
                                                                                                    card_edit_body.set(draft.body);
                                                                                                    card_edit_synthesis.set(entry_body.clone());
                                                                                                    card_edit_synthesis_target_id.set(Some(entry_id.clone()));
                                                                                                    card_edit_labels.set(draft.labels.join(", "));
                                                                                                    card_edit_assignee.set(draft.assignee);
                                                                                                    card_edit_due.set(draft.due);
                                                                                                    card_edit_scope.set(CardEditScope::Synthesis);
                                                                                                    card_detail_edit_status.set(String::new());
                                                                                                    editing_card_detail.set(true);
                                                                                                    card_synthesis_history_open_id.set(None);
                                                                                                    card_synthesis_selected_revision_id.set(None);
                                                                                                }
                                                                                            },
                                                                                            UiIcon { name: "settings" }
                                                                                            span { {crate::i18n::tr("common.edit")} }
                                                                                        }
                                                                                    }
                                                                                }
                                                                                if editing_card_detail()
                                                                                    && card_edit_scope() == CardEditScope::Synthesis
                                                                                    && card_edit_synthesis_target_id().as_deref() == Some(entry.id.as_str()) {
                                                                                    div { class: "workflow-form card-detail-edit-form card-detail-inline-edit-form", "data-testid": "card-detail-edit-form",
                                                                                        div { class: "field",
                                                                                            Label { html_for: "card-detail-synthesis-input", "Synthesis" }
                                                                                            CardMarkdownEditor {
                                                                                                value: card_edit_synthesis(),
                                                                                                base_url: base_url.clone(),
                                                                                                token: token(),
                                                                                                realm_id: selected_realm_id.clone(),
                                                                                                on_change: move |value| card_edit_synthesis.set(value),
                                                                                                slot: "synthesis".to_owned(),
                                                                                            }
                                                                                        }
                                                                                        CardDetailEditActions {
                                                                                            status: card_detail_edit_status(),
                                                                                            on_save: {
                                                                                                let base = base_url.clone();
                                                                                                let realm = selected_realm_id.clone();
                                                                                                let actor = account_did.clone();
                                                                                                let device = device_id.clone();
                                                                                                let current = card.clone();
                                                                                                let entries = synthesis_entries.clone();
                                                                                                move |_| {
                                                                                                    save_card_detail_edit(
                                                                                                        base.clone(),
                                                                                                        token,
                                                                                                        realm.clone(),
                                                                                                        actor.clone(),
                                                                                                        device.clone(),
                                                                                                        current.clone(),
                                                                                                        entries.clone(),
                                                                                                        selected_scope_security_encrypted,
                                                                                                        card_edit_scope,
                                                                                                        card_edit_title,
                                                                                                        card_edit_description,
                                                                                                        card_edit_body,
                                                                                                        card_edit_synthesis,
                                                                                                        card_edit_synthesis_target_id,
                                                                                                        card_edit_labels,
                                                                                                        card_edit_assignee,
                                                                                                        card_edit_due,
                                                                                                        editing_card_detail,
                                                                                                        card_detail_actions_open,
                                                                                                        card_detail_edit_status,
                                                                                                        columns,
                                                                                                        selected_card,
                                                                                                        state_store,
                                                                                                        board_status,
                                                                                                    );
                                                                                                }
                                                                                            },
                                                                                            on_cancel: {
                                                                                                let current = card.clone();
                                                                                                move |_| {
                                                                                                    reset_card_detail_edit(
                                                                                                        &current,
                                                                                                        card_edit_title,
                                                                                                        card_edit_description,
                                                                                                        card_edit_body,
                                                                                                        card_edit_synthesis,
                                                                                                        card_edit_synthesis_target_id,
                                                                                                        card_edit_labels,
                                                                                                        card_edit_assignee,
                                                                                                        card_edit_due,
                                                                                                        editing_card_detail,
                                                                                                        card_detail_actions_open,
                                                                                                        card_synthesis_history_open_id,
                                                                                                        card_synthesis_selected_revision_id,
                                                                                                        card_detail_edit_status,
                                                                                                    );
                                                                                                }
                                                                                            },
                                                                                        }
                                                                                    }
                                                                                } else {
                                                                                    div { class: "card-detail-description card-synthesis-body",
                                                                                        {crate::content::render_blocks(
                                                                                            &crate::content::parse_message_body(&display_revision.body),
                                                                                        )}
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        if editing_card_detail()
                                                            && card_edit_scope() == CardEditScope::Synthesis
                                                            && card_edit_synthesis_target_id().is_none() {
                                                            div { class: "workflow-form card-detail-edit-form card-detail-inline-edit-form", "data-testid": "card-detail-edit-form",
                                                                div { class: "field",
                                                                    Label { html_for: "card-detail-synthesis-input", "Synthesis" }
                                                                    CardMarkdownEditor {
                                                                        value: card_edit_synthesis(),
                                                                        base_url: base_url.clone(),
                                                                        token: token(),
                                                                        realm_id: selected_realm_id.clone(),
                                                                        on_change: move |value| card_edit_synthesis.set(value),
                                                                        slot: "synthesis".to_owned(),
                                                                    }
                                                                }
                                                                CardDetailEditActions {
                                                                    status: card_detail_edit_status(),
                                                                    on_save: {
                                                                        let base = base_url.clone();
                                                                        let realm = selected_realm_id.clone();
                                                                        let actor = account_did.clone();
                                                                        let device = device_id.clone();
                                                                        let current = card.clone();
                                                                        let entries = synthesis_entries.clone();
                                                                        move |_| {
                                                                            save_card_detail_edit(
                                                                                base.clone(),
                                                                                token,
                                                                                realm.clone(),
                                                                                actor.clone(),
                                                                                device.clone(),
                                                                                current.clone(),
                                                                                entries.clone(),
                                                                                selected_scope_security_encrypted,
                                                                                card_edit_scope,
                                                                                card_edit_title,
                                                                                card_edit_description,
                                                                                card_edit_body,
                                                                                card_edit_synthesis,
                                                                                card_edit_synthesis_target_id,
                                                                                card_edit_labels,
                                                                                card_edit_assignee,
                                                                                card_edit_due,
                                                                                editing_card_detail,
                                                                                card_detail_actions_open,
                                                                                card_detail_edit_status,
                                                                                columns,
                                                                                selected_card,
                                                                                state_store,
                                                                                board_status,
                                                                            );
                                                                        }
                                                                    },
                                                                    on_cancel: {
                                                                        let current = card.clone();
                                                                        move |_| {
                                                                            reset_card_detail_edit(
                                                                                &current,
                                                                                card_edit_title,
                                                                                card_edit_description,
                                                                                card_edit_body,
                                                                                card_edit_synthesis,
                                                                                card_edit_synthesis_target_id,
                                                                                card_edit_labels,
                                                                                card_edit_assignee,
                                                                                card_edit_due,
                                                                                editing_card_detail,
                                                                                card_detail_actions_open,
                                                                                card_synthesis_history_open_id,
                                                                                card_synthesis_selected_revision_id,
                                                                                card_detail_edit_status,
                                                                            );
                                                                        }
                                                                    },
                                                                }
                                                            }
                                                        }
                                                        if !editing_card_detail() {
                                                            div { class: "card-synthesis-footer-action",
                                                                Button {
                                                                    variant: ButtonVariant::Secondary,
                                                                    class: "card-detail-mini-action",
                                                                    "data-testid": "card-detail-new-synthesis-button",
                                                                    onclick: {
                                                                        let current = card.clone();
                                                                        move |_| {
                                                                            let draft = card_detail_draft_from_card(&current);
                                                                            card_edit_title.set(draft.title);
                                                                            card_edit_description.set(draft.description);
                                                                            card_edit_body.set(draft.body);
                                                                            card_edit_synthesis.set(String::new());
                                                                            card_edit_synthesis_target_id.set(None);
                                                                            card_edit_labels.set(draft.labels.join(", "));
                                                                            card_edit_assignee.set(draft.assignee);
                                                                            card_edit_due.set(draft.due);
                                                                            card_edit_scope.set(CardEditScope::Synthesis);
                                                                            card_detail_edit_status.set(String::new());
                                                                            editing_card_detail.set(true);
                                                                            card_synthesis_history_open_id.set(None);
                                                                            card_synthesis_selected_revision_id.set(None);
                                                                        }
                                                                    },
                                                                    UiIcon { name: "plus" }
                                                                    span { "New" }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                if discussion_panel_should_mount {
                                                    div {
                                                        class: "{discussion_panel_class}",
                                                        "data-testid": "card-discussion-panel",
                                                        role: "tabpanel",
                                                        "aria-hidden": "{active_detail_tab != CardDetailContentTab::Discussion}",
                                                        crate::views::chat::ChatPanel {
                                                            base_url: base_url.clone(),
                                                            plaintext_service_did: plaintext_service_did.clone(),
                                                            account_did: account_did.clone(),
                                                            device_id: device_id.clone(),
                                                            token,
                                                            selected_realm_id: selected_realm_id.clone(),
                                                            sync_cursor,
                                                            frontier_state,
                                                            state_store,
                                                            initial_flow_id: card.primary_flow_id.clone(),
                                                            embedded: true,
                                                            direct_mode: false,
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if sidebar_is_visible {
                                        aside { class: "card-detail-sidebar",
                                            {
                                                let store = state_store.read().load();
                                                let projection = store.realm_tree_projections.get(&selected_realm_id);
                                                let realm_context = member_roster_realm_context(
                                                    &selected_realm_id,
                                                    &projection_realm_id,
                                                    projection,
                                                );
                                                let realm_member_rows = realm_member_roster(
                                                    projection,
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
                                                        {
                                                            let assigned_actor_ids = card_assigned_actor_ids(&card);
                                                            let assigned_people = {
                                                                let store = state_store.read();
                                                                assigned_actor_ids
                                                                    .iter()
                                                                    .map(|actor_id| {
                                                                        let label = assignee_label_for_actor(
                                                                            &store,
                                                                            &realm_context,
                                                                            &realm_member_rows,
                                                                            actor_id,
                                                                        );
                                                                        let initial = assignee_avatar_initial(&label);
                                                                        (actor_id.clone(), label, initial)
                                                                    })
                                                                    .collect::<Vec<_>>()
                                                            };
                                                            let assignee_title = if assigned_actor_ids.is_empty() {
                                                                "unassigned".to_owned()
                                                            } else {
                                                                assigned_actor_ids.join(", ")
                                                            };
                                                            let picker_rows = assignment_picker_roster(&realm_member_rows, &card);
                                                            let picker_filter = assignee_filter();
                                                            let selected_actor_ids = assignee_selected_actor_ids();
                                                            let picker_people = {
                                                                let store = state_store.read();
                                                                picker_rows
                                                                    .iter()
                                                                    .filter_map(|row| {
                                                                        let label = assignee_label_for_actor(
                                                                            &store,
                                                                            &realm_context,
                                                                            &realm_member_rows,
                                                                            &row.actor_id,
                                                                        );
                                                                        assignee_filter_matches(&picker_filter, &label, &row.actor_id).then(|| {
                                                                            (
                                                                                row.actor_id.clone(),
                                                                                label.clone(),
                                                                                assignee_avatar_initial(&label),
                                                                                short_protocol_id(&row.actor_id),
                                                                            )
                                                                        })
                                                                    })
                                                                    .collect::<Vec<_>>()
                                                            };
                                                            let picker_open = assignee_picker_open();
                                                            let edit_status = assignee_edit_status();
                                                            let activity_items =
                                                                card_activity_items(&card, &store.raw_operations);
                                                            rsx! {
                                                        div { class: "card-detail-side-fields", "data-testid": "card-fields",
                                                            dl { class: "card-detail-field-list",
                                                                div {
                                                                    dt { "Flow ID" }
                                                                    dd { class: "card-detail-field-code", title: "{card.id}", "{card_id_label}" }
                                                                }
                                                                div {
                                                                    dt { "Assignees" }
                                                                    dd {
                                                                        div {
                                                                            class: "assignee-editor",
                                                                            "data-testid": "card-detail-assignees",
                                                                            div { class: "assignee-chip-row", title: "{assignee_title}",
                                                                                if assigned_people.is_empty() {
                                                                                    Button {
                                                                                        variant: ButtonVariant::Secondary,
                                                                                        r#type: "button",
                                                                                        class: "assignee-add assignee-add-empty",
                                                                                        "aria-haspopup": "listbox",
                                                                                        "aria-expanded": "{picker_open}",
                                                                                        title: "Add assignees",
                                                                                        onclick: {
                                                                                            let current_selection = assigned_actor_ids
                                                                                                .iter()
                                                                                                .cloned()
                                                                                                .collect::<BTreeSet<_>>();
                                                                                            move |_| {
                                                                                                assignee_selected_actor_ids.set(current_selection.clone());
                                                                                                assignee_filter.set(String::new());
                                                                                                assignee_edit_status.set(String::new());
                                                                                                assignee_picker_open.set(!assignee_picker_open());
                                                                                            }
                                                                                        },
                                                                                        UiIcon { name: "plus" }
                                                                                        span { "Add assignees" }
                                                                                    }
                                                                                } else {
                                                                                    span { class: "assignee-chip-list",
                                                                                        for (actor_id, label, initial) in assigned_people.iter() {
                                                                                            span {
                                                                                                key: "{actor_id}",
                                                                                                class: "assignee-chip",
                                                                                                title: "{actor_id}",
                                                                                                span { class: "assignee-avatar", "{initial}" }
                                                                                                span { class: "assignee-chip-label", "{label}" }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                    Button {
                                                                                        variant: ButtonVariant::Secondary,
                                                                                        r#type: "button",
                                                                                        class: "assignee-add",
                                                                                        "aria-label": "Add or remove assignees",
                                                                                        "aria-haspopup": "listbox",
                                                                                        "aria-expanded": "{picker_open}",
                                                                                        title: "Add or remove assignees",
                                                                                        onclick: {
                                                                                            let current_selection = assigned_actor_ids
                                                                                                .iter()
                                                                                                .cloned()
                                                                                                .collect::<BTreeSet<_>>();
                                                                                            move |_| {
                                                                                                assignee_selected_actor_ids.set(current_selection.clone());
                                                                                                assignee_filter.set(String::new());
                                                                                                assignee_edit_status.set(String::new());
                                                                                                assignee_picker_open.set(!assignee_picker_open());
                                                                                            }
                                                                                        },
                                                                                        UiIcon { name: "plus" }
                                                                                    }
                                                                                    Button {
                                                                                        variant: ButtonVariant::Secondary,
                                                                                        r#type: "button",
                                                                                        class: "assignee-add assignee-clear",
                                                                                        "aria-label": "Clear assignees",
                                                                                        title: "Clear assignees",
                                                                                        onclick: {
                                                                                            let base = base_url.clone();
                                                                                            let realm = selected_realm_id.clone();
                                                                                            let actor = account_did.clone();
                                                                                            let current_card = card.clone();
                                                                                            move |_| {
                                                                                                assignee_selected_actor_ids.set(BTreeSet::new());
                                                                                                if dispatch_card_assignees_update(
                                                                                                    base.clone(),
                                                                                                    token,
                                                                                                    realm.clone(),
                                                                                                    actor.clone(),
                                                                                                    current_card.clone(),
                                                                                                    BTreeSet::new(),
                                                                                                    columns,
                                                                                                    selected_card,
                                                                                                    state_store,
                                                                                                    board_status,
                                                                                                    assignee_edit_status,
                                                                                                ) {
                                                                                                    assignee_picker_open.set(false);
                                                                                                    assignee_filter.set(String::new());
                                                                                                }
                                                                                            }
                                                                                        },
                                                                                        UiIcon { name: "x" }
                                                                                    }
                                                                                }
                                                                            }
                                                                            if picker_open {
                                                                                div {
                                                                                    class: "assignee-popover",
                                                                                    "data-testid": "card-detail-assignees-picker",
                                                                                    div { class: "assignee-search",
                                                                                        UiIcon { name: "search" }
                                                                                        Input {
                                                                                            class: "input",
                                                                                            "data-testid": "card-detail-assignees-search",
                                                                                            value: "{picker_filter}",
                                                                                            placeholder: "Filter members",
                                                                                            oninput: move |event: FormEvent| assignee_filter.set(event.value()),
                                                                                        }
                                                                                    }
                                                                                    div {
                                                                                        class: "assignee-options",
                                                                                        role: "listbox",
                                                                                        "aria-label": "Assignees",
                                                                                        if picker_people.is_empty() {
                                                                                            div { class: "assignee-option-empty", "No members match" }
                                                                                        } else {
                                                                                            for (actor_id, label, initial, compact_id) in picker_people.iter() {
                                                                                                {
                                                                                                    let selected = selected_actor_ids.contains(actor_id);
                                                                                                    let option_class = if selected {
                                                                                                        "assignee-option selected"
                                                                                                    } else {
                                                                                                        "assignee-option"
                                                                                                    };
                                                                                                    let target_actor_id = actor_id.clone();
                                                                                                    rsx! {
                                                                                                        Button {
                                                                                                            variant: ButtonVariant::Secondary,
                                                                                                            key: "{actor_id}",
                                                                                                            r#type: "button",
                                                                                                            class: "{option_class}",
                                                                                                            role: "option",
                                                                                                            "aria-selected": "{selected}",
                                                                                                            onclick: move |_| {
                                                                                                                let mut next = assignee_selected_actor_ids();
                                                                                                                if next.contains(&target_actor_id) {
                                                                                                                    next.remove(&target_actor_id);
                                                                                                                } else {
                                                                                                                    next.insert(target_actor_id.clone());
                                                                                                                }
                                                                                                                assignee_selected_actor_ids.set(next);
                                                                                                            },
                                                                                                            span { class: "assignee-option-check",
                                                                                                                if selected {
                                                                                                                    UiIcon { name: "check" }
                                                                                                                }
                                                                                                            }
                                                                                                            span { class: "assignee-avatar", "{initial}" }
                                                                                                            span { class: "assignee-option-main",
                                                                                                                span { class: "assignee-option-label", "{label}" }
                                                                                                                span { class: "assignee-option-meta", "{compact_id}" }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                    if !edit_status.trim().is_empty() {
                                                                                        div {
                                                                                            class: "assignee-edit-status",
                                                                                            role: "status",
                                                                                            "aria-live": "polite",
                                                                                            "{edit_status}"
                                                                                        }
                                                                                    }
                                                                                    div { class: "assignee-popover-actions",
                                                                                        Button {
                                                                                            variant: ButtonVariant::Secondary,
                                                                                            r#type: "button",
                                                                                            onclick: move |_| assignee_selected_actor_ids.set(BTreeSet::new()),
                                                                                            "Clear"
                                                                                        }
                                                                                        Button {
                                                                                            variant: ButtonVariant::Secondary,
                                                                                            r#type: "button",
                                                                                            onclick: move |_| {
                                                                                                assignee_picker_open.set(false);
                                                                                                assignee_filter.set(String::new());
                                                                                                assignee_edit_status.set(String::new());
                                                                                            },
                                                                                            {crate::i18n::tr("common.cancel")}
                                                                                        }
                                                                                        Button {
                                                                                            variant: ButtonVariant::Primary,
                                                                                            r#type: "button",
                                                                                            onclick: {
                                                                                                let base = base_url.clone();
                                                                                                let realm = selected_realm_id.clone();
                                                                                                let actor = account_did.clone();
                                                                                                let current_card = card.clone();
                                                                                                move |_| {
                                                                                                    if dispatch_card_assignees_update(
                                                                                                        base.clone(),
                                                                                                        token,
                                                                                                        realm.clone(),
                                                                                                        actor.clone(),
                                                                                                        current_card.clone(),
                                                                                                        assignee_selected_actor_ids(),
                                                                                                        columns,
                                                                                                        selected_card,
                                                                                                        state_store,
                                                                                                        board_status,
                                                                                                        assignee_edit_status,
                                                                                                    ) {
                                                                                                        assignee_picker_open.set(false);
                                                                                                        assignee_filter.set(String::new());
                                                                                                    }
                                                                                                }
                                                                                            },
                                                                                            {crate::i18n::tr("common.save")}
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                                div {
                                                                    dt { "Due" }
                                                                    dd {
                                                                        {
                                                                            let due_editor_value = editor_value_for_optional_card_field(&card.due);
                                                                            let due_has_value = !due_editor_value.is_empty();
                                                                            let due_open = due_picker_open();
                                                                            let due_status = due_edit_status();
                                                                            let selected_date = parse_due_calendar_date(&due_edit_value());
                                                                            let today_date = due_calendar_today();
                                                                            let month = due_calendar_month();
                                                                            let month_label = due_calendar_month_label(month);
                                                                            let calendar_cells = due_calendar_cells(month);
                                                                            rsx! {
                                                                                div {
                                                                                    class: "due-editor",
                                                                                    "data-testid": "card-detail-due",
                                                                                    if due_has_value {
                                                                                        span {
                                                                                            class: "due-pill",
                                                                                            title: "{due_editor_value}",
                                                                                            "{due_editor_value}"
                                                                                        }
                                                                                        Button {
                                                                                            variant: ButtonVariant::Secondary,
                                                                                            r#type: "button",
                                                                                            class: "due-edit-button",
                                                                                            "aria-label": "Edit due date",
                                                                                            "aria-haspopup": "dialog",
                                                                                            "aria-expanded": "{due_open}",
                                                                                            title: "Edit due date",
                                                                                            onclick: {
                                                                                                let current_due = due_editor_value.clone();
                                                                                                move |_| {
                                                                                                    due_edit_value.set(current_due.clone());
                                                                                                    due_calendar_month.set(due_calendar_month_for_value(&current_due));
                                                                                                    due_edit_status.set(String::new());
                                                                                                    assignee_picker_open.set(false);
                                                                                                    due_picker_open.set(!due_picker_open());
                                                                                                }
                                                                                            },
                                                                                            UiIcon { name: "calendar" }
                                                                                        }
                                                                                        Button {
                                                                                            variant: ButtonVariant::Secondary,
                                                                                            r#type: "button",
                                                                                            class: "due-edit-button due-clear-button",
                                                                                            "aria-label": "Clear due date",
                                                                                            title: "Clear due date",
                                                                                            onclick: {
                                                                                                let base = base_url.clone();
                                                                                                let realm = selected_realm_id.clone();
                                                                                                let actor = account_did.clone();
                                                                                                let device = device_id.clone();
                                                                                                let current_card = card.clone();
                                                                                                move |_| {
                                                                                                    due_edit_value.set(String::new());
                                                                                                    due_calendar_month.set(default_due_calendar_month());
                                                                                                    due_picker_open.set(true);
                                                                                                    save_card_due_edit(
                                                                                                        base.clone(),
                                                                                                        token,
                                                                                                        realm.clone(),
                                                                                                        actor.clone(),
                                                                                                        device.clone(),
                                                                                                        current_card.clone(),
                                                                                                        String::new(),
                                                                                                        selected_scope_security_encrypted,
                                                                                                        due_picker_open,
                                                                                                        due_edit_status,
                                                                                                        columns,
                                                                                                        selected_card,
                                                                                                        state_store,
                                                                                                        board_status,
                                                                                                    );
                                                                                                }
                                                                                            },
                                                                                            UiIcon { name: "x" }
                                                                                        }
                                                                                    } else {
                                                                                        Button {
                                                                                            variant: ButtonVariant::Secondary,
                                                                                            r#type: "button",
                                                                                            class: "due-add-button",
                                                                                            "aria-haspopup": "dialog",
                                                                                            "aria-expanded": "{due_open}",
                                                                                            title: "Add due date",
                                                                                            onclick: move |_| {
                                                                                                due_edit_value.set(String::new());
                                                                                                due_calendar_month.set(default_due_calendar_month());
                                                                                                due_edit_status.set(String::new());
                                                                                                assignee_picker_open.set(false);
                                                                                                due_picker_open.set(!due_picker_open());
                                                                                            },
                                                                                            UiIcon { name: "plus" }
                                                                                            span { "Add due date" }
                                                                                        }
                                                                                    }
                                                                                    if due_open {
                                                                                        div {
                                                                                            class: "due-popover",
                                                                                            "data-testid": "card-detail-due-picker",
                                                                                            div { class: "due-popover-field",
                                                                                                Label { html_for: "card-detail-due-inline-input-input", "Due date" }
                                                                                                Input {
                                                                                                    id: "card-detail-due-inline-input-input",
                                                                                                    class: "input",
                                                                                                    "data-testid": "card-detail-due-inline-input",
                                                                                                    value: "{due_edit_value}",
                                                                                                    placeholder: "YYYY-MM-DD",
                                                                                                    oninput: move |event: FormEvent| {
                                                                                                        let next = event.value();
                                                                                                        if let Some(date) = parse_due_calendar_date(&next) {
                                                                                                            due_calendar_month.set(start_of_due_calendar_month(date));
                                                                                                        }
                                                                                                        due_edit_value.set(next);
                                                                                                    },
                                                                                                }
                                                                                            }
                                                                                            div { class: "due-calendar",
                                                                                                div { class: "due-calendar-header",
                                                                                                    Button {
                                                                                                        variant: ButtonVariant::Secondary,
                                                                                                        r#type: "button",
                                                                                                        class: "due-calendar-nav",
                                                                                                        "aria-label": "Previous month",
                                                                                                        title: "Previous month",
                                                                                                        onclick: move |_| {
                                                                                                            due_calendar_month.set(add_due_calendar_months(due_calendar_month(), -1));
                                                                                                        },
                                                                                                        UiIcon { name: "chevron-left" }
                                                                                                    }
                                                                                                    strong { class: "due-calendar-title", "{month_label}" }
                                                                                                    Button {
                                                                                                        variant: ButtonVariant::Secondary,
                                                                                                        r#type: "button",
                                                                                                        class: "due-calendar-nav",
                                                                                                        "aria-label": "Next month",
                                                                                                        title: "Next month",
                                                                                                        onclick: move |_| {
                                                                                                            due_calendar_month.set(add_due_calendar_months(due_calendar_month(), 1));
                                                                                                        },
                                                                                                        UiIcon { name: "chevron-right" }
                                                                                                    }
                                                                                                }
                                                                                                div {
                                                                                                    class: "due-calendar-weekdays",
                                                                                                    span { "Sun" }
                                                                                                    span { "Mon" }
                                                                                                    span { "Tue" }
                                                                                                    span { "Wed" }
                                                                                                    span { "Thu" }
                                                                                                    span { "Fri" }
                                                                                                    span { "Sat" }
                                                                                                }
                                                                                                div {
                                                                                                    class: "due-calendar-grid",
                                                                                                    role: "grid",
                                                                                                    "aria-label": "Due date calendar",
                                                                                                    for cell in calendar_cells.iter() {
                                                                                                        {
                                                                                                            let selected = selected_date.is_some_and(|date| date == cell.date);
                                                                                                            let is_today = today_date == cell.date;
                                                                                                            let mut day_class = String::from("due-calendar-day");
                                                                                                            if !cell.in_current_month {
                                                                                                                day_class.push_str(" outside");
                                                                                                            }
                                                                                                            if is_today {
                                                                                                                day_class.push_str(" today");
                                                                                                            }
                                                                                                            if selected {
                                                                                                                day_class.push_str(" selected");
                                                                                                            }
                                                                                                            let iso_date = cell.iso_date.clone();
                                                                                                            let cell_label = format!("Select {iso_date}");
                                                                                                            rsx! {
                                                                                                                Button {
                                                                                                                    variant: ButtonVariant::Secondary,
                                                                                                                    key: "{cell.iso_date}",
                                                                                                                    r#type: "button",
                                                                                                                    class: "{day_class}",
                                                                                                                    role: "gridcell",
                                                                                                                    "aria-label": "{cell_label}",
                                                                                                                    "aria-pressed": "{selected}",
                                                                                                                    onclick: move |_| {
                                                                                                                        due_edit_value.set(iso_date.clone());
                                                                                                                        due_calendar_month.set(due_calendar_month_for_value(&iso_date));
                                                                                                                    },
                                                                                                                    "{cell.day}"
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                            if !due_status.trim().is_empty() {
                                                                                                div {
                                                                                                    class: "due-edit-status",
                                                                                                    role: "status",
                                                                                                    "aria-live": "polite",
                                                                                                    "{due_status}"
                                                                                                }
                                                                                            }
                                                                                            div { class: "due-popover-actions",
                                                                                                Button {
                                                                                                    variant: ButtonVariant::Secondary,
                                                                                                    r#type: "button",
                                                                                                    onclick: move |_| {
                                                                                                        due_edit_value.set(String::new());
                                                                                                        due_calendar_month.set(default_due_calendar_month());
                                                                                                    },
                                                                                                    "Clear"
                                                                                                }
                                                                                                Button {
                                                                                                    variant: ButtonVariant::Secondary,
                                                                                                    r#type: "button",
                                                                                                    onclick: {
                                                                                                        let cancel_due = due_editor_value.clone();
                                                                                                        move |_| {
                                                                                                            due_picker_open.set(false);
                                                                                                            due_edit_value.set(cancel_due.clone());
                                                                                                            due_calendar_month.set(due_calendar_month_for_value(&cancel_due));
                                                                                                            due_edit_status.set(String::new());
                                                                                                        }
                                                                                                    },
                                                                                                    {crate::i18n::tr("common.cancel")}
                                                                                                }
                                                                                                Button {
                                                                                                    variant: ButtonVariant::Primary,
                                                                                                    r#type: "button",
                                                                                                    onclick: {
                                                                                                        let base = base_url.clone();
                                                                                                        let realm = selected_realm_id.clone();
                                                                                                        let actor = account_did.clone();
                                                                                                        let device = device_id.clone();
                                                                                                        let current_card = card.clone();
                                                                                                        move |_| {
                                                                                                            save_card_due_edit(
                                                                                                                base.clone(),
                                                                                                                token,
                                                                                                                realm.clone(),
                                                                                                                actor.clone(),
                                                                                                                device.clone(),
                                                                                                                current_card.clone(),
                                                                                                                due_edit_value(),
                                                                                                                selected_scope_security_encrypted,
                                                                                                                due_picker_open,
                                                                                                                due_edit_status,
                                                                                                                columns,
                                                                                                                selected_card,
                                                                                                                state_store,
                                                                                                                board_status,
                                                                                                            );
                                                                                                        }
                                                                                                    },
                                                                                                    {crate::i18n::tr("common.save")}
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                        }
                                                                                    }
                                                                                }
                                                                        }
                                                                    }
                                                                }
                                                                div {
                                                                    dt { "Visibility" }
                                                                    dd { "{card.external_visibility}" }
                                                                }
                                                            }
                                                        }
                                                        div { class: "card-detail-side-section card-detail-activity", "data-testid": "card-audit-excerpt",
                                                            h3 { "Activity" }
                                                            for item in activity_items.iter() {
                                                                {
                                                                    let item_class = item.class_name();
                                                                    rsx! {
                                                                        div {
                                                                            key: "{item.key}",
                                                                            class: "{item_class}",
                                                                            span { class: "card-detail-activity-dot" }
                                                                            div { class: "card-detail-activity-body",
                                                                                strong { "{item.title}" }
                                                                                if let Some(detail) = item.detail.as_deref() {
                                                                                    span { "{detail}" }
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
                                                                        // `ck.member.identity.update` event
                                                                        // store. `None` means either no
                                                                        // identity event has been observed
                                                                        // yet, or every effective event is
                                                                        // still `decryption_pending` (MLS
                                                                        // epoch missing — MID-4 stub).
                                                                        // member_display_label falls back to
                                                                        // handle-shaped DID display, then a
                                                                        // compact DID.
                                                                        // TODO(R4): swap the decryption-pending
                                                                        // branch for an explicit muted
                                                                        // placeholder string instead of the
                                                                        // bare DID.
                                                                        let store = state_store.read();
                                                                        let identity =
                                                                            store.resolved_member_identity(&realm_context, &did);
                                                                        let cached_handle = member_handle_lookup_subject(
                                                                            row,
                                                                            identity.as_ref(),
                                                                        )
                                                                        .and_then(|subject_id| {
                                                                            store
                                                                                .cached_member_handle_lookup(
                                                                                    &subject_id,
                                                                                    Some(&realm_context),
                                                                                    row.member_display_state_digest.as_deref(),
                                                                                )
                                                                                .and_then(|entry| entry.primary_handle)
                                                                        });
                                                                        let label = member_display_label(
                                                                            row,
                                                                            identity.as_ref(),
                                                                            cached_handle.as_deref(),
                                                                        );
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
fn kanban_board_route(realm_id: &str, board_id: &str) -> Route {
    let realm_id = card_detail_route_realm_id(realm_id);
    let board_id = board_id.trim();
    if board_id.is_empty() {
        Route::KanbanRealm { realm_id }
    } else {
        Route::KanbanBoard {
            realm_id,
            board_id: board_id.to_owned(),
        }
    }
}

/// Build the URL for an open card. Prefers the board-carrying form so a
/// refresh restores the board; falls back to the board-less task route
/// when the board id is unknown.
fn kanban_card_task_route(realm_id: &str, board_id: &str, task_id: &str) -> Route {
    let realm_id = card_detail_route_realm_id(realm_id);
    let board_id = board_id.trim();
    let task_id = task_id.trim().to_owned();
    if board_id.is_empty() {
        Route::KanbanTask { realm_id, task_id }
    } else {
        Route::KanbanBoardTask {
            realm_id,
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

/// Per-member entry harvested from a cached Realm projection.
///
/// R3.2 (cokret-spec @ b56cab1) — roster entries MUST NOT carry raw
/// handle / display fields. Identity resolution happens by following
/// `identity_event_ids[]` (or inline `identity_events[]`) and applying
/// the SDK's `effective_identity_events` helper. Handle strings only ever
/// appear inside signed `ck.schema.handle_claim.v1` evidence.
///
/// `actor_id` is the actor DID. `membership` is `join` / `invite` /
/// `knock`. `identity_event_ids` are the effective
/// `ck.member.identity.update` event ids (after replacement edges).
/// `member_display_state_digest` is the roster display cache key (R3.2
/// rename of the prior `identity_state_digest`; now folds the visible
/// handle-claim digest set). `subject_id` is the disclosed principal DID
/// — present only when the server disclosed it (gates the handle-claim
/// evidence fields per the R3.2 roster dependentRequired rule).
#[derive(Clone, Debug, PartialEq)]
pub(super) struct RealmMemberRow {
    /// Actor DID. Carried as both `actor_id` and (legacy) `did`.
    pub actor_id: String,
    pub membership: Option<String>,
    pub identity_event_ids: Vec<String>,
    pub member_display_state_digest: Option<String>,
    /// R3.2 roster — disclosed principal/holder DID. `None` when the
    /// server did not disclose it (then the handle-claim fields are also
    /// absent). Drives §3.2.1 primary-handle selection + the
    /// "Why am I seeing this handle?" panel.
    pub subject_id: Option<String>,
    pub handle_claims: Vec<Value>,
    pub handle_claims_limited: bool,
}

/// Pick the best UI label for a roster row.
///
/// R3.2: prefer visible handle-claim evidence, then a fresh
/// `list_handles_for_subject` cache entry, then a materialized subject DID
/// display fallback. If no handle-shaped label is available, use the
/// resolved [`MemberIdentity`] display (via the SDK's effective-set
/// helper), then a compact actor-DID fallback so long `did:webvh:...`
/// strings don't overflow.
///
/// `identity` is the current effective [`MemberIdentity`] for this row
/// (when one has been decrypted + verified). [`None`] means the row is
/// `decryption_pending` or no identity event has been observed yet — in
/// either case we render the compact DID instead of a raw `did:...`.
fn member_display_label(
    row: &RealmMemberRow,
    identity: Option<&cokret_sdk::MemberIdentity>,
    cached_primary_handle: Option<&str>,
) -> String {
    if let Some(handle) = member_inline_handle_label(row) {
        return handle;
    }
    if let Some(handle) = cached_primary_handle.and_then(crate::identity_handle::parse_user_handle)
    {
        return handle.display;
    }
    if let Some(handle) = member_fallback_handle_label(row) {
        return handle;
    }
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

fn member_inline_handle_label(row: &RealmMemberRow) -> Option<String> {
    let subject = row.subject_id.as_deref().unwrap_or(row.actor_id.as_str());
    row.handle_claims.iter().find_map(|claim| {
        let claim_subject = json_path_string(Some(claim), &["subject"])
            .or_else(|| json_path_string(Some(claim), &["subject_id"]))?;
        if claim_subject.trim() != subject {
            return None;
        }
        let binding_state = json_path_string(Some(claim), &["binding_state"])
            .unwrap_or_else(|| "verified".to_owned());
        if !matches!(binding_state.as_str(), "verified" | "active") {
            return None;
        }
        json_path_string(Some(claim), &["handle"])
            .and_then(|raw| crate::identity_handle::parse_user_handle(&raw).map(|h| h.display))
    })
}

fn member_fallback_handle_label(row: &RealmMemberRow) -> Option<String> {
    row.subject_id
        .as_deref()
        .and_then(handle_display_from_did)
        .or_else(|| handle_display_from_did(&row.actor_id))
}

fn member_handle_lookup_subject(
    row: &RealmMemberRow,
    identity: Option<&cokret_sdk::MemberIdentity>,
) -> Option<String> {
    if let Some(subject) = row
        .subject_id
        .as_deref()
        .map(str::trim)
        .filter(|subject| subject.starts_with("did:"))
        .filter(|subject| !subject.is_empty())
    {
        return Some(subject.to_owned());
    }
    if let Some(identity) = identity {
        return Some(identity.subject_id.as_str().to_owned());
    }
    // The roster may omit `subject_id` while the current server still uses
    // the visible actor DID as the principal DID. This lookup is
    // Realm-scoped, display-only, and Directory-enforced; if the actor is a
    // pairwise/private DID the response should simply be empty and cached
    // briefly as a negative display lookup.
    let actor = row.actor_id.trim();
    actor.starts_with("did:").then(|| actor.to_owned())
}

fn member_roster_realm_context(
    selected_realm_id: &str,
    projection_realm_id: &str,
    projection: Option<&Value>,
) -> String {
    let raw = projection
        .and_then(|body| {
            json_path_string(Some(body), &["realm_id"])
                .or_else(|| json_path_string(Some(body), &["summary", "realm_id"]))
        })
        .or_else(|| {
            let trimmed = projection_realm_id.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_owned())
        })
        .unwrap_or_else(|| selected_realm_id.to_owned());
    trim_realm_id(&raw)
}

fn member_handle_fetch_key(realm_id: &str, subject_id: &str, digest: Option<&str>) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}",
        realm_id.trim(),
        subject_id.trim(),
        digest.unwrap_or("")
    )
}

#[derive(Clone, Copy)]
struct CardAuthorDisplayContext<'a> {
    realm_id: &'a str,
    member_rows: &'a [RealmMemberRow],
}

/// Collect the sorted roster of realm members from a cached space
/// projection. R3.2 roster wire shape per
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
                        handle_claims: Vec::new(),
                        handle_claims_limited: false,
                    });
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_member_rows(Some(item), out);
            }
        }
        Value::Object(map) => {
            let did = ["actor_id", "did", "principal_id", "id"]
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
            // R3.2 roster rename: `identity_state_digest` →
            // `member_display_state_digest` (no pre-R3.2 compat).
            let member_display_state_digest = map
                .get("member_display_state_digest")
                .and_then(|child| child.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            // R3.2 roster: disclosed principal/holder DID. Gates the
            // inline handle-claim evidence. dependentRequired is enforced
            // server-side; here we simply read what was disclosed.
            let subject_id = map
                .get("subject_id")
                .and_then(|child| child.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            let handle_claims = map
                .get("handle_claims")
                .and_then(Value::as_array)
                .map(|items| items.to_vec())
                .unwrap_or_default();
            let handle_claims_limited = map
                .get("handle_claims_limited")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if let Some(did) = did {
                let candidate = RealmMemberRow {
                    actor_id: did.clone(),
                    membership: membership.clone(),
                    identity_event_ids: identity_event_ids.clone(),
                    member_display_state_digest: member_display_state_digest.clone(),
                    subject_id: subject_id.clone(),
                    handle_claims: handle_claims.clone(),
                    handle_claims_limited,
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
                        if existing.handle_claims.is_empty() {
                            existing.handle_claims = handle_claims;
                        }
                        existing.handle_claims_limited |= handle_claims_limited;
                    }
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct RealmRosterPagination {
    pub members_limited: bool,
    pub members_next_cursor: Option<String>,
}

#[cfg(test)]
impl RealmRosterPagination {
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
            // 只读 canonical `actor_id` / `sender_actor_id`;legacy
            // `sender` / `author` / `created_by` 为 hard_reject,不再容忍。
            &["body", "actor_id"][..],
            &["body", "sender_actor_id"][..],
            &["payload", "actor_id"][..],
            &["actor_id"][..],
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CardActivityStatus {
    Info,
    Pending,
    Accepted,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CardActivityItem {
    key: String,
    title: String,
    detail: Option<String>,
    status: CardActivityStatus,
}

impl CardActivityItem {
    fn class_name(&self) -> &'static str {
        match self.status {
            CardActivityStatus::Info => "card-detail-activity-item",
            CardActivityStatus::Pending => "card-detail-activity-item pending",
            CardActivityStatus::Accepted => "card-detail-activity-item accepted",
            CardActivityStatus::Failed => "card-detail-activity-item failed",
        }
    }
}

fn card_activity_items(
    card: &KanbanCard,
    raw_operations: &[RawOperationRecord],
) -> Vec<CardActivityItem> {
    let mut records = raw_operations
        .iter()
        .filter(|record| raw_operation_targets_card(&record.payload, card))
        .collect::<Vec<_>>();
    records.sort_by_key(|record| std::cmp::Reverse(record.received_at));
    let mut items = records
        .into_iter()
        .filter_map(|record| card_activity_item_from_raw_operation(record, card))
        .take(5)
        .collect::<Vec<_>>();
    if items.is_empty() {
        items = projection_card_activity_items(card);
    }
    if items.is_empty() {
        items.push(CardActivityItem {
            key: "empty".to_owned(),
            title: "No visible activity yet".to_owned(),
            detail: Some("Recent server events are not loaded in this view.".to_owned()),
            status: CardActivityStatus::Info,
        });
    }
    items
}

fn projection_card_activity_items(card: &KanbanCard) -> Vec<CardActivityItem> {
    let mut items = Vec::new();
    if !card.updated_at.trim().is_empty() {
        items.push(CardActivityItem {
            key: "projection-updated".to_owned(),
            title: "Last updated".to_owned(),
            detail: Some(compact_timestamp_label(&card.updated_at)),
            status: CardActivityStatus::Info,
        });
    }
    if !card.created_at.trim().is_empty() {
        let mut detail = compact_timestamp_label(&card.created_at);
        if !card.created_by.trim().is_empty() {
            detail.push_str(" · ");
            detail.push_str(&short_protocol_id(&card.created_by));
        }
        items.push(CardActivityItem {
            key: "projection-created".to_owned(),
            title: "Created".to_owned(),
            detail: Some(detail),
            status: CardActivityStatus::Info,
        });
    }
    items
}

fn raw_operation_targets_card(payload: &Value, card: &KanbanCard) -> bool {
    let ids = [card.id.trim(), card.primary_flow_id.trim()];
    for path in [
        &["assignment_flow_id"][..],
        &["flow_id"][..],
        &["target_ref"][..],
        &["body", "flow_id"][..],
        &["body", "target_ref"][..],
        &["body", "from_ref"][..],
        &["body", "object", "id"][..],
        &["payload", "flow_id"][..],
        &["payload", "target_ref"][..],
        &["payload", "from_ref"][..],
        &["payload", "object", "id"][..],
    ] {
        if let Some(value) = json_path_string(Some(payload), path)
            && ids.iter().any(|id| !id.is_empty() && *id == value)
        {
            return true;
        }
    }
    false
}

fn card_activity_item_from_raw_operation(
    record: &RawOperationRecord,
    card: &KanbanCard,
) -> Option<CardActivityItem> {
    let payload = &record.payload;
    let kind = json_path_string(Some(payload), &["kind"])
        .or_else(|| json_path_string(Some(payload), &["wire_kind"]))?;
    let status = activity_status_from_payload(payload);
    let title = json_path_string(Some(payload), &["activity_summary"])
        .unwrap_or_else(|| activity_title_from_operation(&kind, payload, card));
    let detail = raw_operation_activity_detail(&kind, payload, record);
    Some(CardActivityItem {
        key: json_path_string(Some(payload), &["operation_id"])
            .unwrap_or_else(|| record.operation_id.clone()),
        title,
        detail: Some(detail),
        status,
    })
}

fn activity_status_from_payload(payload: &Value) -> CardActivityStatus {
    match json_path_string(Some(payload), &["write_state"])
        .unwrap_or_else(|| "queued".to_owned())
        .as_str()
    {
        "queued" | "submitted" | "optimistic" => CardActivityStatus::Pending,
        "accepted" => CardActivityStatus::Accepted,
        "failed" | "soft_failed" | "quarantined" | "conflict" => CardActivityStatus::Failed,
        _ => CardActivityStatus::Info,
    }
}

fn activity_status_label(payload: &Value) -> &'static str {
    match json_path_string(Some(payload), &["write_state"])
        .unwrap_or_else(|| "queued".to_owned())
        .as_str()
    {
        "queued" => "queued",
        "submitted" => "submitted",
        "accepted" => "accepted",
        "failed" => "failed",
        "soft_failed" => "soft failed",
        "quarantined" => "quarantined",
        "conflict" => "conflict",
        _ => "local",
    }
}

fn raw_operation_activity_detail(
    kind: &str,
    payload: &Value,
    record: &RawOperationRecord,
) -> String {
    let timestamp = json_path_string(Some(payload), &["created_at"])
        .unwrap_or_else(|| record.received_at.to_rfc3339());
    let mut parts = vec![
        kind.to_owned(),
        activity_status_label(payload).to_owned(),
        compact_timestamp_label(&timestamp),
    ];
    if let Some(actor) = json_path_string(Some(payload), &["actor_id"])
        .or_else(|| json_path_string(Some(payload), &["body", "actor_id"]))
    {
        parts.push(short_protocol_id(&actor));
    }
    if let Some(event_id) = json_path_string(Some(payload), &["event_id"]) {
        parts.push(short_protocol_id(&event_id));
    }
    parts.join(" · ")
}

fn activity_title_from_operation(kind: &str, payload: &Value, _card: &KanbanCard) -> String {
    match kind {
        "ck.relation.create" => {
            let relation_kind = json_path_string(Some(payload), &["body", "kind"])
                .or_else(|| json_path_string(Some(payload), &["body", "relation_kind"]));
            if relation_kind.as_deref() == Some("assigned_to") {
                let actor = json_path_string(Some(payload), &["assignment_actor_id"])
                    .or_else(|| json_path_string(Some(payload), &["body", "to_ref"]))
                    .map(|actor| short_protocol_id(&actor))
                    .unwrap_or_else(|| "actor".to_owned());
                format!("Assignee added: {actor}")
            } else {
                "Relation added".to_owned()
            }
        }
        "ck.relation.tombstone" => {
            if let Some(actor) = json_path_string(Some(payload), &["assignment_actor_id"]) {
                format!("Assignee removed: {}", short_protocol_id(&actor))
            } else {
                "Relation removed".to_owned()
            }
        }
        "ck.flow.update" => flow_update_activity_title(payload),
        "ck.flow.move" => "Card moved".to_owned(),
        "ck.flow.reorder" => "Card reordered".to_owned(),
        "ck.flow.create" => "Card created".to_owned(),
        _ => kind.to_owned(),
    }
}

fn flow_update_activity_title(payload: &Value) -> String {
    let patch = payload
        .get("body")
        .and_then(|body| body.get("patch"))
        .or_else(|| payload.get("payload").and_then(|body| body.get("patch")));
    if let Some(patch) = patch.and_then(Value::as_object) {
        let fields = patch
            .get("metadata.fields")
            .or_else(|| patch.get("fields"))
            .and_then(|op| {
                (op.get("$op").and_then(Value::as_str) == Some("set"))
                    .then(|| op.get("value"))
                    .flatten()
            })
            .and_then(Value::as_object);
        if let Some(fields) = fields {
            if let Some(due) = fields
                .get("due_at")
                .or_else(|| fields.get("due"))
                .and_then(Value::as_str)
                .filter(|due| !due.trim().is_empty())
            {
                return format!("Due date set to {due}");
            }
            return "Card fields updated".to_owned();
        }
        if patch.contains_key("metadata.title") || patch.contains_key("title") {
            return "Title updated".to_owned();
        }
        if patch.contains_key("metadata.summary") || patch.contains_key("summary") {
            return "Summary updated".to_owned();
        }
        if patch.contains_key("body") || patch.contains_key("synthesis") {
            return "Card content updated".to_owned();
        }
    }
    "Card updated".to_owned()
}

fn card_author_display_label(
    state_store: &LocalStateStore,
    author_context: Option<CardAuthorDisplayContext<'_>>,
    actor_id: &str,
) -> String {
    let actor_id = actor_id.trim();
    if actor_id.is_empty() {
        return "Unknown author".to_owned();
    }
    if let Some(label) = member_display_label_for_actor(state_store, author_context, actor_id) {
        return label;
    }
    display_name_for_did(state_store, actor_id)
}

fn member_display_label_for_actor(
    state_store: &LocalStateStore,
    author_context: Option<CardAuthorDisplayContext<'_>>,
    actor_id: &str,
) -> Option<String> {
    let actor_id = actor_id.trim();
    let context = author_context?;
    let realm_id = context.realm_id.trim();
    if actor_id.is_empty() || realm_id.is_empty() {
        return None;
    }
    let row = context.member_rows.iter().find(|row| {
        row.actor_id.trim() == actor_id
            || row
                .subject_id
                .as_deref()
                .map(str::trim)
                .is_some_and(|subject| subject == actor_id)
    })?;
    let identity = state_store.resolved_member_identity(realm_id, &row.actor_id);
    let cached_handle =
        member_handle_lookup_subject(row, identity.as_ref()).and_then(|subject_id| {
            state_store
                .cached_member_handle_lookup(
                    &subject_id,
                    Some(realm_id),
                    row.member_display_state_digest.as_deref(),
                )
                .and_then(|entry| entry.primary_handle)
        });
    Some(member_display_label(
        row,
        identity.as_ref(),
        cached_handle.as_deref(),
    ))
}

fn bare_member_row(actor_id: String) -> RealmMemberRow {
    RealmMemberRow {
        actor_id,
        membership: None,
        identity_event_ids: Vec::new(),
        member_display_state_digest: None,
        subject_id: None,
        handle_claims: Vec::new(),
        handle_claims_limited: false,
    }
}

fn assignment_picker_roster(
    member_rows: &[RealmMemberRow],
    card: &KanbanCard,
) -> Vec<RealmMemberRow> {
    let mut rows = BTreeMap::<String, RealmMemberRow>::new();
    for row in member_rows {
        rows.entry(row.actor_id.clone())
            .or_insert_with(|| row.clone());
    }
    for actor_id in card_assigned_actor_ids(card) {
        rows.entry(actor_id.clone())
            .or_insert_with(|| bare_member_row(actor_id));
    }
    rows.into_values().collect()
}

fn assignee_label_for_actor(
    state_store: &LocalStateStore,
    realm_context: &str,
    member_rows: &[RealmMemberRow],
    actor_id: &str,
) -> String {
    let context = CardAuthorDisplayContext {
        realm_id: realm_context,
        member_rows,
    };
    member_display_label_for_actor(state_store, Some(context), actor_id)
        .unwrap_or_else(|| display_name_for_did(state_store, actor_id))
}

fn assignee_avatar_initial(label: &str) -> String {
    label
        .chars()
        .find(|ch| ch.is_alphanumeric())
        .map(|ch| ch.to_uppercase().collect::<String>())
        .unwrap_or_else(|| "?".to_owned())
}

fn assignee_filter_matches(filter: &str, label: &str, actor_id: &str) -> bool {
    let filter = filter.trim().to_lowercase();
    if filter.is_empty() {
        return true;
    }
    label.to_lowercase().contains(&filter) || actor_id.to_lowercase().contains(&filter)
}

fn compact_timestamp_label(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "time unknown".to_owned();
    }
    if let Some((date, rest)) = trimmed.split_once('T') {
        let time = rest.trim_end_matches('Z').split('.').next().unwrap_or(rest);
        let hhmm = time.split(':').take(2).collect::<Vec<_>>().join(":");
        if !date.is_empty() && hhmm.len() >= 4 {
            return format!("{date} {hhmm}");
        }
    }
    trimmed.to_owned()
}

const SYNTHESIS_ENTRY_SEPARATOR: &str = "\n\n---\n\n";

fn split_synthesis_entry_bodies(value: &str) -> Vec<String> {
    let mut entries = Vec::<String>::new();
    let mut current = Vec::<String>::new();
    for line in value.lines() {
        if line.trim() == "---" {
            let body = current.join("\n").trim().to_owned();
            if !body.is_empty() {
                entries.push(body);
            }
            current.clear();
        } else {
            current.push(line.to_owned());
        }
    }
    let body = current.join("\n").trim().to_owned();
    if !body.is_empty() {
        entries.push(body);
    }
    entries
}

fn join_synthesis_entry_bodies(entries: Vec<String>) -> String {
    entries
        .into_iter()
        .map(|entry| entry.trim().to_owned())
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>()
        .join(SYNTHESIS_ENTRY_SEPARATOR)
}

fn synthesis_body_after_entry_edit(
    entries: &[CardSynthesisTrackEntry],
    target_entry_id: Option<&str>,
    replacement_body: &str,
) -> String {
    let replacement = replacement_body.trim();
    let mut found_target = false;
    let mut bodies = entries
        .iter()
        .filter_map(|entry| {
            if target_entry_id == Some(entry.id.as_str()) {
                found_target = true;
                (!replacement.is_empty()).then(|| replacement.to_owned())
            } else {
                let body = entry.body.trim();
                (!body.is_empty()).then(|| body.to_owned())
            }
        })
        .collect::<Vec<_>>();
    if !replacement.is_empty() && (target_entry_id.is_none() || !found_target) {
        bodies.push(replacement.to_owned());
    }
    join_synthesis_entry_bodies(bodies)
}

#[allow(clippy::too_many_arguments)]
fn reset_card_detail_edit(
    current: &KanbanCard,
    mut card_edit_title: Signal<String>,
    mut card_edit_description: Signal<String>,
    mut card_edit_body: Signal<String>,
    mut card_edit_synthesis: Signal<String>,
    mut card_edit_synthesis_target_id: Signal<Option<String>>,
    mut card_edit_labels: Signal<String>,
    mut card_edit_assignee: Signal<String>,
    mut card_edit_due: Signal<String>,
    mut editing_card_detail: Signal<bool>,
    mut card_detail_actions_open: Signal<bool>,
    mut card_synthesis_history_open_id: Signal<Option<String>>,
    mut card_synthesis_selected_revision_id: Signal<Option<String>>,
    mut card_detail_edit_status: Signal<String>,
) {
    let draft = card_detail_draft_from_card(current);
    card_edit_title.set(draft.title);
    card_edit_description.set(draft.description);
    card_edit_body.set(draft.body);
    card_edit_synthesis.set(draft.synthesis);
    card_edit_synthesis_target_id.set(None);
    card_edit_labels.set(draft.labels.join(", "));
    card_edit_assignee.set(draft.assignee);
    card_edit_due.set(draft.due);
    editing_card_detail.set(false);
    card_detail_actions_open.set(false);
    card_synthesis_history_open_id.set(None);
    card_synthesis_selected_revision_id.set(None);
    card_detail_edit_status.set(String::new());
}

#[allow(clippy::too_many_arguments)]
fn save_card_detail_edit(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    device_id: String,
    current: KanbanCard,
    synthesis_entries: Vec<CardSynthesisTrackEntry>,
    // R4: three-state security signal (see `kanban_plaintext_block_reason`).
    scope_security_encrypted: Option<bool>,
    card_edit_scope: Signal<CardEditScope>,
    card_edit_title: Signal<String>,
    card_edit_description: Signal<String>,
    card_edit_body: Signal<String>,
    card_edit_synthesis: Signal<String>,
    card_edit_synthesis_target_id: Signal<Option<String>>,
    card_edit_labels: Signal<String>,
    card_edit_assignee: Signal<String>,
    card_edit_due: Signal<String>,
    mut editing_card_detail: Signal<bool>,
    mut card_detail_actions_open: Signal<bool>,
    mut card_detail_edit_status: Signal<String>,
    columns: Signal<Vec<KanbanColumn>>,
    selected_card: Signal<Option<KanbanCard>>,
    state_store: Signal<LocalStateStore>,
    board_status: Signal<String>,
) {
    card_detail_edit_status.set("Saving...".to_owned());
    let edit_scope = card_edit_scope();
    let synthesis_target_id = card_edit_synthesis_target_id();
    let synthesis_revision_body = card_edit_synthesis().trim().to_owned();
    let synthesis_for_save = if edit_scope == CardEditScope::Synthesis {
        synthesis_body_after_entry_edit(
            &synthesis_entries,
            synthesis_target_id.as_deref(),
            &synthesis_revision_body,
        )
    } else {
        synthesis_revision_body.clone()
    };
    let draft = CardDetailDraft {
        title: card_edit_title().trim().to_owned(),
        description: card_edit_description().trim().to_owned(),
        body: card_edit_body().trim().to_owned(),
        synthesis: synthesis_for_save,
        labels: parse_card_labels(&card_edit_labels()),
        assignee: card_edit_assignee().trim().to_owned(),
        due: card_edit_due().trim().to_owned(),
    };
    let synthesis_revision =
        (edit_scope == CardEditScope::Synthesis).then_some(synthesis_revision_body);
    if dispatch_card_detail_update(
        base_url,
        token,
        realm_id,
        actor_id,
        device_id,
        current,
        draft,
        scope_security_encrypted,
        synthesis_target_id,
        synthesis_revision,
        columns,
        selected_card,
        state_store,
        board_status,
    ) {
        card_detail_edit_status.set(String::new());
        editing_card_detail.set(false);
        card_detail_actions_open.set(false);
    } else {
        let status = board_status();
        card_detail_edit_status.set(if status.trim().is_empty() {
            "Unable to save changes.".to_owned()
        } else {
            status
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn save_card_due_edit(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    device_id: String,
    current: KanbanCard,
    due_value: String,
    scope_security_encrypted: Option<bool>,
    mut due_picker_open: Signal<bool>,
    mut due_edit_status: Signal<String>,
    columns: Signal<Vec<KanbanColumn>>,
    selected_card: Signal<Option<KanbanCard>>,
    state_store: Signal<LocalStateStore>,
    board_status: Signal<String>,
) -> bool {
    let mut draft = card_detail_draft_from_card(&current);
    draft.due = due_value.trim().to_owned();
    due_edit_status.set("Saving...".to_owned());
    if dispatch_card_detail_update(
        base_url,
        token,
        realm_id,
        actor_id,
        device_id,
        current,
        draft,
        scope_security_encrypted,
        None,
        None,
        columns,
        selected_card,
        state_store,
        board_status,
    ) {
        due_edit_status.set(String::new());
        due_picker_open.set(false);
        true
    } else {
        let status = board_status();
        due_edit_status.set(if status.trim().is_empty() {
            "Unable to save due date.".to_owned()
        } else {
            status
        });
        false
    }
}

fn projection_synthesis_revision(
    card: &KanbanCard,
    index: usize,
    body: String,
    state_store: &LocalStateStore,
    author_context: Option<CardAuthorDisplayContext<'_>>,
) -> CardSynthesisRevision {
    let actor_id = card.created_by.trim().to_owned();
    let timestamp = if !card.updated_at.trim().is_empty() {
        card.updated_at.clone()
    } else {
        card.created_at.clone()
    };
    let author_label = card_author_display_label(state_store, author_context, &actor_id);
    CardSynthesisRevision {
        id: format!("{}:projection-synthesis:{index}", card.id),
        body,
        actor_id,
        author_label,
        timestamp_label: compact_timestamp_label(&timestamp),
        sort_key: timestamp,
    }
}

fn synthesis_revision_from_raw_operation(
    record: &RawOperationRecord,
    state_store: &LocalStateStore,
    author_context: Option<CardAuthorDisplayContext<'_>>,
) -> Option<(String, String, CardSynthesisRevision)> {
    let update = local_card_update_from_raw_operation(record, None)?;
    let payload = &record.payload;
    let body = json_path_string(Some(payload), &["synthesis_revision_body"])
        .or(match update.synthesis {
            Some(PrivateFieldOverlay::Set(value)) => Some(value),
            _ => None,
        })
        .unwrap_or_default();
    if body.trim().is_empty() {
        return None;
    }
    let actor_id = json_path_string(Some(payload), &["actor_id"])
        .or_else(|| json_path_string(Some(payload), &["body", "actor_id"]))
        .or_else(|| json_path_string(Some(payload), &["payload", "actor_id"]))
        .unwrap_or_default();
    let timestamp = json_path_string(Some(payload), &["created_at"])
        .or_else(|| json_path_string(Some(payload), &["body", "created_at"]))
        .or_else(|| json_path_string(Some(payload), &["payload", "created_at"]))
        .unwrap_or_else(|| {
            record
                .received_at
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        });
    let author_label = card_author_display_label(state_store, author_context, &actor_id);
    let entry_id = json_path_string(Some(payload), &["synthesis_entry_id"])
        .unwrap_or_else(|| format!("{}:synthesis", update.flow_id));
    Some((
        update.flow_id,
        entry_id,
        CardSynthesisRevision {
            id: record.operation_id.clone(),
            body,
            actor_id,
            author_label,
            timestamp_label: compact_timestamp_label(&timestamp),
            sort_key: timestamp,
        },
    ))
}

fn synthesis_entry_from_revisions(
    entry_id: String,
    mut revisions: Vec<CardSynthesisRevision>,
) -> Option<CardSynthesisTrackEntry> {
    revisions.sort_by(|left, right| {
        left.sort_key
            .cmp(&right.sort_key)
            .then(left.id.cmp(&right.id))
    });
    revisions.dedup_by(|left, right| left.id == right.id);
    let latest = revisions.last()?.clone();
    Some(CardSynthesisTrackEntry {
        id: entry_id,
        body: latest.body.clone(),
        actor_id: latest.actor_id.clone(),
        author_label: latest.author_label.clone(),
        timestamp_label: latest.timestamp_label.clone(),
        sort_key: latest.sort_key.clone(),
        edited: revisions.len() > 1,
        revisions,
    })
}

#[cfg(test)]
fn card_synthesis_track_entries(
    card: &KanbanCard,
    raw_operations: &[RawOperationRecord],
    state_store: &LocalStateStore,
) -> Vec<CardSynthesisTrackEntry> {
    card_synthesis_track_entries_with_author_context(card, raw_operations, state_store, None)
}

fn card_synthesis_track_entries_with_author_context(
    card: &KanbanCard,
    raw_operations: &[RawOperationRecord],
    state_store: &LocalStateStore,
    author_context: Option<CardAuthorDisplayContext<'_>>,
) -> Vec<CardSynthesisTrackEntry> {
    let mut grouped = BTreeMap::<String, Vec<CardSynthesisRevision>>::new();
    for (_, entry_id, revision) in raw_operations
        .iter()
        .filter_map(|record| {
            synthesis_revision_from_raw_operation(record, state_store, author_context)
        })
        .filter(|(flow_id, ..)| flow_id == &card.id)
    {
        grouped.entry(entry_id).or_default().push(revision);
    }
    let mut raw_entries = grouped
        .into_iter()
        .filter_map(|(entry_id, revisions)| synthesis_entry_from_revisions(entry_id, revisions))
        .collect::<Vec<_>>();
    raw_entries.sort_by(|left, right| {
        left.sort_key
            .cmp(&right.sort_key)
            .then(left.id.cmp(&right.id))
    });

    let current_bodies = split_synthesis_entry_bodies(&card.synthesis);
    if current_bodies.is_empty() {
        return raw_entries;
    }

    let mut raw_used = vec![false; raw_entries.len()];
    let mut entries = Vec::<CardSynthesisTrackEntry>::new();
    let single_entry_history = current_bodies.len() == 1 && raw_entries.len() == 1;
    for (index, current_body) in current_bodies.into_iter().enumerate() {
        let current_trimmed = current_body.trim().to_owned();
        let matched_index = raw_entries
            .iter()
            .enumerate()
            .find_map(|(raw_index, entry)| {
                (!raw_used[raw_index] && entry.body.trim() == current_trimmed).then_some(raw_index)
            })
            .or_else(|| single_entry_history.then_some(0));

        if let Some(raw_index) = matched_index {
            raw_used[raw_index] = true;
            let mut entry = raw_entries[raw_index].clone();
            if entry.body.trim() != current_trimmed {
                entry.revisions.push(projection_synthesis_revision(
                    card,
                    index,
                    current_body,
                    state_store,
                    author_context,
                ));
                if let Some(rebuilt) =
                    synthesis_entry_from_revisions(entry.id.clone(), entry.revisions.clone())
                {
                    entry = rebuilt;
                }
            }
            entries.push(entry);
        } else {
            let revision = projection_synthesis_revision(
                card,
                index,
                current_body,
                state_store,
                author_context,
            );
            if let Some(entry) = synthesis_entry_from_revisions(
                format!("{}:synthesis:{index}", card.id),
                vec![revision],
            ) {
                entries.push(entry);
            }
        }
    }
    entries
}

fn card_detail_route_realm_id(realm_id: &str) -> String {
    let realm_id = realm_id.trim();
    if realm_id.is_empty() {
        DEMO_BOARD_SPACE_ID.to_owned()
    } else {
        realm_id.to_owned()
    }
}

fn kanban_card_detail_board_route(realm_id: &str, board_id: &str) -> Route {
    let realm_id = realm_id.trim();
    if realm_id.is_empty() {
        Route::Kanban
    } else {
        kanban_board_route(realm_id, board_id)
    }
}

fn card_detail_tab_slug(tab: CardDetailContentTab) -> &'static str {
    match tab {
        CardDetailContentTab::Description => "description",
        CardDetailContentTab::Synthesis => "synthesis",
        CardDetailContentTab::Discussion => "discussion",
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
fn card_detail_tab_from_slug(value: &str) -> Option<CardDetailContentTab> {
    match value.trim().to_ascii_lowercase().as_str() {
        "description" => Some(CardDetailContentTab::Description),
        "synthesis" => Some(CardDetailContentTab::Synthesis),
        "discussion" => Some(CardDetailContentTab::Discussion),
        _ => None,
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
fn card_detail_tab_from_href(href: &str) -> Option<CardDetailContentTab> {
    let url = url::Url::parse(href).ok()?;
    url.query_pairs()
        .find_map(|(key, value)| (key == "tab").then(|| card_detail_tab_from_slug(&value)))
        .flatten()
}

#[cfg(target_arch = "wasm32")]
fn card_detail_tab_from_current_url() -> CardDetailContentTab {
    web_sys::window()
        .and_then(|window| window.location().href().ok())
        .as_deref()
        .and_then(card_detail_tab_from_href)
        .unwrap_or_default()
}

#[cfg(not(target_arch = "wasm32"))]
fn card_detail_tab_from_current_url() -> CardDetailContentTab {
    CardDetailContentTab::default()
}

fn replace_card_detail_tab_query(tab: CardDetailContentTab) {
    let Ok(encoded_slug) = serde_json::to_string(card_detail_tab_slug(tab)) else {
        return;
    };
    let script = format!(
        r#"
(() => {{
  const tab = {encoded_slug};
  const url = new URL(window.location.href);
  if (!url.pathname.includes("/task/")) {{
    return;
  }}
  url.searchParams.set("tab", tab);
  window.history.replaceState(null, "", `${{url.pathname}}${{url.search}}${{url.hash}}`);
}})();
"#
    );
    let _ = document::eval(&script);
}

fn flow_detail_deep_link_path(realm_id: &str, flow_id: &str) -> String {
    format!(
        "/kanban/{}/task/{}",
        card_detail_route_realm_id(realm_id),
        flow_id.trim()
    )
}

fn flow_detail_deep_link_path_with_tab(
    realm_id: &str,
    flow_id: &str,
    tab: CardDetailContentTab,
) -> String {
    format!(
        "{}?tab={}",
        flow_detail_deep_link_path(realm_id, flow_id),
        card_detail_tab_slug(tab)
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct DueCalendarCell {
    date: NaiveDate,
    day: u32,
    in_current_month: bool,
    iso_date: String,
}

fn default_due_calendar_month() -> NaiveDate {
    start_of_due_calendar_month(due_calendar_today())
}

fn due_calendar_today() -> NaiveDate {
    chrono::Utc::now().date_naive()
}

fn start_of_due_calendar_month(date: NaiveDate) -> NaiveDate {
    date.with_day(1).expect("every month has day one")
}

fn due_calendar_month_for_value(value: &str) -> NaiveDate {
    parse_due_calendar_date(value)
        .map(start_of_due_calendar_month)
        .unwrap_or_else(default_due_calendar_month)
}

fn parse_due_calendar_date(value: &str) -> Option<NaiveDate> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    NaiveDate::parse_from_str(trimmed, "%Y-%m-%d")
        .ok()
        .or_else(|| {
            chrono::DateTime::parse_from_rfc3339(trimmed)
                .ok()
                .map(|timestamp| timestamp.date_naive())
        })
}

fn due_calendar_month_label(month: NaiveDate) -> String {
    month.format("%B %Y").to_string()
}

fn add_due_calendar_months(month: NaiveDate, delta: i32) -> NaiveDate {
    let month = start_of_due_calendar_month(month);
    let index = month.year() * 12 + month.month0() as i32 + delta;
    let year = index.div_euclid(12);
    let month0 = index.rem_euclid(12);
    NaiveDate::from_ymd_opt(year, month0 as u32 + 1, 1).unwrap_or(month)
}

fn due_calendar_cells(month: NaiveDate) -> Vec<DueCalendarCell> {
    let month = start_of_due_calendar_month(month);
    let first_weekday_offset = month.weekday().num_days_from_sunday() as i64;
    let first_cell = month - Duration::days(first_weekday_offset);
    (0..42)
        .map(|offset| {
            let date = first_cell + Duration::days(offset);
            DueCalendarCell {
                date,
                day: date.day(),
                in_current_month: date.year() == month.year() && date.month() == month.month(),
                iso_date: date.format("%Y-%m-%d").to_string(),
            }
        })
        .collect()
}

fn card_summary_text(summary: &str) -> String {
    summary.split_whitespace().collect::<Vec<_>>().join(" ")
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
    if trimmed.is_empty() || trimmed == "—" || trimmed.eq_ignore_ascii_case("unscheduled") {
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

fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
}

fn value_is_plaintext_private_content(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(text) => !text.trim().is_empty(),
        Value::Array(values) => !values.is_empty(),
        Value::Object(object) => {
            let encrypted_profile = object
                .get("profile")
                .and_then(Value::as_str)
                .is_some_and(|profile| profile == "ck.profile.encrypted_envelope.v1");
            !(encrypted_profile
                || object.contains_key("encrypted_content")
                || object.contains_key("ciphertext"))
        }
        Value::Bool(_) | Value::Number(_) => true,
    }
}

fn patch_op_plaintext_value(value: &Value) -> bool {
    if let Some(object) = value.as_object()
        && object.get("$op").and_then(Value::as_str) == Some("unset")
    {
        return false;
    }
    value.get("value").map_or_else(
        || value_is_plaintext_private_content(value),
        value_is_plaintext_private_content,
    )
}

fn patch_value_contains_private_path(value: &Value, path: &str) -> bool {
    let Some(candidate) = value.get("value").unwrap_or(value).pointer(&format!(
        "/{}",
        path.split('.').collect::<Vec<_>>().join("/")
    )) else {
        return false;
    };
    value_is_plaintext_private_content(candidate)
}

fn patch_touches_private_paths(payload: &Value, private_paths: &[&str]) -> bool {
    payload
        .get("patch")
        .and_then(Value::as_object)
        .is_some_and(|patch| {
            patch.iter().any(|(key, value)| {
                private_paths.iter().any(|private_path| {
                    if key == private_path || key.starts_with(&format!("{private_path}.")) {
                        patch_op_plaintext_value(value)
                    } else if let Some(suffix) = private_path.strip_prefix(&format!("{key}.")) {
                        patch_value_contains_private_path(value, suffix)
                    } else {
                        false
                    }
                })
            })
        })
}

fn kanban_event_carries_plaintext_private_content(event: &crate::operation::EventEnvelope) -> bool {
    match event.kind.as_str() {
        "ck.flow.create" => [
            &["body"][..],
            &["object", "body"][..],
            &["synthesis"][..],
            &["object", "synthesis"][..],
            &["content"][..],
            &["object", "content"][..],
            &["attachments"][..],
            &["object", "attachments"][..],
            &["fields", "body"][..],
            &["object", "fields", "body"][..],
            &["fields", "synthesis"][..],
            &["object", "fields", "synthesis"][..],
        ]
        .iter()
        .any(|path| {
            value_at_path(&event.payload, path).is_some_and(value_is_plaintext_private_content)
        }),
        "ck.flow.update" => {
            patch_touches_private_paths(&event.payload, KANBAN_PRIVATE_FLOW_PATCH_PATHS)
        }
        _ => false,
    }
}

/// Event kinds that carry ONLY non-secret structural metadata (container
/// title / kind / parent / rank) and therefore MUST submit to the server as
/// plaintext even inside an encrypted Realm. Container creation (`ck.space.create`
/// for Board and List) is the canonical example: a second device needs the
/// plaintext title to render the Board/List name instead of falling back to
/// `generated_board_fallback_title` (`ck:space:...`). Only Flow card private
/// content fields (body / synthesis / discussion) are E2EE — never the
/// container scaffold. Exempting these kinds here is a hard invariant: it
/// guarantees the plaintext-block decision can never silently drop a container
/// create, regardless of what `kanban_event_carries_plaintext_private_content`
/// matches in the future. See _next.md X13.
const KANBAN_PLAINTEXT_METADATA_KINDS: &[&str] = &["ck.space.create"];

/// R4 fail-closed reason surfaced when the Realm security projection has not
/// synced yet and we cannot prove the scope is plaintext. Mirrors the
/// `kanban.security_not_ready` i18n key.
const SECURITY_STATE_NOT_READY_REASON: &str =
    "Security state not ready; please retry shortly before writing to this Realm.";

/// R4 (fail-closed): `scope_security_encrypted` is a THREE-STATE value:
/// - `Some(true)`  — the scope's security projection is known-encrypted.
/// - `Some(false)` — the scope's security projection is known-plaintext (a legitimate plaintext
///   Realm); plaintext writes are allowed.
/// - `None`        — the security projection is MISSING / not yet synced (first paint, incremental
///   window, projection gap). We do NOT know whether the Realm requires E2EE, so we MUST NOT
///   default to plaintext. Block the write and ask the user to retry once the projection lands;
///   otherwise a private field bound for an encrypted Realm could leak in plaintext while the
///   projection is still in flight.
fn kanban_plaintext_block_reason(
    scope_security_encrypted: Option<bool>,
    event: &crate::operation::EventEnvelope,
) -> Option<String> {
    match scope_security_encrypted {
        // Known plaintext Realm — legitimate plaintext write, never block.
        Some(false) => None,
        // Unknown security state — fail-closed: block plaintext private
        // content until the projection is ready. Container scaffold writes
        // (non-secret metadata) are still exempt below.
        None => {
            if !kanban_event_carries_plaintext_private_content(event) {
                return None;
            }
            if KANBAN_PLAINTEXT_METADATA_KINDS.contains(&event.kind.as_str()) {
                return None;
            }
            // NB: kept as a plain string (not `i18n::tr`) so this pure guard
            // stays callable outside a Dioxus runtime (unit tests). The
            // localized copy lives under the `kanban.security_not_ready` key
            // for any UI surface that wants to translate it.
            Some(SECURITY_STATE_NOT_READY_REASON.to_owned())
        }
        // Known encrypted Realm — block plaintext private content.
        Some(true) => {
            if !kanban_event_carries_plaintext_private_content(event) {
                return None;
            }
            // Container scaffold writes (board/list title, kind, parent,
            // rank) are non-secret metadata and ALWAYS submit via the normal
            // plaintext event path even in an encrypted Realm. Never block.
            if KANBAN_PLAINTEXT_METADATA_KINDS.contains(&event.kind.as_str()) {
                return None;
            }
            kanban_plaintext_block_reason_for_kind(true, &event.kind)
        }
    }
}

fn kanban_plaintext_block_reason_for_kind(
    scope_security_encrypted: bool,
    kind: &str,
) -> Option<String> {
    if !scope_security_encrypted {
        return None;
    }
    Some(format!(
        "Encrypted Realm blocks plaintext {} payload; Kanban encrypted write support is required before this event can leave the client.",
        kind
    ))
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
        patch.insert(
            "metadata.title".to_owned(),
            json!({ "$op": "set", "value": title }),
        );
    }

    let description = draft.description.trim();
    if current.description.trim() != description {
        let op = if description.is_empty() {
            json!({ "$op": "unset" })
        } else {
            json!({ "$op": "set", "value": description })
        };
        patch.insert("metadata.summary".to_owned(), op);
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

    let current_due = editor_value_for_optional_card_field(&current.due);
    let fields_changed = current.labels != draft.labels || current_due != draft.due.trim();
    if fields_changed {
        let mut fields = Map::new();
        fields.insert("labels".to_owned(), json!(draft.labels.clone()));
        let due = draft.due.trim();
        if !due.is_empty() && due != "—" {
            fields.insert("due_at".to_owned(), json!(due));
        }
        patch.insert(
            "metadata.fields".to_owned(),
            json!({ "$op": "set", "value": Value::Object(fields) }),
        );
    }

    if patch.is_empty() {
        return Err("no card detail changes to save".to_owned());
    }
    Ok(Value::Object(patch))
}

fn card_detail_activity_summary(current: &KanbanCard, draft: &CardDetailDraft) -> String {
    let current_due = editor_value_for_optional_card_field(&current.due);
    let next_due = draft.due.trim();
    if current_due != next_due {
        return if next_due.is_empty() || next_due == "—" {
            "Due date cleared".to_owned()
        } else {
            format!("Due date set to {next_due}")
        };
    }
    if current.labels != draft.labels {
        return "Labels updated".to_owned();
    }
    if current.title.trim() != draft.title.trim()
        || current.description.trim() != draft.description.trim()
        || current.body.trim() != draft.body.trim()
        || current.synthesis.trim() != draft.synthesis.trim()
    {
        return "Card details updated".to_owned();
    }
    "Card updated".to_owned()
}

fn apply_card_detail_draft(card: &mut KanbanCard, draft: &CardDetailDraft) {
    card.title = draft.title.trim().to_owned();
    card.description = draft.description.trim().to_owned();
    card.body = draft.body.trim().to_owned();
    card.synthesis = draft.synthesis.trim().to_owned();
    card.labels = draft.labels.clone();
    card.due = display_optional_card_field(&draft.due);
    card.state = CardState::Queued;
}

fn kanban_private_patch_path(path: &str) -> bool {
    KANBAN_PRIVATE_FLOW_PATCH_PATHS
        .iter()
        .any(|private_path| path == *private_path || path.starts_with(&format!("{private_path}.")))
}

fn patch_plaintext_value_bytes(value: &Value) -> Result<Option<Vec<u8>>, String> {
    if let Some(object) = value.as_object()
        && object.get("$op").and_then(Value::as_str) == Some("unset")
    {
        return Ok(None);
    }
    let candidate = value.get("value").unwrap_or(value);
    if !value_is_plaintext_private_content(candidate) {
        return Ok(None);
    }
    serde_json::to_vec(candidate)
        .map(Some)
        .map_err(|err| format!("cannot serialize private patch value for encryption: {err}"))
}

fn collect_encryptable_private_patch_values(
    patch: &Value,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let Some(object) = patch.as_object() else {
        return Ok(Vec::new());
    };
    let mut values = Vec::new();
    for (path, patch_value) in object {
        if !kanban_private_patch_path(path) {
            continue;
        }
        if let Some(bytes) = patch_plaintext_value_bytes(patch_value)? {
            values.push((path.clone(), bytes));
        }
    }
    Ok(values)
}

fn replace_private_patch_values(
    patch: &mut Value,
    paths: &[String],
    encrypted_values: Vec<Value>,
) -> Result<(), String> {
    if paths.len() != encrypted_values.len() {
        return Err("internal: encrypted patch value count mismatch".to_owned());
    }
    let Some(object) = patch.as_object_mut() else {
        return Ok(());
    };
    for (path, encrypted_value) in paths.iter().zip(encrypted_values) {
        let Some(patch_value) = object.get_mut(path) else {
            return Err(format!("internal: missing private patch path {path}"));
        };
        if let Some(value) = patch_value.get_mut("value") {
            *value = encrypted_value;
        } else {
            *patch_value = encrypted_value;
        }
    }
    Ok(())
}

fn kanban_sha256_hash_from_ref(value: &str) -> Option<String> {
    if let Some(hex) = value.strip_prefix("sha256:")
        && hex.len() == 64
        && hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Some(value.to_owned());
    }
    for prefix in ["ck:anchor:", "ck:state:"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            return kanban_sha256_hash_from_ref(rest);
        }
    }
    None
}

fn kanban_object_ref_from_anchor_ref(value: &str) -> Option<String> {
    if value.starts_with("ck:event:") && cokret_sdk::EventId::new(value.to_owned()).is_ok() {
        return Some(value.to_owned());
    }
    if value.starts_with("ck:blob:sha256:")
        && value
            .strip_prefix("ck:blob:")
            .and_then(kanban_sha256_hash_from_ref)
            .is_some()
    {
        return Some(value.to_owned());
    }
    if let Some(hash) = kanban_sha256_hash_from_ref(value) {
        return Some(hash);
    }
    None
}

fn kanban_mls_base_epoch_ref(anchor_view: &LocalAnchorView, realm_id: &str) -> String {
    anchor_view
        .frontier
        .iter()
        .chain(anchor_view.leaves.iter())
        .chain(anchor_view.state_root.iter())
        .find_map(|value| kanban_object_ref_from_anchor_ref(value))
        .unwrap_or_else(|| {
            crate::canonical::canonical_sha256(&json!({
                "kind": "kanban_mls_base_epoch",
                "realm_id": realm_id,
                "epoch": anchor_view.mls_epoch.unwrap_or(0),
            }))
            .unwrap_or_else(|_| {
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned()
            })
        })
}

fn kanban_mls_membership_frontier(
    anchor_view: &LocalAnchorView,
    fallback_event_id: &cokret_sdk::EventId,
) -> Vec<cokret_sdk::EventId> {
    let mut frontier = anchor_view
        .frontier
        .iter()
        .chain(anchor_view.leaves.iter())
        .filter_map(|value| cokret_sdk::EventId::new(value.clone()).ok())
        .collect::<Vec<_>>();
    if frontier.is_empty() {
        frontier.push(fallback_event_id.clone());
    }
    frontier.sort();
    frontier.dedup();
    frontier
}

fn kanban_mls_policy_root(
    anchor_view: &LocalAnchorView,
    realm_id: &str,
) -> Result<cokret_sdk::Hash, String> {
    let hash = anchor_view
        .state_root
        .as_deref()
        .and_then(kanban_sha256_hash_from_ref)
        .unwrap_or_else(|| {
            crate::canonical::canonical_sha256(&json!({
                "kind": "kanban_mls_policy_root",
                "realm_id": realm_id,
                "frontier": anchor_view.frontier,
                "state_root": anchor_view.state_root,
            }))
            .unwrap_or_else(|_| {
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned()
            })
        });
    cokret_sdk::Hash::new(hash).map_err(|err| format!("invalid MLS policy root hash: {err:?}"))
}

fn projection_creator_matches_actor(projection: &Value, actor_id: &str) -> bool {
    let actor = actor_id.trim();
    if actor.is_empty() {
        return false;
    }
    for source in [
        projection,
        projection.get("summary").unwrap_or(&Value::Null),
        projection.get("object").unwrap_or(&Value::Null),
        projection.get("realm").unwrap_or(&Value::Null),
        projection.get("metadata").unwrap_or(&Value::Null),
    ] {
        for key in [
            "owner",
            "created_by",
            "created_by_principal",
            "creator",
            "creator_did",
        ] {
            if json_path_string(Some(source), &[key]).as_deref() == Some(actor) {
                return true;
            }
        }
    }
    false
}

fn ensure_creator_mls_snapshot_for_encrypted_scope(
    state_store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> Result<Option<crate::mls::runtime::InitialMlsSnapshotSummary>, String> {
    if state_store.mls_snapshot_for(realm_id).is_some() {
        return Ok(None);
    }
    let state = state_store.load();
    let Some(projection) = crate::security_state::security_projection_for_scope_id(
        &state.realm_tree_projections,
        realm_id,
    ) else {
        return Ok(None);
    };
    if !crate::security_state::realm_projection_is_encrypted(projection)
        || !projection_creator_matches_actor(projection, actor_id)
    {
        return Ok(None);
    }
    crate::mls::runtime::ensure_creator_mls_snapshot(
        state_store,
        secure_store,
        realm_id,
        actor_id,
        device_id,
    )
    .map_err(|err| err.user_message())
}

/// Build the `ck.mls.genesis` [`EventEnvelope`] for a creator group that has a
/// local snapshot but whose genesis has not yet been submitted to soland.
///
/// Returns `None` when genesis was already emitted for this Realm (idempotent —
/// see [`LocalStateStore::mls_genesis_emitted_for`]) or when there is no local
/// snapshot. `fresh_summary` carries the just-created group's epoch-0 ratchet
/// tree / schedule hash captured by `ensure_creator_mls_snapshot`; genesis MUST
/// describe the group at epoch 0, so this builder only emits when that fresh
/// epoch-0 material is available (the normal create-then-first-write path).
///
/// The genesis governance binding installs epoch `0 -> 0` and mirrors the
/// commit path's realm_id / membership_frontier / policy_root derivation.
pub(crate) fn build_creator_mls_genesis_event(
    state_store: &LocalStateStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    fresh_summary: Option<&crate::mls::runtime::InitialMlsSnapshotSummary>,
) -> Result<Option<crate::operation::EventEnvelope>, String> {
    if state_store.mls_genesis_emitted_for(realm_id) {
        return Ok(None);
    }
    // Genesis describes the group at epoch 0. We can only build a
    // contract-correct genesis from the just-created epoch-0 material; once the
    // group has committed past epoch 0 the epoch-0 ratchet tree is gone. The
    // server lazily defaults a never-seen group to epoch 0 anyway, so missing
    // this window is non-fatal (commits still work).
    let Some(summary) = fresh_summary else {
        return Ok(None);
    };
    if summary.realm_id != realm_id {
        return Ok(None);
    }
    let anchor_view = state_store.anchor_view_for_realm(realm_id);
    let event_id = format!("ck:event:{}", uuid_v7());
    let event_id_typed = cokret_sdk::EventId::new(event_id.clone())
        .map_err(|err| format!("invalid MLS genesis event id: {err:?}"))?;
    let typed_realm_id = cokret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|err| format!("invalid MLS genesis Realm id: {err:?}"))?;
    let governance_binding = cokret_sdk::MlsGovernanceBindingPayload::realm(
        typed_realm_id,
        summary.group_id.clone(),
        0,
        0,
        kanban_mls_membership_frontier(&anchor_view, &event_id_typed),
        kanban_mls_policy_root(&anchor_view, realm_id)?,
    )
    .map_err(|err| format!("MLS genesis governance binding failed: {err}"))?;
    let payload = crate::mls::runtime::build_mls_genesis_payload(
        summary,
        actor_id,
        device_id,
        &governance_binding,
    )
    .map_err(|err| err.user_message())?;
    let mut event = crate::operation::ck_ops::mls_genesis_with_governance(
        realm_id,
        actor_id,
        &summary.group_id,
        &payload,
    )
    .build("yougen");
    event.event_id = event_id;
    Ok(Some(event))
}

// pub(crate): the realm_admin epoch-rotation button (YOU-01-009) reuses
// this builder to wrap a forced `self_update_commit` into the canonical
// `ck.mls.commit` event with the governance binding.
pub(crate) fn kanban_mls_commit_event_from_store(
    state_store: &LocalStateStore,
    realm_id: &str,
    actor_id: &str,
    _schedule_hash: &cokret_sdk::Hash,
    commit_envelope: &cokret_sdk::MlsCommitEnvelope,
) -> Result<crate::operation::EventEnvelope, String> {
    let anchor_view = state_store.anchor_view_for_realm(realm_id);
    // `base_epoch` MUST be the SDK group's PRE-commit epoch so the
    // `next_epoch == base_epoch + 1` invariant holds by construction.
    // `commit_envelope.epoch` is the POST-commit epoch (`self_update_commit`
    // merges the pending commit before reading it), so the pre-commit epoch is
    // exactly one less. Deriving `base_epoch` from `anchor_view.mls_epoch`
    // instead — which only refreshes on `/sync` — drifts whenever the local
    // snapshot has advanced past the last server-confirmed epoch, which is what
    // tripped `mls_commit_payload.next_epoch must equal base_epoch + 1`.
    let prev_epoch = commit_envelope.epoch.saturating_sub(1);
    let event_id = format!("ck:event:{}", uuid_v7());
    let event_id_typed = cokret_sdk::EventId::new(event_id.clone())
        .map_err(|err| format!("invalid MLS commit event id: {err:?}"))?;
    let typed_realm_id = cokret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|err| format!("invalid MLS commit Realm id: {err:?}"))?;
    let governance_binding = cokret_sdk::MlsGovernanceBindingPayload::realm(
        typed_realm_id,
        commit_envelope.group_id.clone(),
        prev_epoch,
        commit_envelope.epoch,
        kanban_mls_membership_frontier(&anchor_view, &event_id_typed),
        kanban_mls_policy_root(&anchor_view, realm_id)?,
    )
    .map_err(|err| format!("MLS governance binding failed: {err}"))?;
    let payload = cokret_sdk::MlsCommitPayload::new(
        commit_envelope.group_id.clone(),
        prev_epoch,
        kanban_mls_base_epoch_ref(&anchor_view, realm_id),
        Vec::new(),
        commit_envelope.epoch,
        commit_envelope.commit_digest.clone(),
        governance_binding,
    )
    .map_err(|err| format!("MLS commit payload failed: {err}"))?;
    let mut event =
        crate::operation::ck_ops::mls_commit_with_governance(realm_id, actor_id, &payload)
            .map_err(|err| format!("MLS commit payload failed: {err}"))?
            .build("yougen");
    event.event_id = event_id;
    Ok(event)
}

/// The MLS events an encrypted write must submit, in submit order: the
/// one-time `ck.mls.genesis` (if not yet emitted) MUST precede any forced
/// `ck.mls.commit` so the server has the group at epoch 0 before the commit
/// bumps it.
#[derive(Default, Debug)]
struct EncryptedWriteMlsEvents {
    genesis: Option<crate::operation::EventEnvelope>,
    commit: Option<crate::operation::EventEnvelope>,
    /// X14 — the post-commit MLS snapshot. Persisted by the caller ONLY
    /// after the server ACCEPTS `commit`, so the local snapshot epoch never
    /// races ahead of the server's accepted epoch (the root cause of
    /// permanent `mls_epoch_skew`). `None` when the encrypted write rides the
    /// current epoch without forcing a commit.
    snapshot: Option<crate::mls::persistence::MlsSnapshotEnvelope>,
}

fn encrypt_private_card_detail_patch_values(
    patch: Value,
    realm_id: &str,
    flow_id: &str,
    actor_id: &str,
    device_id: &str,
    mut state_store: Signal<LocalStateStore>,
) -> Result<(Value, EncryptedWriteMlsEvents), String> {
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let mut store = state_store.write();
    encrypt_private_card_detail_patch_values_with_store(
        patch,
        realm_id,
        flow_id,
        actor_id,
        device_id,
        &mut store,
        secure_store.as_ref(),
    )
}

fn encrypt_private_card_detail_patch_values_with_store(
    patch: Value,
    realm_id: &str,
    flow_id: &str,
    actor_id: &str,
    device_id: &str,
    state_store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Result<(Value, EncryptedWriteMlsEvents), String> {
    let values = collect_encryptable_private_patch_values(&patch)?;
    if values.is_empty() {
        return Ok((patch, EncryptedWriteMlsEvents::default()));
    }
    let plaintext_values = values
        .iter()
        .map(|(_, bytes)| bytes.clone())
        .collect::<Vec<_>>();
    let fresh_summary = ensure_creator_mls_snapshot_for_encrypted_scope(
        state_store,
        secure_store,
        realm_id,
        actor_id,
        device_id,
    )?;
    // Build genesis BEFORE the first commit mutates the group past epoch 0.
    let genesis_event = build_creator_mls_genesis_event(
        state_store,
        realm_id,
        actor_id,
        device_id,
        fresh_summary.as_ref(),
    )?;
    let (schedule_hash, _member_dids, encrypted_values, commit_envelope, new_snapshot) =
        crate::mls::runtime::encrypt_values_with_device_snapshot(
            state_store,
            secure_store,
            realm_id,
            actor_id,
            device_id,
            KANBAN_FLOW_PATCH_VALUE_CONTENT_TYPE,
            &plaintext_values,
        )
        .map_err(|err| err.user_message())?;
    let commit_event = match commit_envelope.as_ref() {
        Some(commit_envelope) => Some(kanban_mls_commit_event_from_store(
            state_store,
            realm_id,
            actor_id,
            &schedule_hash,
            commit_envelope,
        )?),
        None => None,
    };
    // X5.1 — encryption succeeded. Persist the author's own plaintext into
    // the local-only sidecar so a later re-projection (refresh / board
    // switch / live poll) can render the author's own content, which can
    // never be recovered by decrypting the author's own MLS ciphertext.
    // The stored value is the JSON-serialized patch *value* (the same
    // `plaintext_values` bytes that were just encrypted) as a UTF-8 string;
    // the read path parses it back with `serde_json::from_str` and feeds it
    // to `flow_body_display_text`, keeping write+read symmetric. This is
    // local-only and NEVER enters the op / `append_raw_operation` payload.
    for (path, plaintext_bytes) in &values {
        if let Ok(plaintext_str) = std::str::from_utf8(plaintext_bytes) {
            state_store.save_private_plaintext(realm_id, flow_id, path, plaintext_str);
        }
    }
    let paths = values.into_iter().map(|(path, _)| path).collect::<Vec<_>>();
    let mut encrypted_patch = patch;
    replace_private_patch_values(&mut encrypted_patch, &paths, encrypted_values)?;
    Ok((
        encrypted_patch,
        EncryptedWriteMlsEvents {
            genesis: genesis_event,
            commit: commit_event,
            // X14 — forced-commit snapshots are persisted by
            // `dispatch_card_detail_update` ONLY after the server accepts the
            // commit (see the commit Ok arm). Ordinary application writes
            // already persisted the same-epoch ratchet snapshot in-place.
            snapshot: new_snapshot,
        },
    ))
}

#[allow(clippy::too_many_arguments)]
fn dispatch_card_detail_update(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    device_id: String,
    current: KanbanCard,
    draft: CardDetailDraft,
    // R4: three-state security signal (see `kanban_plaintext_block_reason`).
    scope_security_encrypted: Option<bool>,
    synthesis_entry_id: Option<String>,
    synthesis_revision_body: Option<String>,
    mut columns: Signal<Vec<KanbanColumn>>,
    mut selected_card: Signal<Option<KanbanCard>>,
    mut state_store: Signal<LocalStateStore>,
    mut board_status: Signal<String>,
) -> bool {
    let patch = match card_detail_update_patch(&current, &draft) {
        Ok(patch) => patch,
        Err(msg) => {
            board_status.set(msg);
            return false;
        }
    };
    // R4 fail-closed: when the Realm security state is unknown (`None`),
    // treat the scope as encrypted so we take the encrypt path rather than
    // emitting a plaintext patch. The plaintext-block guard below still
    // fails closed on the unknown state for any private content.
    let effective_security_encrypted = current
        .security_encrypted
        .unwrap_or_else(|| scope_security_encrypted.unwrap_or(true));
    let (patch, mls_events) = if effective_security_encrypted {
        match encrypt_private_card_detail_patch_values(
            patch,
            &realm_id,
            &current.id,
            &actor_id,
            &device_id,
            state_store,
        ) {
            Ok(result) => result,
            Err(msg) => {
                board_status.set(msg);
                return false;
            }
        }
    } else {
        (patch, EncryptedWriteMlsEvents::default())
    };
    let EncryptedWriteMlsEvents {
        genesis: mls_genesis_op,
        commit: mls_commit_op,
        snapshot: mls_new_snapshot,
    } = mls_events;

    let op =
        match crate::operation::ck_ops::flow_update_patch(&realm_id, &actor_id, &current.id, patch)
        {
            Ok(builder) => builder.build("yougen"),
            Err(err) => {
                board_status.set(format!("cannot update card: {err:#}"));
                return false;
            }
        };
    // R4: feed the guard the three-state security signal. An explicit
    // per-card `security_encrypted` flag (`Some`) wins; otherwise fall back to
    // the scope three-state so an unknown projection fails closed.
    let guard_security_state = current
        .security_encrypted
        .map(Some)
        .unwrap_or(scope_security_encrypted);
    if let Some(reason) = kanban_plaintext_block_reason(guard_security_state, &op) {
        board_status.set(reason);
        return false;
    }

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

    let operation_id = op.local_operation_id().to_owned();
    let synthesis_entry_id = synthesis_revision_body
        .as_ref()
        .map(|_| synthesis_entry_id.unwrap_or_else(|| operation_id.clone()));
    let local_synthesis_revision_body = synthesis_revision_body
        .clone()
        .filter(|_| !effective_security_encrypted);
    state_store.write().append_raw_operation(
        operation_id.clone(),
        Some(realm_id.clone()),
        json!({
            "kind": op.kind.clone(),
            "operation_id": operation_id.clone(),
            "actor_id": op.actor_id.clone(),
            "created_at": op.created_at.clone(),
            "write_state": "queued",
            "body": op.payload.clone(),
            "activity_summary": card_detail_activity_summary(&current, &draft),
            "synthesis_entry_id": synthesis_entry_id,
            "synthesis_revision_body": local_synthesis_revision_body,
            "encrypted_payload_local": effective_security_encrypted,
        }),
    );
    board_status.set(format!(
        "submitting {} operation {}",
        op.kind,
        short_protocol_id(&operation_id)
    ));
    let api_token = token();
    let flow_id = current.id.clone();
    let kind = op.kind.clone();
    let mls_commit_operation_id = mls_commit_op
        .as_ref()
        .map(|op| op.local_operation_id().to_owned());
    // X11.2 — first-write trigger. Read the context-provided
    // `needs_mls_backup` signal HERE (inside the Dioxus scope), so the
    // encrypted-write success arm can flip the backup prompt on directly,
    // bypassing the fragile boot detection effect. Best-effort: `None` when
    // no provider is mounted (unit tests / non-app callers).
    let backup_trigger_signal = crate::components::try_needs_mls_backup_signal();
    let base_for_backup_trigger = base_url.clone();
    let actor_for_backup_trigger = actor_id.clone();
    let device_for_sidecar_backup = device_id.clone();
    spawn(async move {
        // Genesis MUST land before the first commit so the server has the
        // group at epoch 0 before the commit bumps it to 1. A duplicate
        // genesis (`mls_genesis_already_exists`) is treated as success.
        if let Some(genesis_op) = mls_genesis_op {
            let genesis_result = with_authed_api(&base_url, api_token.clone(), |api| async move {
                api.submit_event_envelope(&genesis_op).await
            })
            .await;
            match genesis_result {
                Ok(_) => {
                    state_store
                        .write()
                        .mark_mls_genesis_emitted(realm_id.clone());
                }
                Err(err) => {
                    let err_text = err.display().to_string();
                    if err_text.contains("mls_genesis_already_exists") {
                        // Already installed server-side — record locally and proceed.
                        state_store
                            .write()
                            .mark_mls_genesis_emitted(realm_id.clone());
                    } else {
                        state_store.write().update_raw_operation_write_state(
                            &operation_id,
                            "failed",
                            None,
                            Some(err_text.clone()),
                        );
                        set_card_state_in_columns(&mut columns, &flow_id, CardState::SoftFailed);
                        let selected = selected_card.read().clone();
                        if let Some(mut card) = selected
                            && card.id == flow_id
                        {
                            card.state = CardState::SoftFailed;
                            selected_card.set(Some(card));
                        }
                        board_status.set(format!("MLS genesis event failed: {err_text}"));
                        return;
                    }
                }
            }
        }
        if let Some(commit_op) = mls_commit_op {
            let commit_result = with_authed_api(&base_url, api_token.clone(), |api| async move {
                api.submit_event_envelope(&commit_op).await
            })
            .await;
            match commit_result {
                Ok(resp) => {
                    // X14 — persist-on-accept: the server accepted this commit,
                    // so NOW advance the local snapshot to the post-commit
                    // epoch. This keeps `snapshot.epoch == server.epoch` in
                    // lockstep; if the commit had been rejected we'd skip this
                    // and the snapshot would stay at the pre-commit epoch, so
                    // the next write retries at the correct `expected_prev_epoch`
                    // instead of skewing forever.
                    if let Some(snapshot) = mls_new_snapshot {
                        state_store
                            .write()
                            .save_mls_snapshot(realm_id.clone(), snapshot);
                        // §7.10 continuous backup: the accepted commit advanced
                        // the epoch, so re-upload this Realm's mls_history
                        // series tail (debounced; no-op until the 24-word
                        // Recovery Key exists).
                        crate::components::schedule_mls_history_backup_after_commit(
                            base_for_backup_trigger.clone(),
                            api_token.clone(),
                            actor_for_backup_trigger.clone(),
                            device_for_sidecar_backup.clone(),
                            realm_id.clone(),
                            state_store,
                        );
                    }
                    if let Some(commit_operation_id) = mls_commit_operation_id {
                        state_store.write().record_move_submission_with_event_id(
                            commit_operation_id,
                            Some(resp.event_id),
                            realm_id.clone(),
                            "mls_commit".to_owned(),
                            MoveSubmissionState::from_submit_state("accepted", None),
                            None,
                            None,
                        );
                    }
                }
                Err(err) => {
                    let err_text = err.display().to_string();
                    state_store.write().update_raw_operation_write_state(
                        &operation_id,
                        "failed",
                        None,
                        Some(err_text.clone()),
                    );
                    set_card_state_in_columns(&mut columns, &flow_id, CardState::SoftFailed);
                    let selected = selected_card.read().clone();
                    if let Some(mut card) = selected
                        && card.id == flow_id
                    {
                        card.state = CardState::SoftFailed;
                        selected_card.set(Some(card));
                    }
                    board_status.set(format!("MLS commit event failed: {err_text}"));
                    return;
                }
            }
        }
        match with_authed_api(&base_url, api_token.clone(), |api| async move {
            api.submit_event_envelope(&op).await
        })
        .await
        {
            Ok(resp) => {
                state_store.write().update_raw_operation_write_state(
                    &operation_id,
                    "accepted",
                    Some(resp.event_id.clone()),
                    None,
                );
                set_card_state_in_columns(&mut columns, &flow_id, CardState::Accepted);
                let selected = selected_card.read().clone();
                if let Some(mut card) = selected
                    && card.id == flow_id
                {
                    card.state = CardState::Accepted;
                    selected_card.set(Some(card));
                }
                board_status.set(format!(
                    "{kind} operation accepted by server (event_id={})",
                    short_protocol_id(&resp.event_id)
                ));
                if effective_security_encrypted {
                    crate::components::schedule_mls_private_plaintext_backup_after_encrypted_write(
                        base_for_backup_trigger.clone(),
                        api_token.clone(),
                        actor_for_backup_trigger.clone(),
                        device_for_sidecar_backup.clone(),
                        state_store,
                    );
                    // X11.2 — first-write trigger. After this encrypted write
                    // landed, prompt if no account-secret recovery backup exists.
                    // The helper dedupes its server probe per account/session, so
                    // ordinary writes do not list backups repeatedly.
                    if let Some(signal) = backup_trigger_signal {
                        crate::components::maybe_flag_mls_backup_after_encrypted_write(
                            base_for_backup_trigger.clone(),
                            api_token.clone(),
                            actor_for_backup_trigger.clone(),
                            signal,
                        )
                        .await;
                    }
                }
            }
            Err(err) => {
                state_store.write().update_raw_operation_write_state(
                    &operation_id,
                    "failed",
                    None,
                    Some(err.display().to_string()),
                );
                set_card_state_in_columns(&mut columns, &flow_id, CardState::SoftFailed);
                let selected = selected_card.read().clone();
                if let Some(mut card) = selected
                    && card.id == flow_id
                {
                    card.state = CardState::SoftFailed;
                    selected_card.set(Some(card));
                }
                board_status.set(format!("{kind} operation failed: {}", err.display()));
            }
        }
    });
    true
}

#[derive(Clone)]
enum CardAssignmentMutation {
    Create {
        actor_id: String,
        relation_id: String,
        operation: crate::operation::EventEnvelope,
    },
    Tombstone {
        actor_id: String,
        relation_id: String,
        operation: crate::operation::EventEnvelope,
    },
}

impl CardAssignmentMutation {
    fn relation_id(&self) -> &str {
        match self {
            Self::Create { relation_id, .. } | Self::Tombstone { relation_id, .. } => relation_id,
        }
    }

    fn actor_id(&self) -> &str {
        match self {
            Self::Create { actor_id, .. } | Self::Tombstone { actor_id, .. } => actor_id,
        }
    }

    fn operation(&self) -> &crate::operation::EventEnvelope {
        match self {
            Self::Create { operation, .. } | Self::Tombstone { operation, .. } => operation,
        }
    }
}

fn assignment_activity_summary(mutation: &CardAssignmentMutation) -> String {
    let actor = short_protocol_id(mutation.actor_id());
    match mutation {
        CardAssignmentMutation::Create { .. } => format!("Assignee added: {actor}"),
        CardAssignmentMutation::Tombstone { .. } => format!("Assignee removed: {actor}"),
    }
}

fn relation_id_from_event_id(event_id: &str) -> Option<String> {
    event_id
        .strip_prefix("ck:event:")
        .map(|suffix| format!("ck:relation:{suffix}"))
}

fn normalize_assignee_selection(
    selected_actor_ids: BTreeSet<String>,
) -> Result<BTreeSet<String>, String> {
    let mut normalized = BTreeSet::new();
    for actor_id in selected_actor_ids {
        let actor_id = actor_id.trim();
        if actor_id.is_empty() {
            continue;
        }
        if !actor_id.starts_with("did:") {
            return Err(format!("assignee actor id must be a DID: {actor_id}"));
        }
        normalized.insert(actor_id.to_owned());
    }
    Ok(normalized)
}

fn card_assignment_mutations(
    realm_id: &str,
    actor_id: &str,
    current: &KanbanCard,
    selected_actor_ids: &BTreeSet<String>,
) -> Result<Vec<CardAssignmentMutation>, String> {
    let current_actor_ids = card_assigned_actor_ids(current)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut relation_ids_by_actor = BTreeMap::<String, Vec<String>>::new();
    for relation in &current.assigned_to_relations {
        let relation_id = relation.relation_id.trim();
        let actor_id = relation.actor_id.trim();
        if relation_id.is_empty() || actor_id.is_empty() {
            continue;
        }
        relation_ids_by_actor
            .entry(actor_id.to_owned())
            .or_default()
            .push(relation_id.to_owned());
    }

    let mut mutations = Vec::new();
    for actor_id in selected_actor_ids.difference(&current_actor_ids) {
        let operation = crate::operation::ck_ops::relation_create(
            realm_id,
            actor_id,
            "assigned_to",
            &current.id,
            actor_id,
        )
        .map_err(|err| format!("cannot build assigned_to relation: {err:#}"))?
        .build("yougen");
        let relation_id = relation_id_from_event_id(&operation.event_id).ok_or_else(|| {
            format!(
                "internal: cannot derive assigned_to relation id from {}",
                operation.event_id
            )
        })?;
        mutations.push(CardAssignmentMutation::Create {
            actor_id: actor_id.clone(),
            relation_id,
            operation,
        });
    }

    for actor_id in current_actor_ids.difference(selected_actor_ids) {
        let Some(relation_ids) = relation_ids_by_actor.get(actor_id) else {
            return Err(format!(
                "assignment for {} is missing its relation_id; refresh before removing it",
                short_protocol_id(actor_id)
            ));
        };
        for relation_id in relation_ids {
            let operation =
                crate::operation::ck_ops::relation_tombstone(realm_id, actor_id, relation_id)
                    .build("yougen");
            mutations.push(CardAssignmentMutation::Tombstone {
                actor_id: actor_id.clone(),
                relation_id: relation_id.clone(),
                operation,
            });
        }
    }
    Ok(mutations)
}

fn assignment_relations_after_mutations(
    current: &KanbanCard,
    selected_actor_ids: &BTreeSet<String>,
    mutations: &[CardAssignmentMutation],
) -> Vec<CardAssignedToRelation> {
    let tombstoned = mutations
        .iter()
        .filter_map(|mutation| match mutation {
            CardAssignmentMutation::Tombstone { relation_id, .. } => Some(relation_id.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let mut relations = current
        .assigned_to_relations
        .iter()
        .filter(|relation| selected_actor_ids.contains(relation.actor_id.trim()))
        .filter(|relation| !tombstoned.contains(relation.relation_id.trim()))
        .cloned()
        .collect::<Vec<_>>();
    for mutation in mutations {
        if let CardAssignmentMutation::Create {
            actor_id,
            relation_id,
            ..
        } = mutation
            && selected_actor_ids.contains(actor_id)
        {
            relations.push(CardAssignedToRelation {
                relation_id: relation_id.clone(),
                actor_id: actor_id.clone(),
            });
        }
    }
    relations.sort_by(|left, right| {
        left.actor_id
            .cmp(&right.actor_id)
            .then(left.relation_id.cmp(&right.relation_id))
    });
    relations.dedup_by(|left, right| left.relation_id == right.relation_id);
    relations
}

fn update_card_assignees_in_columns(
    columns: &mut [KanbanColumn],
    flow_id: &str,
    selected_actor_ids: &BTreeSet<String>,
    relations: Vec<CardAssignedToRelation>,
    state: CardState,
) -> Option<KanbanCard> {
    for column in columns.iter_mut() {
        if let Some(card) = column.cards.iter_mut().find(|card| card.id == flow_id) {
            apply_card_assignment_projection(card, selected_actor_ids, relations, state);
            return Some(card.clone());
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn dispatch_card_assignees_update(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    current: KanbanCard,
    selected_actor_ids: BTreeSet<String>,
    mut columns: Signal<Vec<KanbanColumn>>,
    mut selected_card: Signal<Option<KanbanCard>>,
    mut state_store: Signal<LocalStateStore>,
    mut board_status: Signal<String>,
    mut assignee_edit_status: Signal<String>,
) -> bool {
    let selected_actor_ids = match normalize_assignee_selection(selected_actor_ids) {
        Ok(selected) => selected,
        Err(msg) => {
            assignee_edit_status.set(msg.clone());
            board_status.set(msg);
            return false;
        }
    };
    if actor_id.trim().is_empty() {
        let msg = "sign in before editing assignees".to_owned();
        assignee_edit_status.set(msg.clone());
        board_status.set(msg);
        return false;
    }
    if realm_id.trim().is_empty() {
        let msg = "select a Realm before editing assignees".to_owned();
        assignee_edit_status.set(msg.clone());
        board_status.set(msg);
        return false;
    }

    let mutations =
        match card_assignment_mutations(&realm_id, &actor_id, &current, &selected_actor_ids) {
            Ok(mutations) => mutations,
            Err(msg) => {
                assignee_edit_status.set(msg.clone());
                board_status.set(msg);
                return false;
            }
        };
    if mutations.is_empty() {
        board_status.set("No assignee changes to save".to_owned());
        assignee_edit_status.set(String::new());
        return true;
    }

    let optimistic_relations =
        assignment_relations_after_mutations(&current, &selected_actor_ids, &mutations);
    let updated_card = {
        let mut cols = columns.write();
        update_card_assignees_in_columns(
            &mut cols,
            &current.id,
            &selected_actor_ids,
            optimistic_relations.clone(),
            CardState::Queued,
        )
    };
    let Some(updated_card) = updated_card else {
        let msg = format!(
            "internal: card {} not in board state",
            short_protocol_id(&current.id)
        );
        assignee_edit_status.set(msg.clone());
        board_status.set(msg);
        return false;
    };
    selected_card.set(Some(updated_card));

    for mutation in &mutations {
        let operation = mutation.operation();
        let operation_id = operation.local_operation_id().to_owned();
        state_store.write().append_raw_operation(
            operation_id.clone(),
            Some(realm_id.clone()),
            json!({
                "kind": operation.kind.clone(),
                "operation_id": operation_id,
                "actor_id": operation.actor_id.clone(),
                "created_at": operation.created_at.clone(),
                "write_state": "queued",
                "body": operation.payload.clone(),
                "assignment_flow_id": current.id.clone(),
                "assignment_actor_id": mutation.actor_id(),
                "assignment_relation_id": mutation.relation_id(),
                "activity_summary": assignment_activity_summary(mutation),
            }),
        );
    }

    let operation_count = mutations.len();
    board_status.set(format!(
        "submitting {operation_count} assignee relation operation{}",
        if operation_count == 1 { "" } else { "s" }
    ));
    assignee_edit_status.set("Saving...".to_owned());
    let api_token = token();
    let flow_id = current.id.clone();
    spawn(async move {
        for mutation in mutations {
            let operation = mutation.operation().clone();
            let operation_id = operation.local_operation_id().to_owned();
            let kind = operation.kind.clone();
            match with_authed_api(&base_url, api_token.clone(), |api| async move {
                api.submit_event_envelope(&operation).await
            })
            .await
            {
                Ok(resp) => {
                    state_store.write().update_raw_operation_write_state(
                        &operation_id,
                        "accepted",
                        Some(resp.event_id.clone()),
                        None,
                    );
                }
                Err(err) => {
                    let err_text = err.display().to_string();
                    state_store.write().update_raw_operation_write_state(
                        &operation_id,
                        "failed",
                        None,
                        Some(err_text.clone()),
                    );
                    set_card_state_in_columns(&mut columns, &flow_id, CardState::SoftFailed);
                    let selected = selected_card.read().clone();
                    if let Some(mut card) = selected
                        && card.id == flow_id
                    {
                        card.state = CardState::SoftFailed;
                        selected_card.set(Some(card));
                    }
                    assignee_edit_status.set(format!("{kind} failed"));
                    board_status.set(format!("{kind} operation failed: {err_text}"));
                    return;
                }
            }
        }
        set_card_state_in_columns(&mut columns, &flow_id, CardState::Accepted);
        let selected = selected_card.read().clone();
        if let Some(mut card) = selected
            && card.id == flow_id
        {
            card.state = CardState::Accepted;
            selected_card.set(Some(card));
        }
        assignee_edit_status.set(String::new());
        board_status.set("Assignees updated".to_owned());
    });
    true
}

#[allow(clippy::too_many_arguments)]
fn select_kanban_board(
    board_id: String,
    mut selected_board_space_id: Signal<String>,
    mut board_popover: Signal<BoardToolbarPopover>,
    mut selected_card: Signal<Option<KanbanCard>>,
    board_route_realm_id: String,
    local_realm_id: String,
    lifecycle_container_projection: Signal<Vec<crate::api::SpaceContainerProjectionView>>,
    lifecycle_flow_projection: Signal<Vec<crate::api::FlowProjectionView>>,
    mut columns: Signal<Vec<KanbanColumn>>,
    mut adding_card_to: Signal<Option<String>>,
    mut board_status: Signal<String>,
    mut board_space_options: Signal<Vec<BoardSpaceOption>>,
    mut projection_source: Signal<BoardProjectionSource>,
    state_store: Signal<LocalStateStore>,
    decrypt_actor: String,
    decrypt_device: String,
) {
    selected_board_space_id.set(board_id.clone());
    board_popover.set(BoardToolbarPopover::None);
    // Persist the board in the URL so a refresh restores it instead of
    // falling back to the first board. Closing any open card too: a board
    // switch should not keep a card from a different board mounted.
    selected_card.set(None);
    let containers = lifecycle_container_projection();
    let flows = lifecycle_flow_projection();
    if board_id.trim().is_empty() {
        columns.set(Vec::new());
        adding_card_to.set(None);
        board_status.set("Select or create a board before adding lists".to_owned());
        replace_kanban_board_url(&board_route_realm_id, &board_id);
        return;
    }
    if containers.is_empty() && flows.is_empty() {
        let raw_operations = state_store.read().load().raw_operations;
        if raw_operations.is_empty() {
            board_status.set(format!("Board selected · {}", short_protocol_id(&board_id)));
            replace_kanban_board_url(&board_route_realm_id, &board_id);
            return;
        }
        let decrypt_store = state_store.read();
        let decrypt_ctx = MlsDecryptCtx {
            state_store: &decrypt_store,
            realm_id: &board_route_realm_id,
            actor_id: &decrypt_actor,
            device_id: &decrypt_device,
        };
        let (projected_columns, options, projected_board_id) =
            columns_from_lifecycle_projection_with_local(
                &containers,
                &flows,
                &board_id,
                &raw_operations,
                &local_realm_id,
                Some(&decrypt_ctx),
            );
        if !options.is_empty() {
            board_space_options.set(options);
        }
        if projected_board_id.as_deref() == Some(board_id.as_str()) {
            let projected_columns = overlay_local_card_creates_with_decrypt(
                projected_columns,
                &decrypt_store,
                &board_id,
                Some(&decrypt_ctx),
            );
            drop(decrypt_store);
            columns.set(projected_columns);
            projection_source.set(BoardProjectionSource::ApiDerived);
            board_status.set(format!("Board selected · {}", short_protocol_id(&board_id)));
        } else {
            columns.set(Vec::new());
            adding_card_to.set(None);
            board_status.set(format!(
                "No list projection available for selected Board · {}",
                short_protocol_id(&board_id)
            ));
        }
        replace_kanban_board_url(&board_route_realm_id, &board_id);
        return;
    }
    let raw_operations = state_store.read().load().raw_operations;
    let decrypt_store = state_store.read();
    let decrypt_ctx = MlsDecryptCtx {
        state_store: &decrypt_store,
        realm_id: &board_route_realm_id,
        actor_id: &decrypt_actor,
        device_id: &decrypt_device,
    };
    let (projected_columns, options, projected_board_id) =
        columns_from_lifecycle_projection_with_local(
            &containers,
            &flows,
            &board_id,
            &raw_operations,
            &local_realm_id,
            Some(&decrypt_ctx),
        );
    if !options.is_empty() {
        board_space_options.set(options);
    }
    if projected_board_id.as_deref() == Some(board_id.as_str()) {
        let projected_columns = overlay_local_card_creates_with_decrypt(
            projected_columns,
            &decrypt_store,
            &board_id,
            Some(&decrypt_ctx),
        );
        drop(decrypt_store);
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
    replace_kanban_board_url(&board_route_realm_id, &board_id);
}

fn replace_kanban_board_url(realm_id: &str, board_id: &str) {
    let realm_id = card_detail_route_realm_id(realm_id);
    let board_id = board_id.trim();
    let path = if board_id.is_empty() {
        format!("/kanban/{realm_id}")
    } else {
        format!("/kanban/{realm_id}/board/{board_id}")
    };
    let Ok(encoded_path) = serde_json::to_string(&path) else {
        return;
    };
    let script = format!("window.history.replaceState(null, '', {encoded_path});");
    let _ = document::eval(&script);
}

/// Build + sign + submit a `ck.component.flow.position.v1` Move via
/// `api.submit_move(...)`, recording a [`BoardWriteRecord`] in the local
/// queue regardless of submit outcome. Used by both list and card create
/// paths - `subject` is the cell subject (Space-container id or Flow id), `kind` is
/// the classifier the MoveSubmissionState tracker uses to decorate state
/// pills (`ck.space.create` / `ck.flow.create`).
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
            id: "ck:space:01list-todo000000000000000000".to_owned(),
            title: "To Do".to_owned(),
            rank: "U".to_owned(),
            cards: vec![KanbanCard {
                id: DEMO_FLOW_LEGAL_REVIEW_ID.to_owned(),
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
                body_locked: false,
                synthesis_locked: false,
                created_by: "did:web:acme.example:users:alice".to_owned(),
                created_at: "2026-05-08T08:00:00Z".to_owned(),
                updated_at: String::new(),
                labels: vec!["legal".to_owned(), "beta".to_owned()],
                assignee: "Alice".to_owned(),
                assigned_to_relations: Vec::new(),
                due: "May 08".to_owned(),
                primary_flow_id: DEMO_FLOW_REVIEW_DISCUSSION_ID.to_owned(),
                locked_flow: Some(LockedFlow {
                    flow_id_hash: "sha256:locked-private-decision".to_owned(),
                reason: "You can see that a restricted discussion is linked, but not its name or members.".to_owned(),
                }),
                external_visibility: "External counsel discussion only".to_owned(),
                history_visibility: "joined history".to_owned(),
                security_encrypted: None,
                state: CardState::Synced,
                lifecycle: FlowLifecycleState::Active,
            }],
            state: SpaceContainerLifecycleState::Active,
        },
        KanbanColumn {
            id: "ck:space:01list-progress00000000000000".to_owned(),
            title: "In Progress".to_owned(),
            rank: "f".to_owned(),
            cards: vec![KanbanCard {
                id: DEMO_FLOW_ONBOARDING_COPY_ID.to_owned(),
                rank: "U".to_owned(),
                title: "Onboarding copy".to_owned(),
                description: "Waiting on discussion-scoped feedback from support and docs reviewers.".to_owned(),
                body: String::new(),
                synthesis: String::new(),
                body_locked: false,
                synthesis_locked: false,
                created_by: "did:web:acme.example:users:bob".to_owned(),
                created_at: "2026-05-09T09:00:00Z".to_owned(),
                updated_at: String::new(),
                labels: vec!["copy".to_owned(), "support".to_owned()],
                assignee: "Bob".to_owned(),
                assigned_to_relations: Vec::new(),
                due: "May 10".to_owned(),
                primary_flow_id: DEMO_FLOW_SUPPORT_DISCUSSION_ID.to_owned(),
                locked_flow: None,
                external_visibility: "No external discussions linked".to_owned(),
                history_visibility: "shared history".to_owned(),
                security_encrypted: None,
                state: CardState::Queued,
                lifecycle: FlowLifecycleState::Active,
            }],
            state: SpaceContainerLifecycleState::Active,
        },
        KanbanColumn {
            id: "ck:space:01list-done00000000000000000".to_owned(),
            title: "Done".to_owned(),
            rank: "p".to_owned(),
            cards: vec![KanbanCard {
                id: DEMO_FLOW_SECURITY_SIGNOFF_ID.to_owned(),
                rank: "U".to_owned(),
                title: "Security sign-off".to_owned(),
                description: "Projection detected a stale column head after an offline move.".to_owned(),
                body: String::new(),
                synthesis: String::new(),
                body_locked: false,
                synthesis_locked: false,
                created_by: "did:web:acme.example:users:carol".to_owned(),
                created_at: "2026-05-01T10:00:00Z".to_owned(),
                updated_at: String::new(),
                labels: vec!["security".to_owned(), "reviewed".to_owned()],
                assignee: "Carol".to_owned(),
                assigned_to_relations: Vec::new(),
                due: "May 01".to_owned(),
                primary_flow_id: DEMO_FLOW_SECURITY_REVIEW_ID.to_owned(),
                locked_flow: Some(LockedFlow {
                    flow_id_hash: "sha256:locked-incident-notes".to_owned(),
                    reason: "Incident notes require separate discussion capability.".to_owned(),
                }),
                external_visibility: "Internal discussions only".to_owned(),
                history_visibility: "restricted history".to_owned(),
                security_encrypted: None,
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

    const TEST_REALM_ID: &str = "ck:realm:0196419b-0000-7000-8000-000000000010";

    // YOU-05-010: shared hermetic state-store fixture from `local_state`.
    #[cfg(not(target_arch = "wasm32"))]
    use crate::local_state::isolated_store_for_tests as temp_state_store;

    #[cfg(not(target_arch = "wasm32"))]
    fn assert_registered_payload_valid(event: &crate::operation::EventEnvelope) {
        cokret_sdk::schema::event_payload_validator_catalog()
            .validate_payload(&event.kind, &event.payload)
            .unwrap_or_else(|err| {
                panic!(
                    "{} payload violates registered schema: {err}\npayload: {}",
                    event.kind,
                    serde_json::to_string_pretty(&event.payload).unwrap()
                )
            });
    }

    fn board_write_record(state: CardState, note: &str) -> BoardWriteRecord {
        BoardWriteRecord {
            state,
            move_id: "ck:operation:test".to_owned(),
            kind: "ck.flow.create".to_owned(),
            cell_id: "ck:cell:test".to_owned(),
            effect_summary: "{}".to_owned(),
            anchor_ref: "ck:anchor:test".to_owned(),
            hlc: "000000000000-0000-00000000".to_owned(),
            note: note.to_owned(),
            signed_move_json: None,
            rebase_attempts: 0,
        }
    }

    #[test]
    fn board_write_manual_review_is_only_for_conflicts() {
        let transient_failure = board_write_record(
            CardState::Quarantined,
            "submit failed: projection still pending",
        );
        assert!(
            !transient_failure.needs_manual_conflict_review(),
            "ordinary submit failures should not show the board admin review banner"
        );

        let exhausted_conflict = board_write_record(
            CardState::Quarantined,
            "cas_conflict exhausted 3 rebase attempts",
        );
        assert!(exhausted_conflict.needs_manual_conflict_review());

        let active_conflict =
            board_write_record(CardState::Conflict, "server returned cas_conflict");
        assert!(active_conflict.needs_manual_conflict_review());
    }

    #[test]
    fn realm_member_roster_reads_r32_wire_shape() {
        // R3.2 (cokret-spec @ b56cab1): roster entries carry
        // `actor_id` + `membership` + optional `subject_id` /
        // `identity_event_ids` / `member_display_state_digest`. Handle
        // strings only appear inside signed handle_claim evidence.
        let projection = json!({
            "members": [
                {
                    "actor_id": "did:web:acme.example:users:alice",
                    "membership": "join",
                    "subject_id": "did:web:acme.example:principals:alice",
                    "identity_event_ids": ["ck:event:01904100-0000-7000-8000-00000000000a"],
                    "member_display_state_digest": "sha256:abababababababababababababababababababababababababababababababab",
                    "handle_claims": [{
                        "subject": "did:web:acme.example:principals:alice",
                        "handle": "alice:acme.example",
                        "binding_state": "verified"
                    }],
                    "handle_claims_limited": false
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
            vec!["ck:event:01904100-0000-7000-8000-00000000000a".to_owned()]
        );
        assert!(alice.member_display_state_digest.is_some());
        assert_eq!(
            alice.subject_id.as_deref(),
            Some("did:web:acme.example:principals:alice")
        );
        assert_eq!(alice.handle_claims.len(), 1);
        assert!(!alice.handle_claims_limited);

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
    fn realm_member_roster_reads_r32_digest_only() {
        // Aggressive no-compat: only the R3.2 `member_display_state_digest`
        // key is read.
        let projection = json!({
            "members": [{
                "actor_id": "did:web:acme.example:users:v2",
                "membership": "join",
                "member_display_state_digest": "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
            }]
        });
        let rows = realm_member_roster(Some(&projection));
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
    fn member_display_label_prefers_handle_shaped_user_label() {
        use cokret_sdk::{
            DisplayProfile, MemberIdentity, MemberIdentityProof, MemberIdentitySignatureAlgorithm,
        };

        // R3.2: `MemberIdentity` discloses subject_id + display_profile
        // only; the roster label still prefers a handle-shaped label when
        // roster handle evidence or a materialized subject DID exposes one.
        let identity = MemberIdentity {
            schema: cokret_sdk::MEMBER_IDENTITY_SCHEMA.to_owned(),
            realm_id: cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001")
                .unwrap(),
            actor_id: cokret_sdk::Did::new("did:web:acme.example:users:alice".to_owned()).unwrap(),
            subject_id: cokret_sdk::Did::new("did:web:acme.example:users:alice".to_owned())
                .unwrap(),
            display_profile: DisplayProfile {
                display_name: "Alice".to_owned(),
                avatar_blob_ref: None,
            },
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            proof: MemberIdentityProof {
                verification_method: "did:web:acme.example#key-1".to_owned(),
                signature_algorithm: MemberIdentitySignatureAlgorithm::Ed25519,
                payload_digest: cokret_sdk::Hash::new(
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
            handle_claims: Vec::new(),
            handle_claims_limited: false,
        };
        assert_eq!(
            member_display_label(&row, Some(&identity), None),
            "alice:acme.example"
        );

        // Decryption-pending / no MemberIdentity → fall back to compact DID.
        let bare = RealmMemberRow {
            actor_id: "did:webvh:zQmPr8aaaaaaaaaaaaaaaaa7h4q87ha".to_owned(),
            membership: None,
            identity_event_ids: vec![],
            member_display_state_digest: None,
            subject_id: None,
            handle_claims: Vec::new(),
            handle_claims_limited: false,
        };
        let label = member_display_label(&bare, None, None);
        assert!(label.starts_with("did:webvh:"));
        assert!(label.contains("..."));
    }

    #[test]
    fn member_display_label_prefers_inline_verified_handle_claim() {
        let row = RealmMemberRow {
            actor_id: "did:webvh:zQmPairwiseActor".to_owned(),
            membership: Some("join".to_owned()),
            identity_event_ids: vec![],
            member_display_state_digest: Some(
                "sha256:abababababababababababababababababababababababababababababababab"
                    .to_owned(),
            ),
            subject_id: Some("did:key:z6MkPrincipal".to_owned()),
            handle_claims: vec![
                json!({
                    "subject": "did:key:z6MkOther",
                    "handle": "other:acme.example",
                    "binding_state": "verified"
                }),
                json!({
                    "subject": "did:key:z6MkPrincipal",
                    "handle": "alice:acme.example",
                    "binding_state": "verified"
                }),
            ],
            handle_claims_limited: false,
        };

        assert_eq!(member_display_label(&row, None, None), "alice:acme.example");
    }

    #[test]
    fn member_display_label_uses_cached_directory_primary_handle() {
        let row = RealmMemberRow {
            actor_id: "did:webvh:zQmPrincipal".to_owned(),
            membership: Some("join".to_owned()),
            identity_event_ids: vec![],
            member_display_state_digest: None,
            subject_id: Some("did:webvh:zQmPrincipal".to_owned()),
            handle_claims: Vec::new(),
            handle_claims_limited: false,
        };

        assert_eq!(
            member_display_label(&row, None, Some("Alice:Example.COM")),
            "alice:example.com"
        );
    }

    #[test]
    fn member_handle_lookup_subject_falls_back_to_actor_id() {
        let row = RealmMemberRow {
            actor_id: "did:webvh:zQmPrincipal".to_owned(),
            membership: Some("join".to_owned()),
            identity_event_ids: vec![],
            member_display_state_digest: None,
            subject_id: None,
            handle_claims: Vec::new(),
            handle_claims_limited: false,
        };

        assert_eq!(
            member_handle_lookup_subject(&row, None).as_deref(),
            Some("did:webvh:zQmPrincipal")
        );
    }

    #[test]
    fn member_roster_realm_context_prefers_projection_realm_id() {
        assert_eq!(
            member_roster_realm_context(
                "ck:space:board",
                "ck:realm:prop",
                Some(&json!({"realm_id": "ck:realm:projection"})),
            ),
            "ck:realm:projection"
        );
        assert_eq!(
            member_roster_realm_context("ck:realm:board", "ck:realm:legacy", None),
            "ck:realm:legacy"
        );
        assert_eq!(
            member_roster_realm_context("ck:realm:selected", "", None),
            "ck:realm:selected"
        );
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
    /// `CokretApi::collection_projection`. This test still pins the
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
    /// `/_cokret/self/projection/{spaces|flows}` round-trip into the
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
        // R11: `redacted` is the only spec terminal (flow.schema.json).
        assert_eq!(
            flow_lifecycle_from_wire("redacted"),
            FlowLifecycleState::Redacted
        );
        // `deleted` is NOT in the spec enum; it degrades to the safe
        // non-terminal `Active` default (and logs a warning) rather than
        // being treated as a terminal.
        assert_eq!(
            flow_lifecycle_from_wire("deleted"),
            FlowLifecycleState::Active
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
            "ck:space:test",
            SpaceContainerLifecycleState::Active,
            SpaceContainerLifecycleState::Active,
        )
        .expect_err("same-state Active→Active must be refused");
        assert!(err.contains("already in"));
        assert!(err.contains("ck:space:test"));

        // Same-state refusal — Archived → Archived.
        validate_space_container_lifecycle_transition(
            "ck:space:test",
            SpaceContainerLifecycleState::Archived,
            SpaceContainerLifecycleState::Archived,
        )
        .expect_err("same-state Archived→Archived must be refused");

        // Tombstone target refusal — UI never emits Tombstone.
        let err = validate_space_container_lifecycle_transition(
            "ck:space:test",
            SpaceContainerLifecycleState::Active,
            SpaceContainerLifecycleState::Tombstoned,
        )
        .expect_err("UI-emitted Tombstone must be refused");
        assert!(err.contains("Tombstone"));

        // Legal transitions stay green.
        validate_space_container_lifecycle_transition(
            "ck:space:test",
            SpaceContainerLifecycleState::Active,
            SpaceContainerLifecycleState::Archived,
        )
        .expect("Active→Archived is a legal transition");
        validate_space_container_lifecycle_transition(
            "ck:space:test",
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
            "ck:flow:test",
            FlowLifecycleState::Active,
            FlowLifecycleState::Active,
        )
        .expect_err("same-state Active→Active must be refused");
        assert!(err.contains("already in"));
        assert!(err.contains("ck:flow:test"));

        validate_flow_lifecycle_transition(
            "ck:flow:test",
            FlowLifecycleState::Archived,
            FlowLifecycleState::Archived,
        )
        .expect_err("same-state Archived→Archived must be refused");

        let err = validate_flow_lifecycle_transition(
            "ck:flow:test",
            FlowLifecycleState::Active,
            FlowLifecycleState::Redacted,
        )
        .expect_err("UI-emitted Redaction must be refused");
        assert!(err.contains("Redaction"));

        validate_flow_lifecycle_transition(
            "ck:flow:test",
            FlowLifecycleState::Active,
            FlowLifecycleState::Archived,
        )
        .expect("Active→Archived is a legal transition");
        validate_flow_lifecycle_transition(
            "ck:flow:test",
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
            flow_detail_deep_link_path("ck:space:ops", "ck:flow:abc"),
            "/kanban/ck:space:ops/task/ck:flow:abc"
        );
        assert_eq!(
            flow_detail_deep_link_path("", "ck:flow:abc"),
            format!("/kanban/{DEMO_BOARD_SPACE_ID}/task/ck:flow:abc")
        );
    }

    #[test]
    fn card_detail_tab_deep_link_round_trips() {
        assert_eq!(
            card_detail_tab_slug(CardDetailContentTab::Description),
            "description"
        );
        assert_eq!(
            card_detail_tab_from_slug("SYNTHESIS"),
            Some(CardDetailContentTab::Synthesis)
        );
        assert_eq!(
            card_detail_tab_from_slug("discussion"),
            Some(CardDetailContentTab::Discussion)
        );
        assert_eq!(card_detail_tab_from_slug("activity"), None);
    }

    #[test]
    fn card_detail_tab_reads_url_query() {
        assert_eq!(
            card_detail_tab_from_href(
                "http://127.0.0.1:8080/kanban/ck:realm:r/task/ck:flow:f?tab=discussion"
            ),
            Some(CardDetailContentTab::Discussion)
        );
        assert_eq!(
            card_detail_tab_from_href(
                "http://127.0.0.1:8080/kanban/ck:realm:r/task/ck:flow:f?tab=synthesis"
            ),
            Some(CardDetailContentTab::Synthesis)
        );
        assert_eq!(
            card_detail_tab_from_href(
                "http://127.0.0.1:8080/kanban/ck:realm:r/task/ck:flow:f?tab=bad"
            ),
            None
        );
    }

    #[test]
    fn card_detail_share_link_carries_current_tab() {
        assert_eq!(
            flow_detail_deep_link_path_with_tab(
                "ck:space:ops",
                "ck:flow:abc",
                CardDetailContentTab::Discussion
            ),
            "/kanban/ck:space:ops/task/ck:flow:abc?tab=discussion"
        );
    }

    #[test]
    fn route_card_flow_id_reads_task_segment_only() {
        assert_eq!(
            route_card_flow_id(&Route::KanbanTask {
                realm_id: "ck:realm:ops".to_owned(),
                task_id: "ck:flow:abc".to_owned(),
            }),
            Some("ck:flow:abc".to_owned())
        );
        assert_eq!(
            route_card_flow_id(&Route::KanbanBoardTask {
                realm_id: "ck:realm:ops".to_owned(),
                board_id: "ck:space:board".to_owned(),
                task_id: "ck:flow:abc".to_owned(),
            }),
            Some("ck:flow:abc".to_owned())
        );
        assert_eq!(route_card_flow_id(&Route::Kanban), None);
    }

    #[test]
    fn route_board_id_reads_board_segment_only() {
        assert_eq!(
            route_board_id(&Route::KanbanBoard {
                realm_id: "ck:realm:ops".to_owned(),
                board_id: "ck:space:board".to_owned(),
            }),
            Some("ck:space:board".to_owned())
        );
        assert_eq!(
            route_board_id(&Route::KanbanBoardTask {
                realm_id: "ck:realm:ops".to_owned(),
                board_id: "ck:space:board".to_owned(),
                task_id: "ck:flow:abc".to_owned(),
            }),
            Some("ck:space:board".to_owned())
        );
        // The board-less routes carry no board id — it is resolved from
        // the projection on arrival.
        assert_eq!(
            route_board_id(&Route::KanbanTask {
                realm_id: "ck:realm:ops".to_owned(),
                task_id: "ck:flow:abc".to_owned(),
            }),
            None
        );
        assert_eq!(
            route_board_id(&Route::KanbanRealm {
                realm_id: "ck:realm:ops".to_owned(),
            }),
            None
        );
    }

    #[test]
    fn kanban_board_route_carries_board_or_falls_back() {
        assert_eq!(
            kanban_board_route("ck:realm:ops", "ck:space:board"),
            Route::KanbanBoard {
                realm_id: "ck:realm:ops".to_owned(),
                board_id: "ck:space:board".to_owned(),
            }
        );
        assert_eq!(
            kanban_board_route("ck:realm:ops", ""),
            Route::KanbanRealm {
                realm_id: "ck:realm:ops".to_owned(),
            }
        );
    }

    #[test]
    fn kanban_card_task_route_carries_board_or_falls_back() {
        assert_eq!(
            kanban_card_task_route("ck:realm:ops", "ck:space:board", "ck:flow:abc"),
            Route::KanbanBoardTask {
                realm_id: "ck:realm:ops".to_owned(),
                board_id: "ck:space:board".to_owned(),
                task_id: "ck:flow:abc".to_owned(),
            }
        );
        assert_eq!(
            kanban_card_task_route("ck:realm:ops", "", "ck:flow:abc"),
            Route::KanbanTask {
                realm_id: "ck:realm:ops".to_owned(),
                task_id: "ck:flow:abc".to_owned(),
            }
        );
    }

    #[test]
    fn find_card_by_flow_id_matches_card_or_primary_flow() {
        let columns = seed_columns();
        assert_eq!(
            find_card_by_flow_id(&columns, DEMO_FLOW_LEGAL_REVIEW_ID).map(|card| card.title),
            Some("Legal review for public beta".to_owned())
        );
        assert_eq!(
            find_card_by_flow_id(&columns, DEMO_FLOW_REVIEW_DISCUSSION_ID).map(|card| card.id),
            Some(DEMO_FLOW_LEGAL_REVIEW_ID.to_owned())
        );
    }

    #[test]
    fn flow_body_display_text_reads_content_block_body() {
        let body = json!({
            "kind": "ck.content.text",
            "body": "Long-form flow body"
        });

        assert_eq!(flow_body_display_text(Some(&body)), "Long-form flow body");
    }

    #[test]
    fn flow_body_display_text_reads_nested_blocks() {
        let body = json!({
            "blocks": [
                { "kind": "ck.content.text", "body": "First block" },
                { "kind": "ck.content.text", "text": "Second block" }
            ]
        });

        assert_eq!(
            flow_body_display_text(Some(&body)),
            "First block\nSecond block"
        );
    }

    #[test]
    fn value_is_mls_envelope_detects_encrypted_patch_values() {
        // Full envelope shape written by encrypt_values_with_device_snapshot.
        assert!(value_is_mls_envelope(&json!({
            "scheme": "mls-rfc9420",
            "ciphertext": "AAAA",
            "content_type": KANBAN_FLOW_PATCH_VALUE_CONTENT_TYPE,
            "group_id": "g",
            "epoch": 0,
        })));
        // Minimal envelope detected via ciphertext + content_type.
        assert!(value_is_mls_envelope(&json!({
            "ciphertext": "AAAA",
            "content_type": KANBAN_FLOW_PATCH_VALUE_CONTENT_TYPE,
        })));
        // Projection / patch wrappers must still be recognized as encrypted.
        assert!(value_is_mls_envelope(&json!({
            "encrypted_content": {
                "ciphertext": "AAAA",
                "content_type": KANBAN_FLOW_PATCH_VALUE_CONTENT_TYPE,
            }
        })));
        assert!(value_is_mls_envelope(&json!({
            "$op": "set",
            "value": {
                "scheme": "mls-rfc9420",
                "ciphertext": "AAAA",
                "content_type": KANBAN_FLOW_PATCH_VALUE_CONTENT_TYPE,
            }
        })));
        // Plain content blocks are NOT envelopes — unencrypted realms must
        // pay nothing and render as-is.
        assert!(!value_is_mls_envelope(&json!({
            "kind": "ck.content.text",
            "body": "plain body",
        })));
        assert!(!value_is_mls_envelope(&json!("just a string")));
    }

    #[test]
    fn private_flow_display_text_passes_plaintext_through_without_ctx() {
        let plain = json!({ "kind": "ck.content.text", "body": "plain body" });
        // No decrypt ctx, non-envelope value → renders the plaintext as-is.
        assert_eq!(private_flow_display_text(None, Some(&plain)), "plain body");
        // Missing value → blank.
        assert_eq!(private_flow_display_text(None, None), "");
    }

    #[test]
    fn private_flow_display_text_blanks_undecryptable_envelope() {
        let envelope = json!({
            "scheme": "mls-rfc9420",
            "ciphertext": "AAAA",
            "content_type": KANBAN_FLOW_PATCH_VALUE_CONTENT_TYPE,
            "group_id": "g",
            "epoch": 0,
        });
        // Envelope + no ctx must render blank rather than leaking the raw
        // envelope JSON through flow_body_display_text.
        assert_eq!(private_flow_display_text(None, Some(&envelope)), "");
        let store = temp_state_store("private-flow-blank");
        let ctx = MlsDecryptCtx {
            state_store: &store,
            realm_id: "ck:realm:01904100-0000-7000-8000-000000000001",
            actor_id: "did:web:alice.example",
            device_id: "ck:device:01904100-0000-7000-8000-000000000001",
        };
        // Envelope + ctx but no local snapshot → soft failure → blank.
        assert_eq!(private_flow_display_text(Some(&ctx), Some(&envelope)), "");
    }

    #[test]
    fn private_flow_field_text_prefers_local_sidecar_plaintext() {
        // X5.2 — the author's own encrypted field can NEVER be decrypted
        // (OpenMLS refuses the author's own ciphertext). The local sidecar
        // is the only source. With a sidecar hit and NO MLS group at all,
        // the builder must still render the plaintext.
        let realm = "ck:realm:01904100-0000-7000-8000-000000000001";
        let flow = "ck:flow:01904100-0000-7000-8000-0000000000ab";
        let mut store = temp_state_store("private-flow-sidecar");
        // The writer stores the JSON-serialized patch value (a bare string).
        store.save_private_plaintext(realm, flow, "body", "\"author body\"");
        let ctx = MlsDecryptCtx {
            state_store: &store,
            realm_id: realm,
            actor_id: "did:web:alice.example",
            device_id: "ck:device:01904100-0000-7000-8000-000000000001",
        };
        // Even when the projection value is an un-decryptable envelope, the
        // sidecar wins (tier 1) with zero decryption.
        let envelope = json!({
            "scheme": "mls-rfc9420",
            "ciphertext": "AAAA",
            "content_type": KANBAN_FLOW_PATCH_VALUE_CONTENT_TYPE,
        });
        assert_eq!(
            private_flow_field_text(Some(&ctx), flow, "body", Some(&envelope)),
            "author body"
        );
        // A different flow id has no sidecar entry → falls back (blank for an
        // un-decryptable envelope).
        assert_eq!(
            private_flow_field_text(
                Some(&ctx),
                "ck:flow:01904100-0000-7000-8000-0000000000cd",
                "body",
                Some(&envelope)
            ),
            ""
        );
    }

    #[test]
    fn private_flow_empty_sidecar_does_not_mask_encrypted_locked_state() {
        let realm = "ck:realm:01904100-0000-7000-8000-000000000001";
        let flow = "ck:flow:01904100-0000-7000-8000-0000000000ab";
        let mut store = temp_state_store("private-flow-empty-sidecar");
        store.save_private_plaintext(realm, flow, "synthesis", "\"\"");
        let ctx = MlsDecryptCtx {
            state_store: &store,
            realm_id: realm,
            actor_id: "did:web:alice.example",
            device_id: "ck:device:01904100-0000-7000-8000-000000000001",
        };
        let envelope = json!({
            "scheme": "mls-rfc9420",
            "ciphertext": "AAAA",
            "content_type": KANBAN_FLOW_PATCH_VALUE_CONTENT_TYPE,
        });

        assert_eq!(
            private_flow_field_text(Some(&ctx), flow, "synthesis", Some(&envelope)),
            ""
        );
        assert!(private_flow_field_locked(
            Some(&ctx),
            flow,
            "synthesis",
            Some(&envelope)
        ));
    }

    #[test]
    fn card_builder_reads_author_plaintext_from_sidecar_without_mls_group() {
        // X5.2 gate — simulate the writer having stored the author's body
        // plaintext, then build a card from a projection whose body is an
        // un-decryptable MLS envelope, with NO MLS snapshot present. The
        // card must show the author's plaintext (proving the author sees
        // own content with zero decryption).
        let realm = "ck:realm:01904100-0000-7000-8000-000000000000";
        let flow = "ck:flow:01904100-0000-7000-8000-0000000000ab";
        let mut store = temp_state_store("card-builder-sidecar");
        store.save_private_plaintext(realm, flow, "body", "\"recovered body\"");
        let ctx = MlsDecryptCtx {
            state_store: &store,
            realm_id: realm,
            actor_id: "did:web:alice.example",
            device_id: "ck:device:01904100-0000-7000-8000-000000000001",
        };
        let flow_view = crate::api::FlowProjectionView {
            flow_id: flow.to_owned(),
            realm_id: realm.to_owned(),
            title: "Encrypted card".to_owned(),
            summary: Some("public summary".to_owned()),
            body: Some(json!({
                "scheme": "mls-rfc9420",
                "ciphertext": "AAAA",
                "content_type": KANBAN_FLOW_PATCH_VALUE_CONTENT_TYPE,
            })),
            board_space_id: None,
            list_space_id: None,
            rank: Some("U".to_owned()),
            assigned_actor_ids: Vec::new(),
            assigned_to_relations: Vec::new(),
            fields: Map::new(),
            created_by: None,
            created_at: None,
            updated_at: None,
            state: "active".to_owned(),
        };
        let card = card_from_flow_projection(&flow_view, Some(&ctx));
        assert_eq!(card.body, "recovered body");
        // Sanity: there is genuinely no MLS group to decrypt from.
        assert!(store.mls_snapshot_for(realm).is_none());
    }

    /// T20 wire-up — `collection_projection_to_columns` adapter maps the
    /// canonical SDK response into the renderer's KanbanColumn vec. This
    /// is the core integration point; if the spec wire shape changes,
    /// this test fails and points at the renderer adapter.
    #[test]
    fn collection_projection_maps_to_kanban_columns() {
        use cokret_sdk::{
            CollectionProjectionDiscussion, CollectionProjectionGroup, CollectionProjectionItem,
            CollectionProjectionOutcome, ViewId, ViewKind, ViewRenderer,
        };
        let projection = CollectionProjectionOutcome {
            kind: ViewKind::Collection,
            renderer: ViewRenderer::Board,
            view_id: ViewId::new("ck:view:01904100-0000-7000-8000-000000000001").unwrap(),
            frontier: vec!["ck:event:01904100-0000-7000-8000-000000000042".to_owned()],
            groups: vec![
                CollectionProjectionGroup {
                    group_id: "ck:space:01c3b617-7000-7000-8000-000000000000".to_owned(),
                    title: "Review".to_owned(),
                    rank: Some("mV".to_owned()),
                    items: vec![CollectionProjectionItem {
                        object: serde_json::json!({
                            "id": "ck:flow:01d2b330-0000-7000-8000-000000000000",
                            "type": "flow",
                            "title": "Legal review",
                            "summary": "ensure GDPR sign-off",
                            "body": {
                                "kind": "ck.content.text",
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
                    group_id: "ck:space:01t0d0000000000000000000000".to_owned(),
                    title: "To do".to_owned(),
                    rank: Some("aA".to_owned()),
                    items: Vec::new(),
                    hidden_count: None,
                },
            ],
        };

        let cols = collection_projection_to_columns(&projection, None);
        assert_eq!(cols.len(), 2, "two groups → two columns");
        assert_eq!(cols[0].id, "ck:space:01c3b617-7000-7000-8000-000000000000");
        assert_eq!(cols[0].title, "Review");
        assert_eq!(cols[0].rank, "mV");
        assert_eq!(cols[0].cards.len(), 1);
        let card = &cols[0].cards[0];
        assert_eq!(card.id, "ck:flow:01d2b330-0000-7000-8000-000000000000");
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

    #[test]
    fn collection_projection_overlay_applies_remote_encrypted_flow_updates() {
        use cokret_sdk::{
            CollectionProjectionGroup, CollectionProjectionItem, CollectionProjectionOutcome,
            ViewId, ViewKind, ViewRenderer,
        };
        let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
        let flow_id = "ck:flow:0196419b-0000-7000-8000-000000000003";
        let projection = CollectionProjectionOutcome {
            kind: ViewKind::Collection,
            renderer: ViewRenderer::Board,
            view_id: ViewId::new("ck:view:01904100-0000-7000-8000-000000000001").unwrap(),
            frontier: Vec::new(),
            groups: vec![CollectionProjectionGroup {
                group_id: board_id.to_owned(),
                title: "Todo".to_owned(),
                rank: Some("U".to_owned()),
                items: vec![CollectionProjectionItem {
                    object: json!({
                        "id": flow_id,
                        "type": "flow",
                        "title": "Encrypted card",
                    }),
                    position: None,
                    discussion: None,
                }],
                hidden_count: None,
            }],
        };
        let envelope = json!({
            "scheme": "mls-rfc9420",
            "ciphertext": "AAAA",
            "content_type": KANBAN_FLOW_PATCH_VALUE_CONTENT_TYPE,
            "group_id": "g",
            "epoch": 0,
        });
        let events = vec![json!({
            "event_id": "ck:event:0196419b-0000-7000-8000-00000000f003",
            "operation_id": "ck:operation:0196419b-0000-7000-8000-00000000f003",
            "event_kind": "ck.flow.update",
            "actor_id": "did:web:alice.example",
            "created_at": "2026-05-22T10:00:00Z",
            "realm_id": TEST_REALM_ID,
            "payload": {
                "flow_id": flow_id,
                "patch": {
                    "body": { "$op": "set", "value": envelope.clone() },
                    "synthesis": { "$op": "set", "value": envelope }
                }
            }
        })];
        let remote_operations = flow_update_operations_from_events(&events);
        let store = LocalStateStore::default();
        let ctx = MlsDecryptCtx {
            state_store: &store,
            realm_id: TEST_REALM_ID,
            actor_id: "did:web:alice.example",
            device_id: "ck:device:0196419b-0000-7000-8000-000000000001",
        };

        let cols = overlay_collection_projection_with_operations(
            &projection,
            &store,
            board_id,
            &remote_operations,
            Some(&ctx),
        );

        let card = &cols[0].cards[0];
        assert_eq!(card.body, "");
        assert!(card.body_locked);
        assert_eq!(card.synthesis, "");
        assert!(card.synthesis_locked);
    }

    /// T20 — when `discussion` is None on the projection item, the card
    /// renders as synthesis-only without a locked_flow.
    #[test]
    fn projection_item_without_discussion_renders_synthesis_only() {
        use cokret_sdk::CollectionProjectionItem;
        let item = CollectionProjectionItem {
            object: serde_json::json!({
                "id": "ck:flow:01doc",
                "title": "DID method allowlist",
            }),
            position: None,
            discussion: None,
        };
        let card = card_from_projection_item(&item, None);
        assert!(card.locked_flow.is_none());
        assert_eq!(card.history_visibility, "synthesis-only");
        assert_eq!(card.external_visibility, "No external discussions linked");
    }

    #[test]
    fn board_space_options_pick_board_spaces_from_projection() {
        let options = board_space_options_from_projection(&[
            crate::api::SpaceContainerProjectionView {
                space_id: "ck:space:0196419b-0000-7000-8000-000000000001".to_owned(),
                realm_id: "ck:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
                kind: "board".to_owned(),
                title: "Release".to_owned(),
                state: "active".to_owned(),
                rank: None,
                parent_space_id: None,
            },
            crate::api::SpaceContainerProjectionView {
                space_id: "ck:space:0196419b-0000-7000-8000-000000000002".to_owned(),
                realm_id: "ck:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
                kind: "list".to_owned(),
                title: "Todo".to_owned(),
                state: "active".to_owned(),
                rank: Some("U".to_owned()),
                parent_space_id: Some("ck:space:0196419b-0000-7000-8000-000000000001".to_owned()),
            },
        ]);

        assert_eq!(options.len(), 1);
        assert_eq!(
            options[0].id,
            "ck:space:0196419b-0000-7000-8000-000000000001"
        );
        assert_eq!(options[0].title, "Release");
    }

    #[test]
    fn local_space_create_overlay_restores_board_and_list_until_projection_catches_up() {
        let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
        let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
        let list_id = "ck:space:0196419b-0000-7000-8000-000000000002";
        let raw_operations = vec![
            RawOperationRecord {
                operation_id: "sha256:local-board-create".to_owned(),
                realm_id: Some(realm_id.to_owned()),
                received_at: chrono::Utc::now(),
                payload: json!({
                    "kind": "ck.space.create",
                    "operation_id": "sha256:local-board-create",
                    "body": {
                        "object": {
                            "id": board_id,
                            "schema": "ck.schema.space.v1",
                            "realm_id": realm_id,
                            "kind": "board",
                            "title": "Design board"
                        }
                    },
                    "write_state": "queued"
                }),
            },
            RawOperationRecord {
                operation_id: "sha256:local-list-create".to_owned(),
                realm_id: Some(realm_id.to_owned()),
                received_at: chrono::Utc::now(),
                payload: json!({
                    "kind": "ck.space.create",
                    "operation_id": "sha256:local-list-create",
                    "body": {
                        "object": {
                            "id": list_id,
                            "schema": "ck.schema.space.v1",
                            "realm_id": realm_id,
                            "kind": "list",
                            "title": "Todo",
                            "parent_space_id": board_id,
                            "rank": "U"
                        }
                    },
                    "write_state": "queued"
                }),
            },
        ];

        let (columns, options, selected_board) = columns_from_lifecycle_projection_with_local(
            &[],
            &[],
            board_id,
            &raw_operations,
            realm_id,
            None,
        );

        assert_eq!(selected_board.as_deref(), Some(board_id));
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].id, board_id);
        assert_eq!(options[0].title, "Design board");
        assert_eq!(columns.len(), 1);
        assert_eq!(columns[0].id, list_id);
        assert_eq!(columns[0].title, "Todo");
    }

    #[test]
    fn remote_space_create_backfill_restores_board_title_when_projection_only_has_list() {
        let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
        let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
        let list_id = "ck:space:0196419b-0000-7000-8000-000000000002";
        let events = vec![json!({
            "event_id": "ck:event:0196419b-0000-7000-8000-000000000101",
            "event_kind": "ck.space.create",
            "realm_id": realm_id,
            "actor_id": "did:web:alice.example",
            "created_at": "2026-05-31T00:00:00Z",
            "payload": {
                "object": {
                    "id": board_id,
                    "schema": "ck.schema.space.v1",
                    "realm_id": realm_id,
                    "kind": "board",
                    "title": "Board"
                }
            }
        })];
        let remote_operations = space_create_operations_from_events(&events);
        let containers = vec![crate::api::SpaceContainerProjectionView {
            space_id: list_id.to_owned(),
            realm_id: realm_id.to_owned(),
            kind: "list".to_owned(),
            title: "Todos".to_owned(),
            state: "active".to_owned(),
            rank: Some("U".to_owned()),
            parent_space_id: Some(board_id.to_owned()),
        }];

        let (columns, options, selected_board) = columns_from_lifecycle_projection_with_local(
            &containers,
            &[],
            board_id,
            &remote_operations,
            realm_id,
            None,
        );

        assert_eq!(selected_board.as_deref(), Some(board_id));
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].id, board_id);
        assert_eq!(options[0].title, "Board");
        assert_eq!(columns.len(), 1);
        assert_eq!(columns[0].title, "Todos");
    }

    #[test]
    fn local_space_create_state_becomes_synced_once_projection_contains_target() {
        let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
        let raw_operations = vec![RawOperationRecord {
            operation_id: "sha256:local-board-create".to_owned(),
            realm_id: Some("ck:realm:0196419b-0000-7000-8000-000000000000".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ck.space.create",
                "operation_id": "sha256:local-board-create",
                "body": {
                    "object": {
                        "id": board_id,
                        "schema": "ck.schema.space.v1",
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
    fn displayed_card_state_uses_server_flow_projection_over_local_queue() {
        let flow_id = "ck:flow:0196419b-0000-7000-8000-000000000003";
        let mut card = test_card(flow_id, "U");
        card.state = CardState::Queued;
        let projected_flow_ids = BTreeSet::from([flow_id.to_owned()]);

        assert_eq!(
            displayed_card_state(&card, &projected_flow_ids),
            CardState::Synced
        );
    }

    #[test]
    fn lifecycle_projection_builds_persisted_board_columns_and_cards() {
        let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
        let list_id = "ck:space:0196419b-0000-7000-8000-000000000002";
        let containers = vec![
            crate::api::SpaceContainerProjectionView {
                space_id: board_id.to_owned(),
                realm_id: "ck:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
                kind: "board".to_owned(),
                title: "Release".to_owned(),
                state: "active".to_owned(),
                rank: None,
                parent_space_id: None,
            },
            crate::api::SpaceContainerProjectionView {
                space_id: list_id.to_owned(),
                realm_id: "ck:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
                kind: "list".to_owned(),
                title: "Todo".to_owned(),
                state: "active".to_owned(),
                rank: Some("U".to_owned()),
                parent_space_id: Some(board_id.to_owned()),
            },
        ];
        let flows = vec![crate::api::FlowProjectionView {
            flow_id: "ck:flow:0196419b-0000-7000-8000-000000000003".to_owned(),
            realm_id: "ck:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
            title: "Persisted card".to_owned(),
            summary: Some("Loaded from projection".to_owned()),
            body: Some(json!({
                "kind": "ck.content.text",
                "body": "Projection body content"
            })),
            board_space_id: Some(board_id.to_owned()),
            list_space_id: Some(list_id.to_owned()),
            rank: Some("U".to_owned()),
            assigned_actor_ids: vec!["did:web:alice.example".to_owned()],
            assigned_to_relations: vec![crate::api::AssignedToRelationProjectionView {
                relation_id: "ck:relation:0196419b-0000-7000-8000-000000000004".to_owned(),
                actor_id: "did:web:alice.example".to_owned(),
            }],
            fields: Map::from_iter([
                ("labels".to_owned(), json!(["demo", "db"])),
                ("due_at".to_owned(), json!("2026-05-22")),
            ]),
            created_by: Some("did:web:acme.example:users:alice".to_owned()),
            created_at: Some("2026-05-22T10:00:00Z".to_owned()),
            updated_at: None,
            state: "active".to_owned(),
        }];

        let (columns, options, selected_board) =
            columns_from_lifecycle_projection(&containers, &flows, "", None);

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
        assert_eq!(card.assignee, "did:web:alice.example");
        assert_eq!(
            card.assigned_to_relations,
            vec![CardAssignedToRelation {
                relation_id: "ck:relation:0196419b-0000-7000-8000-000000000004".to_owned(),
                actor_id: "did:web:alice.example".to_owned(),
            }]
        );
        assert_eq!(card.due, "2026-05-22");
    }

    #[test]
    fn lifecycle_projection_infers_board_from_list_parent() {
        let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
        let list_id = "ck:space:0196419b-0000-7000-8000-000000000002";
        let containers = vec![crate::api::SpaceContainerProjectionView {
            space_id: list_id.to_owned(),
            realm_id: "ck:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
            kind: "list".to_owned(),
            title: "Todo".to_owned(),
            state: "active".to_owned(),
            rank: Some("U".to_owned()),
            parent_space_id: Some(board_id.to_owned()),
        }];

        let (columns, options, selected_board) =
            columns_from_lifecycle_projection(&containers, &[], "", None);

        assert_eq!(selected_board.as_deref(), Some(board_id));
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].id, board_id);
        assert_eq!(columns.len(), 1);
        assert_eq!(columns[0].id, list_id);
        assert_eq!(columns[0].title, "Todo");
    }

    #[test]
    fn local_flow_create_overlay_restores_card_until_projection_catches_up() {
        let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
        let list_id = "ck:space:0196419b-0000-7000-8000-000000000002";
        let flow_id = "ck:flow:0196419b-0000-7000-8000-000000000003";
        let raw_operations = vec![RawOperationRecord {
            operation_id: "sha256:local-create".to_owned(),
            realm_id: Some("ck:realm:0196419b-0000-7000-8000-000000000000".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ck.flow.create",
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
    fn remote_flow_update_events_overlay_detail_fields_on_projection() {
        let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
        let flow_id = "ck:flow:0196419b-0000-7000-8000-000000000003";
        let mut card = test_card(flow_id, "U");
        card.description = "old summary".to_owned();
        card.body = String::new();
        card.synthesis = String::new();
        let columns = vec![KanbanColumn {
            id: "ck:space:0196419b-0000-7000-8000-000000000002".to_owned(),
            title: "Todo".to_owned(),
            rank: "U".to_owned(),
            cards: vec![card],
            state: SpaceContainerLifecycleState::Active,
        }];
        let events = vec![json!({
            "event_id": "ck:event:0196419b-0000-7000-8000-00000000f001",
            "operation_id": "ck:operation:0196419b-0000-7000-8000-00000000f001",
            "event_kind": "ck.flow.update",
            "actor_id": "did:web:alice.example",
            "created_at": "2026-05-22T10:00:00Z",
            "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
            "payload": {
                "flow_id": flow_id,
                "patch": {
                    "metadata.summary": { "$op": "set", "value": "new summary" },
                    "fields.body": { "$op": "set", "value": "new long description" },
                    "tracks.synthesis.body": { "$op": "set", "value": "new synthesis note" },
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
        let remote_operations = flow_update_operations_from_events(&events);

        let projected = overlay_card_projection_with_operations(
            columns,
            &LocalStateStore::default(),
            board_id,
            &remote_operations,
        );

        let card = &projected[0].cards[0];
        assert_eq!(card.description, "new summary");
        assert_eq!(card.body, "new long description");
        assert_eq!(card.synthesis, "new synthesis note");
        assert_eq!(card.labels, vec!["remote"]);
        assert_eq!(card.due, "2026-05-30");
        assert_eq!(card.state, CardState::Synced);
    }

    #[test]
    fn remote_encrypted_flow_update_overlay_marks_private_fields_locked() {
        let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
        let flow_id = "ck:flow:0196419b-0000-7000-8000-000000000003";
        let mut card = test_card(flow_id, "U");
        card.body = String::new();
        card.synthesis = String::new();
        let columns = vec![KanbanColumn {
            id: "ck:space:0196419b-0000-7000-8000-000000000002".to_owned(),
            title: "Todo".to_owned(),
            rank: "U".to_owned(),
            cards: vec![card],
            state: SpaceContainerLifecycleState::Active,
        }];
        let envelope = json!({
            "scheme": "mls-rfc9420",
            "ciphertext": "AAAA",
            "content_type": KANBAN_FLOW_PATCH_VALUE_CONTENT_TYPE,
            "group_id": "g",
            "epoch": 0,
        });
        let events = vec![json!({
            "event_id": "ck:event:0196419b-0000-7000-8000-00000000f002",
            "operation_id": "ck:operation:0196419b-0000-7000-8000-00000000f002",
            "event_kind": "ck.flow.update",
            "actor_id": "did:web:alice.example",
            "created_at": "2026-05-22T10:00:00Z",
            "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
            "payload": {
                "flow_id": flow_id,
                "patch": {
                    "body": { "$op": "set", "value": envelope.clone() },
                    "tracks.synthesis.body": { "$op": "set", "value": {
                        "encrypted_content": envelope
                    } }
                }
            }
        })];
        let remote_operations = flow_update_operations_from_events(&events);
        let store = LocalStateStore::default();
        let ctx = MlsDecryptCtx {
            state_store: &store,
            realm_id: TEST_REALM_ID,
            actor_id: "did:web:alice.example",
            device_id: "ck:device:0196419b-0000-7000-8000-000000000001",
        };

        let projected = overlay_card_projection_with_operations_and_decrypt(
            columns,
            &store,
            board_id,
            &remote_operations,
            Some(&ctx),
        );

        let card = &projected[0].cards[0];
        assert_eq!(card.body, "");
        assert!(card.body_locked);
        assert_eq!(card.synthesis, "");
        assert!(card.synthesis_locked);
        assert_eq!(card.state, CardState::Synced);
    }

    #[test]
    fn kanban_seed_fallback_requires_explicit_opt_in() {
        assert!(!kanban_seed_fallback_allowed_for_url("https://local.host"));
        assert!(!kanban_seed_fallback_allowed_for_url(
            "http://127.0.0.1:8787"
        ));
        assert!(!kanban_seed_fallback_allowed_for_url(
            "https://cokret.example"
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
    fn due_calendar_parses_date_and_rfc3339_values() {
        assert_eq!(
            parse_due_calendar_date("2026-06-09"),
            Some(NaiveDate::from_ymd_opt(2026, 6, 9).unwrap())
        );
        assert_eq!(
            parse_due_calendar_date("2026-06-09T18:30:00Z"),
            Some(NaiveDate::from_ymd_opt(2026, 6, 9).unwrap())
        );
        assert_eq!(parse_due_calendar_date("unscheduled"), None);
    }

    #[test]
    fn due_calendar_month_navigation_crosses_years() {
        let jan_2026 = NaiveDate::from_ymd_opt(2026, 1, 17).unwrap();
        assert_eq!(
            add_due_calendar_months(jan_2026, -1),
            NaiveDate::from_ymd_opt(2025, 12, 1).unwrap()
        );
        let dec_2026 = NaiveDate::from_ymd_opt(2026, 12, 9).unwrap();
        assert_eq!(
            add_due_calendar_months(dec_2026, 1),
            NaiveDate::from_ymd_opt(2027, 1, 1).unwrap()
        );
    }

    #[test]
    fn due_calendar_cells_cover_sunday_first_six_week_grid() {
        let month = NaiveDate::from_ymd_opt(2026, 6, 1).unwrap();
        let cells = due_calendar_cells(month);
        assert_eq!(cells.len(), 42);
        assert_eq!(cells.first().unwrap().iso_date, "2026-05-31");
        assert_eq!(cells[1].iso_date, "2026-06-01");
        assert_eq!(cells.last().unwrap().iso_date, "2026-07-11");
        assert!(!cells[0].in_current_month);
        assert!(cells[1].in_current_month);
        assert!(!cells.last().unwrap().in_current_month);
    }

    #[test]
    fn card_activity_items_show_local_flow_and_assignment_writes() {
        let mut card = test_card("ck:flow:activity", "U");
        card.primary_flow_id = card.id.clone();
        let received_at = |value: &str| {
            chrono::DateTime::parse_from_rfc3339(value)
                .unwrap()
                .with_timezone(&chrono::Utc)
        };
        let raw_operations = vec![
            RawOperationRecord {
                operation_id: "op-assignee".to_owned(),
                realm_id: Some(TEST_REALM_ID.to_owned()),
                received_at: received_at("2026-06-10T10:00:00Z"),
                payload: json!({
                    "kind": "ck.relation.tombstone",
                    "operation_id": "op-assignee",
                    "write_state": "accepted",
                    "assignment_flow_id": card.id.clone(),
                    "assignment_actor_id": "did:web:alice.example",
                    "assignment_relation_id": "ck:relation:activity",
                    "activity_summary": "Assignee removed: alice",
                    "body": {
                        "relation_id": "ck:relation:activity"
                    }
                }),
            },
            RawOperationRecord {
                operation_id: "op-due".to_owned(),
                realm_id: Some(TEST_REALM_ID.to_owned()),
                received_at: received_at("2026-06-10T11:00:00Z"),
                payload: json!({
                    "kind": "ck.flow.update",
                    "operation_id": "op-due",
                    "write_state": "queued",
                    "activity_summary": "Due date cleared",
                    "body": {
                        "flow_id": card.id.clone(),
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

        let items = card_activity_items(&card, &raw_operations);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "Due date cleared");
        assert_eq!(items[0].status, CardActivityStatus::Pending);
        assert_eq!(items[1].title, "Assignee removed: alice");
        assert_eq!(items[1].status, CardActivityStatus::Accepted);
    }

    #[test]
    fn card_detail_update_patch_uses_flow_update_patch_paths() {
        let mut current = test_card("ck:flow:f1", "U");
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
        assert_eq!(patch["metadata.title"]["value"], "Launch checklist");
        assert_eq!(patch["metadata.summary"]["value"], "Ship blockers only");
        assert_eq!(patch["metadata.fields"]["value"]["labels"][0], "release");
        assert!(patch["metadata.fields"]["value"].get("assignee").is_none());
        assert_eq!(patch["metadata.fields"]["value"]["due_at"], "2026-05-20");
        assert!(patch["metadata.fields"]["value"].get("due").is_none());
    }

    #[test]
    fn relation_id_from_event_id_retags_assignment_relation_ids() {
        assert_eq!(
            relation_id_from_event_id("ck:event:0196419b-0000-7000-8000-000000000004").as_deref(),
            Some("ck:relation:0196419b-0000-7000-8000-000000000004")
        );
        assert!(relation_id_from_event_id("ck:message:bad").is_none());
    }

    #[test]
    fn card_assignment_mutations_create_and_tombstone_relation_events() {
        let mut current = test_card("ck:flow:0196419b-0000-7000-8000-000000000101", "U");
        current.assignee = "did:web:bob.example".to_owned();
        current.assigned_to_relations = vec![CardAssignedToRelation {
            relation_id: "ck:relation:0196419b-0000-7000-8000-0000000000bb".to_owned(),
            actor_id: "did:web:bob.example".to_owned(),
        }];
        let selected = BTreeSet::from(["did:web:alice.example".to_owned()]);

        let mutations = card_assignment_mutations(
            "ck:realm:0196419b-0000-7000-8000-000000000000",
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
        assert_eq!(create.operation().kind, "ck.relation.create");
        assert_eq!(create.operation().payload["kind"], json!("assigned_to"));
        assert_eq!(create.operation().payload["from_ref"], json!(current.id));
        assert_eq!(
            create.operation().payload["to_ref"],
            json!("did:web:alice.example")
        );
        assert!(create.operation().payload.get("relation_id").is_none());

        let tombstone = mutations
            .iter()
            .find(|mutation| matches!(mutation, CardAssignmentMutation::Tombstone { .. }))
            .expect("tombstone mutation");
        assert_eq!(
            tombstone.relation_id(),
            "ck:relation:0196419b-0000-7000-8000-0000000000bb"
        );
        assert_eq!(tombstone.operation().kind, "ck.relation.tombstone");
        assert_eq!(
            tombstone.operation().payload["relation_id"],
            json!("ck:relation:0196419b-0000-7000-8000-0000000000bb")
        );

        let after = assignment_relations_after_mutations(&current, &selected, &mutations);
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].actor_id, "did:web:alice.example");
        assert!(after[0].relation_id.starts_with("ck:relation:"));
    }

    #[test]
    fn card_assignment_mutations_clear_all_assignees() {
        let mut current = test_card("ck:flow:0196419b-0000-7000-8000-000000000101", "U");
        current.assigned_to_relations = vec![
            CardAssignedToRelation {
                relation_id: "ck:relation:0196419b-0000-7000-8000-0000000000aa".to_owned(),
                actor_id: "did:web:alice.example".to_owned(),
            },
            CardAssignedToRelation {
                relation_id: "ck:relation:0196419b-0000-7000-8000-0000000000bb".to_owned(),
                actor_id: "did:web:bob.example".to_owned(),
            },
        ];

        let selected = BTreeSet::new();
        let mutations = card_assignment_mutations(
            "ck:realm:0196419b-0000-7000-8000-000000000000",
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

    #[test]
    fn encrypted_scope_blocks_plaintext_flow_update_payload() {
        let event = crate::operation::ck_ops::flow_update_patch(
            TEST_REALM_ID,
            "did:web:alice.example",
            DEMO_FLOW_LEGAL_REVIEW_ID,
            json!({
                "body": {"$op": "set", "value": "private description"},
            }),
        )
        .expect("builds")
        .build("yougen");

        assert!(kanban_event_carries_plaintext_private_content(&event));
        let reason = kanban_plaintext_block_reason(Some(true), &event).unwrap();
        assert!(reason.contains("Encrypted Realm blocks plaintext ck.flow.update"));
        assert!(kanban_plaintext_block_reason(Some(false), &event).is_none());
    }

    /// R4 fail-closed: when the Realm security state is UNKNOWN (`None`, i.e.
    /// the security projection has not synced yet) the guard MUST block a
    /// plaintext private-content write rather than defaulting to plaintext.
    /// A known-plaintext Realm (`Some(false)`) is the legitimate case that
    /// MUST still be allowed — that is what keeps fail-closed from breaking
    /// normal plaintext flows.
    #[test]
    fn unknown_scope_security_blocks_plaintext_private_content_fail_closed() {
        let private_update = crate::operation::ck_ops::flow_update_patch(
            TEST_REALM_ID,
            "did:web:alice.example",
            DEMO_FLOW_LEGAL_REVIEW_ID,
            json!({
                "body": {"$op": "set", "value": "private description"},
            }),
        )
        .expect("builds")
        .build("yougen");
        assert!(kanban_event_carries_plaintext_private_content(
            &private_update
        ));
        // Unknown security state → fail-closed block.
        assert!(
            kanban_plaintext_block_reason(None, &private_update).is_some(),
            "unknown security state must fail closed for plaintext private content"
        );
        // Known-plaintext Realm → legitimate plaintext write, never blocked.
        assert!(
            kanban_plaintext_block_reason(Some(false), &private_update).is_none(),
            "known-plaintext Realm must keep allowing plaintext writes"
        );

        // Non-private metadata (container scaffold) is exempt even when the
        // security state is unknown, so board/list creation is not bricked
        // while the projection is in flight.
        let board_create = crate::operation::ck_ops::space_create(
            TEST_REALM_ID,
            "did:web:alice.example",
            "ck:space:00000000-0000-7000-8000-0000000000aa",
            "board",
            "Roadmap",
            None,
            None,
        )
        .expect("builds")
        .build("yougen");
        assert!(
            kanban_plaintext_block_reason(None, &board_create).is_none(),
            "container scaffold metadata must not be blocked by unknown security state"
        );
    }

    #[test]
    fn encrypted_scope_allows_encrypted_flow_update_patch_value() {
        let encrypted_payload = crate::crypto::compose_local_encrypted_message(
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-000000000001",
            "ck:space:0196419b-0000-7000-8000-000000000000",
            "ck:message:kanban-patch-test",
            "private synthesis",
        )
        .expect("test encryption should produce payload")
        .payload;
        let encrypted_payload = serde_json::to_value(encrypted_payload).unwrap();
        let event = crate::operation::ck_ops::flow_update_patch(
            TEST_REALM_ID,
            "did:web:alice.example",
            DEMO_FLOW_LEGAL_REVIEW_ID,
            json!({
                "synthesis": {"$op": "set", "value": encrypted_payload},
            }),
        )
        .expect("builds")
        .build("yougen");

        assert!(!kanban_event_carries_plaintext_private_content(&event));
        assert!(kanban_plaintext_block_reason(Some(true), &event).is_none());
    }

    #[test]
    fn private_patch_value_collection_targets_only_content_fields() {
        let patch = json!({
            "summary": {"$op": "set", "value": "metadata is allowed"},
            "body": {"$op": "set", "value": "private body"},
            "synthesis": {"$op": "unset"},
        });

        let values = collect_encryptable_private_patch_values(&patch).unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].0, "body");
        assert_eq!(
            serde_json::from_slice::<Value>(&values[0].1).unwrap(),
            json!("private body")
        );
    }

    #[test]
    fn encrypted_private_patch_without_mls_snapshot_is_blocked_before_queueing() {
        let mut state = temp_state_store("missing-mls");
        let secure = crate::secure_key_store::MemorySecureKeyStore::new();
        let patch = json!({
            "body": {"$op": "set", "value": "private body"},
        });

        let error = encrypt_private_card_detail_patch_values_with_store(
            patch,
            "ck:realm:01904100-0000-7000-8000-000000000001",
            "ck:flow:01904100-0000-7000-8000-0000000000ff",
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-000000000001",
            &mut state,
            &secure,
        )
        .unwrap_err();

        assert!(error.contains("MLS Welcome"));
        assert!(
            state
                .mls_snapshot_for("ck:realm:01904100-0000-7000-8000-000000000001")
                .is_none()
        );
        assert!(state.load().raw_operations.is_empty());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn encrypted_private_patch_creator_bootstraps_initial_mls_snapshot() {
        let actor = "did:web:alice.example";
        let device = "ck:device:01904100-0000-7000-8000-000000000001";
        let realm = "ck:realm:01904100-0000-7000-8000-000000000001";
        let mut state = temp_state_store("creator-bootstrap-mls");
        state.save_realm_tree_projection(
            realm,
            json!({
                "__kind": "realm",
                "owner": actor,
                "summary": {
                    "title": "Encrypted Realm",
                    "encryption_profile": "mls_rfc9420",
                    "owner": actor,
                }
            }),
        );
        let secure = crate::secure_key_store::MemorySecureKeyStore::new();
        let patch = json!({
            "body": {"$op": "set", "value": "private body"},
        });

        let flow_id = "ck:flow:01904100-0000-7000-8000-0000000000ff";
        let (patched, mls_events) = encrypt_private_card_detail_patch_values_with_store(
            patch, realm, flow_id, actor, device, &mut state, &secure,
        )
        .unwrap();

        assert!(state.mls_snapshot_for(realm).is_some());
        // X5.1 — the author's own plaintext is persisted to the local
        // sidecar so a re-projection can render it (the author can never
        // decrypt their own ciphertext).
        assert_eq!(
            state
                .private_plaintext_for(realm, flow_id, "body")
                .as_deref(),
            Some("\"private body\"")
        );
        assert_eq!(
            patched["body"]["value"]["content_type"],
            KANBAN_FLOW_PATCH_VALUE_CONTENT_TYPE
        );
        assert!(mls_events.commit.is_none());
        assert!(mls_events.snapshot.is_none());
        // A freshly-created creator group must still produce a one-time
        // ck.mls.genesis event; ordinary application writes ride epoch 0
        // without a per-write commit.
        let genesis = mls_events
            .genesis
            .expect("freshly-created creator group should emit genesis");
        assert_eq!(genesis.kind, "ck.mls.genesis");
        assert_eq!(genesis.payload["epoch"].as_u64(), Some(0));
        assert_eq!(
            genesis.payload["creator_principal_id"].as_str(),
            Some(actor)
        );
        assert!(genesis.payload.get("governance_binding").is_some());
        assert_registered_payload_valid(&genesis);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn encrypted_private_patch_with_ready_snapshot_replaces_plaintext() {
        use cokret_sdk::{CokretMlsIdentity, DeviceId, Did};

        let actor = "did:web:alice.example";
        let device = "ck:device:01904100-0000-7000-8000-000000000001";
        let realm = "ck:realm:01904100-0000-7000-8000-000000000001";
        let mut state = temp_state_store("ready-mls");
        let secure = crate::secure_key_store::MemorySecureKeyStore::new();
        let secret =
            crate::mls::runtime::load_or_create_device_snapshot_secret(&secure, actor, device)
                .unwrap();
        let identity = CokretMlsIdentity::new_basic(
            Did::new(actor.to_owned()).unwrap(),
            DeviceId::new(device.to_owned()).unwrap(),
        )
        .unwrap();
        let group = identity.create_group(realm.as_bytes()).unwrap();
        let record = group.export_state_record().unwrap();
        let mut envelope = crate::mls::persistence::encrypt_state(
            realm,
            &record.group_id,
            record.epoch,
            &serde_json::to_vec(&record).unwrap(),
            &secret,
            b"deterministic-salt",
        );
        state.save_realm_tree_projection(
            realm,
            json!({ "active_profiles": [cokret_sdk::mls::MINIMAL_METADATA_REALM_PROFILE] }),
        );
        envelope.epoch_started_at = chrono::Utc::now() - chrono::Duration::hours(2);
        state.save_mls_snapshot(realm, envelope);
        let patch = json!({
            "body": {"$op": "set", "value": "private body"},
        });

        let flow_id = "ck:flow:01904100-0000-7000-8000-0000000000ff";
        let (patched, mls_events) = encrypt_private_card_detail_patch_values_with_store(
            patch, realm, flow_id, actor, device, &mut state, &secure,
        )
        .unwrap();

        assert_eq!(
            patched["body"]["value"]["content_type"],
            KANBAN_FLOW_PATCH_VALUE_CONTENT_TYPE
        );
        assert!(patched["body"]["value"].get("ciphertext").is_some());
        // X5.2 gate — the on-the-wire patch value is an MLS envelope (no
        // plaintext), while the local sidecar now holds the plaintext.
        assert!(value_is_mls_envelope(&patched["body"]["value"]));
        let envelope_str = serde_json::to_string(&patched["body"]["value"]).unwrap();
        assert!(
            !envelope_str.contains("private body"),
            "on-wire envelope must not contain the plaintext"
        );
        assert_eq!(
            state
                .private_plaintext_for(realm, flow_id, "body")
                .as_deref(),
            Some("\"private body\"")
        );
        // The snapshot already existed (not freshly created here), so there is
        // no fresh epoch-0 material and genesis is not emitted on this path.
        assert!(mls_events.genesis.is_none());
        assert!(mls_events.snapshot.is_some());
        let commit = mls_events
            .commit
            .expect("overdue minimal metadata MLS snapshot should emit commit event");
        assert_eq!(commit.kind, "ck.mls.commit");
        assert_registered_payload_valid(&commit);
        assert!(commit.payload.get("group_id").is_none());
        assert!(commit.payload.get("expected_prev_epoch").is_none());
        assert!(commit.payload.get("commit_bytes_b64").is_none());
        assert!(commit.payload.get("preconditions").is_none());
        assert!(commit.payload.get("effects").is_none());
        assert_eq!(
            commit.payload["governance_binding"]["realm_id"],
            json!("ck:realm:01904100-0000-7000-8000-000000000001")
        );
        assert_eq!(
            commit.payload["governance_binding"]["effective_scope"],
            json!({
                "kind": "realm",
                "realm_id": "ck:realm:01904100-0000-7000-8000-000000000001",
            })
        );
        assert_eq!(
            commit.payload["governance_binding"]["membership_frontier"][0],
            json!(commit.event_id)
        );
        assert!(state.load().raw_operations.is_empty());
    }

    #[test]
    fn encrypted_metadata_only_patch_does_not_require_mls_snapshot() {
        let mut state = temp_state_store("metadata-only");
        let secure = crate::secure_key_store::MemorySecureKeyStore::new();
        let patch = json!({
            "summary": {"$op": "set", "value": "metadata summary"},
        });

        let (patched, mls_events) = encrypt_private_card_detail_patch_values_with_store(
            patch.clone(),
            "ck:space:01904100-0000-7000-8000-000000000001",
            "ck:flow:01904100-0000-7000-8000-0000000000ff",
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-000000000001",
            &mut state,
            &secure,
        )
        .unwrap();

        assert_eq!(patched, patch);
        assert!(mls_events.commit.is_none());
        assert!(mls_events.genesis.is_none());
        assert!(state.local_identity_record().is_none());
    }

    #[test]
    fn encrypted_scope_allows_structural_flow_position_update() {
        let event = crate::operation::ck_ops::flow_position_update(
            TEST_REALM_ID,
            "did:web:alice.example",
            DEMO_FLOW_LEGAL_REVIEW_ID,
            json!({
                "board_space_id": "ck:space:0196419b-0000-7000-8000-000000000001",
                "list_space_id": "ck:space:0196419b-0000-7000-8000-000000000002",
                "rank": "U",
            }),
        )
        .expect("builds")
        .build("yougen");

        assert_eq!(event.kind, "ck.flow.update");
        assert!(!kanban_event_carries_plaintext_private_content(&event));
        assert!(kanban_plaintext_block_reason(Some(true), &event).is_none());
    }

    #[test]
    fn encrypted_scope_allows_content_only_metadata_create_payloads() {
        let flow = crate::operation::ck_ops::kanban_card_flow_create(
            TEST_REALM_ID,
            "did:web:alice.example",
            DEMO_FLOW_LEGAL_REVIEW_ID,
            "ck:space:0196419b-0000-7000-8000-000000000001",
            "ck:space:0196419b-0000-7000-8000-000000000002",
            "private card title",
            "U",
        )
        .expect("builds")
        .build("yougen");
        let space = crate::operation::ck_ops::space_create(
            TEST_REALM_ID,
            "did:web:alice.example",
            "ck:space:0196419b-0000-7000-8000-000000000002",
            "list",
            "private list title",
            Some("ck:space:0196419b-0000-7000-8000-000000000001"),
            Some("U"),
        )
        .expect("builds")
        .build("yougen");

        assert!(kanban_plaintext_block_reason(Some(true), &flow).is_none());
        assert!(kanban_plaintext_block_reason(Some(true), &space).is_none());
    }

    /// X13 regression: in an encrypted scope, container creation
    /// (`ck.space.create` for BOTH board and list) MUST NOT be blocked — the
    /// title/kind/parent/rank are non-secret metadata that has to reach the
    /// server so a second device can render the real Board/List name. By
    /// contrast a `ck.flow.update` carrying plaintext private body MUST stay
    /// blocked (only E2EE may leave the client for that field).
    #[test]
    fn encrypted_scope_never_blocks_container_create_but_blocks_plaintext_private_content() {
        let board = crate::operation::ck_ops::space_create(
            TEST_REALM_ID,
            "did:web:alice.example",
            "ck:space:0196419b-0000-7000-8000-00000000aa01",
            "board",
            "ZZTEST board title",
            None,
            None,
        )
        .expect("builds")
        .build("yougen");
        assert_eq!(board.kind, "ck.space.create");
        assert!(
            kanban_plaintext_block_reason(Some(true), &board).is_none(),
            "encrypted scope must not block board container create"
        );

        let list = crate::operation::ck_ops::space_create(
            TEST_REALM_ID,
            "did:web:alice.example",
            "ck:space:0196419b-0000-7000-8000-00000000aa02",
            "list",
            "Todos list title",
            Some("ck:space:0196419b-0000-7000-8000-00000000aa01"),
            Some("r001"),
        )
        .expect("builds")
        .build("yougen");
        assert_eq!(list.kind, "ck.space.create");
        assert!(
            kanban_plaintext_block_reason(Some(true), &list).is_none(),
            "encrypted scope must not block list container create"
        );

        // Counter-case: plaintext private body in a flow update is still blocked.
        let private_update = crate::operation::ck_ops::flow_update_patch(
            TEST_REALM_ID,
            "did:web:alice.example",
            DEMO_FLOW_LEGAL_REVIEW_ID,
            json!({
                "body": {"$op": "set", "value": "private description"},
            }),
        )
        .expect("builds")
        .build("yougen");
        assert!(
            kanban_plaintext_block_reason(Some(true), &private_update).is_some(),
            "encrypted scope must still block plaintext private flow content"
        );
    }

    #[test]
    fn encrypted_scope_allows_flow_summary_metadata_update() {
        let event = crate::operation::ck_ops::flow_update_patch(
            TEST_REALM_ID,
            "did:web:alice.example",
            DEMO_FLOW_LEGAL_REVIEW_ID,
            json!({
                "summary": {"$op": "set", "value": "metadata summary"},
            }),
        )
        .expect("builds")
        .build("yougen");

        assert!(!kanban_event_carries_plaintext_private_content(&event));
        assert!(kanban_plaintext_block_reason(Some(true), &event).is_none());
    }

    #[test]
    fn local_card_update_overlay_replays_queued_summary_and_body_on_top_of_projection() {
        // Simulate: server projection returns the pre-edit card; the user
        // had queued a ck.flow.update locally that bumped summary + body.
        // After page refresh, the overlay must re-apply that patch so the
        // user doesn't see their edits silently disappear.
        let mut card = test_card("ck:flow:edit-me", "U");
        card.title = "old title".to_owned();
        card.description = "old summary".to_owned();
        card.body = "old body".to_owned();
        card.synthesis = "old synthesis".to_owned();
        let columns = vec![KanbanColumn {
            id: "ck:space:list-a".to_owned(),
            title: "A".to_owned(),
            rank: "U".to_owned(),
            cards: vec![card],
            state: SpaceContainerLifecycleState::Active,
        }];
        let queued = RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ck:realm:r1".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ck.flow.update",
                "operation_id": "op-1",
                "write_state": "queued",
                "body": {
                    "flow_id": "ck:flow:edit-me",
                    "patch": {
                        "title": { "$op": "set", "value": "new title" },
                        "summary": { "$op": "set", "value": "new summary" },
                        "body": { "$op": "set", "value": "new body" },
                        "synthesis": { "$op": "set", "value": "new synthesis" },
                    },
                },
            }),
        };
        let overlaid = overlay_local_card_update_records(columns, &[queued], None);
        let card = &overlaid[0].cards[0];
        assert_eq!(card.title, "new title");
        assert_eq!(card.description, "new summary");
        assert_eq!(card.body, "new body");
        assert_eq!(card.synthesis, "new synthesis");
        assert_eq!(card.state, CardState::Queued);
    }

    #[test]
    fn overlay_local_card_update_records_clears_due_from_fields_replacement() {
        let mut card = test_card("ck:flow:edit-me", "U");
        card.due = "2026-06-11".to_owned();
        let columns = vec![KanbanColumn {
            id: "ck:space:list-a".to_owned(),
            title: "A".to_owned(),
            rank: "U".to_owned(),
            cards: vec![card],
            state: SpaceContainerLifecycleState::Active,
        }];
        let queued = RawOperationRecord {
            operation_id: "op-clear-due".to_owned(),
            realm_id: Some("ck:realm:r1".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ck.flow.update",
                "operation_id": "op-clear-due",
                "write_state": "queued",
                "body": {
                    "flow_id": "ck:flow:edit-me",
                    "patch": {
                        "metadata.fields": {
                            "$op": "set",
                            "value": { "labels": [] }
                        },
                    },
                },
            }),
        };
        let overlaid = overlay_local_card_update_records(columns, &[queued], None);
        assert_eq!(overlaid[0].cards[0].due, "—");
    }

    #[test]
    fn card_synthesis_track_entries_preserve_append_history() {
        let mut card = test_card("ck:flow:edit-me", "U");
        card.synthesis = "second synthesis".to_owned();
        card.created_by = "did:web:acme.example:users:alice".to_owned();
        card.created_at = "2026-05-22T09:00:00Z".to_owned();
        card.updated_at = "2026-05-22T11:00:00Z".to_owned();
        let received_at = |value: &str| {
            chrono::DateTime::parse_from_rfc3339(value)
                .unwrap()
                .with_timezone(&chrono::Utc)
        };
        let raw_operations = vec![
            RawOperationRecord {
                operation_id: "op-1".to_owned(),
                realm_id: Some("ck:realm:r1".to_owned()),
                received_at: received_at("2026-05-22T10:00:00Z"),
                payload: json!({
                    "kind": "ck.flow.update",
                    "operation_id": "op-1",
                    "actor_id": "did:web:acme.example:users:alice",
                    "created_at": "2026-05-22T10:00:00Z",
                    "write_state": "queued",
                    "body": {
                        "flow_id": "ck:flow:edit-me",
                        "patch": {
                            "synthesis": { "$op": "set", "value": "first synthesis" }
                        }
                    }
                }),
            },
            RawOperationRecord {
                operation_id: "op-2".to_owned(),
                realm_id: Some("ck:realm:r1".to_owned()),
                received_at: received_at("2026-05-22T11:00:00Z"),
                payload: json!({
                    "kind": "ck.flow.update",
                    "operation_id": "op-2",
                    "actor_id": "did:web:acme.example:users:bob",
                    "created_at": "2026-05-22T11:00:00Z",
                    "write_state": "queued",
                    "body": {
                        "flow_id": "ck:flow:edit-me",
                        "patch": {
                            "synthesis": { "$op": "set", "value": "second synthesis" }
                        }
                    }
                }),
            },
        ];

        let entries =
            card_synthesis_track_entries(&card, &raw_operations, &LocalStateStore::default());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].body, "second synthesis");
        assert_eq!(entries[0].author_label, "bob:acme.example");
        assert_eq!(entries[0].timestamp_label, "2026-05-22 11:00");
        assert!(entries[0].edited);
        assert_eq!(entries[0].revisions.len(), 2);
        assert_eq!(entries[0].revisions[0].body, "first synthesis");
        assert_eq!(entries[0].revisions[0].author_label, "alice:acme.example");
        assert_eq!(entries[0].revisions[1].body, "second synthesis");
    }

    #[test]
    fn card_synthesis_author_prefers_cached_member_primary_handle() {
        let actor = "did:web:auth.local.host:users:01kth8q1w1f9c9pt3a0zfvf6gb";
        let subject = "did:web:auth.local.host:principals:alice";
        let digest = "sha256:abababababababababababababababababababababababababababababababab";
        let mut card = test_card("ck:flow:edit-me", "U");
        card.synthesis = "wqefqqwf".to_owned();
        card.created_by = actor.to_owned();

        let projection = json!({
            "realm_id": TEST_REALM_ID,
            "members": [{
                "actor_id": actor,
                "membership": "join",
                "subject_id": subject,
                "member_display_state_digest": digest
            }]
        });
        let rows = realm_member_roster(Some(&projection));
        let mut store = temp_state_store("synthesis-primary-handle");
        store.save_member_handle_lookup(
            subject,
            Some(TEST_REALM_ID.to_owned()),
            Some(digest.to_owned()),
            Some("abbc:auth.local.host".to_owned()),
            1,
            None,
            None,
        );
        let context = CardAuthorDisplayContext {
            realm_id: TEST_REALM_ID,
            member_rows: &rows,
        };

        let entries =
            card_synthesis_track_entries_with_author_context(&card, &[], &store, Some(context));

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].author_label, "abbc:auth.local.host");
        assert_ne!(
            entries[0].author_label,
            "01kth8q1w1f9c9pt3a0zfvf6gb:auth.local.host"
        );
    }

    #[test]
    fn synthesis_new_entry_appends_without_replacing_existing_entries() {
        let mut card = test_card("ck:flow:edit-me", "U");
        card.synthesis = join_synthesis_entry_bodies(vec![
            "first active synthesis".to_owned(),
            "second active synthesis".to_owned(),
        ]);

        let entries = card_synthesis_track_entries(&card, &[], &LocalStateStore::default());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].body, "first active synthesis");
        assert_eq!(entries[1].body, "second active synthesis");

        let updated = synthesis_body_after_entry_edit(&entries, None, "third active synthesis");
        let bodies = split_synthesis_entry_bodies(&updated);
        assert_eq!(
            bodies,
            vec![
                "first active synthesis".to_owned(),
                "second active synthesis".to_owned(),
                "third active synthesis".to_owned(),
            ]
        );
    }

    #[test]
    fn flow_participant_dids_filters_by_target_flow_and_pulls_unique_actors() {
        let ops = vec![
            RawOperationRecord {
                operation_id: "op-a".to_owned(),
                realm_id: Some("ck:realm:r1".to_owned()),
                received_at: chrono::Utc::now(),
                payload: json!({
                    "kind": "ck.flow.update",
                    "body": {
                        "flow_id": "ck:flow:target",
                        "actor_id": "did:web:alice.example",
                    },
                }),
            },
            // Same flow, different actor — both should appear.
            RawOperationRecord {
                operation_id: "op-b".to_owned(),
                realm_id: Some("ck:realm:r1".to_owned()),
                received_at: chrono::Utc::now(),
                payload: json!({
                    "kind": "ck.message.create",
                    "body": {
                        "target_ref": "ck:flow:target",
                        // canonical actor key only — the legacy `sender`
                        // fallback was removed (hard_reject).
                        "actor_id": "did:web:bob.example",
                    },
                }),
            },
            // Different flow — must be excluded so we don't bleed
            // unrelated realm actors into the per-card participant list.
            RawOperationRecord {
                operation_id: "op-c".to_owned(),
                realm_id: Some("ck:realm:r1".to_owned()),
                received_at: chrono::Utc::now(),
                payload: json!({
                    "kind": "ck.flow.update",
                    "body": {
                        "flow_id": "ck:flow:other",
                        "actor_id": "did:web:carol.example",
                    },
                }),
            },
        ];
        let dids = flow_participant_dids(&ops, "ck:flow:target");
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
        let mut current = test_card("ck:flow:f1", "U");
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
        let mut current = test_card("ck:flow:f1", "U");
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
        assert_eq!(patch["metadata.summary"]["$op"], "unset");
        assert!(patch["metadata.fields"]["value"].get("assignee").is_none());
        assert!(patch["metadata.fields"]["value"].get("due_at").is_none());
    }

    #[test]
    fn apply_card_detail_draft_marks_card_queued() {
        let mut card = test_card("ck:flow:f1", "U");
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
    ///   3. insert into the target column such that ascending-rank ordering is preserved (otherwise
    ///      the next drag uses wrong neighbours for `rank_between`).
    #[test]
    fn relocate_card_preserves_rank_ordering_after_move() {
        let mut cols = vec![
            KanbanColumn {
                id: "ck:space:list-a".to_owned(),
                title: "A".to_owned(),
                rank: "U".to_owned(),
                cards: vec![test_card("ck:flow:a1", "U"), test_card("ck:flow:a2", "f")],
                state: SpaceContainerLifecycleState::Active,
            },
            KanbanColumn {
                id: "ck:space:list-b".to_owned(),
                title: "B".to_owned(),
                rank: "f".to_owned(),
                cards: vec![test_card("ck:flow:b1", "U"), test_card("ck:flow:b3", "z")],
                state: SpaceContainerLifecycleState::Active,
            },
        ];
        // Move a1 from A → B, dropped at rank "m" (between b1=U and b3=z).
        let moved = relocate_card(
            &mut cols,
            "ck:flow:a1",
            "ck:space:list-a",
            "ck:space:list-b",
            "m",
        )
        .unwrap();
        assert_eq!(moved.id, "ck:flow:a1");
        assert_eq!(moved.rank, "m");
        // Source column no longer contains a1, still has a2.
        let a = &cols[0];
        assert_eq!(a.cards.len(), 1);
        assert_eq!(a.cards[0].id, "ck:flow:a2");
        // Target column has b1 (U) < a1 (m) < b3 (z), ordering preserved.
        let b = &cols[1];
        assert_eq!(b.cards.len(), 3);
        assert_eq!(b.cards[0].id, "ck:flow:b1");
        assert_eq!(b.cards[1].id, "ck:flow:a1");
        assert_eq!(b.cards[2].id, "ck:flow:b3");
    }

    /// In-list reorder: removing from a column then re-inserting into
    /// the **same** column (target == source) at a new rank should
    /// land at the right position.
    #[test]
    fn relocate_card_handles_in_list_reorder() {
        let mut cols = vec![KanbanColumn {
            id: "ck:space:list-a".to_owned(),
            title: "A".to_owned(),
            rank: "U".to_owned(),
            cards: vec![
                test_card("ck:flow:a1", "U"),
                test_card("ck:flow:a2", "f"),
                test_card("ck:flow:a3", "p"),
            ],
            state: SpaceContainerLifecycleState::Active,
        }];
        // Move a3 to the top of the same list (rank "0" — before "U").
        let moved = relocate_card(
            &mut cols,
            "ck:flow:a3",
            "ck:space:list-a",
            "ck:space:list-a",
            "0",
        )
        .unwrap();
        assert_eq!(moved.rank, "0");
        let a = &cols[0];
        assert_eq!(a.cards.len(), 3);
        assert_eq!(a.cards[0].id, "ck:flow:a3");
        assert_eq!(a.cards[1].id, "ck:flow:a1");
        assert_eq!(a.cards[2].id, "ck:flow:a2");
    }

    /// `locate_flow_position_in_projection` is the post-conflict rebase
    /// adapter — it must find the flow's current cell pre-state from a
    /// freshly-fetched projection. When the flow is present with a
    /// position, return `At { list_space_id, rank }`; absent ⇒ `Initial`.
    #[test]
    fn locate_flow_position_finds_present_flow_with_rank() {
        use cokret_sdk::{
            CollectionProjectionGroup, CollectionProjectionItem, CollectionProjectionPosition,
            CollectionProjectionOutcome, ViewId, ViewKind, ViewRenderer,
        };
        let projection = CollectionProjectionOutcome {
            kind: ViewKind::Collection,
            renderer: ViewRenderer::Board,
            view_id: ViewId::new("ck:view:01904100-0000-7000-8000-000000000001").unwrap(),
            frontier: Vec::new(),
            groups: vec![CollectionProjectionGroup {
                group_id: "ck:space:01list-review".to_owned(),
                title: "Review".to_owned(),
                rank: Some("U".to_owned()),
                items: vec![CollectionProjectionItem {
                    object: serde_json::json!({
                        "id": "ck:flow:01wanted",
                        "title": "Find me",
                    }),
                    position: Some(CollectionProjectionPosition {
                        relation_id: "ck:relation:01rel".to_owned(),
                        rank: "h3".to_owned(),
                    }),
                    discussion: None,
                }],
                hidden_count: None,
            }],
        };
        let expected = locate_flow_position_in_projection(&projection, "ck:flow:01wanted");
        assert_eq!(
            expected,
            FlowPositionExpectation::At {
                list_space_id: "ck:space:01list-review".to_owned(),
                rank: "h3".to_owned(),
            }
        );
    }

    /// When the flow isn't in the projection, the rebase must use
    /// `head_eq null` (Initial) — soland's reducer rejects if the cell
    /// is actually non-initial, which is the safe behaviour.
    #[test]
    fn locate_flow_position_missing_flow_returns_initial() {
        use cokret_sdk::{CollectionProjectionOutcome, ViewId, ViewKind, ViewRenderer};
        let projection = CollectionProjectionOutcome {
            kind: ViewKind::Collection,
            renderer: ViewRenderer::Board,
            view_id: ViewId::new("ck:view:01904100-0000-7000-8000-000000000001").unwrap(),
            frontier: Vec::new(),
            groups: Vec::new(),
        };
        let expected = locate_flow_position_in_projection(&projection, "ck:flow:01missing");
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
            body_locked: false,
            synthesis_locked: false,
            created_by: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
            labels: Vec::new(),
            assignee: String::new(),
            assigned_to_relations: Vec::new(),
            due: String::new(),
            primary_flow_id: String::new(),
            locked_flow: None,
            external_visibility: String::new(),
            history_visibility: String::new(),
            security_encrypted: None,
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
            .flat_map(|c| c.cards.iter().map(|card| card.state.data_state()))
            .collect();
        states.sort();
        states.dedup();
        assert!(states.contains(&"synced"), "seed missing Synced demo card");
        assert!(states.contains(&"queued"), "seed missing Queued demo card");
        assert!(
            states.contains(&"conflict"),
            "seed missing Conflict demo card"
        );
    }

    #[test]
    fn seed_flow_ids_are_valid_object_patch_targets() {
        for flow_id in [
            DEMO_FLOW_LEGAL_REVIEW_ID,
            DEMO_FLOW_ONBOARDING_COPY_ID,
            DEMO_FLOW_SECURITY_SIGNOFF_ID,
        ] {
            let event = crate::operation::ck_ops::flow_update_patch(
                DEMO_BOARD_SPACE_ID,
                "did:web:acme.example:users:alice",
                flow_id,
                json!({"synthesis": {"$op": "set", "value": "demo synthesis"}}),
            )
            .expect("builds")
            .build("yougen");
            assert_eq!(event.kind, "ck.flow.update");
            assert_eq!(event.local_target_ref(), Some(flow_id));
        }
    }
}
