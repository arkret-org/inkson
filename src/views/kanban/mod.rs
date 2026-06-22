use std::collections::BTreeSet;

use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use dioxus_router::hooks::{use_navigator, use_route};
use serde_json::{Map, Value, json};

use crate::components::{
    EmptyState, EmptyStateKind, SecurityStateBadge, SelfAttributionBadge, UiIcon, WriteStateIcon,
};
use crate::local_state::LocalStateStore;
use crate::operation::uuid_v7;
use crate::rank::rank_for_drop;
use crate::routes::Route;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::select::{Select, SelectOption};
use crate::ui::textarea::Textarea;
use crate::views::helpers::{short_protocol_id, with_authed_api};

mod dnd;
// YOU-07-001: card due-calendar pure calculation helpers moved to `due_calendar`
// (move-only).
mod due_calendar;
/// Board Space id used only when the explicit demo seed fallback is
/// enabled. Normal kanban routes render server projections instead of
/// hard-coded cards.
mod model;

use dnd::*;
use due_calendar::*;
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
    /// confuse the toast bootstrap script. Defaults to the stable
    /// `"description"` slot used by existing data-testids.
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
            let Some(script) = toast_editor_bootstrap_script(&host_id, &fallback_id, &value) else {
                return;
            };
            // YOU-06-002: the editor JS only extracts file bytes and hands
            // them to Rust over the eval channel; the upload itself runs
            // through the canonical `CokretApi` pipeline (auth headers,
            // retry/backoff, error-envelope decoding) instead of a JS
            // `fetch` that hand-rolls the wire.
            let mut eval = document::eval(&script);
            let base_url = base_url.clone();
            let token = token.clone();
            let realm_id = realm_id.clone();
            spawn(async move {
                loop {
                    let request: Value = match eval.recv().await {
                        Ok(request) => request,
                        Err(_) => break,
                    };
                    match request.get("kind").and_then(Value::as_str) {
                        Some("upload") => {}
                        // The JS side releases this bridge (editor torn
                        // down, bootstrap superseded, or fallback mode).
                        Some("dispose") => break,
                        _ => continue,
                    }
                    let id = request.get("id").cloned().unwrap_or(Value::Null);
                    let reply = match toast_editor_upload_via_api(
                        &base_url,
                        token.clone(),
                        &realm_id,
                        &request,
                    )
                    .await
                    {
                        Ok((blob_ref, media_type)) => json!({
                            "id": id,
                            "ok": true,
                            "blob_ref": blob_ref,
                            "media_type": media_type,
                        }),
                        Err(error) => json!({"id": id, "ok": false, "error": error}),
                    };
                    if eval.send(reply).is_err() {
                        break;
                    }
                }
            });
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

fn update_calendar_draft(
    mut calendar: Signal<CalendarCardFields>,
    update: impl FnOnce(&mut CalendarCardFields),
) {
    let mut next = calendar();
    update(&mut next);
    calendar.set(next);
}

#[component]
fn CalendarScheduleEditForm(
    calendar: Signal<CalendarCardFields>,
    status: String,
    on_save: EventHandler<()>,
    on_cancel: EventHandler<()>,
) -> Element {
    let selected_frequency = use_memo(move || {
        let frequency = calendar().recurrence_frequency.trim().to_owned();
        Some(if frequency.is_empty() {
            "none".to_owned()
        } else {
            frequency
        })
    });
    rsx! {
        div { class: "workflow-form card-detail-edit-form", "data-testid": "card-detail-calendar-edit-form",
            div { class: "field",
                Label { html_for: "card-detail-calendar-start-input", "Start" }
                Input {
                    id: "card-detail-calendar-start-input",
                    class: "input",
                    "data-testid": "card-detail-calendar-start-input",
                    value: "{calendar().start}",
                    placeholder: "2026-06-20T09:00:00Z",
                    oninput: move |event: FormEvent| update_calendar_draft(calendar, |draft| draft.start = event.value()),
                }
            }
            div { class: "field",
                Label { html_for: "card-detail-calendar-end-input", "End" }
                Input {
                    id: "card-detail-calendar-end-input",
                    class: "input",
                    "data-testid": "card-detail-calendar-end-input",
                    value: "{calendar().end}",
                    placeholder: "2026-06-20T10:00:00Z",
                    oninput: move |event: FormEvent| update_calendar_draft(calendar, |draft| draft.end = event.value()),
                }
            }
            div { class: "field",
                Label { html_for: "card-detail-calendar-timezone-input", "Timezone" }
                Input {
                    id: "card-detail-calendar-timezone-input",
                    class: "input",
                    "data-testid": "card-detail-calendar-timezone-input",
                    value: "{calendar().timezone}",
                    placeholder: "Asia/Shanghai",
                    oninput: move |event: FormEvent| update_calendar_draft(calendar, |draft| draft.timezone = event.value()),
                }
            }
            label { class: "discussion-checkbox-row",
                Checkbox {
                    "data-testid": "card-detail-calendar-all-day",
                    checked: if calendar().all_day { CheckboxState::Checked } else { CheckboxState::Unchecked },
                    on_checked_change: move |state: CheckboxState| {
                        update_calendar_draft(calendar, |draft| draft.all_day = bool::from(state));
                    },
                }
                span { "All day" }
            }
            div { class: "field",
                Label { html_for: "card-detail-calendar-recurrence-select", "Recurrence" }
                Select::<String> {
                    "data-testid": "card-detail-calendar-recurrence-select",
                    value: Some(selected_frequency.into()),
                    on_value_change: move |value: Option<String>| {
                        if let Some(value) = value {
                            update_calendar_draft(calendar, |draft| {
                                draft.recurrence_frequency = if value == "none" {
                                    String::new()
                                } else {
                                    value
                                };
                            });
                        }
                    },
                    SelectOption::<String> { index: 0usize, value: "none".to_owned(), text_value: "None", "None" }
                    SelectOption::<String> { index: 1usize, value: "DAILY".to_owned(), text_value: "Daily", "Daily" }
                    SelectOption::<String> { index: 2usize, value: "WEEKLY".to_owned(), text_value: "Weekly", "Weekly" }
                    SelectOption::<String> { index: 3usize, value: "MONTHLY".to_owned(), text_value: "Monthly", "Monthly" }
                    SelectOption::<String> { index: 4usize, value: "YEARLY".to_owned(), text_value: "Yearly", "Yearly" }
                }
            }
            div { class: "field",
                Label { html_for: "card-detail-calendar-interval-input", "Interval" }
                Input {
                    id: "card-detail-calendar-interval-input",
                    class: "input",
                    "data-testid": "card-detail-calendar-interval-input",
                    value: "{calendar().recurrence_interval}",
                    placeholder: "1",
                    oninput: move |event: FormEvent| update_calendar_draft(calendar, |draft| draft.recurrence_interval = event.value()),
                }
            }
            div { class: "field",
                Label { html_for: "card-detail-calendar-by-day-input", "By day" }
                Input {
                    id: "card-detail-calendar-by-day-input",
                    class: "input",
                    "data-testid": "card-detail-calendar-by-day-input",
                    value: "{calendar().recurrence_by_day}",
                    placeholder: "MO, WE, FR",
                    oninput: move |event: FormEvent| update_calendar_draft(calendar, |draft| draft.recurrence_by_day = event.value()),
                }
            }
            div { class: "field",
                Label { html_for: "card-detail-calendar-count-input", "Count" }
                Input {
                    id: "card-detail-calendar-count-input",
                    class: "input",
                    "data-testid": "card-detail-calendar-count-input",
                    value: "{calendar().recurrence_count}",
                    placeholder: "10",
                    oninput: move |event: FormEvent| update_calendar_draft(calendar, |draft| draft.recurrence_count = event.value()),
                }
            }
            div { class: "field",
                Label { html_for: "card-detail-calendar-until-input", "Until" }
                Input {
                    id: "card-detail-calendar-until-input",
                    class: "input",
                    "data-testid": "card-detail-calendar-until-input",
                    value: "{calendar().recurrence_expires_at}",
                    placeholder: "2026-12-31T23:59:59Z",
                    oninput: move |event: FormEvent| update_calendar_draft(calendar, |draft| draft.recurrence_expires_at = event.value()),
                }
            }
            div { class: "field",
                Label { html_for: "card-detail-calendar-location-input", "Location" }
                Input {
                    id: "card-detail-calendar-location-input",
                    class: "input",
                    "data-testid": "card-detail-calendar-location-input",
                    value: "{calendar().location}",
                    placeholder: "Encrypted location",
                    oninput: move |event: FormEvent| update_calendar_draft(calendar, |draft| {
                        draft.location = event.value();
                        draft.location_locked = false;
                    }),
                }
            }
            CardDetailEditActions {
                status,
                on_save,
                on_cancel,
            }
        }
    }
}

/// Decode one `uploadImage` bridge request from the Toast editor JS and run
/// it through the canonical Rust blob pipeline
/// (`CokretApi::upload_blob_bytes_scoped`, multipart/form-data per
/// YOU-01-007), so authorization, retry/backoff and spec error-envelope
/// decoding stay owned by the network layer. Returns
/// `(blob_ref, media_type)` for the editor to build its markdown target.
async fn toast_editor_upload_via_api(
    base_url: &str,
    token: String,
    realm_id: &str,
    request: &Value,
) -> Result<(String, Option<String>), String> {
    use base64::Engine as _;
    let content_base64 = request
        .get("content_base64")
        .and_then(Value::as_str)
        .ok_or_else(|| "upload request missing content_base64".to_owned())?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(content_base64)
        .map_err(|error| format!("invalid base64 content: {error}"))?;
    if bytes.is_empty() {
        return Err("upload request carries no bytes".to_owned());
    }
    let media_type = request
        .get("media_type")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|media_type| !media_type.is_empty())
        .unwrap_or("application/octet-stream")
        .to_owned();
    let filename = request
        .get("filename")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|filename| !filename.is_empty())
        .map(ToOwned::to_owned);
    let realm_id = realm_id.trim();
    let realm_id = (!realm_id.is_empty()).then(|| realm_id.to_owned());
    let outcome = with_authed_api(base_url, token, move |api| async move {
        api.upload_blob_bytes_scoped(bytes, &media_type, realm_id.as_deref(), filename.as_deref())
            .await
    })
    .await
    .map_err(|error| error.display())?;
    Ok((outcome.blob_ref.to_string(), outcome.media_type))
}

fn toast_editor_bootstrap_script(host_id: &str, fallback_id: &str, value: &str) -> Option<String> {
    let config = serde_json::to_string(&json!({
        "hostId": host_id,
        "fallbackId": fallback_id,
        "value": value,
        "scriptUrl": TOAST_EDITOR_SCRIPT_URL,
        "cssUrl": TOAST_EDITOR_CSS_URL,
    }))
    .ok()?;
    Some(format!(
        r##"(async () => {{
    const config = {config};
    // Tell the Rust side of this eval channel it is not needed (editor
    // unavailable, bootstrap superseded, or fallback mode) so its upload
    // bridge task ends instead of waiting forever.
    const releaseBridge = () => {{
        try {{ dioxus.send({{ kind: "dispose" }}); }} catch (_) {{}}
    }};
    const host = document.getElementById(config.hostId);
    const fallback = document.getElementById(config.fallbackId);
    if (!host || !fallback) {{
        releaseBridge();
        return;
    }}

    const registry = window.__yougenToastEditors || (window.__yougenToastEditors = new Map());
    const existing = registry.get(config.hostId);
    if (existing && host.childElementCount > 0) {{
        releaseBridge();
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
        releaseBridge();
        return;
    }}

    if (!window.toastui || !window.toastui.Editor) {{
        fallback.classList.remove("toast-fallback-hidden");
        releaseBridge();
        return;
    }}

    if (existing) {{
        try {{ existing.dispose(); }} catch (_) {{}}
        try {{ existing.editor.destroy(); }} catch (_) {{}}
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

    // YOU-06-002: JS never talks to the protocol endpoint itself. It only
    // extracts the picked file's bytes and hands them to Rust over the
    // bidirectional eval channel; the upload runs through the canonical
    // `CokretApi::upload_blob_bytes_scoped` pipeline and Rust sends the
    // typed `BlobUploadOutcome` fields back for the markdown insert.
    let nextUploadId = 1;
    const pendingUploads = new Map();

    (async () => {{
        for (;;) {{
            let reply;
            try {{ reply = await dioxus.recv(); }} catch (_) {{ break; }}
            if (!reply || typeof reply !== "object") {{
                continue;
            }}
            const resolve = pendingUploads.get(reply.id);
            if (resolve) {{
                pendingUploads.delete(reply.id);
                resolve(reply);
            }}
        }}
    }})();

    const uploadImage = async (blob, callback) => {{
        try {{
            const safeName = (blob.name || "")
                .split(/[\\/]/)
                .pop()
                .replace(/[^A-Za-z0-9._-]+/g, "_")
                .replace(/^[._-]+|[._-]+$/g, "")
                .slice(0, 128);
            const bytes = new Uint8Array(await blob.arrayBuffer());
            let binary = "";
            for (let i = 0; i < bytes.length; i += 0x8000) {{
                binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
            }}
            const id = nextUploadId++;
            const reply = new Promise((resolve) => pendingUploads.set(id, resolve));
            dioxus.send({{
                kind: "upload",
                id,
                filename: safeName,
                media_type: blob.type || "application/octet-stream",
                content_base64: btoa(binary)
            }});
            const outcome = await reply;
            if (!outcome.ok) {{
                throw new Error(outcome.error || "upload failed");
            }}
            const markdownMediaType = blob.type || outcome.media_type || "image/png";
            const markdownTarget = outcome.blob_ref.includes("#")
                ? outcome.blob_ref
                : `${{outcome.blob_ref}}#${{markdownMediaType}}`;
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
    registry.set(config.hostId, {{ editor, dispose: releaseBridge }});
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
    // its `/task/<strand>` extension). Seeding `selected_board_space_id`
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
                // only): no encrypted strand cards are produced, so no
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
    let mut lifecycle_strand_projection = use_signal(Vec::<crate::api::StrandProjectionView>::new);
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
    let mut card_edit_calendar = use_signal(CalendarCardFields::default);
    let mut calendar_rsvp_occurrence = use_signal(String::new);
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
        let routed_strand_id = route_card_strand_id(&route);
        use_effect(move || {
            let Some(strand_id) = routed_strand_id.clone() else {
                return;
            };
            if selected_card()
                .as_ref()
                .is_some_and(|card| card_matches_strand_id(card, &strand_id))
            {
                return;
            }
            if let Some(card) = find_card_by_strand_id(&columns.read(), &strand_id) {
                let draft = card_detail_draft_from_card(&card);
                card_edit_title.set(draft.title);
                card_edit_description.set(draft.description);
                card_edit_body.set(draft.body);
                card_edit_synthesis.set(draft.synthesis);
                card_edit_synthesis_target_id.set(None);
                card_edit_labels.set(draft.labels.join(", "));
                card_edit_assignee.set(draft.assignee);
                card_edit_due.set(draft.due);
                let calendar = draft.calendar.clone();
                card_edit_calendar.set(calendar.clone());
                calendar_rsvp_occurrence.set(calendar_occurrence_hint(&calendar));
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
                    card_detail_discussion_mounted_for.set(Some(card.primary_strand_id.clone()));
                }
                card_detail_tab.set(routed_tab);
                card_synthesis_history_open_id.set(None);
                card_synthesis_selected_revision_id.set(None);
                selected_card.set(Some(card));
            }
        });
    }

    // Route board → selection sync. The board id is authoritative when
    // it is present in the URL (`/kanban/<realm>/board/<board>` and the
    // `/task/<strand>` extension). This effect keeps
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
            let strands = lifecycle_strand_projection();
            let raw_operations = state_store.read().load().raw_operations;
            if containers.is_empty() && strands.is_empty() && raw_operations.is_empty() {
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
                    &strands,
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
    // page (`/kanban/<realm>/task/<strand>`) and the card's home board
    // is NOT the currently-selected board, switch the board and
    // re-project the columns from the cached lifecycle snapshot. This
    // handles the case where the user arrives at the card-detail URL
    // via a fresh KanbanPanel mount (e.g. coming from `/spaces/<realm>`
    // Board tab where a different KanbanPanel instance held the
    // previous selection) — the bootstrap fetch may have already
    // picked `board_options.first()` before this reconciler runs, so
    // we override here whenever the URL's task_id resolves to a known
    // strand with a different `board_space_id`.
    {
        let routed_strand_id = route_card_strand_id(&route);
        let route_local_realm_id = local_realm_id.clone();
        let decrypt_realm_id = selected_realm_id.clone();
        let decrypt_actor = account_did.clone();
        let decrypt_device = device_id.clone();
        use_effect(move || {
            let Some(strand_id) = routed_strand_id.clone() else {
                return;
            };
            let strand_items = lifecycle_strand_projection.read();
            let Some(strand_board) = strand_items
                .iter()
                .find(|f| f.strand_id == strand_id)
                .and_then(|f| f.board_space_id.clone())
            else {
                return;
            };
            if selected_board_space_id() == strand_board {
                return;
            }
            // Re-project columns for the resolved board so the existing
            // card-detail effect (above) can find the card on the next
            // render cycle.
            let containers = lifecycle_container_projection.read().clone();
            let strands = strand_items.clone();
            drop(strand_items);
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
                    &strands,
                    &strand_board,
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
            if api_token.trim().is_empty() {
                return;
            }
            if view.trim().is_empty() {
                board_status.set(
                    "No board View selected; using Space-container/Strand projections and local queue only"
                        .to_owned(),
                );
                return;
            }
            let events_res = if lifecycle_realm_id.trim().is_empty() {
                None
            } else {
                let realm_id = lifecycle_realm_id.clone();
                match with_authed_api(&base, api_token.clone(), |api| async move {
                    api.backfill(&realm_id).await
                })
                .await
                {
                    Ok(response) => Some(response),
                    Err(err) if err.is_auth_expired() => return,
                    Err(_) => None,
                }
            };
            let remote_update_operations = events_res
                .as_ref()
                .map(|resp| strand_update_operations_from_events(&resp.events))
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
                        projection_source.set(BoardProjectionSource::Unavailable);
                        board_status.set(format!(
                            "Board view unavailable on mount: {}; keeping lifecycle projection",
                            err.display()
                        ));
                    }
                }
            }
        }
    });

    // F-KANBAN-LIVE-1: refresh the board projection only when account
    // subscribe advances. The global SyncEngine owns the liveness channel;
    // this panel must not poll `spaces` / `strands` / `events` on a timer while
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
        if api_token.trim().is_empty() {
            return;
        }
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
                    match with_authed_api(&base, api_token.clone(), |api| async move {
                        api.backfill(&realm_id).await
                    })
                    .await
                    {
                        Ok(response) => Some(response),
                        Err(err) if err.is_auth_expired() => return,
                        Err(_) => None,
                    }
                };
                let remote_update_operations = events_res
                    .as_ref()
                    .map(|resp| strand_update_operations_from_events(&resp.events))
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
                if containers_res
                    .as_ref()
                    .err()
                    .is_some_and(|err| err.is_auth_expired())
                {
                    return;
                }
                let strands_res = {
                    let realm_id = lifecycle_realm_id.clone();
                    with_authed_api(&base, api_token.clone(), |api| async move {
                        api.list_strand_projections(&realm_id).await
                    })
                    .await
                };
                if strands_res
                    .as_ref()
                    .err()
                    .is_some_and(|err| err.is_auth_expired())
                {
                    return;
                }
                let events_res = {
                    let realm_id = lifecycle_realm_id.clone();
                    with_authed_api(&base, api_token, |api| async move {
                        api.backfill(&realm_id).await
                    })
                    .await
                };
                if events_res
                    .as_ref()
                    .err()
                    .is_some_and(|err| err.is_auth_expired())
                {
                    return;
                }
                if containers_res.is_ok() || strands_res.is_ok() {
                    let container_items = containers_res
                        .ok()
                        .map(|resp| resp.items)
                        .unwrap_or_default();
                    let strand_items = strands_res.ok().map(|resp| resp.items).unwrap_or_default();
                    let event_items = events_res.ok().map(|resp| resp.events).unwrap_or_default();
                    let remote_update_operations =
                        strand_update_operations_from_events(&event_items);
                    let remote_space_create_operations =
                        space_create_operations_from_events(&event_items);
                    let container_items = containers_with_local_space_creates(
                        &container_items,
                        &remote_space_create_operations,
                        &lifecycle_local_realm_id,
                    );
                    lifecycle_container_projection.set(container_items.clone());
                    lifecycle_strand_projection.set(strand_items.clone());
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
                            &strand_items,
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

    // Hydrate Space-container / Strand lifecycle state from the soland
    // `/_cokret/self/projection/{spaces|strands}` endpoints so
    // an Archive accepted on the server stays archived after a page
    // refresh. The probe is fire-and-forget; a 404 / 401 just leaves
    // columns/cards in their `Active` default and the user is no worse
    // off than before this wiring.
    let mut lifecycle_bootstrapped_for = use_signal(String::new);
    let lifecycle_realm_id = local_realm_id.clone();
    // When the kanban panel mounts on a card-detail URL
    // (`/kanban/<realm>/task/<strand>`), the user typically came from a
    // different shell (e.g. `/spaces/<realm>` with the Board tab open)
    // and the freshly-mounted panel has no `selected_board_space_id`
    // yet. Without a hint, `columns_from_lifecycle_projection` falls
    // back to `board_options.first()`, which may not be the board that
    // actually contains the card. Capture the routed strand id so the
    // lifecycle fetch below can resolve the card's home board.
    let lifecycle_routed_strand_id = route_card_strand_id(&route);
    if !lifecycle_realm_id.is_empty() && lifecycle_bootstrapped_for() != lifecycle_realm_id {
        lifecycle_bootstrapped_for.set(lifecycle_realm_id.clone());
        let base = base_url.clone();
        let lifecycle_token = token;
        let lifecycle_routed_strand_id = lifecycle_routed_strand_id.clone();
        let lifecycle_local_realm_id = local_realm_id.clone();
        let decrypt_realm_id = selected_realm_id.clone();
        let decrypt_actor = account_did.clone();
        let decrypt_device = device_id.clone();
        spawn(async move {
            let realm_id = lifecycle_realm_id.clone();
            let api_token = lifecycle_token();
            if api_token.trim().is_empty() {
                return;
            }
            let containers_res = {
                let realm_id = realm_id.clone();
                with_authed_api(&base, api_token.clone(), |api| async move {
                    api.list_space_container_projections(&realm_id).await
                })
                .await
            };
            if containers_res
                .as_ref()
                .err()
                .is_some_and(|err| err.is_auth_expired())
            {
                return;
            }
            let strands_res = {
                let realm_id = realm_id.clone();
                with_authed_api(&base, api_token.clone(), |api| async move {
                    api.list_strand_projections(&realm_id).await
                })
                .await
            };
            if strands_res
                .as_ref()
                .err()
                .is_some_and(|err| err.is_auth_expired())
            {
                return;
            }
            let events_res = {
                let realm_id = realm_id.clone();
                with_authed_api(&base, api_token, |api| async move {
                    api.backfill(&realm_id).await
                })
                .await
            };
            if events_res
                .as_ref()
                .err()
                .is_some_and(|err| err.is_auth_expired())
            {
                return;
            }
            let mut applied = 0_usize;
            let mut server_projection_applied = false;
            let containers_ok = containers_res.is_ok();
            let strands_ok = strands_res.is_ok();
            if containers_ok || strands_ok {
                let container_items = containers_res
                    .ok()
                    .map(|resp| resp.items)
                    .unwrap_or_default();
                let strand_items = strands_res.ok().map(|resp| resp.items).unwrap_or_default();
                let event_items = events_res.ok().map(|resp| resp.events).unwrap_or_default();
                let remote_update_operations = strand_update_operations_from_events(&event_items);
                let remote_space_create_operations =
                    space_create_operations_from_events(&event_items);
                let container_items = containers_with_local_space_creates(
                    &container_items,
                    &remote_space_create_operations,
                    &lifecycle_local_realm_id,
                );
                lifecycle_container_projection.set(container_items.clone());
                lifecycle_strand_projection.set(strand_items.clone());
                let current_board = selected_board_space_id();
                // If the user landed on a card-detail URL and no board
                // is selected yet, resolve the card's home board from
                // the just-fetched strand projection so the matching
                // board is loaded (instead of `board_options.first()`).
                let current_board = if current_board.trim().is_empty() {
                    lifecycle_routed_strand_id
                        .as_deref()
                        .and_then(|strand_id| {
                            strand_items
                                .iter()
                                .find(|f| f.strand_id == strand_id)
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
                        &strand_items,
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
                    for view in &strand_items {
                        for col in cols.iter_mut() {
                            if let Some(card) =
                                col.cards.iter_mut().find(|c| c.id == view.strand_id)
                            {
                                let new_lifecycle = strand_lifecycle_from_wire(&view.state);
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
    let projected_strand_ids = lifecycle_strand_projection()
        .into_iter()
        .map(|view| view.strand_id)
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
                                                    lifecycle_strand_projection,
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
                                                        lifecycle_strand_projection,
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
                                                                lifecycle_strand_projection,
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
                                        // until `ck.self.events.command.submit` returns.
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
                                                Ok(builder) => builder
                                                    .build_sdk_event("yougen"),
                                                Err(err) => {
                                                    board_status.set(format!("cannot create list: {err:#}"));
                                                    return;
                                                }
                                            };
                                            let op = match op {
                                                Ok(event) => event,
                                                Err(err) => {
                                                    board_status.set(format!("cannot create list: {err}"));
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
                                                    Ok(builder) => builder
                                                        .build_sdk_event("yougen"),
                                                    Err(err) => {
                                                        board_status.set(format!("cannot create board: {err:#}"));
                                                        return;
                                                }
                                            };
                                                let op = match op {
                                                    Ok(event) => event,
                                                    Err(err) => {
                                                        board_status.set(format!("cannot create board: {err}"));
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
                                                        .map(|resp| strand_update_operations_from_events(&resp.events))
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
                                                                projection_source.set(BoardProjectionSource::Unavailable);
                                                                board_status.set(format!(
                                                                    "Board view unavailable: {}; keeping lifecycle projection",
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
                                            let seal_ref_label = short_protocol_id(&record.seal_ref);
                                            rsx! {
                                                div { class: "event", "data-testid": "board-event-record",
                                                    div { class: "event-head",
                                                        span { "{record.kind}" }
                                                        WriteStateBadge { state: record.state }
                                                    }
                                                    div { class: "muted", title: "{record.move_id}", "move_id {move_id_label}" }
                                                    div { class: "muted", title: "{record.cell_id}", "cell {cell_id_label} / hlc {record.hlc}" }
                                                    div { class: "muted", title: "{record.seal_ref}", "seal_ref {seal_ref_label}" }
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
                                dispatch_strand_position_move(
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
                    .filter(|(_, c)| c.lifecycle == StrandLifecycleState::Active)
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
                                        dispatch_strand_position_move(
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
                                        let calendar = draft.calendar.clone();
                                        card_edit_calendar.set(calendar.clone());
                                        calendar_rsvp_occurrence.set(calendar_occurrence_hint(&calendar));
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
                                    span { class: "entity-title strand-title-with-security",
                                        SecurityStateBadge {
                                            encrypted: card.security_encrypted.unwrap_or(selected_scope_security_encrypted_or_secure),
                                            compact: true,
                                            test_id: Some("strand-card-security-state".to_owned()),
                                        }
                                        span { class: "strand-title-text", "{card.title}" }
                                    }
                                    WriteStateBadge { state: displayed_card_state(card, &projected_strand_ids) }
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
                                        let gate = capability_gate_for_strand(
                                            &capability_engine,
                                            &account_did,
                                            &selected_board_space_id(),
                                            &card.id,
                                            "ck.strand.archive",
                                        );
                                        let title_text = if gate.enabled {
                                            "Archive this card (ck.strand.archive)".to_owned()
                                        } else {
                                            format!("Archive gated: {}", gate.reason)
                                        };
                                        let testid_state = if gate.enabled { "open" } else { "denied" };
                                        rsx! {
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                class: "kanban-inline-action",
                                                "data-testid": "card-archive-button",
                                                "data-strand-id": "{card.id}",
                                                "data-cap-gate": testid_state,
                                                disabled: !gate.enabled,
                                                title: title_text,
                                                onclick: {
                                                    let base = base_url.clone();
                                                    let realm = selected_realm_id.clone();
                                                    let actor = account_did.clone();
                                                    let strand_id = card.id.clone();
                                                    move |evt: dioxus::events::MouseEvent| {
                                                        evt.stop_propagation();
                                                        dispatch_strand_lifecycle(
                                                            base.clone(),
                                                            token,
                                                            realm.clone(),
                                                            actor.clone(),
                                                            strand_id.clone(),
                                                            StrandLifecycleState::Archived,
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

                        // R11: `redacted` clears Strand content but retains the
                        // envelope/audit trail (strand.schema.json terminal). The
                        // UI MUST surface a withdrawn-message placeholder rather than
                        // hiding the Strand, so the card stays visible without
                        // leaking its (now-cleared) title/body.
                        for redacted_card in column
                            .cards
                            .iter()
                            .filter(|c| c.lifecycle == StrandLifecycleState::Redacted)
                        {
                            div {
                                key: "{redacted_card.id}",
                                class: "event board-card board-card-redacted",
                                "data-testid": "kanban-card-redacted",
                                "data-strand-id": "{redacted_card.id}",
                                div { class: "event-head",
                                    span { class: "entity-title muted", "{crate::i18n::tr(\"message.redacted\")}" }
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
                                            // ck.strand.create envelope. The
                                            // initial Board/List placement
                                            // rides in the strand.position
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
                                                let strand_id = format!("ck:strand:{}", uuid_v7());
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
                                                    strand_id.clone(),
                                                    title.clone(),
                                                    rank.clone(),
                                                    String::new(),
                                                    CardState::Queued,
                                                );
                                                if let Some(col) = columns.write().iter_mut().find(|c| c.id == col_id) {
                                                    col.cards.push(card);
                                                }
                                                let value = json!({
                                                    "strand_id": strand_id,
                                                    "board_space_id": board_space_id,
                                                    "list_space_id": col_id,
                                                    "title": title,
                                                    "rank": rank,
                                                    "strand_kind": "card",
                                                });
                                                submit_kanban_move(
                                                    base.clone(),
                                                    token,
                                                    realm.clone(),
                                                    actor.clone(),
                                                    strand_id.clone(),
                                                    "ck.strand.create",
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

            // Archived cards drawer — Strand lifecycle `archived` state.
            // Cards appear here after `ck.strand.archive` is accepted and
            // are removed from the column above. Each row carries the
            // column title (where it came from) + a Restore button that
            // submits `ck.strand.restore` (SDK reducer enforces
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
                            .filter(|c| c.lifecycle == StrandLifecycleState::Archived)
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
                                        span { class: "entity-title strand-title-with-security",
                                            SecurityStateBadge {
                                                encrypted: row.card.security_encrypted.unwrap_or(selected_scope_security_encrypted_or_secure),
                                                compact: true,
                                                test_id: Some("strand-card-security-state".to_owned()),
                                            }
                                            span { class: "strand-title-text", "{row.card.title}" }
                                        }
                                        span { "from list: {row.column_title}" }
                                        {
                                            let gate = capability_gate_for_strand(
                                                &capability_engine,
                                                &account_did,
                                                &selected_board_space_id(),
                                                &row.card.id,
                                                "ck.strand.restore",
                                            );
                                            let title_text = if gate.enabled {
                                                "Restore this card (ck.strand.restore)".to_owned()
                                            } else {
                                                format!("Restore gated: {}", gate.reason)
                                            };
                                            let testid_state = if gate.enabled { "open" } else { "denied" };
                                            rsx! {
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    "data-testid": "card-restore-button",
                                                    "data-strand-id": "{row.card.id}",
                                                    "data-cap-gate": testid_state,
                                                    disabled: !gate.enabled,
                                                    title: title_text,
                                                    onclick: {
                                                        let base = base_url.clone();
                                                        let realm = selected_realm_id.clone();
                                                        let actor = account_did.clone();
                                                        let strand_id = row.card.id.clone();
                                                        move |_| {
                                                            dispatch_strand_lifecycle(
                                                                base.clone(),
                                                                token,
                                                                realm.clone(),
                                                                actor.clone(),
                                                                strand_id.clone(),
                                                                StrandLifecycleState::Active,
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
                    let card_link_path = strand_detail_deep_link_path_with_tab(
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
                            .is_some_and(|strand_id| strand_id == card.primary_strand_id.as_str());
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
                                card_edit_calendar.set(CalendarCardFields::default());
                                calendar_rsvp_occurrence.set(String::new());
                                card_detail_actions_open.set(false);
                                if route_is_card_detail {
                                    let _ = overlay_navigator.push(overlay_board_route.clone());
                                }
                            },
                            div {
                                class: "{popup_class}",
                                style: "{popup_style}",
                                "data-testid": "card-detail-modal",
                                role: "dialog",
                                "aria-modal": "true",
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
                                                test_id: Some("strand-detail-security-state".to_owned()),
                                            }
                                            h2 { "{card.title}" }
                                            div { class: "card-detail-title-meta",
                                                WriteStateBadge { state: displayed_card_state(card, &projected_strand_ids) }
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
                                            "aria-label": "Copy strand link",
                                            title: "Copy strand link",
                                            onclick: {
                                                let link_path = card_link_path.clone();
                                                move |_| {
                                                    share_kanban_strand_link(&link_path);
                                                    board_status.set("Strand link copied".to_owned());
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
                                                            let target = if card.lifecycle == StrandLifecycleState::Archived {
                                                                StrandLifecycleState::Active
                                                            } else {
                                                                StrandLifecycleState::Archived
                                                            };
                                                            let action = if target == StrandLifecycleState::Archived {
                                                                "ck.strand.archive"
                                                            } else {
                                                                "ck.strand.restore"
                                                            };
                                                            let gate = capability_gate_for_strand(
                                                                &capability_engine,
                                                                &account_did,
                                                                &selected_board_space_id(),
                                                                &card.id,
                                                                action,
                                                            );
                                                            let label = if target == StrandLifecycleState::Archived {
                                                                crate::i18n::tr("kanban.archive_action")
                                                            } else {
                                                                crate::i18n::tr("kanban.restore_action")
                                                            };
                                                            let testid = if target == StrandLifecycleState::Archived {
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
                                                                    "data-strand-id": "{card.id}",
                                                                    "data-cap-gate": testid_state,
                                                                    disabled: !gate.enabled,
                                                                    title: title_text,
                                                                    onclick: {
                                                                        let base = base_url.clone();
                                                                        let realm = selected_realm_id.clone();
                                                                        let actor = account_did.clone();
                                                                        let strand_id = card.id.clone();
                                                                        move |_| {
                                                                            dispatch_strand_lifecycle(
                                                                                base.clone(),
                                                                                token,
                                                                                realm.clone(),
                                                                                actor.clone(),
                                                                                strand_id.clone(),
                                                                                target,
                                                                                columns,
                                                                                board_status,
                                                                            );
                                                                            selected_card.set(None);
                                                                            editing_card_detail.set(false);
                                                                            card_detail_edit_status.set(String::new());
                                                                            card_edit_calendar.set(CalendarCardFields::default());
                                                                            calendar_rsvp_occurrence.set(String::new());
                                                                            card_detail_actions_open.set(false);
                                                                            if route_is_card_detail {
                                                                                let _ = action_navigator.push(action_board_route.clone());
                                                                            }
                                                                        }
                                                                    },
                                                                    UiIcon { name: if target == StrandLifecycleState::Archived { "archive" } else { "refresh" } }
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
                                                card_edit_calendar.set(CalendarCardFields::default());
                                                calendar_rsvp_occurrence.set(String::new());
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
                                                    "aria-label": "Strand tracks",
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
                                                            let strand_id = card.primary_strand_id.clone();
                                                            move |_| {
                                                                card_detail_discussion_mounted_for.set(Some(strand_id.clone()));
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
                                                                        let synthesis_is_own =
                                                                            actor_is_current_account(&display_revision.actor_id, &account_did);
                                                                        let entry_class = if selected_synthesis_is_latest {
                                                                            if synthesis_is_own {
                                                                                "card-synthesis-entry is-latest is-own"
                                                                            } else {
                                                                                "card-synthesis-entry is-latest"
                                                                            }
                                                                        } else {
                                                                            if synthesis_is_own {
                                                                                "card-synthesis-entry is-history is-own"
                                                                            } else {
                                                                                "card-synthesis-entry is-history"
                                                                            }
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
                                                                                    if synthesis_is_own {
                                                                                        SelfAttributionBadge {
                                                                                            class: Some("card-synthesis-self-badge".to_owned()),
                                                                                            test_id: Some("card-synthesis-self-badge".to_owned()),
                                                                                        }
                                                                                    }
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
                                                                                                            let history_is_own =
                                                                                                                actor_is_current_account(&history_entry.actor_id, &account_did);
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
                                                                                                                        if history_is_own {
                                                                                                                            SelfAttributionBadge {
                                                                                                                                class: Some("card-synthesis-history-self-badge".to_owned()),
                                                                                                                                test_id: Some("card-synthesis-history-self-badge".to_owned()),
                                                                                                                            }
                                                                                                                        }
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
                                                            initial_strand_id: card.primary_strand_id.clone(),
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
                                                let participant_set: BTreeSet<String> = strand_participant_dids(
                                                    &store.raw_operations,
                                                    &card.primary_strand_id,
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
                                                                    dt { "Strand ID" }
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
                                                                    dt { "Calendar" }
                                                                    dd {
                                                                        {
                                                                            let schedule = card.calendar.clone();
                                                                            let has_schedule = schedule.has_schedule();
                                                                            let recurrence_label = schedule.recurrence_label();
                                                                            let occurrence_hint = calendar_occurrence_hint(&schedule);
                                                                            let location_label = if schedule.location_locked {
                                                                                MLS_LOCKED_FIELD_PLACEHOLDER.to_owned()
                                                                            } else {
                                                                                schedule.location.clone()
                                                                            };
                                                                            rsx! {
                                                                                div {
                                                                                    class: "calendar-editor",
                                                                                    "data-testid": "card-detail-calendar",
                                                                                    if editing_card_detail() && card_edit_scope() == CardEditScope::Calendar {
                                                                                        CalendarScheduleEditForm {
                                                                                            calendar: card_edit_calendar,
                                                                                            status: card_detail_edit_status(),
                                                                                            on_save: {
                                                                                                let base = base_url.clone();
                                                                                                let realm = selected_realm_id.clone();
                                                                                                let actor = account_did.clone();
                                                                                                let device = device_id.clone();
                                                                                                let current_card = card.clone();
                                                                                                move |_| {
                                                                                                    save_card_calendar_edit(
                                                                                                        base.clone(),
                                                                                                        token,
                                                                                                        realm.clone(),
                                                                                                        actor.clone(),
                                                                                                        device.clone(),
                                                                                                        current_card.clone(),
                                                                                                        card_edit_calendar(),
                                                                                                        selected_scope_security_encrypted,
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
                                                                                                let current_calendar = card.calendar.clone();
                                                                                                move |_| {
                                                                                                    card_edit_calendar.set(current_calendar.clone());
                                                                                                    calendar_rsvp_occurrence.set(calendar_occurrence_hint(&current_calendar));
                                                                                                    editing_card_detail.set(false);
                                                                                                    card_detail_actions_open.set(false);
                                                                                                    card_detail_edit_status.set(String::new());
                                                                                                }
                                                                                            },
                                                                                        }
                                                                                    } else {
                                                                                        if has_schedule {
                                                                                            div { class: "calendar-summary",
                                                                                                if !schedule.start.trim().is_empty() {
                                                                                                    div {
                                                                                                        span { "Start" }
                                                                                                        strong { "{schedule.start}" }
                                                                                                    }
                                                                                                }
                                                                                                if !schedule.end.trim().is_empty() {
                                                                                                    div {
                                                                                                        span { "End" }
                                                                                                        strong { "{schedule.end}" }
                                                                                                    }
                                                                                                }
                                                                                                if !schedule.timezone.trim().is_empty() {
                                                                                                    div {
                                                                                                        span { "Timezone" }
                                                                                                        strong { "{schedule.timezone}" }
                                                                                                    }
                                                                                                }
                                                                                                if schedule.all_day {
                                                                                                    div {
                                                                                                        span { "Mode" }
                                                                                                        strong { "All day" }
                                                                                                    }
                                                                                                }
                                                                                                if !recurrence_label.trim().is_empty() {
                                                                                                    div {
                                                                                                        span { "Recurrence" }
                                                                                                        strong { "{recurrence_label}" }
                                                                                                    }
                                                                                                }
                                                                                                if !location_label.trim().is_empty() {
                                                                                                    div {
                                                                                                        span { "Location" }
                                                                                                        strong { "{location_label}" }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        } else {
                                                                                            div { class: "card-detail-empty", "No schedule" }
                                                                                        }
                                                                                        Button {
                                                                                            variant: ButtonVariant::Secondary,
                                                                                            r#type: "button",
                                                                                            class: "card-detail-mini-action",
                                                                                            "data-testid": "card-detail-edit-calendar-button",
                                                                                            onclick: {
                                                                                                let current = card.clone();
                                                                                                move |_| {
                                                                                                    let draft = card_detail_draft_from_card(&current);
                                                                                                    let calendar = draft.calendar.clone();
                                                                                                    card_edit_calendar.set(calendar.clone());
                                                                                                    calendar_rsvp_occurrence.set(calendar_occurrence_hint(&calendar));
                                                                                                    card_edit_scope.set(CardEditScope::Calendar);
                                                                                                    card_detail_edit_status.set(String::new());
                                                                                                    editing_card_detail.set(true);
                                                                                                    card_detail_actions_open.set(false);
                                                                                                    assignee_picker_open.set(false);
                                                                                                    due_picker_open.set(false);
                                                                                                }
                                                                                            },
                                                                                            UiIcon { name: if has_schedule { "settings" } else { "plus" } }
                                                                                            span { if has_schedule { "Edit schedule" } else { "Add schedule" } }
                                                                                        }
                                                                                        if has_schedule {
                                                                                            div {
                                                                                                class: "calendar-rsvp",
                                                                                                "data-testid": "card-detail-calendar-rsvp",
                                                                                                Label { html_for: "card-detail-calendar-rsvp-occurrence", "Occurrence" }
                                                                                                Input {
                                                                                                    id: "card-detail-calendar-rsvp-occurrence",
                                                                                                    class: "input",
                                                                                                    "data-testid": "card-detail-calendar-rsvp-occurrence",
                                                                                                    value: "{calendar_rsvp_occurrence}",
                                                                                                    placeholder: "{occurrence_hint}",
                                                                                                    oninput: move |event: FormEvent| calendar_rsvp_occurrence.set(event.value()),
                                                                                                }
                                                                                                div { class: "calendar-rsvp-actions",
                                                                                                    Button {
                                                                                                        variant: ButtonVariant::Secondary,
                                                                                                        r#type: "button",
                                                                                                        onclick: move |_| calendar_rsvp_occurrence.set(String::new()),
                                                                                                        "Series"
                                                                                                    }
                                                                                                    Button {
                                                                                                        variant: ButtonVariant::Secondary,
                                                                                                        r#type: "button",
                                                                                                        "data-testid": "card-detail-rsvp-accepted",
                                                                                                        onclick: {
                                                                                                            let base = base_url.clone();
                                                                                                            let realm = selected_realm_id.clone();
                                                                                                            let actor = account_did.clone();
                                                                                                            let current_card = card.clone();
                                                                                                            move |_| {
                                                                                                                dispatch_calendar_rsvp(
                                                                                                                    base.clone(),
                                                                                                                    token,
                                                                                                                    realm.clone(),
                                                                                                                    actor.clone(),
                                                                                                                    current_card.clone(),
                                                                                                                    "accepted",
                                                                                                                    calendar_rsvp_occurrence(),
                                                                                                                    state_store,
                                                                                                                    board_status,
                                                                                                                );
                                                                                                            }
                                                                                                        },
                                                                                                        "Accept"
                                                                                                    }
                                                                                                    Button {
                                                                                                        variant: ButtonVariant::Secondary,
                                                                                                        r#type: "button",
                                                                                                        "data-testid": "card-detail-rsvp-tentative",
                                                                                                        onclick: {
                                                                                                            let base = base_url.clone();
                                                                                                            let realm = selected_realm_id.clone();
                                                                                                            let actor = account_did.clone();
                                                                                                            let current_card = card.clone();
                                                                                                            move |_| {
                                                                                                                dispatch_calendar_rsvp(
                                                                                                                    base.clone(),
                                                                                                                    token,
                                                                                                                    realm.clone(),
                                                                                                                    actor.clone(),
                                                                                                                    current_card.clone(),
                                                                                                                    "tentative",
                                                                                                                    calendar_rsvp_occurrence(),
                                                                                                                    state_store,
                                                                                                                    board_status,
                                                                                                                );
                                                                                                            }
                                                                                                        },
                                                                                                        "Maybe"
                                                                                                    }
                                                                                                    Button {
                                                                                                        variant: ButtonVariant::Secondary,
                                                                                                        r#type: "button",
                                                                                                        "data-testid": "card-detail-rsvp-declined",
                                                                                                        onclick: {
                                                                                                            let base = base_url.clone();
                                                                                                            let realm = selected_realm_id.clone();
                                                                                                            let actor = account_did.clone();
                                                                                                            let current_card = card.clone();
                                                                                                            move |_| {
                                                                                                                dispatch_calendar_rsvp(
                                                                                                                    base.clone(),
                                                                                                                    token,
                                                                                                                    realm.clone(),
                                                                                                                    actor.clone(),
                                                                                                                    current_card.clone(),
                                                                                                                    "declined",
                                                                                                                    calendar_rsvp_occurrence(),
                                                                                                                    state_store,
                                                                                                                    board_status,
                                                                                                                );
                                                                                                            }
                                                                                                        },
                                                                                                        "Decline"
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
                                                                        let in_strand = participant_set.contains(&did);
                                                                        let row_class = if in_strand {
                                                                            "card-detail-actor-row participant"
                                                                        } else {
                                                                            "card-detail-actor-row"
                                                                        };
                                                                        let dot_class = if in_strand {
                                                                            "card-detail-actor-dot participant"
                                                                        } else {
                                                                            "card-detail-actor-dot"
                                                                        };
                                                                        let dot_title = if in_strand {
                                                                            "Participated in this Strand"
                                                                        } else {
                                                                            "Realm member"
                                                                        };
                                                                        rsx! {
                                                                            li {
                                                                                key: "{did}",
                                                                                class: "{row_class}",
                                                                                "data-strand-participant": "{in_strand}",
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

mod assignment;
mod board_select;
mod card_activity;
mod card_detail;
mod card_patch;
mod members;
mod mls_encrypt;
mod plaintext_guard;

use assignment::*;
use board_select::*;
use card_activity::*;
use card_detail::*;
use card_patch::*;
use members::*;
use mls_encrypt::*;
// `build_creator_mls_genesis_event` / `kanban_mls_commit_event_from_store`
// are reused by sibling views (realm_admin epoch rotation, sync_engine,
// setup) through `crate::views::kanban::<name>`, so re-export them at the
// module root to keep those `pub(crate)` call sites resolving after the
// move into `mls_encrypt`.
pub(crate) use mls_encrypt::{
    build_creator_mls_genesis_event, kanban_mls_commit_event_from_store,
    kanban_mls_commit_event_from_store_for_effective_scope,
    kanban_mls_commit_event_from_store_for_effective_scope_with_proposal_refs,
    kanban_mls_remove_commit_event_from_store_for_effective_scope_with_proposal_refs,
};
use plaintext_guard::*;

#[cfg(test)]
mod tests;
