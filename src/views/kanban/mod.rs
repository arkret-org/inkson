use std::collections::{BTreeMap, BTreeSet};

use dioxus::prelude::{Asset, AssetOptions, asset, manganis, *};
use dioxus_primitives::checkbox::CheckboxState;
use dioxus_router::hooks::{use_navigator, use_route};
use serde_json::{Map, Value, json};

use crate::components::{
    ActorIdentityLabel, EmptyState, EmptyStateKind, SecurityStateBadge, UiIcon, WriteStateIcon,
};
use crate::rank::rank_for_drop;
use crate::routes::Route;
use crate::state::LocalStateStore;
use crate::transport::auth::{with_authed_api, with_authed_sdk_client};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::select::{Select, SelectOption};
use crate::ui::textarea::Textarea;
use crate::views::helpers::short_protocol_id;

mod card_detail_surface;
mod controller;
mod drag_drop_controller;
mod effects;
// card due-calendar pure calculation helpers moved to `due_calendar`
// (move-only).
mod due_calendar;
/// Board Space id used only when the explicit demo seed fallback is
/// enabled. Normal kanban routes render server projections instead of
/// hard-coded cards.
mod model;

use card_detail_surface::{CardDetail, CardDetailContext};
#[cfg(test)]
use card_detail_surface::{content_edit_scope_for_tab, suspend_track_edit};
use controller::{KanbanCommand, KanbanController, use_kanban_controller};
use drag_drop_controller::*;
use due_calendar::*;
use effects::KanbanEffects;
use model::*;
pub(crate) use model::{calendar_schedule_revision_winner, strand_views_from_ops};

fn current_board_cell_demand(
    columns: &[KanbanColumn],
    selected_board: Option<&str>,
) -> Vec<arkret_sdk::CellRef> {
    let mut cells = BTreeSet::new();
    let spaces = selected_board
        .into_iter()
        .chain(columns.iter().map(|column| column.id.as_str()))
        .filter(|id| arkret_sdk::SpaceId::new((*id).to_owned()).is_ok());
    for space_id in spaces {
        for family in [
            "ak.component.space.metadata.v1",
            "ak.component.space.lifecycle.v1",
            "ak.component.space.parent.v1",
        ] {
            if let Ok(cell) = arkret_sdk::CellRef::new(format!("ak:cell:{family}:{space_id}")) {
                cells.insert(cell);
            }
        }
    }
    for relation_id in columns
        .iter()
        .flat_map(|column| &column.cards)
        .flat_map(|card| &card.assigned_to_relations)
        .map(|relation| relation.relation_id.as_str())
    {
        for family in [
            "ak.component.relation.v1",
            "ak.component.relation.lifecycle.v1",
        ] {
            if let Ok(cell) = arkret_sdk::CellRef::new(format!("ak:cell:{family}:{relation_id}")) {
                cells.insert(cell);
            }
        }
    }
    cells.into_iter().take(256).collect()
}

#[cfg(test)]
pub(crate) use crate::state::projection::kanban_ops::kanban_operations_from_events;

#[used]
static TOAST_EDITOR_SCRIPT: Asset = asset!(
    "/assets/vendor/toastui-editor-all.min.js",
    AssetOptions::js()
        .with_hash_suffix(false)
        .with_minify(false)
);

#[used]
static TOAST_EDITOR_CSS: Asset = asset!(
    "/assets/vendor/toastui-editor.min.css",
    AssetOptions::css()
        .with_hash_suffix(false)
        .with_minify(false)
);

#[component]
fn CardMarkdownEditor(
    value: String,
    token: String,
    realm_id: String,
    allow_image_upload: Option<bool>,
    on_change: EventHandler<String>,
    /// Optional id suffix so multiple editor instances on the same card
    /// detail (e.g. Summary + Description) don't share a DOM id and
    /// confuse the toast bootstrap script. Defaults to the stable
    /// `"description"` slot used by existing data-testids.
    slot: Option<String>,
    /// Accessible name for the fallback textarea. The track editors sit
    /// inside a tab panel whose tab already names the track, so they carry
    /// the name here instead of repeating it as a visible `<label>` above
    /// the editor.
    aria_label: Option<String>,
) -> Element {
    // A4 — base_url from session context instead of a prop.
    let base_url = crate::app::SessionContext::base_url_string();
    let allow_image_upload = allow_image_upload.unwrap_or(true);
    let slot = slot.unwrap_or_else(|| "description".to_owned());
    let host_id = format!("card-detail-{slot}-toast-editor");
    let fallback_id = format!("card-detail-{slot}-input");

    use_drop({
        let host_id = host_id.clone();
        move || {
            if let Some(script) = toast_editor_cleanup_script(&host_id) {
                let _ = document::eval(&script);
            }
        }
    });

    use_effect({
        let host_id = host_id.clone();
        let fallback_id = fallback_id.clone();
        let value = value.clone();
        let base_url = base_url.clone();
        let token = token.clone();
        let realm_id = realm_id.clone();
        move || {
            let Some(script) =
                toast_editor_bootstrap_script(&host_id, &fallback_id, &value, allow_image_upload)
            else {
                return;
            };
            // the editor JS only extracts file bytes and hands
            // them to Rust over the eval channel; the upload itself runs
            // through the canonical `TransportClient` pipeline (auth headers,
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
                        allow_image_upload,
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
                "aria-label": aria_label.clone().unwrap_or_default(),
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
    #[props(default)] save_disabled: bool,
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
                disabled: save_disabled,
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
        let frequency = calendar().recurrence_frequency.trim().to_ascii_lowercase();
        Some(if frequency.is_empty() {
            "none".to_owned()
        } else {
            frequency
        })
    });
    let selected_status = use_memo(move || {
        Some(match calendar().status.trim() {
            "" => "confirmed".to_owned(),
            value => value.to_owned(),
        })
    });
    let recurrence_enabled = use_memo(move || !calendar().recurrence_frequency.trim().is_empty());
    let custom_recurrence_configured = use_memo(move || {
        let draft = calendar();
        !draft.recurrence_interval.trim().is_empty()
            || !draft.recurrence_by_day.trim().is_empty()
            || !draft.recurrence_by_month.trim().is_empty()
            || !draft.recurrence_by_month_day.trim().is_empty()
            || !draft.recurrence_by_set_position.trim().is_empty()
            || !draft.recurrence_first_day_of_week.trim().is_empty()
            || !draft.recurrence_count.trim().is_empty()
            || !draft.recurrence_until.trim().is_empty()
    });
    rsx! {
        div { class: "workflow-form card-detail-edit-form calendar-schedule-edit-form", "data-testid": "card-detail-calendar-edit-form",
            section { class: "calendar-schedule-section calendar-schedule-primary",
                div { class: "calendar-schedule-field-grid",
                    div { class: "field",
                        Label { html_for: "card-detail-calendar-start-input", "Start" }
                        Input {
                            id: "card-detail-calendar-start-input",
                            class: "input",
                            "data-testid": "card-detail-calendar-start-input",
                            value: "{calendar().start}",
                            placeholder: "2026-06-20T09:00:00",
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
                            placeholder: "2026-06-20T10:00:00",
                            oninput: move |event: FormEvent| update_calendar_draft(calendar, |draft| draft.end = event.value()),
                        }
                    }
                    label { class: "discussion-checkbox-row calendar-schedule-all-day",
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
                    div { class: "field calendar-schedule-span-2",
                        Label { html_for: "card-detail-calendar-location-input", "Location" }
                        Input {
                            id: "card-detail-calendar-location-input",
                            class: "input",
                            "data-testid": "card-detail-calendar-location-input",
                            value: "{calendar().location}",
                            placeholder: "Add a location",
                            oninput: move |event: FormEvent| update_calendar_draft(calendar, |draft| {
                                draft.location = event.value();
                                draft.location_locked = false;
                            }),
                        }
                    }
                    div { class: "field calendar-schedule-repeat-field",
                        Label { html_for: "card-detail-calendar-recurrence-select", "Repeat" }
                        Select::<String> {
                            "data-testid": "card-detail-calendar-recurrence-select",
                            value: Some(selected_frequency.into()),
                            on_value_change: move |value: Option<String>| {
                                if let Some(value) = value {
                                    update_calendar_draft(calendar, |draft| {
                                        if value == "none" {
                                            draft.recurrence_frequency.clear();
                                            draft.recurrence_interval.clear();
                                            draft.recurrence_by_day.clear();
                                            draft.recurrence_by_month.clear();
                                            draft.recurrence_by_month_day.clear();
                                            draft.recurrence_by_set_position.clear();
                                            draft.recurrence_first_day_of_week.clear();
                                            draft.recurrence_count.clear();
                                            draft.recurrence_until.clear();
                                        } else {
                                            draft.recurrence_frequency = value;
                                        }
                                    });
                                }
                            },
                            SelectOption::<String> { index: 0usize, value: "none".to_owned(), text_value: "Does not repeat", "Does not repeat" }
                            SelectOption::<String> { index: 1usize, value: "daily".to_owned(), text_value: "Daily", "Daily" }
                            SelectOption::<String> { index: 2usize, value: "weekly".to_owned(), text_value: "Weekly", "Weekly" }
                            SelectOption::<String> { index: 3usize, value: "monthly".to_owned(), text_value: "Monthly", "Monthly" }
                            SelectOption::<String> { index: 4usize, value: "yearly".to_owned(), text_value: "Yearly", "Yearly" }
                        }
                    }
                }
            }
            if recurrence_enabled() {
                details {
                    class: "calendar-schedule-disclosure",
                    "data-testid": "card-detail-calendar-recurrence-options",
                    summary { class: "calendar-schedule-disclosure-summary",
                        span {
                            strong { "Customize recurrence" }
                            small {
                                if custom_recurrence_configured() {
                                    "Custom repeat rules are configured"
                                } else {
                                    "Intervals, selected days, and an optional end"
                                }
                            }
                        }
                        UiIcon { name: "chevron-down" }
                    }
                    div { class: "calendar-schedule-field-grid calendar-schedule-disclosure-body",
                        div { class: "field",
                            Label { html_for: "card-detail-calendar-interval-input", "Repeat every" }
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
                            Label { html_for: "card-detail-calendar-by-day-input", "Days of week" }
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
                            Label { html_for: "card-detail-calendar-by-month-input", "Months" }
                            Input {
                                id: "card-detail-calendar-by-month-input",
                                class: "input",
                                "data-testid": "card-detail-calendar-by-month-input",
                                value: "{calendar().recurrence_by_month}",
                                placeholder: "1, 6, 12",
                                oninput: move |event: FormEvent| update_calendar_draft(calendar, |draft| draft.recurrence_by_month = event.value()),
                            }
                        }
                        div { class: "field",
                            Label { html_for: "card-detail-calendar-by-month-day-input", "Days of month" }
                            Input {
                                id: "card-detail-calendar-by-month-day-input",
                                class: "input",
                                "data-testid": "card-detail-calendar-by-month-day-input",
                                value: "{calendar().recurrence_by_month_day}",
                                placeholder: "1, 15, -1",
                                oninput: move |event: FormEvent| update_calendar_draft(calendar, |draft| draft.recurrence_by_month_day = event.value()),
                            }
                        }
                        div { class: "field",
                            Label { html_for: "card-detail-calendar-by-set-position-input", "Position in period" }
                            Input {
                                id: "card-detail-calendar-by-set-position-input",
                                class: "input",
                                "data-testid": "card-detail-calendar-by-set-position-input",
                                value: "{calendar().recurrence_by_set_position}",
                                placeholder: "1, -1",
                                oninput: move |event: FormEvent| update_calendar_draft(calendar, |draft| draft.recurrence_by_set_position = event.value()),
                            }
                        }
                        div { class: "field",
                            Label { html_for: "card-detail-calendar-first-weekday-input", "Week starts on" }
                            Input {
                                id: "card-detail-calendar-first-weekday-input",
                                class: "input",
                                "data-testid": "card-detail-calendar-first-weekday-input",
                                value: "{calendar().recurrence_first_day_of_week}",
                                placeholder: "MO",
                                oninput: move |event: FormEvent| update_calendar_draft(calendar, |draft| draft.recurrence_first_day_of_week = event.value()),
                            }
                        }
                        div { class: "field",
                            Label { html_for: "card-detail-calendar-count-input", "End after occurrences" }
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
                            Label { html_for: "card-detail-calendar-until-input", "End on" }
                            Input {
                                id: "card-detail-calendar-until-input",
                                class: "input",
                                "data-testid": "card-detail-calendar-until-input",
                                value: "{calendar().recurrence_until}",
                                placeholder: "2026-12-31T23:59:59",
                                oninput: move |event: FormEvent| update_calendar_draft(calendar, |draft| draft.recurrence_until = event.value()),
                            }
                        }
                    }
                }
            }
            details {
                class: "calendar-schedule-disclosure calendar-schedule-technical",
                "data-testid": "card-detail-calendar-advanced-options",
                summary { class: "calendar-schedule-disclosure-summary",
                    span {
                        strong { "Advanced calendar settings" }
                        small { "Status and timezone database version" }
                    }
                    UiIcon { name: "chevron-down" }
                }
                div { class: "calendar-schedule-field-grid calendar-schedule-disclosure-body",
                    div { class: "field",
                        Label { html_for: "card-detail-calendar-status-select", "Calendar status" }
                        Select::<String> {
                            "data-testid": "card-detail-calendar-status-select",
                            value: Some(selected_status.into()),
                            on_value_change: move |value: Option<String>| {
                                if let Some(value) = value {
                                    update_calendar_draft(calendar, |draft| draft.status = value);
                                }
                            },
                            SelectOption::<String> { index: 0usize, value: "confirmed".to_owned(), text_value: "Confirmed", "Confirmed" }
                            SelectOption::<String> { index: 1usize, value: "tentative".to_owned(), text_value: "Tentative", "Tentative" }
                            SelectOption::<String> { index: 2usize, value: "cancelled".to_owned(), text_value: "Cancelled", "Cancelled" }
                        }
                    }
                    div { class: "field",
                        Label { html_for: "card-detail-calendar-tzdb-input", "TZDB version" }
                        Input {
                            id: "card-detail-calendar-tzdb-input",
                            class: "input",
                            "data-testid": "card-detail-calendar-tzdb-input",
                            value: "{calendar().tzdb_version}",
                            placeholder: "{DEFAULT_CALENDAR_TZDB_VERSION}",
                            oninput: move |event: FormEvent| update_calendar_draft(calendar, |draft| draft.tzdb_version = event.value()),
                        }
                    }
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
/// (`BlobEndpoints::upload_bytes_scoped`, multipart/form-data per
/// ), so authorization, retry/backoff and spec error-envelope
/// decoding stay owned by the network layer. Returns
/// `(blob_ref, media_type)` for the editor to build its markdown target.
async fn toast_editor_upload_via_api(
    base_url: &str,
    token: String,
    realm_id: &str,
    allow_image_upload: bool,
    request: &Value,
) -> Result<(String, Option<String>), String> {
    use base64::Engine as _;
    if !allow_image_upload {
        return Err("image upload is unavailable for this encrypted scope".to_owned());
    }
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
    let outcome = crate::transport::auth::with_endpoint_clients(
        base_url,
        token,
        None,
        move |clients| async move {
            clients
                .blob()
                .upload_bytes_scoped(bytes, &media_type, realm_id.as_deref(), filename.as_deref())
                .await
        },
    )
    .await
    .map_err(|error| error.display())?;
    Ok((outcome.blob_ref.to_string(), outcome.media_type))
}

fn toast_editor_bootstrap_script(
    host_id: &str,
    fallback_id: &str,
    value: &str,
    allow_image_upload: bool,
) -> Option<String> {
    let config = serde_json::to_string(&json!({
        "hostId": host_id,
        "fallbackId": fallback_id,
        "value": value,
        "allowImageUpload": allow_image_upload,
        // The asset pipeline flattens source directories and may hash the
        // emitted filename. Use the generated URLs instead of guessing the
        // public path; a guessed miss falls through to the SPA index and the
        // browser then tries to parse HTML as JavaScript/CSS.
        "scriptUrl": TOAST_EDITOR_SCRIPT.to_string(),
        "cssUrl": TOAST_EDITOR_CSS.to_string(),
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

    const registry = window.__inksonToastEditors || (window.__inksonToastEditors = new Map());
    const initialExisting = registry.get(config.hostId);
    if (initialExisting && initialExisting.host === host && host.childElementCount > 0) {{
        releaseBridge();
        return;
    }}

    if (!window.__inksonLoadToastEditor) {{
        window.__inksonLoadToastEditor = () => new Promise((resolve, reject) => {{
            const cssId = "inkson-toast-editor-css";
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

            const scriptId = "inkson-toast-editor-script";
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
        await window.__inksonLoadToastEditor();
    }} catch (error) {{
        console.warn("[inkson] Toast UI Editor unavailable; using textarea fallback", error);
        fallback.classList.remove("toast-fallback-hidden");
        releaseBridge();
        return;
    }}

    if (!window.toastui || !window.toastui.Editor) {{
        fallback.classList.remove("toast-fallback-hidden");
        releaseBridge();
        return;
    }}

    // The component can be unmounted while the shared editor bundle is still
    // loading. Never attach an editor (and its wasm-backed input listener) to
    // a detached host retained only by this async closure.
    if (!host.isConnected || !fallback.isConnected
        || document.getElementById(config.hostId) !== host
        || document.getElementById(config.fallbackId) !== fallback) {{
        releaseBridge();
        return;
    }}

    const existing = registry.get(config.hostId);
    if (existing && existing.host === host && host.childElementCount > 0) {{
        releaseBridge();
        return;
    }}
    if (existing) {{
        // The registry can outlive the Dioxus component that created this
        // editor. Its old eval bridge belongs to an already-reclaimed WASM
        // scope, so calling it here can invoke a stale wasm-bindgen closure
        // and corrupt the whole tab. The scope-bound Rust task is cancelled
        // on unmount; only the detached JS editor needs explicit teardown.
        registry.delete(config.hostId);
        try {{ existing.editor.off("change", existing.sync); }} catch (_) {{}}
        try {{ existing.editor.destroy(); }} catch (_) {{}}
    }}

    host.innerHTML = "";
    fallback.classList.add("toast-fallback-hidden");

    let editor = null;

    const sync = () => {{
        const current = registry.get(config.hostId);
        if (!current || current.editor !== editor || current.host !== host
            || !host.isConnected || !fallback.isConnected) {{
            return;
        }}
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

    // JS never talks to the protocol endpoint itself. It only
    // extracts the picked file's bytes and hands them to Rust over the
    // bidirectional eval channel; the upload runs through the canonical
    // `BlobEndpoints::upload_bytes_scoped` pipeline and Rust sends the
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
            console.warn("[inkson] image upload failed", error);
            window.alert("Image upload failed.");
        }}
        return false;
    }};

    editor = new window.toastui.Editor({{
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
            config.allowImageUpload ? ["table", "image", "link"] : ["table", "link"],
            ["code", "codeblock"]
        ],
        hooks: config.allowImageUpload ? {{
            addImageBlobHook: uploadImage
        }} : {{}}
    }});

    registry.set(config.hostId, {{ editor, host, sync }});
    editor.on("change", sync);
}})();"##
    ))
}

fn toast_editor_cleanup_script(host_id: &str) -> Option<String> {
    let host_id = serde_json::to_string(host_id).ok()?;
    Some(format!(
        r#"(() => {{
    const registry = window.__inksonToastEditors;
    if (!registry) return;
    const host = document.getElementById({host_id});
    const existing = registry.get({host_id});
    if (!existing || existing.host !== host) return;
    // Delete first: even if the third-party teardown emits a late change or
    // throws, the callback's registry guard prevents it from dispatching an
    // input event into a Dioxus listener whose wasm scope is being reclaimed.
    registry.delete({host_id});
    try {{ existing.editor.off("change", existing.sync); }} catch (_) {{}}
    try {{ existing.editor.destroy(); }} catch (_) {{}}
}})();"#
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
    plaintext_service_id: String,
    token: Signal<String>,
    principal_id: arkret_sdk::DidCoreId,
    account_primary_handle: Signal<String>,
    device_id: String,
    selected_realm_id: String,
    projection_realm_id: String,
    sync_cursor: Signal<String>,
    /// Monotonic counter bumped by the per-realm `events/subscribe` engine
    /// ([`crate::realm_events_engine`]) when it folds fresh realm events that
    /// the account `sync_cursor` never delivered (cross-member case). Drives the
    /// live reconciler independently of the account cursor.
    realm_live_epoch: Signal<u64>,
    frontier_state: Signal<String>,
    event_write_ready: bool,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let principal_core_id = principal_id.clone();
    let principal_id = principal_id.as_str().to_owned();
    let session_context = crate::app::SessionContext::get();
    let base_url = session_context.base_url.read().clone();
    let state_store = session_context.state_store;
    let Some(active_account) = session_context.active_account.read().clone() else {
        return rsx! {};
    };
    let authority = active_account.authority;
    let hosted_sidecar_state = use_context::<crate::sidecar::HostedSidecarStateContext>().0;
    // Demo seed fallback remains explicit; normal boards derive from events.
    let seed_fallback_allowed = kanban_seed_fallback_allowed(&base_url);
    let initial_columns = if seed_fallback_allowed {
        seed_columns()
    } else {
        Vec::new()
    };
    let navigator = use_navigator();
    let route = use_route::<Route>();
    let local_realm_id = local_projection_realm_id(&selected_realm_id, &projection_realm_id);
    // Authoring uses the authenticated Station's current digest suite. The
    // Realm events engine refreshes this bounded result independently of history.
    // Durable same-operation retry still covers changes after the click.
    let station_frontier_ready = state_store
        .read()
        .station_realm_digest_suite(&selected_realm_id)
        .is_some();
    // The board id lives in the URL (`/kanban/<realm>/board/<board>` and
    // its `/task/<strand>` extension). Seeding `selected_board`
    // from the route — instead of always `board_options.first()` — is
    // what makes a refresh restore the exact board the user had open,
    // including when the open card is a local draft the server
    // projection does not know about yet. `route_board_id` parses the
    // untrusted segment as a `SpaceId` and fails closed, so a stale URL can
    // never put a holder-local operation id into the selection.
    let routed_board_id = route_board_id(&route);
    let (initial_board_options, initial_board_pending_create) = {
        let seed_options = initial_board_space_options(seed_fallback_allowed);
        let state = state_store.read().load();
        let options =
            overlay_local_board_space_options(seed_options, &state.raw_operations, &local_realm_id);
        // A pending create outlives a refresh via the durable op log. While
        // one exists, cold start must NOT seed the first confirmed Board —
        // the pending surface (title + creating state) owns the view until
        // the receipt transition commits the accepted Space id.
        let pending_create =
            !pending_board_creates_from_ops(&state.raw_operations, &local_realm_id).is_empty();
        (options, pending_create)
    };
    let initial_board = routed_board_id.or_else(|| {
        if initial_board_pending_create {
            None
        } else {
            initial_board_options
                .first()
                .map(|option| option.id.clone())
        }
    });
    let controller = use_kanban_controller(
        initial_board_options.clone(),
        initial_board,
        seed_fallback_allowed,
        event_write_ready,
    );
    let KanbanController {
        board_space_options,
        mut selected_board,
        lifecycle_container_projection,
        lifecycle_strand_projection,
        mut new_board_title,
        mut new_column_title,
        mut new_card_title,
        mut adding_card_to,
        mut selected_card,
        mls_sidecar_restore_key_seen: _,
        mut board_popover,
        mut archive_board_confirm_open,
        mut list_archive_confirm,
        mut editing_card_detail,
        card_edit_scope,
        card_detail_sidebar_visible: _,
        mut card_detail_actions_open,
        mut card_detail_tab,
        card_detail_discussion_mounted_for: _,
        card_detail_sidebar_tab: _,
        card_detail_docked: _,
        card_detail_dock_width: _,
        card_detail_resizing: _,
        card_detail_resize_start_x: _,
        card_detail_resize_start_width: _,
        member_handle_fetching: _,
        mut card_edit_title,
        mut card_edit_description,
        mut card_edit_body,
        mut card_edit_synthesis,
        mut card_edit_synthesis_target_id,
        mut card_detail_edit_status,
        mut assignee_picker_open,
        mut assignee_filter,
        mut assignee_selected_actor_ids,
        mut assignee_edit_status,
        mut due_picker_open,
        mut due_edit_value,
        mut due_calendar_month,
        mut due_edit_status,
        mut card_edit_calendar,
        mut calendar_rsvp_occurrence,
        mut card_synthesis_history_open_id,
        mut card_synthesis_selected_revision_id,
        mut card_edit_labels,
        mut card_edit_assignee,
        mut card_edit_due,
        mut dragging_card,
        mut dragging_column,
        mut drop_target_column,
        mut editing_column_id,
        mut editing_column_title,
        mut board_status,
        command_queue: _,
    } = controller;
    let selected_board_value_for_select =
        use_memo(move || selected_board().map(|board_id| board_id.to_string()));
    // Pending Board creates derive from the durable op log (no extra signal,
    // no extra persistence): the row carries the user-entered title and the
    // write state until the accept receipt reconciles it into a confirmed
    // `SpaceId` option.
    let pending_board_creates = use_memo({
        let pending_realm_id = local_realm_id.clone();
        move || {
            let store = state_store.read();
            pending_board_creates_from_ops(&store.load().raw_operations, &pending_realm_id)
        }
    });
    // `columns` merges the server's current Space/Strand baseline with the
    // visible Event log. The baseline recovers current objects whose create
    // Event predates a `since_join` floor; Events provide signed updates,
    // optimistic writes and E2EE content without turning the server projection
    // into a second truth source.
    let columns = use_memo({
        let seed_realm_id = local_realm_id.clone();
        let decrypt_realm_id = selected_realm_id.clone();
        let decrypt_authority = authority.clone();
        let decrypt_device = device_id.clone();
        let self_actor_id = principal_id.clone();
        let seed_columns = initial_columns.clone();
        move || {
            let board_id = selected_board()
                .map(|board_id| board_id.to_string())
                .unwrap_or_default();
            let decrypt_store = state_store.read();
            let raw_operations = decrypt_store.load().raw_operations;
            let projected_containers = lifecycle_container_projection();
            let projected_strands = lifecycle_strand_projection();
            let decrypt_ctx = mls_decrypt_ctx_if_ready(
                &decrypt_store,
                &decrypt_realm_id,
                &decrypt_authority,
                &decrypt_device,
            );
            if raw_operations.is_empty() && !seed_columns.is_empty() {
                // Demo / seed-fallback columns: layer local optimistic ops on top.
                let cols = overlay_local_card_create_records(
                    seed_columns.clone(),
                    &raw_operations,
                    &board_id,
                );
                let cols =
                    overlay_local_card_update_records(cols, &raw_operations, decrypt_ctx.as_ref());
                return overlay_local_card_assignment_records(cols, &raw_operations);
            }
            let (mut cols, ..) = project_board_with_projection_for_actor(
                &raw_operations,
                &projected_containers,
                &projected_strands,
                &board_id,
                &seed_realm_id,
                decrypt_ctx.as_ref(),
                &self_actor_id,
            );
            let entries = decrypt_store
                .load()
                .realm_tree_projections
                .get(&seed_realm_id)
                .and_then(|value| value.get("current"))
                .and_then(|value| {
                    serde_json::from_value::<arkret_sdk::CurrentEntries>(value.clone()).ok()
                })
                .map(|current| current.entries)
                .unwrap_or_default();
            install_current_strand_positions(
                &mut cols,
                &entries,
                &projected_strands,
                &board_id,
                decrypt_ctx.as_ref(),
                &self_actor_id,
            );
            install_current_strand_lifecycles(&mut cols, &entries);
            install_current_space_cells(&mut cols, &entries);
            install_current_card_sources(
                &mut cols,
                &entries,
                &projected_strands,
                decrypt_ctx.as_ref(),
                &self_actor_id,
            );
            let pending = raw_operations
                .iter()
                .filter(|record| {
                    matches!(
                        record
                            .payload
                            .get("write_state")
                            .and_then(serde_json::Value::as_str),
                        Some("queued" | "submitting")
                    )
                })
                .cloned()
                .collect::<Vec<_>>();
            let cols = overlay_local_card_update_records(cols, &pending, decrypt_ctx.as_ref());
            overlay_local_card_assignment_records(cols, &raw_operations)
        }
    });
    let mut current_card_page = use_signal(|| 0usize);
    let current_page = use_memo(move || {
        card_current_page(&columns(), current_card_page(), selected_card().as_ref())
    });
    use_effect({
        let authority = authority.clone();
        let realm = local_realm_id.clone();
        move || {
            let (strands, _) = current_page();
            let selected = selected_board();
            let cells = current_board_cell_demand(
                &columns(),
                selected.as_ref().map(arkret_sdk::SpaceId::as_str),
            );
            state_store
                .read()
                .set_product_current_demand(&authority, &realm, Some(strands), cells);
        }
    });
    use_drop({
        let authority = authority.clone();
        let realm = local_realm_id.clone();
        move || {
            state_store
                .read()
                .set_product_current_demand(&authority, &realm, None, Vec::new())
        }
    });
    let (current_card_ids, current_page_count) = current_page();
    let current_card_ids = current_card_ids
        .into_iter()
        .map(|id| id.to_string())
        .collect::<BTreeSet<_>>();
    let selected_board_value = selected_board();
    let BoardHeader {
        active_pending_board,
        title: selected_board_title,
    } = board_header(
        selected_board_value.as_ref(),
        &board_space_options(),
        pending_board_creates(),
    );
    let board_status_text = board_status();
    let board_select_label = format!("{}:", crate::i18n::tr("kanban.board_header"));

    // Synthesis track projection (option`ak.strand.update). The track is built
    // by decrypting and replaying every `ak.strand.update` op for this strand
    // from the LOCAL `raw_operations` log. Those ops are kept current by the
    // per-realm events engine (`realm_events_engine` → `ingest_kanban_events`),
    // which folds the full realm history — including each update's
    // authoritative per-event `actor_id` — into the store. Historical revisions
    // therefore recover their true author from local state, with NO per-tab
    // realm backfill: opening the Synthesis tab no longer fetches the realm
    // event log. Memoized so the (MLS-decrypting) replay runs only when its
    // inputs change — `selected_card`, the active tab/edit scope, the local op
    // log (`state_store`), or a fresh per-realm engine ingest
    // (`realm_live_epoch`) — instead of on every KanbanPanel re-render.
    let synthesis_entries_memo = {
        let memo_realm_id = selected_realm_id.clone();
        let memo_projection_realm_id = projection_realm_id.clone();
        let memo_authority = authority.clone();
        let memo_device = device_id.clone();
        use_memo(move || {
            let want_synthesis = matches!(card_detail_tab(), CardDetailContentTab::Synthesis)
                || (editing_card_detail() && card_edit_scope() == CardEditScope::Synthesis);
            let Some(card) = selected_card() else {
                return Vec::<CardSynthesisTrackEntry>::new();
            };
            if !want_synthesis {
                return Vec::new();
            }
            // Subscribe to per-realm engine ingests so a freshly-folded update
            // re-projects the track even when the account `sync_cursor` is the
            // (cross-member-lossy) path.
            let _ = realm_live_epoch();
            let store = state_store.read();
            let snapshot = store.load();
            let projection = snapshot.realm_tree_projections.get(&memo_realm_id);
            let realm_context =
                member_roster_realm_context(&memo_realm_id, &memo_projection_realm_id, projection);
            let member_rows = realm_member_roster(projection);
            let author_context = CardAuthorDisplayContext {
                realm_id: &realm_context,
                member_rows: &member_rows,
            };
            let decrypt_ctx =
                mls_decrypt_ctx_if_ready(&store, &memo_realm_id, &memo_authority, &memo_device);
            let _active_sidecar = hosted_sidecar_state().filter(|session| {
                session.source_realm_id == memo_realm_id
                    && session.source_strand_id == card.primary_strand_id
            });
            let private_card: Option<KanbanCard> = None;
            let projected_card = private_card.as_ref().unwrap_or(&card);
            card_synthesis_track_entries_with_author_context_and_decrypt(
                projected_card,
                &snapshot.raw_operations,
                &store,
                Some(author_context),
                decrypt_ctx.as_ref(),
            )
        })
    };

    let board_selected = selected_board_value.is_some();
    let board_surface_active = board_selected || active_pending_board.is_some();
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
        garth::security_projection_for_scope_id(&state.realm_tree_projections, scope_id)
            .or_else(|| {
                garth::security_projection_for_scope_id(
                    &state.realm_tree_projections,
                    &selected_realm_id,
                )
            })
            .and_then(garth::realm_projection_security_state)
    };
    // Fail-closed `bool` projection for the non-guard consumers (security
    // badge display, the per-card encrypt decision): when the Realm security
    // state is unknown we treat it as encrypted so those paths never take the
    // plaintext branch. Known-plaintext (`Some(false)`) stays `false`.
    let selected_scope_security_encrypted_or_secure =
        selected_scope_security_encrypted.unwrap_or(true);
    let projected_strand_ids = lifecycle_strand_projection()
        .into_iter()
        .map(|view| view.strand_id)
        .collect::<BTreeSet<_>>();
    rsx! {
        div { class: "timeline kanban-panel", "data-testid": "kanban-panel",
            KanbanEffects {
                controller,
                columns,
                route: route.clone(),
                local_realm_id: local_realm_id.clone(),
                base_url: base_url.clone(),
                token,
                selected_realm_id: selected_realm_id.clone(),
                projection_realm_id: projection_realm_id.clone(),
                authority: authority.clone(),
                principal_id: principal_id.clone(),
                device_id: device_id.clone(),
                sync_cursor,
                realm_live_epoch,
            }
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
                                rsx! {
                                    Select::<String> {
                                        class: "board-select-native",
                                        "data-testid": "board-space-select",
                                        value: Some(selected_board_value_for_select.into()),
                                        on_value_change: move |v: Option<String>| {
                                            if let Some(v) = v {
                                                // The empty sentinel option clears the
                                                // selection; anything else must parse
                                                // as a canonical Space id.
                                                select_kanban_board(
                                                    arkret_sdk::SpaceId::new(v).ok(),
                                                    selected_board,
                                                    board_popover,
                                                    selected_card,
                                                    board_route_realm_id_for_select.clone(),
                                                    adding_card_to,
                                                    board_status,
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
                                        rsx! {
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                class: if selected_board().is_none() { "board-select-menu-item is-active" } else { "board-select-menu-item" },
                                                role: "option",
                                                "aria-selected": "{selected_board().is_none()}",
                                                onclick: move |_| {
                                                    select_kanban_board(
                                                        None,
                                                        selected_board,
                                                        board_popover,
                                                        selected_card,
                                                        board_route_realm_id_for_empty.clone(),
                                                        adding_card_to,
                                                        board_status,
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
                                            let option_is_active =
                                                selected_board().as_ref() == Some(&option_id);
                                            let board_route_realm_id_for_option = board_route_realm_id.clone();
                                            rsx! {
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    class: if option_is_active { "board-select-menu-item is-active" } else { "board-select-menu-item" },
                                                    role: "option",
                                                    "aria-selected": "{option_is_active}",
                                                    title: "{option_title}",
                                                    onclick: {
                                                        let option_id = option_id.clone();
                                                        move |_| {
                                                            select_kanban_board(
                                                                Some(option_id.clone()),
                                                                selected_board,
                                                                board_popover,
                                                                selected_card,
                                                                board_route_realm_id_for_option.clone(),
                                                                adding_card_to,
                                                                board_status,
                                                            );
                                                        }
                                                    },
                                                    UiIcon { name: "board" }
                                                    span { "{option_title}" }
                                                }
                                            }
                                        }
                                    }
                                    // Pending creates are not selectable options:
                                    // they have no protocol identity yet. An
                                    // in-flight row stays disabled; a failed row
                                    // is the durable retry affordance for the same
                                    // holder-local operation id.
                                    for pending in pending_board_creates().iter() {
                                        {
                                            let pending_label =
                                                format!("{} ({})", pending.title, pending.status_hint());
                                            let retryable = pending.is_retryable();
                                            let retry_title = pending.error.clone().unwrap_or_else(|| {
                                                if retryable {
                                                    "Retry Board creation".to_owned()
                                                } else {
                                                    "Waiting for the Board to be accepted".to_owned()
                                                }
                                            });
                                            let retry_board_title = pending.title.clone();
                                            let retry_operation_id = pending.operation_id.clone();
                                            let retry_base_url = base_url.clone();
                                            let retry_realm_id = selected_realm_id.clone();
                                            let retry_actor_id = principal_id.clone();
                                            rsx! {
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    class: "board-select-menu-item",
                                                    role: "option",
                                                    "aria-selected": "false",
                                                    "aria-disabled": "{!retryable}",
                                                    disabled: !retryable,
                                                    title: "{retry_title}",
                                                    onclick: move |_| {
                                                        if !retryable {
                                                            return;
                                                        }
                                                        let operation = crate::operation::ak_ops::space_create(
                                                            &retry_realm_id,
                                                            &retry_actor_id,
                                                            "board",
                                                            &retry_board_title,
                                                            None,
                                                            None,
                                                        )
                                                        .and_then(|builder| builder.build_sdk_event("inkson"))
                                                        .map(|operation| {
                                                            operation.with_local_operation_id(
                                                                retry_operation_id.clone(),
                                                            )
                                                        });
                                                        match operation {
                                                            Ok(operation) => {
                                                                controller.enqueue_operation(
                                                                    retry_base_url.clone(),
                                                                    token,
                                                                    retry_realm_id.clone(),
                                                                    operation,
                                                                    selected_scope_security_encrypted,
                                                                );
                                                                board_status.set(
                                                                    "Retrying Board creation".to_owned(),
                                                                );
                                                                board_popover.set(BoardToolbarPopover::None);
                                                            }
                                                            Err(error) => board_status.set(format!(
                                                                "cannot retry Board creation: {error:#}"
                                                            )),
                                                        }
                                                    },
                                                    UiIcon { name: "board" }
                                                    span { "{pending_label}" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if board_surface_active {
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
                                    // A pending Board has no protocol id yet, so it
                                    // cannot be a List `parent_space_id`; the action
                                    // unlocks when the receipt commits the selection.
                                    disabled: selected_board_value.is_none(),
                                    title: if selected_board_value.is_some() {
                                        "Add a list to this board"
                                    } else {
                                        "Waiting for the board to be accepted"
                                    },
                                    onclick: {
                                        // Lists are Space containers in v1. The local column is
                                        // visible but remains in sending/failed state
                                        // until `ak.self.events.command.submit.v1` returns.
                                        let base = base_url.clone();
                                        let realm = selected_realm_id.clone();
                                        let actor = principal_id.clone();
                                        move |_| {
                                            let title = new_column_title().trim().to_owned();
                                            if title.is_empty() {
                                                return;
                                            }
                                            if actor.trim().is_empty() {
                                                board_status.set("sign in before adding lists".to_owned());
                                                return;
                                            }
                                            let Some(board_space_id) = selected_board() else {
                                                board_status.set(
                                                    "Board is still being created; add a list after server confirmation."
                                                        .to_owned(),
                                                );
                                                return;
                                            };
                                            let col_count = columns()
                                                .iter()
                                                .filter(|column| column.state == SpaceContainerLifecycleState::Active)
                                                .count();
                                            let rank = format!("r{:03}", col_count + 1);
                                            let op = match crate::operation::ak_ops::space_create(
                                                &realm,
                                                &actor,
                                                "list",
                                                &title,
                                                Some(board_space_id.as_str()),
                                                Some(&rank),
                                            ) {
                                                Ok(builder) => builder
                                                    .build_sdk_event("inkson"),
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
                                            // The new list`ak.space.createtely: `submit_kanban_operation_event`
                                            // appends the `ak.space.create` op, which the `columns` memo folds.
                                            controller.enqueue_operation(
                                                base.clone(),
                                                token,
                                                realm.clone(),
                                                op,
                                                selected_scope_security_encrypted,
                                            );
                                            new_column_title.set(String::new());
                                        }
                                    },
                                    {crate::i18n::tr("kanban.add_list")}
                                }
                            }
                        }
                        if board_selected {
                            Button {
                                variant: ButtonVariant::Secondary,
                                size: ButtonSize::Sm,
                                class: "btn board-archive-board",
                                "data-testid": "archive-board-button",
                                title: crate::i18n::tr("kanban.archive_board_action"),
                                // End-of-week bulk archive cascades every active
                                // card + list before the board Space itself, so
                                // the click only opens the confirmation dialog;
                                // `dispatch_board_archive_cascade` runs from the
                                // dialog's confirm button.
                                onclick: move |_| archive_board_confirm_open.set(true),
                                {crate::i18n::tr("kanban.archive_board_action")}
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
                                        disabled: !event_write_ready || !station_frontier_ready,
                                        title: if station_frontier_ready {
                                            "Create Board"
                                        } else {
                                            "Waiting for the Realm Station frontier"
                                        },
                                        onclick: {
                                            let base = base_url.clone();
                                            let realm = selected_realm_id.clone();
                                            let actor = principal_id.clone();
                                            let create_route_realm_id = board_route_realm_id.clone();
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
                                                let op = match crate::operation::ak_ops::space_create(
                                                    &realm,
                                                    &actor,
                                                    "board",
                                                    &title,
                                                    None,
                                                    None,
                                                ) {
                                                    Ok(builder) => builder
                                                        .build_sdk_event("inkson"),
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
                                                // The Board Space is named by `retype(event_id)` of the
                                                // FINAL create Event, which does not exist yet, so the
                                                // create only enqueues the durable `LocalOperation`.
                                                // Clear the confirmed selection and fall back to the
                                                // realm-level route: the op-log-derived
                                                // `pending_board_creates` memo then renders the new
                                                // Board's title + creating state immediately, and the
                                                // route reconciler cannot pin the previous Board back.
                                                // The transition effect commits the accepted `SpaceId`
                                                // selection + canonical route once the receipt lands.
                                                adding_card_to.set(None);
                                                controller.enqueue_operation(
                                                    base.clone(),
                                                    token,
                                                    realm.clone(),
                                                    op,
                                                    selected_scope_security_encrypted,
                                                );
                                                selected_board.set(None);
                                                let _ = navigator.replace(kanban_board_route(
                                                    &create_route_realm_id,
                                                    "",
                                                ));
                                                board_status.set(
                                                    "Creating Board; lists will be available after server confirmation."
                                                        .to_owned(),
                                                );
                                                new_board_title.set("Board".to_owned());
                                                board_popover.set(BoardToolbarPopover::None);
                                            }
                                        },
                                        "Create Board"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            div {
                class: "muted board-status",
                "data-testid": "board-status",
                "{board_status_text}"
            }
            if current_page_count > 1 {
                nav { "aria-label": "Card pages",
                    Button {
                        disabled: current_card_page() == 0,
                        onclick: move |_| current_card_page.set(current_card_page().saturating_sub(1)),
                        "Previous cards"
                    }
                    span { "Page {current_card_page().min(current_page_count - 1) + 1} / {current_page_count}" }
                    Button {
                        disabled: current_card_page() >= current_page_count - 1,
                        onclick: move |_| current_card_page.set(current_card_page() + 1),
                        "Next cards"
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
                        if board_surface_active {
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
                    let active_cards = column
                        .cards
                        .iter()
                        .filter(|card| card.lifecycle == StrandLifecycleState::Active)
                        .cloned()
                        .collect::<Vec<_>>();
                    let is_active_drop_target =
                        drop_target_column().as_deref() == Some(column_id.as_str());
                    let column_div_class = if is_active_drop_target {
                        format!("{board_column_class} is-drop-target")
                    } else {
                        board_column_class.to_owned()
                    };
                    rsx! {
                    div {
                        class: "{column_div_class}",
                        "data-testid": "kanban-column",
                        "data-column-draft": if arkret_sdk::SpaceId::new(column_id.clone()).is_ok() { "false" } else { "true" },
                        ondragover: {
                            let column_id = column_id.clone();
                            move |event: DragEvent| {
                                event.prevent_default();
                                // Only paint the accent while a card (not a
                                // column reorder) is in flight.
                                if dragging_card().is_some()
                                    && drop_target_column().as_deref() != Some(column_id.as_str())
                                {
                                    drop_target_column.set(Some(column_id.clone()));
                                }
                            }
                        },
                        ondragleave: {
                            let column_id = column_id.clone();
                            move |_| {
                                if drop_target_column().as_deref() == Some(column_id.as_str()) {
                                    drop_target_column.set(None);
                                }
                            }
                        },
                        ondrop: {
                            // Drop landing on the column background (not on
                            // a card) lands the card at the END of the
                            // column. Drops on individual cards (handled
                            // by their own `ondrop`) land ABOVE that card.
                            let target_column_id = column.id.clone();
                            let last_rank = active_cards.last().map(|c| c.rank.clone());
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor = principal_id.clone();
                            move |event| {
                                event.prevent_default();
                                drop_target_column.set(None);
                                let Some(dragged) = dragging_card() else {
                                    return;
                                };
                                let Some(board_space_id) = selected_board() else {
                                    board_status.set("select or create a Board Space before moving cards".to_owned());
                                    return;
                                };
                                dragging_card.set(None);
                                let neighbours = ColumnNeighbours {
                                    prev_rank: last_rank.clone(),
                                    next_rank: None,
                                };
                                dispatch_strand_position_move(
                                    base.clone(),
                                    token,
                                    realm.clone(),
                                    board_space_id.to_string(),
                                    actor.clone(),
                                    dragged,
                                    target_column_id.clone(),
                                    neighbours,
                                    state_store,
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
                                let actor = principal_id.clone();
                                move |event| {
                                    event.prevent_default();
                                    let dragged = dragging_column().or_else(|| {
                                        event
                                            .data_transfer()
                                            .get_data("application/x-arkret-column-id")
                                            .or_else(|| event.data_transfer().get_data("text/plain"))
                                            .filter(|id| id.starts_with("ak:space:"))
                                            .map(|column_id| DraggedColumn { column_id })
                                    });
                                    let Some(dragged) = dragged else {
                                        return;
                                    };
                                    dragging_column.set(None);
                                    // Compute the new column`ak.space.updated-only snapshot, then
                                    // submit the per-column `ak.space.update` rank patches. Each
                                    // appended op folds into the `columns` memo via the space-update
                                    // reducer, so the reorder renders without a direct signal write.
                                    let reordered_columns = {
                                        let mut cols = columns();
                                        reorder_column_before(
                                            &mut cols,
                                            &dragged.column_id,
                                            &target_column_id,
                                        )
                                        .then_some(cols)
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
                                    disabled: columns().iter().filter(|column| column.state == SpaceContainerLifecycleState::Active).any(|column| arkret_sdk::SpaceId::new(column.id.clone()).is_err()),
                                    draggable: if columns().iter().filter(|column| column.state == SpaceContainerLifecycleState::Active).all(|column| arkret_sdk::SpaceId::new(column.id.clone()).is_ok()) { "true" } else { "false" },
                                    title: "Drag column {column.title}",
                                    "aria-label": "Drag column {column.title}",
                                    ondragstart: {
                                        let column_id = column_id.clone();
                                        move |event| {
                                            let _ = event
                                                .data_transfer()
                                                .set_data("application/x-arkret-column-id", &column_id);
                                            let _ = event.data_transfer().set_data("text/plain", &column_id);
                                            dragging_column.set(Some(DraggedColumn {
                                                column_id: column_id.clone(),
                                            }));
                                        }
                                    },
                                    ondragend: move |_| dragging_column.set(None),
                                    "::"
                                }
                                if editing_column_id().as_deref() == Some(column_id.as_str()) {
                                    input {
                                        class: "entity-title column-rename-input",
                                        "data-testid": "column-rename-input",
                                        r#type: "text",
                                        autofocus: true,
                                        maxlength: "512",
                                        value: "{editing_column_title}",
                                        oninput: move |event: FormEvent| editing_column_title.set(event.value()),
                                        onkeydown: {
                                            let column_id = column_id.clone();
                                            let base = base_url.clone();
                                            let realm = selected_realm_id.clone();
                                            let actor = principal_id.clone();
                                            move |event: KeyboardEvent| match event.key().to_string().as_str() {
                                                "Enter" => {
                                                    event.prevent_default();
                                                    submit_column_rename(
                                                        base.clone(),
                                                        token,
                                                        realm.clone(),
                                                        actor.clone(),
                                                        column_id.clone(),
                                                        editing_column_title(),
                                                        selected_scope_security_encrypted,
                                                        state_store,
                                                        board_status,
                                                    );
                                                    editing_column_id.set(None);
                                                }
                                                "Escape" => {
                                                    event.prevent_default();
                                                    editing_column_id.set(None);
                                                }
                                                _ => {}
                                            }
                                        },
                                        onblur: {
                                            let column_id = column_id.clone();
                                            let base = base_url.clone();
                                            let realm = selected_realm_id.clone();
                                            let actor = principal_id.clone();
                                            move |_| {
                                                // Commit on blur so a click elsewhere keeps the edit;
                                                // an empty draft is ignored by `submit_column_rename`.
                                                if editing_column_id().as_deref() == Some(column_id.as_str()) {
                                                    submit_column_rename(
                                                        base.clone(),
                                                        token,
                                                        realm.clone(),
                                                        actor.clone(),
                                                        column_id.clone(),
                                                        editing_column_title(),
                                                        selected_scope_security_encrypted,
                                                        state_store,
                                                        board_status,
                                                    );
                                                    editing_column_id.set(None);
                                                }
                                            }
                                        },
                                    }
                                } else {
                                    span {
                                        class: "entity-title",
                                        "data-testid": "kanban-column-title",
                                        title: crate::i18n::tr("kanban.rename_list_hint"),
                                        ondoubleclick: {
                                            let column_id = column_id.clone();
                                            let column_title = column.title.clone();
                                            move |_| {
                                                editing_column_title.set(column_title.clone());
                                                editing_column_id.set(Some(column_id.clone()));
                                            }
                                        },
                                        "{column.title}"
                                    }
                                }
                            }
                        }

                for (card_index, card) in active_cards.iter().enumerate().filter(|(_, card)| {
                    let optimistic_local_id = arkret_sdk::StrandId::new(card.id.clone()).is_err();
                    optimistic_local_id
                        || (current_card_ids.contains(&card.id)
                            && card.position_basis_refs.len() == 1)
                })
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
                                    if !displayed_card_state(card, &projected_strand_ids)
                                        .is_settled()
                                    {
                                        classes.push_str(" is-draft");
                                    }
                                    classes
                                },
                                "data-testid": "kanban-card",
                                // Surface the per-card write state on the tile so
                                // a locally-queued (not-yet-acked) card is
                                // distinguishable from a server-synced one. The
                                // archive-then-recreate promote pattern waits on
                                // this leaving the draft state.
                                "data-card-state": displayed_card_state(card, &projected_strand_ids).data_state(),
                                "data-card-draft": if displayed_card_state(card, &projected_strand_ids).is_settled() { "false" } else { "true" },
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
                                        Some(active_cards[card_index - 1].rank.clone())
                                    };
                                    let base = base_url.clone();
                                    let realm = selected_realm_id.clone();
                                    let actor = principal_id.clone();
                                    move |event| {
                                        event.prevent_default();
                                        // Stop propagation so the column's
                                        // ondrop above doesn't also fire
                                        // and double-insert at the tail.
                                        event.stop_propagation();
                                        let Some(dragged) = dragging_card() else {
                                            return;
                                        };
                                        let Some(board_space_id) = selected_board() else {
                                            board_status.set("select or create a Board Space before moving cards".to_owned());
                                            return;
                                        };
                                        dragging_card.set(None);
                                        let neighbours = ColumnNeighbours {
                                            prev_rank: prev_rank.clone(),
                                            next_rank: Some(this_rank.clone()),
                                        };
                                        dispatch_strand_position_move(
                                            base.clone(),
                                            token,
                                            realm.clone(),
                                            board_space_id.to_string(),
                                            actor.clone(),
                                            dragged,
                                            target_column_id.clone(),
                                            neighbours,
                                            state_store,
                                            board_status,
                                        );
                                    }
                                },
                                ondragstart: {
                                    let card_id = card.id.clone();
                                    let column_id = column.id.clone();
                                    let from_rank = card.rank.clone();
                                    let position_basis_refs = card.position_basis_refs.clone();
                                    move |_| {
                                        dragging_card.set(Some(DraggedCard {
                                            card_id: card_id.clone(),
                                            from_column_id: column_id.clone(),
                                            from_rank: from_rank.clone(),
                                            position_basis_refs: position_basis_refs.clone(),
                                        }));
                                    }
                                },
                                ondragend: move |_| {
                                    dragging_card.set(None);
                                    drop_target_column.set(None);
                                },
                                onclick: {
                                    let c = card.clone();
                                    let route_realm_id = card_detail_route_realm_id(&selected_realm_id);
                                    move |_| {
                                        let draft = card_detail_draft_from_card(&c);
                                        card_edit_title.set(draft.title);
                                        card_edit_description.set(draft.description);
                                        card_edit_body.set(draft.description_body);
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
                                        card_detail_tab.set(CardDetailContentTab::default());
                                        card_synthesis_history_open_id.set(None);
                                        card_synthesis_selected_revision_id.set(None);
                                        selected_card.set(Some(c.clone()));
                                        let _ = navigator.push(kanban_card_task_route(
                                            &route_realm_id,
                                            selected_board()
                                                .as_ref()
                                                .map(arkret_sdk::SpaceId::as_str)
                                                .unwrap_or(""),
                                            &c.id,
                                        ));
                                        replace_card_detail_tab_query(CardDetailContentTab::default());
                                    }
                                },
                                div { class: "event-head board-card-title-row",
                                    span { class: "entity-title board-card-title", title: "{card.title}", "{card.title}" }
                                    if !displayed_card_state(card, &projected_strand_ids).is_settled() {
                                        span {
                                            class: "badge blue board-card-draft-badge",
                                            "data-testid": "kanban-card-draft-badge",
                                            title: crate::i18n::tr("kanban.card.draft_hint"),
                                            {crate::i18n::tr("kanban.card.draft")}
                                        }
                                    }
                                }
                                if !card.labels.is_empty() {
                                    div { class: "actions board-card-labels",
                                    for label in &card.labels {
                                        span { key: "{label}", class: "badge", "{label}" }
                                    }
                                    }
                                }
                                if !card.description.trim().is_empty() {
                                    div { class: "muted board-card-description", "{card.description}" }
                                }
                                {
                                    let assignee_text = card.assignee.trim();
                                    let due_text = card.due.trim();
                                    let show_assignee =
                                        !assignee_text.is_empty() && assignee_text != "\u{2014}";
                                    let show_due = !due_text.is_empty()
                                        && due_text != "\u{2014}"
                                        && !due_text.eq_ignore_ascii_case("unscheduled");
                                    let overdue = due_value_is_overdue(due_text);
                                    rsx! {
                                        if show_assignee || show_due {
                                            div { class: "card-meta board-card-meta",
                                                if show_assignee {
                                                    span {
                                                        class: "board-card-meta-item",
                                                        "data-testid": "kanban-card-assignee",
                                                        "assignees {assignee_text}"
                                                    }
                                                }
                                                if show_due {
                                                    span {
                                                        class: if overdue {
                                                            "board-card-meta-item board-card-due-overdue"
                                                        } else {
                                                            "board-card-meta-item"
                                                        },
                                                        "data-testid": "kanban-card-due",
                                                        "data-overdue": if overdue { "true" } else { "false" },
                                                        "due {due_text}"
                                                    }
                                                }
                                                if overdue {
                                                    span {
                                                        class: "badge danger board-card-overdue-badge",
                                                        "data-testid": "kanban-card-overdue-badge",
                                                        "overdue"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                div { class: "board-card-footer",
                                    {
                                        // Block archive until the card's create
                                        // event is server-acked. The SDK reducer
                                        // `ak.strand.archive active` for
                                        // `ak.strand.archive`, so archiving a still-
                                        // draft card would just round-trip to a
                                        // rejection; we fail closed locally and tell
                                        // the user to wait for the draft to settle.
                                        let card_settled = displayed_card_state(card, &projected_strand_ids)
                                            .is_settled();
                                        let archive_enabled = card_settled;
                                        let title_text = if !card_settled {
                                            crate::i18n::tr("kanban.archive_draft_blocked")
                                        } else {
                                            "Archive this card (ak.strand.archive)".to_owned()
                                        };
                                        let testid_state = if !card_settled {
                                            "draft"
                                        } else {
                                            "open"
                                        };
                                        rsx! {
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                class: "kanban-inline-action",
                                                "data-testid": "card-archive-button",
                                                "data-strand-id": "{card.id}",
                                                "data-cap-gate": testid_state,
                                                disabled: !archive_enabled,
                                                title: title_text,
                                                onclick: {
                                                    let base = base_url.clone();
                                                    let realm = selected_realm_id.clone();
                                                    let actor = principal_id.clone();
                                                    let strand_id = card.id.clone();
                                                    let lifecycle_basis_refs =
                                                        card.lifecycle_basis_refs.clone();
                                                    move |evt: dioxus::events::MouseEvent| {
                                                        evt.stop_propagation();
                                                        if !card_settled {
                                                            board_status.set(crate::i18n::tr(
                                                                "kanban.archive_draft_blocked",
                                                            ));
                                                            return;
                                                        }
                                                        dispatch_strand_lifecycle(
                                                            base.clone(),
                                                            token,
                                                            realm.clone(),
                                                            actor.clone(),
                                                            strand_id.clone(),
                                                            StrandLifecycleState::Archived,
                                                            lifecycle_basis_refs.clone(),
                                                            state_store,
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
                                            // ak.strand.create envelope, which
                                            // carries NO placement. The first
                                            // Board/List placement is a
                                            // separate ak.strand.move that
                                            // `submit_kanban_card_create`
                                            // authors once the create receipt
                                            // names the Strand.
                                            let base = base_url.clone();
                                            let col_id = column.id.clone();
                                            let realm = selected_realm_id.clone();
                                            let actor = principal_id.clone();
                                            move |_| {
                                                let title = new_card_title().trim().to_owned();
                                                if title.is_empty() {
                                                    return;
                                                }
                                                let Some(board_space_id) = selected_board() else {
                                                    board_status.set("select or create a Board Space before adding cards".to_owned());
                                                    return;
                                                };
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
                                                // The create command appends the `ak.strand.create`
                                                // op (write_state queued), which the `columns` memo
                                                // folds over the current baseline. `rank` and the
                                                // two Space ids ride the row's holder-local
                                                // `effect` only: they are the optimistic overlay's
                                                // placement and the input to the follow-up Move,
                                                // never members of the create payload.
                                                // No `strand_id` here: the card Strand is named by
                                                // its own create Event, so the command boundary
                                                // fills the subject in once the envelope exists.
                                                let command = KanbanCardCreateCommand {
                                                    board_space_id: board_space_id.to_string(),
                                                    list_space_id: col_id.clone(),
                                                    title,
                                                    rank,
                                                };
                                                submit_kanban_card_create(
                                                    base.clone(),
                                                    token,
                                                    realm.clone(),
                                                    actor.clone(),
                                                    command,
                                                    selected_scope_security_encrypted,
                                                    state_store,
                                                    board_status,
                                                );
                                                // Continuous-create (design/kanban-baseline.md M1):
                                                // keep the composer open and clear the field so the
                                                // user can add several cards without re-opening it.
                                                // The textarea stays mounted, so focus is retained;
                                                // the ✕ cancel button closes it explicitly.
                                                new_card_title.set(String::new());
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
                                    // A pending List has no protocol id yet, so it
                                    // cannot be a card's `list_space_id`; the action
                                    // unlocks when the receipt commits the Space id.
                                    disabled: arkret_sdk::SpaceId::new(column.id.as_str()).is_err(),
                                    title: if arkret_sdk::SpaceId::new(column.id.as_str()).is_ok() {
                                        "Add a card to this list"
                                    } else {
                                        "Waiting for the list to be accepted"
                                    },
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
                            let title_text = "Archive this list (ak.space.archive)".to_owned();
                            rsx! {
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    class: "kanban-inline-action",
                                    "data-testid": "list-archive-button",
                                    "data-space-container-id": "{column.id}",
                                    "data-cap-gate": "open",
                                    title: title_text,
                                    onclick: {
                                        // Archiving a list hides all of its cards
                                        // from the board grid, so route the click
                                        // through the co`ak.space.archive instead
                                        // of submitting `ak.space.archive` directly.
                                        let space_container_id = column.id.clone();
                                        let list_title = column.title.clone();
                                        let active_card_count = column
                                            .cards
                                            .iter()
                                            .filter(|card| {
                                                card.lifecycle == StrandLifecycleState::Active
                                            })
                                            .count();
                                        move |_| {
                                            list_archive_confirm.set(Some((
                                                space_container_id.clone(),
                                                list_title.clone(),
                                                active_card_count,
                                            )));
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

            // Keep malformed or incomplete lifecycle data out of normal
            // active/archived surfaces until a complete current value arrives.
            {
                let lifecycle_issues = columns()
                    .iter()
                    .flat_map(|column| column.cards.iter())
                    .filter(|card| card.lifecycle == StrandLifecycleState::Unavailable)
                    .cloned()
                    .collect::<Vec<_>>();
                rsx! {
                    if !lifecycle_issues.is_empty() {
                        details {
                            class: "event board-maintenance",
                            "data-testid": "kanban-lifecycle-unavailable",
                            open: true,
                            summary {
                                span { "Lifecycle unavailable" }
                                span { "{lifecycle_issues.len()} card(s)" }
                            }
                            for card in lifecycle_issues.iter() {
                                div {
                                    key: "{card.id}",
                                    class: "event",
                                    "data-testid": "kanban-lifecycle-unavailable-row",
                                    div { class: "event-head",
                                        span { class: "entity-title", "{card.title}" }
                                        span { "Canonical lifecycle state is unavailable" }
                                    }
                                    div { class: "muted", "Refresh to retry." }
                                }
                            }
                        }
                    }
                }
            }

            // Keep cards with malformed or incomplete position data outside
            // the Board grid until a complete current value arrives.
            {
                let cols = columns();
                let unavailable = cols
                    .iter()
                    .find(|column| {
                        column.state == SpaceContainerLifecycleState::PositionUnavailable
                    })
                    .map(|column| {
                        column
                            .cards
                            .iter()
                            .filter(|card| card.lifecycle == StrandLifecycleState::Active)
                            .cloned()
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                rsx! {
                    if !unavailable.is_empty() {
                        details {
                            class: "event board-maintenance",
                            "data-testid": "kanban-position-unavailable",
                            open: true,
                            summary {
                                span { "Position unavailable" }
                                span { "{unavailable.len()} card(s)" }
                            }
                            for card in unavailable.iter() {
                                div {
                                    key: "{card.id}",
                                    class: "event",
                                    "data-testid": "kanban-position-unavailable-row",
                                    div { class: "event-head",
                                        span { class: "entity-title", "{card.title}" }
                                        span { "Canonical position is unavailable" }
                                    }
                                    div { class: "muted", "Refresh to retry." }
                                }
                            }
                        }
                    }
                }
            }

            {
                let unresolved: Vec<KanbanColumn> = columns()
                    .iter()
                    .filter(|column| column.state == SpaceContainerLifecycleState::Unavailable)
                    .cloned()
                    .collect();
                if !unresolved.is_empty() {
                    rsx! {
                        details { class: "event board-maintenance", open: true, "data-testid": "kanban-space-conflicts",
                            summary { "Unavailable list state ({unresolved.len()})" }
                            for column in unresolved {
                                div { key: "space-unavailable-{column.id}", class: "event",
                                    div { class: "event-head",
                                        span { class: "entity-title", "{column.id}" }
                                        span { "Canonical Space state is unavailable; refresh to retry." }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    rsx! {}
                }
            }

            // Archived lists panel — c`ak.space.archivefecycle `archived` state.
            // Lists appear here after `ak.space.archive` is accepted and
            // are removed from the main boar`ak.space.restoreh row carries
            // a Restore button that submits `ak.space.restore` (SDK reducer
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
                                div { key: "{column.id}", class: "event", "data-testid": "kanban-archived-list-row",
                                    div { class: "event-head",
                                        span { class: "entity-title", "{column.title}" }
                                        span { "rank {column.rank} / {column.cards.len()} card(s)" }
                                        {
                                            let title_text = "Restore this list (ak.space.restore)".to_owned();
                                            rsx! {
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    "data-testid": "list-restore-button",
                                                    "data-space-container-id": "{column.id}",
                                                    "data-cap-gate": "open",
                                                    title: title_text,
                                                    onclick: {
                                                        let base = base_url.clone();
                                                        let realm = selected_realm_id.clone();
                                                        let actor = principal_id.clone();
                                                        let space_container_id = column.id.clone();
                                                        move |_| {
                                                            dispatch_space_container_lifecycle(
                                                                base.clone(),
                                                                token,
                                                                realm.clone(),
                                                                actor.clone(),
                                                                space_container_id.clone(),
                                                                SpaceContainerLifecycleState::Active,
                                                                state_store,
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

            // Archived cards drawer — `ak.strand.archivearchived` state.
            // Cards appear here after `ak.strand.archive` is accepted and
            // are removed from the column above. Each row carries the
            // column t`ak.strand.restoree from) + a Restore button that
            // submits `ak.strand.restore` (SDK reducer enforces
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
                            for row in archived_cards.iter().filter(|row| current_card_ids.iter().any(|id| id.as_str() == row.card.id)) {
                                div { key: "{row.card.id}", class: "event", "data-testid": "kanban-archived-card-row",
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
                                            let title_text = "Restore this card (ak.strand.restore)".to_owned();
                                            rsx! {
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    "data-testid": "card-restore-button",
                                                    "data-strand-id": "{row.card.id}",
                                                    "data-cap-gate": "open",
                                                    title: title_text,
                                                    onclick: {
                                                        let base = base_url.clone();
                                                        let realm = selected_realm_id.clone();
                                                        let actor = principal_id.clone();
                                                        let strand_id = row.card.id.clone();
                                                        let lifecycle_basis_refs =
                                                            row.card.lifecycle_basis_refs.clone();
                                                        move |_| {
                                                            dispatch_strand_lifecycle(
                                                                base.clone(),
                                                                token,
                                                                realm.clone(),
                                                                actor.clone(),
                                                                strand_id.clone(),
                                                                StrandLifecycleState::Active,
                                                                lifecycle_basis_refs.clone(),
                                                                state_store,
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

            // Board-archive confirmation dialog. Same DismissiblePopup modal
            // pattern as the realm-admin danger zone: the destructive cascade
            // only fires from the explicit confirm button below.
            if archive_board_confirm_open() {
                {
                    // Impact preview mirrors `dispatch_board_archive_cascade`,
                    // which archives every active card and active list before
                    // archiving the board Space itself.
                    let cols = columns();
                    let active_list_count = cols
                        .iter()
                        .filter(|col| col.state == SpaceContainerLifecycleState::Active)
                        .count();
                    let active_card_count = cols
                        .iter()
                        .flat_map(|col| col.cards.iter())
                        .filter(|card| card.lifecycle == StrandLifecycleState::Active)
                        .count();
                    let scope_line = crate::i18n::tr("kanban.archive_board_confirm_scope")
                        .replace("{lists}", &active_list_count.to_string())
                        .replace("{cards}", &active_card_count.to_string());
                    rsx! {
                        crate::components::DismissiblePopup {
                            overlay_class: "modal-backdrop",
                            surface_class: "modal danger-confirm-modal",
                            overlay_test_id: Some("archive-board-confirm-modal".to_owned()),
                            surface_test_id: Some("archive-board-confirm-dialog".to_owned()),
                            aria_label: crate::i18n::tr("kanban.archive_board_confirm_title"),
                            on_dismiss: move |_| archive_board_confirm_open.set(false),
                            div { class: "modal-head",
                                h3 { {crate::i18n::tr("kanban.archive_board_confirm_title")} }
                            }
                            div { class: "modal-body workflow-form",
                                div { class: "callout danger", "data-testid": "archive-board-confirm-impact",
                                    p { "{scope_line}" }
                                    p { {crate::i18n::tr("kanban.archive_board_confirm_recover")} }
                                }
                            }
                            div { class: "modal-foot",
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "archive-board-cancel-button",
                                    onclick: move |_| archive_board_confirm_open.set(false),
                                    {crate::i18n::tr("kanban.archive_board_confirm_cancel")}
                                }
                                Button {
                                    variant: ButtonVariant::Destructive,
                                    "data-testid": "archive-board-confirm-button",
                                    onclick: {
                                        // Confirmed end-of-week bulk archive:
                                        // cascade-archive every active card +
                                        // list, then the board Space itself
                                        // (client-driven cascade; v1 has no
                                        // server Space->Strand cascade).
                                        let base = base_url.clone();
                                        let realm = selected_realm_id.clone();
                                        let actor = principal_id.clone();
                                        move |_| {
                                            archive_board_confirm_open.set(false);
                                            dispatch_board_archive_cascade(
                                                base.clone(),
                                                token,
                                                realm.clone(),
                                                actor.clone(),
                                                selected_board()
                                                    .map(|board_id| board_id.to_string())
                                                    .unwrap_or_default(),
                                                columns(),
                                                state_store,
                                                board_status,
                                            );
                                        }
                                    },
                                    {crate::i18n::tr("kanban.archive_board_confirm_confirm")}
                                }
                            }
                        }
                    }
                }
            }

            // List-archive confirmation dialog (lighter single-step variant of
            // the board dialog above). Archiving a list hides its cards from
            // the board grid until the list is restored, so it warrants a
            // confirmation even though it is reversible.
            if let Some((confirm_list_id, confirm_list_title, confirm_card_count)) =
                list_archive_confirm()
            {
                {
                    let body_line = crate::i18n::tr("kanban.archive_list_confirm_body")
                        .replace("{title}", &confirm_list_title)
                        .replace("{cards}", &confirm_card_count.to_string());
                    rsx! {
                        crate::components::DismissiblePopup {
                            overlay_class: "modal-backdrop",
                            surface_class: "modal danger-confirm-modal",
                            overlay_test_id: Some("list-archive-confirm-modal".to_owned()),
                            surface_test_id: Some("list-archive-confirm-dialog".to_owned()),
                            aria_label: crate::i18n::tr("kanban.archive_list_confirm_title"),
                            on_dismiss: move |_| list_archive_confirm.set(None),
                            div { class: "modal-head",
                                h3 { {crate::i18n::tr("kanban.archive_list_confirm_title")} }
                            }
                            div { class: "modal-body workflow-form",
                                p { "data-testid": "list-archive-confirm-impact", "{body_line}" }
                            }
                            div { class: "modal-foot",
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "list-archive-cancel-button",
                                    onclick: move |_| list_archive_confirm.set(None),
                                    {crate::i18n::tr("kanban.archive_list_confirm_cancel")}
                                }
                                Button {
                                    variant: ButtonVariant::Destructive,
                                    "data-testid": "list-archive-confirm-button",
                                    onclick: {
                                        let base = base_url.clone();
                                        let realm = selected_realm_id.clone();
                                        let actor = principal_id.clone();
                                        let space_container_id = confirm_list_id.clone();
                                        move |_| {
                                            list_archive_confirm.set(None);
                                            dispatch_space_container_lifecycle(
                                                base.clone(),
                                                token,
                                                realm.clone(),
                                                actor.clone(),
                                                space_container_id.clone(),
                                                SpaceContainerLifecycleState::Archived,
                                                state_store,
                                                board_status,
                                            );
                                        }
                                    },
                                    {crate::i18n::tr("kanban.archive_list_confirm_confirm")}
                                }
                            }
                        }
                    }
                }
            }

            CardDetail {
                controller,
                context: CardDetailContext {
                    base_url: base_url.clone(),
                    plaintext_service_id: plaintext_service_id.clone(),
                    principal_id: principal_core_id.clone(),
                    account_primary_handle: account_primary_handle(),
                    device_id: device_id.clone(),
                    selected_realm_id: selected_realm_id.clone(),
                    projection_realm_id: projection_realm_id.clone(),
                    token,
                    sync_cursor,
                    frontier_state,
                    realm_live_epoch,
                    synthesis_entries: synthesis_entries_memo,
                    selected_scope_security_encrypted,
                    selected_scope_security_encrypted_or_secure,
                    projected_strand_ids: projected_strand_ids.clone(),
                }
            }
        }
    }
}

mod assignment;
mod board_select;
mod card_detail;
mod card_patch;
mod members;
mod mls_encrypt;
mod plaintext_guard;

use assignment::*;
use board_select::*;
use card_detail::*;
use card_patch::*;
use members::*;
use mls_encrypt::*;
use plaintext_guard::*;

#[cfg(test)]
mod tests;
