//! `ak.space.create` form + Space lifecycle actions section component.

use arkret_sdk::events::EventKind;
use arkret_wire::SchemaId;
use dioxus::prelude::*;
use serde_json::Value;

use super::data::SPACE_KIND_OPTIONS;
use crate::i18n::tr;
use crate::models::{RealmTreeNode, RealmTreeNodeKind};
use crate::transport::auth::authed_api;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::select::{Select, SelectOption};
use crate::ui::textarea::Textarea;
use crate::views::helpers::short_protocol_id;

/// Space lifecycle status templates resolved before the submit tasks are
/// spawned — same constraint as `realms::BootstrapProgressStrings`: `tr()`
/// needs Dioxus context, which a spawned task does not have.
#[derive(Clone)]
struct SpaceStatusStrings {
    created: String,
    archived: String,
    restored: String,
    tombstoned: String,
    create_failed: String,
    archive_failed: String,
    restore_failed: String,
    tombstone_failed: String,
    invalid_base_url: String,
}

impl SpaceStatusStrings {
    fn resolve() -> Self {
        Self {
            created: tr("setup.space.state.created"),
            archived: tr("setup.space.state.archived"),
            restored: tr("setup.space.state.restored"),
            tombstoned: tr("setup.space.state.tombstoned"),
            create_failed: tr("setup.space.error.create_failed"),
            archive_failed: tr("setup.space.error.archive_failed"),
            restore_failed: tr("setup.space.error.restore_failed"),
            tombstone_failed: tr("setup.space.error.tombstone_failed"),
            invalid_base_url: tr("setup.space.error.invalid_base_url"),
        }
    }

    fn fill(template: &str, args: &[(&'static str, String)]) -> String {
        crate::i18n::substitute_args(template.to_owned(), args)
    }
}

#[component]
pub(super) fn NewSpaceSection(
    token: Signal<String>,
    selected_realm_id: Signal<String>,
    realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    new_space_context_node: Signal<String>,
    // State signals are owned by the parent `SetupPanel` so the draft Space
    // survives switching between setup sections (the sections are
    // conditionally rendered, so locally-owned hooks would reset on every
    // section change).
    mut new_space_realm_id: Signal<String>,
    mut new_space_title: Signal<String>,
    mut new_space_summary: Signal<String>,
    mut new_space_kind: Signal<String>,
    mut new_space_parent_id: Signal<String>,
    mut new_space_default_realm_id: Signal<String>,
    mut new_space_context_seen: Signal<String>,
    mut new_space_state: Signal<String>,
    mut new_space_created_id: Signal<String>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let session_context = crate::app::SessionContext::get();
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state_store = session_context.state_store;
    let principal_did = session_context
        .active_account()
        .map(|account| account.did().to_string())
        .unwrap_or_default();
    let principal_did_for_create = principal_did.clone();
    let principal_did_for_archive = principal_did.clone();
    let principal_did_for_restore = principal_did.clone();
    let principal_did_for_tombstone = principal_did;
    let has_session = !token().trim().is_empty();
    let draft_state_label = tr("setup.state.draft");
    let status_strings = SpaceStatusStrings::resolve();

    let new_space_kind_selected = use_memo(move || Some(new_space_kind()));
    let new_space_parent_id_selected = use_memo(move || Some(new_space_parent_id()));
    let new_space_default_realm_id_selected = use_memo(move || Some(new_space_default_realm_id()));

    // M-UX-CONTEXT-1: the sidebar's per-row "+" action sets
    // `new_space_context_node` to the clicked Realm / Space and routes
    // to the NewSpace section. The form no longer exposes a Realm
    // picker, so every explicit sidebar context change must update the
    // hidden realm_id / parent_space_id used by submission.
    {
        let selected_context = new_space_context_node();
        let selected_context = selected_context.trim().to_owned();
        let selected_fallback = selected_realm_id();
        let selected_fallback = selected_fallback.trim().to_owned();
        let context_key = if selected_context.is_empty() {
            selected_fallback.clone()
        } else {
            selected_context.clone()
        };
        if !context_key.is_empty() && new_space_context_seen() != context_key {
            if let Some(node) = realm_tree_nodes()
                .into_iter()
                .find(|node| node.id == context_key)
            {
                new_space_context_seen.set(context_key);
                new_space_created_id.set(String::new());
                new_space_state.set(draft_state_label.clone());

                match node.kind {
                    RealmTreeNodeKind::Realm => {
                        new_space_realm_id.set(node.id);
                        new_space_parent_id.set(String::new());
                    }
                    RealmTreeNodeKind::Space => {
                        new_space_realm_id.set(node.projection_realm_id().to_owned());
                        new_space_parent_id.set(node.id);
                    }
                }
            } else if let Some(body) = state_store
                .read()
                .load()
                .realm_tree_projections
                .get(&context_key)
                .cloned()
            {
                new_space_context_seen.set(context_key.clone());
                new_space_created_id.set(String::new());
                new_space_state.set(draft_state_label.clone());

                let kind = match body
                    .get("__kind")
                    .and_then(|kind| kind.as_str())
                    .or_else(|| body.get("schema").and_then(|schema| schema.as_str()))
                {
                    Some("space") | Some(SchemaId::SPACE_V1) => "space",
                    _ => "realm",
                };
                if kind == "realm" {
                    new_space_realm_id.set(context_key);
                    new_space_parent_id.set(String::new());
                } else {
                    // For a Space row, the new child lives in the
                    // same home Realm; the clicked Space becomes
                    // the parent.
                    let realm = body
                        .get("realm_id")
                        .and_then(|realm| realm.as_str())
                        .unwrap_or(&selected_fallback)
                        .to_owned();
                    new_space_realm_id.set(realm);
                    new_space_parent_id.set(context_key);
                }
            } else if context_key.starts_with("ak:realm:") {
                new_space_context_seen.set(context_key.clone());
                new_space_created_id.set(String::new());
                new_space_state.set(draft_state_label.clone());
                new_space_realm_id.set(context_key);
                new_space_parent_id.set(String::new());
            } else if context_key.starts_with("ak:space:") && !selected_fallback.is_empty() {
                new_space_context_seen.set(context_key.clone());
                new_space_created_id.set(String::new());
                new_space_state.set(draft_state_label.clone());
                new_space_realm_id.set(selected_fallback);
                new_space_parent_id.set(context_key);
            }
        }
    }

    let new_space_realm_id_value = new_space_realm_id();
    let new_space_title_value = new_space_title();
    let new_space_summary_value = new_space_summary();
    let new_space_kind_value = new_space_kind();
    let _new_space_parent_id_value = new_space_parent_id();
    let _new_space_default_realm_id_value = new_space_default_realm_id();
    let new_space_state_value = new_space_state();
    let new_space_created_id_value = new_space_created_id();
    let new_space_created_id_label = short_protocol_id(&new_space_created_id_value);
    // Every persisted projection is either a Realm or a Space; the
    // tag is recorded under `__kind` ("realm" | "space") when we
    // save it.
    let projections_snapshot: Vec<(String, Value)> = state_store
        .read()
        .load()
        .realm_tree_projections
        .iter()
        .map(|(id, body)| (id.clone(), body.clone()))
        .collect();
    let projection_kind = |body: &Value| -> &'static str {
        match body
            .get("__kind")
            .and_then(|kind| kind.as_str())
            .or_else(|| body.get("schema").and_then(|schema| schema.as_str()))
        {
            Some("space") | Some(SchemaId::SPACE_V1) => "space",
            _ => "realm",
        }
    };
    let projection_realm_id = |id: &str, body: &Value| -> String {
        body.get("realm_id")
            .and_then(|realm_id| realm_id.as_str())
            .or_else(|| {
                body.get("summary")
                    .and_then(|summary| summary.get("realm_id"))
                    .and_then(|realm_id| realm_id.as_str())
            })
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| id.to_owned())
    };
    let projection_title =
        |id: &str, body: &Value| -> String { crate::realm_tree::projection_title(id, body) };
    let available_realms: Vec<(String, String)> = projections_snapshot
        .iter()
        .filter(|(_, body)| projection_kind(body) == "realm")
        .map(|(id, body)| (id.clone(), projection_title(id, body)))
        .collect();
    // Parent picker = every Space already inside the selected Realm,
    // plus a "(root)" sentinel. Realms themselves can't be parents
    // per spec §2.1 (Realms don't have parent/child).
    let parent_candidates: Vec<(String, String)> = projections_snapshot
        .iter()
        .filter(|(_, body)| {
            projection_kind(body) == "space"
                && projection_realm_id("", body) == new_space_realm_id_value
        })
        .map(|(id, body)| (id.clone(), projection_title(id, body)))
        .collect();
    let new_space_ready =
        !new_space_title_value.trim().is_empty() && !new_space_realm_id_value.trim().is_empty();
    let new_space_can_submit = has_session && new_space_ready;

    rsx! {
        div { class: "setup-shell new-space-shell", "data-testid": "space-create-strand",
            div { class: "setup-column",
                div { class: "event",
                    div { class: "workflow-form setup-form-grid",
                        div { class: "setup-field",
                            Label {
                                html_for: "new-space-title-input-input",
                                {tr("setup.space.field.title")}
                                span { class: "required-indicator", "aria-hidden": "true", " *" }
                            }
                            Input {
                                id: "new-space-title-input-input",
                                "data-testid": "new-space-title-input",
                                required: true,
                                "aria-required": "true",
                                value: "{new_space_title_value}",
                                placeholder: tr("setup.space.field.title_placeholder"),
                                oninput: move |event: FormEvent| new_space_title.set(event.value())
                            }
                        }
                        div { class: "setup-field",
                            label { {tr("setup.space.field.kind")} }
                            Select::<String> {
                                "data-testid": "new-space-kind-input",
                                value: Some(new_space_kind_selected.into()),
                                on_value_change: move |v: Option<String>| {
                                    if let Some(v) = v {
                                        new_space_kind.set(v);
                                    }
                                },
                                for (i, (option_value, label_key, _)) in SPACE_KIND_OPTIONS.iter().enumerate() {
                                    SelectOption::<String> {
                                        index: i,
                                        value: option_value.to_string(),
                                        text_value: tr(label_key),
                                        {tr(label_key)}
                                    }
                                }
                            }
                            if let Some(kind_hint) = SPACE_KIND_OPTIONS
                                .iter()
                                .find(|(value, _, _)| *value == new_space_kind_value)
                                .map(|(_, _, hint_key)| tr(hint_key))
                                .filter(|hint| !hint.is_empty())
                            {
                                div { class: "muted", "{kind_hint}" }
                            }
                        }
                        div { class: "setup-field setup-field-span-2",
                            Label { html_for: "new-space-summary-input-input", {tr("setup.field.summary")} }
                            Textarea {
                                id: "new-space-summary-input-input",
                                "data-testid": "new-space-summary-input",
                                value: "{new_space_summary_value}",
                                rows: "3",
                                placeholder: tr("setup.space.field.summary_placeholder"),
                                oninput: move |event: FormEvent| new_space_summary.set(event.value())
                            }
                        }
                        // Spec realm-and-space.md §3.2 — optional
                        // parent. Picker is filtered by realm_id
                        // (Realms aren't valid parents per §2.1;
                        // cross-Realm parents are valid but live
                        // under `default_realm_id`).
                        div { class: "setup-field setup-field-span-2",
                            label { {tr("setup.space.field.parent")} }
                            if new_space_realm_id_value.trim().is_empty() {
                                div { class: "muted", {tr("setup.space.parent.no_realm")} }
                            } else if parent_candidates.is_empty() {
                                div { class: "muted", {tr("setup.space.parent.no_siblings")} }
                            } else {
                                Select::<String> {
                                    "data-testid": "new-space-parent-input",
                                    value: Some(new_space_parent_id_selected.into()),
                                    on_value_change: move |v: Option<String>| {
                                        if let Some(v) = v {
                                            new_space_parent_id.set(v);
                                        }
                                    },
                                    SelectOption::<String> {
                                        index: 0usize,
                                        value: "".to_string(),
                                        text_value: tr("setup.space.parent.root"),
                                        {tr("setup.space.parent.root")}
                                    }
                                    for (i, (id, title)) in parent_candidates.iter().enumerate() {
                                        {
                                            let id_label = short_protocol_id(id);
                                            rsx! {
                                                SelectOption::<String> {
                                                    index: i + 1,
                                                    value: id.to_string(),
                                                    text_value: "{title} ({id_label})",
                                                    "{title} ({id_label})"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Spec realm-and-space.md §3.2 — `default_realm_id`
                    // points new resources created from this Space at
                    // a different Realm. Most users leave this empty
                    // (= inherit home Realm). Folded as advanced.
                    details { class: "setup-advanced",
                        "data-testid": "new-space-advanced",
                        summary { class: "setup-advanced-summary",
                            {tr("setup.space.advanced_summary")}
                        }
                        div { class: "workflow-form setup-form-grid",
                            div { class: "setup-field setup-field-span-2",
                                label { {tr("setup.space.default_realm.label")} }
                                if available_realms.is_empty() {
                                    div { class: "muted", {tr("setup.space.default_realm.empty")} }
                                } else {
                                    Select::<String> {
                                        "data-testid": "new-space-default-realm-ref-input",
                                        value: Some(new_space_default_realm_id_selected.into()),
                                        on_value_change: move |v: Option<String>| {
                                            if let Some(v) = v {
                                                new_space_default_realm_id.set(v);
                                            }
                                        },
                                        SelectOption::<String> {
                                            index: 0usize,
                                            value: "".to_string(),
                                            text_value: tr("setup.space.default_realm.inherit"),
                                            {tr("setup.space.default_realm.inherit")}
                                        }
                                        for (i, (id, title)) in available_realms.iter().enumerate() {
                                            {
                                                let id_label = short_protocol_id(id);
                                                rsx! {
                                                    SelectOption::<String> {
                                                        index: i + 1,
                                                        value: id.to_string(),
                                                        text_value: "{title} ({id_label})",
                                                        "{title} ({id_label})"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                div { class: "muted",
                                    {tr("setup.space.default_realm.hint")}
                                }
                            }
                        }
                    }
                    div { class: "actions setup-nav-actions",
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "new-space-submit-button",
                            disabled: !new_space_can_submit,
                            onclick: {
                                let base_url = base_url.clone();
                                let strings = status_strings.clone();
                                move |_| {
                                let strings = strings.clone();
                                let api_token = token();
                                let base = base_url.clone();
                                let realm_id = new_space_realm_id();
                                let title = new_space_title();
                                let summary = new_space_summary();
                                let kind = new_space_kind();
                                let parent_id = new_space_parent_id();
                                let default_realm_id = new_space_default_realm_id();
                                let actor = principal_did_for_create.clone();
                                new_space_state.set(tr("setup.space.state.submitting_create"));
                                spawn(async move {
                                    match authed_api(&base, api_token).and_then(|api| api.event_submitter()) {
                                        Ok(submitter) => {
                                            let summary_opt = if summary.trim().is_empty() {
                                                None
                                            } else {
                                                Some(summary.as_str())
                                            };
                                            let parent_opt = if parent_id.trim().is_empty() {
                                                None
                                            } else {
                                                Some(parent_id.as_str())
                                            };
                                            let default_realm_opt = if default_realm_id.trim().is_empty() {
                                                None
                                            } else {
                                                Some(default_realm_id.as_str())
                                            };
                                            match crate::transport::realm_write::create_space_under_realm(
                                                &submitter,
                                                &realm_id,
                                                &actor,
                                                &title,
                                                summary_opt,
                                                &kind,
                                                parent_opt,
                                                default_realm_opt,
                                            ).await {
                                                Ok(space) => {
                                                    // Persist a tagged Space projection so
                                                    // the sidebar (M-SIDEBAR-TIER-1) can
                                                    // classify it without re-fetching.
                                                    // `__kind` is inkson-local metadata —
                                                    // server-projected entries use the
                                                    // canonical `schema` field, but for the
                                                    // optimistic local write here we use the
                                                    // simpler marker.
                                                    let projection_body =
                                                        crate::realm_tree::OptimisticRealmTreeProjection::space(
                                                            crate::realm_tree::SpaceProjectionInput {
                                                                realm_id: realm_id.clone(),
                                                                kind: kind.clone(),
                                                                title: title.clone(),
                                                                summary: summary.clone(),
                                                                parent_space_id: parent_opt.map(str::to_owned),
                                                                default_realm_id: default_realm_opt.map(str::to_owned),
                                                            },
                                                        )
                                                        .into_value();
                                                    state_store.write().save_realm_tree_projection(
                                                        space.space_id.clone(),
                                                        projection_body,
                                                    );
                                                    new_space_created_id.set(space.space_id.clone());
                                                    new_space_state.set(SpaceStatusStrings::fill(
                                                        &strings.created,
                                                        &[
                                                            ("id", space.space_id.clone()),
                                                            ("kind", kind.clone()),
                                                            ("realm", realm_id.clone()),
                                                            (
                                                                "parent",
                                                                parent_opt
                                                                    .map(|p| format!(" under {p}"))
                                                                    .unwrap_or_default(),
                                                            ),
                                                        ],
                                                    ));
                                                }
                                                Err(error) => {
                                                    new_space_state.set(SpaceStatusStrings::fill(
                                                        &strings.create_failed,
                                                        &[("error", error.to_string())],
                                                    ));
                                                }
                                            }
                                        }
                                        Err(error) => {
                                            new_space_state.set(SpaceStatusStrings::fill(
                                                &strings.invalid_base_url,
                                                &[("error", error.to_string())],
                                            ));
                                        }
                                    }
                                });
                                }
                            },
                            {tr("setup.space.action.create")}
                        }
                    }
                }
            }

            div { class: "setup-column setup-summary-column",
                div { class: "event new-space-summary",
                    div { class: "event-head",
                        span { {tr("setup.space.outcome")} }
                        span { {tr("setup.space.outcome.hint")} }
                    }
                    div { class: "setup-summary-row",
                        strong { {tr("setup.space.created")} }
                        span { class: "mono", "data-testid": "new-space-created-id",
                            if !new_space_created_id_value.trim().is_empty() {
                                "{new_space_created_id_label}"
                            } else {
                                {tr("setup.space.not_created")}
                            }
                        }
                    }
                    div { class: "setup-summary-row setup-summary-row-stack",
                        strong { {tr("setup.space.status")} }
                        span { class: "muted", "{new_space_state_value}" }
                    }
                    div { class: "setup-summary-row setup-summary-row-stack",
                        strong { {tr("setup.space.wire_shape")} }
                        span { class: "muted",
                            {tr("setup.space.wire_shape.body")}
                        }
                    }
                }

                // Spec realm-and-space.md §3.4 — Space lifecycle
                // (archive / restore / tombstone). Disabled
                // until a Space has been created in this session;
                // server enforces the state-machine transitions.
                div { class: "event",
                    "data-testid": "space-lifecycle-panel",
                    div { class: "event-head",
                        span { {tr("setup.space.lifecycle")} }
                        span { {tr("setup.space.lifecycle.hint")} }
                    }
                    if new_space_created_id_value.trim().is_empty() {
                        div { class: "muted",
                            {tr("setup.space.lifecycle.empty")}
                        }
                    } else {
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "space-lifecycle-archive",
                                title: tr("setup.space.action.archive.title"),
                                onclick: {
                                    let base = base_url.clone();
                                    let strings = status_strings.clone();
                                    move |_| {
                                        let strings = strings.clone();
                                        let api_token = token();
                                        let base = base.clone();
                                        let actor = principal_did_for_archive.clone();
                                        let space_id = new_space_created_id();
                                        let realm_id = new_space_realm_id();
                                        new_space_state.set(tr("setup.space.state.submitting_archive"));
                                        spawn(async move {
                                            match authed_api(&base, api_token).and_then(|api| api.event_submitter()) {
                                                Ok(submitter) => match crate::transport::realm_write::change_space_lifecycle(
                                                    &submitter, &space_id, &realm_id, &actor, EventKind::SpaceArchive,
                                                ).await {
                                                    Ok(()) => new_space_state.set(SpaceStatusStrings::fill(
                                                        &strings.archived,
                                                        &[("id", short_protocol_id(&space_id))],
                                                    )),
                                                    Err(error) => new_space_state.set(SpaceStatusStrings::fill(
                                                        &strings.archive_failed,
                                                        &[("error", error.to_string())],
                                                    )),
                                                },
                                                Err(error) => new_space_state.set(SpaceStatusStrings::fill(
                                                    &strings.invalid_base_url,
                                                    &[("error", error.to_string())],
                                                )),
                                            }
                                        });
                                    }
                                },
                                {tr("setup.space.action.archive")}
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "space-lifecycle-restore",
                                title: tr("setup.space.action.restore.title"),
                                onclick: {
                                    let base = base_url.clone();
                                    let strings = status_strings.clone();
                                    move |_| {
                                        let strings = strings.clone();
                                        let api_token = token();
                                        let base = base.clone();
                                        let actor = principal_did_for_restore.clone();
                                        let space_id = new_space_created_id();
                                        let realm_id = new_space_realm_id();
                                        new_space_state.set(tr("setup.space.state.submitting_restore"));
                                        spawn(async move {
                                            match authed_api(&base, api_token).and_then(|api| api.event_submitter()) {
                                                Ok(submitter) => match crate::transport::realm_write::change_space_lifecycle(
                                                    &submitter, &space_id, &realm_id, &actor, EventKind::SpaceRestore,
                                                ).await {
                                                    Ok(()) => new_space_state.set(SpaceStatusStrings::fill(
                                                        &strings.restored,
                                                        &[("id", short_protocol_id(&space_id))],
                                                    )),
                                                    Err(error) => new_space_state.set(SpaceStatusStrings::fill(
                                                        &strings.restore_failed,
                                                        &[("error", error.to_string())],
                                                    )),
                                                },
                                                Err(error) => new_space_state.set(SpaceStatusStrings::fill(
                                                    &strings.invalid_base_url,
                                                    &[("error", error.to_string())],
                                                )),
                                            }
                                        });
                                    }
                                },
                                {tr("setup.space.action.restore")}
                            }
                            Button {
                                variant: ButtonVariant::Destructive,
                                "data-testid": "space-lifecycle-tombstone",
                                title: tr("setup.space.action.tombstone.title"),
                                onclick: {
                                    let base = base_url.clone();
                                    let strings = status_strings.clone();
                                    move |_| {
                                        let strings = strings.clone();
                                        let api_token = token();
                                        let base = base.clone();
                                        let actor = principal_did_for_tombstone.clone();
                                        let space_id = new_space_created_id();
                                        let realm_id = new_space_realm_id();
                                        new_space_state.set(tr("setup.space.state.submitting_tombstone"));
                                        spawn(async move {
                                            match authed_api(&base, api_token).and_then(|api| api.event_submitter()) {
                                                Ok(submitter) => match crate::transport::realm_write::change_space_lifecycle(
                                                    &submitter, &space_id, &realm_id, &actor, EventKind::SpaceTombstone,
                                                ).await {
                                                    Ok(()) => new_space_state.set(SpaceStatusStrings::fill(
                                                        &strings.tombstoned,
                                                        &[("id", short_protocol_id(&space_id))],
                                                    )),
                                                    Err(error) => new_space_state.set(SpaceStatusStrings::fill(
                                                        &strings.tombstone_failed,
                                                        &[("error", error.to_string())],
                                                    )),
                                                },
                                                Err(error) => new_space_state.set(SpaceStatusStrings::fill(
                                                    &strings.invalid_base_url,
                                                    &[("error", error.to_string())],
                                                )),
                                            }
                                        });
                                    }
                                },
                                {tr("setup.space.action.tombstone")}
                            }
                        }
                        div { class: "muted",
                            {tr("setup.space.tombstone_warning")}
                        }
                    }
                }
            }
        }
    }
}
