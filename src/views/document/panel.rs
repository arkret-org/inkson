use dioxus::prelude::*;
use serde_json::Value;

use super::model::{
    BlockKind, DocumentBlock, DocumentCommentReply, DocumentCommentThread, DocumentVersion,
    RemoteCursor, SyncState,
};
use super::projection::{
    blocks_from_document_body, build_version_diff, comments_from_projection,
    cursors_from_projection, document_body_payload, document_collaboration_enabled, load_draft,
    mint_morph_id, morph_id_storage_key, parse_comment_range, restore_status_label, save_draft,
    versions_from_projection,
};
use crate::local_state::LocalStateStore;
use crate::operation::ck_ops;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::dialog::Dialog;
use crate::ui::input::Input;
use crate::ui::textarea::Textarea;
use crate::views::helpers::{display_name_for_did, short_protocol_id, with_authed_api};

#[component]
pub fn DocumentPanel(
    base_url: String,
    token: Signal<String>,
    selected_realm_id: String,
    document_ref: Option<String>,
    state_store: Signal<LocalStateStore>,
    account_did: String,
) -> Element {
    let realm_id = selected_realm_id.clone();
    let actor_key = account_did.clone();
    let initial = load_draft(&state_store, &actor_key, &realm_id);
    let initial_title = initial
        .blocks
        .iter()
        .find(|block| block.kind == BlockKind::Heading)
        .map(|block| block.content.clone())
        .unwrap_or_else(|| "Untitled Document".to_owned());
    let initial_body = initial
        .blocks
        .iter()
        .find(|block| block.kind == BlockKind::Paragraph)
        .map(|block| block.content.clone())
        .unwrap_or_default();
    let linked_incident_default = realm_id.clone();

    let mut blocks = use_signal(|| initial.blocks.clone());
    let mut versions = use_signal(|| initial.versions.clone());
    let mut editing_block = use_signal(|| Option::<String>::None);
    let mut edit_text = use_signal(String::new);
    let mut show_versions = use_signal(|| false);
    let mut save_status = use_signal(String::new);
    let mut sync_state = use_signal(|| SyncState::Local);
    let mut document_title_input = use_signal(move || initial_title.clone());
    let mut document_body_editor = use_signal(move || initial_body.clone());
    let mut linked_incident_input = use_signal(move || linked_incident_default.clone());
    let initial_morph_id = document_ref.clone().or_else(|| {
        state_store
            .read()
            .load_private_data(&actor_key, &morph_id_storage_key(&realm_id))
    });
    let mut current_morph_id = use_signal(move || initial_morph_id.unwrap_or_default());
    let document_realm_initial = realm_id.clone();
    let mut document_realm_id = use_signal(move || document_realm_initial.clone());
    let mut hydrated_document_id = use_signal(String::new);

    // ─────────────────────────────────────────────────────────────
    // G3.Y4 — collaborative state (cursors, comments, versions)
    // ─────────────────────────────────────────────────────────────
    // Self cursor position — driven by edit clicks; on wasm32 a
    // selectionchange listener would update this from the textarea
    // selection, but the harness can also stamp the value via the
    // visible `data-position-*` attributes.
    // TODO(G3.Y4-followup): subscribe to a browser `selectionchange`
    // listener via web-sys when the renderer is on wasm32 to keep
    // `self_cursor` honestly synced to the textarea selection.
    let self_cursor_line = use_signal(|| 0u32);
    let self_cursor_col = use_signal(|| 0u32);
    // Remote cursors — populated by the cotest harness through
    // `ck.presence` ephemerals; the panel currently renders whatever
    // the projection layer has stamped here.
    // TODO(G3.Y4-followup): replace the locally-held Vec with a
    // subscription to `state_store`'s presence projection once the
    // soland-side presence relay is in place; for now the panel only
    // renders what the harness seeds via this signal.
    let mut remote_cursors = use_signal(Vec::<RemoteCursor>::new);
    // Comment threads keyed by comment_id; the renderer reads through
    // this list in insertion order so the cotest harness sees a
    // stable per-thread DOM order.
    let mut comment_threads = use_signal(Vec::<DocumentCommentThread>::new);
    let mut comment_composer_open = use_signal(|| false);
    let mut comment_range_input = use_signal(String::new);
    let mut comment_text_input = use_signal(String::new);
    let mut comment_reply_input = use_signal(String::new);
    let mut comment_status = use_signal(String::new);
    // Version diff modal: when `Some(target_version_id)` the modal
    // renders for that version's snapshot vs the latest.
    let mut diff_modal_for = use_signal(|| Option::<String>::None);
    let mut restore_status = use_signal(String::new);

    let persist = {
        let actor_key = actor_key.clone();
        let realm_id = realm_id.clone();
        move |store: &mut Signal<LocalStateStore>,
              blocks_snapshot: Vec<DocumentBlock>,
              versions_snapshot: Vec<DocumentVersion>| {
            let draft = super::model::DocumentDraft {
                blocks: blocks_snapshot,
                versions: versions_snapshot,
            };
            save_draft(store, &actor_key, &realm_id, &draft);
        }
    };
    let realm_id_label = short_protocol_id(&realm_id);
    let actor_key_label = short_protocol_id(&actor_key);

    {
        let base = base_url.clone();
        let actor_key = actor_key.clone();
        use_effect(move || {
            let morph_id = current_morph_id();
            if !morph_id.starts_with("ck:morph:") || hydrated_document_id() == morph_id {
                return;
            }
            hydrated_document_id.set(morph_id.clone());
            sync_state.set(SyncState::Pending);
            let preserve_save_status = should_preserve_save_status_during_hydrate(&save_status());
            if !preserve_save_status {
                save_status.set(format!("Loading document {}", short_protocol_id(&morph_id)));
            }
            let base = base.clone();
            let token_val = token();
            let actor_key = actor_key.clone();
            spawn(async move {
                let morph_id_for_request = morph_id.clone();
                match with_authed_api(&base, token_val, |api| async move {
                    api.document_projection(&morph_id_for_request).await
                })
                .await
                {
                    Ok(projection) => {
                        let body = projection
                            .get("document")
                            .and_then(|document| document.get("body"))
                            .cloned()
                            .unwrap_or(Value::Null);
                        let projected_blocks = blocks_from_document_body(&body);
                        if !projected_blocks.is_empty() {
                            blocks.set(projected_blocks.clone());
                            document_title_input.set(
                                projected_blocks
                                    .iter()
                                    .find(|block| block.kind == BlockKind::Heading)
                                    .map(|block| block.content.clone())
                                    .unwrap_or_else(|| "Untitled Document".to_owned()),
                            );
                            document_body_editor.set(
                                projected_blocks
                                    .iter()
                                    .find(|block| block.kind == BlockKind::Paragraph)
                                    .map(|block| block.content.clone())
                                    .unwrap_or_default(),
                            );
                        }
                        let projected_versions = versions_from_projection(&projection);
                        if !projected_versions.is_empty() {
                            versions.set(projected_versions);
                        }
                        comment_threads.set(comments_from_projection(&projection));
                        remote_cursors.set(
                            cursors_from_projection(&projection)
                                .into_iter()
                                .filter(|cursor| cursor.actor_id != actor_key)
                                .collect(),
                        );
                        if let Some(realm_id) = projection
                            .get("document")
                            .and_then(|document| document.get("realm_id"))
                            .and_then(Value::as_str)
                        {
                            document_realm_id.set(realm_id.to_owned());
                        }
                        sync_state.set(SyncState::Synced);
                        if !preserve_save_status {
                            save_status
                                .set(format!("Loaded document {}", short_protocol_id(&morph_id)));
                        }
                    }
                    Err(err) => {
                        sync_state.set(SyncState::Failed);
                        save_status.set(format!("Document hydrate failed: {}", err.display()));
                    }
                }
            });
        });
    }

    rsx! {
        div { class: "timeline", "data-testid": "document-panel",
            // Document header
            div { class: "event",
                div { class: "event-head",
                    span { "Document" }
                    crate::components::SyncBadge {
                        state: sync_state(),
                        local_label: Some("Local draft".to_owned()),
                        pending_label: Some("Pending sync…".to_owned()),
                        failed_label: Some("Local draft (sync failed)".to_owned()),
                        test_id: Some("document-sync-badge".to_owned()),
                    }
                    span { class: "mono", title: "{realm_id}", "{realm_id_label}" }
                }
                div { class: "muted",
                    "Edits save locally first. Save Version writes the document Morph projection."
                }
                div { class: "workflow-form", "data-testid": "postmortem-link-controls",
                    Input {
                        "data-testid": "document-title-input",
                        value: "{document_title_input}",
                        placeholder: "Postmortem title",
                        oninput: move |event: FormEvent| {
                            let value = event.value();
                            document_title_input.set(value.clone());
                            let mut draft_blocks = blocks.write();
                            if let Some(block) = draft_blocks
                                .iter_mut()
                                .find(|block| block.kind == BlockKind::Heading)
                            {
                                block.content = value;
                            } else {
                                draft_blocks.insert(0, DocumentBlock {
                                    id: format!("block-title-{}", chrono::Utc::now().timestamp_millis()),
                                    kind: BlockKind::Heading,
                                    content: value,
                                });
                            }
                        },
                    }
                    Textarea {
                        "data-testid": "document-body-editor",
                        value: "{document_body_editor}",
                        placeholder: "Impact, root cause, action items.",
                        style: "width: 100%; min-height: 96px;",
                        oninput: move |event: FormEvent| {
                            let value = event.value();
                            document_body_editor.set(value.clone());
                            let mut draft_blocks = blocks.write();
                            if let Some(block) = draft_blocks
                                .iter_mut()
                                .find(|block| block.kind == BlockKind::Paragraph)
                            {
                                block.content = value;
                            } else {
                                draft_blocks.push(DocumentBlock {
                                    id: format!("block-body-{}", chrono::Utc::now().timestamp_millis()),
                                    kind: BlockKind::Paragraph,
                                    content: value,
                                });
                            }
                        },
                    }
                    Input {
                        "data-testid": "document-link-incident-input",
                        value: "{linked_incident_input}",
                        placeholder: "Incident Strand or Space id",
                        oninput: move |event: FormEvent| linked_incident_input.set(event.value()),
                    }
                }
                if !save_status().is_empty() {
                    div { class: "muted", "data-testid": "document-save-status", "{save_status}" }
                    div { class: "muted", "data-testid": "document-status", "{save_status}" }
                }
                div { class: "actions",
                    Button {
                        variant: if !show_versions() { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| show_versions.set(false),
                        "Edit"
                    }
                    Button {
                        variant: if show_versions() { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        "data-testid": "document-versions-button",
                        onclick: move |_| show_versions.set(true),
                        "History ({versions().len()})"
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "save-document-button",
                        onclick: {
                            let persist = persist.clone();
                            let mut store = state_store;
                            let actor_key_save = actor_key.clone();
                            let realm_id_save = realm_id.clone();
                            let base = base_url.clone();
                            move |_| {
                                let v_count = versions().len();
                                let b_count = blocks().len();
                                versions.write().push(DocumentVersion {
                                    id: format!("v-{v_count}"),
                                    timestamp: chrono::Utc::now().format("%Y-%m-%d %H:%M").to_string(),
                                    author: "yougen".to_owned(),
                                    block_count: b_count,
                                });
                                persist(&mut store, blocks(), versions());
                                save_status.set(format!(
                                    "Saved locally at {}",
                                    chrono::Utc::now().format("%H:%M:%S")
                                ));

                                if realm_id_save.trim().is_empty() {
                                    sync_state.set(SyncState::Local);
                                    return;
                                }
                                sync_state.set(SyncState::Pending);

                                let blocks_for_wire = blocks();
                                let linked_incident_for_wire = linked_incident_input();
                                let base = base.clone();
                                let token_val = token();
                                let actor_key_save = actor_key_save.clone();
                                let realm_id_save = realm_id_save.clone();
                                let mut store_for_sync = store;
                                spawn(async move {
                                    let body = document_body_payload(
                                        &blocks_for_wire,
                                        Some(linked_incident_for_wire.as_str()),
                                    );
                                    let title = blocks_for_wire
                                        .iter()
                                        .find(|b| b.kind == BlockKind::Heading)
                                        .map(|b| b.content.clone())
                                        .unwrap_or_else(|| "Untitled Document".to_owned());

                                    let morph_id_key = morph_id_storage_key(&realm_id_save);
                                    let existing_morph_id = current_morph_id();
                                    let existing_morph_id = if existing_morph_id.trim().is_empty() {
                                        store_for_sync
                                            .read()
                                            .load_private_data(&actor_key_save, &morph_id_key)
                                            .unwrap_or_default()
                                    } else {
                                        existing_morph_id
                                    };

                                    let (morph_id, is_create) = if existing_morph_id.trim().is_empty() {
                                        (mint_morph_id(), true)
                                    } else {
                                        (existing_morph_id, false)
                                    };
                                    let operation_realm_id = if document_realm_id().trim().is_empty() {
                                        realm_id_save.clone()
                                    } else {
                                        document_realm_id()
                                    };

                                    // YOU-02-001: payload builders no longer
                                    // panic on non-canonical ids; surface the
                                    // build error in the save status instead.
                                    let op_builder = if is_create {
                                        ck_ops::document_morph_create(
                                            &operation_realm_id,
                                            &actor_key_save,
                                            &morph_id,
                                            &title,
                                            body,
                                        )
                                    } else {
                                        ck_ops::document_morph_update(
                                            &operation_realm_id,
                                            &actor_key_save,
                                            &morph_id,
                                            body,
                                        )
                                    };
                                    let op = match op_builder {
                                        Ok(builder) => builder.build_sdk_event("yougen"),
                                        Err(err) => {
                                            sync_state.set(SyncState::Failed);
                                            save_status.set(format!(
                                                "Saved locally; sync: {err:#}"
                                            ));
                                            return;
                                        }
                                    };
                                    let op = match op {
                                        Ok(op) => op,
                                        Err(err) => {
                                            sync_state.set(SyncState::Failed);
                                            save_status
                                                .set(format!("Saved locally; sync: {err:#}"));
                                            return;
                                        }
                                    };
                                    let relation_op = if linked_incident_for_wire
                                        .trim()
                                        .starts_with("ck:")
                                    {
                                        match ck_ops::document_relation_create(
                                            &operation_realm_id,
                                            &actor_key_save,
                                            &morph_id,
                                                linked_incident_for_wire.trim(),
                                            ) {
                                            Ok(builder) => Some(builder.build_sdk_event("yougen")),
                                            Err(err) => {
                                                sync_state.set(SyncState::Failed);
                                                save_status.set(format!(
                                                    "Saved locally; sync: {err:#}"
                                                ));
                                                return;
                                            }
                                        }
                                    } else {
                                        None
                                    };
                                    let relation_op = match relation_op.transpose() {
                                        Ok(relation_op) => relation_op,
                                        Err(err) => {
                                            sync_state.set(SyncState::Failed);
                                            save_status
                                                .set(format!("Saved locally; sync: {err:#}"));
                                            return;
                                        }
                                    };

                                    // YOU-02-007: the incident relation op
                                    // failure used to be swallowed; carry it
                                    // out so the user sees the link did not
                                    // stick even though the document synced.
                                    match with_authed_api(&base, token_val, |api| async move {
                                        let resp = api.submit_sdk_event(&op).await?;
                                        let mut relation_error = None;
                                        if let Some(relation_op) = relation_op
                                            && let Err(err) =
                                                api.submit_sdk_event(&relation_op).await
                                        {
                                            relation_error = Some(format!("{err:#}"));
                                        }
                                        Ok((resp, relation_error))
                                    })
                                    .await
                                    {
                                        Ok((resp, relation_error)) => {
                                            if is_create {
                                                store_for_sync.write().save_private_data(
                                                    &actor_key_save,
                                                    morph_id_key,
                                                    morph_id.clone(),
                                                );
                                            }
                                            current_morph_id.set(morph_id.clone());
                                            document_realm_id.set(operation_realm_id.clone());
                                            sync_state.set(SyncState::Synced);
                                            if let Some(relation_error) = relation_error {
                                                save_status.set(format!(
                                                    "Saved and synced document {} (event {}); \
                                                     incident link failed: {relation_error}",
                                                    morph_id, resp.event_id
                                                ));
                                            } else {
                                                save_status.set(format!(
                                                    "Saved and synced document {} (event {})",
                                                    morph_id, resp.event_id
                                                ));
                                            }
                                        }
                                        Err(err) => {
                                            sync_state.set(SyncState::Failed);
                                            save_status.set(format!(
                                                "Saved locally; sync: {}",
                                                err.display()
                                            ));
                                        }
                                    }
                                });
                            }
                        },
                        "Save Version"
                    }
                }
            }

            if show_versions() {
                // Version history
                div { class: "event", "data-testid": "version-history",
                    div { class: "event-head", span { "Version History" } span { "{versions().len()} versions" } }
                    for version in versions() {
                        {
                            let version_id_label = short_protocol_id(&version.id);
                            rsx! {
                                div { class: "event", "data-testid": "version-entry",
                                    div { class: "event-head",
                                        span { title: "{version.id}", "{version_id_label}" }
                                        span { "{version.timestamp}" }
                                    }
                                    div { class: "muted", "By: {version.author} ({version.block_count} blocks)" }
                                }
                            }
                        }
                    }
                }
            } else {
                // Block editor
                for (idx, block) in blocks().iter().enumerate() {
                    div {
                        class: "event",
                        "data-testid": "document-block",
                        div { class: "event-head",
                            span { match block.kind {
                                BlockKind::Paragraph => "paragraph",
                                BlockKind::Heading => "heading",
                                BlockKind::BulletList => "list",
                                BlockKind::CodeBlock => "code",
                            }}
                            span { "block {idx}" }
                        }

                        if editing_block() == Some(block.id.clone()) {
                            Textarea {
                                "data-testid": "block-edit-input",
                                value: "{edit_text}",
                                oninput: move |event: FormEvent| edit_text.set(event.value()),
                                style: "width: 100%; min-height: 60px;",
                            }
                            div { class: "actions",
                                Button {
                                    variant: ButtonVariant::Primary,
                                    onclick: {
                                        let persist = persist.clone();
                                        let mut store = state_store;
                                        move |_| {
                                            let text = edit_text().trim().to_owned();
                                            if !text.is_empty()
                                                && let Some(b) = blocks.write().iter_mut().find(|b| b.id == editing_block().unwrap_or_default())
                                            {
                                                b.content = text;
                                            }
                                            editing_block.set(None);
                                            edit_text.set(String::new());
                                            persist(&mut store, blocks(), versions());
                                            save_status.set(format!(
                                                "Saved locally at {}",
                                                chrono::Utc::now().format("%H:%M:%S")
                                            ));
                                        }
                                    },
                                    "Save"
                                }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    onclick: move |_| { editing_block.set(None); edit_text.set(String::new()); },
                                    "Cancel"
                                }
                            }
                        } else {
                            div {
                                onclick: {
                                    let bid = block.id.clone();
                                    let content = block.content.clone();
                                    move |_| {
                                        editing_block.set(Some(bid.clone()));
                                        edit_text.set(content.clone());
                                    }
                                },
                                style: "cursor: text; padding: 8px 0;",
                                match block.kind {
                                    BlockKind::Heading => rsx! { h2 { class: "document-block-text", "{block.content}" } },
                                    BlockKind::BulletList => rsx! { ul { li { "{block.content}" } } },
                                    BlockKind::CodeBlock => rsx! { pre { code { "{block.content}" } } },
                                    BlockKind::Paragraph => rsx! { p { class: "document-block-text", "{block.content}" } },
                                }
                            }
                        }

                        // Block type change
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Secondary,
                                title: "Paragraph",
                                "aria-label": "Convert block to paragraph",
                                onclick: {
                                    let bid = block.id.clone();
                                    let persist = persist.clone();
                                    let mut store = state_store;
                                    move |_| {
                                        if let Some(b) = blocks.write().iter_mut().find(|b| b.id == bid) {
                                            b.kind = BlockKind::Paragraph;
                                        }
                                        persist(&mut store, blocks(), versions());
                                    }
                                },
                                "P"
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                title: "Heading",
                                "aria-label": "Convert block to heading",
                                onclick: {
                                    let bid = block.id.clone();
                                    let persist = persist.clone();
                                    let mut store = state_store;
                                    move |_| {
                                        if let Some(b) = blocks.write().iter_mut().find(|b| b.id == bid) {
                                            b.kind = BlockKind::Heading;
                                        }
                                        persist(&mut store, blocks(), versions());
                                    }
                                },
                                "H"
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                title: "Bullet list",
                                "aria-label": "Convert block to bullet list",
                                onclick: {
                                    let bid = block.id.clone();
                                    let persist = persist.clone();
                                    let mut store = state_store;
                                    move |_| {
                                        if let Some(b) = blocks.write().iter_mut().find(|b| b.id == bid) {
                                            b.kind = BlockKind::BulletList;
                                        }
                                        persist(&mut store, blocks(), versions());
                                    }
                                },
                                "L"
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                title: "Code block",
                                "aria-label": "Convert block to code block",
                                onclick: {
                                    let bid = block.id.clone();
                                    let persist = persist.clone();
                                    let mut store = state_store;
                                    move |_| {
                                        if let Some(b) = blocks.write().iter_mut().find(|b| b.id == bid) {
                                            b.kind = BlockKind::CodeBlock;
                                        }
                                        persist(&mut store, blocks(), versions());
                                    }
                                },
                                "</>"
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                title: "Delete block",
                                "aria-label": "Delete this block",
                                onclick: {
                                    let bid = block.id.clone();
                                    let persist = persist.clone();
                                    let mut store = state_store;
                                    move |_| {
                                        blocks.write().retain(|b| b.id != bid);
                                        persist(&mut store, blocks(), versions());
                                    }
                                },
                                "Delete"
                            }
                        }
                    }
                }

                // Add block button
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "add-block-button",
                        onclick: {
                            let persist = persist.clone();
                            let mut store = state_store;
                            move |_| {
                                blocks.write().push(DocumentBlock {
                                    id: format!("block-{}", chrono::Utc::now().timestamp_millis()),
                                    kind: BlockKind::Paragraph,
                                    content: String::new(),
                                });
                                persist(&mut store, blocks(), versions());
                            }
                        },
                        "+ Add Block"
                    }
                }
            }

            // ─────────────────────────────────────────────────────
            // G3.Y4 — collaborative surface
            // ─────────────────────────────────────────────────────
            if document_collaboration_enabled() {

            // Editor wrapper carrying the cursor markers and `data-*`
            // attributes the cotest harness uses to assert presence.
            div {
                class: "document-editor",
                "data-testid": "document-editor",
                span {
                    class: "document-cursor-self",
                    "data-testid": "document-cursor-self",
                    "data-position-line": "{self_cursor_line()}",
                    "data-position-col": "{self_cursor_col()}",
                    ""
                }
                for cursor in remote_cursors().iter() {
                    span {
                        class: "document-cursor-remote",
                        "data-testid": "document-cursor-remote",
                        "data-actor-did": "{cursor.actor_id}",
                        "data-position-line": "{cursor.line}",
                        "data-position-col": "{cursor.col}",
                        title: "{cursor.display_name}",
                        ""
                    }
                }
            }

            // Presence sidebar
            aside {
                class: "document-presence-list",
                "data-testid": "document-presence-list",
                div { class: "event-head",
                    span { "Editing now" }
                    span { class: "badge", "{remote_cursors().len() + 1}" }
                }
                ul {
                    li { class: "mono", title: "{actor_key}", "{actor_key_label} (you)" }
                    for cursor in remote_cursors().iter() {
                        li { class: "mono",
                            span { "data-actor-did": "{cursor.actor_id}", "{cursor.display_name}" }
                            span { class: "muted", " @ line {cursor.line}, col {cursor.col}" }
                        }
                    }
                }
            }

            // Comment composer + thread list
            div { class: "event", "data-testid": "document-comments",
                div { class: "event-head",
                    span { "Comments" }
                    span { class: "badge", "{comment_threads().len()} thread(s)" }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "document-comment-add-button",
                        onclick: move |_| comment_composer_open.set(!comment_composer_open()),
                        if comment_composer_open() { "Close" } else { "+ Comment" }
                    }
                }
                if comment_composer_open() {
                    div { class: "workflow-form",
                        Input {
                            "data-testid": "document-comment-range-input",
                            placeholder: "start..end (e.g. 100..110)",
                            value: "{comment_range_input}",
                            oninput: move |event: FormEvent| comment_range_input.set(event.value()),
                        }
                        Textarea {
                            "data-testid": "document-comment-text-input",
                            placeholder: "comment body",
                            value: "{comment_text_input}",
                            oninput: move |event: FormEvent| comment_text_input.set(event.value()),
                            style: "width: 100%; min-height: 40px;",
                        }
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "document-comment-submit-button",
                            onclick: {
                                let author_did = actor_key.clone();
                                let base = base_url.clone();
                                let fallback_realm_id = realm_id.clone();
                                move |_| {
                                    let raw_range = comment_range_input();
                                    let body = comment_text_input().trim().to_owned();
                                    let Some((start, end)) = parse_comment_range(&raw_range) else {
                                        comment_status.set(
                                            "range must look like 100..110 (end > start)".to_owned(),
                                        );
                                        return;
                                    };
                                    if body.is_empty() {
                                        comment_status.set("comment body cannot be empty".to_owned());
                                        return;
                                    }
                                    let id = format!(
                                        "comment-{}",
                                        chrono::Utc::now().timestamp_millis()
                                    );
                                    let body_for_wire = body.clone();
                                    comment_threads.write().push(DocumentCommentThread {
                                        comment_id: id.clone(),
                                        author_did: author_did.clone(),
                                        range_start: start,
                                        range_end: end,
                                        body,
                                        replies: Vec::new(),
                                        resolved: false,
                                        orphaned: false,
                                    });
                                    comment_range_input.set(String::new());
                                    comment_text_input.set(String::new());
                                    comment_composer_open.set(false);
                                    comment_status.set(format!("comment {id} added"));
                                    let morph_id = current_morph_id();
                                    let realm_id = if document_realm_id().trim().is_empty() {
                                        fallback_realm_id.clone()
                                    } else {
                                        document_realm_id()
                                    };
                                    if !morph_id.starts_with("ck:morph:") || realm_id.trim().is_empty() {
                                        comment_status.set(format!("comment {id} added locally"));
                                        return;
                                    }
                                    let op = match ck_ops::document_comment_create(
                                        &realm_id,
                                        &author_did,
                                        &morph_id,
                                        start,
                                        end,
                                        &body_for_wire,
                                        None,
                                    ) {
                                        Ok(builder) => builder.build_sdk_event("yougen"),
                                        Err(err) => {
                                            comment_status.set(format!(
                                                "comment {id} local; sync: {err:#}"
                                            ));
                                            return;
                                        }
                                    };
                                    let op = match op {
                                        Ok(op) => op,
                                        Err(err) => {
                                            comment_status.set(format!(
                                                "comment {id} local; sync: {err:#}"
                                            ));
                                            return;
                                        }
                                    };
                                    let base = base.clone();
                                    let token_val = token();
                                    spawn(async move {
                                        match with_authed_api(&base, token_val, |api| async move {
                                            api.submit_sdk_event(&op).await
                                        })
                                        .await
                                        {
                                            Ok(resp) => comment_status.set(format!(
                                                "comment {} synced",
                                                short_protocol_id(&resp.event_id)
                                            )),
                                            Err(err) => comment_status.set(format!(
                                                "comment {id} local; sync: {}",
                                                err.display()
                                            )),
                                        }
                                    });
                                }
                            },
                            "Submit"
                        }
                    }
                    if !comment_status().is_empty() {
                        div { class: "muted", "data-testid": "document-comment-status", "{comment_status}" }
                    }
                }
                for thread in comment_threads().iter() {
                    {
                        let thread_id = thread.comment_id.clone();
                        let range_start = thread.range_start;
                        let range_end = thread.range_end;
                        let author_did = thread.author_did.clone();
                        let author_did_label = display_name_for_did(&state_store.read(), &author_did);
                        let body = thread.body.clone();
                        let resolved = thread.resolved;
                        let orphaned = thread.orphaned;
                        let replies = thread.replies.clone();
                        rsx! {
                            div { class: "event",
                                "data-testid": "document-comment-thread",
                                "data-comment-id": "{thread_id}",
                                "data-range-start": "{range_start}",
                                "data-range-end": "{range_end}",
                                div { class: "event-head",
                                    span { class: "mono", title: "{author_did}", "{author_did_label}" }
                                    span { class: "badge", "[{range_start}..{range_end})" }
                                    if resolved {
                                        span { class: "badge green", "resolved" }
                                    }
                                    if orphaned {
                                        span { class: "badge warning", "data-testid": "document-comment-orphan-badge", "orphaned" }
                                    }
                                }
                                div { class: "muted", "{body}" }
                                for reply in replies.iter() {
                                    {
                                        let reply_author_did_label =
                                            display_name_for_did(&state_store.read(), &reply.author_did);
                                        rsx! {
                                            div { class: "muted",
                                                span { class: "mono", title: "{reply.author_did}", "{reply_author_did_label}: " }
                                                span { "{reply.body}" }
                                            }
                                        }
                                    }
                                }
                                if !resolved {
                                    div { class: "actions",
                                        Input {
                                            "data-testid": "document-comment-reply-input",
                                            placeholder: "reply…",
                                            value: "{comment_reply_input}",
                                            oninput: move |event: FormEvent| comment_reply_input.set(event.value()),
                                        }
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "document-comment-reply-button",
                                            onclick: {
                                                let thread_id = thread_id.clone();
                                                let actor_key = actor_key.clone();
                                                move |_| {
                                                    let reply_body =
                                                        comment_reply_input().trim().to_owned();
                                                    if reply_body.is_empty() {
                                                        return;
                                                    }
                                                    if let Some(t) = comment_threads
                                                        .write()
                                                        .iter_mut()
                                                        .find(|t| t.comment_id == thread_id)
                                                    {
                                                        t.replies.push(DocumentCommentReply {
                                                            author_did: actor_key.clone(),
                                                            body: reply_body,
                                                        });
                                                    }
                                                    comment_reply_input.set(String::new());
                                                }
                                            },
                                            "Reply"
                                        }
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "document-comment-resolve-button",
                                            onclick: {
                                                let thread_id = thread_id.clone();
                                                move |_| {
                                                    if let Some(t) = comment_threads
                                                        .write()
                                                        .iter_mut()
                                                        .find(|t| t.comment_id == thread_id)
                                                    {
                                                        t.resolved = true;
                                                    }
                                                }
                                            },
                                            "Resolve"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Version list sidebar — distinct from the in-line
            // history view above; this is the always-visible sidebar
            // that the harness asserts. Each row carries the
            // canonical version metadata via `data-*` attributes.
            aside {
                class: "document-version-list",
                "data-testid": "document-version-list",
                div { class: "event-head",
                    span { "Versions" }
                    span { class: "badge", "{versions().len()}" }
                }
                if !restore_status().is_empty() {
                    div {
                        class: "muted",
                        "data-testid": "document-version-restore-status",
                        "{restore_status}"
                    }
                }
                for version in versions().iter() {
                    {
                        let version_id = version.id.clone();
                        let version_id_label = short_protocol_id(&version_id);
                        let timestamp = version.timestamp.clone();
                        let block_count = version.block_count;
                        rsx! {
                            div {
                                class: "event",
                                "data-testid": "document-version-row",
                                "data-version-id": "{version_id}",
                                "data-created-at": "{timestamp}",
                                div { class: "event-head",
                                    span { class: "mono", title: "{version_id}", "{version_id_label}" }
                                    span { class: "muted", "{timestamp}" }
                                }
                                div { class: "muted", "{block_count} blocks" }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "document-version-restore-button",
                                        onclick: {
                                            let vid = version_id.clone();
                                            move |_| {
                                                let current = versions()
                                                    .last()
                                                    .map(|v| v.id.clone())
                                                    .unwrap_or_default();
                                                restore_status.set(
                                                    restore_status_label(&vid, &current),
                                                );
                                                // TODO(G3.Y4-followup):
                                                // submit a real
                                                // ck.morph.update with
                                                // state_witness +
                                                // inclusion_proof per
                                                // spec
                                                // event-auth-state-resolution
                                                // §8.1 once soland's
                                                // seal-finality
                                                // endpoints accept
                                                // restore moves.
                                            }
                                        },
                                        "Restore"
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "document-version-diff-button",
                                        onclick: {
                                            let vid = version_id.clone();
                                            move |_| diff_modal_for.set(Some(vid.clone()))
                                        },
                                        "Diff"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Diff modal — renders only when the harness clicked
            // `document-version-diff-button` on a row.
            if let Some(target_vid) = diff_modal_for() {
                {
                    let target_vid_label = short_protocol_id(&target_vid);
                    rsx! {
                        Dialog {
                            open: true,
                            on_open_change: move |open: bool| {
                                if !open {
                                    diff_modal_for.set(None);
                                }
                            },
                            "data-testid": "document-version-diff-modal",
                            div {
                                class: "publish-to-source-modal",
                                header {
                                    class: "publish-to-source-modal-header",
                                    h2 { title: "{target_vid}", "Diff vs {target_vid_label}" }
                                }
                                section {
                                    class: "publish-to-source-modal-body",
                                    pre {
                                        // The diff body is a TODO seam (see
                                        // build_version_diff); for now we
                                        // render block-count-only delta
                                        // because soland does not yet expose
                                        // per-version block snapshots in its
                                        // seal history.
                                        // TODO(G3.Y4-followup): wire to
                                        // soland's per-seal snapshot
                                        // endpoint when it ships.
                                        "{build_version_diff(&blocks(), &blocks())}"
                                    }
                                }
                                footer {
                                    class: "publish-to-source-modal-footer",
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        onclick: move |_| diff_modal_for.set(None),
                                        "Close"
                                    }
                                }
                            }
                        }
                    }
                }
            }
            } else {
                div {
                    class: "event",
                    "data-testid": "document-collaboration-deferred",
                    "data-feature": "experimental-document-collaboration",
                    div { class: "event-head",
                        span { "Collaboration" }
                        span { class: "badge", "Deferred" }
                    }
                    div { class: "muted",
                        "Presence, sealed comments, restore, and version diff controls are hidden in the default UI until the collaboration transport and snapshot endpoints are wired."
                    }
                }
            }
        }
    }
}

fn should_preserve_save_status_during_hydrate(status: &str) -> bool {
    status
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("saved")
}

#[cfg(test)]
mod tests {
    use super::should_preserve_save_status_during_hydrate;

    #[test]
    fn hydrate_preserves_save_result_status() {
        assert!(should_preserve_save_status_during_hydrate(
            "Saved and synced document ck:morph:abc (event ck:event:abc)"
        ));
        assert!(should_preserve_save_status_during_hydrate(
            "Saved locally; sync: unavailable"
        ));
        assert!(!should_preserve_save_status_during_hydrate(""));
        assert!(!should_preserve_save_status_during_hydrate(
            "Loading document ck:morph:abc"
        ));
        assert!(!should_preserve_save_status_during_hydrate(
            "Loaded document ck:morph:abc"
        ));
    }
}
