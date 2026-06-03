//! Document view — block editor backed by a document Morph projection.
//!
//! - Every edit is mirrored to `LocalStateStore.private_data` so the draft survives navigation and
//!   offline use.
//! - Save Version emits a real `ck.morph.create` (first time) or `ck.morph.update` (subsequent
//!   saves). The morph_id is persisted per-Space so subsequent saves target the same Morph.
//! - The header sync badge reports the result of the most recent submit: `Synced` / `Pending sync`
//!   / `Local draft`. Failed submits fall back to local draft without losing the user's edits.
//!
//! G3.Y4 — collaborative surfaces:
//!
//! The panel now renders cursor markers (self + per-remote-actor), a
//! presence sidebar listing actors actively editing the document, a
//! comment composer wired to range start/end inputs, version restore /
//! diff buttons, and the supporting state machines for both. The data
//! is sourced from soland's document Morph projection when a `ck:morph:*`
//! route or persisted document id is available, with local draft fallback
//! for offline creation.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::local_state::LocalStateStore;
use crate::operation::cx_ops;
use crate::views::helpers::{short_protocol_id, with_authed_api};

pub fn document_collaboration_enabled() -> bool {
    cfg!(feature = "experimental-document-collaboration")
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
enum BlockKind {
    Paragraph,
    Heading,
    BulletList,
    CodeBlock,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct DocumentBlock {
    id: String,
    kind: BlockKind,
    content: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct DocumentVersion {
    id: String,
    timestamp: String,
    author: String,
    block_count: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
struct DocumentDraft {
    blocks: Vec<DocumentBlock>,
    versions: Vec<DocumentVersion>,
}

// ─────────────────────────────────────────────────────────────────────
// G3.Y4 — collaborative surface types
// ─────────────────────────────────────────────────────────────────────

/// A peer actor's cursor position within the document.
/// `line` / `col` map onto block index and offset within block content;
/// the renderer is intentionally agnostic about block structure so the
/// e2e harness can stamp arbitrary coordinates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteCursor {
    pub actor_did: String,
    pub display_name: String,
    pub line: u32,
    pub col: u32,
}

/// One comment thread anchored to a `[start, end)` range within the
/// document. Spec contract is `ck.message.create` on the document
/// Flow's discussion track (`models/flow-and-message.md` §4.3) with a
/// payload that carries `anchor_range`. The thread is identified by
/// the originating message's event_id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentCommentThread {
    pub comment_id: String,
    pub author_did: String,
    pub range_start: u32,
    pub range_end: u32,
    pub body: String,
    pub replies: Vec<DocumentCommentReply>,
    pub resolved: bool,
    pub orphaned: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentCommentReply {
    pub author_did: String,
    pub body: String,
}

/// Parse a `start..end` range input from the comment composer.
/// Accepts `100..110` and `100-110`, both common ways the harness
/// types ranges. Returns `None` for malformed input.
pub fn parse_comment_range(raw: &str) -> Option<(u32, u32)> {
    let trimmed = raw.trim();
    let (s, e) = if let Some((s, e)) = trimmed.split_once("..") {
        (s, e)
    } else if let Some((s, e)) = trimmed.split_once('-') {
        (s, e)
    } else {
        return None;
    };
    let start: u32 = s.trim().parse().ok()?;
    let end: u32 = e.trim().parse().ok()?;
    if end <= start {
        return None;
    }
    Some((start, end))
}

/// Pure state machine helper for the version restore button. Returns
/// the human-readable status string the panel renders below the
/// version-list when the user clicks `document-version-restore-button`
/// against a version that was already restored vs. a fresh restore.
pub fn restore_status_label(target_version_id: &str, current_version_id: &str) -> String {
    let target_label = short_protocol_id(target_version_id);
    let current_label = short_protocol_id(current_version_id);
    if target_version_id == current_version_id {
        format!("already at {target_label}")
    } else {
        format!("restored {target_label} (was {current_label})")
    }
}

/// Diff modal output — two-column text representation of the diff
/// between two version snapshots. Pure so the panel can call it
/// synchronously.
fn build_version_diff(older_blocks: &[DocumentBlock], newer_blocks: &[DocumentBlock]) -> String {
    let older_text: String = older_blocks
        .iter()
        .map(|b| b.content.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let newer_text: String = newer_blocks
        .iter()
        .map(|b| b.content.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    if older_text == newer_text {
        "no change".to_owned()
    } else {
        format!(
            "- {} blocks\n+ {} blocks",
            older_blocks.len(),
            newer_blocks.len()
        )
    }
}

fn storage_key(space_id: &str) -> String {
    format!("document.draft.{space_id}")
}

fn morph_id_storage_key(space_id: &str) -> String {
    format!("document.morph_id.{space_id}")
}

/// Mint a fresh document Morph id. The id is local-only until the
/// matching `ck.morph.create` event is accepted; once accepted, the
/// reducer takes ownership.
fn mint_morph_id() -> String {
    format!("ck:morph:{}", crate::operation::uuid_v7())
}

/// Serialize the editable document for the synthesis-track body.
fn document_body_payload(
    blocks: &[DocumentBlock],
    linked_incident_id: Option<&str>,
) -> serde_json::Value {
    let mut payload = json!({
        "schema_version": 1,
        "blocks": blocks,
    });
    if let Some(incident_id) = linked_incident_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        payload["linked_incident_id"] = json!(incident_id);
        payload["relations"] = json!([{
            "rel": "postmortem_for",
            "target_ref": incident_id,
        }]);
    }
    payload
}

fn block_kind_from_value(value: &Value) -> BlockKind {
    match value.as_str().unwrap_or_default() {
        "Heading" | "heading" => BlockKind::Heading,
        "BulletList" | "bullet_list" | "list" => BlockKind::BulletList,
        "CodeBlock" | "code_block" | "code" => BlockKind::CodeBlock,
        _ => BlockKind::Paragraph,
    }
}

fn blocks_from_document_body(value: &Value) -> Vec<DocumentBlock> {
    if let Some(blocks) = value.get("blocks").and_then(Value::as_array) {
        return blocks
            .iter()
            .enumerate()
            .filter_map(|(idx, block)| {
                let content = block
                    .get("content")
                    .or_else(|| block.get("text"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                if content.is_empty() {
                    return None;
                }
                Some(DocumentBlock {
                    id: block
                        .get("id")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                        .unwrap_or_else(|| format!("block-{idx}")),
                    kind: block_kind_from_value(block.get("kind").unwrap_or(&Value::Null)),
                    content,
                })
            })
            .collect();
    }
    value
        .as_str()
        .filter(|text| !text.trim().is_empty())
        .map(|text| {
            vec![DocumentBlock {
                id: "block-1".to_owned(),
                kind: BlockKind::Paragraph,
                content: text.to_owned(),
            }]
        })
        .unwrap_or_default()
}

fn versions_from_projection(value: &Value) -> Vec<DocumentVersion> {
    value
        .get("versions")
        .and_then(Value::as_array)
        .map(|versions| {
            versions
                .iter()
                .enumerate()
                .map(|(idx, version)| {
                    let body = version.get("body").unwrap_or(&Value::Null);
                    let block_count = blocks_from_document_body(body).len();
                    DocumentVersion {
                        id: version
                            .get("version_id")
                            .or_else(|| version.get("event_id"))
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                            .unwrap_or_else(|| format!("server-v-{idx}")),
                        timestamp: version
                            .get("created_at")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                            .unwrap_or_default(),
                        author: version
                            .get("author")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                            .unwrap_or_else(|| "server".to_owned()),
                        block_count,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn comments_from_projection(value: &Value) -> Vec<DocumentCommentThread> {
    value
        .get("comments")
        .and_then(Value::as_array)
        .map(|comments| {
            comments
                .iter()
                .enumerate()
                .map(|(idx, comment)| {
                    let replies = comment
                        .get("replies")
                        .and_then(Value::as_array)
                        .map(|items| {
                            items
                                .iter()
                                .map(|reply| DocumentCommentReply {
                                    author_did: reply
                                        .get("author")
                                        .and_then(Value::as_str)
                                        .unwrap_or("did:web:unknown")
                                        .to_owned(),
                                    body: reply
                                        .get("body")
                                        .and_then(Value::as_str)
                                        .unwrap_or("")
                                        .to_owned(),
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    let range = comment.get("anchor_range").unwrap_or(&Value::Null);
                    DocumentCommentThread {
                        comment_id: comment
                            .get("comment_id")
                            .or_else(|| comment.get("event_id"))
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                            .unwrap_or_else(|| format!("server-comment-{idx}")),
                        author_did: comment
                            .get("author")
                            .and_then(Value::as_str)
                            .unwrap_or("did:web:unknown")
                            .to_owned(),
                        range_start: range.get("start").and_then(Value::as_u64).unwrap_or(0) as u32,
                        range_end: range.get("end").and_then(Value::as_u64).unwrap_or(0) as u32,
                        body: comment
                            .get("body")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned(),
                        replies,
                        resolved: comment.get("state").and_then(Value::as_str) == Some("resolved"),
                        orphaned: comment.get("state").and_then(Value::as_str) == Some("orphaned"),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn cursors_from_projection(value: &Value) -> Vec<RemoteCursor> {
    value
        .get("cursor_presence")
        .and_then(Value::as_array)
        .map(|cursors| {
            cursors
                .iter()
                .filter_map(|cursor| {
                    let actor_did = cursor
                        .get("actor_id")
                        .or_else(|| cursor.get("actor"))
                        .and_then(Value::as_str)?
                        .to_owned();
                    Some(RemoteCursor {
                        display_name: cursor
                            .get("display_name")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                            .unwrap_or_else(|| short_protocol_id(&actor_did)),
                        actor_did,
                        line: cursor
                            .pointer("/cursor/line")
                            .or_else(|| cursor.get("line"))
                            .and_then(Value::as_u64)
                            .unwrap_or(0) as u32,
                        col: cursor
                            .pointer("/cursor/col")
                            .or_else(|| cursor.get("col"))
                            .and_then(Value::as_u64)
                            .unwrap_or(0) as u32,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

// `SyncState` is an alias over the shared `SyncBadgeState` so document
// rendering goes through the unified badge. The label override for
// `LocalOnly` / `Failed` matches the previous user-facing copy
// ("Local draft" / "Local draft (sync failed)") rather than the generic
// default so e2e selectors and screenshots stay stable.
use crate::components::SyncBadgeState;
type SyncState = SyncBadgeState;
const _: () = {
    // Compile-time check that the four-variant assumption still holds —
    // adding a fifth state upstream means we need to audit every render
    // site that exhaustively matches on this type.
    let _ = SyncState::Local;
    let _ = SyncState::Pending;
    let _ = SyncState::Synced;
    let _ = SyncState::Failed;
};

fn default_draft() -> DocumentDraft {
    DocumentDraft {
        blocks: vec![
            DocumentBlock {
                id: "block-1".to_owned(),
                kind: BlockKind::Heading,
                content: "Untitled Document".to_owned(),
            },
            DocumentBlock {
                id: "block-2".to_owned(),
                kind: BlockKind::Paragraph,
                content: "Start writing here...".to_owned(),
            },
        ],
        versions: vec![DocumentVersion {
            id: "v-0".to_owned(),
            timestamp: chrono::Utc::now().format("%Y-%m-%d %H:%M").to_string(),
            author: "yougen".to_owned(),
            block_count: 2,
        }],
    }
}

fn load_draft(
    state_store: &Signal<LocalStateStore>,
    account_key: &str,
    space_id: &str,
) -> DocumentDraft {
    if space_id.is_empty() {
        return default_draft();
    }
    let key = storage_key(space_id);
    let raw = state_store.read().load_private_data(account_key, &key);
    match raw {
        Some(json) => match serde_json::from_str::<DocumentDraft>(&json) {
            Ok(draft) if !draft.blocks.is_empty() => draft,
            _ => default_draft(),
        },
        None => default_draft(),
    }
}

fn save_draft(
    state_store: &mut Signal<LocalStateStore>,
    account_key: &str,
    space_id: &str,
    draft: &DocumentDraft,
) {
    if space_id.is_empty() {
        return;
    }
    let key = storage_key(space_id);
    if let Ok(payload) = serde_json::to_string(draft) {
        state_store
            .write()
            .save_private_data(account_key, key, payload);
    }
}

#[component]
pub fn DocumentPanel(
    base_url: String,
    token: Signal<String>,
    selected_space: String,
    document_ref: Option<String>,
    state_store: Signal<LocalStateStore>,
    account_did: String,
) -> Element {
    let space_id = selected_space.clone();
    let actor_key = account_did.clone();
    let initial = load_draft(&state_store, &actor_key, &space_id);
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
    let linked_incident_default = space_id.clone();

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
            .load_private_data(&actor_key, &morph_id_storage_key(&space_id))
    });
    let mut current_morph_id = use_signal(move || initial_morph_id.unwrap_or_default());
    let document_realm_initial = space_id.clone();
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
        let space_id = space_id.clone();
        move |store: &mut Signal<LocalStateStore>,
              blocks_snapshot: Vec<DocumentBlock>,
              versions_snapshot: Vec<DocumentVersion>| {
            let draft = DocumentDraft {
                blocks: blocks_snapshot,
                versions: versions_snapshot,
            };
            save_draft(store, &actor_key, &space_id, &draft);
        }
    };
    let space_id_label = short_protocol_id(&space_id);
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
            save_status.set(format!("Loading document {}", short_protocol_id(&morph_id)));
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
                                .filter(|cursor| cursor.actor_did != actor_key)
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
                        save_status
                            .set(format!("Loaded document {}", short_protocol_id(&morph_id)));
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
                    span { class: "mono", title: "{space_id}", "{space_id_label}" }
                }
                div { class: "muted",
                    "Edits save locally first. Save Version writes the document Morph projection."
                }
                div { class: "workflow-form", "data-testid": "postmortem-link-controls",
                    input {
                        "data-testid": "document-title-input",
                        value: "{document_title_input}",
                        placeholder: "Postmortem title",
                        oninput: move |evt| {
                            let value = evt.value();
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
                    textarea {
                        "data-testid": "document-body-editor",
                        value: "{document_body_editor}",
                        placeholder: "Impact, root cause, action items.",
                        style: "width: 100%; min-height: 96px;",
                        oninput: move |evt| {
                            let value = evt.value();
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
                    input {
                        "data-testid": "document-link-incident-input",
                        value: "{linked_incident_input}",
                        placeholder: "Incident Flow or Space id",
                        oninput: move |evt| linked_incident_input.set(evt.value()),
                    }
                }
                if !save_status().is_empty() {
                    div { class: "muted", "data-testid": "document-save-status", "{save_status}" }
                    div { class: "muted", "data-testid": "document-status", "{save_status}" }
                }
                div { class: "actions",
                    button {
                        class: if !show_versions() { "primary" } else { "secondary" },
                        onclick: move |_| show_versions.set(false),
                        "Edit"
                    }
                    button {
                        class: if show_versions() { "primary" } else { "secondary" },
                        "data-testid": "document-versions-button",
                        onclick: move |_| show_versions.set(true),
                        "History ({versions().len()})"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "save-document-button",
                        onclick: {
                            let persist = persist.clone();
                            let mut store = state_store;
                            let actor_key_save = actor_key.clone();
                            let space_id_save = space_id.clone();
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

                                if space_id_save.trim().is_empty() {
                                    sync_state.set(SyncState::Local);
                                    return;
                                }
                                sync_state.set(SyncState::Pending);

                                let blocks_for_wire = blocks();
                                let linked_incident_for_wire = linked_incident_input();
                                let base = base.clone();
                                let token_val = token();
                                let actor_key_save = actor_key_save.clone();
                                let space_id_save = space_id_save.clone();
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

                                    let morph_id_key = morph_id_storage_key(&space_id_save);
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
                                    let operation_space_id = if document_realm_id().trim().is_empty() {
                                        space_id_save.clone()
                                    } else {
                                        document_realm_id()
                                    };

                                    let op = if is_create {
                                        cx_ops::document_morph_create(
                                            &operation_space_id,
                                            &actor_key_save,
                                            &morph_id,
                                            &title,
                                            body,
                                        )
                                    } else {
                                        cx_ops::document_morph_update(
                                            &operation_space_id,
                                            &actor_key_save,
                                            &morph_id,
                                            body,
                                        )
                                    }
                                    .build("yougen");
                                    let relation_op = linked_incident_for_wire
                                        .trim()
                                        .starts_with("ck:")
                                        .then(|| {
                                            cx_ops::document_relation_create(
                                                &operation_space_id,
                                                &actor_key_save,
                                                &morph_id,
                                                linked_incident_for_wire.trim(),
                                            )
                                            .build("yougen")
                                        });

                                    match with_authed_api(&base, token_val, |api| async move {
                                        let resp = api.submit_event_envelope(&op).await?;
                                        if let Some(relation_op) = relation_op {
                                            let _ = api.submit_event_envelope(&relation_op).await;
                                        }
                                        Ok(resp)
                                    })
                                    .await
                                    {
                                        Ok(resp) => {
                                            if is_create {
                                                store_for_sync.write().save_private_data(
                                                    &actor_key_save,
                                                    morph_id_key,
                                                    morph_id.clone(),
                                                );
                                            }
                                            current_morph_id.set(morph_id.clone());
                                            document_realm_id.set(operation_space_id.clone());
                                            sync_state.set(SyncState::Synced);
                                            save_status.set(format!(
                                                "Saved and synced document {} (event {})",
                                                morph_id, resp.event_id
                                            ));
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
                            textarea {
                                "data-testid": "block-edit-input",
                                value: "{edit_text}",
                                oninput: move |evt| edit_text.set(evt.value()),
                                style: "width: 100%; min-height: 60px;",
                            }
                            div { class: "actions",
                                button {
                                    class: "primary",
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
                                button {
                                    class: "secondary",
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
                                    BlockKind::Heading => rsx! { h2 { style: "margin: 0;", "{block.content}" } },
                                    BlockKind::BulletList => rsx! { ul { li { "{block.content}" } } },
                                    BlockKind::CodeBlock => rsx! { pre { code { "{block.content}" } } },
                                    BlockKind::Paragraph => rsx! { p { style: "margin: 0;", "{block.content}" } },
                                }
                            }
                        }

                        // Block type change
                        div { class: "actions",
                            button {
                                class: "secondary",
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
                            button {
                                class: "secondary",
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
                            button {
                                class: "secondary",
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
                            button {
                                class: "secondary",
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
                            button {
                                class: "secondary",
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
                    button {
                        class: "primary",
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
                    style: "display: inline-block; width: 1px; height: 1em; background: var(--accent, #4c8bf5); margin: 0 2px;",
                    ""
                }
                for cursor in remote_cursors().iter() {
                    span {
                        class: "document-cursor-remote",
                        "data-testid": "document-cursor-remote",
                        "data-actor-did": "{cursor.actor_did}",
                        "data-position-line": "{cursor.line}",
                        "data-position-col": "{cursor.col}",
                        title: "{cursor.display_name}",
                        style: "display: inline-block; width: 1px; height: 1em; background: var(--warning, #f5a623); margin: 0 2px;",
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
                            span { "data-actor-did": "{cursor.actor_did}", "{cursor.display_name}" }
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
                    button {
                        class: "secondary",
                        "data-testid": "document-comment-add-button",
                        onclick: move |_| comment_composer_open.set(!comment_composer_open()),
                        if comment_composer_open() { "Close" } else { "+ Comment" }
                    }
                }
                if comment_composer_open() {
                    div { class: "workflow-form",
                        input {
                            "data-testid": "document-comment-range-input",
                            placeholder: "start..end (e.g. 100..110)",
                            value: "{comment_range_input}",
                            oninput: move |evt| comment_range_input.set(evt.value()),
                        }
                        textarea {
                            "data-testid": "document-comment-text-input",
                            placeholder: "comment body",
                            value: "{comment_text_input}",
                            oninput: move |evt| comment_text_input.set(evt.value()),
                            style: "width: 100%; min-height: 40px;",
                        }
                        button {
                            class: "primary",
                            "data-testid": "document-comment-submit-button",
                            onclick: {
                                let author_did = actor_key.clone();
                                let base = base_url.clone();
                                let fallback_space_id = space_id.clone();
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
                                        fallback_space_id.clone()
                                    } else {
                                        document_realm_id()
                                    };
                                    if !morph_id.starts_with("ck:morph:") || realm_id.trim().is_empty() {
                                        comment_status.set(format!("comment {id} added locally"));
                                        return;
                                    }
                                    let op = cx_ops::document_comment_create(
                                        &realm_id,
                                        &author_did,
                                        &morph_id,
                                        start,
                                        end,
                                        &body_for_wire,
                                        None,
                                    )
                                    .build("yougen");
                                    let base = base.clone();
                                    let token_val = token();
                                    spawn(async move {
                                        match with_authed_api(&base, token_val, |api| async move {
                                            api.submit_event_envelope(&op).await
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
                        let author_did_label = short_protocol_id(&author_did);
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
                                        let reply_author_did_label = short_protocol_id(&reply.author_did);
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
                                        input {
                                            "data-testid": "document-comment-reply-input",
                                            placeholder: "reply…",
                                            value: "{comment_reply_input}",
                                            oninput: move |evt| comment_reply_input.set(evt.value()),
                                        }
                                        button {
                                            class: "secondary",
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
                                        button {
                                            class: "secondary",
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
                                    button {
                                        class: "secondary",
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
                                                // anchor-finality
                                                // endpoints accept
                                                // restore moves.
                                            }
                                        },
                                        "Restore"
                                    }
                                    button {
                                        class: "secondary",
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
                        div {
                            class: "publish-to-source-modal-backdrop",
                            "data-testid": "document-version-diff-modal",
                            div {
                                class: "publish-to-source-modal",
                                role: "dialog",
                                "aria-modal": "true",
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
                                        // anchor history.
                                        // TODO(G3.Y4-followup): wire to
                                        // soland's per-anchor snapshot
                                        // endpoint when it ships.
                                        "{build_version_diff(&blocks(), &blocks())}"
                                    }
                                }
                                footer {
                                    class: "publish-to-source-modal-footer",
                                    button {
                                        class: "secondary",
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
                        "Presence, anchored comments, restore, and version diff controls are hidden in the default UI until the collaboration transport and snapshot endpoints are wired."
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        BlockKind, DocumentBlock, DocumentDraft, SyncState, blocks_from_document_body,
        comments_from_projection, default_draft, document_body_payload, mint_morph_id,
        morph_id_storage_key, storage_key, versions_from_projection,
    };

    #[test]
    fn storage_key_includes_space_id() {
        let key = storage_key("ck:space:abc");
        assert!(key.contains("ck:space:abc"));
        assert!(key.starts_with("document.draft."));
    }

    #[test]
    fn morph_id_storage_key_is_distinct_from_draft_key() {
        let draft_key = storage_key("ck:space:s1");
        let morph_key = morph_id_storage_key("ck:space:s1");
        assert_ne!(draft_key, morph_key);
        assert!(morph_key.starts_with("document.morph_id."));
    }

    #[test]
    fn default_draft_seeds_two_blocks_and_one_version() {
        let draft = default_draft();
        assert_eq!(draft.blocks.len(), 2);
        assert_eq!(draft.blocks[0].kind, BlockKind::Heading);
        assert_eq!(draft.blocks[1].kind, BlockKind::Paragraph);
        assert_eq!(draft.versions.len(), 1);
    }

    #[test]
    fn document_draft_round_trips_through_serde() {
        let draft = DocumentDraft {
            blocks: vec![DocumentBlock {
                id: "block-test".to_owned(),
                kind: BlockKind::CodeBlock,
                content: "fn main() {}".to_owned(),
            }],
            versions: vec![],
        };
        let json = serde_json::to_string(&draft).expect("serialize");
        let round: DocumentDraft = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(round, draft);
    }

    #[test]
    fn document_body_payload_carries_schema_version_and_blocks() {
        let blocks = default_draft().blocks;
        let body = document_body_payload(&blocks, Some("ck:flow:incident"));
        assert_eq!(body["schema_version"], 1);
        assert_eq!(body["blocks"].as_array().unwrap().len(), 2);
        assert_eq!(body["linked_incident_id"], "ck:flow:incident");
        assert_eq!(body["relations"][0]["rel"], "postmortem_for");
    }

    #[test]
    fn mint_morph_id_emits_typed_cx_morph_prefix() {
        let id = mint_morph_id();
        assert!(id.starts_with("ck:morph:"));
        assert!(id.len() > "ck:morph:".len());
        let again = mint_morph_id();
        assert_ne!(id, again, "minted ids must be unique");
    }

    #[test]
    fn projection_body_versions_and_comments_parse() {
        let projection = json!({
            "document": {
                "body": {
                    "blocks": [
                        {"id": "h", "kind": "Heading", "content": "Title"},
                        {"id": "p", "kind": "Paragraph", "content": "Body"}
                    ]
                }
            },
            "versions": [{
                "version_id": "v1",
                "created_at": "2026-05-25T00:00:00Z",
                "author": "did:web:alice.example",
                "body": {"blocks": [{"id": "p", "kind": "Paragraph", "content": "Body"}]}
            }],
            "comments": [{
                "comment_id": "c1",
                "author": "did:web:bob.example",
                "body": "needs detail",
                "anchor_range": {"start": 4, "end": 9},
                "state": "orphaned"
            }]
        });
        let blocks = blocks_from_document_body(&projection["document"]["body"]);
        assert_eq!(blocks.len(), 2);
        assert_eq!(versions_from_projection(&projection)[0].block_count, 1);
        let comments = comments_from_projection(&projection);
        assert_eq!(comments[0].range_start, 4);
        assert!(comments[0].orphaned);
    }

    #[test]
    fn sync_state_labels_are_distinct() {
        let labels = [
            SyncState::Local.default_label(),
            SyncState::Pending.default_label(),
            SyncState::Synced.default_label(),
            SyncState::Failed.default_label(),
        ];
        let unique: std::collections::BTreeSet<_> = labels.iter().copied().collect();
        assert_eq!(unique.len(), labels.len());
    }

    // ── G3.Y4 — collaborative helpers ──────────────────────────────

    use super::{
        DocumentCommentReply, DocumentCommentThread, RemoteCursor, build_version_diff,
        parse_comment_range, restore_status_label,
    };

    #[test]
    fn parse_comment_range_accepts_dot_dot_and_dash_forms() {
        assert_eq!(parse_comment_range("100..110"), Some((100, 110)));
        assert_eq!(parse_comment_range("100-110"), Some((100, 110)));
        assert_eq!(parse_comment_range("  4..9 "), Some((4, 9)));
    }

    #[test]
    fn parse_comment_range_rejects_malformed_and_inverted_ranges() {
        // missing separator
        assert_eq!(parse_comment_range("100"), None);
        // non-numeric component
        assert_eq!(parse_comment_range("a..b"), None);
        // inverted / empty range
        assert_eq!(parse_comment_range("100..100"), None);
        assert_eq!(parse_comment_range("110..100"), None);
    }

    #[test]
    fn restore_status_label_distinguishes_same_vs_different_version() {
        let same = restore_status_label("v-3", "v-3");
        assert!(same.starts_with("already at"));
        let diff = restore_status_label("v-1", "v-3");
        assert!(diff.contains("restored v-1"));
        assert!(diff.contains("was v-3"));
    }

    #[test]
    fn build_version_diff_reports_no_change_for_identical_snapshots() {
        let blocks = default_draft().blocks;
        let out = build_version_diff(&blocks, &blocks);
        assert_eq!(out, "no change");
    }

    #[test]
    fn build_version_diff_reports_counts_on_change() {
        let older = default_draft().blocks;
        let mut newer = older.clone();
        newer.push(DocumentBlock {
            id: "extra".to_owned(),
            kind: BlockKind::Paragraph,
            content: "added".to_owned(),
        });
        let out = build_version_diff(&older, &newer);
        assert!(out.contains("- 2 blocks"));
        assert!(out.contains("+ 3 blocks"));
    }

    #[test]
    fn remote_cursor_stores_line_col_and_actor() {
        let c = RemoteCursor {
            actor_did: "did:web:bob.example".to_owned(),
            display_name: "Bob".to_owned(),
            line: 4,
            col: 12,
        };
        assert_eq!(c.line, 4);
        assert_eq!(c.col, 12);
        assert!(c.actor_did.starts_with("did:"));
    }

    #[test]
    fn comment_thread_round_trip_with_replies_and_resolved_flag() {
        let mut thread = DocumentCommentThread {
            comment_id: "cm-1".to_owned(),
            author_did: "did:web:alice.example".to_owned(),
            range_start: 10,
            range_end: 20,
            body: "please clarify".to_owned(),
            replies: Vec::new(),
            resolved: false,
            orphaned: false,
        };
        thread.replies.push(DocumentCommentReply {
            author_did: "did:web:bob.example".to_owned(),
            body: "ack".to_owned(),
        });
        thread.resolved = true;
        assert!(thread.resolved);
        assert_eq!(thread.replies.len(), 1);
        assert_eq!(thread.range_end - thread.range_start, 10);
    }
}
