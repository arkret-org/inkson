use dioxus::prelude::*;
use serde_json::{Value, json};

use super::model::{
    BlockKind, DocumentBlock, DocumentCommentReply, DocumentCommentThread, DocumentDraft,
    DocumentVersion, RemoteCursor,
};
use crate::local_state::LocalStateStore;
use crate::views::helpers::short_protocol_id;

pub fn document_collaboration_enabled() -> bool {
    cfg!(feature = "experimental-document-collaboration")
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
pub(super) fn build_version_diff(
    older_blocks: &[DocumentBlock],
    newer_blocks: &[DocumentBlock],
) -> String {
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

pub(super) fn storage_key(realm_id: &str) -> String {
    format!("document.draft.{realm_id}")
}

pub(super) fn morph_id_storage_key(realm_id: &str) -> String {
    format!("document.morph_id.{realm_id}")
}

/// Mint a fresh document Morph id. The id is local-only until the
/// matching `ck.morph.create` event is accepted; once accepted, the
/// reducer takes ownership.
pub(super) fn mint_morph_id() -> String {
    format!("ck:morph:{}", crate::operation::uuid_v7())
}

/// Serialize the editable document for the synthesis-track body.
pub(super) fn document_body_payload(
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

pub(super) fn blocks_from_document_body(value: &Value) -> Vec<DocumentBlock> {
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

pub(super) fn versions_from_projection(value: &Value) -> Vec<DocumentVersion> {
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

pub(super) fn comments_from_projection(value: &Value) -> Vec<DocumentCommentThread> {
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

pub(super) fn cursors_from_projection(value: &Value) -> Vec<RemoteCursor> {
    value
        .get("cursor_presence")
        .and_then(Value::as_array)
        .map(|cursors| {
            cursors
                .iter()
                .filter_map(|cursor| {
                    let actor_id = cursor
                        .get("actor_id")
                        .or_else(|| cursor.get("actor"))
                        .and_then(Value::as_str)?
                        .to_owned();
                    Some(RemoteCursor {
                        display_name: cursor
                            .get("display_name")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                            .unwrap_or_else(|| short_protocol_id(&actor_id)),
                        actor_id,
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

pub(super) fn default_draft() -> DocumentDraft {
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

pub(super) fn load_draft(
    state_store: &Signal<LocalStateStore>,
    account_key: &str,
    realm_id: &str,
) -> DocumentDraft {
    if realm_id.is_empty() {
        return default_draft();
    }
    let key = storage_key(realm_id);
    let raw = state_store.read().load_private_data(account_key, &key);
    match raw {
        Some(json) => match serde_json::from_str::<DocumentDraft>(&json) {
            Ok(draft) if !draft.blocks.is_empty() => draft,
            _ => default_draft(),
        },
        None => default_draft(),
    }
}

pub(super) fn save_draft(
    state_store: &mut Signal<LocalStateStore>,
    account_key: &str,
    realm_id: &str,
    draft: &DocumentDraft,
) {
    if realm_id.is_empty() {
        return;
    }
    let key = storage_key(realm_id);
    if let Ok(payload) = serde_json::to_string(draft) {
        state_store
            .write()
            .save_private_data(account_key, key, payload);
    }
}
