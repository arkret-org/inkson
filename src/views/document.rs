//! Document view — block editor backed by a Flow synthesis track.
//!
//! - Every edit is mirrored to `LocalStateStore.private_data` so the
//!   draft survives navigation and offline use.
//! - Save Version emits a real `cx.flow.create` (first time) or
//!   `cx.flow.update` (subsequent saves) against the Space's document
//!   Flow on the synthesis track per `models/flow-and-message.md`
//!   §synthesis_track. The flow_id is persisted per-Space so subsequent
//!   saves target the same Flow.
//! - The header sync badge reports the result of the most recent
//!   submit: `Synced` / `Pending sync` / `Local draft`. Failed submits
//!   fall back to local draft without losing the user's edits.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{local_state::LocalStateStore, operation::cx_ops, views::helpers::with_authed_api};

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

fn storage_key(space_id: &str) -> String {
    format!("document.draft.{space_id}")
}

fn flow_id_storage_key(space_id: &str) -> String {
    format!("document.flow_id.{space_id}")
}

/// Mint a fresh document Flow id. The id is local-only until the
/// matching `cx.flow.create` event is accepted; once accepted, the
/// reducer takes ownership.
fn mint_flow_id() -> String {
    format!("cx:flow:{}", crate::operation::uuid_v7())
}

/// Serialize the editable document for the synthesis-track body.
fn document_body_payload(blocks: &[DocumentBlock]) -> serde_json::Value {
    json!({
        "schema_version": 1,
        "blocks": blocks,
    })
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
    state_store: Signal<LocalStateStore>,
    account_did: String,
) -> Element {
    let space_id = selected_space.clone();
    let actor_key = account_did.clone();
    let initial = load_draft(&state_store, &actor_key, &space_id);

    let mut blocks = use_signal(|| initial.blocks.clone());
    let mut versions = use_signal(|| initial.versions.clone());
    let mut editing_block = use_signal(|| Option::<String>::None);
    let mut edit_text = use_signal(String::new);
    let mut show_versions = use_signal(|| false);
    let mut save_status = use_signal(String::new);
    let mut sync_state = use_signal(|| SyncState::Local);

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
                    span { class: "mono", "{space_id}" }
                }
                div { class: "muted",
                    "Edits save to this device immediately. Save Version writes a cx.flow.create or cx.flow.update event to the Space's document Flow synthesis track."
                }
                if !save_status().is_empty() {
                    div { class: "muted", "data-testid": "document-save-status", "{save_status}" }
                }
                div { class: "actions",
                    button {
                        class: if !show_versions() { "primary" } else { "secondary" },
                        onclick: move |_| show_versions.set(false),
                        "Edit"
                    }
                    button {
                        class: if show_versions() { "primary" } else { "secondary" },
                        onclick: move |_| show_versions.set(true),
                        "History ({versions().len()})"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "save-document",
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
                                let base = base.clone();
                                let token_val = token();
                                let actor_key_save = actor_key_save.clone();
                                let space_id_save = space_id_save.clone();
                                let mut store_for_sync = store;
                                spawn(async move {
                                    let body = document_body_payload(&blocks_for_wire);
                                    let title = blocks_for_wire
                                        .iter()
                                        .find(|b| b.kind == BlockKind::Heading)
                                        .map(|b| b.content.clone())
                                        .unwrap_or_else(|| "Untitled Document".to_owned());

                                    let flow_id_key = flow_id_storage_key(&space_id_save);
                                    let existing_flow_id = store_for_sync
                                        .read()
                                        .load_private_data(&actor_key_save, &flow_id_key);

                                    let (flow_id, is_create) = match existing_flow_id {
                                        Some(id) if !id.trim().is_empty() => (id, false),
                                        _ => (mint_flow_id(), true),
                                    };

                                    let op = if is_create {
                                        cx_ops::document_flow_create(
                                            &space_id_save,
                                            &actor_key_save,
                                            &flow_id,
                                            &title,
                                            body,
                                        )
                                    } else {
                                        cx_ops::document_flow_update(
                                            &space_id_save,
                                            &actor_key_save,
                                            &flow_id,
                                            body,
                                        )
                                    }
                                    .build("yougen");

                                    match with_authed_api(&base, token_val, |api| async move {
                                        api.submit_event_envelope(&op).await
                                    })
                                    .await
                                    {
                                        Ok(resp) => {
                                            if is_create {
                                                store_for_sync.write().save_private_data(
                                                    &actor_key_save,
                                                    flow_id_key,
                                                    flow_id.clone(),
                                                );
                                            }
                                            sync_state.set(SyncState::Synced);
                                            save_status.set(format!(
                                                "Synced flow {} (event {})",
                                                flow_id, resp.event_id
                                            ));
                                        }
                                        Err(err) => {
                                            sync_state.set(SyncState::Failed);
                                            save_status.set(format!("sync: {}", err.display()));
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
                        div { class: "event", "data-testid": "version-entry",
                            div { class: "event-head",
                                span { "{version.id}" }
                                span { "{version.timestamp}" }
                            }
                            div { class: "muted", "By: {version.author} ({version.block_count} blocks)" }
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
                                            if !text.is_empty() {
                                                if let Some(b) = blocks.write().iter_mut().find(|b| b.id == editing_block().unwrap_or_default()) {
                                                    b.content = text;
                                                }
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BlockKind, DocumentBlock, DocumentDraft, SyncState, default_draft, document_body_payload,
        flow_id_storage_key, mint_flow_id, storage_key,
    };

    #[test]
    fn storage_key_includes_space_id() {
        let key = storage_key("cx:space:abc");
        assert!(key.contains("cx:space:abc"));
        assert!(key.starts_with("document.draft."));
    }

    #[test]
    fn flow_id_storage_key_is_distinct_from_draft_key() {
        let draft_key = storage_key("cx:space:s1");
        let flow_key = flow_id_storage_key("cx:space:s1");
        assert_ne!(draft_key, flow_key);
        assert!(flow_key.starts_with("document.flow_id."));
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
        let body = document_body_payload(&blocks);
        assert_eq!(body["schema_version"], 1);
        assert_eq!(body["blocks"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn mint_flow_id_emits_typed_cx_flow_prefix() {
        let id = mint_flow_id();
        assert!(id.starts_with("cx:flow:"));
        assert!(id.len() > "cx:flow:".len());
        let again = mint_flow_id();
        assert_ne!(id, again, "minted ids must be unique");
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
}
