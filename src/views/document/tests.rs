use serde_json::json;

use super::model::{
    BlockKind, DocumentBlock, DocumentCommentReply, DocumentCommentThread, DocumentDraft,
    RemoteCursor, SyncState,
};
use super::projection::{
    blocks_from_document_body, build_version_diff, comments_from_projection, default_draft,
    document_body_payload, mint_morph_id, morph_id_storage_key, parse_comment_range,
    restore_status_label, storage_key, versions_from_projection,
};

#[test]
fn storage_key_includes_realm_id() {
    let key = storage_key("ck:realm:abc");
    assert!(key.contains("ck:realm:abc"));
    assert!(key.starts_with("document.draft."));
}

#[test]
fn morph_id_storage_key_is_distinct_from_draft_key() {
    let draft_key = storage_key("ck:realm:s1");
    let morph_key = morph_id_storage_key("ck:realm:s1");
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
    let body = document_body_payload(&blocks, Some("ck:strand:incident"));
    assert_eq!(body["schema_version"], 1);
    assert_eq!(body["blocks"].as_array().unwrap().len(), 2);
    assert_eq!(body["linked_incident_id"], "ck:strand:incident");
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
        actor_id: "did:web:bob.example".to_owned(),
        display_name: "Bob".to_owned(),
        line: 4,
        col: 12,
    };
    assert_eq!(c.line, 4);
    assert_eq!(c.col, 12);
    assert!(c.actor_id.starts_with("did:"));
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
