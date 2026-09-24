//! Wire-event -> `ChatMessage` parsing and received-tombstone folding.

use super::*;

#[test]
fn parses_committed_message_event_fields() {
    let mut event = json!({
        "event_id": "ak:event:AZccWZlaAUrqgOzXQ7OucnyL0J8C4O-JnwPOLdtlGX9k",
        "kind": "ak.message.create",
        "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}},
        "realm_id": "ak:realm:ARUALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        "scope_ref": {"kind":"realm","realm_id":"ak:realm:ARUALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE"},
        "created_at": "2026-05-14T01:23:45.000Z",
        "payload": {
            "content": {"kind": "ak.content.text", "body": "restored from durable history"},
            "strand_id": "ak:strand:A2XzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c",
            "mentions": [{
                "kind": "mention",
                "subject_account_id": {
                    "principal_id": "ak:did_core:web:bob.example",
                    "station_id": "ak:did_core:web:principal.example"
                },
                "mention_text_original": "@bob"
            }]
        }
    });
    sign_chat_fixture(&mut event);

    let message = chat_message_from_event(
        "ak:realm:Ag51V75jn75rRYCrxiU0PfMG0uo93vCh_5AfJiv15VPU",
        &event,
    )
    .unwrap();

    assert_eq!(
        message.id,
        "ak:event:AZccWZlaAUrqgOzXQ7OucnyL0J8C4O-JnwPOLdtlGX9k"
    );
    assert_eq!(
        message.realm_id,
        "ak:realm:ARUALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE"
    );
    assert_eq!(
        message.strand_id,
        "ak:strand:A2XzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c"
    );
    assert_eq!(message.body, "restored from durable history");
    assert_eq!(message.content_format, None);
    assert_eq!(message.sender, "ak:did_core:web:alice.example");
    assert_eq!(
        message.mentions[0].target(),
        arkret_sdk::MentionTarget::Subject(&local_fixture_account("ak:did_core:web:bob.example"))
    );
}

#[test]
fn parses_message_event_with_nested_envelope_payload_shape() {
    let mut event = json!({
        "event": {
            "event_id": "ak:event:AQ6V68zzvc5Qi7Qo6XcK38HBtXkkopkL0Y-dhmOTIlmE",
            "kind": "ak.message.create",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}},
            "realm_id": "ak:realm:ARUALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
            "scope_ref": {"kind":"realm","realm_id":"ak:realm:ARUALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE"},
            "created_at": "2026-05-14T01:23:46.000Z",
            "payload": {
                "content": {
                    "kind": "ak.content.text",
                    "body": "nested payload message",
                    "format": "markdown"
                },
                "strand_id": "ak:strand:A-KafHE4KSJLkmXVT_Mi2jvxt9YuOP_vQeOTOtjeaXSc"
            }
        }
    });
    sign_chat_fixture(&mut event);

    let message = chat_message_from_event(
        "ak:realm:ARUALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        &event,
    )
    .unwrap();

    assert_eq!(
        message.id,
        "ak:event:AQ6V68zzvc5Qi7Qo6XcK38HBtXkkopkL0Y-dhmOTIlmE"
    );
    assert_eq!(
        message.strand_id,
        "ak:strand:A-KafHE4KSJLkmXVT_Mi2jvxt9YuOP_vQeOTOtjeaXSc"
    );
    assert_eq!(message.body, "nested payload message");
    assert_eq!(
        message.content_format,
        Some(arkret_sdk::TextFormat::Markdown)
    );
}

#[test]
fn long_text_projection_derives_markdown_from_media_type() {
    let mut event = json!({
        "event_id": "ak:event:AdYyTPegfva2k0jRQeI4iVcOhvxyHN1MeQ2dpTfPOF0l",
        "kind": "ak.message.create",
        "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}},
        "realm_id": "ak:realm:ARUALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        "scope_ref": {"kind":"realm","realm_id":"ak:realm:ARUALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE"},
        "created_at": "2026-05-14T01:23:47.000Z",
        "payload": {
            "strand_id": "ak:strand:A-KafHE4KSJLkmXVT_Mi2jvxt9YuOP_vQeOTOtjeaXSc",
            "content": {
                "kind": "ak.content.long_text",
                "body": "# fallback",
                "body_kind": "prefix",
                "blob_ref": format!("ak:blob:sha256:{}", "a".repeat(64)),
                "size_bytes": 262_145,
                "media_type": "text/markdown"
            }
        }
    });
    sign_chat_fixture(&mut event);

    let message = chat_message_from_event(
        "ak:realm:ARUALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        &event,
    )
    .unwrap();
    assert_eq!(
        message.content_format,
        Some(arkret_sdk::TextFormat::Markdown)
    );
    assert!(message.body.starts_with('\u{1e}'));
}

#[test]
fn long_text_projection_reads_encrypted_attachment_media_type() {
    for (media_type, expected) in [
        ("text/plain", Some(arkret_sdk::TextFormat::Plain)),
        ("text/markdown", Some(arkret_sdk::TextFormat::Markdown)),
        ("text/html", None),
        ("text/markdown; charset=utf-8", None),
    ] {
        let content = json!({
            "kind": "ak.content.long_text",
            "body": "authenticated fallback",
            "body_kind": "summary",
            "attachment": {"media_type": media_type}
        });
        assert_eq!(content_format_from_value(&content), expected);
    }
    let missing = json!({
        "kind": "ak.content.long_text",
        "body": "fallback",
        "body_kind": "summary",
        "attachment": {},
        "format": "markdown"
    });
    assert_eq!(content_format_from_value(&missing), None);
}

#[test]
fn folds_received_redaction_tombstone_onto_message() {
    // A committed ak.message.create can carry per-message tombstone markers:
    // body stripped, redacted/state markers set. The receive path MUST render
    // the tombstone (redacted=true, empty body) even though this is the only
    // copy of the message the reader ever sees.
    let mut event = json!({
        "kind": "ak.message.create",
        "event_id": "ak:event:AVpOUPvtrgs_YaMdpjTSrJvTrtQP8fvBxcu1UnOriMzY",
        "realm_id": "ak:realm:ARUALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        "scope_ref": {"kind":"realm","realm_id":"ak:realm:ARUALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE"},
        "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
        "created_at": "2026-05-14T01:23:45.000Z",
        "payload": {
            "message_id": "ak:message:AST13ozMXrAgNmz6E-qiQFr9vg-w3JDZGPHpHPq_JTpY",
            "strand_id": "ak:strand:A-KafHE4KSJLkmXVT_Mi2jvxt9YuOP_vQeOTOtjeaXSc",
            "redacted": true,
            "state": "redacted",
            "redacted_at": "2026-05-14T02:00:00.000Z",
            "redaction_ref": "ak:event:A-RSupDyayuw4R7tIwZPpZWnF36wsoZuXYPDzQJ-jmhk",
            "content": {"kind": "ak.content.text", "body": "[redacted]"}
        }
    });
    sign_chat_fixture(&mut event);

    let message = chat_message_from_event(
        "ak:realm:ARUALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        &event,
    )
    .unwrap();

    assert_eq!(
        message.id,
        "ak:event:AVpOUPvtrgs_YaMdpjTSrJvTrtQP8fvBxcu1UnOriMzY"
    );
    assert!(message.redacted);
    assert_eq!(message.body, "");
}
