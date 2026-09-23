use super::*;

/// D1: the former `events.rs` / `strands.rs` merge-helper twins were unified
/// into the single canonical `merge_duplicate_create_message`. These tests pin
/// the aligned semantics: the `>=` same-version tie-break, local-metadata
/// preservation, revision-body append, reaction union/sort, whitespace-trim on
/// reaction keys/actors, and the folded-in `created_at` carry-forward.
#[cfg(test)]
mod merge_duplicate_create_message_alignment_tests {
    use super::*;

    fn at(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        Some(
            chrono::DateTime::parse_from_rfc3339(value)
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
    }

    fn msg(id: &str, body: &str, created_at: Option<chrono::DateTime<chrono::Utc>>) -> ChatMessage {
        ChatMessage {
            realm_id: "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0".to_owned(),
            id: id.to_owned(),
            protocol_message_id: Some(
                "ak:message:AZhIGxyGMJYSpWhMOugJZewLoNM88CzSBohQQRpKgw1c".to_owned(),
            ),
            actor_id: None,
            sender: "ak:did_core:web:bob.example".to_owned(),
            executed_by: None,
            body: body.to_owned(),
            content_format: None,
            timestamp: "10:00".to_owned(),
            created_at,
            strand_id: "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE".to_owned(),
            reply_to: None,
            reactions: Vec::new(),
            redacted: false,
            edited: false,
            revisions: Vec::new(),
            revision_source: None,
            pending: false,
            failed: false,
            error: None,
            mentions: Vec::new(),
            crypto_state: MessageCryptoState::Plaintext,
        }
    }

    // The `>=` same-version tie-break is the load-bearing predicate the two
    // former merge families now share. On an equal timestamp the incoming row
    // wins (and thus carries local metadata forward) iff its id is `>=`.
    #[test]
    fn newer_or_same_lifecycle_version_uses_ge_id_tiebreak_on_equal_timestamp() {
        let existing = msg(
            "ak:event:AWSsryl67JAGALOqh0ZH5T-813hPA-GnZxpV3_U9Xp8c",
            "existing",
            at("2026-07-07T06:19:20.000Z"),
        );
        let same_id = msg(
            "ak:event:AWSsryl67JAGALOqh0ZH5T-813hPA-GnZxpV3_U9Xp8c",
            "incoming",
            at("2026-07-07T06:19:20.000Z"),
        );
        let higher_id = msg(
            "ak:event:AZccWZlaAUrqgOzXQ7OucnyL0J8C4O-JnwPOLdtlGX9k",
            "incoming",
            at("2026-07-07T06:19:20.000Z"),
        );
        let lower_id = msg(
            "ak:event:ASnA61b1h_g939GicWajzCOTfc2Z3pGGQvQlQ_YHYbN4",
            "incoming",
            at("2026-07-07T06:19:20.000Z"),
        );
        assert!(same_id.is_newer_or_same_lifecycle_version_than(&existing));
        assert!(higher_id.is_newer_or_same_lifecycle_version_than(&existing));
        assert!(!lower_id.is_newer_or_same_lifecycle_version_than(&existing));
    }

    #[test]
    fn newer_or_same_lifecycle_version_prefers_strictly_newer_timestamp() {
        let existing = msg(
            "ak:event:AWSsryl67JAGALOqh0ZH5T-813hPA-GnZxpV3_U9Xp8c",
            "existing",
            at("2026-07-07T06:19:20.000Z"),
        );
        // A strictly newer timestamp wins regardless of the id tie-break.
        let newer = msg(
            "ak:event:ASnA61b1h_g939GicWajzCOTfc2Z3pGGQvQlQ_YHYbN4",
            "incoming",
            at("2026-07-07T06:19:30.000Z"),
        );
        let older = msg(
            "ak:event:ATwS2vge4nnhtaqL3ss6x3XcMjGpGXRvnIbosXzWy_PY",
            "incoming",
            at("2026-07-07T06:19:10.000Z"),
        );
        assert!(newer.is_newer_or_same_lifecycle_version_than(&existing));
        assert!(!older.is_newer_or_same_lifecycle_version_than(&existing));
    }

    #[test]
    fn newer_or_same_lifecycle_version_missing_timestamps() {
        let existing_none = msg(
            "ak:event:ASnA61b1h_g939GicWajzCOTfc2Z3pGGQvQlQ_YHYbN4",
            "existing",
            None,
        );
        let existing_some = msg(
            "ak:event:ASnA61b1h_g939GicWajzCOTfc2Z3pGGQvQlQ_YHYbN4",
            "existing",
            at("2026-07-07T06:19:20.000Z"),
        );
        let incoming_none = msg(
            "ak:event:ASnA61b1h_g939GicWajzCOTfc2Z3pGGQvQlQ_YHYbN4",
            "incoming",
            None,
        );
        let incoming_some = msg(
            "ak:event:ASnA61b1h_g939GicWajzCOTfc2Z3pGGQvQlQ_YHYbN4",
            "incoming",
            at("2026-07-07T06:19:20.000Z"),
        );
        // incoming timestamped, existing not → incoming newer.
        assert!(incoming_some.is_newer_or_same_lifecycle_version_than(&existing_none));
        // existing timestamped, incoming not → NOT newer.
        assert!(!incoming_none.is_newer_or_same_lifecycle_version_than(&existing_some));
        // neither timestamped → treat incoming as newer-or-same.
        assert!(incoming_none.is_newer_or_same_lifecycle_version_than(&existing_none));
    }

    // A newer incoming replaces the row but preserves locally-tracked edit
    // metadata (edited flag + revision history) and folds the previous body
    // into the revision list.
    #[test]
    fn merge_newer_incoming_preserves_local_edit_metadata_and_appends_old_body() {
        let mut existing = msg(
            "ak:event:Az44QHRciASAFcKvTeHUu3sA84dj1h1KUH4_ZULaOFck",
            "edited body",
            at("2026-07-07T06:19:22.000Z"),
        );
        existing.edited = true;
        existing.revisions = vec!["draft".to_owned()];
        let incoming = msg(
            "ak:event:AR7M-BmzB0WZaDxMCMGGTR6MG8p04uMLRtEf7jJsmZlk",
            "newer body",
            at("2026-07-07T06:19:30.000Z"),
        );

        merge_duplicate_create_message(&mut existing, incoming);

        assert_eq!(
            existing.id,
            "ak:event:AR7M-BmzB0WZaDxMCMGGTR6MG8p04uMLRtEf7jJsmZlk"
        );
        assert_eq!(existing.body, "newer body");
        assert!(existing.edited, "edited flag carried forward");
        assert_eq!(
            existing.revisions,
            vec!["draft".to_owned(), "edited body".to_owned()]
        );
    }

    // A late older create folds into the existing (newer) row: existing stays
    // authoritative, the older body is appended as a revision, reactions union.
    #[test]
    fn merge_older_incoming_keeps_existing_and_folds_body_into_revisions() {
        let mut existing = msg(
            "ak:event:Az44QHRciASAFcKvTeHUu3sA84dj1h1KUH4_ZULaOFck",
            "current body",
            at("2026-07-07T06:19:30.000Z"),
        );
        existing.edited = true;
        let mut incoming = msg(
            "ak:event:AR7M-BmzB0WZaDxMCMGGTR6MG8p04uMLRtEf7jJsmZlk",
            "original body",
            at("2026-07-07T06:19:20.000Z"),
        );
        incoming.reactions = vec![(
            "+1".to_owned(),
            vec!["ak:did_core:web:carol.example".to_owned()],
        )];

        merge_duplicate_create_message(&mut existing, incoming);

        assert_eq!(
            existing.id,
            "ak:event:Az44QHRciASAFcKvTeHUu3sA84dj1h1KUH4_ZULaOFck"
        );
        assert_eq!(existing.body, "current body");
        assert_eq!(existing.revisions, vec!["original body".to_owned()]);
        assert_eq!(
            existing.reactions,
            vec![(
                "+1".to_owned(),
                vec!["ak:did_core:web:carol.example".to_owned()]
            )]
        );
    }

    // Reaction members from both sides union, dedupe overlapping reactors, and
    // sort by key then by member.
    #[test]
    fn merge_unions_and_sorts_reaction_members() {
        let mut existing = msg(
            "ak:event:AR7M-BmzB0WZaDxMCMGGTR6MG8p04uMLRtEf7jJsmZlk",
            "body",
            at("2026-07-07T06:19:20.000Z"),
        );
        existing.reactions = vec![(
            "+1".to_owned(),
            vec!["ak:did_core:web:bob.example".to_owned()],
        )];
        let mut incoming = msg(
            "ak:event:AIS3CfzQ4_aXiTARf8qv5G4C8b5BRZ7VN-tyB7K8oZmA",
            "body",
            at("2026-07-07T06:19:30.000Z"),
        );
        incoming.reactions = vec![
            (
                "\u{2764}".to_owned(),
                vec!["ak:did_core:web:dave.example".to_owned()],
            ),
            (
                "+1".to_owned(),
                vec![
                    "ak:did_core:web:carol.example".to_owned(),
                    "ak:did_core:web:bob.example".to_owned(),
                ],
            ),
        ];

        merge_duplicate_create_message(&mut existing, incoming);

        assert_eq!(
            existing.reactions,
            vec![
                (
                    "+1".to_owned(),
                    vec![
                        "ak:did_core:web:bob.example".to_owned(),
                        "ak:did_core:web:carol.example".to_owned(),
                    ],
                ),
                (
                    "\u{2764}".to_owned(),
                    vec!["ak:did_core:web:dave.example".to_owned()]
                ),
            ]
        );
    }

    // The retained (events) `push_reaction_member` trims whitespace on both the
    // reaction key and the actor — the divergence that the deleted strands twin
    // did NOT apply. Exercised through the real construction path.
    #[test]
    fn reactions_from_summary_trim_whitespace_in_key_and_actor() {
        let mut events = vec![json!({
            "event_id": "ak:event:AzlDwYnXxsrAJPnV18jXnpRSyNg1pwLq9kdhlLSr3PlI",
            "kind": "ak.message.create",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "realm_id": "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI",
            "scope_ref": {"kind":"realm","realm_id":"ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI"},
            "created_at": "2026-07-07T06:19:20.000Z",
            "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
            "message_id": "ak:message:AiMtOq_gs6Il6jSfTW_-c3OYzV-X5k9afNn8RSyisj38",
            "body": "hi",
            "reaction_summary": { " +1 ": { "members": [" ak:did_core:web:carol.example "] } },
            "producer_proof": null
        })];
        sign_chat_fixtures(&mut events);
        let messages = chat_messages_from_events_with_sidecar(
            "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI",
            &events,
            None,
            None,
        );
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0].reactions,
            vec![(
                "+1".to_owned(),
                vec!["ak:did_core:web:carol.example".to_owned()]
            )]
        );
    }

    // Folded-in strands improvement: a redaction tombstone that arrives without
    // its own `created_at` keeps the existing row's timestamp so ordering is
    // stable. (The former events twin dropped the timestamp here.)
    #[test]
    fn merge_redaction_tombstone_without_timestamp_keeps_existing_created_at() {
        let mut existing = msg(
            "ak:event:AR7M-BmzB0WZaDxMCMGGTR6MG8p04uMLRtEf7jJsmZlk",
            "secret",
            at("2026-07-07T06:19:20.000Z"),
        );
        let mut tombstone = msg(
            "ak:event:AR7M-BmzB0WZaDxMCMGGTR6MG8p04uMLRtEf7jJsmZlk",
            "",
            None,
        );
        tombstone.redacted = true;

        merge_duplicate_create_message(&mut existing, tombstone);

        assert!(existing.redacted);
        assert_eq!(existing.created_at, at("2026-07-07T06:19:20.000Z"));
    }

    // An echo / re-projection that could not recover the plaintext arrives
    // with an empty body; the merge must not blank out the body the local
    // (optimistic) copy already rendered, and the carried body must not leak
    // into the edit history.
    #[test]
    fn merge_newer_incoming_with_empty_body_preserves_rendered_body() {
        let mut existing = msg(
            "ak:event:Az44QHRciASAFcKvTeHUu3sA84dj1h1KUH4_ZULaOFck",
            "rendered body",
            at("2026-07-07T06:19:20.000Z"),
        );
        let incoming = msg(
            "ak:event:Az44QHRciASAFcKvTeHUu3sA84dj1h1KUH4_ZULaOFck",
            "",
            at("2026-07-07T06:19:30.000Z"),
        );

        merge_duplicate_create_message(&mut existing, incoming);

        assert_eq!(existing.body, "rendered body");
        assert!(existing.revisions.is_empty());
    }
}
