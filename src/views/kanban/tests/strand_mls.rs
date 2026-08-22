use super::*;

#[test]
fn strand_body_display_text_reads_content_block_body() {
    let body = json!({
        "kind": "ak.content.text",
        "body": "Long-form strand body"
    });

    assert_eq!(
        strand_body_display_text(Some(&body)),
        "Long-form strand body"
    );
}

#[test]
fn strand_body_display_text_reads_composite_parts() {
    let body = json!({
        "kind": "ak.content.composite",
        "parts": [
            { "kind": "ak.content.text", "body": "First block" },
            { "kind": "ak.content.text", "text": "Second block" }
        ]
    });

    assert_eq!(
        strand_body_display_text(Some(&body)),
        "First block\nSecond block"
    );
}

#[test]
fn value_is_mls_envelope_detects_encrypted_patch_values() {
    // Full envelope shape written by encrypt_values_with_device_snapshot.
    assert!(value_is_mls_envelope(&json!({
        "scheme": "mls_rfc9420",
        "ciphertext": "AAAA",
        "content_type": KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
        "group_id": "g",
        "epoch": 0,
    })));
    // Minimal envelope detected via ciphertext + content_type.
    assert!(value_is_mls_envelope(&json!({
        "ciphertext": "AAAA",
        "content_type": KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
    })));
    // Projection / patch wrappers must still be recognized as encrypted.
    assert!(value_is_mls_envelope(&json!({
        "encrypted_content": {
            "ciphertext": "AAAA",
            "content_type": KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
        }
    })));
    assert!(value_is_mls_envelope(&json!({
        "$op": "set",
        "value": {
            "scheme": "mls_rfc9420",
            "ciphertext": "AAAA",
            "content_type": KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
        }
    })));
    // Plain content blocks are NOT envelopes — unencrypted realms must
    // pay nothing and render as-is.
    assert!(!value_is_mls_envelope(&json!({
        "kind": "ak.content.text",
        "body": "plain body",
    })));
    assert!(!value_is_mls_envelope(&json!("just a string")));
}

#[test]
fn private_strand_display_text_passes_plaintext_through_without_ctx() {
    let plain = json!({ "kind": "ak.content.text", "body": "plain body" });
    // No decrypt ctx, non-envelope value → renders the plaintext as-is.
    assert_eq!(
        private_strand_display_text(None, Some(&plain)),
        "plain body"
    );
    // Missing value → blank.
    assert_eq!(private_strand_display_text(None, None), "");
}

#[test]
fn private_strand_display_text_blanks_undecryptable_envelope() {
    let envelope = json!({
        "scheme": "mls_rfc9420",
        "ciphertext": "AAAA",
        "content_type": KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
        "group_id": "g",
        "epoch": 0,
    });
    // Envelope + no ctx must render blank rather than leaking the raw
    // envelope JSON through strand_body_display_text.
    assert_eq!(private_strand_display_text(None, Some(&envelope)), "");
    let store = isolated_store_for_tests("private-strand-blank");
    let ctx = MlsDecryptCtx {
        state_store: &store,
        realm_id: "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
    };
    // Envelope + ctx but no local snapshot → soft failure → blank.
    assert_eq!(private_strand_display_text(Some(&ctx), Some(&envelope)), "");
}

#[test]
fn private_strand_field_text_prefers_local_sidecar_plaintext() {
    // X5.2 — the author's own encrypted field can NEVER be decrypted
    // (OpenMLS refuses the author's own ciphertext). The local sidecar
    // is the only source. With a sidecar hit and NO MLS group at all,
    // the builder must still render the plaintext.
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let strand = "ak:strand:ARKSHgBichO7ZjwprTMf4UrKn7x1GHkl16zz6U4xm586";
    let mut store = isolated_store_for_tests("private-strand-sidecar");
    // The writer stores the JSON-serialized patch value (a bare string).
    store.save_private_plaintext(
        realm,
        strand,
        KANBAN_ENCRYPTED_CONTENT_PATH,
        "\"author body\"",
    );
    let ctx = MlsDecryptCtx {
        state_store: &store,
        realm_id: realm,
    };
    // Even when the projection value is an un-decryptable envelope, the
    // sidecar wins (tier 1) with zero decryption.
    let envelope = json!({
        "scheme": "mls_rfc9420",
        "ciphertext": "AAAA",
        "content_type": KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
    });
    assert_eq!(
        private_strand_field_text(
            Some(&ctx),
            strand,
            KANBAN_ENCRYPTED_CONTENT_PATH,
            Some(&envelope)
        ),
        "author body"
    );
    // A different strand id has no sidecar entry → falls back (blank for an
    // un-decryptable envelope).
    assert_eq!(
        private_strand_field_text(
            Some(&ctx),
            "ak:strand:ATEG2QCavtpxeXB5vkEeQqzkPjtieb9NlGtUvdteawYZ",
            KANBAN_ENCRYPTED_CONTENT_PATH,
            Some(&envelope)
        ),
        ""
    );
}

#[test]
fn private_strand_empty_sidecar_does_not_mask_encrypted_locked_state() {
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let strand = "ak:strand:ARKSHgBichO7ZjwprTMf4UrKn7x1GHkl16zz6U4xm586";
    let mut store = isolated_store_for_tests("private-strand-empty-sidecar");
    store.save_private_plaintext(realm, strand, KANBAN_ENCRYPTED_CONTENT_PATH, "\"\"");
    let ctx = MlsDecryptCtx {
        state_store: &store,
        realm_id: realm,
    };
    let envelope = json!({
        "scheme": "mls_rfc9420",
        "ciphertext": "AAAA",
        "content_type": KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
    });

    assert_eq!(
        private_strand_field_text(
            Some(&ctx),
            strand,
            KANBAN_ENCRYPTED_CONTENT_PATH,
            Some(&envelope)
        ),
        ""
    );
    assert!(private_strand_field_locked(
        Some(&ctx),
        strand,
        KANBAN_ENCRYPTED_CONTENT_PATH,
        Some(&envelope)
    ));
}

#[test]
fn card_builder_reads_author_plaintext_from_sidecar_without_mls_group() {
    // X5.2 gate — simulate the writer having stored the author's synthesis
    // plaintext, then build a card from a projection whose
    // `tracks.synthesis.encrypted_content` is an un-decryptable MLS envelope,
    // with NO MLS snapshot present. The
    // card must show the author's plaintext (proving the author sees
    // own content with zero decryption).
    let realm = "ak:realm:ARuquux-GRSwGPPZ0lJor6JUmVSERFPzPWlj1mjx8JCX";
    let strand = "ak:strand:ARKSHgBichO7ZjwprTMf4UrKn7x1GHkl16zz6U4xm586";
    let mut store = isolated_store_for_tests("card-builder-sidecar");
    // The writer stores the JSON-serialized patch VALUE, i.e. the ContentBlock.
    store.save_private_plaintext(
        realm,
        strand,
        KANBAN_ENCRYPTED_SYNTHESIS_CONTENT_PATH,
        &serde_json::to_string(&json!({
            "kind": "ak.content.text",
            "format": "markdown",
            "body": "recovered synthesis"
        }))
        .unwrap(),
    );
    let ctx = MlsDecryptCtx {
        state_store: &store,
        realm_id: realm,
    };
    let strand_view = crate::state::projection_views::StrandProjectionView {
        strand_id: strand.to_owned(),
        realm_id: realm.to_owned(),
        title: "Encrypted card".to_owned(),
        summary: Some("public summary".to_owned()),
        content: None,
        encrypted_content: None,
        tracks: BTreeMap::from([(
            arkret_sdk::STRAND_TRACK_NAME_SYNTHESIS.to_owned(),
            arkret_sdk::StrandTrack {
                encrypted_content: Some(test_encrypted_content_envelope(realm, "AAAA")),
                ..Default::default()
            },
        )]),
        board_space_id: None,
        list_space_id: None,
        rank: Some("U".to_owned()),
        assigned_actor_ids: Vec::new(),
        assigned_to_relations: Vec::new(),
        schema_refs: Vec::new(),
        rsvps: Vec::new(),
        schedule_revision_heads: Vec::new(),
        fields: Map::new(),
        created_by: None,
        created_at: None,
        updated_by: None,
        updated_at: None,
        state: arkret_sdk::ProjectionObjectState::Active,
    };
    let card = card_from_strand_projection(&strand_view, Some(&ctx));
    assert_eq!(card.synthesis, "recovered synthesis");
    // Sanity: there is genuinely no MLS group to decrypt from.
    assert!(store.mls_snapshot_for(realm).is_none());
}

/// E2EE locked vs unlocked on the SAME canonical path.
///
/// The card builder resolves the display text and the locked flag from one
/// expression over `encrypted_content`, so the two can never disagree: with a
/// readable local plaintext the card is unlocked and shows the text; without it
/// the card is locked and the text stays EMPTY (never the raw envelope, never
/// the placeholder, which the editor would otherwise re-save over ciphertext).
#[test]
fn encrypted_card_content_is_locked_exactly_when_it_is_unreadable() {
    let realm = "ak:realm:ARuquux-GRSwGPPZ0lJor6JUmVSERFPzPWlj1mjx8JCX";
    let strand = "ak:strand:ARKSHgBichO7ZjwprTMf4UrKn7x1GHkl16zz6U4xm586";
    let envelope = test_encrypted_content_envelope(realm, "AAAA");
    let strand_view =
        |realm: &str, strand: &str| crate::state::projection_views::StrandProjectionView {
            strand_id: strand.to_owned(),
            realm_id: realm.to_owned(),
            title: "Encrypted card".to_owned(),
            summary: Some("public summary".to_owned()),
            content: None,
            encrypted_content: None,
            tracks: BTreeMap::from([(
                arkret_sdk::STRAND_TRACK_NAME_SYNTHESIS.to_owned(),
                arkret_sdk::StrandTrack {
                    encrypted_content: Some(envelope.clone()),
                    ..Default::default()
                },
            )]),
            board_space_id: None,
            list_space_id: None,
            rank: Some("U".to_owned()),
            assigned_actor_ids: Vec::new(),
            assigned_to_relations: Vec::new(),
            schema_refs: Vec::new(),
            rsvps: Vec::new(),
            schedule_revision_heads: Vec::new(),
            fields: Map::new(),
            created_by: None,
            created_at: None,
            updated_by: None,
            updated_at: None,
            state: arkret_sdk::ProjectionObjectState::Active,
        };

    // Locked: an envelope with no sidecar and no group to decrypt with.
    let locked_store = isolated_store_for_tests("encrypted-card-locked");
    let locked_ctx = MlsDecryptCtx {
        state_store: &locked_store,
        realm_id: realm,
    };
    let locked = card_from_strand_projection(&strand_view(realm, strand), Some(&locked_ctx));
    assert_eq!(locked.synthesis, "");
    assert!(locked.synthesis_locked);
    assert!(!locked.synthesis.contains(MLS_LOCKED_FIELD_PLACEHOLDER));
    assert_eq!(locked.security_encrypted, Some(true));

    // Unlocked: the same envelope, now with the author's local plaintext.
    let mut unlocked_store = isolated_store_for_tests("encrypted-card-unlocked");
    unlocked_store.save_private_plaintext(
        realm,
        strand,
        KANBAN_ENCRYPTED_SYNTHESIS_CONTENT_PATH,
        &serde_json::to_string(&json!({
            "kind": "ak.content.text",
            "format": "markdown",
            "body": "unlocked synthesis"
        }))
        .unwrap(),
    );
    let unlocked_ctx = MlsDecryptCtx {
        state_store: &unlocked_store,
        realm_id: realm,
    };
    let unlocked = card_from_strand_projection(&strand_view(realm, strand), Some(&unlocked_ctx));
    assert_eq!(unlocked.synthesis, "unlocked synthesis");
    assert!(!unlocked.synthesis_locked);

    // A plaintext scope reads the ContentBlock straight through and is never
    // locked, so the two branches share one canonical path.
    let mut plaintext_view = strand_view(realm, strand);
    plaintext_view.tracks.insert(
        arkret_sdk::STRAND_TRACK_NAME_SYNTHESIS.to_owned(),
        arkret_sdk::StrandTrack {
            content: Some(
                arkret_sdk::ContentBlock::text("plaintext synthesis")
                    .with_field("format", json!("markdown")),
            ),
            ..Default::default()
        },
    );
    let plaintext = card_from_strand_projection(&plaintext_view, None);
    assert_eq!(plaintext.synthesis, "plaintext synthesis");
    assert!(!plaintext.synthesis_locked);
}
