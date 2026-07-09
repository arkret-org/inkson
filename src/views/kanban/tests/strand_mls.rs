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
fn strand_body_display_text_reads_nested_blocks() {
    let body = json!({
        "blocks": [
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
        "scheme": "mls-rfc9420",
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
            "scheme": "mls-rfc9420",
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
        "scheme": "mls-rfc9420",
        "ciphertext": "AAAA",
        "content_type": KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
        "group_id": "g",
        "epoch": 0,
    });
    // Envelope + no ctx must render blank rather than leaking the raw
    // envelope JSON through strand_body_display_text.
    assert_eq!(private_strand_display_text(None, Some(&envelope)), "");
    let store = temp_state_store("private-strand-blank");
    let ctx = MlsDecryptCtx {
        state_store: &store,
        realm_id: "ak:realm:01904100-0000-7000-8000-000000000001",
        actor_id: "did:web:alice.example",
        device_id: "ak:device:01904100-0000-7000-8000-000000000001",
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
    let realm = "ak:realm:01904100-0000-7000-8000-000000000001";
    let strand = "ak:strand:01904100-0000-7000-8000-0000000000ab";
    let mut store = temp_state_store("private-strand-sidecar");
    // The writer stores the JSON-serialized patch value (a bare string).
    store.save_private_plaintext(realm, strand, "body", "\"author body\"");
    let ctx = MlsDecryptCtx {
        state_store: &store,
        realm_id: realm,
        actor_id: "did:web:alice.example",
        device_id: "ak:device:01904100-0000-7000-8000-000000000001",
    };
    // Even when the projection value is an un-decryptable envelope, the
    // sidecar wins (tier 1) with zero decryption.
    let envelope = json!({
        "scheme": "mls-rfc9420",
        "ciphertext": "AAAA",
        "content_type": KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
    });
    assert_eq!(
        private_strand_field_text(Some(&ctx), strand, "body", Some(&envelope)),
        "author body"
    );
    // A different strand id has no sidecar entry → falls back (blank for an
    // un-decryptable envelope).
    assert_eq!(
        private_strand_field_text(
            Some(&ctx),
            "ak:strand:01904100-0000-7000-8000-0000000000cd",
            "body",
            Some(&envelope)
        ),
        ""
    );
}

#[test]
fn private_strand_empty_sidecar_does_not_mask_encrypted_locked_state() {
    let realm = "ak:realm:01904100-0000-7000-8000-000000000001";
    let strand = "ak:strand:01904100-0000-7000-8000-0000000000ab";
    let mut store = temp_state_store("private-strand-empty-sidecar");
    store.save_private_plaintext(realm, strand, "synthesis", "\"\"");
    let ctx = MlsDecryptCtx {
        state_store: &store,
        realm_id: realm,
        actor_id: "did:web:alice.example",
        device_id: "ak:device:01904100-0000-7000-8000-000000000001",
    };
    let envelope = json!({
        "scheme": "mls-rfc9420",
        "ciphertext": "AAAA",
        "content_type": KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
    });

    assert_eq!(
        private_strand_field_text(Some(&ctx), strand, "synthesis", Some(&envelope)),
        ""
    );
    assert!(private_strand_field_locked(
        Some(&ctx),
        strand,
        "synthesis",
        Some(&envelope)
    ));
}

#[test]
fn card_builder_reads_author_plaintext_from_sidecar_without_mls_group() {
    // X5.2 gate — simulate the writer having stored the author's body
    // plaintext, then build a card from a projection whose body is an
    // un-decryptable MLS envelope, with NO MLS snapshot present. The
    // card must show the author's plaintext (proving the author sees
    // own content with zero decryption).
    let realm = "ak:realm:01904100-0000-7000-8000-000000000000";
    let strand = "ak:strand:01904100-0000-7000-8000-0000000000ab";
    let mut store = temp_state_store("card-builder-sidecar");
    store.save_private_plaintext(realm, strand, "body", "\"recovered body\"");
    let ctx = MlsDecryptCtx {
        state_store: &store,
        realm_id: realm,
        actor_id: "did:web:alice.example",
        device_id: "ak:device:01904100-0000-7000-8000-000000000001",
    };
    let strand_view = crate::projection_views::StrandProjectionView {
        strand_id: strand.to_owned(),
        realm_id: realm.to_owned(),
        title: "Encrypted card".to_owned(),
        summary: Some("public summary".to_owned()),
        body: Some(json!({
            "scheme": "mls-rfc9420",
            "ciphertext": "AAAA",
            "content_type": KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
        })),
        board_space_id: None,
        list_space_id: None,
        rank: Some("U".to_owned()),
        assigned_actor_ids: Vec::new(),
        assigned_to_relations: Vec::new(),
        fields: Map::new(),
        created_by: None,
        created_at: None,
        updated_by: None,
        updated_at: None,
        state: "active".to_owned(),
    };
    let card = card_from_strand_projection(&strand_view, Some(&ctx));
    assert_eq!(card.body, "recovered body");
    // Sanity: there is genuinely no MLS group to decrypt from.
    assert!(store.mls_snapshot_for(realm).is_none());
}
