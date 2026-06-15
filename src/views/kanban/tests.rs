use super::*;

const TEST_REALM_ID: &str = "ck:realm:0196419b-0000-7000-8000-000000000010";

// YOU-05-010: shared hermetic state-store fixture from `local_state`.
#[cfg(not(target_arch = "wasm32"))]
use crate::local_state::isolated_store_for_tests as temp_state_store;

#[cfg(not(target_arch = "wasm32"))]
fn assert_registered_payload_valid(event: &crate::operation::EventEnvelope) {
    cokret_sdk::schema::event_payload_validator_catalog()
        .validate_payload(&event.kind, &event.payload)
        .unwrap_or_else(|err| {
            panic!(
                "{} payload violates registered schema: {err}\npayload: {}",
                event.kind,
                serde_json::to_string_pretty(&event.payload).unwrap()
            )
        });
}

fn board_write_record(state: CardState, note: &str) -> BoardWriteRecord {
    BoardWriteRecord {
        state,
        move_id: "ck:operation:test".to_owned(),
        kind: "ck.strand.create".to_owned(),
        cell_id: "ck:cell:test".to_owned(),
        effect_summary: "{}".to_owned(),
        seal_ref: "ck:seal:test".to_owned(),
        hlc: "000000000000-0000-00000000".to_owned(),
        note: note.to_owned(),
        signed_move_json: None,
        rebase_attempts: 0,
    }
}

#[test]
fn board_write_manual_review_is_only_for_conflicts() {
    let transient_failure = board_write_record(
        CardState::Quarantined,
        "submit failed: projection still pending",
    );
    assert!(
        !transient_failure.needs_manual_conflict_review(),
        "ordinary submit failures should not show the board admin review banner"
    );

    let exhausted_conflict = board_write_record(
        CardState::Quarantined,
        "cas_conflict exhausted 3 rebase attempts",
    );
    assert!(exhausted_conflict.needs_manual_conflict_review());

    let active_conflict = board_write_record(CardState::Conflict, "server returned cas_conflict");
    assert!(active_conflict.needs_manual_conflict_review());
}

#[test]
fn realm_member_roster_reads_r32_wire_shape() {
    // R3.2 (cokret-spec @ b56cab1): roster entries carry
    // `actor_id` + `membership` + optional `subject_id` /
    // `identity_event_ids` / `member_display_state_digest`. Handle
    // strings only appear inside signed handle_claim evidence.
    let projection = json!({
        "members": [
            {
                "actor_id": "did:web:acme.example:users:alice",
                "membership": "join",
                "subject_id": "did:web:acme.example:principals:alice",
                "identity_event_ids": ["ck:event:01904100-0000-7000-8000-00000000000a"],
                "member_display_state_digest": "sha256:abababababababababababababababababababababababababababababababab",
                "handle_claims": [{
                    "subject": "did:web:acme.example:principals:alice",
                    "handle": "alice:acme.example",
                    "binding_state": "verified"
                }],
                "handle_claims_limited": false
            },
            {
                "actor_id": "did:webvh:zQmPr8",
                "membership": "invite"
            }
        ]
    });
    let rows = realm_member_roster(Some(&projection));
    assert_eq!(rows.len(), 2);
    let alice = rows
        .iter()
        .find(|row| row.actor_id.contains("alice"))
        .unwrap();
    assert_eq!(alice.membership.as_deref(), Some("join"));
    assert_eq!(
        alice.identity_event_ids,
        vec!["ck:event:01904100-0000-7000-8000-00000000000a".to_owned()]
    );
    assert!(alice.member_display_state_digest.is_some());
    assert_eq!(
        alice.subject_id.as_deref(),
        Some("did:web:acme.example:principals:alice")
    );
    assert_eq!(alice.handle_claims.len(), 1);
    assert!(!alice.handle_claims_limited);

    let webvh = rows
        .iter()
        .find(|row| row.actor_id.starts_with("did:webvh:"))
        .unwrap();
    assert_eq!(webvh.membership.as_deref(), Some("invite"));
    assert!(webvh.identity_event_ids.is_empty());
    assert!(webvh.member_display_state_digest.is_none());
    // subject_id not disclosed for the invite row.
    assert!(webvh.subject_id.is_none());
}

#[test]
fn realm_member_roster_reads_r32_digest_only() {
    // Aggressive no-compat: only the R3.2 `member_display_state_digest`
    // key is read.
    let projection = json!({
        "members": [{
            "actor_id": "did:web:acme.example:users:v2",
            "membership": "join",
            "member_display_state_digest": "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        }]
    });
    let rows = realm_member_roster(Some(&projection));
    assert_eq!(rows.len(), 1);
    assert!(rows[0].member_display_state_digest.is_some());
}

#[test]
fn realm_member_roster_ignores_removed_digest_key() {
    // The pre-R3.2 `identity_state_digest` key is NOT honoured.
    let projection = json!({
        "members": [{
            "actor_id": "did:web:acme.example:users:removed",
            "membership": "join",
            "identity_state_digest": "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        }]
    });
    let rows = realm_member_roster(Some(&projection));
    assert_eq!(rows.len(), 1);
    assert!(rows[0].member_display_state_digest.is_none());
}

#[test]
fn realm_member_roster_ignores_bare_did_strings() {
    let projection = json!({
        "members": ["did:web:bob.example", "did:web:carol.example"]
    });
    let rows = realm_member_roster(Some(&projection));
    assert!(rows.is_empty());
}

#[test]
fn member_display_label_prefers_handle_shaped_user_label() {
    use cokret_sdk::{
        DisplayProfile, MemberIdentity, MemberIdentityProof, MemberIdentitySignatureAlgorithm,
    };

    // R3.2: `MemberIdentity` discloses subject_id + display_profile
    // only; the roster label still prefers a handle-shaped label when
    // roster handle evidence or a materialized subject DID exposes one.
    let identity = MemberIdentity {
        schema: cokret_sdk::MEMBER_IDENTITY_SCHEMA.to_owned(),
        realm_id: cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001")
            .unwrap(),
        actor_id: cokret_sdk::Did::new("did:web:acme.example:users:alice".to_owned()).unwrap(),
        subject_id: cokret_sdk::Did::new("did:web:acme.example:users:alice".to_owned()).unwrap(),
        display_profile: DisplayProfile {
            display_name: "Alice".to_owned(),
            avatar_blob_ref: None,
        },
        asserted_at: chrono::Utc::now(),
        expires_at: None,
        proof: MemberIdentityProof {
            verification_method: "did:web:acme.example#key-1".to_owned(),
            signature_algorithm: MemberIdentitySignatureAlgorithm::Ed25519,
            payload_digest: cokret_sdk::Hash::new(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            signature: "AAAA".to_owned(),
        },
    };

    let row = RealmMemberRow {
        actor_id: "did:web:acme.example:users:alice".to_owned(),
        membership: Some("join".to_owned()),
        identity_event_ids: vec![],
        member_display_state_digest: None,
        subject_id: None,
        handle_claims: Vec::new(),
        handle_claims_limited: false,
    };
    assert_eq!(
        member_display_label(&row, Some(&identity), None),
        "alice:acme.example"
    );

    // Decryption-pending / no MemberIdentity → fall back to compact DID.
    let bare = RealmMemberRow {
        actor_id: "did:webvh:zQmPr8aaaaaaaaaaaaaaaaa7h4q87ha".to_owned(),
        membership: None,
        identity_event_ids: vec![],
        member_display_state_digest: None,
        subject_id: None,
        handle_claims: Vec::new(),
        handle_claims_limited: false,
    };
    let label = member_display_label(&bare, None, None);
    assert!(label.starts_with("did:webvh:"));
    assert!(label.contains("..."));
}

#[test]
fn member_display_label_prefers_inline_verified_handle_claim() {
    let row = RealmMemberRow {
        actor_id: "did:webvh:zQmPairwiseActor".to_owned(),
        membership: Some("join".to_owned()),
        identity_event_ids: vec![],
        member_display_state_digest: Some(
            "sha256:abababababababababababababababababababababababababababababababab".to_owned(),
        ),
        subject_id: Some("did:key:z6MkPrincipal".to_owned()),
        handle_claims: vec![
            json!({
                "subject": "did:key:z6MkOther",
                "handle": "other:acme.example",
                "binding_state": "verified"
            }),
            json!({
                "subject": "did:key:z6MkPrincipal",
                "handle": "alice:acme.example",
                "binding_state": "verified"
            }),
        ],
        handle_claims_limited: false,
    };

    assert_eq!(member_display_label(&row, None, None), "alice:acme.example");
}

#[test]
fn member_display_label_uses_cached_directory_primary_handle() {
    let row = RealmMemberRow {
        actor_id: "did:webvh:zQmPrincipal".to_owned(),
        membership: Some("join".to_owned()),
        identity_event_ids: vec![],
        member_display_state_digest: None,
        subject_id: Some("did:webvh:zQmPrincipal".to_owned()),
        handle_claims: Vec::new(),
        handle_claims_limited: false,
    };

    assert_eq!(
        member_display_label(&row, None, Some("Alice:Example.COM")),
        "alice:example.com"
    );
}

#[test]
fn member_handle_lookup_subject_falls_back_to_actor_id() {
    let row = RealmMemberRow {
        actor_id: "did:webvh:zQmPrincipal".to_owned(),
        membership: Some("join".to_owned()),
        identity_event_ids: vec![],
        member_display_state_digest: None,
        subject_id: None,
        handle_claims: Vec::new(),
        handle_claims_limited: false,
    };

    assert_eq!(
        member_handle_lookup_subject(&row, None).as_deref(),
        Some("did:webvh:zQmPrincipal")
    );
}

#[test]
fn member_roster_realm_context_prefers_projection_realm_id() {
    assert_eq!(
        member_roster_realm_context(
            "ck:space:board",
            "ck:realm:prop",
            Some(&json!({"realm_id": "ck:realm:projection"})),
        ),
        "ck:realm:projection"
    );
    assert_eq!(
        member_roster_realm_context("ck:realm:board", "ck:realm:projection-fallback", None),
        "ck:realm:projection-fallback"
    );
    assert_eq!(
        member_roster_realm_context("ck:realm:selected", "", None),
        "ck:realm:selected"
    );
}

#[test]
fn realm_roster_pagination_extracts_limited_and_cursor() {
    // ROST-4: truncated rosters MUST signal `members_limited=true`
    // so the UI surfaces a "load more" affordance.
    let projection = json!({
        "members": [],
        "members_limited": true,
        "members_next_cursor": "cursor-opaque.v1.abc"
    });
    let pagination = RealmRosterPagination::from_projection(Some(&projection));
    assert!(pagination.members_limited);
    assert_eq!(
        pagination.members_next_cursor.as_deref(),
        Some("cursor-opaque.v1.abc")
    );

    // Complete projections leave the flag unset.
    let complete = json!({ "members": [] });
    let pagination = RealmRosterPagination::from_projection(Some(&complete));
    assert!(!pagination.members_limited);
    assert!(pagination.members_next_cursor.is_none());
}

/// `try_load_api_columns` is the synchronous-init probe. Real API
/// fetching now lives in the async refresh handler that calls
/// `CokretApi::collection_projection`. This test still pins the
/// init-time behaviour as None so UI startup stays empty unless explicit
/// demo seed is enabled; async projection hydrate promotes to ApiDerived
/// once the HTTP call returns.
#[test]
fn try_load_api_columns_returns_none_in_sync_init_context() {
    let result = try_load_api_columns("");
    assert!(
        result.is_none(),
        "synchronous init MUST return None; async refresh handles real fetch"
    );
}

/// Wire state strings emitted by soland's
/// `/_cokret/self/projection/{spaces|strands}` round-trip into the
/// renderer enums. Unknown values stay at the safe `Active` default.
#[test]
fn lifecycle_wire_strings_decode_to_enums() {
    assert_eq!(
        space_container_state_from_wire("active"),
        SpaceContainerLifecycleState::Active
    );
    assert_eq!(
        space_container_state_from_wire("archived"),
        SpaceContainerLifecycleState::Archived
    );
    assert_eq!(
        space_container_state_from_wire("tombstoned"),
        SpaceContainerLifecycleState::Tombstoned
    );
    assert_eq!(
        space_container_state_from_wire("garbage"),
        SpaceContainerLifecycleState::Active
    );

    assert_eq!(
        strand_lifecycle_from_wire("active"),
        StrandLifecycleState::Active
    );
    assert_eq!(
        strand_lifecycle_from_wire("archived"),
        StrandLifecycleState::Archived
    );
    // R11: `redacted` is the only spec terminal (strand.schema.json).
    assert_eq!(
        strand_lifecycle_from_wire("redacted"),
        StrandLifecycleState::Redacted
    );
    // `deleted` is NOT in the spec enum; it degrades to the safe
    // non-terminal `Active` default (and logs a warning) rather than
    // being treated as a terminal.
    assert_eq!(
        strand_lifecycle_from_wire("deleted"),
        StrandLifecycleState::Active
    );
    assert_eq!(
        strand_lifecycle_from_wire("garbage"),
        StrandLifecycleState::Active
    );
}

/// Space-container lifecycle state defaults to Active per the spec wire
/// default; seed columns and projection-mapped columns MUST start
/// active so they appear in the main board grid.
#[test]
fn space_container_lifecycle_state_default_is_active() {
    assert_eq!(
        SpaceContainerLifecycleState::default(),
        SpaceContainerLifecycleState::Active
    );
    // Every seeded column starts Active.
    for column in seed_columns() {
        assert_eq!(
            column.state,
            SpaceContainerLifecycleState::Active,
            "seed column {} must start Active",
            column.id
        );
    }
}

/// Space-container lifecycle validator rejects (a) same-state self-transition
/// and (b) UI-emitted Tombstone target. The legal transitions
/// (Active → Archived and Archived → Active) MUST be accepted so
/// archive / restore continue to work end-to-end.
#[test]
fn validate_space_container_lifecycle_transition_rules() {
    // Same-state refusal — Active → Active.
    let err = validate_space_container_lifecycle_transition(
        "ck:space:test",
        SpaceContainerLifecycleState::Active,
        SpaceContainerLifecycleState::Active,
    )
    .expect_err("same-state Active→Active must be refused");
    assert!(err.contains("already in"));
    assert!(err.contains("ck:space:test"));

    // Same-state refusal — Archived → Archived.
    validate_space_container_lifecycle_transition(
        "ck:space:test",
        SpaceContainerLifecycleState::Archived,
        SpaceContainerLifecycleState::Archived,
    )
    .expect_err("same-state Archived→Archived must be refused");

    // Tombstone target refusal — UI never emits Tombstone.
    let err = validate_space_container_lifecycle_transition(
        "ck:space:test",
        SpaceContainerLifecycleState::Active,
        SpaceContainerLifecycleState::Tombstoned,
    )
    .expect_err("UI-emitted Tombstone must be refused");
    assert!(err.contains("Tombstone"));

    // Legal transitions stay green.
    validate_space_container_lifecycle_transition(
        "ck:space:test",
        SpaceContainerLifecycleState::Active,
        SpaceContainerLifecycleState::Archived,
    )
    .expect("Active→Archived is a legal transition");
    validate_space_container_lifecycle_transition(
        "ck:space:test",
        SpaceContainerLifecycleState::Archived,
        SpaceContainerLifecycleState::Active,
    )
    .expect("Archived→Active is a legal transition");
}

/// Symmetric to `validate_space_container_lifecycle_transition_rules` at the
/// Strand layer. Same two refusal cases, same two legal transitions.
#[test]
fn validate_strand_lifecycle_transition_rules() {
    let err = validate_strand_lifecycle_transition(
        "ck:strand:test",
        StrandLifecycleState::Active,
        StrandLifecycleState::Active,
    )
    .expect_err("same-state Active→Active must be refused");
    assert!(err.contains("already in"));
    assert!(err.contains("ck:strand:test"));

    validate_strand_lifecycle_transition(
        "ck:strand:test",
        StrandLifecycleState::Archived,
        StrandLifecycleState::Archived,
    )
    .expect_err("same-state Archived→Archived must be refused");

    let err = validate_strand_lifecycle_transition(
        "ck:strand:test",
        StrandLifecycleState::Active,
        StrandLifecycleState::Redacted,
    )
    .expect_err("UI-emitted Redaction must be refused");
    assert!(err.contains("Redaction"));

    validate_strand_lifecycle_transition(
        "ck:strand:test",
        StrandLifecycleState::Active,
        StrandLifecycleState::Archived,
    )
    .expect("Active→Archived is a legal transition");
    validate_strand_lifecycle_transition(
        "ck:strand:test",
        StrandLifecycleState::Archived,
        StrandLifecycleState::Active,
    )
    .expect("Archived→Active is a legal transition");
}

/// Symmetric to `space_container_lifecycle_state_default_is_active` —
/// StrandLifecycleState MUST default to Active and every seeded card
/// MUST start Active so the demo board exercises the happy path.
#[test]
fn strand_lifecycle_state_default_is_active() {
    assert_eq!(
        StrandLifecycleState::default(),
        StrandLifecycleState::Active
    );
    for column in seed_columns() {
        for card in &column.cards {
            assert_eq!(
                card.lifecycle,
                StrandLifecycleState::Active,
                "seed card {} in column {} must start Active",
                card.id,
                column.id
            );
        }
    }
}

#[test]
fn card_detail_deep_link_targets_kanban_task_route() {
    assert_eq!(
        strand_detail_deep_link_path("ck:space:ops", "ck:strand:abc"),
        "/kanban/ck:space:ops/task/ck:strand:abc"
    );
    assert_eq!(
        strand_detail_deep_link_path("", "ck:strand:abc"),
        format!("/kanban/{DEMO_BOARD_SPACE_ID}/task/ck:strand:abc")
    );
}

#[test]
fn card_detail_tab_deep_link_round_trips() {
    assert_eq!(
        card_detail_tab_slug(CardDetailContentTab::Description),
        "description"
    );
    assert_eq!(
        card_detail_tab_from_slug("SYNTHESIS"),
        Some(CardDetailContentTab::Synthesis)
    );
    assert_eq!(
        card_detail_tab_from_slug("discussion"),
        Some(CardDetailContentTab::Discussion)
    );
    assert_eq!(card_detail_tab_from_slug("activity"), None);
}

#[test]
fn card_detail_tab_reads_url_query() {
    assert_eq!(
        card_detail_tab_from_href(
            "http://127.0.0.1:8080/kanban/ck:realm:r/task/ck:strand:f?tab=discussion"
        ),
        Some(CardDetailContentTab::Discussion)
    );
    assert_eq!(
        card_detail_tab_from_href(
            "http://127.0.0.1:8080/kanban/ck:realm:r/task/ck:strand:f?tab=synthesis"
        ),
        Some(CardDetailContentTab::Synthesis)
    );
    assert_eq!(
        card_detail_tab_from_href(
            "http://127.0.0.1:8080/kanban/ck:realm:r/task/ck:strand:f?tab=bad"
        ),
        None
    );
}

#[test]
fn card_detail_share_link_carries_current_tab() {
    assert_eq!(
        strand_detail_deep_link_path_with_tab(
            "ck:space:ops",
            "ck:strand:abc",
            CardDetailContentTab::Discussion
        ),
        "/kanban/ck:space:ops/task/ck:strand:abc?tab=discussion"
    );
}

#[test]
fn route_card_strand_id_reads_task_segment_only() {
    assert_eq!(
        route_card_strand_id(&Route::KanbanTask {
            realm_id: "ck:realm:ops".to_owned(),
            task_id: "ck:strand:abc".to_owned(),
        }),
        Some("ck:strand:abc".to_owned())
    );
    assert_eq!(
        route_card_strand_id(&Route::KanbanBoardTask {
            realm_id: "ck:realm:ops".to_owned(),
            board_id: "ck:space:board".to_owned(),
            task_id: "ck:strand:abc".to_owned(),
        }),
        Some("ck:strand:abc".to_owned())
    );
    assert_eq!(route_card_strand_id(&Route::Kanban), None);
}

#[test]
fn route_board_id_reads_board_segment_only() {
    assert_eq!(
        route_board_id(&Route::KanbanBoard {
            realm_id: "ck:realm:ops".to_owned(),
            board_id: "ck:space:board".to_owned(),
        }),
        Some("ck:space:board".to_owned())
    );
    assert_eq!(
        route_board_id(&Route::KanbanBoardTask {
            realm_id: "ck:realm:ops".to_owned(),
            board_id: "ck:space:board".to_owned(),
            task_id: "ck:strand:abc".to_owned(),
        }),
        Some("ck:space:board".to_owned())
    );
    // The board-less routes carry no board id — it is resolved from
    // the projection on arrival.
    assert_eq!(
        route_board_id(&Route::KanbanTask {
            realm_id: "ck:realm:ops".to_owned(),
            task_id: "ck:strand:abc".to_owned(),
        }),
        None
    );
    assert_eq!(
        route_board_id(&Route::KanbanRealm {
            realm_id: "ck:realm:ops".to_owned(),
        }),
        None
    );
}

#[test]
fn kanban_board_route_carries_board_or_falls_back() {
    assert_eq!(
        kanban_board_route("ck:realm:ops", "ck:space:board"),
        Route::KanbanBoard {
            realm_id: "ck:realm:ops".to_owned(),
            board_id: "ck:space:board".to_owned(),
        }
    );
    assert_eq!(
        kanban_board_route("ck:realm:ops", ""),
        Route::KanbanRealm {
            realm_id: "ck:realm:ops".to_owned(),
        }
    );
}

#[test]
fn kanban_card_task_route_carries_board_or_falls_back() {
    assert_eq!(
        kanban_card_task_route("ck:realm:ops", "ck:space:board", "ck:strand:abc"),
        Route::KanbanBoardTask {
            realm_id: "ck:realm:ops".to_owned(),
            board_id: "ck:space:board".to_owned(),
            task_id: "ck:strand:abc".to_owned(),
        }
    );
    assert_eq!(
        kanban_card_task_route("ck:realm:ops", "", "ck:strand:abc"),
        Route::KanbanTask {
            realm_id: "ck:realm:ops".to_owned(),
            task_id: "ck:strand:abc".to_owned(),
        }
    );
}

#[test]
fn find_card_by_strand_id_matches_card_or_primary_strand() {
    let columns = seed_columns();
    assert_eq!(
        find_card_by_strand_id(&columns, DEMO_STRAND_LEGAL_REVIEW_ID).map(|card| card.title),
        Some("Legal review for public beta".to_owned())
    );
    assert_eq!(
        find_card_by_strand_id(&columns, DEMO_STRAND_REVIEW_DISCUSSION_ID).map(|card| card.id),
        Some(DEMO_STRAND_LEGAL_REVIEW_ID.to_owned())
    );
}

#[test]
fn strand_body_display_text_reads_content_block_body() {
    let body = json!({
        "kind": "ck.content.text",
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
            { "kind": "ck.content.text", "body": "First block" },
            { "kind": "ck.content.text", "text": "Second block" }
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
        "kind": "ck.content.text",
        "body": "plain body",
    })));
    assert!(!value_is_mls_envelope(&json!("just a string")));
}

#[test]
fn private_strand_display_text_passes_plaintext_through_without_ctx() {
    let plain = json!({ "kind": "ck.content.text", "body": "plain body" });
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
        realm_id: "ck:realm:01904100-0000-7000-8000-000000000001",
        actor_id: "did:web:alice.example",
        device_id: "ck:device:01904100-0000-7000-8000-000000000001",
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
    let realm = "ck:realm:01904100-0000-7000-8000-000000000001";
    let strand = "ck:strand:01904100-0000-7000-8000-0000000000ab";
    let mut store = temp_state_store("private-strand-sidecar");
    // The writer stores the JSON-serialized patch value (a bare string).
    store.save_private_plaintext(realm, strand, "body", "\"author body\"");
    let ctx = MlsDecryptCtx {
        state_store: &store,
        realm_id: realm,
        actor_id: "did:web:alice.example",
        device_id: "ck:device:01904100-0000-7000-8000-000000000001",
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
            "ck:strand:01904100-0000-7000-8000-0000000000cd",
            "body",
            Some(&envelope)
        ),
        ""
    );
}

#[test]
fn private_strand_empty_sidecar_does_not_mask_encrypted_locked_state() {
    let realm = "ck:realm:01904100-0000-7000-8000-000000000001";
    let strand = "ck:strand:01904100-0000-7000-8000-0000000000ab";
    let mut store = temp_state_store("private-strand-empty-sidecar");
    store.save_private_plaintext(realm, strand, "synthesis", "\"\"");
    let ctx = MlsDecryptCtx {
        state_store: &store,
        realm_id: realm,
        actor_id: "did:web:alice.example",
        device_id: "ck:device:01904100-0000-7000-8000-000000000001",
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
    let realm = "ck:realm:01904100-0000-7000-8000-000000000000";
    let strand = "ck:strand:01904100-0000-7000-8000-0000000000ab";
    let mut store = temp_state_store("card-builder-sidecar");
    store.save_private_plaintext(realm, strand, "body", "\"recovered body\"");
    let ctx = MlsDecryptCtx {
        state_store: &store,
        realm_id: realm,
        actor_id: "did:web:alice.example",
        device_id: "ck:device:01904100-0000-7000-8000-000000000001",
    };
    let strand_view = crate::api::StrandProjectionView {
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
        updated_at: None,
        state: "active".to_owned(),
    };
    let card = card_from_strand_projection(&strand_view, Some(&ctx));
    assert_eq!(card.body, "recovered body");
    // Sanity: there is genuinely no MLS group to decrypt from.
    assert!(store.mls_snapshot_for(realm).is_none());
}

/// T20 wire-up — `collection_projection_to_columns` adapter maps the
/// spec-registered `collection_projection_view` response
/// (`view.schema.json`) into the renderer's KanbanColumn vec. This
/// is the core integration point; if the spec wire shape changes,
/// this test fails and points at the renderer adapter.
#[test]
fn collection_projection_maps_to_kanban_columns() {
    use crate::api::{
        CollectionProjectionGroupView, CollectionProjectionView, ProjectionItemView,
        StateFrontierView,
    };
    let projection = CollectionProjectionView {
        projection: "collection".to_owned(),
        renderer: Some("board".to_owned()),
        view_id: "ck:view:01904100-0000-7000-8000-000000000001".to_owned(),
        realm_id: None,
        frontier: StateFrontierView {
            state_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_owned(),
            event_ids: vec!["ck:event:01904100-0000-7000-8000-000000000042".to_owned()],
            actor_frontiers: Vec::new(),
        },
        groups: vec![
            CollectionProjectionGroupView {
                key: "ck:space:01c3b617-7000-7000-8000-000000000000".to_owned(),
                title: "Review".to_owned(),
                rank: Some("mV".to_owned()),
                source: None,
                items: vec![ProjectionItemView {
                    object: serde_json::json!({
                        "id": "ck:strand:01d2b330-0000-7000-8000-000000000000",
                        "type": "strand",
                        "title": "Legal review",
                        "summary": "ensure GDPR sign-off",
                        "body": {
                            "kind": "ck.content.text",
                            "body": "Review processor wording before beta."
                        },
                    }),
                    render: None,
                    display: None,
                    position: None,
                    state: Some(serde_json::json!({
                        "discussion": {
                            "enabled": true,
                            "visibility": "locked",
                            "lazy_link": true,
                        }
                    })),
                }],
                next_cursor: None,
                limited: false,
                wip_state: None,
                total_estimate: None,
            },
            CollectionProjectionGroupView {
                key: "ck:space:01t0d0000000000000000000000".to_owned(),
                title: "To do".to_owned(),
                rank: Some("aA".to_owned()),
                source: None,
                items: Vec::new(),
                next_cursor: None,
                limited: false,
                wip_state: None,
                total_estimate: None,
            },
        ],
        items: Vec::new(),
        next_cursor: None,
        total_estimate: None,
        stale: None,
    };

    let cols = collection_projection_to_columns(&projection, None);
    assert_eq!(cols.len(), 2, "two groups → two columns");
    assert_eq!(cols[0].id, "ck:space:01c3b617-7000-7000-8000-000000000000");
    assert_eq!(cols[0].title, "Review");
    assert_eq!(cols[0].rank, "mV");
    assert_eq!(cols[0].cards.len(), 1);
    let card = &cols[0].cards[0];
    assert_eq!(card.id, "ck:strand:01d2b330-0000-7000-8000-000000000000");
    assert_eq!(card.title, "Legal review");
    assert_eq!(card.description, "ensure GDPR sign-off");
    assert_eq!(card.body, "Review processor wording before beta.");
    // Locked discussion + lazy_link should populate locked_strand
    // and the cross-Space hint without leaking room contents.
    assert!(
        card.locked_strand.is_some(),
        "locked discussion → LockedStrand"
    );
    assert_eq!(
        card.history_visibility, "lazy_link (cross-Space)",
        "lazy_link=true must be reflected without exposing members"
    );
    assert!(matches!(card.state, CardState::Synced));
    // Empty group still produces an empty-cards column (board renders it).
    assert_eq!(cols[1].cards.len(), 0);
}

#[test]
fn collection_projection_overlay_applies_remote_encrypted_strand_updates() {
    use crate::api::{
        CollectionProjectionGroupView, CollectionProjectionView, ProjectionItemView,
        StateFrontierView,
    };
    let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
    let strand_id = "ck:strand:0196419b-0000-7000-8000-000000000003";
    let projection = CollectionProjectionView {
        projection: "collection".to_owned(),
        renderer: Some("board".to_owned()),
        view_id: "ck:view:01904100-0000-7000-8000-000000000001".to_owned(),
        realm_id: None,
        frontier: StateFrontierView::default(),
        groups: vec![CollectionProjectionGroupView {
            key: board_id.to_owned(),
            title: "Todo".to_owned(),
            rank: Some("U".to_owned()),
            source: None,
            items: vec![ProjectionItemView {
                object: json!({
                    "id": strand_id,
                    "type": "strand",
                    "title": "Encrypted card",
                }),
                render: None,
                display: None,
                position: None,
                state: None,
            }],
            next_cursor: None,
            limited: false,
            wip_state: None,
            total_estimate: None,
        }],
        items: Vec::new(),
        next_cursor: None,
        total_estimate: None,
        stale: None,
    };
    let envelope = json!({
        "scheme": "mls-rfc9420",
        "ciphertext": "AAAA",
        "content_type": KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
        "group_id": "g",
        "epoch": 0,
    });
    let events = vec![json!({
        "event_id": "ck:event:0196419b-0000-7000-8000-00000000f003",
        "operation_id": "ck:operation:0196419b-0000-7000-8000-00000000f003",
        "event_kind": "ck.strand.update",
        "actor_id": "did:web:alice.example",
        "created_at": "2026-05-22T10:00:00Z",
        "realm_id": TEST_REALM_ID,
        "payload": {
            "strand_id": strand_id,
            "patch": {
                "body": { "$op": "set", "value": envelope.clone() },
                "synthesis": { "$op": "set", "value": envelope }
            }
        }
    })];
    let remote_operations = strand_update_operations_from_events(&events);
    let store = LocalStateStore::default();
    let ctx = MlsDecryptCtx {
        state_store: &store,
        realm_id: TEST_REALM_ID,
        actor_id: "did:web:alice.example",
        device_id: "ck:device:0196419b-0000-7000-8000-000000000001",
    };

    let cols = overlay_collection_projection_with_operations(
        &projection,
        &store,
        board_id,
        &remote_operations,
        Some(&ctx),
    );

    let card = &cols[0].cards[0];
    assert_eq!(card.body, "");
    assert!(card.body_locked);
    assert_eq!(card.synthesis, "");
    assert!(card.synthesis_locked);
}

/// T20 — when no `state.discussion` metadata is present on the
/// registered projection item, the card renders as synthesis-only
/// without a locked_strand.
#[test]
fn projection_item_without_discussion_renders_synthesis_only() {
    use crate::api::ProjectionItemView;
    let item = ProjectionItemView {
        object: serde_json::json!({
            "id": "ck:strand:01doc",
            "title": "DID method allowlist",
        }),
        render: None,
        display: None,
        position: None,
        state: None,
    };
    let card = card_from_projection_item(&item, None);
    assert!(card.locked_strand.is_none());
    assert_eq!(card.history_visibility, "synthesis-only");
    assert_eq!(card.external_visibility, "No external discussions linked");
}

#[test]
fn board_space_options_pick_board_spaces_from_projection() {
    let options = board_space_options_from_projection(&[
        crate::api::SpaceContainerProjectionView {
            space_id: "ck:space:0196419b-0000-7000-8000-000000000001".to_owned(),
            realm_id: "ck:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
            kind: "board".to_owned(),
            title: "Release".to_owned(),
            state: "active".to_owned(),
            rank: None,
            parent_space_id: None,
        },
        crate::api::SpaceContainerProjectionView {
            space_id: "ck:space:0196419b-0000-7000-8000-000000000002".to_owned(),
            realm_id: "ck:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
            kind: "list".to_owned(),
            title: "Todo".to_owned(),
            state: "active".to_owned(),
            rank: Some("U".to_owned()),
            parent_space_id: Some("ck:space:0196419b-0000-7000-8000-000000000001".to_owned()),
        },
    ]);

    assert_eq!(options.len(), 1);
    assert_eq!(
        options[0].id,
        "ck:space:0196419b-0000-7000-8000-000000000001"
    );
    assert_eq!(options[0].title, "Release");
}

#[test]
fn local_space_create_overlay_restores_board_and_list_until_projection_catches_up() {
    let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
    let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
    let list_id = "ck:space:0196419b-0000-7000-8000-000000000002";
    let raw_operations = vec![
        RawOperationRecord {
            operation_id: "sha256:local-board-create".to_owned(),
            realm_id: Some(realm_id.to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ck.space.create",
                "operation_id": "sha256:local-board-create",
                "body": {
                    "object": {
                        "id": board_id,
                        "schema": "ck.schema.space.v1",
                        "realm_id": realm_id,
                        "kind": "board",
                        "title": "Design board"
                    }
                },
                "write_state": "queued"
            }),
        },
        RawOperationRecord {
            operation_id: "sha256:local-list-create".to_owned(),
            realm_id: Some(realm_id.to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ck.space.create",
                "operation_id": "sha256:local-list-create",
                "body": {
                    "object": {
                        "id": list_id,
                        "schema": "ck.schema.space.v1",
                        "realm_id": realm_id,
                        "kind": "list",
                        "title": "Todo",
                        "parent_space_id": board_id,
                        "rank": "U"
                    }
                },
                "write_state": "queued"
            }),
        },
    ];

    let (columns, options, selected_board) = columns_from_lifecycle_projection_with_local(
        &[],
        &[],
        board_id,
        &raw_operations,
        realm_id,
        None,
    );

    assert_eq!(selected_board.as_deref(), Some(board_id));
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].id, board_id);
    assert_eq!(options[0].title, "Design board");
    assert_eq!(columns.len(), 1);
    assert_eq!(columns[0].id, list_id);
    assert_eq!(columns[0].title, "Todo");
}

#[test]
fn remote_space_create_backfill_restores_board_title_when_projection_only_has_list() {
    let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
    let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
    let list_id = "ck:space:0196419b-0000-7000-8000-000000000002";
    let events = vec![json!({
        "event_id": "ck:event:0196419b-0000-7000-8000-000000000101",
        "event_kind": "ck.space.create",
        "realm_id": realm_id,
        "actor_id": "did:web:alice.example",
        "created_at": "2026-05-31T00:00:00Z",
        "payload": {
            "object": {
                "id": board_id,
                "schema": "ck.schema.space.v1",
                "realm_id": realm_id,
                "kind": "board",
                "title": "Board"
            }
        }
    })];
    let remote_operations = space_create_operations_from_events(&events);
    let containers = vec![crate::api::SpaceContainerProjectionView {
        space_id: list_id.to_owned(),
        realm_id: realm_id.to_owned(),
        kind: "list".to_owned(),
        title: "Todos".to_owned(),
        state: "active".to_owned(),
        rank: Some("U".to_owned()),
        parent_space_id: Some(board_id.to_owned()),
    }];

    let (columns, options, selected_board) = columns_from_lifecycle_projection_with_local(
        &containers,
        &[],
        board_id,
        &remote_operations,
        realm_id,
        None,
    );

    assert_eq!(selected_board.as_deref(), Some(board_id));
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].id, board_id);
    assert_eq!(options[0].title, "Board");
    assert_eq!(columns.len(), 1);
    assert_eq!(columns[0].title, "Todos");
}

#[test]
fn local_space_create_state_becomes_synced_once_projection_contains_target() {
    let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
    let raw_operations = vec![RawOperationRecord {
        operation_id: "sha256:local-board-create".to_owned(),
        realm_id: Some("ck:realm:0196419b-0000-7000-8000-000000000000".to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ck.space.create",
            "operation_id": "sha256:local-board-create",
            "body": {
                "object": {
                    "id": board_id,
                    "schema": "ck.schema.space.v1",
                    "kind": "board",
                    "title": "Design board"
                }
            },
            "write_state": "queued"
        }),
    }];
    let projected_ids = BTreeSet::from([board_id.to_owned()]);

    let state = local_space_create_state_for_target(&raw_operations, &projected_ids, board_id);

    assert_eq!(state, Some(CardState::Synced));
}

#[test]
fn displayed_card_state_uses_server_strand_projection_over_local_queue() {
    let strand_id = "ck:strand:0196419b-0000-7000-8000-000000000003";
    let mut card = test_card(strand_id, "U");
    card.state = CardState::Queued;
    let projected_strand_ids = BTreeSet::from([strand_id.to_owned()]);

    assert_eq!(
        displayed_card_state(&card, &projected_strand_ids),
        CardState::Synced
    );
}

#[test]
fn lifecycle_projection_builds_persisted_board_columns_and_cards() {
    let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
    let list_id = "ck:space:0196419b-0000-7000-8000-000000000002";
    let containers = vec![
        crate::api::SpaceContainerProjectionView {
            space_id: board_id.to_owned(),
            realm_id: "ck:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
            kind: "board".to_owned(),
            title: "Release".to_owned(),
            state: "active".to_owned(),
            rank: None,
            parent_space_id: None,
        },
        crate::api::SpaceContainerProjectionView {
            space_id: list_id.to_owned(),
            realm_id: "ck:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
            kind: "list".to_owned(),
            title: "Todo".to_owned(),
            state: "active".to_owned(),
            rank: Some("U".to_owned()),
            parent_space_id: Some(board_id.to_owned()),
        },
    ];
    let strands = vec![crate::api::StrandProjectionView {
        strand_id: "ck:strand:0196419b-0000-7000-8000-000000000003".to_owned(),
        realm_id: "ck:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
        title: "Persisted card".to_owned(),
        summary: Some("Loaded from projection".to_owned()),
        body: Some(json!({
            "kind": "ck.content.text",
            "body": "Projection body content"
        })),
        board_space_id: Some(board_id.to_owned()),
        list_space_id: Some(list_id.to_owned()),
        rank: Some("U".to_owned()),
        assigned_actor_ids: vec!["did:web:alice.example".to_owned()],
        assigned_to_relations: vec![crate::api::AssignedToRelationProjectionView {
            relation_id: "ck:relation:0196419b-0000-7000-8000-000000000004".to_owned(),
            actor_id: "did:web:alice.example".to_owned(),
        }],
        fields: Map::from_iter([
            ("labels".to_owned(), json!(["demo", "db"])),
            ("due_at".to_owned(), json!("2026-05-22")),
        ]),
        created_by: Some("did:web:acme.example:users:alice".to_owned()),
        created_at: Some("2026-05-22T10:00:00Z".to_owned()),
        updated_at: None,
        state: "active".to_owned(),
    }];

    let (columns, options, selected_board) =
        columns_from_lifecycle_projection(&containers, &strands, "", None);

    assert_eq!(selected_board.as_deref(), Some(board_id));
    assert_eq!(options.len(), 1);
    assert_eq!(columns.len(), 1);
    assert_eq!(columns[0].title, "Todo");
    assert_eq!(columns[0].cards.len(), 1);
    let card = &columns[0].cards[0];
    assert_eq!(card.title, "Persisted card");
    assert_eq!(card.description, "Loaded from projection");
    assert_eq!(card.body, "Projection body content");
    assert_eq!(card.labels, vec!["demo".to_owned(), "db".to_owned()]);
    assert_eq!(card.assignee, "did:web:alice.example");
    assert_eq!(
        card.assigned_to_relations,
        vec![CardAssignedToRelation {
            relation_id: "ck:relation:0196419b-0000-7000-8000-000000000004".to_owned(),
            actor_id: "did:web:alice.example".to_owned(),
        }]
    );
    assert_eq!(card.due, "2026-05-22");
}

#[test]
fn lifecycle_projection_infers_board_from_list_parent() {
    let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
    let list_id = "ck:space:0196419b-0000-7000-8000-000000000002";
    let containers = vec![crate::api::SpaceContainerProjectionView {
        space_id: list_id.to_owned(),
        realm_id: "ck:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
        kind: "list".to_owned(),
        title: "Todo".to_owned(),
        state: "active".to_owned(),
        rank: Some("U".to_owned()),
        parent_space_id: Some(board_id.to_owned()),
    }];

    let (columns, options, selected_board) =
        columns_from_lifecycle_projection(&containers, &[], "", None);

    assert_eq!(selected_board.as_deref(), Some(board_id));
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].id, board_id);
    assert_eq!(columns.len(), 1);
    assert_eq!(columns[0].id, list_id);
    assert_eq!(columns[0].title, "Todo");
}

#[test]
fn local_strand_create_overlay_restores_card_until_projection_catches_up() {
    let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
    let list_id = "ck:space:0196419b-0000-7000-8000-000000000002";
    let strand_id = "ck:strand:0196419b-0000-7000-8000-000000000003";
    let raw_operations = vec![RawOperationRecord {
        operation_id: "sha256:local-create".to_owned(),
        realm_id: Some("ck:realm:0196419b-0000-7000-8000-000000000000".to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ck.strand.create",
            "operation_id": "sha256:local-create",
            "effect": {
                "strand_id": strand_id,
                "board_space_id": board_id,
                "list_space_id": list_id,
                "title": "Refresh-surviving card",
                "rank": "U",
                "strand_kind": "card"
            },
            "write_state": "queued"
        }),
    }];
    let projected_columns = vec![KanbanColumn {
        id: list_id.to_owned(),
        title: "Todo".to_owned(),
        rank: "U".to_owned(),
        cards: Vec::new(),
        state: SpaceContainerLifecycleState::Active,
    }];

    let overlaid =
        overlay_local_card_create_records(projected_columns.clone(), &raw_operations, board_id);
    assert_eq!(overlaid[0].cards.len(), 1);
    assert_eq!(overlaid[0].cards[0].id, strand_id);
    assert_eq!(overlaid[0].cards[0].title, "Refresh-surviving card");
    assert_eq!(overlaid[0].cards[0].state, CardState::Queued);

    let overlaid_again =
        overlay_local_card_create_records(overlaid.clone(), &raw_operations, board_id);
    assert_eq!(
        overlaid_again[0].cards.len(),
        1,
        "overlay must be idempotent across repeated projection refreshes"
    );

    let mut projected_with_server_card = projected_columns;
    projected_with_server_card[0]
        .cards
        .push(test_card(strand_id, "U"));
    let de_duped =
        overlay_local_card_create_records(projected_with_server_card, &raw_operations, board_id);
    assert_eq!(
        de_duped[0].cards.len(),
        1,
        "server projection wins once the reducer has materialized the card"
    );
    assert_eq!(de_duped[0].cards[0].state, CardState::Synced);
}

#[test]
fn remote_strand_update_events_overlay_detail_fields_on_projection() {
    let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
    let strand_id = "ck:strand:0196419b-0000-7000-8000-000000000003";
    let mut card = test_card(strand_id, "U");
    card.description = "old summary".to_owned();
    card.body = String::new();
    card.synthesis = String::new();
    let columns = vec![KanbanColumn {
        id: "ck:space:0196419b-0000-7000-8000-000000000002".to_owned(),
        title: "Todo".to_owned(),
        rank: "U".to_owned(),
        cards: vec![card],
        state: SpaceContainerLifecycleState::Active,
    }];
    let events = vec![json!({
        "event_id": "ck:event:0196419b-0000-7000-8000-00000000f001",
        "operation_id": "ck:operation:0196419b-0000-7000-8000-00000000f001",
        "event_kind": "ck.strand.update",
        "actor_id": "did:web:alice.example",
        "created_at": "2026-05-22T10:00:00Z",
        "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
        "payload": {
            "strand_id": strand_id,
            "patch": {
                "metadata.summary": { "$op": "set", "value": "new summary" },
                "fields.body": { "$op": "set", "value": "new long description" },
                "tracks.synthesis.body": { "$op": "set", "value": "new synthesis note" },
                "metadata.fields": {
                    "$op": "set",
                    "value": {
                        "labels": ["remote"],
                        "due_at": "2026-05-30"
                    }
                }
            }
        }
    })];
    let remote_operations = strand_update_operations_from_events(&events);

    let projected = overlay_card_projection_with_operations(
        columns,
        &LocalStateStore::default(),
        board_id,
        &remote_operations,
    );

    let card = &projected[0].cards[0];
    assert_eq!(card.description, "new summary");
    assert_eq!(card.body, "new long description");
    assert_eq!(card.synthesis, "new synthesis note");
    assert_eq!(card.labels, vec!["remote"]);
    assert_eq!(card.due, "2026-05-30");
    assert_eq!(card.state, CardState::Synced);
}

#[test]
fn remote_encrypted_strand_update_overlay_marks_private_fields_locked() {
    let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
    let strand_id = "ck:strand:0196419b-0000-7000-8000-000000000003";
    let mut card = test_card(strand_id, "U");
    card.body = String::new();
    card.synthesis = String::new();
    let columns = vec![KanbanColumn {
        id: "ck:space:0196419b-0000-7000-8000-000000000002".to_owned(),
        title: "Todo".to_owned(),
        rank: "U".to_owned(),
        cards: vec![card],
        state: SpaceContainerLifecycleState::Active,
    }];
    let envelope = json!({
        "scheme": "mls-rfc9420",
        "ciphertext": "AAAA",
        "content_type": KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
        "group_id": "g",
        "epoch": 0,
    });
    let events = vec![json!({
        "event_id": "ck:event:0196419b-0000-7000-8000-00000000f002",
        "operation_id": "ck:operation:0196419b-0000-7000-8000-00000000f002",
        "event_kind": "ck.strand.update",
        "actor_id": "did:web:alice.example",
        "created_at": "2026-05-22T10:00:00Z",
        "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
        "payload": {
            "strand_id": strand_id,
            "patch": {
                "body": { "$op": "set", "value": envelope.clone() },
                "tracks.synthesis.body": { "$op": "set", "value": {
                    "encrypted_content": envelope
                } }
            }
        }
    })];
    let remote_operations = strand_update_operations_from_events(&events);
    let store = LocalStateStore::default();
    let ctx = MlsDecryptCtx {
        state_store: &store,
        realm_id: TEST_REALM_ID,
        actor_id: "did:web:alice.example",
        device_id: "ck:device:0196419b-0000-7000-8000-000000000001",
    };

    let projected = overlay_card_projection_with_operations_and_decrypt(
        columns,
        &store,
        board_id,
        &remote_operations,
        Some(&ctx),
    );

    let card = &projected[0].cards[0];
    assert_eq!(card.body, "");
    assert!(card.body_locked);
    assert_eq!(card.synthesis, "");
    assert!(card.synthesis_locked);
    assert_eq!(card.state, CardState::Synced);
}

#[test]
fn kanban_seed_fallback_requires_explicit_opt_in() {
    assert!(!kanban_seed_fallback_allowed_for_url("https://local.host"));
    assert!(!kanban_seed_fallback_allowed_for_url(
        "http://127.0.0.1:8787"
    ));
    assert!(!kanban_seed_fallback_allowed_for_url(
        "https://cokret.example"
    ));
    assert!(truthy_env_value(Some("1")));
    assert!(truthy_env_value(Some("true")));
    assert!(!truthy_env_value(Some("0")));
    assert!(!truthy_env_value(None));
}

#[test]
fn parse_card_labels_trims_and_deduplicates() {
    assert_eq!(
        parse_card_labels(" release, ops, release, ,OPS "),
        vec!["release".to_owned(), "ops".to_owned()]
    );
}

#[test]
fn due_calendar_parses_date_and_rfc3339_values() {
    assert_eq!(
        parse_due_calendar_date("2026-06-09"),
        Some(NaiveDate::from_ymd_opt(2026, 6, 9).unwrap())
    );
    assert_eq!(
        parse_due_calendar_date("2026-06-09T18:30:00Z"),
        Some(NaiveDate::from_ymd_opt(2026, 6, 9).unwrap())
    );
    assert_eq!(parse_due_calendar_date("unscheduled"), None);
}

#[test]
fn due_calendar_month_navigation_crosses_years() {
    let jan_2026 = NaiveDate::from_ymd_opt(2026, 1, 17).unwrap();
    assert_eq!(
        add_due_calendar_months(jan_2026, -1),
        NaiveDate::from_ymd_opt(2025, 12, 1).unwrap()
    );
    let dec_2026 = NaiveDate::from_ymd_opt(2026, 12, 9).unwrap();
    assert_eq!(
        add_due_calendar_months(dec_2026, 1),
        NaiveDate::from_ymd_opt(2027, 1, 1).unwrap()
    );
}

#[test]
fn due_calendar_cells_cover_sunday_first_six_week_grid() {
    let month = NaiveDate::from_ymd_opt(2026, 6, 1).unwrap();
    let cells = due_calendar_cells(month);
    assert_eq!(cells.len(), 42);
    assert_eq!(cells.first().unwrap().iso_date, "2026-05-31");
    assert_eq!(cells[1].iso_date, "2026-06-01");
    assert_eq!(cells.last().unwrap().iso_date, "2026-07-11");
    assert!(!cells[0].in_current_month);
    assert!(cells[1].in_current_month);
    assert!(!cells.last().unwrap().in_current_month);
}

#[test]
fn card_activity_items_show_local_strand_and_assignment_writes() {
    let mut card = test_card("ck:strand:activity", "U");
    card.primary_strand_id = card.id.clone();
    let received_at = |value: &str| {
        chrono::DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&chrono::Utc)
    };
    let raw_operations = vec![
        RawOperationRecord {
            operation_id: "op-assignee".to_owned(),
            realm_id: Some(TEST_REALM_ID.to_owned()),
            received_at: received_at("2026-06-10T10:00:00Z"),
            payload: json!({
                "kind": "ck.relation.tombstone",
                "operation_id": "op-assignee",
                "write_state": "accepted",
                "assignment_strand_id": card.id.clone(),
                "assignment_actor_id": "did:web:alice.example",
                "assignment_relation_id": "ck:relation:activity",
                "activity_summary": "Assignee removed: alice",
                "body": {
                    "relation_id": "ck:relation:activity"
                }
            }),
        },
        RawOperationRecord {
            operation_id: "op-due".to_owned(),
            realm_id: Some(TEST_REALM_ID.to_owned()),
            received_at: received_at("2026-06-10T11:00:00Z"),
            payload: json!({
                "kind": "ck.strand.update",
                "operation_id": "op-due",
                "write_state": "queued",
                "activity_summary": "Due date cleared",
                "body": {
                    "strand_id": card.id.clone(),
                    "patch": {
                        "metadata.fields": {
                            "$op": "set",
                            "value": { "labels": [] }
                        }
                    }
                }
            }),
        },
    ];

    let items = card_activity_items(&card, &raw_operations);
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].title, "Due date cleared");
    assert_eq!(items[0].status, CardActivityStatus::Pending);
    assert_eq!(items[1].title, "Assignee removed: alice");
    assert_eq!(items[1].status, CardActivityStatus::Accepted);
}

#[test]
fn card_detail_update_patch_uses_strand_update_patch_paths() {
    let mut current = test_card("ck:strand:f1", "U");
    current.title = "Old".to_owned();
    current.description = "old summary".to_owned();
    current.labels = vec!["old".to_owned()];
    current.assignee = "did:web:bob.example".to_owned();
    current.due = "2026-05-19".to_owned();
    let draft = CardDetailDraft {
        title: "Launch checklist".to_owned(),
        description: "Ship blockers only".to_owned(),
        body: String::new(),
        synthesis: String::new(),
        labels: vec!["release".to_owned(), "ops".to_owned()],
        assignee: "did:web:alice.example".to_owned(),
        due: "2026-05-20".to_owned(),
    };

    let patch = card_detail_update_patch(&current, &draft).unwrap();
    assert_eq!(patch["metadata.title"]["value"], "Launch checklist");
    assert_eq!(patch["metadata.summary"]["value"], "Ship blockers only");
    assert_eq!(patch["metadata.fields"]["value"]["labels"][0], "release");
    assert!(patch["metadata.fields"]["value"].get("assignee").is_none());
    assert_eq!(patch["metadata.fields"]["value"]["due_at"], "2026-05-20");
    assert!(patch["metadata.fields"]["value"].get("due").is_none());
}

#[test]
fn relation_id_from_event_id_retags_assignment_relation_ids() {
    assert_eq!(
        relation_id_from_event_id("ck:event:0196419b-0000-7000-8000-000000000004").as_deref(),
        Some("ck:relation:0196419b-0000-7000-8000-000000000004")
    );
    assert!(relation_id_from_event_id("ck:message:bad").is_none());
}

#[test]
fn card_assignment_mutations_create_and_tombstone_relation_events() {
    let mut current = test_card("ck:strand:0196419b-0000-7000-8000-000000000101", "U");
    current.assignee = "did:web:bob.example".to_owned();
    current.assigned_to_relations = vec![CardAssignedToRelation {
        relation_id: "ck:relation:0196419b-0000-7000-8000-0000000000bb".to_owned(),
        actor_id: "did:web:bob.example".to_owned(),
    }];
    let selected = BTreeSet::from(["did:web:alice.example".to_owned()]);

    let mutations = card_assignment_mutations(
        "ck:realm:0196419b-0000-7000-8000-000000000000",
        "did:web:owner.example",
        &current,
        &selected,
    )
    .unwrap();

    assert_eq!(mutations.len(), 2);
    let create = mutations
        .iter()
        .find(|mutation| matches!(mutation, CardAssignmentMutation::Create { .. }))
        .expect("create mutation");
    assert_eq!(create.actor_id(), "did:web:alice.example");
    assert_eq!(create.operation().kind, "ck.relation.create");
    assert_eq!(create.operation().payload["kind"], json!("assigned_to"));
    assert_eq!(create.operation().payload["from_ref"], json!(current.id));
    assert_eq!(
        create.operation().payload["to_ref"],
        json!("did:web:alice.example")
    );
    assert!(create.operation().payload.get("relation_id").is_none());

    let tombstone = mutations
        .iter()
        .find(|mutation| matches!(mutation, CardAssignmentMutation::Tombstone { .. }))
        .expect("tombstone mutation");
    assert_eq!(
        tombstone.relation_id(),
        "ck:relation:0196419b-0000-7000-8000-0000000000bb"
    );
    assert_eq!(tombstone.operation().kind, "ck.relation.tombstone");
    assert_eq!(
        tombstone.operation().payload["relation_id"],
        json!("ck:relation:0196419b-0000-7000-8000-0000000000bb")
    );

    let after = assignment_relations_after_mutations(&current, &selected, &mutations);
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].actor_id, "did:web:alice.example");
    assert!(after[0].relation_id.starts_with("ck:relation:"));
}

#[test]
fn card_assignment_mutations_clear_all_assignees() {
    let mut current = test_card("ck:strand:0196419b-0000-7000-8000-000000000101", "U");
    current.assigned_to_relations = vec![
        CardAssignedToRelation {
            relation_id: "ck:relation:0196419b-0000-7000-8000-0000000000aa".to_owned(),
            actor_id: "did:web:alice.example".to_owned(),
        },
        CardAssignedToRelation {
            relation_id: "ck:relation:0196419b-0000-7000-8000-0000000000bb".to_owned(),
            actor_id: "did:web:bob.example".to_owned(),
        },
    ];

    let selected = BTreeSet::new();
    let mutations = card_assignment_mutations(
        "ck:realm:0196419b-0000-7000-8000-000000000000",
        "did:web:owner.example",
        &current,
        &selected,
    )
    .unwrap();

    assert_eq!(mutations.len(), 2);
    assert!(
        mutations
            .iter()
            .all(|mutation| matches!(mutation, CardAssignmentMutation::Tombstone { .. }))
    );
    assert!(assignment_relations_after_mutations(&current, &selected, &mutations).is_empty());
}

#[test]
fn encrypted_scope_blocks_plaintext_strand_update_payload() {
    let event = crate::operation::ck_ops::strand_update_patch(
        TEST_REALM_ID,
        "did:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        json!({
            "body": {"$op": "set", "value": "private description"},
        }),
    )
    .expect("builds")
    .build("yougen");

    assert!(kanban_event_carries_plaintext_private_content(&event));
    let reason = kanban_plaintext_block_reason(Some(true), &event).unwrap();
    assert!(reason.contains("Encrypted Realm blocks plaintext ck.strand.update"));
    assert!(kanban_plaintext_block_reason(Some(false), &event).is_none());
}

/// R4 fail-closed: when the Realm security state is UNKNOWN (`None`, i.e.
/// the security projection has not synced yet) the guard MUST block a
/// plaintext private-content write rather than defaulting to plaintext.
/// A known-plaintext Realm (`Some(false)`) is the legitimate case that
/// MUST still be allowed — that is what keeps fail-closed from breaking
/// normal plaintext strands.
#[test]
fn unknown_scope_security_blocks_plaintext_private_content_fail_closed() {
    let private_update = crate::operation::ck_ops::strand_update_patch(
        TEST_REALM_ID,
        "did:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        json!({
            "body": {"$op": "set", "value": "private description"},
        }),
    )
    .expect("builds")
    .build("yougen");
    assert!(kanban_event_carries_plaintext_private_content(
        &private_update
    ));
    // Unknown security state → fail-closed block.
    assert!(
        kanban_plaintext_block_reason(None, &private_update).is_some(),
        "unknown security state must fail closed for plaintext private content"
    );
    // Known-plaintext Realm → legitimate plaintext write, never blocked.
    assert!(
        kanban_plaintext_block_reason(Some(false), &private_update).is_none(),
        "known-plaintext Realm must keep allowing plaintext writes"
    );

    // Non-private metadata (container scaffold) is exempt even when the
    // security state is unknown, so board/list creation is not bricked
    // while the projection is in flight.
    let board_create = crate::operation::ck_ops::space_create(
        TEST_REALM_ID,
        "did:web:alice.example",
        "ck:space:00000000-0000-7000-8000-0000000000aa",
        "board",
        "Roadmap",
        None,
        None,
    )
    .expect("builds")
    .build("yougen");
    assert!(
        kanban_plaintext_block_reason(None, &board_create).is_none(),
        "container scaffold metadata must not be blocked by unknown security state"
    );
}

#[test]
fn encrypted_scope_allows_encrypted_strand_update_patch_value() {
    let encrypted_payload = crate::crypto::compose_local_encrypted_message(
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-000000000001",
        "ck:space:0196419b-0000-7000-8000-000000000000",
        "ck:message:kanban-patch-test",
        "private synthesis",
    )
    .expect("test encryption should produce payload")
    .payload;
    let encrypted_payload = serde_json::to_value(encrypted_payload).unwrap();
    let event = crate::operation::ck_ops::strand_update_patch(
        TEST_REALM_ID,
        "did:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        json!({
            "synthesis": {"$op": "set", "value": encrypted_payload},
        }),
    )
    .expect("builds")
    .build("yougen");

    assert!(!kanban_event_carries_plaintext_private_content(&event));
    assert!(kanban_plaintext_block_reason(Some(true), &event).is_none());
}

#[test]
fn private_patch_value_collection_targets_only_content_fields() {
    let patch = json!({
        "summary": {"$op": "set", "value": "metadata is allowed"},
        "body": {"$op": "set", "value": "private body"},
        "synthesis": {"$op": "unset"},
    });

    let values = collect_encryptable_private_patch_values(&patch).unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].0, "body");
    assert_eq!(
        serde_json::from_slice::<Value>(&values[0].1).unwrap(),
        json!("private body")
    );
}

#[test]
fn encrypted_private_patch_without_mls_snapshot_is_blocked_before_queueing() {
    let mut state = temp_state_store("missing-mls");
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let patch = json!({
        "body": {"$op": "set", "value": "private body"},
    });

    let error = encrypt_private_card_detail_patch_values_with_store(
        patch,
        "ck:realm:01904100-0000-7000-8000-000000000001",
        "ck:strand:01904100-0000-7000-8000-0000000000ff",
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-000000000001",
        &mut state,
        &secure,
    )
    .unwrap_err();

    assert!(error.contains("MLS Welcome"));
    assert!(
        state
            .mls_snapshot_for("ck:realm:01904100-0000-7000-8000-000000000001")
            .is_none()
    );
    assert!(state.load().raw_operations.is_empty());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypted_private_patch_creator_bootstraps_initial_mls_snapshot() {
    let actor = "did:web:alice.example";
    let device = "ck:device:01904100-0000-7000-8000-000000000001";
    let realm = "ck:realm:01904100-0000-7000-8000-000000000001";
    let mut state = temp_state_store("creator-bootstrap-mls");
    state.save_realm_tree_projection(
        realm,
        json!({
            "__kind": "realm",
            "owner": actor,
            "summary": {
                "title": "Encrypted Realm",
                "encryption_profile": "mls_rfc9420",
                "owner": actor,
            }
        }),
    );
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let patch = json!({
        "body": {"$op": "set", "value": "private body"},
    });

    let strand_id = "ck:strand:01904100-0000-7000-8000-0000000000ff";
    let (patched, mls_events) = encrypt_private_card_detail_patch_values_with_store(
        patch, realm, strand_id, actor, device, &mut state, &secure,
    )
    .unwrap();

    assert!(state.mls_snapshot_for(realm).is_some());
    // X5.1 — the author's own plaintext is persisted to the local
    // sidecar so a re-projection can render it (the author can never
    // decrypt their own ciphertext).
    assert_eq!(
        state
            .private_plaintext_for(realm, strand_id, "body")
            .as_deref(),
        Some("\"private body\"")
    );
    assert_eq!(
        patched["body"]["value"]["content_type"],
        KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE
    );
    assert!(mls_events.commit.is_none());
    assert!(mls_events.snapshot.is_none());
    // A freshly-created creator group must still produce a one-time
    // ck.mls.genesis event; ordinary application writes ride epoch 0
    // without a per-write commit.
    let genesis = mls_events
        .genesis
        .expect("freshly-created creator group should emit genesis");
    assert_eq!(genesis.kind, "ck.mls.genesis");
    assert_eq!(genesis.payload["epoch"].as_u64(), Some(0));
    assert_eq!(
        genesis.payload["creator_principal_id"].as_str(),
        Some(actor)
    );
    assert!(genesis.payload.get("governance_binding").is_some());
    assert_registered_payload_valid(&genesis);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypted_private_patch_with_ready_snapshot_replaces_plaintext() {
    use cokret_sdk::{CokretMlsIdentity, DeviceId, Did};

    let actor = "did:web:alice.example";
    let device = "ck:device:01904100-0000-7000-8000-000000000001";
    let realm = "ck:realm:01904100-0000-7000-8000-000000000001";
    let mut state = temp_state_store("ready-mls");
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let secret =
        crate::mls::runtime::load_or_create_device_snapshot_secret(&secure, actor, device).unwrap();
    let identity = CokretMlsIdentity::new_basic(
        Did::new(actor.to_owned()).unwrap(),
        DeviceId::new(device.to_owned()).unwrap(),
    )
    .unwrap();
    let group = identity.create_group(realm.as_bytes()).unwrap();
    let record = group.export_state_record().unwrap();
    let mut envelope = crate::mls::persistence::encrypt_state(
        realm,
        &record.group_id,
        record.epoch,
        &serde_json::to_vec(&record).unwrap(),
        &secret,
        b"deterministic-salt",
    );
    state.save_realm_tree_projection(
        realm,
        json!({ "active_profiles": [cokret_sdk::mls::MINIMAL_METADATA_REALM_PROFILE] }),
    );
    envelope.epoch_started_at = chrono::Utc::now() - chrono::Duration::hours(2);
    state.save_mls_snapshot(realm, envelope);
    let patch = json!({
        "body": {"$op": "set", "value": "private body"},
    });

    let strand_id = "ck:strand:01904100-0000-7000-8000-0000000000ff";
    let (patched, mls_events) = encrypt_private_card_detail_patch_values_with_store(
        patch, realm, strand_id, actor, device, &mut state, &secure,
    )
    .unwrap();

    assert_eq!(
        patched["body"]["value"]["content_type"],
        KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE
    );
    assert!(patched["body"]["value"].get("ciphertext").is_some());
    // X5.2 gate — the on-the-wire patch value is an MLS envelope (no
    // plaintext), while the local sidecar now holds the plaintext.
    assert!(value_is_mls_envelope(&patched["body"]["value"]));
    let envelope_str = serde_json::to_string(&patched["body"]["value"]).unwrap();
    assert!(
        !envelope_str.contains("private body"),
        "on-wire envelope must not contain the plaintext"
    );
    assert_eq!(
        state
            .private_plaintext_for(realm, strand_id, "body")
            .as_deref(),
        Some("\"private body\"")
    );
    // The snapshot already existed (not freshly created here), so there is
    // no fresh epoch-0 material and genesis is not emitted on this path.
    assert!(mls_events.genesis.is_none());
    assert!(mls_events.snapshot.is_some());
    let commit = mls_events
        .commit
        .expect("overdue minimal metadata MLS snapshot should emit commit event");
    assert_eq!(commit.kind, "ck.mls.commit");
    assert_registered_payload_valid(&commit);
    assert!(commit.payload.get("group_id").is_none());
    assert!(commit.payload.get("expected_prev_epoch").is_none());
    assert!(commit.payload.get("commit_bytes_b64").is_none());
    assert!(commit.payload.get("preconditions").is_none());
    assert!(commit.payload.get("effects").is_none());
    assert_eq!(
        commit.payload["governance_binding"]["realm_id"],
        json!("ck:realm:01904100-0000-7000-8000-000000000001")
    );
    assert_eq!(
        commit.payload["governance_binding"]["effective_scope"],
        json!({
            "kind": "realm",
            "realm_id": "ck:realm:01904100-0000-7000-8000-000000000001",
        })
    );
    assert_eq!(
        commit.payload["governance_binding"]["membership_frontier"][0],
        json!(commit.event_id)
    );
    assert!(state.load().raw_operations.is_empty());
}

#[test]
fn encrypted_metadata_only_patch_does_not_require_mls_snapshot() {
    let mut state = temp_state_store("metadata-only");
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let patch = json!({
        "summary": {"$op": "set", "value": "metadata summary"},
    });

    let (patched, mls_events) = encrypt_private_card_detail_patch_values_with_store(
        patch.clone(),
        "ck:space:01904100-0000-7000-8000-000000000001",
        "ck:strand:01904100-0000-7000-8000-0000000000ff",
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-000000000001",
        &mut state,
        &secure,
    )
    .unwrap();

    assert_eq!(patched, patch);
    assert!(mls_events.commit.is_none());
    assert!(mls_events.genesis.is_none());
    assert!(state.local_identity_record().is_none());
}

#[test]
fn encrypted_scope_allows_structural_strand_position_update() {
    let event = crate::operation::ck_ops::strand_position_update(
        TEST_REALM_ID,
        "did:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        json!({
            "board_space_id": "ck:space:0196419b-0000-7000-8000-000000000001",
            "list_space_id": "ck:space:0196419b-0000-7000-8000-000000000002",
            "rank": "U",
        }),
    )
    .expect("builds")
    .build("yougen");

    assert_eq!(event.kind, "ck.strand.update");
    assert!(!kanban_event_carries_plaintext_private_content(&event));
    assert!(kanban_plaintext_block_reason(Some(true), &event).is_none());
}

#[test]
fn encrypted_scope_allows_content_only_metadata_create_payloads() {
    let strand = crate::operation::ck_ops::kanban_card_strand_create(
        TEST_REALM_ID,
        "did:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        "ck:space:0196419b-0000-7000-8000-000000000001",
        "ck:space:0196419b-0000-7000-8000-000000000002",
        "private card title",
        "U",
    )
    .expect("builds")
    .build("yougen");
    let space = crate::operation::ck_ops::space_create(
        TEST_REALM_ID,
        "did:web:alice.example",
        "ck:space:0196419b-0000-7000-8000-000000000002",
        "list",
        "private list title",
        Some("ck:space:0196419b-0000-7000-8000-000000000001"),
        Some("U"),
    )
    .expect("builds")
    .build("yougen");

    assert!(kanban_plaintext_block_reason(Some(true), &strand).is_none());
    assert!(kanban_plaintext_block_reason(Some(true), &space).is_none());
}

/// X13 regression: in an encrypted scope, container creation
/// (`ck.space.create` for BOTH board and list) MUST NOT be blocked — the
/// title/kind/parent/rank are non-secret metadata that has to reach the
/// server so a second device can render the real Board/List name. By
/// contrast a `ck.strand.update` carrying plaintext private body MUST stay
/// blocked (only E2EE may leave the client for that field).
#[test]
fn encrypted_scope_never_blocks_container_create_but_blocks_plaintext_private_content() {
    let board = crate::operation::ck_ops::space_create(
        TEST_REALM_ID,
        "did:web:alice.example",
        "ck:space:0196419b-0000-7000-8000-00000000aa01",
        "board",
        "ZZTEST board title",
        None,
        None,
    )
    .expect("builds")
    .build("yougen");
    assert_eq!(board.kind, "ck.space.create");
    assert!(
        kanban_plaintext_block_reason(Some(true), &board).is_none(),
        "encrypted scope must not block board container create"
    );

    let list = crate::operation::ck_ops::space_create(
        TEST_REALM_ID,
        "did:web:alice.example",
        "ck:space:0196419b-0000-7000-8000-00000000aa02",
        "list",
        "Todos list title",
        Some("ck:space:0196419b-0000-7000-8000-00000000aa01"),
        Some("r001"),
    )
    .expect("builds")
    .build("yougen");
    assert_eq!(list.kind, "ck.space.create");
    assert!(
        kanban_plaintext_block_reason(Some(true), &list).is_none(),
        "encrypted scope must not block list container create"
    );

    // Counter-case: plaintext private body in a strand update is still blocked.
    let private_update = crate::operation::ck_ops::strand_update_patch(
        TEST_REALM_ID,
        "did:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        json!({
            "body": {"$op": "set", "value": "private description"},
        }),
    )
    .expect("builds")
    .build("yougen");
    assert!(
        kanban_plaintext_block_reason(Some(true), &private_update).is_some(),
        "encrypted scope must still block plaintext private strand content"
    );
}

#[test]
fn encrypted_scope_allows_strand_summary_metadata_update() {
    let event = crate::operation::ck_ops::strand_update_patch(
        TEST_REALM_ID,
        "did:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        json!({
            "summary": {"$op": "set", "value": "metadata summary"},
        }),
    )
    .expect("builds")
    .build("yougen");

    assert!(!kanban_event_carries_plaintext_private_content(&event));
    assert!(kanban_plaintext_block_reason(Some(true), &event).is_none());
}

#[test]
fn local_card_update_overlay_replays_queued_summary_and_body_on_top_of_projection() {
    // Simulate: server projection returns the pre-edit card; the user
    // had queued a ck.strand.update locally that bumped summary + body.
    // After page refresh, the overlay must re-apply that patch so the
    // user doesn't see their edits silently disappear.
    let mut card = test_card("ck:strand:edit-me", "U");
    card.title = "old title".to_owned();
    card.description = "old summary".to_owned();
    card.body = "old body".to_owned();
    card.synthesis = "old synthesis".to_owned();
    let columns = vec![KanbanColumn {
        id: "ck:space:list-a".to_owned(),
        title: "A".to_owned(),
        rank: "U".to_owned(),
        cards: vec![card],
        state: SpaceContainerLifecycleState::Active,
    }];
    let queued = RawOperationRecord {
        operation_id: "op-1".to_owned(),
        realm_id: Some("ck:realm:r1".to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ck.strand.update",
            "operation_id": "op-1",
            "write_state": "queued",
            "body": {
                "strand_id": "ck:strand:edit-me",
                "patch": {
                    "title": { "$op": "set", "value": "new title" },
                    "summary": { "$op": "set", "value": "new summary" },
                    "body": { "$op": "set", "value": "new body" },
                    "synthesis": { "$op": "set", "value": "new synthesis" },
                },
            },
        }),
    };
    let overlaid = overlay_local_card_update_records(columns, &[queued], None);
    let card = &overlaid[0].cards[0];
    assert_eq!(card.title, "new title");
    assert_eq!(card.description, "new summary");
    assert_eq!(card.body, "new body");
    assert_eq!(card.synthesis, "new synthesis");
    assert_eq!(card.state, CardState::Queued);
}

#[test]
fn overlay_local_card_update_records_clears_due_from_fields_replacement() {
    let mut card = test_card("ck:strand:edit-me", "U");
    card.due = "2026-06-11".to_owned();
    let columns = vec![KanbanColumn {
        id: "ck:space:list-a".to_owned(),
        title: "A".to_owned(),
        rank: "U".to_owned(),
        cards: vec![card],
        state: SpaceContainerLifecycleState::Active,
    }];
    let queued = RawOperationRecord {
        operation_id: "op-clear-due".to_owned(),
        realm_id: Some("ck:realm:r1".to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ck.strand.update",
            "operation_id": "op-clear-due",
            "write_state": "queued",
            "body": {
                "strand_id": "ck:strand:edit-me",
                "patch": {
                    "metadata.fields": {
                        "$op": "set",
                        "value": { "labels": [] }
                    },
                },
            },
        }),
    };
    let overlaid = overlay_local_card_update_records(columns, &[queued], None);
    assert_eq!(overlaid[0].cards[0].due, "—");
}

#[test]
fn card_synthesis_track_entries_preserve_append_history() {
    let mut card = test_card("ck:strand:edit-me", "U");
    card.synthesis = "second synthesis".to_owned();
    card.created_by = "did:web:acme.example:users:alice".to_owned();
    card.created_at = "2026-05-22T09:00:00Z".to_owned();
    card.updated_at = "2026-05-22T11:00:00Z".to_owned();
    let received_at = |value: &str| {
        chrono::DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&chrono::Utc)
    };
    let raw_operations = vec![
        RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ck:realm:r1".to_owned()),
            received_at: received_at("2026-05-22T10:00:00Z"),
            payload: json!({
                "kind": "ck.strand.update",
                "operation_id": "op-1",
                "actor_id": "did:web:acme.example:users:alice",
                "created_at": "2026-05-22T10:00:00Z",
                "write_state": "queued",
                "body": {
                    "strand_id": "ck:strand:edit-me",
                    "patch": {
                        "synthesis": { "$op": "set", "value": "first synthesis" }
                    }
                }
            }),
        },
        RawOperationRecord {
            operation_id: "op-2".to_owned(),
            realm_id: Some("ck:realm:r1".to_owned()),
            received_at: received_at("2026-05-22T11:00:00Z"),
            payload: json!({
                "kind": "ck.strand.update",
                "operation_id": "op-2",
                "actor_id": "did:web:acme.example:users:bob",
                "created_at": "2026-05-22T11:00:00Z",
                "write_state": "queued",
                "body": {
                    "strand_id": "ck:strand:edit-me",
                    "patch": {
                        "synthesis": { "$op": "set", "value": "second synthesis" }
                    }
                }
            }),
        },
    ];

    let entries = card_synthesis_track_entries(&card, &raw_operations, &LocalStateStore::default());
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].body, "second synthesis");
    assert_eq!(entries[0].author_label, "bob:acme.example");
    assert_eq!(entries[0].timestamp_label, "2026-05-22 11:00");
    assert!(entries[0].edited);
    assert_eq!(entries[0].revisions.len(), 2);
    assert_eq!(entries[0].revisions[0].body, "first synthesis");
    assert_eq!(entries[0].revisions[0].author_label, "alice:acme.example");
    assert_eq!(entries[0].revisions[1].body, "second synthesis");
}

#[test]
fn card_synthesis_author_prefers_cached_member_primary_handle() {
    let actor = "did:web:auth.local.host:users:01kth8q1w1f9c9pt3a0zfvf6gb";
    let subject = "did:web:auth.local.host:principals:alice";
    let digest = "sha256:abababababababababababababababababababababababababababababababab";
    let mut card = test_card("ck:strand:edit-me", "U");
    card.synthesis = "wqefqqwf".to_owned();
    card.created_by = actor.to_owned();

    let projection = json!({
        "realm_id": TEST_REALM_ID,
        "members": [{
            "actor_id": actor,
            "membership": "join",
            "subject_id": subject,
            "member_display_state_digest": digest
        }]
    });
    let rows = realm_member_roster(Some(&projection));
    let mut store = temp_state_store("synthesis-primary-handle");
    store.save_member_handle_lookup(
        subject,
        Some(TEST_REALM_ID.to_owned()),
        Some(digest.to_owned()),
        Some("abbc:auth.local.host".to_owned()),
        1,
        None,
        None,
    );
    let context = CardAuthorDisplayContext {
        realm_id: TEST_REALM_ID,
        member_rows: &rows,
    };

    let entries =
        card_synthesis_track_entries_with_author_context(&card, &[], &store, Some(context));

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].author_label, "abbc:auth.local.host");
    assert_ne!(
        entries[0].author_label,
        "01kth8q1w1f9c9pt3a0zfvf6gb:auth.local.host"
    );
}

#[test]
fn synthesis_new_entry_appends_without_replacing_existing_entries() {
    let mut card = test_card("ck:strand:edit-me", "U");
    card.synthesis = join_synthesis_entry_bodies(vec![
        "first active synthesis".to_owned(),
        "second active synthesis".to_owned(),
    ]);

    let entries = card_synthesis_track_entries(&card, &[], &LocalStateStore::default());
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].body, "first active synthesis");
    assert_eq!(entries[1].body, "second active synthesis");

    let updated = synthesis_body_after_entry_edit(&entries, None, "third active synthesis");
    let bodies = split_synthesis_entry_bodies(&updated);
    assert_eq!(
        bodies,
        vec![
            "first active synthesis".to_owned(),
            "second active synthesis".to_owned(),
            "third active synthesis".to_owned(),
        ]
    );
}

#[test]
fn strand_participant_dids_filters_by_target_strand_and_pulls_unique_actors() {
    let ops = vec![
        RawOperationRecord {
            operation_id: "op-a".to_owned(),
            realm_id: Some("ck:realm:r1".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ck.strand.update",
                "body": {
                    "strand_id": "ck:strand:target",
                    "actor_id": "did:web:alice.example",
                },
            }),
        },
        // Same strand, different actor — both should appear.
        RawOperationRecord {
            operation_id: "op-b".to_owned(),
            realm_id: Some("ck:realm:r1".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ck.message.create",
                "body": {
                    "target_ref": "ck:strand:target",
                    // Canonical actor key only; forbidden `sender`
                    // fields are hard-rejected.
                    "actor_id": "did:web:bob.example",
                },
            }),
        },
        // Different strand — must be excluded so we don't bleed
        // unrelated realm actors into the per-card participant list.
        RawOperationRecord {
            operation_id: "op-c".to_owned(),
            realm_id: Some("ck:realm:r1".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ck.strand.update",
                "body": {
                    "strand_id": "ck:strand:other",
                    "actor_id": "did:web:carol.example",
                },
            }),
        },
    ];
    let dids = strand_participant_dids(&ops, "ck:strand:target");
    assert_eq!(
        dids,
        vec![
            "did:web:alice.example".to_owned(),
            "did:web:bob.example".to_owned(),
        ]
    );
    assert!(strand_participant_dids(&ops, "").is_empty());
}

#[test]
fn card_detail_update_patch_emits_body_set_and_unset_ops() {
    let mut current = test_card("ck:strand:f1", "U");
    current.title = "Keep".to_owned();
    current.body = "old long-form body".to_owned();
    let mut draft = card_detail_draft_from_card(&current);
    draft.body = "new long-form body".to_owned();
    let patch = card_detail_update_patch(&current, &draft).unwrap();
    assert_eq!(patch["body"]["$op"], "set");
    assert_eq!(patch["body"]["value"], "new long-form body");

    let mut draft_clear = card_detail_draft_from_card(&current);
    draft_clear.body = String::new();
    let patch = card_detail_update_patch(&current, &draft_clear).unwrap();
    assert_eq!(patch["body"]["$op"], "unset");
}

#[test]
fn card_detail_update_patch_unsets_empty_optional_fields() {
    let mut current = test_card("ck:strand:f1", "U");
    current.title = "Keep".to_owned();
    current.description = "old summary".to_owned();
    current.assignee = "did:web:bob.example".to_owned();
    current.due = "2026-05-19".to_owned();
    let draft = CardDetailDraft {
        title: "Keep".to_owned(),
        description: String::new(),
        body: String::new(),
        synthesis: String::new(),
        labels: Vec::new(),
        assignee: String::new(),
        due: String::new(),
    };

    let patch = card_detail_update_patch(&current, &draft).unwrap();
    assert_eq!(patch["metadata.summary"]["$op"], "unset");
    assert!(patch["metadata.fields"]["value"].get("assignee").is_none());
    assert!(patch["metadata.fields"]["value"].get("due_at").is_none());
}

#[test]
fn apply_card_detail_draft_marks_card_queued() {
    let mut card = test_card("ck:strand:f1", "U");
    let draft = CardDetailDraft {
        title: "New title".to_owned(),
        description: "New summary".to_owned(),
        body: "Body content".to_owned(),
        synthesis: "Synthesis content".to_owned(),
        labels: vec!["ops".to_owned()],
        assignee: String::new(),
        due: "2026-05-20".to_owned(),
    };

    apply_card_detail_draft(&mut card, &draft);
    assert_eq!(card.title, "New title");
    assert_eq!(card.description, "New summary");
    assert_eq!(card.body, "Body content");
    assert_eq!(card.synthesis, "Synthesis content");
    assert_eq!(card.labels, vec!["ops".to_owned()]);
    assert_eq!(card.assignee, "—");
    assert_eq!(card.due, "2026-05-20");
    assert_eq!(card.state, CardState::Queued);
}

/// `relocate_card` is the optimistic local mutation that runs as
/// soon as the user drops a card — before the server sees the
/// Move. It MUST:
///   1. remove the card from the source column,
///   2. assign the new rank,
///   3. insert into the target column such that ascending-rank ordering is preserved (otherwise the
///      next drag uses wrong neighbours for `rank_between`).
#[test]
fn relocate_card_preserves_rank_ordering_after_move() {
    let mut cols = vec![
        KanbanColumn {
            id: "ck:space:list-a".to_owned(),
            title: "A".to_owned(),
            rank: "U".to_owned(),
            cards: vec![
                test_card("ck:strand:a1", "U"),
                test_card("ck:strand:a2", "f"),
            ],
            state: SpaceContainerLifecycleState::Active,
        },
        KanbanColumn {
            id: "ck:space:list-b".to_owned(),
            title: "B".to_owned(),
            rank: "f".to_owned(),
            cards: vec![
                test_card("ck:strand:b1", "U"),
                test_card("ck:strand:b3", "z"),
            ],
            state: SpaceContainerLifecycleState::Active,
        },
    ];
    // Move a1 from A → B, dropped at rank "m" (between b1=U and b3=z).
    let moved = relocate_card(
        &mut cols,
        "ck:strand:a1",
        "ck:space:list-a",
        "ck:space:list-b",
        "m",
    )
    .unwrap();
    assert_eq!(moved.id, "ck:strand:a1");
    assert_eq!(moved.rank, "m");
    // Source column no longer contains a1, still has a2.
    let a = &cols[0];
    assert_eq!(a.cards.len(), 1);
    assert_eq!(a.cards[0].id, "ck:strand:a2");
    // Target column has b1 (U) < a1 (m) < b3 (z), ordering preserved.
    let b = &cols[1];
    assert_eq!(b.cards.len(), 3);
    assert_eq!(b.cards[0].id, "ck:strand:b1");
    assert_eq!(b.cards[1].id, "ck:strand:a1");
    assert_eq!(b.cards[2].id, "ck:strand:b3");
}

/// In-list reorder: removing from a column then re-inserting into
/// the **same** column (target == source) at a new rank should
/// land at the right position.
#[test]
fn relocate_card_handles_in_list_reorder() {
    let mut cols = vec![KanbanColumn {
        id: "ck:space:list-a".to_owned(),
        title: "A".to_owned(),
        rank: "U".to_owned(),
        cards: vec![
            test_card("ck:strand:a1", "U"),
            test_card("ck:strand:a2", "f"),
            test_card("ck:strand:a3", "p"),
        ],
        state: SpaceContainerLifecycleState::Active,
    }];
    // Move a3 to the top of the same list (rank "0" — before "U").
    let moved = relocate_card(
        &mut cols,
        "ck:strand:a3",
        "ck:space:list-a",
        "ck:space:list-a",
        "0",
    )
    .unwrap();
    assert_eq!(moved.rank, "0");
    let a = &cols[0];
    assert_eq!(a.cards.len(), 3);
    assert_eq!(a.cards[0].id, "ck:strand:a3");
    assert_eq!(a.cards[1].id, "ck:strand:a1");
    assert_eq!(a.cards[2].id, "ck:strand:a2");
}

/// `locate_strand_position_in_projection` is the post-conflict rebase
/// adapter — it must find the strand's current cell pre-state from a
/// freshly-fetched projection. When the strand is present with a
/// position, return `At { list_space_id, rank }`; absent ⇒ `Initial`.
#[test]
fn locate_strand_position_finds_present_strand_with_rank() {
    use crate::api::{
        CollectionProjectionGroupView, CollectionProjectionView, ProjectionItemView,
        StateFrontierView,
    };
    let projection = CollectionProjectionView {
        projection: "collection".to_owned(),
        renderer: Some("board".to_owned()),
        view_id: "ck:view:01904100-0000-7000-8000-000000000001".to_owned(),
        realm_id: None,
        frontier: StateFrontierView::default(),
        groups: vec![CollectionProjectionGroupView {
            key: "ck:space:01list-review".to_owned(),
            title: "Review".to_owned(),
            rank: Some("U".to_owned()),
            source: None,
            items: vec![ProjectionItemView {
                object: serde_json::json!({
                    "id": "ck:strand:01wanted",
                    "title": "Find me",
                }),
                render: None,
                display: None,
                // Registered `collection_position` relation model.
                position: Some(serde_json::json!({
                    "model": "relation",
                    "scope_container_id": "ck:space:01board",
                    "container_id": "ck:space:01list-review",
                    "relation_kind": "contains",
                    "relation_id": "ck:relation:01rel",
                    "rank": "h3",
                })),
                state: None,
            }],
            next_cursor: None,
            limited: false,
            wip_state: None,
            total_estimate: None,
        }],
        items: Vec::new(),
        next_cursor: None,
        total_estimate: None,
        stale: None,
    };
    let expected = locate_strand_position_in_projection(&projection, "ck:strand:01wanted");
    assert_eq!(
        expected,
        StrandPositionExpectation::At {
            list_space_id: "ck:space:01list-review".to_owned(),
            rank: "h3".to_owned(),
        }
    );
}

/// When the strand isn't in the projection, the rebase must use
/// `head_eq null` (Initial) — soland's reducer rejects if the cell
/// is actually non-initial, which is the safe behaviour.
#[test]
fn locate_strand_position_missing_strand_returns_initial() {
    use crate::api::{CollectionProjectionView, StateFrontierView};
    let projection = CollectionProjectionView {
        projection: "collection".to_owned(),
        renderer: Some("board".to_owned()),
        view_id: "ck:view:01904100-0000-7000-8000-000000000001".to_owned(),
        realm_id: None,
        frontier: StateFrontierView::default(),
        groups: Vec::new(),
        items: Vec::new(),
        next_cursor: None,
        total_estimate: None,
        stale: None,
    };
    let expected = locate_strand_position_in_projection(&projection, "ck:strand:01missing");
    assert_eq!(expected, StrandPositionExpectation::Initial);
}

/// Helper for `relocate_card` tests — builds a KanbanCard with the
/// supplied id and rank, defaulting the rest of the demo fields.
fn test_card(id: &str, rank: &str) -> KanbanCard {
    KanbanCard {
        id: id.to_owned(),
        rank: rank.to_owned(),
        title: "test".to_owned(),
        description: String::new(),
        body: String::new(),
        synthesis: String::new(),
        body_locked: false,
        synthesis_locked: false,
        created_by: String::new(),
        created_at: String::new(),
        updated_at: String::new(),
        labels: Vec::new(),
        assignee: String::new(),
        assigned_to_relations: Vec::new(),
        due: String::new(),
        primary_strand_id: String::new(),
        locked_strand: None,
        external_visibility: String::new(),
        history_visibility: String::new(),
        security_encrypted: None,
        state: CardState::Synced,
        lifecycle: StrandLifecycleState::Active,
    }
}

#[test]
fn seed_columns_reflect_three_lifecycle_states_for_demo_drift_check() {
    // Seed must include at least one Synced, one Queued (= optimistic
    // queued write) and one Conflict so the kanban demo exercises the
    // full WriteState rendering path. If a refactor changes seeds, fix
    // this test along with the matching screenshot fixtures.
    let cols = seed_columns();
    let mut states: Vec<&'static str> = cols
        .iter()
        .flat_map(|c| c.cards.iter().map(|card| card.state.data_state()))
        .collect();
    states.sort();
    states.dedup();
    assert!(states.contains(&"synced"), "seed missing Synced demo card");
    assert!(states.contains(&"queued"), "seed missing Queued demo card");
    assert!(
        states.contains(&"conflict"),
        "seed missing Conflict demo card"
    );
}

#[test]
fn seed_strand_ids_are_valid_object_patch_targets() {
    for strand_id in [
        DEMO_STRAND_LEGAL_REVIEW_ID,
        DEMO_STRAND_ONBOARDING_COPY_ID,
        DEMO_STRAND_SECURITY_SIGNOFF_ID,
    ] {
        let event = crate::operation::ck_ops::strand_update_patch(
            DEMO_BOARD_SPACE_ID,
            "did:web:acme.example:users:alice",
            strand_id,
            json!({"synthesis": {"$op": "set", "value": "demo synthesis"}}),
        )
        .expect("builds")
        .build("yougen");
        assert_eq!(event.kind, "ck.strand.update");
        assert_eq!(event.local_target_ref(), Some(strand_id));
    }
}
