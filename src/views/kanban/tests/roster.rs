use super::*;

#[test]
fn realm_member_roster_reads_r32_wire_shape() {
    // R3.2 (arkret-spec @ b56cab1): roster entries carry
    // `actor_id` + `membership` + optional `subject_id` /
    // `identity_event_ids` / `member_display_state_digest`. Handle
    // strings only appear inside signed handle_claim evidence.
    let projection = json!({
        "members": [
            {
                "actor_id": "ak:did_core:web:acme.example:users:alice",
                "membership": "join",
                "subject_id": "ak:did_core:web:acme.example:principals:alice",
                "identity_event_ids": ["ak:event:ATOz4l-vKJUCGZDmS_knGS9TjZ64pkOzx-HNGAgY5RGJ"],
                "member_display_state_digest": "sha256:abababababababababababababababababababababababababababababababab",
                "handle_claims": [{
                    "subject": "ak:did_core:web:acme.example:principals:alice",
                    "handle": "alice:acme.example",
                    "binding_state": "verified"
                }],
                "handle_claims_limited": false
            },
            {
                "actor_id": "ak:did_core:webvh:zQmPr8",
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
        vec!["ak:event:ATOz4l-vKJUCGZDmS_knGS9TjZ64pkOzx-HNGAgY5RGJ".to_owned()]
    );
    assert!(alice.member_display_state_digest.is_some());
    assert_eq!(
        alice.subject_id.as_deref(),
        Some("ak:did_core:web:acme.example:principals:alice")
    );
    assert_eq!(alice.handle_claims.len(), 1);
    assert!(!alice.handle_claims_limited);

    let webvh = rows
        .iter()
        .find(|row| row.actor_id.starts_with("ak:did_core:webvh:"))
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
            "actor_id": "ak:did_core:web:acme.example:users:v2",
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
            "actor_id": "ak:did_core:web:acme.example:users:removed",
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
fn realm_member_roster_reads_only_root_members() {
    let projection = json!({
        "summary": {
            "members": [{ "actor_id": "ak:did_core:web:summary-member.example" }],
            "participants": [{ "actor_id": "ak:did_core:web:participant.example" }]
        },
        "owners": [{ "actor_id": "ak:did_core:web:owner.example" }],
        "members": [{ "actor_id": "ak:did_core:web:canonical.example" }]
    });

    let rows = realm_member_roster(Some(&projection));
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor_id, "ak:did_core:web:canonical.example");
}

#[test]
fn realm_member_roster_keeps_first_duplicate_actor_entry() {
    let projection = json!({
        "members": [
            { "actor_id": "ak:did_core:web:alice.example", "membership": "join" },
            { "actor_id": "ak:did_core:web:alice.example", "membership": "invite" }
        ]
    });

    let rows = realm_member_roster(Some(&projection));
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].membership.as_deref(), Some("join"));
}

#[test]
fn member_display_label_uses_identity_name_when_no_verified_handle_exists() {
    use arkret_sdk::{
        DisplayProfile, MemberIdentity, MemberIdentityProof, MemberIdentitySignatureAlgorithm,
    };

    // R3.2: `MemberIdentity` discloses subject_id + display_profile
    // only. A materialized DID path is not itself verified handle evidence.
    let identity = MemberIdentity {
        schema: arkret_sdk::SchemaId::MEMBER_IDENTITY_V1.to_owned(),
        realm_id: arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
            .unwrap(),
        actor_id: crate::mls_api_helpers::principal_core_id("did:web:acme.example:users:alice")
            .unwrap(),
        subject_id: crate::mls_api_helpers::principal_core_id("did:web:acme.example:users:alice")
            .unwrap(),
        display_profile: DisplayProfile {
            display_name: "Alice".to_owned(),
            avatar_blob_ref: None,
        },
        asserted_at: chrono::Utc::now(),
        expires_at: None,
        proof: MemberIdentityProof {
            verification_method: arkret_sdk::DidUrl::new("did:web:acme.example#key-1").unwrap(),
            signature_algorithm: MemberIdentitySignatureAlgorithm::Ed25519,
            payload_digest: arkret_sdk::Hash::new(
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
    assert_eq!(member_label(&row, Some(&identity), None), "Alice");

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
    let label = member_label(&bare, None, None);
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

    assert_eq!(member_label(&row, None, None), "alice:acme.example");
}

#[test]
fn member_display_label_rejects_unverified_or_noncanonical_handle_claims() {
    let row = RealmMemberRow {
        actor_id: "did:webvh:zQmPairwiseActor".to_owned(),
        membership: Some("join".to_owned()),
        identity_event_ids: vec![],
        member_display_state_digest: None,
        subject_id: Some("did:key:z6MkPrincipal".to_owned()),
        handle_claims: vec![
            json!({
                "subject": "did:key:z6MkPrincipal",
                "handle": "pending:acme.example",
                "binding_state": "pending"
            }),
            json!({
                "subject_id": "ak:did_core:key:z6MkPrincipal",
                "handle": "legacy:acme.example",
                "binding_state": "verified"
            }),
        ],
        handle_claims_limited: false,
    };

    assert!(verified_inline_handle(&row).is_none());

    let undisclosed = RealmMemberRow {
        subject_id: None,
        handle_claims: vec![json!({
            "subject": "did:webvh:zQmPairwiseActor",
            "handle": "hidden:acme.example",
            "binding_state": "verified"
        })],
        ..row
    };
    assert!(verified_inline_handle(&undisclosed).is_none());
}

#[test]
fn member_display_label_uses_cached_directory_primary_handle() {
    let row = RealmMemberRow {
        actor_id: "ak:did_core:webvh:zQmPrincipal".to_owned(),
        membership: Some("join".to_owned()),
        identity_event_ids: vec![],
        member_display_state_digest: None,
        subject_id: Some("did:webvh:zQmPrincipal".to_owned()),
        handle_claims: Vec::new(),
        handle_claims_limited: false,
    };

    assert_eq!(
        member_label(&row, None, Some("Alice:Example.COM")),
        "alice:example.com"
    );
}

#[test]
fn resolved_member_display_uses_persisted_current_account_handle() {
    let actor = "did:webvh:zQmCurrentAccount";
    let row = RealmMemberRow {
        actor_id: actor.to_owned(),
        membership: Some("join".to_owned()),
        identity_event_ids: vec![],
        member_display_state_digest: None,
        subject_id: None,
        handle_claims: Vec::new(),
        handle_claims_limited: false,
    };
    let mut store = isolated_store_for_tests("member-display-current-account");
    store.switch_test_account(actor);
    store.set_primary_handle_for_did(actor, "alice:local.host");

    let display = crate::views::member_display::resolve_member_display(&store, TEST_REALM_ID, &row);

    assert_eq!(display.label, "alice:local.host");
    assert_eq!(display.primary_handle.as_deref(), Some("alice:local.host"));
}

#[test]
fn member_handle_lookup_keeps_authoritative_subject_separate_from_actor_candidate() {
    let row = RealmMemberRow {
        actor_id: "ak:did_core:webvh:zQmPrincipal".to_owned(),
        membership: Some("join".to_owned()),
        identity_event_ids: vec![],
        member_display_state_digest: None,
        subject_id: None,
        handle_claims: Vec::new(),
        handle_claims_limited: false,
    };

    assert!(crate::views::member_display::member_lookup_subject(&row, None).is_none());

    let store = isolated_store_for_tests("actor-subject-handle-candidate");
    let requests = crate::views::member_display::missing_member_handle_lookups(
        &store,
        TEST_REALM_ID,
        std::slice::from_ref(&row),
        &std::collections::BTreeSet::new(),
    );
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].subject_id, row.actor_id);
    assert_eq!(requests[0].realm_id, TEST_REALM_ID);
}

#[test]
fn member_roster_realm_context_prefers_projection_realm_id() {
    assert_eq!(
        member_roster_realm_context(
            "ak:space:board",
            "ak:realm:AzFgbMgjZqbtbhJi4df_hVGsURuFaaKqsgvzmu2cW-dA",
            Some(&json!({"realm_id": "ak:realm:ATn1eDmPIlZjKnyP4TfzoZJIT-CufZ-jFJZgOSyvBwKo"})),
        ),
        "ak:realm:ATn1eDmPIlZjKnyP4TfzoZJIT-CufZ-jFJZgOSyvBwKo"
    );
    assert_eq!(
        member_roster_realm_context(
            "ak:realm:AD7mrZtfTNN1HudeGAjpVIZoCycBIIpKGmT3Hbi6UJ7k",
            "ak:realm:ArtCds6gQh96PTCABrrKYswyGOj4rLT3a_FT62MVBKug",
            None
        ),
        "ak:realm:ArtCds6gQh96PTCABrrKYswyGOj4rLT3a_FT62MVBKug"
    );
    assert_eq!(
        member_roster_realm_context(
            "ak:realm:AB8ClU7V2Rh794lMmCuSv9UkhOs5PtqZpBoIa_KSscNI",
            "",
            None
        ),
        "ak:realm:AB8ClU7V2Rh794lMmCuSv9UkhOs5PtqZpBoIa_KSscNI"
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
