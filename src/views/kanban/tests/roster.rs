use super::*;
use crate::views::member_display::test_inline_handle_claim;

#[test]
fn assignment_mutations_preserve_same_principal_accounts_at_different_stations() {
    use super::super::assignment::{
        assignment_relations_after_mutations, card_assignment_mutations,
    };
    let principal = arkret_sdk::DidCoreId::new("ak:did_core:web:assignee.example").unwrap();
    let actor = |station: &str| {
        arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            principal.clone(),
            arkret_sdk::DidCoreId::new(station).unwrap(),
        ))
    };
    let first = actor("ak:did_core:web:station-a.example");
    let second = actor("ak:did_core:web:station-b.example");
    let mut card = test_card(
        "ak:strand:AiRwjMAZ14M9aj2p96Vy4ORV9RjgnslFIV7wS1_2Zhig",
        "U",
    );
    let selected = std::collections::BTreeSet::from([first.clone(), second.clone()]);
    let creates =
        card_assignment_mutations(TEST_REALM_ID, "did:web:author.example", &card, &selected)
            .unwrap();
    assert_eq!(creates.len(), 2);
    for mutation in &creates {
        assert_eq!(
            mutation.operation().payload_for_schema()["relation"]["to_ref"],
            serde_json::to_value(mutation.actor_id()).unwrap()
        );
    }
    card.assigned_to_relations = vec![
        CardAssignedToRelation {
            actor_id: first.clone(),
            relation_id: "ak:relation:AiRwjMAZ14M9aj2p96Vy4ORV9RjgnslFIV7wS1_2Zhig".to_owned(),
        },
        CardAssignedToRelation {
            actor_id: second.clone(),
            relation_id: "ak:relation:AFjQnGmj11wy2rA2YjgbfhdhIJlFu9cPeZN5Ld0XzQp4".to_owned(),
        },
    ];
    let retained = std::collections::BTreeSet::from([second.clone()]);
    let removes =
        card_assignment_mutations(TEST_REALM_ID, "did:web:author.example", &card, &retained)
            .unwrap();
    assert_eq!(removes.len(), 1);
    assert_eq!(removes[0].actor_id(), &first);
    assert_eq!(
        assignment_relations_after_mutations(&card, &retained, &removes)[0].actor_id,
        second
    );
}

#[test]
fn realm_member_roster_reads_r32_wire_shape() {
    // (arkret-spec @ b56cab1): roster entries carry
    // `actor_id` + `membership` + optional `subject_id` /
    // `identity_event_ids` / `member_display_state_digest`. Handle
    // strings only appear inside signed handle_claim evidence.
    let projection = json!({
        "member_roster_entries": [
            {
                "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:acme.example:users:alice","station_id":"ak:did_core:web:principal.example"}},
                "membership": "join",
                "subject_id": "ak:did_core:web:acme.example:principals:alice",
                "identity_event_ids": ["ak:event:ATOz4l-vKJUCGZDmS_knGS9TjZ64pkOzx-HNGAgY5RGJ"],
                "member_display_state_digest": "sha256:abababababababababababababababababababababababababababababababab",
                "handle_claims": [test_inline_handle_claim(
                    "ak:did_core:web:acme.example:principals:alice",
                    "alice:acme.example",
                    "verified"
                )],
                "handle_claims_limited": false
            },
            {
                "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:webvh:zQmPr8","station_id":"ak:did_core:web:principal.example"}},
                "membership": "knock"
            }
        ]
    });
    let rows = realm_member_roster(Some(&projection));
    assert_eq!(rows.len(), 2);
    let alice = rows
        .iter()
        .find(|row| {
            row.actor_id
                .signing_principal_id()
                .as_str()
                .contains("alice")
        })
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
        .find(|row| {
            row.actor_id
                .signing_principal_id()
                .as_str()
                .starts_with("ak:did_core:webvh:")
        })
        .unwrap();
    assert_eq!(webvh.membership.as_deref(), Some("knock"));
    assert!(webvh.identity_event_ids.is_empty());
    assert!(webvh.member_display_state_digest.is_none());
    // subject_id not disclosed for the invite row.
    assert!(webvh.subject_id.is_none());
}

#[test]
fn realm_member_roster_reads_r32_digest_only() {
    // Aggressive no-compat: only the `member_display_state_digest`
    // key is read.
    let projection = json!({
        "member_roster_entries": [{
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:acme.example:users:v2","station_id":"ak:did_core:web:principal.example"}},
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
    // The legacy `identity_state_digest` key is NOT honoured.
    let projection = json!({
        "member_roster_entries": [{
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:acme.example:users:removed","station_id":"ak:did_core:web:principal.example"}},
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
        "member_roster_entries": ["ak:did_core:web:bob.example", "ak:did_core:web:carol.example"]
    });
    let rows = realm_member_roster(Some(&projection));
    assert!(rows.is_empty());
}

#[test]
fn realm_member_roster_reads_only_root_members() {
    let projection = json!({
        "summary": {
            "members": [{ "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:summary-member.example","station_id":"ak:did_core:web:principal.example"}} }],
            "participants": [{ "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:participant.example","station_id":"ak:did_core:web:principal.example"}} }]
        },
        "owners": [{ "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:owner.example","station_id":"ak:did_core:web:principal.example"}} }],
        "member_roster_entries": [{ "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:canonical.example","station_id":"ak:did_core:web:principal.example"}} }]
    });

    let rows = realm_member_roster(Some(&projection));
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].actor_id.signing_principal_id().as_str(),
        "ak:did_core:web:canonical.example"
    );
}

#[test]
fn realm_member_roster_keeps_first_duplicate_actor_entry() {
    let projection = json!({
        "member_roster_entries": [
            { "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}}, "membership": "join" },
            { "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}}, "membership": "knock" }
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

    // `MemberIdentity` discloses subject_id + display_profile
    // only. A materialized DID path is not itself verified handle evidence.
    let identity = MemberIdentity {
        schema: arkret_sdk::SchemaId::MEMBER_IDENTITY_V1.to_owned(),
        realm_id: arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
            .unwrap(),
        actor_id: crate::mls_api_helpers::local_account_actor_id(
            "ak:did_core:web:acme.example:users:alice",
        )
        .unwrap(),
        subject_actor_id: crate::mls_api_helpers::local_account_actor_id(
            "ak:did_core:web:acme.example:users:alice",
        )
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
        actor_id: crate::mls_api_helpers::local_account_actor_id(
            "ak:did_core:web:acme.example:users:alice",
        )
        .unwrap(),
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
        actor_id: crate::mls_api_helpers::local_account_actor_id(
            "ak:did_core:webvh:zQmPr8aaaaaaaaaaaaaaaaa7h4q87ha",
        )
        .unwrap(),
        membership: None,
        identity_event_ids: vec![],
        member_display_state_digest: None,
        subject_id: None,
        handle_claims: Vec::new(),
        handle_claims_limited: false,
    };
    let label = member_label(&bare, None, None);
    assert!(label.starts_with("ak:did_core:webvh:"));
    assert!(label.contains("..."));
}

#[test]
fn member_display_label_prefers_inline_verified_handle_claim() {
    let row = RealmMemberRow {
        actor_id: crate::mls_api_helpers::local_account_actor_id(
            "ak:did_core:webvh:zQmPairwiseActor",
        )
        .unwrap(),
        membership: Some("join".to_owned()),
        identity_event_ids: vec![],
        member_display_state_digest: Some(
            "sha256:abababababababababababababababababababababababababababababababab".to_owned(),
        ),
        subject_id: Some("did:key:z6MkPrincipal".to_owned()),
        handle_claims: vec![
            test_inline_handle_claim("did:key:z6MkOther", "other:acme.example", "verified"),
            test_inline_handle_claim("did:key:z6MkPrincipal", "alice:acme.example", "verified"),
        ],
        handle_claims_limited: false,
    };

    assert_eq!(member_label(&row, None, None), "alice:acme.example");
}

#[test]
fn member_display_label_rejects_unverified_or_noncanonical_handle_claims() {
    let row = RealmMemberRow {
        actor_id: crate::mls_api_helpers::local_account_actor_id(
            "ak:did_core:webvh:zQmPairwiseActor",
        )
        .unwrap(),
        membership: Some("join".to_owned()),
        identity_event_ids: vec![],
        member_display_state_digest: None,
        subject_id: Some("did:key:z6MkPrincipal".to_owned()),
        handle_claims: vec![
            test_inline_handle_claim("did:key:z6MkPrincipal", "pending:acme.example", "pending"),
            test_inline_handle_claim(
                "ak:did_core:key:z6MkPrincipal",
                "other:acme.example",
                "verified",
            ),
        ],
        handle_claims_limited: false,
    };

    assert!(verified_inline_handle(&row).is_none());

    let undisclosed = RealmMemberRow {
        subject_id: None,
        handle_claims: vec![test_inline_handle_claim(
            "ak:did_core:webvh:zQmPairwiseActor",
            "hidden:acme.example",
            "verified",
        )],
        ..row
    };
    assert!(verified_inline_handle(&undisclosed).is_none());
}

#[test]
fn member_display_label_uses_cached_directory_primary_handle() {
    let row = RealmMemberRow {
        actor_id: crate::mls_api_helpers::local_account_actor_id("ak:did_core:webvh:zQmPrincipal")
            .unwrap(),
        membership: Some("join".to_owned()),
        identity_event_ids: vec![],
        member_display_state_digest: None,
        subject_id: Some("ak:did_core:webvh:zQmPrincipal".to_owned()),
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
    let actor = "ak:did_core:web:current-account.example";
    let did = "did:web:current-account.example";
    let row = RealmMemberRow {
        actor_id: crate::mls_api_helpers::local_account_actor_id(actor).unwrap(),
        membership: Some("join".to_owned()),
        identity_event_ids: vec![],
        member_display_state_digest: None,
        subject_id: None,
        handle_claims: Vec::new(),
        handle_claims_limited: false,
    };
    let mut store = isolated_store_for_tests("member-display-current-account");
    store.switch_test_account(did);
    store.set_primary_handle_for_principal_id(actor, "alice:local.host");

    let display = crate::views::member_display::resolve_member_display(&store, TEST_REALM_ID, &row);

    assert_eq!(display.label, "alice:local.host");
    assert_eq!(display.primary_handle.as_deref(), Some("alice:local.host"));
}

#[test]
fn member_handle_lookup_keeps_authoritative_subject_separate_from_actor_candidate() {
    let row = RealmMemberRow {
        actor_id: crate::mls_api_helpers::local_account_actor_id("ak:did_core:webvh:zQmPrincipal")
            .unwrap(),
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
    assert_eq!(
        requests[0].subject_id,
        row.actor_id.signing_principal_id().as_str()
    );
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
    // ROST-4: truncated rosters MUST signal `member_roster_entries_limited=true`
    // so the UI surfaces a "load more" affordance.
    let projection = json!({
        "member_roster_entries": [],
        "member_roster_entries_limited": true,
        "member_roster_entries_next_cursor": "cursor-opaque.v1.abc"
    });
    let pagination = RealmRosterPagination::from_projection(Some(&projection));
    assert!(pagination.member_roster_entries_limited);
    assert_eq!(
        pagination.member_roster_entries_next_cursor.as_deref(),
        Some("cursor-opaque.v1.abc")
    );

    // Complete projections leave the flag unset.
    let complete = json!({ "member_roster_entries": [] });
    let pagination = RealmRosterPagination::from_projection(Some(&complete));
    assert!(!pagination.member_roster_entries_limited);
    assert!(pagination.member_roster_entries_next_cursor.is_none());
}
