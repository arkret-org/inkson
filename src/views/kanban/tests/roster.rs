use super::*;

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
    let creates = card_assignment_mutations(
        TEST_REALM_ID,
        "did:web:author.example",
        &card,
        &selected,
        &std::collections::BTreeMap::new(),
    )
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
    let removed_head = arkret_sdk::Hash::new(format!("sha256:{}", "42".repeat(32))).unwrap();
    let bases = std::collections::BTreeMap::from([
        (
            "ak:relation:AiRwjMAZ14M9aj2p96Vy4ORV9RjgnslFIV7wS1_2Zhig".to_owned(),
            vec![removed_head.clone()],
        ),
        (
            "ak:relation:AFjQnGmj11wy2rA2YjgbfhdhIJlFu9cPeZN5Ld0XzQp4".to_owned(),
            Vec::new(),
        ),
    ]);
    let removes = card_assignment_mutations(
        TEST_REALM_ID,
        "did:web:author.example",
        &card,
        &retained,
        &bases,
    )
    .unwrap();
    assert_eq!(removes.len(), 1);
    assert_eq!(
        removes[0].operation().intent().causal_refs(),
        &[removed_head]
    );
    assert_eq!(removes[0].actor_id(), &first);
    assert_eq!(
        assignment_relations_after_mutations(&card, &retained, &removes)[0].actor_id,
        second
    );
}

const ROSTER_ISSUER: &str = "ak:did_core:web:acme.example";
const ROSTER_STATION: &str = "ak:did_core:web:principal.example";

fn acme_policy() -> Vec<arkret_sdk::identity::HandleIssuerPolicyEntry> {
    vec![crate::views::member_display::test_issuer_policy(
        ROSTER_ISSUER,
        "acme.example",
    )]
}

fn verified_claim(
    subject: &arkret_sdk::AccountId,
    handle: &str,
) -> arkret_models_identity::HandleClaim {
    crate::views::member_display::test_handle_claim(
        subject,
        handle,
        ROSTER_ISSUER,
        arkret_models_identity::HandleClaimStatus::Verified,
    )
}

#[test]
fn realm_member_roster_reads_r32_wire_shape() {
    // (arkret-spec @ b56cab1): roster entries carry
    // `actor_id` + `membership` + optional `subject_account_id` /
    // `identity_event_ids` / `member_display_state_digest`. Handle
    // strings only appear inside signed handle_claim evidence.
    let alice_subject = fixture::authority("ak:did_core:web:acme.example:principals:alice");
    let projection = json!({
        "member_roster_entries": [
            {
                "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:acme.example:users:alice","station_id":ROSTER_STATION}},
                "membership": "join",
                "subject_account_id": alice_subject,
                "identity_event_ids": ["ak:event:ATOz4l-vKJUCGZDmS_knGS9TjZ64pkOzx-HNGAgY5RGJ"],
                "member_display_state_digest": "sha256:abababababababababababababababababababababababababababababababab",
                "handle_claims": [verified_claim(&alice_subject, "alice:acme.example")],
                "handle_claims_limited": false
            },
            {
                "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:webvh:zQmPr8","station_id":ROSTER_STATION}},
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
    assert_eq!(
        alice.membership,
        Some(arkret_sdk::sync::MemberRosterMembership::Join)
    );
    assert_eq!(
        alice.identity_event_ids,
        vec!["ak:event:ATOz4l-vKJUCGZDmS_knGS9TjZ64pkOzx-HNGAgY5RGJ".to_owned()]
    );
    assert!(alice.member_display_state_digest.is_some());
    assert_eq!(alice.subject_account_id.as_ref(), Some(&alice_subject));
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
    assert_eq!(
        webvh.membership,
        Some(arkret_sdk::sync::MemberRosterMembership::Knock)
    );
    assert!(webvh.identity_event_ids.is_empty());
    assert!(webvh.member_display_state_digest.is_none());
    // subject_account_id not disclosed for the invite row.
    assert!(webvh.subject_account_id.is_none());
}

#[test]
fn realm_member_roster_reads_r32_digest_only() {
    // Aggressive no-compat: only the `member_display_state_digest`
    // key is read.
    let projection = json!({
        "member_roster_entries": [{
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:acme.example:users:v2","station_id":ROSTER_STATION}},
            "membership": "join",
            "member_display_state_digest": "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        }]
    });
    let rows = realm_member_roster(Some(&projection));
    assert_eq!(rows.len(), 1);
    assert!(rows[0].member_display_state_digest.is_some());
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
            "members": [{ "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:summary-member.example","station_id":ROSTER_STATION}} }],
            "participants": [{ "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:participant.example","station_id":ROSTER_STATION}} }]
        },
        "owners": [{ "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:owner.example","station_id":ROSTER_STATION}} }],
        "member_roster_entries": [{ "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:canonical.example","station_id":ROSTER_STATION}}, "membership": "join" }]
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
            { "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":ROSTER_STATION}}, "membership": "join" },
            { "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":ROSTER_STATION}}, "membership": "knock" }
        ]
    });

    let rows = realm_member_roster(Some(&projection));
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].membership,
        Some(arkret_sdk::sync::MemberRosterMembership::Join)
    );
}

#[test]
fn realm_member_roster_drops_undisclosed_rows_carrying_claim_evidence() {
    // R3.2 dependentRequired: handle-claim evidence without
    // `subject_account_id` disclosure is a malformed entry, not a row to
    // render with the evidence silently ignored.
    let subject = fixture::authority("ak:did_core:web:acme.example:principals:mallory");
    let projection = json!({
        "member_roster_entries": [{
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:acme.example:users:mallory","station_id":ROSTER_STATION}},
            "membership": "join",
            "handle_claims": [verified_claim(&subject, "mallory:acme.example")]
        }]
    });
    assert!(realm_member_roster(Some(&projection)).is_empty());
}

#[test]
fn member_display_label_uses_identity_name_when_no_verified_handle_exists() {
    use arkret_sdk::{
        DisplayProfile, MemberIdentity, MemberIdentityProof, MemberIdentitySignatureAlgorithm,
    };

    // `MemberIdentity` discloses the subject account + display_profile
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

    let rendered = crate::views::member_display::resolve_subject_display(
        identity.subject_actor_id.as_account_id(),
        &[],
        &acme_policy(),
        Some(TEST_REALM_ID),
        None,
        Some(identity.display_profile.display_name.as_str()),
        "ak:did_core:web:acme...ice",
    );
    assert_eq!(rendered.label, "Alice");
    assert_eq!(
        rendered.tier,
        crate::views::member_display::MemberDisplayTier::NameOnly
    );

    // Decryption-pending / no MemberIdentity → fall back to compact DID.
    let bare = crate::views::member_display::resolve_subject_display(
        None,
        &[],
        &[],
        None,
        None,
        None,
        "ak:did_core:webvh:zQmPr8...7ha",
    );
    assert!(bare.label.starts_with("ak:did_core:webvh:"));
    assert_eq!(
        bare.tier,
        crate::views::member_display::MemberDisplayTier::Unresolved
    );
}

#[test]
fn member_display_label_prefers_inline_verified_handle_claim() {
    let subject = fixture::authority("ak:did_core:web:acme.example:principals:alice");
    let other = fixture::authority("ak:did_core:web:acme.example:principals:other");
    let row = RealmMemberRow {
        actor_id: crate::mls_api_helpers::local_account_actor_id(
            "ak:did_core:webvh:zQmPairwiseActor",
        )
        .unwrap(),
        membership: Some(arkret_sdk::sync::MemberRosterMembership::Join),
        identity_event_ids: vec![],
        member_display_state_digest: Some(
            "sha256:abababababababababababababababababababababababababababababababab".to_owned(),
        ),
        subject_account_id: Some(subject.clone()),
        handle_claims: vec![
            verified_claim(&other, "other:acme.example"),
            verified_claim(&subject, "alice:acme.example"),
        ],
        handle_claims_limited: false,
    };

    let handle = crate::views::member_display::inline_primary_handle(
        &row,
        &acme_policy(),
        Some(TEST_REALM_ID),
    );
    assert_eq!(
        handle.as_ref().map(arkret_sdk::Handle::canonical),
        Some("alice:acme.example")
    );
}

/// `identity-handles.md` §3.2 compares the whole `AccountId`. A claim bound to
/// the same principal at another Station is not evidence about this member, so
/// the inline path must decline it and let the display degrade rather than
/// show a handle that belongs to a different subject.
#[test]
fn inline_handle_claim_for_another_station_is_not_this_members_handle() {
    let principal = "ak:did_core:web:acme.example:principals:alice";
    let here = fixture::authority_at_station(principal, "ak:did_core:web:station-a.example");
    let elsewhere = fixture::authority_at_station(principal, "ak:did_core:web:station-b.example");
    assert_eq!(here.principal_id, elsewhere.principal_id);
    assert_ne!(here.station_id, elsewhere.station_id);

    let row_with = |subject: &arkret_sdk::AccountId| RealmMemberRow {
        actor_id: crate::mls_api_helpers::local_account_actor_id(
            "ak:did_core:webvh:zQmPairwiseActor",
        )
        .unwrap(),
        membership: Some(arkret_sdk::sync::MemberRosterMembership::Join),
        identity_event_ids: vec![],
        member_display_state_digest: None,
        subject_account_id: Some(here.clone()),
        handle_claims: vec![verified_claim(subject, "alice:acme.example")],
        handle_claims_limited: false,
    };

    // Positive control first: the same fixture with a matching subject does
    // resolve, so the None below means the Station differed.
    assert_eq!(
        crate::views::member_display::inline_primary_handle(
            &row_with(&here),
            &acme_policy(),
            Some(TEST_REALM_ID),
        )
        .as_ref()
        .map(arkret_sdk::Handle::canonical),
        Some("alice:acme.example")
    );
    assert!(
        crate::views::member_display::inline_primary_handle(
            &row_with(&elsewhere),
            &acme_policy(),
            Some(TEST_REALM_ID),
        )
        .is_none()
    );
}

#[test]
fn member_display_label_rejects_unverified_or_untrusted_handle_claims() {
    let subject = fixture::authority("ak:did_core:web:acme.example:principals:alice");
    let row = RealmMemberRow {
        actor_id: crate::mls_api_helpers::local_account_actor_id(
            "ak:did_core:webvh:zQmPairwiseActor",
        )
        .unwrap(),
        membership: Some(arkret_sdk::sync::MemberRosterMembership::Join),
        identity_event_ids: vec![],
        member_display_state_digest: None,
        subject_account_id: Some(subject.clone()),
        handle_claims: vec![crate::views::member_display::test_handle_claim(
            &subject,
            "pending:acme.example",
            ROSTER_ISSUER,
            arkret_models_identity::HandleClaimStatus::Pending,
        )],
        handle_claims_limited: false,
    };
    assert!(
        crate::views::member_display::inline_primary_handle(
            &row,
            &acme_policy(),
            Some(TEST_REALM_ID)
        )
        .is_none()
    );

    // §3.2.1 Step 0 makes the issuer trust + domain-authority filter
    // mandatory: a verified claim from an issuer the Realm policy does not
    // authorize MUST NOT be displayed, and an empty policy is not "no
    // constraint".
    let untrusted = RealmMemberRow {
        handle_claims: vec![verified_claim(&subject, "alice:acme.example")],
        ..row
    };
    assert!(
        crate::views::member_display::inline_primary_handle(&untrusted, &[], Some(TEST_REALM_ID))
            .is_none()
    );
    assert!(
        crate::views::member_display::inline_primary_handle(
            &untrusted,
            &[crate::views::member_display::test_issuer_policy(
                ROSTER_ISSUER,
                "other.example"
            )],
            Some(TEST_REALM_ID)
        )
        .is_none()
    );
    assert!(
        crate::views::member_display::inline_primary_handle(
            &untrusted,
            &acme_policy(),
            Some(TEST_REALM_ID)
        )
        .is_some()
    );
}

#[test]
fn member_display_label_uses_cached_directory_primary_handle() {
    let subject = fixture::authority("ak:did_core:webvh:zQmPrincipal");
    let rendered = crate::views::member_display::resolve_subject_display(
        Some(&subject),
        &[],
        &acme_policy(),
        Some(TEST_REALM_ID),
        Some(&arkret_sdk::Handle::parse("alice:example.com").unwrap()),
        None,
        "ak:did_core:webvh:zQm...pal",
    );
    assert_eq!(rendered.label, "alice:example.com");
    assert_eq!(
        rendered.tier,
        crate::views::member_display::MemberDisplayTier::Cached
    );
}

#[test]
fn resolved_member_display_uses_persisted_current_account_handle() {
    let actor = "ak:did_core:web:current-account.example";
    let did = "did:web:current-account.example";
    let row = RealmMemberRow {
        actor_id: crate::mls_api_helpers::local_account_actor_id(actor).unwrap(),
        membership: Some(arkret_sdk::sync::MemberRosterMembership::Join),
        identity_event_ids: vec![],
        member_display_state_digest: None,
        subject_account_id: None,
        handle_claims: Vec::new(),
        handle_claims_limited: false,
    };
    let mut store = isolated_store_for_tests("member-display-current-account");
    store.switch_test_account(did);
    store.set_primary_handle_for_principal_id(actor, "alice:local.host");

    let display = crate::views::member_display::resolve_member_display(&store, TEST_REALM_ID, &row);

    assert_eq!(display.label, "alice:local.host");
    assert_eq!(display.primary_handle.as_deref(), Some("alice:local.host"));
    assert_eq!(
        display.tier,
        crate::views::member_display::MemberDisplayTier::Cached
    );
}

/// Negative case locked by
/// `tasks/spec-done/2026-09-04-2153-member-roster-subject-carrier-prose-and-schema-disagree.md`:
/// one principal with accounts at two Stations is two subjects. A handle
/// cached for the Station-B account MUST NOT decorate the Station-A member
/// row, and the row MUST still raise its own lookup instead of reusing that
/// entry. The row degrades to the name-only / truncated-DID rung rather than
/// showing the other account's handle.
#[test]
fn cached_handle_for_another_station_never_reaches_the_member_row() {
    let principal = "ak:did_core:webvh:zQmSharedPrincipal";
    let at_station_a =
        fixture::authority_at_station(principal, "ak:did_core:web:station-a.example");
    let at_station_b =
        fixture::authority_at_station(principal, "ak:did_core:web:station-b.example");
    let row = RealmMemberRow {
        actor_id: arkret_sdk::ActorId::account(at_station_a.clone()),
        membership: Some(arkret_sdk::sync::MemberRosterMembership::Join),
        identity_event_ids: vec![],
        member_display_state_digest: None,
        subject_account_id: Some(at_station_a.clone()),
        handle_claims: Vec::new(),
        handle_claims_limited: false,
    };

    let mut store = isolated_store_for_tests("cross-station-handle-cache");
    store.save_member_handle_lookup(
        &at_station_b,
        Some(TEST_REALM_ID.to_owned()),
        None,
        Some("bob:elsewhere.example".to_owned()),
        1,
        None,
        None,
    );

    let display = crate::views::member_display::resolve_member_display(&store, TEST_REALM_ID, &row);
    assert_eq!(display.primary_handle, None);
    assert_ne!(display.label, "bob:elsewhere.example");
    assert_eq!(
        display.tier,
        crate::views::member_display::MemberDisplayTier::Unresolved
    );

    // Once the Station-A subject itself has evidence the row renders it, which
    // proves the miss above came from the Station split and not from the row
    // being unable to read the cache at all.
    store.save_member_handle_lookup(
        &at_station_a,
        Some(TEST_REALM_ID.to_owned()),
        None,
        Some("alice:example.com".to_owned()),
        1,
        None,
        None,
    );
    let display = crate::views::member_display::resolve_member_display(&store, TEST_REALM_ID, &row);
    assert_eq!(display.primary_handle.as_deref(), Some("alice:example.com"));
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
