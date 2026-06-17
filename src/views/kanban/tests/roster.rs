use super::*;

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
