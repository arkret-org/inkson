use std::collections::BTreeMap;

use serde_json::json;

use super::*;

fn test_realm_id(value: &str) -> arkret_sdk::RealmId {
    arkret_sdk::RealmId::new(value.to_owned()).unwrap()
}

fn test_realm_remark(value: &str, local_name: &str) -> RealmRemark {
    let mut remark = RealmRemark::new(
        test_realm_id(value),
        "2026-06-01T00:00:00.000Z".parse().unwrap(),
    );
    remark.local_name = local_name.to_owned();
    remark
}

// ── F-ACCT-SNAP-1 ────────────────────────────────────────────────

#[test]
fn snapshot_head_default_is_none_and_round_trips() {
    let mut store = AccountDataStore::new();
    assert_eq!(store.snapshot_head(), None);

    store.set_snapshot_head("sha256:abc123");
    assert_eq!(store.snapshot_head(), Some("sha256:abc123"));

    // Subsequent reconcile overwrites without affecting entries.
    store
        .set(
            AccountDataKey::ClientUi,
            json!({"theme": "night"}),
            1,
            "01970e589d21-0001-a13f9c2e".to_owned(),
        )
        .unwrap();
    store.set_snapshot_head("sha256:def456");
    assert_eq!(store.snapshot_head(), Some("sha256:def456"));
    assert_eq!(store.len(), 1);
}

#[test]
fn snapshot_head_clears_independently_of_entries() {
    let mut store = AccountDataStore::new();
    store
        .set(
            AccountDataKey::ClientUi,
            json!({"theme": "light"}),
            1,
            "01970e589d21-0001-a13f9c2e".to_owned(),
        )
        .unwrap();
    store.set_snapshot_head("sha256:abc123");
    store.clear_snapshot_head();
    assert_eq!(store.snapshot_head(), None);
    // Entries survive the snapshot reset — a trust-bundle change
    // forces re-reconciliation but doesn't wipe live data.
    assert_eq!(store.len(), 1);
}

#[test]
fn snapshot_head_persists_through_serde_round_trip() {
    let mut store = AccountDataStore::new();
    store
        .set(
            AccountDataKey::ClientUi,
            json!({"theme": "night"}),
            1,
            "01970e589d21-0001-a13f9c2e".to_owned(),
        )
        .unwrap();
    store.set_snapshot_head("sha256:abc123");

    let bytes = serde_json::to_string(&store).unwrap();
    let restored: AccountDataStore = serde_json::from_str(&bytes).unwrap();
    assert_eq!(restored.snapshot_head(), Some("sha256:abc123"));
    assert_eq!(restored.len(), 1);
}

#[test]
fn snapshot_head_absent_from_state_defaults_to_none() {
    let persisted = json!({
        "entries": {
            "ak.client.ui_state": {
                "key": "ak.client.ui_state",
                "value": {"theme": "light"},
                "revision": 1,
                "hlc": ""
            }
        }
    });
    let store: AccountDataStore = serde_json::from_value(persisted).unwrap();
    assert_eq!(store.snapshot_head(), None);
    assert_eq!(store.len(), 1);
}

#[test]
fn key_round_trip() {
    for s in [
        "ak.client.ui_state",
        "ak.read_receipt.preferences",
        "ak.presence.visibility",
        "ak.presence.preference",
        "ak.account.blocklist",
        "ak.push_rules",
        "ak.dnd_schedule",
        "client.language",
    ] {
        assert_eq!(AccountDataKey::from_wire(s).as_wire(), s);
    }
    assert_eq!(AccountDataKey::from_wire("custom.x").as_wire(), "custom.x");
}

#[test]
fn set_tracks_server_revision() {
    let mut store = AccountDataStore::new();
    let revision_a = store
        .set(
            AccountDataKey::ClientUi,
            json!({"sidebar_collapsed": true}),
            1,
            "0-0-0".into(),
        )
        .unwrap();
    let revision_b = store
        .set(
            AccountDataKey::ClientUi,
            json!({"sidebar_collapsed": false}),
            2,
            "0-0-1".into(),
        )
        .unwrap();
    assert_eq!(revision_a, 1);
    assert_eq!(revision_b, 2);
    assert_eq!(
        store.get(&AccountDataKey::ClientUi).unwrap().revision,
        revision_b
    );
    assert!(
        store
            .set(
                AccountDataKey::ClientUi,
                json!({"sidebar_collapsed": true}),
                1,
                "0-0-0".into(),
            )
            .is_err()
    );
}

#[test]
fn realm_remark_key_round_trip() {
    let realm_id = "ak:realm:0196419b-0000-7000-8000-000000000000";
    let key = realm_remark_account_data_key(realm_id);
    assert_eq!(key, format!("ak.contacts.realm.{realm_id}"));
    assert_eq!(realm_id_from_realm_remark_key(&key), Some(realm_id));
    assert_eq!(
        realm_id_from_realm_remark_key("ak.read_receipt.preferences"),
        None
    );
}

#[test]
fn contact_remark_key_round_trip() {
    let did = "did:web:alice.example";
    let key = contact_remark_account_data_key(did);
    assert_eq!(key, format!("ak.contacts.actor.{did}"));
    assert_eq!(actor_id_from_contact_remark_key(&key), Some(did));
    assert_eq!(
        actor_id_from_contact_remark_key("ak.contacts.realm.x"),
        None
    );
}

#[test]
fn realm_remark_serialises_minimal_payload() {
    // Empty fields MUST NOT appear on the wire — keeps the payload
    // tombstone-friendly and avoids leaking placeholder data.
    let remark = test_realm_remark(
        "ak:realm:0196419b-0000-7000-8000-000000000000",
        "Acme · Eng",
    );
    let wire = serde_json::to_value(&remark).unwrap();
    assert_eq!(
        wire["subject"],
        serde_json::json!({
            "kind": "realm",
            "id": "ak:realm:0196419b-0000-7000-8000-000000000000"
        })
    );
    assert_eq!(wire["local_name"], "Acme · Eng");
    assert_eq!(wire["version"], 1);
    assert!(wire["saved_at"].is_string());
    assert!(wire.get("note").is_none());
    assert!(wire.get("pinned").is_none());
    assert!(wire.get("tags").is_none());
}

#[test]
fn realm_remark_display_name_prefers_local_name() {
    let realm_id = "ak:realm:0196419b-0000-7000-8000-000000000001";
    let r = test_realm_remark(realm_id, "Acme · Eng");
    assert_eq!(r.display_name("Engineering"), "Acme · Eng");
    let empty = test_realm_remark(realm_id, "   ");
    assert_eq!(empty.display_name("Engineering"), "Engineering");
}

#[test]
fn realm_remark_is_empty_treats_whitespace_as_tombstone() {
    let realm_id = "ak:realm:0196419b-0000-7000-8000-000000000002";
    let r = test_realm_remark(realm_id, "   ");
    assert!(r.is_empty());
    let r2 = test_realm_remark(realm_id, "x");
    assert!(!r2.is_empty());
}

#[test]
fn realm_remark_pinned_builder_preserves_private_fields() {
    let realm_id = "ak:realm:0196419b-0000-7000-8000-000000000000";
    let existing = RealmRemark {
        version: 1,
        subject: RealmRemarkSubject {
            kind: "realm".to_owned(),
            id: test_realm_id(realm_id),
        },
        local_name: "Acme Eng".to_owned(),
        note: "Private note".to_owned(),
        tags: vec!["work".to_owned()],
        pinned: false,
        verified_title_at_save: Some("Engineering".to_owned()),
        verified_owning_organizations_at_save: vec![
            arkret_sdk::Did::new("did:web:acme.example".to_owned()).unwrap(),
        ],
        saved_at: "2026-06-01T00:00:00.000Z".parse().unwrap(),
        updated_at: Some("2026-06-01T00:00:00.000Z".parse().unwrap()),
    };

    let next = RealmRemark::with_pinned_preserving_fields(
        test_realm_id(realm_id),
        Some(&existing),
        true,
        "2026-06-06T00:00:00.000Z".parse().unwrap(),
    );

    assert!(next.pinned);
    assert_eq!(next.local_name, existing.local_name);
    assert_eq!(next.note, existing.note);
    assert_eq!(next.tags, existing.tags);
    assert_eq!(next.verified_title_at_save, existing.verified_title_at_save);
    assert_eq!(
        next.verified_owning_organizations_at_save,
        existing.verified_owning_organizations_at_save
    );
    assert_eq!(next.saved_at, existing.saved_at);
    assert_eq!(
        next.updated_at,
        Some("2026-06-06T00:00:00.000Z".parse().unwrap())
    );
}

#[test]
fn realm_remark_unpin_builder_can_tombstone_empty_remark() {
    let realm_id = "ak:realm:0196419b-0000-7000-8000-000000000000";
    let existing = RealmRemark::with_pinned_preserving_fields(
        test_realm_id(realm_id),
        None,
        true,
        "2026-06-06T00:00:00.000Z".parse().unwrap(),
    );
    assert!(!existing.is_empty());

    let next = RealmRemark::with_pinned_preserving_fields(
        test_realm_id(realm_id),
        Some(&existing),
        false,
        "2026-06-06T00:01:00.000Z".parse().unwrap(),
    );

    assert!(!next.pinned);
    assert_eq!(next.subject.id.as_str(), realm_id);
    assert!(next.is_empty());
}

#[test]
fn contact_remark_serialises_minimal_private_payload() {
    let saved_at = "2026-06-05T00:00:00.000Z".parse().unwrap();
    let actor_did = arkret_sdk::Did::new("did:web:alice.example".to_owned()).unwrap();
    let remark = ContactRemark::new(actor_did.clone(), "Alice from Ops", saved_at);
    let wire = serde_json::to_value(&remark).unwrap();
    assert_eq!(wire["version"], 1);
    assert_eq!(wire["subject"]["kind"], "actor");
    assert_eq!(wire["subject"]["did"], "did:web:alice.example");
    assert!(wire.get("actor_id").is_none());
    assert_eq!(wire["local_name"], "Alice from Ops");
    assert!(wire.get("note").is_none());
    assert_eq!(remark.display_name("Alice"), "Alice from Ops");

    let empty = ContactRemark {
        version: 1,
        subject: ContactRemarkSubject {
            kind: "actor".to_owned(),
            did: actor_did,
        },
        local_name: " ".to_owned(),
        note: String::new(),
        tags: Vec::new(),
        pinned: false,
        verified_handle_at_save: None,
        saved_at,
        updated_at: None,
    };
    assert!(empty.is_empty());
}

#[test]
fn contact_remark_pinned_builder_preserves_private_fields() {
    let actor_id = "did:web:alice.example";
    let actor_did = arkret_sdk::Did::new(actor_id.to_owned()).unwrap();
    let existing = ContactRemark {
        version: 1,
        subject: ContactRemarkSubject {
            kind: "actor".to_owned(),
            did: actor_did.clone(),
        },
        local_name: "Alice from Ops".to_owned(),
        note: "met at launch".to_owned(),
        tags: vec!["ops".to_owned()],
        pinned: false,
        verified_handle_at_save: Some("alice:example.com".to_owned()),
        saved_at: "2026-06-05T00:00:00.000Z".parse().unwrap(),
        updated_at: Some("2026-06-05T00:00:00.000Z".parse().unwrap()),
    };

    let next = ContactRemark::with_pinned_preserving_fields(
        actor_did,
        Some(&existing),
        true,
        "2026-06-06T00:00:00.000Z".parse().unwrap(),
    );

    assert!(next.pinned);
    assert_eq!(next.local_name, existing.local_name);
    assert_eq!(next.note, existing.note);
    assert_eq!(next.tags, existing.tags);
    assert_eq!(
        next.verified_handle_at_save,
        existing.verified_handle_at_save
    );
    assert_eq!(next.saved_at, existing.saved_at);
    assert_eq!(
        next.updated_at,
        Some("2026-06-06T00:00:00.000Z".parse().unwrap())
    );
}

#[test]
fn is_blocked_returns_true_for_blocked_did() {
    let list = vec![
        BlocklistEntry::new("did:web:alice.example", None),
        BlocklistEntry::new("did:web:bob.example", Some("spam".into())),
    ];
    assert!(is_blocked(&list, "did:web:alice.example"));
    assert!(is_blocked(&list, "did:web:bob.example"));
    assert!(!is_blocked(&list, "did:web:carol.example"));
    // Whitespace-only / empty needle short-circuits to false.
    assert!(!is_blocked(&list, ""));
    assert!(!is_blocked(&list, "   "));
}

#[test]
fn block_user_appends_to_list_without_duplicates() {
    let mut list: Vec<BlocklistEntry> = Vec::new();
    assert!(block_user_in(
        &mut list,
        "did:web:alice.example",
        Some("spam".into()),
        Some("2026-05-18T00:00:00.000Z".into()),
    ));
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].did, "did:web:alice.example");
    assert_eq!(list[0].reason.as_deref(), Some("spam"));
    assert_eq!(
        list[0].blocked_at.as_deref(),
        Some("2026-05-18T00:00:00.000Z")
    );
    // Second call with the same DID is a no-op.
    assert!(!block_user_in(
        &mut list,
        "did:web:alice.example",
        Some("different".into()),
        None,
    ));
    assert_eq!(list.len(), 1);
    // Empty DID is rejected.
    assert!(!block_user_in(&mut list, "   ", None, None));
    assert_eq!(list.len(), 1);
    // Empty reason tombstones to None on the wire.
    assert!(block_user_in(
        &mut list,
        "did:web:bob.example",
        Some("   ".into()),
        None,
    ));
    assert_eq!(list[1].reason, None);
}

#[test]
fn unblock_user_removes_matching_did() {
    let mut list = vec![
        BlocklistEntry::new("did:web:alice.example", None),
        BlocklistEntry::new("did:web:bob.example", Some("spam".into())),
    ];
    assert!(unblock_user_in(&mut list, "did:web:alice.example"));
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].did, "did:web:bob.example");
    // Idempotent: removing a missing DID returns false.
    assert!(!unblock_user_in(&mut list, "did:web:alice.example"));
    assert_eq!(list.len(), 1);
    // Empty needle is rejected.
    assert!(!unblock_user_in(&mut list, ""));
}

#[test]
fn block_target_in_dedupes_per_kind_and_value_and_stamps_entry_id() {
    let mut list: Vec<BlocklistEntry> = Vec::new();
    // Domain block: value is normalized (scheme stripped, lower-cased).
    assert!(block_target_in(
        &mut list,
        "domain",
        "https://Spam.Example/path",
        None,
        vec!["dm".into(), "calls".into()],
        Some("2026-08-01T00:00:00.000Z".into()),
        Some("2026-05-18T00:00:00.000Z".into()),
    ));
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].kind, "domain");
    assert_eq!(list[0].did, "spam.example");
    assert_eq!(list[0].applies_to, vec!["dm", "calls"]);
    assert_eq!(
        list[0].expires_at.as_deref(),
        Some("2026-08-01T00:00:00.000Z")
    );
    assert!(
        list[0]
            .entry_id
            .as_deref()
            .is_some_and(|id| id.starts_with("ak:block:"))
    );
    // Same (kind, value) is a no-op even with different metadata.
    assert!(!block_target_in(
        &mut list,
        "domain",
        "spam.example",
        None,
        Vec::new(),
        None,
        None,
    ));
    assert_eq!(list.len(), 1);
    // Same value, different kind (service) is a distinct entry.
    assert!(block_target_in(
        &mut list,
        "service",
        "did:web:spam.example",
        None,
        Vec::new(),
        None,
        None,
    ));
    assert_eq!(list.len(), 2);
    assert_eq!(list[1].kind, "service");
}

#[test]
fn is_blocked_is_scoped_to_actor_kind() {
    let mut list: Vec<BlocklistEntry> = Vec::new();
    block_target_in(
        &mut list,
        "service",
        "did:web:server.example",
        None,
        Vec::new(),
        None,
        None,
    );
    // A service block must not satisfy the actor-sender filter.
    assert!(!is_blocked(&list, "did:web:server.example"));
    block_user_in(&mut list, "did:web:alice.example", None, None);
    assert!(is_blocked(&list, "did:web:alice.example"));
}

#[test]
fn unblock_target_in_removes_only_matching_kind() {
    let mut list: Vec<BlocklistEntry> = Vec::new();
    block_user_in(&mut list, "did:web:dup.example", None, None);
    block_target_in(
        &mut list,
        "service",
        "did:web:dup.example",
        None,
        Vec::new(),
        None,
        None,
    );
    assert_eq!(list.len(), 2);
    // Removing the service block leaves the actor block intact.
    assert!(unblock_target_in(
        &mut list,
        "service",
        "did:web:dup.example"
    ));
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].kind, "actor");
    assert!(!unblock_target_in(
        &mut list,
        "service",
        "did:web:dup.example"
    ));
}

#[test]
fn build_blocklist_account_data_body_emits_domain_and_expiry_fields() {
    let mut list: Vec<BlocklistEntry> = Vec::new();
    block_target_in(
        &mut list,
        "domain",
        "spam.example",
        None,
        vec!["dm".into()],
        Some("2026-08-01T00:00:00.000Z".into()),
        None,
    );
    let body = build_blocklist_account_data_body("did:web:owner.example", 1, &list).unwrap();
    let entry = &body["entries"][0];
    assert_eq!(entry["target"]["kind"], "domain");
    // Non-DID target kinds use the canonical polymorphic `value` slot.
    assert_eq!(entry["target"]["value"], "spam.example");
    assert!(entry["target"].get("did").is_none());
    assert_eq!(entry["mode"], "block");
    assert_eq!(entry["applies_to"], json!(["dm"]));
    assert_eq!(entry["expires_at"], "2026-08-01T00:00:00.000Z");
    assert!(entry["entry_id"].as_str().unwrap().starts_with("ak:block:"));
}

#[test]
fn build_blocklist_account_data_body_omits_expiry_for_permanent_block() {
    let mut list: Vec<BlocklistEntry> = Vec::new();
    block_user_in(&mut list, "did:web:alice.example", None, None);
    let body = build_blocklist_account_data_body("did:web:owner.example", 1, &list).unwrap();
    // The typed SDK omits the optional expiry for a permanent block.
    assert!(body["entries"][0].get("expires_at").is_none());
}

#[test]
fn build_blocklist_account_data_body_emits_entries_array() {
    let entries = vec![BlocklistEntry::new(
        "did:web:alice.example",
        Some("spam".into()),
    )];
    let body = build_blocklist_account_data_body("did:web:owner.example", 1, &entries).unwrap();
    assert_eq!(body["owner"], "did:web:owner.example");
    assert_eq!(body["version"], 1);
    assert_eq!(body["entries"][0]["target"]["kind"], "actor");
    assert_eq!(body["entries"][0]["target"]["did"], "did:web:alice.example");
    assert_eq!(body["entries"][0]["mode"], "block");
    assert_eq!(body["entries"][0]["reason_code"], "spam");
    assert!(body["entries"][0]["created_at"].is_string());
    assert!(
        body["entries"][0]["applies_to"]
            .as_array()
            .unwrap()
            .contains(&json!("messages"))
    );
}

#[test]
fn build_blocklist_account_data_body_clears_with_next_empty_revision() {
    let body = build_blocklist_account_data_body("did:web:owner.example", 7, &[]).unwrap();
    assert_eq!(body["owner"], "did:web:owner.example");
    assert_eq!(body["version"], 7);
    assert_eq!(body["entries"], json!([]));
}

#[test]
fn blocklist_entries_parse_canonical_account_data_body() {
    let body = json!({
        "owner": "did:web:owner.example",
        "version": 1,
        "entries": [
            {
                "target": {"kind": "actor", "did": "did:web:mallory.example"},
                "mode": "block",
                "applies_to": ["messages"],
                "reason_code": "harassment",
                "created_at": "2026-05-29T00:00:00.000Z"
            },
            {
                "target": {"kind": "domain", "value": "Example.com"},
                "mode": "block",
                "applies_to": ["dm", "calls"],
                "expires_at": "2026-07-01T00:00:00.000Z",
                "created_at": "2026-05-29T00:00:00.000Z"
            }
        ]
    });
    let entries = blocklist_entries_from_account_data(&body, "did:web:owner.example", 1).unwrap();
    // The canonical actor + domain blocks parse through the SDK wire model.
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].did, "did:web:mallory.example");
    assert_eq!(entries[0].kind, "actor");
    assert_eq!(entries[0].reason.as_deref(), Some("harassment"));
    assert_eq!(
        chrono::DateTime::parse_from_rfc3339(entries[0].blocked_at.as_deref().unwrap()).unwrap(),
        chrono::DateTime::parse_from_rfc3339("2026-05-29T00:00:00.000Z").unwrap()
    );
    // Domain target: kind preserved, value normalized (lower-cased),
    // applies_to + expires_at round-tripped.
    assert_eq!(entries[1].kind, "domain");
    assert_eq!(entries[1].did, "example.com");
    assert_eq!(entries[1].applies_to, vec!["dm", "calls"]);
    assert_eq!(
        chrono::DateTime::parse_from_rfc3339(entries[1].expires_at.as_deref().unwrap()).unwrap(),
        chrono::DateTime::parse_from_rfc3339("2026-07-01T00:00:00.000Z").unwrap()
    );
}

#[test]
fn blocklist_round_trip_preserves_owner_closed_targets_modes_and_surfaces() {
    let owner = "did:web:owner.example";
    let body = json!({
        "owner": owner,
        "version": 4,
        "entries": [
            {
                "target": {
                    "kind": "device",
                    "object_ref": "ak:device:01904100-0000-7000-8000-000000000901"
                },
                "mode": "mute",
                "applies_to": ["contacts", "notifications"],
                "created_at": "2026-05-29T00:00:00.000Z"
            },
            {
                "target": {
                    "kind": "applet",
                    "object_ref": "ak:applet:01904100-0000-7000-8000-000000000902"
                },
                "mode": "hide",
                "applies_to": ["applets"],
                "created_at": "2026-05-29T00:00:01.000Z"
            }
        ]
    });

    let entries = blocklist_entries_from_account_data(&body, owner, 4).unwrap();
    assert_eq!(entries[0].kind, "device");
    assert_eq!(
        entries[0].mode,
        arkret_models_collaboration::objects::productivity::AccountBlocklistMode::Mute
    );
    assert_eq!(entries[0].applies_to, vec!["contacts", "notifications"]);
    assert_eq!(entries[1].kind, "applet");
    assert_eq!(
        entries[1].mode,
        arkret_models_collaboration::objects::productivity::AccountBlocklistMode::Hide
    );

    let rebuilt = build_blocklist_account_data_body(owner, 5, &entries).unwrap();
    assert_eq!(rebuilt["owner"], owner);
    assert_eq!(rebuilt["version"], 5);
    assert_eq!(rebuilt["entries"][0]["target"]["kind"], "device");
    assert_eq!(
        rebuilt["entries"][0]["target"]["object_ref"],
        "ak:device:01904100-0000-7000-8000-000000000901"
    );
    assert_eq!(rebuilt["entries"][0]["mode"], "mute");
    assert_eq!(rebuilt["entries"][1]["target"]["kind"], "applet");
    assert_eq!(rebuilt["entries"][1]["mode"], "hide");

    assert!(blocklist_entries_from_account_data(&body, "did:web:other.example", 4).is_err());
    assert!(blocklist_entries_from_account_data(&body, owner, 3).is_err());
}

#[test]
fn blocklist_projection_respects_mode_surface_and_expiry() {
    use arkret_models_collaboration::objects::productivity::AccountBlocklistMode;

    let mut muted = BlocklistEntry::new("did:web:muted.example", None);
    muted.mode = AccountBlocklistMode::Mute;
    assert!(!is_blocked(&[muted.clone()], &muted.did));
    assert!(suppresses_notifications(
        &[muted.clone()],
        &muted.did,
        &["notifications"]
    ));
    assert!(!hides_actor_messages(&muted));

    let mut notification_only = BlocklistEntry::new("did:web:notification.example", None);
    notification_only.applies_to = vec!["notifications".to_owned()];
    assert!(!is_blocked(
        &[notification_only.clone()],
        &notification_only.did
    ));
    assert!(suppresses_notifications(
        &[notification_only.clone()],
        &notification_only.did,
        &["notifications"]
    ));

    let mut mention_only = BlocklistEntry::new("did:web:mention.example", None);
    mention_only.mode = AccountBlocklistMode::Mute;
    mention_only.applies_to = vec!["mentions".to_owned()];
    assert!(!suppresses_notifications(
        &[mention_only.clone()],
        &mention_only.did,
        &["notifications"]
    ));
    assert!(suppresses_notifications(
        &[mention_only.clone()],
        &mention_only.did,
        &["notifications", "mentions"]
    ));

    let mut hidden = BlocklistEntry::new("did:web:hidden.example", None);
    hidden.mode = AccountBlocklistMode::Hide;
    assert!(hides_actor_messages(&hidden));

    let mut expired = BlocklistEntry::new("did:web:expired.example", None);
    expired.expires_at = Some("2020-01-01T00:00:00.000Z".to_owned());
    assert!(!is_blocked(&[expired.clone()], &expired.did));
    assert!(!suppresses_notifications(
        &[expired.clone()],
        &expired.did,
        &["notifications"]
    ));
}

// ── A4a — ak.client.ui_state shape + merge logic ────────────────────────────
#[test]
fn build_client_ui_body_only_emits_present_fields() {
    let body = build_client_ui_body(Some("light"), None, &BTreeMap::new(), None);
    assert_eq!(body["theme"], "light");
    assert!(body.get("sidebar_collapsed").is_none());
    assert!(body.get("per_realm_view").is_none());
    assert!(body.get("avatar_blob_ref").is_none());

    let mut per_realm = BTreeMap::new();
    per_realm.insert("ak:realm:abc".to_owned(), "kanban".to_owned());
    let body = build_client_ui_body(Some("night"), Some(true), &per_realm, None);
    assert_eq!(body["theme"], "night");
    assert_eq!(body["sidebar_collapsed"], true);
    assert_eq!(body["per_realm_view"]["ak:realm:abc"], "kanban");

    // Empty theme string is dropped (treated as unset).
    let body = build_client_ui_body(Some(""), Some(false), &BTreeMap::new(), None);
    assert!(body.get("theme").is_none());
    assert_eq!(body["sidebar_collapsed"], false);
}

// ── A4b — avatar_blob_ref round-trip through ak.client.ui_state ─────────────
#[test]
fn avatar_blob_ref_round_trips_through_client_ui() {
    let blob_ref =
        "ak:blob:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let body = build_client_ui_body(Some("light"), None, &BTreeMap::new(), Some(blob_ref));
    assert_eq!(body["avatar_blob_ref"], blob_ref);
    assert_eq!(
        avatar_blob_ref_from_client_ui(&body),
        Some(blob_ref.to_owned())
    );

    // Empty / whitespace-only references are preserved as an explicit
    // tombstone so another device can clear its local avatar cache.
    let tombstoned = build_client_ui_body(None, None, &BTreeMap::new(), Some("   "));
    assert_eq!(tombstoned["avatar_blob_ref"], "");
    assert_eq!(avatar_blob_ref_from_client_ui(&tombstoned), None);
    assert!(avatar_blob_ref_tombstoned_from_client_ui(&tombstoned));

    let without_avatar = json!({"theme": "light"});
    assert_eq!(avatar_blob_ref_from_client_ui(&without_avatar), None);

    // Non-string values are rejected.
    let weird = json!({"avatar_blob_ref": 42});
    assert_eq!(avatar_blob_ref_from_client_ui(&weird), None);

    let malformed = json!({"avatar_blob_ref": "ak:blob:sha256:not-a-digest"});
    assert_eq!(avatar_blob_ref_from_client_ui(&malformed), None);
}

#[test]
fn theme_from_client_ui_only_accepts_known_themes() {
    assert_eq!(
        theme_from_client_ui(&json!({"theme": "light"})),
        Some("light".to_owned())
    );
    assert_eq!(
        theme_from_client_ui(&json!({"theme": "night"})),
        Some("night".to_owned())
    );
    assert_eq!(
        theme_from_client_ui(&json!({"theme": "system"})),
        Some("system".to_owned())
    );
    assert_eq!(theme_from_client_ui(&json!({"theme": "neon"})), None);
    assert_eq!(theme_from_client_ui(&json!({"theme": ""})), None);
    assert_eq!(theme_from_client_ui(&json!({})), None);
}

#[test]
fn merge_client_ui_theme_prefers_remote_when_different() {
    // remote has a different valid theme → return it
    assert_eq!(
        merge_client_ui_theme("light", &json!({"theme": "night"})),
        Some("night".to_owned())
    );
    // remote matches local → no change
    assert_eq!(
        merge_client_ui_theme("light", &json!({"theme": "light"})),
        None
    );
    // remote has no theme field → no change (older client wrote only
    // sidebar_collapsed); local stays authoritative
    assert_eq!(
        merge_client_ui_theme("light", &json!({"sidebar_collapsed": true})),
        None
    );
    // remote has an invalid theme → no change
    assert_eq!(
        merge_client_ui_theme("system", &json!({"theme": "neon"})),
        None
    );
}

#[test]
fn build_account_data_set_emits_canonical_kind() {
    let op = build_account_data_set(
        "ak:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice",
        &AccountDataKey::ClientReadReceipts,
        json!({"send": false}),
        0,
    )
    .build("node");
    assert_eq!(op.kind, "ak.account_data.set");
    assert_eq!(op.payload["key"], "ak.read_receipt.preferences");
    assert_eq!(op.payload["owner"], "did:web:alice");
    assert_eq!(op.payload["body"]["send"], false);
    assert!(op.payload["updated_at"].is_string());
}

#[test]
fn productivity_account_data_keys_use_sdk_private_derivation() {
    let ns = b"inkson-account-data-test-key";
    let target_ref = "ak:strand:01904100-0000-7000-8000-000000000001";
    let snooze = snooze_account_data_key(ns, target_ref).unwrap();
    let saved = saved_account_data_key(ns, "Focus", target_ref).unwrap();
    let draft = draft_account_data_key(
        ns,
        arkret_sdk::DraftKind::Message,
        target_ref,
        DRAFT_MESSAGE_SLOT,
    )
    .unwrap();
    let manifest =
        search_index_manifest_account_data_key(ns, "ak:realm:01904100-0000-7000-8000-000000000001")
            .unwrap();
    let transfer = file_transfer_account_data_key(ns, "0123456789abcdefghijkl").unwrap();

    for key in [&snooze, &saved, &draft, &manifest, &transfer] {
        assert!(validate_private_account_data_key(key).is_ok());
        assert!(!key.contains("ak:strand:"));
        assert!(!key.contains("Focus"));
    }
}

#[test]
fn scheduled_send_key_requires_message_typed_id() {
    assert!(
        scheduled_send_account_data_key("ak:message:01904100-0000-7000-8000-000000000001").is_ok()
    );
    assert!(scheduled_send_account_data_key("not-a-message-id").is_err());
}

#[test]
fn contact_and_realm_remarks_are_encrypted_account_data() {
    let realm_id = "ak:realm:01904100-0000-7000-8000-000000000001";
    let realm_key = realm_remark_account_data_key(realm_id);
    let actor_key = contact_remark_account_data_key("did:web:alice.example");

    assert_eq!(
        private_account_data_key_prefix(&realm_key),
        Some(arkret_sdk::AccountDataKey::CONTACTS_REALM)
    );
    assert_eq!(
        private_account_data_key_prefix(&actor_key),
        Some(arkret_sdk::AccountDataKey::CONTACTS_ACTOR)
    );
    assert!(validate_private_account_data_key(&realm_key).is_ok());
    assert!(validate_private_account_data_key(&actor_key).is_ok());

    let op = build_account_data_set(
        realm_id,
        "did:web:alice.example",
        &AccountDataKey::Custom(realm_key),
        json!({"pinned": true}),
        0,
    )
    .build("node");
    assert!(op.payload.contains_key("encrypted_payload"));
    assert!(!op.payload.contains_key("body"));
}

#[test]
fn private_view_and_notification_inbox_are_encrypted_account_data() {
    let realm_id = "ak:realm:01904100-0000-7000-8000-000000000001";
    let view_key = private_view_account_data_key("ak:view:01904100-0000-7000-8000-848727f328fe")
        .expect("valid view id");
    let inbox_key =
        notification_inbox_account_data_key("ak:notification:01904100-0000-7000-8000-848727f328ff")
            .expect("valid notification id");

    assert_eq!(
        private_account_data_key_prefix(&view_key),
        Some(arkret_sdk::AccountDataKey::VIEWS_PRIVATE)
    );
    assert_eq!(
        private_account_data_key_prefix(&inbox_key),
        Some(arkret_sdk::AccountDataKey::NOTIFICATIONS_INBOX)
    );
    validate_private_account_data_key(&view_key).unwrap();
    validate_private_account_data_key(&inbox_key).unwrap();

    // The definition / inbox state must land in `encrypted_payload`; `body`
    // would put a View title or query in front of the server in plaintext.
    for key in [&view_key, &inbox_key] {
        let op = build_account_data_set(
            realm_id,
            "did:web:alice.example",
            &AccountDataKey::Custom(key.clone()),
            json!({"ciphertext": "opaque"}),
            0,
        )
        .build("node");
        assert!(op.payload.contains_key("encrypted_payload"), "{key}");
        assert!(!op.payload.contains_key("body"), "{key}");
    }

    assert!(
        private_view_account_data_key("ak:realm:01904100-0000-7000-8000-848727f328fe").is_err()
    );
    assert!(notification_inbox_account_data_key("not-a-notification-id").is_err());
}

#[test]
fn private_account_data_builders_emit_encrypted_payload() {
    let key = "ak.scheduled_send.v1:ak:message:01904100-0000-7000-8000-000000000001";
    let op = build_private_account_data_set(
        "ak:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice",
        key,
        json!({"ciphertext": "opaque"}),
        0,
    )
    .unwrap()
    .build("node");
    assert_eq!(op.kind, "ak.account_data.set");
    assert_eq!(op.payload["key"], key);
    assert!(!op.payload.contains_key("body"));
    assert_eq!(op.payload["encrypted_payload"]["ciphertext"], "opaque");

    let tombstone = build_private_account_data_tombstone(
        "ak:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice",
        key,
        1,
    )
    .unwrap()
    .build("node");
    assert_eq!(tombstone.payload["tombstone"], true);
}

#[test]
fn private_account_data_builder_emits_required_revision() {
    let key = draft_account_data_key(
        b"inkson-account-data-test-key",
        arkret_sdk::DraftKind::Message,
        "ak:realm:01904100-0000-7000-8000-000000000001",
        DRAFT_MESSAGE_SLOT,
    )
    .unwrap();
    let op = build_private_account_data_set(
        "ak:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice",
        &key,
        json!({"ciphertext": "opaque"}),
        7,
    )
    .unwrap()
    .build("node");
    assert_eq!(op.kind, "ak.account_data.set");
    assert_eq!(op.payload["expected_revision"], 7);
    assert!(!op.payload.contains_key("body"));
    assert_eq!(op.payload["encrypted_payload"]["ciphertext"], "opaque");
}

#[test]
fn generic_builder_does_not_put_private_values_under_body() {
    let key = AccountDataKey::Custom(
        "ak.scheduled_send.v1:ak:message:01904100-0000-7000-8000-000000000001".to_owned(),
    );
    let op = build_account_data_set(
        "ak:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice",
        &key,
        json!({"ciphertext": "opaque"}),
        0,
    )
    .build("node");
    assert!(!op.payload.contains_key("body"));
    assert_eq!(op.payload["encrypted_payload"]["ciphertext"], "opaque");
}

#[test]
fn build_account_data_tombstone_emits_canonical_payload() {
    let op = build_account_data_tombstone(
        "ak:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice",
        &AccountDataKey::ClientReadReceipts,
        3,
    )
    .build("node");
    assert_eq!(op.kind, "ak.account_data.set");
    assert_eq!(op.payload["key"], "ak.read_receipt.preferences");
    assert_eq!(op.payload["owner"], "did:web:alice");
    assert_eq!(op.payload["expected_revision"], 3);
    assert_eq!(op.payload["tombstone"], true);
    assert!(op.payload["updated_at"].is_string());
}

#[test]
fn draft_sync_value_requires_origin_device_id_and_current_slot_shape() {
    let missing_origin = json!({
        "target_ref": "ak:realm:01904100-0000-7000-8000-000000000001",
        "kind": "message",
        "draft_slot": "compose",
        "content": {"body": "draft"},
        "updated_hlc": "01970e589d21-0000-a13f9c2e",
        "retention_expires_at": "2026-06-07T00:00:00.000Z"
    });
    assert!(draft_sync_value_from_account_data(&missing_origin).is_err());

    let bad_slot = build_message_draft_sync_value(
        "ak:realm:01904100-0000-7000-8000-000000000001",
        json!({"body": "draft"}),
        "01970e589d21-0000-a13f9c2e",
        "ak:device:01904100-0000-7000-8000-000000000001",
        "2026-06-07T00:00:00.000Z",
    )
    .map(|mut value| {
        value.draft_slot = "main".to_owned();
        value
    })
    .unwrap();
    assert!(validate_draft_sync_value(&bad_slot).is_err());

    let field_slot = draft_slot_for_strand_field_path(&json!("metadata.title")).unwrap();
    assert!(field_slot.starts_with("field_"));
    assert_eq!(field_slot.len(), "field_".len() + 64);
    assert!(validate_draft_slot(arkret_sdk::DraftKind::StrandField, &field_slot).is_ok());
}

#[test]
fn draft_merge_uses_hlc_then_origin_device_tiebreaker() {
    let local = build_message_draft_sync_value(
        "ak:realm:01904100-0000-7000-8000-000000000001",
        json!({"body": "local"}),
        "01970e589d21-0000-a13f9c2e",
        "ak:device:01904100-0000-7000-8000-000000000001",
        "2026-06-07T00:00:00.000Z",
    )
    .unwrap();
    let newer_remote = build_message_draft_sync_value(
        "ak:realm:01904100-0000-7000-8000-000000000001",
        json!({"body": "remote"}),
        "01970e589d22-0000-a13f9c2e",
        "ak:device:01904100-0000-7000-8000-000000000002",
        "2026-06-07T00:00:00.000Z",
    )
    .unwrap();
    let merged = merge_draft_values(Some(&local), newer_remote).unwrap();
    assert_eq!(merged.choice, AccountDataMergeChoice::Remote);
    assert_eq!(merged.winner.content["body"], "remote");
    assert_eq!(merged.conflict_copy.unwrap().content["body"], "local");

    let same_hlc_higher_device = build_message_draft_sync_value(
        "ak:realm:01904100-0000-7000-8000-000000000001",
        json!({"body": "device wins"}),
        "01970e589d21-0000-a13f9c2e",
        "ak:device:01904100-0000-7000-8000-000000000002",
        "2026-06-07T00:00:00.000Z",
    )
    .unwrap();
    let merged = merge_draft_values(Some(&local), same_hlc_higher_device).unwrap();
    assert_eq!(merged.choice, AccountDataMergeChoice::Remote);
    assert_eq!(merged.winner.content["body"], "device wins");
}

#[test]
fn draft_merge_fails_closed_for_same_hlc_and_device_with_different_content() {
    let local = build_message_draft_sync_value(
        "ak:realm:01904100-0000-7000-8000-000000000001",
        json!({"body": "a"}),
        "01970e589d21-0000-a13f9c2e",
        "ak:device:01904100-0000-7000-8000-000000000001",
        "2026-06-07T00:00:00.000Z",
    )
    .unwrap();
    let remote = build_message_draft_sync_value(
        "ak:realm:01904100-0000-7000-8000-000000000001",
        json!({"body": "b"}),
        "01970e589d21-0000-a13f9c2e",
        "ak:device:01904100-0000-7000-8000-000000000001",
        "2026-06-07T00:00:00.000Z",
    )
    .unwrap();
    assert!(merge_draft_values(Some(&local), remote).is_err());
}
