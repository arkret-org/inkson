use std::collections::BTreeMap;

use serde_json::json;

use super::*;

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
            "client.ui": {
                "key": "client.ui",
                "value": {"theme": "light"},
                "digest": "sha256:00",
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
        "client.ui",
        "ck.read_receipt.preferences",
        "ck.presence.visibility",
        "ck.presence.preference",
        "ck.account.blocklist",
        "ck.push_rules",
        "ck.dnd_schedule",
        "client.language",
    ] {
        assert_eq!(AccountDataKey::from_wire(s).as_wire(), s);
    }
    assert_eq!(AccountDataKey::from_wire("custom.x").as_wire(), "custom.x");
}

#[test]
fn set_recomputes_digest() {
    let mut store = AccountDataStore::new();
    let digest_a = store
        .set(
            AccountDataKey::ClientUi,
            json!({"sidebar_collapsed": true}),
            "0-0-0".into(),
        )
        .unwrap();
    let digest_b = store
        .set(
            AccountDataKey::ClientUi,
            json!({"sidebar_collapsed": false}),
            "0-0-1".into(),
        )
        .unwrap();
    assert_ne!(digest_a, digest_b);
    assert_eq!(
        store.get(&AccountDataKey::ClientUi).unwrap().digest,
        digest_b
    );
}

#[test]
fn realm_remark_key_round_trip() {
    let realm_id = "ak:realm:0196419b-0000-7000-8000-000000000000";
    let key = realm_remark_account_data_key(realm_id);
    assert_eq!(key, format!("ck.contacts.realm.{realm_id}"));
    assert_eq!(realm_id_from_realm_remark_key(&key), Some(realm_id));
    assert_eq!(
        realm_id_from_realm_remark_key("ck.read_receipt.preferences"),
        None
    );
}

#[test]
fn contact_remark_key_round_trip() {
    let did = "did:web:alice.example";
    let key = contact_remark_account_data_key(did);
    assert_eq!(key, format!("ck.contacts.actor.{did}"));
    assert_eq!(actor_id_from_contact_remark_key(&key), Some(did));
    assert_eq!(
        actor_id_from_contact_remark_key("ck.contacts.realm.x"),
        None
    );
}

#[test]
fn realm_remark_serialises_minimal_payload() {
    // Empty fields MUST NOT appear on the wire — keeps the payload
    // tombstone-friendly and avoids leaking placeholder data.
    let remark = RealmRemark::new(
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
    assert!(wire.get("note").is_none());
    assert!(wire.get("pinned").is_none());
    assert!(wire.get("tags").is_none());
}

#[test]
fn realm_remark_display_name_prefers_local_name() {
    let r = RealmRemark::new("ak:realm:abc", "Acme · Eng");
    assert_eq!(r.display_name("Engineering"), "Acme · Eng");
    let empty = RealmRemark {
        local_name: "   ".into(),
        ..RealmRemark::default()
    };
    assert_eq!(empty.display_name("Engineering"), "Engineering");
}

#[test]
fn realm_remark_is_empty_treats_whitespace_as_tombstone() {
    let r = RealmRemark {
        local_name: "   ".into(),
        note: String::new(),
        ..RealmRemark::default()
    };
    assert!(r.is_empty());
    let r2 = RealmRemark {
        local_name: "x".into(),
        ..RealmRemark::default()
    };
    assert!(!r2.is_empty());
}

#[test]
fn realm_remark_pinned_builder_preserves_private_fields() {
    let realm_id = "ak:realm:0196419b-0000-7000-8000-000000000000";
    let existing = RealmRemark {
        version: 1,
        subject: RemarkSubject {
            kind: "realm".to_owned(),
            id: realm_id.to_owned(),
        },
        local_name: "Acme Eng".to_owned(),
        note: "Private note".to_owned(),
        tags: vec!["work".to_owned()],
        pinned: false,
        verified_title_at_save: Some("Engineering".to_owned()),
        verified_owning_organizations_at_save: vec!["did:web:acme.example".to_owned()],
        saved_at: Some("2026-06-01T00:00:00Z".to_owned()),
        updated_at: Some("2026-06-01T00:00:00Z".to_owned()),
    };

    let next = RealmRemark::with_pinned_preserving_fields(
        realm_id,
        Some(&existing),
        true,
        Some("2026-06-06T00:00:00Z".to_owned()),
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
    assert_eq!(next.updated_at.as_deref(), Some("2026-06-06T00:00:00Z"));
}

#[test]
fn realm_remark_unpin_builder_can_tombstone_empty_remark() {
    let realm_id = "ak:realm:0196419b-0000-7000-8000-000000000000";
    let existing = RealmRemark::with_pinned_preserving_fields(
        realm_id,
        None,
        true,
        Some("2026-06-06T00:00:00Z".to_owned()),
    );
    assert!(!existing.is_empty());

    let next = RealmRemark::with_pinned_preserving_fields(
        realm_id,
        Some(&existing),
        false,
        Some("2026-06-06T00:01:00Z".to_owned()),
    );

    assert!(!next.pinned);
    assert_eq!(next.subject.id, realm_id);
    assert!(next.is_empty());
}

#[test]
fn contact_remark_serialises_minimal_private_payload() {
    let remark = ContactRemark::new("did:web:alice.example", "Alice from Ops");
    let wire = serde_json::to_value(&remark).unwrap();
    assert_eq!(wire["version"], 1);
    assert_eq!(wire["actor_id"], "did:web:alice.example");
    assert_eq!(wire["local_name"], "Alice from Ops");
    assert!(wire.get("note").is_none());
    assert_eq!(remark.display_name("Alice"), "Alice from Ops");

    let empty = ContactRemark {
        actor_id: "did:web:alice.example".to_owned(),
        local_name: " ".to_owned(),
        ..ContactRemark::default()
    };
    assert!(empty.is_empty());
}

#[test]
fn contact_remark_pinned_builder_preserves_private_fields() {
    let actor_id = "did:web:alice.example";
    let existing = ContactRemark {
        version: 1,
        actor_id: actor_id.to_owned(),
        local_name: "Alice from Ops".to_owned(),
        note: "met at launch".to_owned(),
        tags: vec!["ops".to_owned()],
        pinned: false,
        verified_handle_at_save: Some("alice:example.com".to_owned()),
        saved_at: Some("2026-06-05T00:00:00Z".to_owned()),
        updated_at: Some("2026-06-05T00:00:00Z".to_owned()),
    };

    let next = ContactRemark::with_pinned_preserving_fields(
        actor_id,
        Some(&existing),
        true,
        Some("2026-06-06T00:00:00Z".to_owned()),
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
    assert_eq!(next.updated_at.as_deref(), Some("2026-06-06T00:00:00Z"));
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
        Some("2026-05-18T00:00:00Z".into()),
    ));
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].did, "did:web:alice.example");
    assert_eq!(list[0].reason.as_deref(), Some("spam"));
    assert_eq!(list[0].blocked_at.as_deref(), Some("2026-05-18T00:00:00Z"));
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
        Some("2026-08-01T00:00:00Z".into()),
        Some("2026-05-18T00:00:00Z".into()),
    ));
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].kind, "domain");
    assert_eq!(list[0].did, "spam.example");
    assert_eq!(list[0].applies_to, vec!["dm", "calls"]);
    assert_eq!(list[0].expires_at.as_deref(), Some("2026-08-01T00:00:00Z"));
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
        Some("2026-08-01T00:00:00Z".into()),
        None,
    );
    let body = build_blocklist_account_data_body(&list);
    let entry = &body["entries"][0];
    assert_eq!(entry["target"]["kind"], "domain");
    // Domain kinds emit the value under `domain`, not `did`.
    assert_eq!(entry["target"]["domain"], "spam.example");
    assert!(entry["target"].get("did").is_none());
    assert_eq!(entry["mode"], "block");
    assert_eq!(entry["applies_to"], json!(["dm"]));
    assert_eq!(entry["expires_at"], "2026-08-01T00:00:00Z");
    assert!(entry["entry_id"].as_str().unwrap().starts_with("ak:block:"));
}

#[test]
fn build_blocklist_account_data_body_emits_null_expiry_for_permanent_block() {
    let mut list: Vec<BlocklistEntry> = Vec::new();
    block_user_in(&mut list, "did:web:alice.example", None, None);
    let body = build_blocklist_account_data_body(&list);
    // Permanent blocks emit an explicit null so peers can tell "no expiry"
    // apart from "field absent".
    assert!(body["entries"][0]["expires_at"].is_null());
}

#[test]
fn build_blocklist_account_data_body_emits_entries_array() {
    let entries = vec![BlocklistEntry::new(
        "did:web:alice.example",
        Some("spam".into()),
    )];
    let body = build_blocklist_account_data_body(&entries);
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
fn blocklist_entries_parse_canonical_account_data_body() {
    let body = json!({
        "version": 1,
        "entries": [
            {
                "target": {"kind": "actor", "did": "did:web:mallory.example"},
                "mode": "block",
                "reason_code": "harassment",
                "created_at": "2026-05-29T00:00:00Z"
            },
            {
                "target": {"kind": "actor", "did": "did:web:carol.example"},
                "mode": "unblock",
                "created_at": "2026-05-29T00:00:00Z"
            },
            {
                "target": {"kind": "domain", "domain": "Example.com"},
                "mode": "block",
                "applies_to": ["dm", "calls"],
                "expires_at": "2026-07-01T00:00:00Z",
                "created_at": "2026-05-29T00:00:00Z"
            }
        ]
    });
    let entries = blocklist_entries_from_account_data(&body).unwrap();
    // The `unblock` mode entry is dropped; the actor + domain blocks parse.
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].did, "did:web:mallory.example");
    assert_eq!(entries[0].kind, "actor");
    assert_eq!(entries[0].reason.as_deref(), Some("harassment"));
    assert_eq!(
        entries[0].blocked_at.as_deref(),
        Some("2026-05-29T00:00:00Z")
    );
    // Domain target: kind preserved, value normalized (lower-cased),
    // applies_to + expires_at round-tripped.
    assert_eq!(entries[1].kind, "domain");
    assert_eq!(entries[1].did, "example.com");
    assert_eq!(entries[1].applies_to, vec!["dm", "calls"]);
    assert_eq!(
        entries[1].expires_at.as_deref(),
        Some("2026-07-01T00:00:00Z")
    );
}

// ── A4a — client.ui shape + merge logic ────────────────────────────
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

// ── A4b — avatar_blob_ref round-trip through client.ui ─────────────
#[test]
fn avatar_blob_ref_round_trips_through_client_ui() {
    let blob_ref = "ak:blob:sha256:0123456789abcdef";
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
    )
    .build("node");
    assert_eq!(op.kind, "ck.account_data.set");
    assert_eq!(op.payload["key"], "ck.read_receipt.preferences");
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
        Some(arkret_sdk::ACCOUNT_DATA_TYPE_CONTACTS_REALM)
    );
    assert_eq!(
        private_account_data_key_prefix(&actor_key),
        Some(arkret_sdk::ACCOUNT_DATA_TYPE_CONTACTS_ACTOR)
    );
    assert!(validate_private_account_data_key(&realm_key).is_ok());
    assert!(validate_private_account_data_key(&actor_key).is_ok());

    let op = build_account_data_set(
        realm_id,
        "did:web:alice.example",
        &AccountDataKey::Custom(realm_key),
        json!({"pinned": true}),
    )
    .build("node");
    assert!(op.payload.get("encrypted_payload").is_some());
    assert!(op.payload.get("body").is_none());
}

#[test]
fn private_account_data_builders_emit_encrypted_payload() {
    let key = "ck.scheduled_send.v1:ak:message:01904100-0000-7000-8000-000000000001";
    let op = build_private_account_data_set(
        "ak:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice",
        key,
        json!({"ciphertext": "opaque"}),
    )
    .unwrap()
    .build("node");
    assert_eq!(op.kind, "ck.account_data.set");
    assert_eq!(op.payload["key"], key);
    assert!(op.payload.get("body").is_none());
    assert_eq!(op.payload["encrypted_payload"]["ciphertext"], "opaque");

    let tombstone = build_private_account_data_tombstone(
        "ak:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice",
        key,
    )
    .unwrap()
    .build("node");
    assert_eq!(tombstone.payload["tombstone"], true);
}

#[test]
fn private_account_data_builder_can_emit_cas_guard() {
    let key = draft_account_data_key(
        b"inkson-account-data-test-key",
        arkret_sdk::DraftKind::Message,
        "ak:realm:01904100-0000-7000-8000-000000000001",
        DRAFT_MESSAGE_SLOT,
    )
    .unwrap();
    let expected = format!("sha256:{}", "12".repeat(32));
    let op = build_private_account_data_set_with_cas(
        "ak:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice",
        &key,
        json!({"ciphertext": "opaque"}),
        Some(&expected),
    )
    .unwrap()
    .build("node");
    assert_eq!(op.kind, "ck.account_data.set");
    assert_eq!(op.payload["expected_state_digest"], expected);
    assert!(op.payload.get("body").is_none());
    assert_eq!(op.payload["encrypted_payload"]["ciphertext"], "opaque");

    assert!(
        build_private_account_data_set_with_cas(
            "ak:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice",
            &key,
            json!({"ciphertext": "opaque"}),
            Some("sha256:ABC")
        )
        .is_err()
    );
}

#[test]
fn generic_builder_does_not_put_private_values_under_body() {
    let key = AccountDataKey::Custom(
        "ck.scheduled_send.v1:ak:message:01904100-0000-7000-8000-000000000001".to_owned(),
    );
    let op = build_account_data_set(
        "ak:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice",
        &key,
        json!({"ciphertext": "opaque"}),
    )
    .build("node");
    assert!(op.payload.get("body").is_none());
    assert_eq!(op.payload["encrypted_payload"]["ciphertext"], "opaque");
}

#[test]
fn build_account_data_tombstone_emits_canonical_payload() {
    let op = build_account_data_tombstone(
        "ak:realm:0196419b-0000-7000-8000-000000000001",
        "did:web:alice",
        &AccountDataKey::ClientReadReceipts,
    )
    .build("node");
    assert_eq!(op.kind, "ck.account_data.set");
    assert_eq!(op.payload["key"], "ck.read_receipt.preferences");
    assert_eq!(op.payload["owner"], "did:web:alice");
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
        "retention_expires_at": "2026-06-07T00:00:00Z"
    });
    assert!(draft_sync_value_from_account_data(&missing_origin).is_err());

    let bad_slot = build_message_draft_sync_value(
        "ak:realm:01904100-0000-7000-8000-000000000001",
        json!({"body": "draft"}),
        "01970e589d21-0000-a13f9c2e",
        "ak:device:01904100-0000-7000-8000-000000000001",
        "2026-06-07T00:00:00Z",
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
        "2026-06-07T00:00:00Z",
    )
    .unwrap();
    let newer_remote = build_message_draft_sync_value(
        "ak:realm:01904100-0000-7000-8000-000000000001",
        json!({"body": "remote"}),
        "01970e589d22-0000-a13f9c2e",
        "ak:device:01904100-0000-7000-8000-000000000002",
        "2026-06-07T00:00:00Z",
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
        "2026-06-07T00:00:00Z",
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
        "2026-06-07T00:00:00Z",
    )
    .unwrap();
    let remote = build_message_draft_sync_value(
        "ak:realm:01904100-0000-7000-8000-000000000001",
        json!({"body": "b"}),
        "01970e589d21-0000-a13f9c2e",
        "ak:device:01904100-0000-7000-8000-000000000001",
        "2026-06-07T00:00:00Z",
    )
    .unwrap();
    assert!(merge_draft_values(Some(&local), remote).is_err());
}

#[test]
fn legacy_local_drafts_migrate_to_private_draft_account_data() {
    let mut drafts = BTreeMap::new();
    drafts.insert(
        "ak:realm:01904100-0000-7000-8000-000000000001".to_owned(),
        " draft text ".to_owned(),
    );
    drafts.insert(
        "ak:realm:01904100-0000-7000-8000-000000000002".to_owned(),
        "   ".to_owned(),
    );
    let migrated = migrate_legacy_local_drafts(
        b"inkson-account-data-test-key",
        &drafts,
        "ak:device:01904100-0000-7000-8000-000000000001",
        "01970e589d21-0000-a13f9c2e",
        "2026-06-07T00:00:00Z",
    )
    .unwrap();
    assert_eq!(migrated.len(), 1);
    let item = &migrated[0];
    assert!(item.account_data_key.starts_with("ck.draft.v1:message:"));
    assert!(item.account_data_key.ends_with(":compose"));
    assert!(!item.account_data_key.contains("ak:realm:"));
    assert_eq!(item.value.content["body"], "draft text");
    assert_eq!(
        item.value.origin_device_id.to_string(),
        "ak:device:01904100-0000-7000-8000-000000000001"
    );
    assert!(item.state_digest.starts_with("sha256:"));
}

#[test]
fn legacy_saved_items_migrate_to_independent_private_values() {
    let migrated = migrate_legacy_saved_items(
        b"inkson-account-data-test-key",
        &[LegacySavedItem {
            collection_title: "Focus".to_owned(),
            target_ref: "ak:message:01904100-0000-7000-8000-000000000001".to_owned(),
            note: Some(" read later ".to_owned()),
        }],
        "01970e589d21-0000-a13f9c2e",
    )
    .unwrap();
    assert_eq!(migrated.len(), 1);
    assert!(migrated[0].account_data_key.starts_with("ck.saved.v1:"));
    assert!(!migrated[0].account_data_key.contains("Focus"));
    assert!(!migrated[0].account_data_key.contains("ak:message:"));
    assert_eq!(migrated[0].value.collection_title, "Focus");
    assert_eq!(migrated[0].value.note.as_deref(), Some("read later"));

    let wire = saved_item_account_data_value(&migrated[0].value).unwrap();
    assert_eq!(wire["kind"], "saved_item");
    assert_eq!(
        saved_item_value_from_account_data(&wire)
            .unwrap()
            .collection_title,
        "Focus"
    );
}
