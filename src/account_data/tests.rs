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
    let realm_id = "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j";
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
        "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j",
        "Acme · Eng",
    );
    let wire = serde_json::to_value(&remark).unwrap();
    assert_eq!(
        wire["subject"],
        serde_json::json!({
            "kind": "realm",
            "id": "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j"
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
    let realm_id = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let r = test_realm_remark(realm_id, "Acme · Eng");
    assert_eq!(r.display_name("Engineering"), "Acme · Eng");
    let empty = test_realm_remark(realm_id, "   ");
    assert_eq!(empty.display_name("Engineering"), "Engineering");
}

#[test]
fn realm_remark_is_empty_treats_whitespace_as_tombstone() {
    let realm_id = "ak:realm:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL";
    let r = test_realm_remark(realm_id, "   ");
    assert!(r.is_empty());
    let r2 = test_realm_remark(realm_id, "x");
    assert!(!r2.is_empty());
}

#[test]
fn realm_remark_pinned_builder_preserves_private_fields() {
    let realm_id = "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j";
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
            crate::mls_api_helpers::principal_core_id("did:web:acme.example").unwrap(),
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
    let realm_id = "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j";
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
    let actor_did = crate::mls_api_helpers::principal_core_id("did:web:alice.example").unwrap();
    let remark = ContactRemark::new(actor_did.clone(), "Alice from Ops", saved_at);
    let wire = serde_json::to_value(&remark).unwrap();
    assert_eq!(wire["version"], 1);
    assert_eq!(wire["subject"]["kind"], "actor");
    assert_eq!(wire["subject"]["actor_id"], actor_did.as_str());
    assert!(wire.get("actor_id").is_none());
    assert_eq!(wire["local_name"], "Alice from Ops");
    assert!(wire.get("note").is_none());
    assert_eq!(remark.display_name("Alice"), "Alice from Ops");

    let empty = ContactRemark {
        version: 1,
        subject: ContactRemarkSubject {
            kind: "actor".to_owned(),
            actor_id: actor_did,
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
    let actor_did = crate::mls_api_helpers::principal_core_id(actor_id).unwrap();
    let existing = ContactRemark {
        version: 1,
        subject: ContactRemarkSubject {
            kind: "actor".to_owned(),
            actor_id: actor_did.clone(),
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
fn typed_blocklist_entries_filter_by_closed_mode_surface_and_expiry() {
    use arkret_models_collaboration::objects::productivity::{
        AccountBlocklistMode, AccountBlocklistSurface,
    };

    let created_at = "2026-08-02T00:00:00.000Z".parse().unwrap();
    let mut entry = new_blocklist_entry(
        BlocklistUiTargetKind::Actor,
        "did:web:alice.example",
        Some("spam".to_owned()),
        vec![AccountBlocklistSurface::Messages],
        None,
        created_at,
    )
    .unwrap();
    assert!(is_blocked(&[entry.clone()], "did:web:alice.example"));
    assert!(!suppresses_notifications(
        &[entry.clone()],
        "did:web:alice.example",
        &[AccountBlocklistSurface::Notifications],
    ));

    entry.mode = AccountBlocklistMode::Mute;
    assert!(!is_blocked(&[entry.clone()], "did:web:alice.example"));
    entry.applies_to = vec![AccountBlocklistSurface::Notifications];
    assert!(suppresses_notifications(
        &[entry.clone()],
        "did:web:alice.example",
        &[AccountBlocklistSurface::Notifications],
    ));

    entry.expires_at = Some("2020-01-01T00:00:00.000Z".parse().unwrap());
    assert!(!suppresses_notifications(
        &[entry],
        "did:web:alice.example",
        &[AccountBlocklistSurface::Notifications],
    ));
}

#[test]
fn typed_blocklist_mutators_dedupe_and_unblock_exact_targets() {
    use arkret_models_collaboration::objects::productivity::AccountBlocklistSurface;

    let mut entries = Vec::new();
    let created_at = "2026-08-02T00:00:00.000Z".parse().unwrap();
    assert!(block_target_in(
        &mut entries,
        BlocklistUiTargetKind::Actor,
        "did:web:alice.example",
        None,
        vec![AccountBlocklistSurface::Messages],
        None,
        created_at,
    ));
    assert!(!block_target_in(
        &mut entries,
        BlocklistUiTargetKind::Actor,
        "did:web:alice.example",
        None,
        vec![AccountBlocklistSurface::Messages],
        None,
        created_at,
    ));
    assert!(block_target_in(
        &mut entries,
        BlocklistUiTargetKind::Domain,
        "https://EXAMPLE.com/path",
        None,
        vec![AccountBlocklistSurface::Dm],
        None,
        created_at,
    ));
    assert_eq!(entries.len(), 2);
    assert_eq!(blocklist_target_value(&entries[1].target), "example.com");

    let domain_target = entries[1].target.clone();
    assert!(unblock_target_in(&mut entries, &domain_target));
    assert_eq!(entries.len(), 1);
    assert!(unblock_user_in(&mut entries, "did:web:alice.example"));
    assert!(entries.is_empty());
}

#[test]
fn blocklist_payload_uses_cas_revision_and_preserves_empty_clear() {
    let owner = "did:web:owner.example";
    let body = build_blocklist_account_data_body(owner, 7, &[]).unwrap();
    assert_eq!(body["owner"], "ak:did_core:web:owner.example");
    assert_eq!(body["version"], 7);
    assert_eq!(body["entries"], json!([]));
    assert!(
        blocklist_entries_from_account_data(&body, owner)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn blocklist_payload_rejects_wrong_owner_and_zero_revision() {
    let owner = "did:web:owner.example";
    let body = build_blocklist_account_data_body(owner, 2, &[]).unwrap();
    assert!(blocklist_entries_from_account_data(&body, "did:web:other.example").is_err());

    let mut wrong_version = body;
    wrong_version["version"] = json!(0);
    assert!(blocklist_entries_from_account_data(&wrong_version, owner).is_err());
}

#[test]
fn blocklist_payload_round_trip_keeps_sdk_closed_types() {
    use arkret_models_collaboration::objects::productivity::{
        AccountBlocklistMode, AccountBlocklistSurface, AccountBlocklistTarget,
        AccountBlocklistValueTargetKind,
    };

    let created_at = "2026-08-02T00:00:00.000Z".parse().unwrap();
    let mut entry = new_blocklist_entry(
        BlocklistUiTargetKind::Domain,
        "Example.COM",
        Some("spam".to_owned()),
        vec![AccountBlocklistSurface::Dm, AccountBlocklistSurface::Calls],
        Some("2026-09-01T00:00:00.000Z".parse().unwrap()),
        created_at,
    )
    .unwrap();
    entry.mode = AccountBlocklistMode::Hide;

    let body =
        build_blocklist_account_data_body("did:web:owner.example", 9, &[entry.clone()]).unwrap();
    let decoded = blocklist_entries_from_account_data(&body, "did:web:owner.example").unwrap();
    assert_eq!(decoded, vec![entry]);
    assert!(matches!(
        &decoded[0].target,
        AccountBlocklistTarget::Value(target)
            if target.kind == AccountBlocklistValueTargetKind::Domain
                && target.value.as_str() == "example.com"
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
    per_realm.insert(
        "ak:realm:AQ_DYndfRLGXFTmGil1KY2oQW2AKjYbSN9mi4f-HASKg".to_owned(),
        "kanban".to_owned(),
    );
    let body = build_client_ui_body(Some("night"), Some(true), &per_realm, None);
    assert_eq!(body["theme"], "night");
    assert_eq!(body["sidebar_collapsed"], true);
    assert_eq!(
        body["per_realm_view"]["ak:realm:AQ_DYndfRLGXFTmGil1KY2oQW2AKjYbSN9mi4f-HASKg"],
        "kanban"
    );

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
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        "did:web:alice",
        &AccountDataKey::ClientReadReceipts,
        json!({"send": false}),
        0,
    )
    .unwrap()
    .build("node");
    assert_eq!(op.kind, "ak.account_data.set");
    assert_eq!(op.payload["key"], "ak.read_receipt.preferences");
    assert_eq!(op.payload["owner"], "ak:did_core:web:alice");
    assert_eq!(op.payload["body"]["send"], false);
    assert!(op.payload["updated_at"].is_string());
}

#[test]
fn productivity_account_data_keys_use_sdk_private_derivation() {
    let ns = b"inkson-account-data-test-key";
    let target_ref = "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let snooze = snooze_account_data_key(ns, target_ref).unwrap();
    let saved = saved_account_data_key(ns, "Focus", target_ref).unwrap();
    let draft = draft_account_data_key(
        ns,
        arkret_sdk::DraftKind::Message,
        target_ref,
        DRAFT_MESSAGE_SLOT,
    )
    .unwrap();
    let manifest = search_index_manifest_account_data_key(
        ns,
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
    )
    .unwrap();
    let transfer = file_transfer_account_data_key(ns, "0123456789abcdefghijkl").unwrap();

    for key in [&snooze, &saved, &draft, &manifest, &transfer] {
        assert!(validate_private_account_data_key(key).is_ok());
        assert!(!key.contains("ak:strand:"));
        assert!(!key.contains("Focus"));
    }
}

#[test]
fn scheduled_send_key_requires_independent_scheduled_send_id() {
    assert!(
        scheduled_send_account_data_key("ak:scheduled_send:01904100-0000-7000-8000-000000000003")
            .is_ok()
    );
    assert!(scheduled_send_account_data_key("not-a-scheduled-send-id").is_err());
}

#[test]
fn contact_and_realm_remarks_are_encrypted_account_data() {
    let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
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
    .unwrap()
    .build("node");
    assert!(op.payload.contains_key("encrypted_payload"));
    assert!(!op.payload.contains_key("body"));
}

#[test]
fn private_view_and_notification_inbox_are_encrypted_account_data() {
    let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let view_key =
        private_view_account_data_key("ak:view:AaiFHUI8GObKlPqeNvnl4E37L9moM-J0DjA4_UN9FvhR")
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
        .unwrap()
        .build("node");
        assert!(op.payload.contains_key("encrypted_payload"), "{key}");
        assert!(!op.payload.contains_key("body"), "{key}");
    }

    assert!(
        private_view_account_data_key("ak:realm:AaiFHUI8GObKlPqeNvnl4E37L9moM-J0DjA4_UN9FvhR")
            .is_err()
    );
    assert!(notification_inbox_account_data_key("not-a-notification-id").is_err());
}

#[test]
fn private_account_data_builders_emit_encrypted_payload() {
    let key = "ak.scheduled_send.v1:ak:scheduled_send:01904100-0000-7000-8000-000000000003";
    let op = build_private_account_data_set(
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
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
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
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
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        DRAFT_MESSAGE_SLOT,
    )
    .unwrap();
    let op = build_private_account_data_set(
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
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
        "ak.scheduled_send.v1:ak:scheduled_send:01904100-0000-7000-8000-000000000003".to_owned(),
    );
    let op = build_account_data_set(
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        "did:web:alice",
        &key,
        json!({"ciphertext": "opaque"}),
        0,
    )
    .unwrap()
    .build("node");
    assert!(!op.payload.contains_key("body"));
    assert_eq!(op.payload["encrypted_payload"]["ciphertext"], "opaque");
}

#[test]
fn build_account_data_tombstone_emits_canonical_payload() {
    let op = build_account_data_tombstone(
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        "did:web:alice",
        &AccountDataKey::ClientReadReceipts,
        3,
    )
    .unwrap()
    .build("node");
    assert_eq!(op.kind, "ak.account_data.set");
    assert_eq!(op.payload["key"], "ak.read_receipt.preferences");
    assert_eq!(op.payload["owner"], "ak:did_core:web:alice");
    assert_eq!(op.payload["expected_revision"], 3);
    assert_eq!(op.payload["tombstone"], true);
    assert!(op.payload["updated_at"].is_string());
}

#[test]
fn draft_sync_value_requires_origin_device_id_and_current_slot_shape() {
    let missing_origin = json!({
        "target_ref": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "kind": "message",
        "draft_slot": "compose",
        "content": {"body": "draft"},
        "updated_hlc": "01970e589d21-0000-a13f9c2e",
        "retention_expires_at": "2026-06-07T00:00:00.000Z"
    });
    assert!(draft_sync_value_from_account_data(&missing_origin).is_err());

    let bad_slot = build_message_draft_sync_value(
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        json!({"body": "draft"}),
        "01970e589d21-0000-a13f9c2e",
        "ak:device:01904100-0000-7000-8000-000000000001",
        "2026-06-07T00:00:00.000Z",
    )
    .map(|mut value| {
        match &mut value {
            arkret_sdk::DraftSyncValue::Message { draft_slot, .. }
            | arkret_sdk::DraftSyncValue::StrandField { draft_slot, .. } => {
                *draft_slot = "main".to_owned();
            }
        }
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
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        json!({"body": "local"}),
        "01970e589d21-0000-a13f9c2e",
        "ak:device:01904100-0000-7000-8000-000000000001",
        "2026-06-07T00:00:00.000Z",
    )
    .unwrap();
    let newer_remote = build_message_draft_sync_value(
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        json!({"body": "remote"}),
        "01970e589d22-0000-a13f9c2e",
        "ak:device:01904100-0000-7000-8000-000000000002",
        "2026-06-07T00:00:00.000Z",
    )
    .unwrap();
    let merged = merge_draft_values(Some(&local), newer_remote).unwrap();
    assert_eq!(merged.choice, AccountDataMergeChoice::Remote);
    assert_eq!(merged.winner.content()["body"], "remote");
    assert_eq!(merged.conflict_copy.unwrap().content()["body"], "local");

    let same_hlc_higher_device = build_message_draft_sync_value(
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        json!({"body": "device wins"}),
        "01970e589d21-0000-a13f9c2e",
        "ak:device:01904100-0000-7000-8000-000000000002",
        "2026-06-07T00:00:00.000Z",
    )
    .unwrap();
    let merged = merge_draft_values(Some(&local), same_hlc_higher_device).unwrap();
    assert_eq!(merged.choice, AccountDataMergeChoice::Remote);
    assert_eq!(merged.winner.content()["body"], "device wins");
}

#[test]
fn draft_merge_fails_closed_for_same_hlc_and_device_with_different_content() {
    let local = build_message_draft_sync_value(
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        json!({"body": "a"}),
        "01970e589d21-0000-a13f9c2e",
        "ak:device:01904100-0000-7000-8000-000000000001",
        "2026-06-07T00:00:00.000Z",
    )
    .unwrap();
    let remote = build_message_draft_sync_value(
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        json!({"body": "b"}),
        "01970e589d21-0000-a13f9c2e",
        "ak:device:01904100-0000-7000-8000-000000000001",
        "2026-06-07T00:00:00.000Z",
    )
    .unwrap();
    assert!(merge_draft_values(Some(&local), remote).is_err());
}
