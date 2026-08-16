//! Realm and contact remark (local rename) tests — spec client-preferences.md §3.7.

use super::*;

fn test_realm_remark(realm_id: &str, local_name: &str) -> crate::account_data::RealmRemark {
    let mut remark = crate::account_data::RealmRemark::new(
        arkret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
        chrono::Utc::now(),
    );
    remark.local_name = local_name.to_owned();
    remark
}

// ── Realm remarks (spec client-preferences.md §3.7) ─

#[test]
fn realm_remark_set_and_display_name_prefers_local_name() {
    let path = temp_state_path("realm-remark-set");
    let mut store = LocalStateStore::with_path(path);
    let realm_id = "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j";
    assert!(store.realm_remark(realm_id).is_none());
    assert_eq!(
        store.display_name_for_realm(realm_id, "Engineering"),
        "Engineering",
        "no remark → public title"
    );

    let remark = test_realm_remark(realm_id, "Acme · Eng");
    store.set_realm_remark(realm_id, remark);
    assert_eq!(
        store.display_name_for_realm(realm_id, "Engineering"),
        "Acme · Eng",
        "remark → local_name"
    );
    assert!(store.realm_remarks().contains_key(realm_id));
}

#[test]
fn realm_remark_empty_value_tombstones_entry() {
    let path = temp_state_path("realm-remark-tombstone");
    let mut store = LocalStateStore::with_path(path);
    let realm_id = "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j";
    store.set_realm_remark(realm_id, test_realm_remark(realm_id, "x"));
    assert!(store.realm_remark(realm_id).is_some());

    // Whitespace-only local_name is treated as tombstone — see
    // RealmRemark::is_empty.
    store.set_realm_remark(realm_id, test_realm_remark(realm_id, "   "));
    assert!(
        store.realm_remark(realm_id).is_none(),
        "empty remark must remove the entry"
    );
}

#[test]
fn realm_remark_remove_clears_only_target_realm() {
    let path = temp_state_path("realm-remark-remove");
    let mut store = LocalStateStore::with_path(path);
    let a = "ak:realm:AREJ2sax0HZ-uNC0y6FCrUUYnZGM7V9mXZR7P9w_0b-p";
    let b = "ak:realm:ASN1KcEFxnvVLnuGJd-DNluWz_xjnpOu-L3Kh4VB0JsG";
    store.set_realm_remark(a, test_realm_remark(a, "A"));
    store.set_realm_remark(b, test_realm_remark(b, "B"));

    store.remove_realm_remark(a);
    assert!(store.realm_remark(a).is_none());
    assert_eq!(
        store.realm_remark(b).map(|r| r.local_name),
        Some("B".to_owned()),
        "removing one Realm remark must not touch the other"
    );
}

#[test]
fn realm_remark_persists_to_disk_between_instances() {
    let path = temp_state_path("realm-remark-persist");
    let realm_id = "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j";
    {
        let mut writer = LocalStateStore::with_path(path.clone());
        writer.set_realm_remark(realm_id, test_realm_remark(realm_id, "Acme · Eng"));
    }
    let reader = LocalStateStore::with_path(path);
    assert_eq!(
        reader.display_name_for_realm(realm_id, "Engineering"),
        "Acme · Eng"
    );
}

#[test]
fn contact_remark_set_tombstone_and_display_name() {
    let path = temp_state_path("contact-remark-set");
    let mut store = LocalStateStore::with_path(path);
    let did = "ak:did_core:web:alice.example";
    assert_eq!(store.display_name_for_actor(did, "Alice"), "Alice");

    let accepted = crate::models::ContactListRow {
        peer: arkret_sdk::contact_operations::ContactPeer::Human {
            principal_id: arkret_sdk::DidCoreId::new(did).unwrap(),
        },
        state: arkret_sdk::ContactState::Accepted,
        request_event_ref: None,
        request_receipt: None,
        response_event_ref: None,
        tombstone_event_ref: None,
        next_prepare_input: None,
        granted_to_peer_scopes: Vec::new(),
        granted_by_peer_scopes: Vec::new(),
        bidirectional_scopes: Vec::new(),
        effective_scopes: None,
        peer_service_id: None,
        continuity_evidence: None,
        direct_conversation: None,
        agents: Vec::new(),
    };
    store.replace_accepted_human_contacts(std::slice::from_ref(&accepted));

    store.set_contact_remark(
        did,
        crate::account_data::ContactRemark::new(
            arkret_sdk::DidCoreId::new(did).unwrap(),
            "Alice from Ops",
            chrono::Utc::now(),
        ),
    );
    assert_eq!(store.display_name_for_actor(did, "Alice"), "Alice from Ops");
    assert!(store.contact_remarks().contains_key(did));

    store.replace_accepted_human_contacts(&[]);
    assert_eq!(store.display_name_for_actor(did, "Alice"), "Alice");
    assert!(store.contact_remarks().contains_key(did));
    store.replace_accepted_human_contacts(&[accepted]);

    store.set_contact_remark(
        did,
        crate::account_data::ContactRemark::new(
            arkret_sdk::DidCoreId::new(did).unwrap(),
            "",
            chrono::Utc::now(),
        ),
    );
    assert!(store.contact_remark(did).is_none());
}

#[test]
fn opaque_contact_remark_tombstone_removes_only_the_bound_principal() {
    let path = temp_state_path("contact-remark-opaque-tombstone");
    let mut store = LocalStateStore::with_path(path);
    let namespace_key: Vec<u8> = (0_u8..=31).collect();
    let alice = arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
    let bob = arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap();
    store.set_contact_remark(
        alice.to_string(),
        crate::account_data::ContactRemark::new(
            alice.clone(),
            "Alice from Ops",
            chrono::Utc::now(),
        ),
    );
    store.set_contact_remark(
        bob.to_string(),
        crate::account_data::ContactRemark::new(bob.clone(), "Bob", chrono::Utc::now()),
    );
    let persisted_projection = serde_json::to_string(&store.load()).unwrap();
    assert!(!persisted_projection.contains("Alice from Ops"));
    assert!(!persisted_projection.contains("\"contact_remarks\""));

    let alice_key =
        crate::account_data::contact_remark_account_data_key(&namespace_key, &alice).unwrap();
    assert!(store.remove_contact_remark_by_storage_key(&namespace_key, &alice_key));
    assert!(store.contact_remark(alice.as_str()).is_none());
    assert!(store.contact_remark(bob.as_str()).is_some());
    assert!(!store.remove_contact_remark_by_storage_key(&namespace_key, &alice_key));
}
