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
    let realm_id = "ak:realm:0196419b-0000-8000-8000-000000000000";
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
    let realm_id = "ak:realm:0196419b-0000-8000-8000-000000000000";
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
    let a = "ak:realm:00000000-0000-8000-8000-000000000001";
    let b = "ak:realm:00000000-0000-8000-8000-000000000002";
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
    let realm_id = "ak:realm:0196419b-0000-8000-8000-000000000000";
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
    let did = "did:web:alice.example";
    assert_eq!(store.display_name_for_actor(did, "Alice"), "Alice");

    store.set_contact_remark(
        did,
        crate::account_data::ContactRemark::new(
            arkret_sdk::Did::new(did.to_owned()).unwrap(),
            "Alice from Ops",
            chrono::Utc::now(),
        ),
    );
    assert_eq!(store.display_name_for_actor(did, "Alice"), "Alice from Ops");
    assert!(store.contact_remarks().contains_key(did));

    store.set_contact_remark(
        did,
        crate::account_data::ContactRemark::new(
            arkret_sdk::Did::new(did.to_owned()).unwrap(),
            "",
            chrono::Utc::now(),
        ),
    );
    assert!(store.contact_remark(did).is_none());
}
