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
    let realm_id = "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk";
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
    let realm_id = "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk";
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
    let realm_id = "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk";
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
    assert!(store.active_contact_remark(did).is_none());

    let accepted = crate::models::ContactListRow {
        peer: arkret_sdk::contact_operations::ContactPeer::Human {
            account_id: arkret_sdk::AccountId::new(
                arkret_sdk::DidCoreId::new(did).unwrap(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            ),
        },
        state: arkret_sdk::ContactState::Accepted,
        request_event_ref: None,
        request_message: None,
        response_event_ref: None,
        tombstone_event_ref: None,
        next_prepare_input: None,
        granted_to_peer_scopes: Vec::new(),
        granted_by_peer_scopes: Vec::new(),
        bidirectional_scopes: Vec::new(),
        effective_scopes: None,
        continuity_evidence: None,
        direct_conversation: None,
        contact_agent_projections: Vec::new(),
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
    assert_eq!(
        store
            .active_contact_remark(did)
            .expect("active remark")
            .display_name("Alice"),
        "Alice from Ops"
    );
    assert!(store.contact_remarks().contains_key(did));

    store.replace_accepted_human_contacts(&[]);
    assert!(store.active_contact_remark(did).is_none());
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

#[test]
fn cold_reload_restores_private_contact_labels_without_redelivering_the_cursor() {
    use base64::Engine as _;
    let did = arkret_sdk::Did::new(format!(
        "did:web:remark-{}.example",
        crate::operation::uuid_v7()
    ))
    .unwrap();
    let mut store = LocalStateStore::with_path(temp_state_path("retained-private-contact"));
    store.switch_test_account(did.as_str());
    let authority = store.active_authority().unwrap();
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([29u8; 32]);
    crate::mls::runtime::store_account_mls_secret(secure.as_ref(), &authority, &secret).unwrap();
    let peer = arkret_sdk::DidCoreId::new("ak:did_core:web:remark-peer.example").unwrap();
    let saved_at =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    let mut remark =
        crate::account_data::ContactRemark::new(peer.clone(), "Holder petname", saved_at);
    remark.confirmed_display_name = Some("Original confirmed name".to_owned());
    let namespace = crate::account_data::account_data_namespace_key(&authority).unwrap();
    let key = crate::account_data::contact_remark_account_data_key(&namespace, &peer).unwrap();
    let body = crate::account_data::encrypt_account_data_value(
        &authority,
        &key,
        &serde_json::to_value(&remark).unwrap(),
    )
    .unwrap();
    let scope = garth::CursorScope::Account {
        service_id: None,
        actor_id: arkret_sdk::ActorId::account(authority.clone()),
        device_id: test_device_id(),
    };
    let checkpoint = garth::AccountCursorCheckpoint {
        cursor: "ak:cursor:contact-already-consumed".to_owned(),
        station_cas: garth::StationCasProjection::default(),
    };
    for variant in [
        "matching",
        "wrong-station",
        "wrong-slot",
        "bad-envelope",
        "missing-secret",
    ] {
        let path = temp_state_path(&format!("retained-contact-{variant}"));
        let mut writer = LocalStateStore::with_path(path.clone());
        let account = test_account_context_for_authority(&did, authority.clone());
        writer.switch_active_account(&account).unwrap();
        let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let mut event: arkret_sdk::Event = serde_json::from_value(serde_json::json!({
            "event_id": "ak:event:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
            "kind": "ak.account_data.set", "realm_id": realm,
            "scope_ref": {"kind": "realm", "realm_id": realm},
            "actor_id": arkret_sdk::ActorId::account(authority.clone()),
            "created_at": "2026-10-02T00:00:00.000Z",
            "payload": {"key": key, "expected_server_revision": 0, "body": body}
        }))
        .unwrap();
        match variant {
            "wrong-station" => {
                event.actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                    authority.principal_id.clone(),
                    arkret_sdk::DidCoreId::new("ak:did_core:web:another-station.example").unwrap(),
                ))
            }
            "wrong-slot" => {
                let other =
                    arkret_sdk::DidCoreId::new("ak:did_core:web:another-peer.example").unwrap();
                event.payload.insert(
                    "key".to_owned(),
                    serde_json::json!(
                        crate::account_data::contact_remark_account_data_key(&namespace, &other)
                            .unwrap()
                    ),
                );
            }
            "bad-envelope" => {
                event
                    .payload
                    .insert("body".to_owned(), serde_json::json!({}));
            }
            "missing-secret" => {
                secure
                    .delete_secret(
                        &crate::mls::runtime::account_mls_secret_key(&authority).unwrap(),
                    )
                    .unwrap();
            }
            _ => {}
        }
        let frame: arkret_sdk::sync::AccountSubscribeFrame =
            serde_json::from_value(serde_json::json!({
                "kind": "delta", "cursor": checkpoint.cursor, "partial": false,
                "account_data": {"events": [event]}
            }))
            .unwrap();
        let accepted = writer.prepare_account_demand_frame(&frame).unwrap();
        writer.finish_account_demand_frame(&accepted).unwrap();
        writer
            .save_account_checkpoint(&scope, checkpoint.clone())
            .unwrap();
        let persisted = std::fs::read_to_string(
            writer.account_state_path(&writer.active_authority_namespace_for_test()),
        )
        .unwrap();
        assert!(!persisted.contains("Holder petname"));
        assert!(!persisted.contains("Original confirmed name"));
        let mut reopened = LocalStateStore::with_path(path);
        assert!(reopened.contact_remark(peer.as_str()).is_none());
        let restored = reopened.restore_contact_remarks_from_retained_account_data(&authority);
        assert_eq!(restored, usize::from(variant == "matching"), "{variant}");
        assert_eq!(
            reopened.load_account_checkpoint(&scope).unwrap(),
            Some(checkpoint.clone())
        );
        assert!(reopened.active_contact_remark(peer.as_str()).is_none());
        if variant == "matching" {
            assert_eq!(reopened.contact_remark(peer.as_str()), Some(remark.clone()));
            let mut newer = remark.clone();
            newer.petname = "Newer local accepted value".to_owned();
            reopened.set_contact_remark(peer.to_string(), newer.clone());
            assert_eq!(
                reopened.restore_contact_remarks_from_retained_account_data(&authority),
                0
            );
            assert_eq!(reopened.contact_remark(peer.as_str()), Some(newer));
            reopened.set_contact_remark(
                peer.to_string(),
                crate::account_data::ContactRemark::new(peer.clone(), "", chrono::Utc::now()),
            );
            assert_eq!(
                reopened.restore_contact_remarks_from_retained_account_data(&authority),
                0
            );
            assert!(
                reopened.contact_remark(peer.as_str()).is_none(),
                "a reconnect cannot resurrect an accepted local delete before its delta arrives"
            );
        }
    }
}
