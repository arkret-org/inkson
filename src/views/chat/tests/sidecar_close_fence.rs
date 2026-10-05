use super::*;

fn fixture() -> (
    tempfile::TempDir,
    LocalStateStore,
    arkret_sdk::AccountId,
    arkret_sdk::DeviceId,
    String,
) {
    use crate::test_support::committed_event::{
        FixtureStation, fixture_time, verified_realm_fixture_as,
    };

    let directory = tempfile::tempdir().unwrap();
    let mut store = LocalStateStore::with_path(directory.path().join("state.json"));
    store.switch_test_account("did:web:alice.example");
    let authority = store.active_authority().unwrap();
    let device =
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap();
    let realm = arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::DigestSuite::Sha256,
        [71; 32],
    ));
    let (bundle, ..) =
        verified_realm_fixture_as(realm.clone(), Vec::new(), "alice.example", device.as_str());
    let mut snapshot = arkret_sdk::RealmStateSnapshot {
        snapshot_id: arkret_sdk::RealmSnapshotId::from_digest([0; 32]),
        realm_id: realm.clone(),
        governance_generation: 0,
        visible_stream_heads: Vec::new(),
        current_state_entries: Vec::new(),
        retention_and_history_floor: arkret_sdk::RetentionAndHistoryFloor {
            history_access: arkret_sdk::HistoryAccess::SinceJoin,
            stream_floors: Vec::new(),
        },
        created_at: fixture_time(10),
        signature: bundle.genesis_commit.signature.clone(),
    };
    FixtureStation::did_web().sign_snapshot(&mut snapshot);
    let mut state = store.load();
    state.device_authoring_authority = Some(crate::state::PersistedDeviceAuthoringAuthority {
        account_id: authority.clone(),
        device_id: device.clone(),
        device_projection: arkret_models_crypto::VerifiedDeviceProjection {
            device_signing_key_did: arkret_sdk::DidKey::new(
                "did:key:z6MkhHrTbtosB4xyyJM217fS4ry35F7JhZ5oA9uVHErBJDL5",
            )
            .unwrap(),
            hpke_key: arkret_sdk::NonEmptyString::new("hpke-test").unwrap(),
            device_authorize_event_id: bundle.genesis_event.event_id,
            authorized_generation_ref: 0,
            device_status: arkret_models_crypto::DeviceStatus::Active,
            authorization_window: arkret_models_crypto::DeviceAuthorizationWindow {
                not_before: fixture_time(0),
                expires_at: None,
            },
            attested_at: fixture_time(0),
            expires_at: fixture_time(100),
        },
        authoring_generation: crate::identity::authoring_generation::AuthoringGeneration {
            authority_model:
                crate::identity::authoring_generation::AuthoringAuthorityModel::AcceptedDevice,
            authority_principal_id: authority.principal_id.clone(),
            generation_ref: "generation-0".to_owned(),
        },
    });
    // Signature admission is covered by the native Sidecar replay tests. This
    // fixture isolates the disposable author's exact-cut comparison with a
    // signed complete empty private cut, without rebuilding any MLS history.
    state
        .verified_sidecar_current
        .insert(realm.to_string(), snapshot);
    store.save(state);
    (directory, store, authority, device, realm.to_string())
}

#[tokio::test]
async fn close_cut_refuses_changed_signed_current_after_a_suspension() {
    let (_dir, mut store, authority, device, realm) = fixture();
    let captured = SidecarCloseCutFence::capture(&store, &authority, &device, &realm).unwrap();
    captured.check(&store, &authority, &device, &realm).unwrap();
    tokio::task::yield_now().await;
    let mut state = store.load();
    let snapshot = state.verified_sidecar_current.get_mut(&realm).unwrap();
    snapshot.created_at += chrono::Duration::seconds(1);
    crate::test_support::committed_event::FixtureStation::did_web().sign_snapshot(snapshot);
    store.save(state);
    assert!(captured.check(&store, &authority, &device, &realm).is_err());
    let replacement = SidecarCloseCutFence::capture(&store, &authority, &device, &realm).unwrap();
    replacement
        .check(&store, &authority, &device, &realm)
        .unwrap();
}

#[tokio::test]
async fn close_cut_refuses_switched_account_and_replaced_device_after_a_suspension() {
    let (_dir, mut store, authority, device, realm) = fixture();
    let captured = SidecarCloseCutFence::capture(&store, &authority, &device, &realm).unwrap();
    tokio::task::yield_now().await;
    let mut state = store.load();
    state.device_authoring_authority.as_mut().unwrap().device_id =
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000002").unwrap();
    store.save(state);
    assert!(captured.check(&store, &authority, &device, &realm).is_err());
    store.switch_test_account("did:web:bob.example");
    assert!(captured.check(&store, &authority, &device, &realm).is_err());
}

#[test]
fn close_cut_requires_complete_history_and_current_authoring_generation() {
    let (_dir, mut store, authority, device, realm) = fixture();
    let captured = SidecarCloseCutFence::capture(&store, &authority, &device, &realm).unwrap();
    let mut state = store.load();
    state
        .device_authoring_authority
        .as_mut()
        .unwrap()
        .authoring_generation
        .generation_ref = "generation-1".to_owned();
    store.save(state);
    assert!(captured.check(&store, &authority, &device, &realm).is_err());
    let mut state = store.load();
    state
        .verified_sidecar_current
        .get_mut(&realm)
        .unwrap()
        .visible_stream_heads
        .push(arkret_sdk::CommitStreamHead {
            stream_ref: arkret_sdk::CommitStreamRef::Sidecar {
                realm_id: arkret_sdk::RealmId::new(realm.clone()).unwrap(),
                sidecar_id: arkret_sdk::SidecarId::from_event_id(
                    &arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [74; 32]),
                ),
            },
            commit_id: arkret_sdk::RealmCommitId::from_digest([75; 32]),
            stream_position: 0,
        });
    store.save(state);
    assert!(SidecarCloseCutFence::capture(&store, &authority, &device, &realm).is_none());
}

#[test]
fn close_authoring_refuses_a_replaced_signer_even_on_the_same_cut() {
    let (_dir, store, authority, device, realm) = fixture();
    let _scope_guard =
        crate::secure_key_store::DeviceSeedScopeTestGuard::replace(Some((&authority, &device)));
    let signer = std::sync::Arc::new(crate::event_signer::build_ed25519_signer(
        [81; 32],
        "did:web:alice.example",
    ));
    let _signer_guard = crate::event_signer::ActiveSignerTestGuard::replace(Some(signer));
    let session = crate::transport::auth::AuthoringSessionFence::capture().unwrap();
    let captured = SidecarCloseCutFence::capture(&store, &authority, &device, &realm).unwrap();
    let replacement = std::sync::Arc::new(crate::event_signer::build_ed25519_signer(
        [82; 32],
        "did:web:alice.example",
    ));
    // Installation is intentionally first-write-only. An actual rotation
    // uses replacement, which must invalidate the captured signer instance.
    let previous = crate::event_signer::replace_active_signer(Some(replacement.clone())).unwrap();
    assert!(std::sync::Arc::ptr_eq(&previous, &session.signer));
    assert!(std::sync::Arc::ptr_eq(
        &crate::event_signer::active_signer().unwrap(),
        &replacement,
    ));
    assert!(
        check_sidecar_close_authoring(&captured, &session, &store, &authority, &device, &realm)
            .is_err()
    );
}
