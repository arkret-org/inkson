use super::*;

#[tokio::test]
async fn target_fence_rejects_a_success_that_completed_after_target_change() {
    let active = std::cell::Cell::new(true);
    let result = with_target_fence(
        async {
            active.set(false);
            Ok("late successful upload")
        },
        || active.get(),
    )
    .await;
    assert!(result.is_err());
}

fn event(seed: u8) -> EventId {
    EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [seed; 32])
}

fn scopes() -> Vec<ScopeRef> {
    let realm_id = arkret_sdk::RealmId::from_event_id(&event(1));
    vec![
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        ScopeRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: arkret_sdk::CircleId::from_event_id(&event(2)),
        },
        ScopeRef::Sidecar {
            realm_id,
            sidecar_id: arkret_sdk::SidecarId::from_event_id(&event(3)),
        },
    ]
}

fn parameters(
    reference: EventId,
    suite: arkret_sdk::DigestSuite,
) -> arkret_crypto::blob_aead::StreamEncryptParams {
    arkret_crypto::blob_aead::StreamEncryptParams {
        key_ref: EncryptedAttachmentKeyRef {
            algorithm: EncryptedAttachmentKeyAlgorithm::Mls,
            group_state_ref: EncryptedAttachmentGroupStateRef::Event(reference),
        },
        content_key_salt: AttachmentContentKeySalt::from_bytes([7; 32]),
        digest_suite: suite,
        media_type: "text/plain".into(),
        segment_bytes: SEGMENT_BYTES,
    }
}

/// The signed/current authorization is an explicit input premise here. This
/// regression exercises local context resolution, not a Station authorization.
#[tokio::test]
async fn authorized_durable_cut_resolves_history_and_alias_without_a_product_view() {
    for scope in scopes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let mut state = crate::state::LocalStateStore::with_path(&path);
        assert!(state.switch_test_account("did:web:alice.example"));
        let authority = state.active_authority().unwrap();
        let group_id = scope.canonical_mls_group_id().unwrap();
        for epoch in 0..2 {
            let snapshot = crate::mls::persistence::encrypt_state(
                scope.realm_id().as_str(),
                group_id.as_str(),
                epoch,
                b"opaque installed checkpoint",
                "secret",
                &[8; 16],
            );
            state
                .install_accepted_mls_transition(&scope, snapshot, &event(20 + epoch as u8))
                .unwrap()
                .wait()
                .await
                .unwrap();
        }
        drop(state);
        let state = crate::state::LocalStateStore::with_path(&path);
        assert!(state.current_mls_group_for_scope(&scope).is_none());
        let current = arkret_wire::MlsGroupCurrent {
            effective_scope: scope.clone(),
            genesis_event_ref: event(20),
            cipher_suite: arkret_sdk::NonEmptyString::new(
                "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            )
            .unwrap(),
            current_mls_commit_event_ref: event(21),
            epoch: 1,
            current_key_access_revision: 0,
            covered_key_access_revision: 0,
            public_tree_ref: arkret_sdk::BlobRef::new(format!(
                "ak:blob:sha256:{}",
                "33".repeat(32)
            ))
            .unwrap(),
        };
        let (_, descriptor) = arkret_crypto::blob_aead::encrypt_stream(
            b"history",
            &[9; 32],
            &parameters(event(20), arkret_sdk::DigestSuite::Sha256),
            &|_: &EncryptedAttachmentGroupStateRef| Some(0),
        )
        .unwrap();
        let (context, checkpoint, reference) =
            attachment_receive_context(&state, &authority, &scope, &current, &descriptor).unwrap();
        assert_eq!(context.epoch, 0);
        assert_eq!(checkpoint.epoch, 0);
        assert_eq!(context.genesis_event_ref, event(20));
        assert_eq!(reference, event(20));
        let EncryptedAttachment::Stream(mut alias) = descriptor.clone() else {
            unreachable!()
        };
        alias.key_ref.group_state_ref = EncryptedAttachmentGroupStateRef::Digest(
            arkret_sdk::Hash::new(format!("sha256:{}", hex::encode([20; 32]))).unwrap(),
        );
        assert_eq!(
            attachment_receive_context(
                &state,
                &authority,
                &scope,
                &current,
                &EncryptedAttachment::Stream(alias.clone())
            )
            .unwrap()
            .0,
            context
        );
        assert!(matches!(
            alias.key_ref.group_state_ref,
            EncryptedAttachmentGroupStateRef::Digest(_)
        ));
        alias.key_ref.group_state_ref = EncryptedAttachmentGroupStateRef::Event(event(90));
        assert!(
            attachment_receive_context(
                &state,
                &authority,
                &scope,
                &current,
                &EncryptedAttachment::Stream(alias)
            )
            .is_err()
        );
        let foreign = crate::test_support::authority("ak:did_core:web:bob.example");
        assert!(
            attachment_receive_context(&state, &foreign, &scope, &current, &descriptor).is_err()
        );
        let wrong_scope = ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::from_event_id(&event(99)),
        };
        assert!(
            attachment_receive_context(&state, &authority, &wrong_scope, &current, &descriptor)
                .is_err()
        );
        let mut no_checkpoint =
            crate::state::LocalStateStore::with_path(directory.path().join("empty.json"));
        assert!(no_checkpoint.switch_test_account("did:web:alice.example"));
        assert!(
            attachment_receive_context(&no_checkpoint, &authority, &scope, &current, &descriptor)
                .is_err()
        );
    }
}

#[test]
fn real_checkpoint_restore_and_registered_kdf_bind_scope_epoch_account_and_device() {
    let authority = crate::test_support::authority("ak:did_core:web:alice.example");
    let device = DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap();
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    crate::mls::runtime::store_account_mls_secret(&secure, &authority, "checkpoint-secret")
        .unwrap();
    for scope in scopes() {
        let identity = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
            arkret_sdk::ActorId::account(authority.clone()),
            device.clone(),
        )
        .unwrap();
        let group = identity.create_group(&scope).unwrap();
        let record = group.export_state_record().unwrap();
        let snapshot = crate::mls::persistence::encrypt_state(
            scope.realm_id().as_str(),
            &record.group_id,
            record.epoch,
            &serde_json::to_vec(&record).unwrap(),
            "checkpoint-secret",
            &[11; 16],
        );
        let context = AttachmentContentKeyContext {
            effective_scope: scope.clone(),
            genesis_event_ref: event(20),
            epoch: group.epoch(),
            scheme: "ak.blob.stream_aead.v1".into(),
            encryption_algorithm: arkret_crypto::blob_aead::ALG_STREAM_XCHACHA.into(),
            content_key_salt: AttachmentContentKeySalt::from_bytes([7; 32]),
        };
        let restored =
            restore_attachment_group_from_store(&snapshot, &authority, &device, &context, &secure)
                .unwrap();
        let key = arkret_sdk::mls::derive_attachment_content_key(&restored, &context).unwrap();
        assert_eq!(
            key,
            arkret_sdk::mls::derive_attachment_content_key(&group, &context).unwrap()
        );
        for suite in [
            arkret_sdk::DigestSuite::Sha256,
            arkret_sdk::DigestSuite::Blake3,
        ] {
            let resolve = |r: &EncryptedAttachmentGroupStateRef| {
                (r.event_id().ok() == Some(event(20))).then_some(0)
            };
            let (ciphertext, descriptor) = arkret_crypto::blob_aead::encrypt_stream(
                b"real scoped MLS attachment",
                &key,
                &parameters(event(20), suite),
                &resolve,
            )
            .unwrap();
            assert_eq!(
                arkret_crypto::blob_aead::decrypt_stream(&ciphertext, &descriptor, &key, &resolve)
                    .unwrap(),
                b"real scoped MLS attachment"
            );
            let mut alias_parameters = parameters(event(20), suite);
            alias_parameters.key_ref.group_state_ref = EncryptedAttachmentGroupStateRef::Digest(
                arkret_sdk::Hash::new(format!("sha256:{}", hex::encode([20; 32]))).unwrap(),
            );
            let (alias_bytes, alias_descriptor) = arkret_crypto::blob_aead::encrypt_stream(
                b"real scoped MLS attachment",
                &key,
                &alias_parameters,
                &resolve,
            )
            .unwrap();
            assert_eq!(
                alias_descriptor.content_key_context(scope.clone(), event(20), 0),
                context
            );
            assert_eq!(
                arkret_crypto::blob_aead::decrypt_stream(
                    &alias_bytes,
                    &alias_descriptor,
                    &key,
                    &resolve
                )
                .unwrap(),
                b"real scoped MLS attachment"
            );
            let mut changed = descriptor.clone();
            stream_mut(&mut changed).key_ref = alias_parameters.key_ref;
            assert!(
                arkret_crypto::blob_aead::decrypt_stream(&ciphertext, &changed, &key, &resolve)
                    .is_err()
            );
            let mut wrong_genesis = context.clone();
            wrong_genesis.genesis_event_ref = event(99);
            let wrong_key =
                arkret_sdk::mls::derive_attachment_content_key(&restored, &wrong_genesis).unwrap();
            assert_ne!(wrong_key, key);
            assert!(
                arkret_crypto::blob_aead::decrypt_stream(
                    &ciphertext,
                    &descriptor,
                    &wrong_key,
                    &resolve
                )
                .is_err()
            );
            let mut changed = descriptor.clone();
            stream_mut(&mut changed).content_key_salt =
                AttachmentContentKeySalt::from_bytes([8; 32]);
            assert!(
                arkret_crypto::blob_aead::decrypt_stream(&ciphertext, &changed, &key, &resolve)
                    .is_err()
            );
            changed = descriptor.clone();
            stream_mut(&mut changed).media_type = "text/markdown".into();
            assert!(
                arkret_crypto::blob_aead::decrypt_stream(&ciphertext, &changed, &key, &resolve)
                    .is_err()
            );
            changed = descriptor.clone();
            stream_mut(&mut changed).size_bytes += 1;
            assert!(
                arkret_crypto::blob_aead::decrypt_stream(&ciphertext, &changed, &key, &resolve)
                    .is_err()
            );
            changed = descriptor.clone();
            stream_mut(&mut changed).blob_ref =
                arkret_sdk::BlobRef::new(format!("ak:blob:{}:{}", suite.as_str(), "44".repeat(32)))
                    .unwrap();
            assert!(
                arkret_crypto::blob_aead::decrypt_stream(&ciphertext, &changed, &key, &resolve)
                    .is_err()
            );
            let mut corrupt = ciphertext.clone();
            corrupt[0] ^= 1;
            assert!(
                arkret_crypto::blob_aead::decrypt_stream(&corrupt, &descriptor, &key, &resolve)
                    .is_err()
            );
        }
        let missing = crate::secure_key_store::MemorySecureKeyStore::new();
        assert!(
            restore_attachment_group_from_store(&snapshot, &authority, &device, &context, &missing)
                .is_err()
        );
        let foreign = crate::test_support::authority("ak:did_core:web:bob.example");
        crate::mls::runtime::store_account_mls_secret(&secure, &foreign, "checkpoint-secret")
            .unwrap();
        assert!(
            restore_attachment_group_from_store(&snapshot, &foreign, &device, &context, &secure)
                .is_err()
        );
        let other_device = DeviceId::new("ak:device:01964137-0000-7000-8000-000000000002").unwrap();
        assert!(
            restore_attachment_group_from_store(
                &snapshot,
                &authority,
                &other_device,
                &context,
                &secure
            )
            .is_err()
        );
        let mut wrong = context.clone();
        wrong.epoch += 1;
        assert!(
            restore_attachment_group_from_store(&snapshot, &authority, &device, &wrong, &secure)
                .is_err()
        );
        wrong = context.clone();
        wrong.effective_scope = ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::from_event_id(&event(99)),
        };
        assert!(
            restore_attachment_group_from_store(&snapshot, &authority, &device, &wrong, &secure)
                .is_err()
        );
    }
}

fn stream_mut(
    descriptor: &mut EncryptedAttachment,
) -> &mut arkret_models_crypto::StreamEncryptedAttachment {
    let EncryptedAttachment::Stream(stream) = descriptor else {
        unreachable!()
    };
    stream
}
