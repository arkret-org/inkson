//! Local cryptographic fixtures. These helpers never prove native admission,
//! a successful backup PUT, original read access or a recoverable server cut.

use arkret_models_crypto::{
    ContentContext, ContentEncryptionAlgorithm, ContentProtection, ContentPurpose,
    ContentRootContext, EventContentMaterial,
};

pub(crate) fn public_refs(info: &[u8], tree: &[u8]) -> (arkret_sdk::BlobRef, arkret_sdk::BlobRef) {
    let reference = |bytes: &[u8]| {
        arkret_sdk::BlobRef::new(format!(
            "ak:blob:{}",
            arkret_sdk::canonical::sha256_digest(bytes)
        ))
        .unwrap()
    };
    (reference(info), reference(tree))
}

pub(crate) fn scope(
    realm: &str,
    circle: Option<&str>,
    sidecar: Option<&arkret_sdk::SidecarId>,
) -> arkret_sdk::ScopeRef {
    let realm_id = arkret_sdk::RealmId::new(realm).unwrap();
    match (circle, sidecar) {
        (_, Some(id)) => arkret_sdk::ScopeRef::Sidecar {
            realm_id,
            sidecar_id: id.clone(),
        },
        (Some(id), _) => arkret_sdk::ScopeRef::Circle {
            realm_id,
            circle_id: arkret_sdk::CircleId::new(id).unwrap(),
        },
        _ => arkret_sdk::ScopeRef::Realm { realm_id },
    }
}

pub(crate) fn material(
    group: &arkret_sdk::ArkretMlsGroup,
    kind: &str,
    reference: &arkret_sdk::EventId,
) -> EventContentMaterial {
    let producer = group
        .local_content_endpoint()
        .expect("fixture must install its original endpoint authority");
    let root_context = ContentRootContext {
        effective_scope: group.scope().clone(),
        genesis_event_ref: reference.clone(),
        epoch: group.epoch(),
        group_state_ref: reference.clone(),
        cipher_suite: group.group_ciphersuite_canonical_id().unwrap().to_owned(),
        encryption_backup_strategy: arkret_sdk::EncryptionBackupStrategy::EpochContentRoots,
        backup_strategy_ref: arkret_sdk::EventId::from_digest(
            group.scope().realm_id().digest_suite_code().digest_suite(),
            group.scope().realm_id().digest_bytes(),
        ),
    };
    let root = group.export_content_root(&root_context).unwrap();
    let root_ref = arkret_crypto::content_history::content_root_ref(&root, &root_context).unwrap();
    let content_context = ContentContext {
        root_context,
        root_ref: root_ref.clone(),
        purpose: ContentPurpose::EventBody,
        encryption_scheme: arkret_sdk::EncryptedPayloadScheme::EpochContentAead,
        encryption_algorithm: ContentEncryptionAlgorithm::Aes128Gcm,
        producer,
        content_key_salt: arkret_crypto::content_history::fresh_content_key_salt().unwrap(),
    };
    let intent: arkret_sdk::EventIntent = serde_json::from_value(serde_json::json!({
        "kind":kind,"scope_ref":group.scope(),"actor_id":group.local_actor_id(),
        "created_at":"2026-09-22T00:00:00.000Z","payload":{},
    }))
    .unwrap();
    let key = arkret_crypto::content_history::derive_content_key(&root, &content_context).unwrap();
    EventContentMaterial {
        key_commitment: arkret_crypto::content_history::content_key_commitment(
            &content_context,
            &key,
        )
        .unwrap(),
        content_context,
        outer_event: intent.pre_encryption_outer_event().unwrap(),
        protection: ContentProtection {
            root_refs: vec![root_ref],
            blob_refs: vec![],
            backup_refs: vec![garth::mls::backup_series::fresh_backup_id().unwrap()],
        },
    }
}

pub(crate) fn checkpoint_material(
    state: &crate::state::LocalStateStore,
    secure: &dyn crate::secure_key_store::SecureKeyStore,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    scope: &arkret_sdk::ScopeRef,
    kind: &str,
    reference: &arkret_sdk::EventId,
) -> EventContentMaterial {
    let restored = state.mls_checkpoint_for_scope(scope).and_then(|snapshot| {
        let secret =
            crate::mls::runtime::load_device_checkpoint_secret(secure, account, device).ok()?;
        crate::mls::persistence::restore_envelope(&snapshot, &secret, 0).ok()
    });
    if let Some(group) = restored {
        return material(&group, kind, reference);
    }
    // Negative readiness tests supply complete formal staging material, then
    // assert production rejects the absent/invalid checkpoint before sealing.
    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json")
            .unwrap();
    serde_json::from_value(serde_json::json!({
        "content_context":fixture["kat"]["content_context"],"outer_event":fixture["kat"]["outer_event"],
        "protection":fixture["kat"]["envelope"]["encryption_context"]["protection"],
        "key_commitment":fixture["kat"]["envelope"]["encryption_context"]["key_commitment"],
    })).unwrap()
}
