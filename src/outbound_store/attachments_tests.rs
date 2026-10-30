use super::*;

const INPUT: &[u8] = b"durable attachment original bytes";

fn object(suite: arkret_sdk::DigestSuite) -> AttachmentObject {
    let salt = arkret_crypto::blob_aead::fresh_content_key_salt().unwrap();
    AttachmentObject {
        id: salt.as_str().into(),
        salt,
        authority: crate::test_support::authority("ak:did_core:web:alice.example"),
        device_id: arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001")
            .unwrap(),
        scope: arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
                arkret_sdk::DigestSuite::Sha256,
                [1; 32],
            )),
        },
        strand_id: arkret_sdk::StrandId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [2; 32],
        )),
        filename: "private.txt".into(),
        long_text: false,
        input_size: INPUT.len() as u64,
        input_digest: None,
        text_prefix: None,
        line_count: None,
        media_type: "text/plain".into(),
        digest_suite: suite,
        context: None,
        checkpoint: None,
        state_tree_ref: None,
        nonce_prefix: None,
        prepared: None,
        uploaded: false,
        submitted_operation: None,
    }
}

async fn stage(
    vault: &InksonOutboundStore,
    chunks: &crate::state::current_index::AttachmentChunkStore,
    original: &AttachmentObject,
) -> AttachmentObject {
    vault.freeze_attachment(original.clone()).await.unwrap();
    let digest = crate::attachments::input_bytes_to_parts(chunks, INPUT, original.digest_suite)
        .await
        .unwrap();
    vault
        .freeze_attachment_input(&original.id, digest)
        .await
        .unwrap()
}

#[tokio::test]
async fn native_attachment_input_and_descriptor_are_protected_and_endpoint_bound() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("outbound.json");
    let object = object(arkret_sdk::DigestSuite::Sha256);
    let secrets = std::sync::Arc::new(crate::secure_key_store::MemorySecureKeyStore::new());
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(Some((
        &object.authority,
        &object.device_id,
    )));
    crate::secure_key_store::store_signing_seed(secrets.as_ref(), &[91; 32]).unwrap();
    let vault = || InksonOutboundStore {
        creator_decision: Default::default(),
        path: path.clone(),
        protection: Some((object.authority.clone(), secrets.clone())),
    };
    let chunks =
        crate::state::current_index::AttachmentChunkStore::for_test(dir.path().join("parts.db"))
            .await
            .unwrap();
    let staged = stage(&vault(), &chunks, &object).await;
    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(!raw.contains(&object.filename));
    assert!(!raw.contains(std::str::from_utf8(INPUT).unwrap()));
    let restored = vault()
        .attachment_object(&object.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restored, staged);
    let prepared = restored.prepare(&chunks).await.unwrap();
    vault()
        .freeze_prepared_attachment(&object.id, prepared.clone())
        .await
        .unwrap();
    assert_eq!(
        vault()
            .attachment_object(&object.id)
            .await
            .unwrap()
            .unwrap()
            .prepared
            .as_ref(),
        Some(&prepared)
    );
    let mut tampered: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    tampered["attachments"][0]["object_id"] = serde_json::json!("different-object");
    std::fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
    assert!(vault().attachment_object(&object.id).await.is_err());
}

#[tokio::test]
async fn restart_and_unknown_upload_reuse_the_exact_frozen_object() {
    for suite in [
        arkret_sdk::DigestSuite::Sha256,
        arkret_sdk::DigestSuite::Blake3,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outbound.json");
        let store = InksonOutboundStore::for_test_path(path.clone());
        let chunks = crate::state::current_index::AttachmentChunkStore::for_test(
            dir.path().join("parts.db"),
        )
        .await
        .unwrap();
        let original = object(suite);
        let staged = stage(&store, &chunks, &original).await;
        drop(store);
        let store = InksonOutboundStore::for_test_path(path.clone());
        let restored = store
            .attachment_object(&original.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored, staged);
        let prepared = restored.prepare(&chunks).await.unwrap();
        store
            .freeze_prepared_attachment(&original.id, prepared.clone())
            .await
            .unwrap();
        let exact_bytes = chunks.read_part("ciphertext", 0).await.unwrap().to_vec();
        chunks.clear("input").await.unwrap();
        drop(store);
        let restarted = InksonOutboundStore::for_test_path(path);
        let exact = restarted
            .attachment_object(&original.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(exact.prepared.as_ref(), Some(&prepared));
        assert_eq!(exact.prepare(&chunks).await.unwrap(), prepared);
        assert_eq!(
            &*chunks.read_part("ciphertext", 0).await.unwrap(),
            &exact_bytes
        );
        assert!(!exact.uploaded);
        restarted
            .mark_attachment_uploaded(&original.id)
            .await
            .unwrap();
        assert!(
            restarted
                .attachment_object(&original.id)
                .await
                .unwrap()
                .unwrap()
                .uploaded
        );
        let mut changed = staged;
        changed.filename = "different.txt".into();
        assert!(restarted.freeze_attachment(changed).await.is_err());
    }
}

#[tokio::test]
async fn corrupted_preparation_never_replaces_the_durable_intent() {
    let dir = tempfile::tempdir().unwrap();
    let store = InksonOutboundStore::for_test_path(dir.path().join("outbound.json"));
    let chunks =
        crate::state::current_index::AttachmentChunkStore::for_test(dir.path().join("parts.db"))
            .await
            .unwrap();
    let original = object(arkret_sdk::DigestSuite::Sha256);
    let staged = stage(&store, &chunks, &original).await;
    let mut tampered = staged.prepare(&chunks).await.unwrap();
    tampered.ciphertext_size += 1;
    assert!(
        store
            .freeze_prepared_attachment(&original.id, tampered)
            .await
            .is_err()
    );
    assert_eq!(
        store
            .attachment_object(&original.id)
            .await
            .unwrap()
            .unwrap(),
        staged
    );
    assert!(
        chunks
            .write_part("input", 0, b"different source")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn large_attachment_parts_are_read_on_demand_and_never_enter_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("outbound.json");
    let store = InksonOutboundStore::for_test_path(vault_path.clone());
    let chunks =
        crate::state::current_index::AttachmentChunkStore::for_test(dir.path().join("parts.db"))
            .await
            .unwrap();
    let mut object = object(arkret_sdk::DigestSuite::Sha256);
    let length = 20 * crate::attachments::SEGMENT_BYTES as usize + 17;
    object.input_size = length as u64;
    store.freeze_attachment(object.clone()).await.unwrap();
    let count = arkret_models_crypto::stream_segment_count(
        length as u64,
        crate::attachments::SEGMENT_BYTES,
    )
    .unwrap();
    let mut hasher = arkret_sdk::canonical::ContentHasher::new(object.digest_suite);
    for index in 0..count {
        let len = length
            .saturating_sub(index as usize * crate::attachments::SEGMENT_BYTES as usize)
            .min(crate::attachments::SEGMENT_BYTES as usize);
        let part = vec![index as u8; len];
        hasher.update(&part);
        chunks.write_part("input", index, &part).await.unwrap();
    }
    let object = store
        .freeze_attachment_input(&object.id, arkret_sdk::Hash::new(hasher.finish()).unwrap())
        .await
        .unwrap();
    let prepared = object.prepare(&chunks).await.unwrap();
    store
        .freeze_prepared_attachment(&object.id, prepared.clone())
        .await
        .unwrap();
    assert!(std::fs::metadata(&vault_path).unwrap().len() < 16_384);
    assert_eq!(prepared.part_count, count);
    for index in 0..count {
        assert!(
            chunks.read_part("ciphertext", index).await.unwrap().len()
                <= crate::attachments::SEGMENT_BYTES as usize
        );
    }
}
