//! Host adapter restoring the SDK MLS provider from a shared encrypted checkpoint.

use garth::mls::checkpoint::{EnvelopeError, MlsLocalCheckpointEnvelope, decrypt_with_epoch_check};

#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    #[error(transparent)]
    Checkpoint(#[from] EnvelopeError),
    #[error("SDK restore failed: {0}")]
    Provider(String),
}

/// Helper used by the boot path and local MLS actions. Decrypts the envelope,
/// checks the epoch floor, and reconstructs the SDK group via
/// [`arkret_sdk::ArkretMlsGroup::restore_from_state_record`].
///
/// `current_epoch_floor` is the highest epoch this client already knows the
/// scope's accepted MLS group reached; pass `0` to skip the freshness check
/// (for example on a first-boot rehydrate where no accepted epoch is known).
pub fn restore_envelope(
    envelope: &MlsLocalCheckpointEnvelope,
    snapshot_secret: &str,
    current_epoch_floor: u64,
) -> Result<arkret_sdk::ArkretMlsGroup, RestoreError> {
    let bytes = decrypt_with_epoch_check(envelope, snapshot_secret, current_epoch_floor)?;
    let record = MlsLocalCheckpointEnvelope::restore_state_record(&bytes)?;
    arkret_sdk::ArkretMlsGroup::restore_from_state_record(&record)
        .map_err(|err| RestoreError::Provider(err.to_string()))
}

#[cfg(test)]
mod tests {
    use garth::mls::checkpoint::encrypt_state;

    use super::*;
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn sdk_round_trip_persist_and_restore_real_group() {
        // End-to-end: SDK creates a group -> export_state_record -> encrypt ->
        // decrypt -> SDK restore. The restored group must report the same
        // group_id and epoch.
        use arkret_sdk::{ArkretMlsIdentity, DeviceId};

        let identity = ArkretMlsIdentity::new_test_human_device(
            crate::test_support::account_actor("did:web:alice.example"),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001".to_owned()).unwrap(),
        )
        .unwrap();
        let realm_id =
            arkret_sdk::RealmId::new("ak:realm:Afa-XWDzmMaAI5o0i4JEB845_F-vdio4zG-xF_FzJHK1")
                .unwrap();
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        let group = identity.create_group(&scope).unwrap();
        let record = group.export_state_record().unwrap();
        let original_group_id = record.group_id.clone();
        let original_epoch = record.epoch;

        let bytes = serde_json::to_vec(&record).unwrap();
        let envelope = encrypt_state(
            realm_id.as_str(),
            &original_group_id,
            original_epoch,
            &bytes,
            "mls-snapshot-passphrase",
            b"deterministic-salt-for-test",
        );

        let restored =
            restore_envelope(&envelope, "mls-snapshot-passphrase", original_epoch).unwrap();
        assert_eq!(restored.group_id(), original_group_id);
        assert_eq!(restored.epoch(), original_epoch);
    }
}
