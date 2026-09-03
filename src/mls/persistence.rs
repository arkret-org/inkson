//! Device-local MLS group-state persistence — host half.
//!
//! The envelope itself (layout, HKDF/AEAD, AAD binding, epoch freshness check)
//! is host-neutral and lives in [`garth::mls::snapshot_envelope`]; every client
//! that persists MLS state needs exactly that envelope, so it is not inkson's
//! to own. What stays here is the one step that needs the SDK MLS engine:
//! turning a decrypted state record back into a live `ArkretMlsGroup`.
//!
//! The happy path is `encrypt_state` -> write through `LocalStateStore` -> read
//! back -> [`restore_envelope`]. That is the same path the device rehydrate
//! strand drives.

pub use garth::mls::snapshot_envelope::{
    AEAD_VERSION_CHACHA20_POLY1305, EnvelopeError, MLS_ENVELOPE_MAGIC, MlsSnapshotEnvelope,
    decrypt_envelope, decrypt_with_epoch_check, encrypt_state,
};

/// Helper used by the boot path and local MLS actions. Decrypts the envelope,
/// sanity-checks the epoch, and reconstructs the SDK group via
/// [`arkret_sdk::ArkretMlsGroup::restore_from_state_record`].
///
/// `current_epoch_floor` is taken from the latest Seal view; pass
/// `0` to skip the freshness check (e.g. first-boot rehydrate where
/// no Seal view is known yet).
pub fn restore_envelope(
    envelope: &MlsSnapshotEnvelope,
    snapshot_secret: &str,
    current_epoch_floor: u64,
) -> Result<arkret_sdk::ArkretMlsGroup, EnvelopeError> {
    let bytes = decrypt_with_epoch_check(envelope, snapshot_secret, current_epoch_floor)?;
    let record = MlsSnapshotEnvelope::restore_state_record(&bytes)?;
    arkret_sdk::ArkretMlsGroup::restore_from_state_record(&record)
        .map_err(|err| EnvelopeError::SdkRestore(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn sdk_round_trip_persist_and_restore_real_group() {
        // End-to-end: SDK creates a group → export_state_record →
        // encrypt → decrypt → SDK restore. The restored group must
        // report the same group_id + epoch. The envelope layer's own
        // failure modes are covered in `garth::mls::snapshot_envelope`.
        use arkret_sdk::{ArkretMlsIdentity, DeviceId};

        let identity = ArkretMlsIdentity::new_test_human_device(
            crate::mls_api_helpers::principal_core_id("did:web:alice.example").unwrap(),
            // SDK 0.7 requires the canonical `ak:device:<uuid7>` form.
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001".to_owned()).unwrap(),
        )
        .unwrap();
        let group = identity
            .create_group(b"ak:realm:Afa-XWDzmMaAI5o0i4JEB845_F-vdio4zG-xF_FzJHK1")
            .unwrap();
        let record = group.export_state_record().unwrap();
        let original_group_id = record.group_id.clone();
        let original_epoch = record.epoch;

        let bytes = serde_json::to_vec(&record).unwrap();
        let envelope = encrypt_state(
            "ak:realm:Afa-XWDzmMaAI5o0i4JEB845_F-vdio4zG-xF_FzJHK1",
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
