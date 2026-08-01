//! §2.9 E2EE reaction sealing and routing-tag derivation.

use super::{
    MlsRuntimeError, PreparedMlsCommit, assert_minimal_metadata_aad, load_device_snapshot_secret,
    should_force_epoch_advance,
};
use crate::secure_key_store::SecureKeyStore;

/// MLS exporter label for the v1 reaction routing tag
/// (`encryption-and-audit.md` §2.9). Bound, together with `context =
/// realm_id` and the current group epoch's exporter secret, into the
/// keyed-HMAC routing tag.
pub const REACTION_ROUTING_LABEL_V1: &str = "arkret-reaction-routing-v1";
/// Length (bytes) of the MLS exporter output used as the HMAC key.
pub const REACTION_ROUTING_EXPORT_LEN: usize = 32;
/// Content type for the encrypted real-emoji payload of a reaction.
pub const REACTION_ENCRYPTED_CONTENT_TYPE: &str = "application/vnd.arkret.reaction+json";

/// Result of sealing an E2EE reaction: the plaintext routing tag for the
/// wire `reaction_payload.key`, plus the structured encrypted payload that
/// carries the real emoji.
pub struct EncryptedReaction {
    /// `sha256:<hex>` keyed-HMAC routing tag for `reaction_payload.key`.
    pub routing_tag: String,
    /// MLS application-message payload carrying the real emoji JSON.
    pub encrypted_payload: arkret_sdk::EncryptedPayload,
    /// SEC-08 (`encryption-and-audit.md` §2.9) — present ONLY when this
    /// reaction force-advanced the MLS epoch because the
    /// `minimal_metadata_realm` 1h cap was exceeded. The caller MUST submit
    /// this `ak.mls.commit` and, on server-accept, persist
    /// [`Self::forced_commit_snapshot`] (X14 persist-on-accept). When `None`
    /// the reaction rode the current epoch and its snapshot was already
    /// persisted internally (epoch unchanged ⇒ no epoch-skew risk).
    pub forced_commit: Option<PreparedMlsCommit>,
    /// Post-forced-commit snapshot the caller persists on server-accept. Set
    /// iff [`Self::forced_commit`] is `Some`.
    pub forced_commit_snapshot: Option<crate::mls::persistence::MlsSnapshotEnvelope>,
}

/// Pure derivation of the §2.9 v1 routing tag from an MLS exporter secret.
///
/// `tag = "sha256:" || hex(HMAC-SHA256(exporter_secret, NFC(canonical_emoji)))`.
/// Split out from [`reaction_routing_tag_v1`] so it can be unit-tested with a
/// fixed exporter secret (the MLS half is exercised separately).
#[allow(clippy::expect_used)]
pub fn reaction_routing_tag_from_exporter(exporter_secret: &[u8], canonical_emoji: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use unicode_normalization::UnicodeNormalization;

    let nfc: String = canonical_emoji.nfc().collect();
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(exporter_secret)
        .expect("HMAC-SHA256 accepts a key of any length");
    mac.update(nfc.as_bytes());
    let tag = mac.finalize().into_bytes();
    format!("sha256:{}", crate::canonical::hex_encode(&tag))
}

/// Restore this device's MLS group for `realm_id` and derive the §2.9 v1
/// reaction routing tag for `canonical_emoji` at the current epoch.
///
/// Read-only on the MLS group — it only reads the epoch's exporter secret,
/// so it neither commits, advances the ratchet, nor mutates persisted
/// snapshot state. Returns the `sha256:<hex>` wire form for
/// `reaction_payload.key`.
pub fn reaction_routing_tag_v1(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    canonical_emoji: &str,
) -> Result<String, MlsRuntimeError> {
    let snapshot = state_store
        .mls_snapshot_for(realm_id)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    let secret = load_device_snapshot_secret(secure_store, actor_id, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // COR-04: read-only exporter read for the routing tag — floor 0 is intentional
    // (no commit, no ratchet advance, no snapshot mutation).
    let group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0)
        .map_err(|err| MlsRuntimeError::SnapshotRestore(err.to_string()))?;
    let exporter = group
        .export_secret(
            REACTION_ROUTING_LABEL_V1,
            realm_id.as_bytes(),
            REACTION_ROUTING_EXPORT_LEN,
        )
        .map_err(|err| MlsRuntimeError::Export(err.to_string()))?;
    Ok(reaction_routing_tag_from_exporter(
        &exporter,
        canonical_emoji,
    ))
}

/// Seal an E2EE reaction: derive the v1 routing tag and encrypt the real
/// emoji as an MLS application message, both under the current epoch.
///
/// Unlike message send, this does NOT advance the MLS epoch (no commit) —
/// `encryption-and-audit.md` §2.9 reuses the application-key strand, so
/// reactions ride the current epoch and the server deduplicates on the
/// routing tag. The post-encrypt snapshot IS persisted immediately so the
/// sender's application ratchet never reuses a generation; because the epoch
/// is unchanged there is no epoch-skew risk that would require
/// persist-on-accept.
pub fn encrypt_reaction_with_device_snapshot(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    canonical_emoji: &str,
) -> Result<EncryptedReaction, MlsRuntimeError> {
    let snapshot = state_store
        .mls_snapshot_for(realm_id)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    let secret = load_device_snapshot_secret(secure_store, actor_id, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // COR-04: reaction send may force an epoch commit; bind it to the Seal-view
    // epoch floor so a stale local snapshot can't seal a reaction on a forked ratchet.
    let epoch_floor = super::seal_view_epoch_floor(state_store, realm_id);
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::SnapshotRestore(err.to_string()))?;

    // SEC-08 (§2.9) — fail-closed AAD policy: this path always builds a
    // `hidden` AAD below, but for a `minimal_metadata_realm` Realm the hidden
    // requirement is a MUST. Assert it up front (with the same SDK helper
    // soland rejects with) so any future edit that widens visibility on a
    // minimal Realm fails loudly here instead of leaking message-id metadata.
    let is_minimal_metadata = state_store.realm_projection_is_minimal_metadata(realm_id);
    assert_minimal_metadata_aad(
        &arkret_sdk::EncryptedEnvelopeAadVisibility::Hidden,
        is_minimal_metadata,
    )?;

    // SEC-08 (§2.9) — minimal-metadata epoch lifetime ≤ 1h. A reaction normally
    // reuses the current epoch (no commit), so on a minimal Realm we MUST roll
    // the epoch once it has outlived the cap, bounding within-epoch reaction
    // frequency to a ≤1h window. The forced `ak.mls.commit` is surfaced to the
    // caller (X14 persist-on-accept) rather than persisted optimistically.
    // COR-08: use the injectable clock (same source as `snapshot.epoch_started_at`)
    // so the §2.9 1h epoch-lifetime comparison is not split across two clock sources.
    let now = crate::clock::now_utc();
    let forced_commit = if should_force_epoch_advance(
        is_minimal_metadata,
        snapshot.epoch_started_at,
        now,
        snapshot.app_messages_observed,
        state_store.realm_has_pending_mls_binding(realm_id),
    ) {
        let previous_governance_binding = group
            .current_governance_binding()
            .map_err(|error| MlsRuntimeError::Commit(error.to_string()))?
            .ok_or_else(|| {
                MlsRuntimeError::Commit(
                    "MLS commit requires the current governance binding predecessor".to_owned(),
                )
            })?;
        Some(PreparedMlsCommit {
            envelope: group
                .self_update_commit()
                .map_err(|err| MlsRuntimeError::Commit(err.to_string()))?,
            previous_governance_binding,
        })
    } else {
        None
    };

    // Routing tag is derived from the post-(optional-commit) epoch exporter
    // secret; the application message below does not change the epoch further.
    let exporter = group
        .export_secret(
            REACTION_ROUTING_LABEL_V1,
            realm_id.as_bytes(),
            REACTION_ROUTING_EXPORT_LEN,
        )
        .map_err(|err| MlsRuntimeError::Export(err.to_string()))?;
    let routing_tag = reaction_routing_tag_from_exporter(&exporter, canonical_emoji);

    // The decrypted plaintext MUST validate as
    // event-payload.schema.json#/$defs/reaction_encrypted_payload_plaintext —
    // a JSON object whose `key` is the real emoji / short tag.
    let plaintext = serde_json::to_vec(&serde_json::json!({ "key": canonical_emoji }))
        .map_err(|err| MlsRuntimeError::Serialize(err.to_string()))?;
    let aad_realm_id = arkret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|err| MlsRuntimeError::Serialize(format!("invalid AAD realm id: {err}")))?;
    let aad = arkret_sdk::EncryptedEnvelopeAad::hidden(aad_realm_id, "ak.reaction.add");
    let encrypted_payload = group
        .encrypt_payload_with_aad(REACTION_ENCRYPTED_CONTENT_TYPE, Some(aad), &plaintext)
        .map_err(|err| MlsRuntimeError::Encrypt(err.to_string()))?;

    let post_state = group
        .export_state_record()
        .map_err(|err| MlsRuntimeError::Export(err.to_string()))?;
    let serialized_state = serde_json::to_vec(&post_state)
        .map_err(|err| MlsRuntimeError::Serialize(format!("MLS state record: {err}")))?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|err| MlsRuntimeError::Salt(err.to_string()))?;
    let new_envelope = crate::mls::persistence::encrypt_state(
        realm_id,
        &post_state.group_id,
        post_state.epoch,
        &serialized_state,
        &secret,
        &salt,
    );

    if forced_commit.is_some() {
        // X14 — a forced epoch advance must NOT be persisted before the server
        // accepts the `ak.mls.commit`, or the local epoch races ahead and every
        // later write is rejected with `mls_epoch_skew`. Hand the snapshot back
        // for the caller to persist on accept.
        Ok(EncryptedReaction {
            routing_tag,
            encrypted_payload,
            forced_commit,
            forced_commit_snapshot: Some(new_envelope.with_app_messages_observed(1)),
        })
    } else {
        // No epoch change → persist the advanced application ratchet now (no
        // epoch-skew risk, and persisting prevents nonce reuse on the next
        // reaction). Carry the epoch-start clock forward so a stream of
        // reactions can never reset the §2.9 1h cap.
        let new_envelope = new_envelope
            .carry_epoch_started_at(&snapshot)
            .with_app_messages_observed(snapshot.app_messages_observed.saturating_add(1));
        state_store.save_mls_snapshot(realm_id.to_owned(), new_envelope);
        Ok(EncryptedReaction {
            routing_tag,
            encrypted_payload,
            forced_commit: None,
            forced_commit_snapshot: None,
        })
    }
}
