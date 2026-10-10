//! §2.9 E2EE reaction sealing and routing-tag derivation.

use arkret_sdk::{AccountId, DeviceId};
use arkret_wire::event_kind_str;

use super::{MlsRuntimeError, load_device_checkpoint_secret, should_force_epoch_advance};
use crate::secure_key_store::SecureKeyStore;

/// The registered reaction tag is an HMAC over NFC emoji bytes. Its key is
/// already bound by the SDK exporter to the exact MLS epoch, effective scope,
/// target Event and one-hour routing window. It intentionally does not include
/// the sender: the formal `(target_ref, key)` projection groups equal reactions
/// across members, and the cross-sender equality exposure is documented.
fn reaction_routing_tag_from_key(
    key: &[u8],
    canonical_emoji: &str,
) -> Result<String, MlsRuntimeError> {
    use hmac::{Hmac, KeyInit, Mac};

    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key)
        .map_err(|error| MlsRuntimeError::Encrypt(format!("reaction routing HMAC key: {error}")))?;
    let normalized = arkret_sdk::canonical::to_nfc(canonical_emoji);
    mac.update(normalized.as_bytes());
    Ok(arkret_sdk::base64url_encode(mac.finalize().into_bytes()))
}

/// Content type for the encrypted real-emoji payload of a reaction.
pub const REACTION_ENCRYPTED_CONTENT_TYPE: &str = "application/vnd.arkret.reaction+json";

/// Result of sealing an E2EE reaction: the plaintext routing tag for the
/// wire `reaction_payload.key`, plus the structured encrypted payload that
/// carries the real emoji.
pub struct EncryptedReaction {
    /// 43-character base64url keyed-HMAC routing tag used by both
    /// `reaction_payload.key` and the encrypted envelope routing context.
    pub routing_tag: String,
    /// MLS application-message payload carrying the real emoji JSON. The
    /// caller wraps this in an `EncryptedEnvelope` only after it has resolved
    /// the accepted group-state Event for the payload epoch (or built the
    /// forced commit Event returned alongside it).
    pub encrypted_payload: arkret_sdk::EncryptedPayload,
}

/// Seal an E2EE reaction: derive the v1 routing tag and encrypt the real
/// emoji as an MLS application message, both under the current epoch.
///
/// Unlike message send, this does NOT advance the MLS epoch (no commit) —
/// `encryption-and-audit.md` §2.9 reuses the application-key flow, so
/// reactions ride the current epoch and the server deduplicates on the
/// routing tag. The post-encrypt snapshot IS persisted immediately so the
/// sender's application ratchet never reuses a generation; because the epoch
/// is unchanged there is no epoch-skew risk that would require
/// persist-on-accept.
pub fn encrypt_reaction_with_device_snapshot(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &AccountId,
    device_id: &DeviceId,
    target_ref: &arkret_sdk::EventId,
    created_at: chrono::DateTime<chrono::Utc>,
    canonical_emoji: &str,
) -> Result<EncryptedReaction, MlsRuntimeError> {
    super::reject_retired_minimal_metadata_realm(state_store, realm_id)?;
    let snapshot = state_store
        .mls_checkpoint_for(realm_id)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    let secret = load_device_checkpoint_secret(secure_store, authority, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // COR-04: reaction send may force an epoch commit; bind it to the Seal-view
    // epoch floor so a stale local snapshot can't seal a reaction on a forked ratchet.
    let epoch_floor = super::accepted_mls_epoch_floor(state_store, realm_id);
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::CheckpointRestore(err.to_string()))?;

    // General self-preservation rotation is handled by the same pending
    // accepted-Commit boundary as ordinary encrypted messages.
    let now = crate::clock::now_utc();
    if should_force_epoch_advance(
        snapshot.epoch_started_at,
        now,
        snapshot.app_messages_observed,
        state_store.realm_has_pending_mls_binding(realm_id),
    ) {
        // A new application Event cannot name the pending Commit as its
        // group-state reference before that Commit is accepted. The normal MLS
        // rotation path authors and submits the transition; this operation is
        // retried only after sync installs the accepted successor state.
        return Err(MlsRuntimeError::EncryptionTransitionPending);
    }

    let effective_scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())
            .map_err(|error| MlsRuntimeError::Serialize(error.to_string()))?,
    };
    // A scope is standard RFC 9420 from its accepted Genesis onward, so a
    // reaction rides the same scheme as every other application payload. The
    // caller resolved the durable send gate; submission re-checks the frozen
    // envelope against the accepted current (`crate::mls::send_gate`).
    let scheme = arkret_sdk::EncryptedPayloadScheme::MlsRfc9420;
    let routing_window = u64::try_from(created_at.timestamp_millis().div_euclid(3_600_000))
        .map_err(|_| {
            MlsRuntimeError::Serialize("reaction timestamp precedes Unix epoch".to_owned())
        })?;
    let routing_root = arkret_sdk::mls::derive_reaction_routing_root(&group, &effective_scope)
        .map_err(|error| MlsRuntimeError::Encrypt(error.to_string()))?;
    let routing_key = arkret_sdk::mls::derive_reaction_routing_key(
        &routing_root,
        &arkret_sdk::mls::ReactionRoutingKeyContext {
            effective_scope: effective_scope.clone(),
            target_ref: target_ref.clone(),
            routing_window,
        },
    )
    .map_err(|error| MlsRuntimeError::Encrypt(error.to_string()))?;
    let routing_tag = reaction_routing_tag_from_key(&routing_key, canonical_emoji)?;

    // The decrypted plaintext MUST validate as
    // event-payload.schema.json#/$defs/reaction_encrypted_payload_plaintext —
    // a JSON object whose `key` is the real emoji / short tag.
    let plaintext = serde_json::to_vec(&serde_json::json!({ "key": canonical_emoji }))
        .map_err(|err| MlsRuntimeError::Serialize(err.to_string()))?;
    let group_state_ref = crate::mls::group_events::mls_base_epoch_ref_for_scope(
        state_store,
        realm_id,
        None,
        &group.group_id(),
        group.epoch(),
    )
    .map_err(MlsRuntimeError::Encrypt)?;
    let group_state_ref = arkret_sdk::EventId::new(group_state_ref)
        .map_err(|error| MlsRuntimeError::Serialize(error.to_string()))?;
    let sender_domain = group
        .local_content_sender_domain()
        .map_err(|error| MlsRuntimeError::Encrypt(error.to_string()))?;
    let header = arkret_sdk::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        REACTION_ENCRYPTED_CONTENT_TYPE,
        scheme,
        effective_scope,
        event_kind_str::REACTION_ADD,
        group.epoch(),
        group_state_ref,
        sender_domain,
        arkret_sdk::EventContentRoutingContext::Reaction {
            target_ref: target_ref.clone(),
            routing_window,
            routing_tag: routing_tag.clone(),
        },
    )
    .map_err(|error| MlsRuntimeError::Encrypt(error.to_string()))?;
    let encrypted_payload = group
        .encrypt_payload(header, &plaintext)
        .map_err(|error| MlsRuntimeError::Encrypt(error.to_string()))?;
    let post_state = group
        .export_state_record()
        .map_err(|err| MlsRuntimeError::Export(err.to_string()))?;
    let serialized_state = serde_json::to_vec(&post_state)
        .map_err(|err| MlsRuntimeError::Serialize(format!("MLS state record: {err}")))?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt)
        .map_err(|err| MlsRuntimeError::Encrypt(format!("MLS checkpoint salt: {err}")))?;
    let new_envelope = crate::mls::persistence::encrypt_state(
        realm_id,
        &post_state.group_id,
        post_state.epoch,
        &serialized_state,
        &secret,
        &salt,
    );

    // No epoch change: persist the advanced application ratchet now so the
    // next reaction cannot reuse a generation. Carry the epoch-start clock
    // forward for the general self-preservation rotation policy.
    let new_envelope = new_envelope
        .carry_epoch_started_at(&snapshot)
        .with_app_messages_observed(snapshot.app_messages_observed.saturating_add(1));
    state_store
        .save_mls_checkpoint(realm_id.to_owned(), new_envelope)
        .map_err(MlsRuntimeError::Commit)?;
    Ok(EncryptedReaction {
        routing_tag,
        encrypted_payload,
    })
}

#[cfg(test)]
mod routing_tag_tests {
    use super::reaction_routing_tag_from_key;

    #[test]
    fn registered_reaction_hmac_vector_normalizes_emoji_bytes() {
        // arkret-private-kdf-fixture.json:
        // ak.vector.reaction.routing_hmac_kat.v1. The SDK separately tests
        // the exporter root and target/window key expansion.
        let key = hex::decode("0599b6e51be62e8baf6cdec6bf5f326fe1a7c3cf1d56e38d091029b5a7dcf675")
            .unwrap();
        let expected = arkret_sdk::base64url_encode(
            hex::decode("e61c8ae48d2cf86d721e73c9f72969aacdff69fdbbbf5383a18e17173d2bdddb")
                .unwrap(),
        );
        assert_eq!(
            reaction_routing_tag_from_key(&key, "e\u{301}").unwrap(),
            expected
        );
        assert_eq!(reaction_routing_tag_from_key(&key, "é").unwrap(), expected);
        let skin_tone = arkret_sdk::base64url_encode(
            hex::decode("65a3319be4bc655c9967c470fe339c129ffb46fea1b5a125fe4665a4576a0158")
                .unwrap(),
        );
        assert_eq!(
            reaction_routing_tag_from_key(&key, "👍🏽").unwrap(),
            skin_tone
        );
    }
}
