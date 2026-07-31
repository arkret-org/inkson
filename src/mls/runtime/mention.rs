//! §4.5 E2EE mention routing-key derivation.

use super::MlsRuntimeError;

/// MLS exporter label for the v1 mention routing key
/// (`discovery/push-notifications.md` §4.5). Bound, together with
/// `context = realm_id` and the current group epoch's exporter secret, into
/// the keyed-HMAC routing key each mention digest is taken under.
pub const MENTION_ROUTING_LABEL_V1: &str = arkret_sdk::mls::MENTION_ROUTING_EXPORTER_LABEL;
/// Length (bytes) of the MLS exporter output used as the HMAC key.
pub const MENTION_ROUTING_EXPORT_LEN: usize = 32;

/// Read the mention routing key from an already-restored group, honouring the
/// Realm's effective `mention_routing_hint`.
///
/// Returns `None` when §4.5 forbids the sidecar for this Realm — a hardened
/// profile, a non-E2EE Realm, or a policy that never opted in. Callers on the
/// send path use this so the key is taken from the same group instance (and
/// therefore the same epoch) that produced the ciphertext.
pub fn mention_routing_key_from_group(
    state_store: &crate::state::LocalStateStore,
    realm_id: &str,
    group: &arkret_sdk::ArkretMlsGroup,
) -> Result<Option<Vec<u8>>, MlsRuntimeError> {
    if state_store.realm_mention_routing_hint(realm_id)
        != arkret_sdk::MentionRoutingHint::RecipientRegisteredToken
    {
        return Ok(None);
    }
    let routing_key = group
        .export_secret(
            MENTION_ROUTING_LABEL_V1,
            realm_id.as_bytes(),
            MENTION_ROUTING_EXPORT_LEN,
        )
        .map_err(|err| MlsRuntimeError::Export(err.to_string()))?;
    Ok(Some(routing_key.to_vec()))
}
