//! Controller-owned Agent DID inception and PCR-binding update.

use arkret_sdk::webvh::{
    AgentBindingUpdateInput, AgentInceptionInput, PreparedPrincipalInception,
    PreparedPrincipalRotation, prepare_agent_binding_update, prepare_agent_inception,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::secure_key_store::{SecureKeyStore, SecureKeyStoreError};

const MANAGED_AGENT_DID_KEYS: &str = "agent.did.keys";

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct AgentDidKeys {
    pub(crate) local_id: String,
    binding_seed_hex: String,
    next_seed_hex: String,
}

impl AgentDidKeys {
    fn seed(value: &str, label: &str) -> anyhow::Result<[u8; 32]> {
        let bytes = crate::canonical::hex_decode(value)
            .ok_or_else(|| anyhow::anyhow!("{label} hex decode failed"))?;
        bytes.try_into().map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!("{label} has {} bytes, expected 32", bytes.len())
        })
    }

    fn binding_seed(&self) -> anyhow::Result<Zeroizing<[u8; 32]>> {
        Ok(Zeroizing::new(Self::seed(
            &self.binding_seed_hex,
            "Agent binding seed",
        )?))
    }

    fn next_public_key(&self) -> anyhow::Result<String> {
        let seed = Zeroizing::new(Self::seed(&self.next_seed_hex, "Agent next seed")?);
        Ok(arkret_sdk::ed25519_pubkey_to_did_key_multibase(
            SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
        ))
    }
}

fn storage_key(did: &str) -> String {
    format!(
        "{MANAGED_AGENT_DID_KEYS}.{}",
        URL_SAFE_NO_PAD.encode(did.as_bytes())
    )
}

fn random_seed() -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|error| anyhow::anyhow!("secure random generation failed: {error}"))?;
    Ok(Zeroizing::new(seed))
}

pub(crate) fn prepare_inception(
    principal_endpoint: &str,
    local_id: &str,
    controller_id: &arkret_sdk::DidCoreId,
) -> anyhow::Result<(PreparedPrincipalInception, AgentDidKeys)> {
    let endpoint = url::Url::parse(principal_endpoint)?;
    let root_seed = random_seed()?;
    let binding_seed = random_seed()?;
    let next_seed = random_seed()?;
    let binding_public_key = arkret_sdk::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&binding_seed)
            .verifying_key()
            .as_bytes(),
    );
    let prepared = prepare_agent_inception(&AgentInceptionInput {
        principal_endpoint: &endpoint,
        local_id,
        controller_id,
        version_time: crate::clock::now_utc(),
        root_seed: &root_seed,
        next_root_public_key_multibase: &binding_public_key,
    })?;
    let keys = AgentDidKeys {
        local_id: prepared.local_id.clone(),
        binding_seed_hex: crate::canonical::hex_encode(&binding_seed[..]),
        next_seed_hex: crate::canonical::hex_encode(&next_seed[..]),
    };
    Ok((prepared, keys))
}

/// The binding key and its successor are durably stored before entry-0 is
/// submitted, so an accepted inception cannot strand the controller.
pub(crate) async fn store_keys_durable(
    store: &dyn SecureKeyStore,
    did: &str,
    keys: &AgentDidKeys,
) -> Result<(), SecureKeyStoreError> {
    let encoded = serde_json::to_string(keys)
        .map_err(|error| SecureKeyStoreError::Backend(error.to_string()))?;
    store
        .store_secret_durable(&storage_key(did), &encoded)
        .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_binding_update(
    inception: &PreparedPrincipalInception,
    keys: &AgentDidKeys,
    controller_id: &arkret_sdk::DidCoreId,
    principal_control_realm_id: &arkret_sdk::RealmId,
    requested_scope_digest: &arkret_sdk::Hash,
) -> anyhow::Result<PreparedPrincipalRotation> {
    let binding_seed = keys.binding_seed()?;
    let next_public_key = keys.next_public_key()?;
    Ok(prepare_agent_binding_update(&AgentBindingUpdateInput {
        did: &inception.did,
        local_id: &keys.local_id,
        previous_entries: std::slice::from_ref(&inception.log_entry),
        version_time: crate::clock::now_utc(),
        current_root_seed: &binding_seed,
        next_root_public_key_multibase: &next_public_key,
        controller_id,
        principal_control_realm_id,
        requested_scope_digest,
    })?)
}
