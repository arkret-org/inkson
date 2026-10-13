//! Agent ceremonies share the existing account authoring vault and its CAS.

use super::*;
use crate::agent_identity::provision::ProvisionCeremony;

impl InksonOutboundStore {
    pub(crate) async fn agent_provision_record(
        &self,
        authority: &arkret_sdk::AccountId,
        operation_id: &arkret_sdk::ProtocolOperationId,
    ) -> garth::Result<ProvisionCeremony> {
        self.check_agent_ceremony_vault(authority)?;
        self.mutate_state(|state| {
            state
                .agent_provision_records
                .iter()
                .find(|record| {
                    &record.authority == authority && &record.operation_id == operation_id
                })
                .cloned()
                .ok_or_else(|| {
                    garth::Error::Storage("original Agent ceremony is not durably available".into())
                })
        })
        .await
    }

    fn check_agent_ceremony_vault(&self, authority: &arkret_sdk::AccountId) -> garth::Result<()> {
        #[cfg(target_arch = "wasm32")]
        if &self.authority != authority {
            return Err(garth::Error::Storage(
                "Agent ceremony attempted another complete Account vault".into(),
            ));
        }
        #[cfg(not(target_arch = "wasm32"))]
        if self
            .protection
            .as_ref()
            .is_some_and(|(owner, _)| owner != authority)
        {
            return Err(garth::Error::Storage(
                "Agent ceremony attempted another complete Account vault".into(),
            ));
        }
        Ok(())
    }
    pub(crate) async fn pending_agent_provisions(
        &self,
        authority: &arkret_sdk::AccountId,
    ) -> garth::Result<Vec<ProvisionCeremony>> {
        self.check_agent_ceremony_vault(authority)?;
        self.mutate_state(|state| {
            if state
                .agent_provision_records
                .iter()
                .any(|record| &record.authority != authority)
            {
                return Err(garth::Error::Storage(
                    "Agent ceremony belongs to another complete Account vault".into(),
                ));
            }
            Ok(state
                .agent_provision_records
                .iter()
                .filter(|record| record.outcome.is_none())
                .cloned()
                .collect())
        })
        .await
    }

    pub(crate) async fn freeze_agent_provision(
        &self,
        candidate: ProvisionCeremony,
    ) -> garth::Result<ProvisionCeremony> {
        self.check_agent_ceremony_vault(&candidate.authority)?;
        candidate
            .validate()
            .map_err(|error| garth::Error::Storage(error.to_string()))?;
        self.mutate_state(|state| {
            if let Some(winner) = state
                .agent_provision_records
                .iter()
                .find(|record| record.authority == candidate.authority && record.outcome.is_none())
            {
                if winner.device_id != candidate.device_id
                    || winner.slug != candidate.slug
                    || winner.controller_did != candidate.controller_did
                    || winner.principal_endpoint != candidate.principal_endpoint
                    || crate::canonical::canonical_json_bytes(&winner.requested_scope)
                        .map_err(|error| garth::Error::Storage(error.to_string()))?
                        != crate::canonical::canonical_json_bytes(&candidate.requested_scope)
                            .map_err(|error| garth::Error::Storage(error.to_string()))?
                {
                    return Err(garth::Error::Storage(
                        "another immutable Agent intent is pending for this controller".into(),
                    ));
                }
                return Ok(winner.clone());
            }
            state.agent_provision_records.push(candidate.clone());
            Ok(candidate)
        })
        .await
    }

    pub(crate) async fn advance_agent_provision(
        &self,
        original: &ProvisionCeremony,
        next: ProvisionCeremony,
    ) -> garth::Result<ProvisionCeremony> {
        self.check_agent_ceremony_vault(&original.authority)?;
        original
            .check_successor(&next)
            .map_err(|error| garth::Error::Storage(error.to_string()))?;
        self.mutate_state(|state| {
            let saved = state
                .agent_provision_records
                .iter_mut()
                .find(|record| record.operation_id == original.operation_id)
                .ok_or_else(|| {
                    garth::Error::Storage("Agent ceremony lost its original durable intent".into())
                })?;
            if saved
                .exact_bytes()
                .map_err(|error| garth::Error::Storage(error.to_string()))?
                .as_slice()
                != original
                    .exact_bytes()
                    .map_err(|error| garth::Error::Storage(error.to_string()))?
                    .as_slice()
            {
                return Err(garth::Error::Storage(
                    "Agent ceremony advanced in another holder; reread its committed winner".into(),
                ));
            }
            *saved = next.clone();
            Ok(next)
        })
        .await
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedCeremony {
    device_id: arkret_sdk::DeviceId,
    nonce: String,
    ciphertext: String,
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn protect_records(
    value: &mut serde_json::Value,
    authority: &arkret_sdk::AccountId,
    store: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<()> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
    if let Some(records) = value
        .get_mut("agent_provision_records")
        .and_then(serde_json::Value::as_array_mut)
    {
        for raw in records {
            let record: ProvisionCeremony = serde_json::from_value(raw.clone())?;
            record.validate()?;
            anyhow::ensure!(
                &record.authority == authority,
                "Agent ceremony belongs to another Account vault"
            );
            let key = zeroize::Zeroizing::new(super::creator_protection::device_key_for_domain(
                store,
                authority,
                &record.device_id,
                "inkson.agent.provision.v1",
                "record",
            )?);
            let aad = crate::canonical::canonical_json_bytes(&(
                authority,
                &record.device_id,
                "inkson.agent.provision.v1",
            ))?;
            let mut nonce = [0u8; 12];
            getrandom::fill(&mut nonce)?;
            let plaintext = record.exact_bytes()?;
            let ciphertext = ChaCha20Poly1305::new((&*key).into())
                .encrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: &plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| anyhow::anyhow!("encrypt Agent ceremony"))?;
            *raw = serde_json::to_value(ProtectedCeremony {
                device_id: record.device_id.clone(),
                nonce: URL_SAFE_NO_PAD.encode(nonce),
                ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            })?;
        }
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn open_records(
    value: &mut serde_json::Value,
    authority: &arkret_sdk::AccountId,
    store: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<()> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
    if let Some(records) = value
        .get_mut("agent_provision_records")
        .and_then(serde_json::Value::as_array_mut)
    {
        for raw in records {
            let protected: ProtectedCeremony = serde_json::from_value(raw.clone())?;
            let key = zeroize::Zeroizing::new(super::creator_protection::device_key_for_domain(
                store,
                authority,
                &protected.device_id,
                "inkson.agent.provision.v1",
                "record",
            )?);
            let aad = crate::canonical::canonical_json_bytes(&(
                authority,
                &protected.device_id,
                "inkson.agent.provision.v1",
            ))?;
            let nonce: [u8; 12] = URL_SAFE_NO_PAD
                .decode(protected.nonce)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid Agent ceremony nonce"))?;
            let ciphertext = URL_SAFE_NO_PAD.decode(protected.ciphertext)?;
            let plaintext = zeroize::Zeroizing::new(
                ChaCha20Poly1305::new((&*key).into())
                    .decrypt(
                        &Nonce::from(nonce),
                        Payload {
                            msg: &ciphertext,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| {
                        anyhow::anyhow!("Agent ceremony device secret mismatch or tamper")
                    })?,
            );
            let record: ProvisionCeremony = serde_json::from_slice(&plaintext)?;
            record.validate()?;
            anyhow::ensure!(
                &record.authority == authority && record.device_id == protected.device_id,
                "protected Agent ceremony coordinate mismatch"
            );
            *raw = serde_json::to_value(record)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use garth::SecureKeyStore;

    use super::*;

    fn fixture() -> ProvisionCeremony {
        let controller = arkret_sdk::Did::new("did:web:controller.agent-journal.example").unwrap();
        let authority = arkret_sdk::AccountId::new(
            arkret_sdk::project_did_to_core_id(&controller).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.agent-journal.example").unwrap(),
        );
        let nonce = crate::operation::uuid_v7();
        let endpoint = "https://station.agent-journal.example";
        let (inception, keys) = crate::agent_identity::prepare_inception(
            endpoint,
            &format!("agent-{nonce}"),
            &authority.principal_id,
        )
        .unwrap();
        ProvisionCeremony {
            authority,
            device_id: arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000011").unwrap(),
            controller_did: controller, principal_endpoint: endpoint.to_owned(),
            operation_id: arkret_sdk::ProtocolOperationId::new(format!("ak:operation:agent.provision.{nonce}")).unwrap(),
            idempotency_key: arkret_sdk::IdempotencyKey::new(nonce).unwrap(), slug: "journal-agent".to_owned(),
            requested_scope: serde_json::from_value(serde_json::json!({"actions":["ak.self.agent.resource.get.v1"],"resources":[{"kind":"operation","operation":"ak.self.agent.resource.get.v1"}]})).unwrap(),
            inception, keys, preparation: None, authored: None, binding_operation: None, outcome: None,
        }
    }

    #[tokio::test]
    async fn independent_handles_keep_one_original_intent_and_reject_substitution() {
        let store = garth::MemorySecureKeyStore::new();
        let key = "inkson.outbound.v1::agent-journal-cas.standard";
        let original = fixture();
        let left = original.clone();
        let right = fixture();
        let (first, second) = tokio::join!(
            mutate_authenticated_state_in_store(&store, key, Some(&original.authority), |state| {
                state.agent_provision_records.push(left.clone());
                Ok(())
            }),
            mutate_authenticated_state_in_store(&store, key, Some(&original.authority), |state| {
                state.agent_provision_records.push(right.clone());
                Ok(())
            })
        );
        assert!(first.is_ok() ^ second.is_ok());
        let saved = store.read_secret_bytes_durable(key).await.unwrap().unwrap();
        let state: DurableOutboundState = serde_json::from_slice(saved.as_slice()).unwrap();
        assert_eq!(state.agent_provision_records.len(), 1);
        let winner = &state.agent_provision_records[0];
        let mut replacement = winner.clone();
        replacement.operation_id = fixture().operation_id;
        assert!(winner.check_successor(&replacement).is_err());
        replacement = winner.clone();
        replacement
            .requested_scope
            .actions
            .push("ak.self.agent.command.deactivate.v1".to_owned());
        assert!(winner.check_successor(&replacement).is_err());
        assert!(
            store
                .read_secret_bytes_durable(key)
                .await
                .unwrap()
                .unwrap()
                .as_slice()
                == saved.as_slice()
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn native_vault_encrypts_ceremony_and_cold_reads_without_replacing_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("standard.json");
        let record = fixture();
        let secrets = std::sync::Arc::new(garth::MemorySecureKeyStore::new());
        crate::secure_key_store::UserLocalStore::new(
            record.authority.clone(),
            record.device_id.clone(),
        )
        .unwrap()
        .save_signing_seed(secrets.as_ref(), &[97; 32])
        .unwrap();
        let make = || InksonOutboundStore {
            creator_decision: Default::default(),
            path: path.clone(),
            protection: Some((record.authority.clone(), secrets.clone())),
        };
        let frozen = make().freeze_agent_provision(record.clone()).await.unwrap();
        let disk = std::fs::read(&path).unwrap();
        let text = std::str::from_utf8(&disk).unwrap();
        assert!(!text.contains("binding_seed_hex"));
        assert!(!text.contains(record.controller_did.as_str()));
        assert!(!text.contains("ak.self.agent.resource.get.v1"));
        let cold = make()
            .pending_agent_provisions(&record.authority)
            .await
            .unwrap();
        assert_eq!(cold.len(), 1);
        assert!(
            cold[0].exact_bytes().unwrap().as_slice() == frozen.exact_bytes().unwrap().as_slice()
        );
        assert!(std::fs::read(&path).unwrap() == disk);
        let mut other = record.authority.clone();
        other.station_id =
            arkret_sdk::DidCoreId::new("ak:did_core:web:other.agent-journal.example").unwrap();
        assert!(make().pending_agent_provisions(&other).await.is_err());
        assert!(std::fs::read(&path).unwrap() == disk);
    }
}
