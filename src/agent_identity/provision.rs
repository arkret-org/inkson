//! Holder-private recovery of one immutable Agent provisioning ceremony.

use arkret_sdk::{
    AccountId, AgentKeyScope, AgentProvisionAwaitingControllerEvent,
    AgentProvisionCommitRequestBody, AgentProvisionComplete, DeviceId, Did,
    DidOperationSubmitRequestBody, IdempotencyKey, ProtocolOperationId,
};
use serde::{Deserialize, Serialize};

use super::{AgentDidKeys, PreparedPrincipalInception};

mod resume;
pub(crate) use resume::resume_ceremony;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthoredProvision {
    pub(crate) commit: AgentProvisionCommitRequestBody,
    pub(crate) genesis: arkret_sdk::AuthoredEvent,
}

/// A local encrypted journal, never a protocol carrier or authorization source.
/// Optional successor material is frozen before its first external write.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProvisionCeremony {
    pub(crate) authority: AccountId,
    pub(crate) device_id: DeviceId,
    pub(crate) controller_did: Did,
    pub(crate) principal_endpoint: String,
    pub(crate) operation_id: ProtocolOperationId,
    pub(crate) idempotency_key: IdempotencyKey,
    pub(crate) slug: String,
    pub(crate) requested_scope: AgentKeyScope,
    pub(crate) inception: PreparedPrincipalInception,
    pub(crate) keys: AgentDidKeys,
    pub(crate) preparation: Option<AgentProvisionAwaitingControllerEvent>,
    pub(crate) authored: Option<AuthoredProvision>,
    pub(crate) binding_operation: Option<DidOperationSubmitRequestBody>,
    pub(crate) outcome: Option<AgentProvisionComplete>,
}

impl ProvisionCeremony {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        self.authority.validate()?;
        let did = Did::new(self.inception.did.clone())?;
        let controller = arkret_sdk::project_did_to_core_id(&self.controller_did)?;
        anyhow::ensure!(
            controller == self.authority.principal_id,
            "ceremony controller Account mismatch"
        );
        anyhow::ensure!(
            self.inception.submit_body.did == did && self.keys.local_id == self.inception.local_id,
            "ceremony inception coordinates mismatch"
        );
        let binding_seed = self.keys.binding_seed()?;
        anyhow::ensure!(
            arkret_sdk::ed25519_pubkey_to_did_key_multibase(
                ed25519_dalek::SigningKey::from_bytes(&binding_seed)
                    .verifying_key()
                    .as_bytes()
            ) == self.inception.next_root_public_key_multibase,
            "ceremony update secret does not match inception precommitment"
        );
        anyhow::ensure!(
            url::Url::parse(&self.principal_endpoint)?.scheme() == "https",
            "Agent ceremony requires the authenticated HTTPS endpoint"
        );
        if let Some(prepared) = &self.preparation {
            anyhow::ensure!(
                prepared.did == did
                    && arkret_sdk::project_did_to_core_id(&did)? == prepared.agent_id
                    && prepared.initial_resolution.did == did
                    && prepared.initial_resolution.version_id == self.inception.version_id
                    && prepared.initial_resolution.method_history_head
                        == crate::canonical::canonical_sha256(&self.inception.log_entry)?,
                "ceremony preparation replaced its accepted inception"
            );
        }
        if let Some(authored) = &self.authored {
            let prepared = self
                .preparation
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("authored provision lost its allocation"))?;
            let commit = &authored.commit;
            let provision = &commit.provision_event.event;
            let genesis = authored.genesis.event();
            let payload: arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload =
                serde_json::from_value(serde_json::to_value(&provision.payload)?)?;
            let digest = arkret_signatures::agent::agent_requested_scope_digest(
                &prepared.agent_id,
                &self.authority.principal_id,
                &self.requested_scope,
            )?;
            anyhow::ensure!(
                commit.operation_id == self.operation_id
                    && commit.idempotency_key == self.idempotency_key
                    && commit.agent_id == prepared.agent_id
                    && commit.did == did
                    && commit.slug == self.slug
                    && crate::canonical::canonical_json_bytes(&commit.requested_scope)?
                        == crate::canonical::canonical_json_bytes(&self.requested_scope)?
                    && commit.allocation_handle == prepared.allocation_handle
                    && provision.actor_id.as_account_id() == Some(&self.authority)
                    && provision.realm_id == prepared.controller_realm_id
                    && payload.agent_id == prepared.agent_id
                    && payload.controller_principal_id == self.authority.principal_id
                    && payload.controller_authorization_ref
                        == prepared.controller_authorization_ref
                    && payload.requested_scope_digest == digest
                    && payload.principal_control_realm_id == commit.principal_control_realm_id
                    && genesis.realm_id == commit.principal_control_realm_id
                    && genesis.actor_id.as_account_id()
                        == Some(&AccountId::new(
                            prepared.agent_id.clone(),
                            self.authority.station_id.clone()
                        )),
                "ceremony lost its exact authored Agent/PCR/provision binding"
            );
        }
        anyhow::ensure!(
            self.binding_operation.is_none() || self.authored.is_some(),
            "DID binding precedes the frozen provision"
        );
        if let Some(binding) = &self.binding_operation {
            anyhow::ensure!(binding.did == did, "ceremony DID binding changed principal");
        }
        if let Some(outcome) = &self.outcome {
            let authored = self
                .authored
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("complete ceremony lost its original provision"))?;
            anyhow::ensure!(
                self.binding_operation.is_some()
                    && outcome.did == did
                    && outcome.agent_id == authored.commit.agent_id
                    && outcome.principal_control_realm_id
                        == authored.commit.principal_control_realm_id,
                "complete ceremony changed its immutable coordinates"
            );
        }
        Ok(())
    }

    pub(crate) fn exact_bytes(&self) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
        self.validate()?;
        Ok(zeroize::Zeroizing::new(
            crate::canonical::canonical_json_bytes(self)?,
        ))
    }

    /// Recovery may append frozen successor units, never replace one already saved.
    pub(crate) fn check_successor(&self, next: &Self) -> anyhow::Result<()> {
        self.validate()?;
        next.validate()?;
        let base = |record: &Self| -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
            Ok(zeroize::Zeroizing::new(
                crate::canonical::canonical_json_bytes(&(
                    &record.authority,
                    &record.device_id,
                    &record.controller_did,
                    &record.principal_endpoint,
                    &record.operation_id,
                    &record.idempotency_key,
                    &record.slug,
                    &record.requested_scope,
                    &record.inception,
                    &record.keys,
                ))?,
            ))
        };
        anyhow::ensure!(
            base(self)?.as_slice() == base(next)?.as_slice(),
            "ceremony retry substituted immutable original bytes"
        );
        macro_rules! preserve {
            ($field:ident) => {
                if let Some(original) = &self.$field {
                    let successor = next.$field.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("ceremony lost frozen {}", stringify!($field))
                    })?;
                    anyhow::ensure!(
                        zeroize::Zeroizing::new(crate::canonical::canonical_json_bytes(original)?)
                            .as_slice()
                            == zeroize::Zeroizing::new(crate::canonical::canonical_json_bytes(
                                successor
                            )?)
                            .as_slice(),
                        "ceremony substituted frozen {}",
                        stringify!($field)
                    );
                }
            };
        }
        preserve!(preparation);
        preserve!(authored);
        preserve!(binding_operation);
        preserve!(outcome);
        Ok(())
    }
}
